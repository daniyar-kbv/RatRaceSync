use super::*;
use openraft::{
    Config, ReadPolicy, SnapshotPolicy,
    network::{NetSnapshot, RaftNetworkFactory},
};

use futures::lock::{Mutex as AsyncMutex, OwnedMutexGuard};
use openraft::type_config::TypeConfigExt;
use std::{collections::HashMap, sync::Weak};

pub type Raft = openraft::Raft<Types, Replica>;

// Receipt ownership is per game, actor and UUID. All normal command families on
// this node use the same admission lock for that identity.
type RequestKey = (Vec<u8>, [u8; 16]);
type PendingRequests = Mutex<HashMap<RequestKey, Weak<AsyncMutex<()>>>>;
pub struct GameNode {
    pub(crate) raft: Raft,
    pub(crate) replica: Replica,
    pending_requests: PendingRequests,
    pub(crate) sealer: Mutex<Option<learner::SealWorker>>,
}
#[derive(Debug)]
pub enum SubmitError {
    PreflightFailed(io::Error),
    ReconciliationRequired,
}
impl GameNode {
    /// Open an already provisioned replica or an empty replica awaiting genesis.
    /// Fixed voters are initialized exactly once by the trusted game-setup boundary.
    pub async fn start<N>(
        id: ReplicaId,
        replica: Replica,
        mut config: Config,
        network: N,
    ) -> io::Result<Self>
    where
        N: RaftNetworkFactory<Types>,
        N::Network: NetSnapshot<Types, SnapshotData = ()>,
    {
        config.snapshot_policy = SnapshotPolicy::Never;
        let config = Arc::new(config.validate().map_err(io::Error::other)?);
        // Clones share the database for Raft's readers and writers. Only the
        // first startup may claim it; a restart must reopen after all handles close.
        if replica
            .started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(io::Error::other("replica is already claimed"));
        }
        {
            let db = replica.lock()?;
            replica.verify_pending_lobby_membership(&db)?;
            match store::meta::<ReplicaId>(&db, "local_node")? {
                Some(saved) if saved != id => {
                    return Err(invalid("database belongs to another replica"));
                }
                None => store::put(&db, "local_node", &id)?,
                _ => {}
            }
        }
        let raft = Raft::new(id, config, network, replica.clone(), replica.clone())
            .await
            .map_err(io::Error::other)?;
        Ok(Self {
            raft,
            replica,
            sealer: Default::default(),
            pending_requests: Default::default(),
        })
    }
    pub async fn submit(&self, signed: Signed) -> Result<Reply, SubmitError> {
        if seating::preference_actor(&signed.0).is_some() {
            return Err(SubmitError::PreflightFailed(invalid(
                "private receipt requires authenticated owner",
            )));
        }
        self.submit_authorized(signed).await
    }
    /// The transport supplies the authenticated installation for this private reply.
    pub async fn submit_preference(
        &self,
        peer: ReplicaId,
        signed: Signed,
    ) -> Result<Reply, SubmitError> {
        let actor = seating::preference_actor(&signed.0).ok_or_else(|| {
            SubmitError::PreflightFailed(invalid("expected player setup command"))
        })?;
        {
            let db = self.replica.lock().map_err(SubmitError::PreflightFailed)?;
            seating::authenticated_member(&db, actor, peer)
                .map_err(SubmitError::PreflightFailed)?;
        }
        self.submit_authorized(signed).await
    }
    pub(crate) async fn request_permit(&self, signed: &Signed) -> io::Result<OwnedMutexGuard<()>> {
        if signed.0.len() > 2048 {
            return Err(invalid("oversized command"));
        }
        let envelope = wire::fields(&signed.0, &[1, 2])?;
        let family = if self.replica.lobby_format.is_some() {
            12
        } else {
            11
        };
        let body = wire::fields(envelope[&1], &[1, 2, 3, 4, 5, family])?;
        let key = (
            body[&3].to_vec(),
            body[&4].try_into().map_err(io::Error::other)?,
        );
        let lock = {
            let mut pending = self
                .pending_requests
                .lock()
                .map_err(|_| io::Error::other("request admission unavailable"))?;
            pending.retain(|_, lock| lock.strong_count() > 0);
            let entry = pending.entry(key).or_default();
            if let Some(lock) = entry.upgrade() {
                lock
            } else {
                let lock = Arc::new(AsyncMutex::new(()));
                *entry = Arc::downgrade(&lock);
                lock
            }
        };
        Ok(lock.lock_owned().await)
    }
    async fn submit_authorized(&self, signed: Signed) -> Result<Reply, SubmitError> {
        let permit = self
            .request_permit(&signed)
            .await
            .map_err(SubmitError::PreflightFailed)?;
        self.raft
            .ensure_linearizable(ReadPolicy::ReadIndex)
            .await
            .map_err(|_| SubmitError::ReconciliationRequired)?;
        if let Some(reply) = self
            .replica
            .preflight(&signed)
            .map_err(SubmitError::PreflightFailed)?
        {
            return Ok(reply);
        }
        // Once submitted, Raft may commit even if the transport drops its caller.
        // Keep ownership until the write resolves. A waiting retry then reads the
        // current leader's applied history before deciding whether to submit.
        let raft = self.raft.clone();
        Types::spawn(async move {
            let _permit = permit;
            raft.client_write(signed).await.map(|v| v.data)
        })
        .await
        .map_err(|_| SubmitError::ReconciliationRequired)?
        .map_err(|_| SubmitError::ReconciliationRequired)
    }
    /// Trusted adapter entry point. The caller must authenticate the actor and
    /// establish owner read permission before requesting their position guard.
    pub async fn redemption_guard(
        &self,
        actor: &[u8],
        position: &[u8],
    ) -> Result<(i64, [u8; 32]), SubmitError> {
        self.raft
            .ensure_linearizable(ReadPolicy::ReadIndex)
            .await
            .map_err(|_| SubmitError::ReconciliationRequired)?;
        self.replica
            .redemption_guard(actor, position)
            .map_err(SubmitError::PreflightFailed)
    }

    /// Handle for the authenticated peer transport and trusted lifecycle adapter.
    pub fn raft(&self) -> &Raft {
        &self.raft
    }
}
