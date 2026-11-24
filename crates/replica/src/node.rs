use super::*;
use openraft::{
    Config, ReadPolicy, SnapshotPolicy,
    network::{NetSnapshot, RaftNetworkFactory},
};

pub type Raft = openraft::Raft<Types, Replica>;
pub struct GameNode {
    pub(crate) raft: Raft,
    pub(crate) replica: Replica,
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
        })
    }
    pub async fn submit(&self, signed: Signed) -> Result<Reply, SubmitError> {
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
        self.raft
            .client_write(signed)
            .await
            .map(|v| v.data)
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
