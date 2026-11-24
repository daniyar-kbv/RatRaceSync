//! Verified recovery and first-player admission over an authenticated peer transport.
use crate::{
    genesis::{Creator, SignedGenesis},
    wire::{fields, message},
    *,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
mod history;
mod join;
mod quorum;
pub(crate) mod third;
pub use join::{JoinDelivery, JoinResult, JoinedMember};
pub use quorum::VotingHistoryRequest;
mod installation;
mod sealing;
pub(crate) use installation::check_inventory;
pub(crate) use sealing::SealWorker;

const INVITE: &[u8] = b"RatRaceSync/learner/invitation/1";
const ADMIT: &[u8] = b"RatRaceSync/learner/admission/1";
const REQUEST: &[u8] = b"RatRaceSync/learner/request/1";
const RESPONSE: &[u8] = b"RatRaceSync/learner/transfer/1";
const LIMIT: usize = 1 << 20;

fn signed(body: &[u8], key: &SigningKey) -> Vec<u8> {
    message(&[(1, body), (2, &key.sign(body).to_bytes())])
}
fn authenticate<'a>(packet: &'a [u8], key: &[u8; 32]) -> io::Result<&'a [u8]> {
    if packet.len() > LIMIT {
        return Err(invalid("recovery message too large"));
    }
    let f = fields(packet, &[1, 2])?;
    VerifyingKey::from_bytes(key)
        .map_err(io::Error::other)?
        .verify_strict(
            f[&1],
            &Signature::from_slice(f[&2]).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
    Ok(f[&1])
}
fn fixed<const N: usize>(v: &[u8]) -> io::Result<[u8; N]> {
    v.try_into()
        .map_err(|_| invalid("invalid recovery field width"))
}
fn fresh<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes)
}

pub(crate) fn invitation(session: &[u8], packet: &[u8]) -> io::Result<(Creator, SignedGenesis)> {
    if packet.len() > LIMIT || session.len() != 16 {
        return Err(invalid("invalid invitation size"));
    }
    let f = fields(packet, &[1, 2, 3, 4])?;
    let body = fields(f[&2], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])?;
    if f[&1] != INVITE
        || body[&1] != b"RatRaceSync/genesis/v1"
        || body[&2] != session
        || body[&3].is_empty()
        || body[&3].len() > 64
        || body[&6] != 1u64.to_be_bytes()
        || body[&7].len() != 32
        || body[&7][24..] != 0u64.to_be_bytes()
        || body[&8].len() != 32
        || body[&9] != b"membership-source-1"
        || body[&11] != genesis::profile_manifest(lobby::LobbyFormat::SemanticLinks.profile())
    {
        return Err(invalid("unsupported lobby invitation"));
    }
    let creator = Creator {
        actor: body[&3].into(),
        key: fixed(body[&4])?,
        node: ReplicaId(fixed(body[&5])?),
    };
    let proof = SignedGenesis {
        body: f[&2].into(),
        signature: f[&3].into(),
        fingerprint: fixed(f[&4])?,
    };
    proof.verify(f[&2], &creator)?;
    let members = store::decode::<Members>(body[&10])?;
    if members.get_joint_config().len() != 1
        || !members.voter_ids().eq([creator.node])
        || members.non_write_voter_ids().next().is_some()
    {
        return Err(invalid("invitation requires creator-only genesis"));
    }
    use openraft::entry::RaftPayload;
    if body[&8] != Sha256::digest(Source::blank().with_membership(members).bytes).as_slice() {
        return Err(invalid("genesis membership source digest mismatch"));
    }
    Ok((creator, proof))
}

pub struct Learner {
    pub(crate) node: GameNode,
    pub(crate) id: ReplicaId,
    pub(crate) actor: Vec<u8>,
    pub(crate) key: [u8; 32],
    pub(crate) root: [u8; 32],
    pub(crate) creator: Creator,
    pub(crate) pending: Option<Vec<u8>>,
}
/// Inbound replication for the authenticated creator-only transport. The
/// receiver has no client-write, election or membership-management endpoint.
#[derive(Clone)]
pub struct LearnerReplication {
    raft: Raft,
    replica: Replica,
    creator: ReplicaId,
    local: ReplicaId,
}
impl LearnerReplication {
    pub async fn vote(
        &self,
        sender: ReplicaId,
        request: openraft::raft::VoteRequest<Types>,
        pre_vote: bool,
    ) -> io::Result<openraft::raft::VoteResponse<Types>> {
        self.vote_with_join_source(sender, request, pre_vote, None)
            .await
    }
    /// When the candidate crashed after appending Join but before replication,
    /// its durable effective configuration can be ahead of this receiver.
    pub async fn vote_with_join_source(
        &self,
        sender: ReplicaId,
        request: openraft::raft::VoteRequest<Types>,
        pre_vote: bool,
        source: Option<&[u8]>,
    ) -> io::Result<openraft::raft::VoteResponse<Types>> {
        if sender != self.creator
            || request.vote.leader_id.node_id != sender
            || third::local_route(&self.replica, &*self.replica.lock()?)?.is_some()
        {
            return Err(invalid("vote outside authorized two-voter configuration"));
        }
        if !self.raft.voter_ids().any(|id| id == self.local) {
            self.replica.verify_candidate_join(
                &request,
                pre_vote,
                source.ok_or(invalid("missing candidate's effective Join entry"))?,
            )?;
        }
        if pre_vote {
            self.raft.pre_vote(request).await
        } else {
            self.raft.vote(request).await
        }
        .map_err(io::Error::other)
    }
    pub async fn append_entries(
        &self,
        authenticated_sender: ReplicaId,
        request: openraft::raft::AppendEntriesRequest<Types>,
    ) -> io::Result<openraft::raft::AppendResult<Types>> {
        let route = { third::local_route(&self.replica, &*self.replica.lock()?)? };
        if let Some(route) = route {
            route.check_replication(self.creator, authenticated_sender, &request)?;
            return self
                .raft
                .append_entries(request)
                .await
                .map_err(io::Error::other);
        }
        if authenticated_sender != self.creator || request.vote.leader_id.node_id != self.creator {
            return Err(invalid("replication sender differs from pinned creator"));
        }
        for entry in &request.entries {
            if let Some(raw) = entry.payload.join_command()? {
                self.replica.verify_local_promotion(raw, &entry.payload)?;
                continue;
            }
            if let Some(m) = entry.payload.check_members()? {
                if let Some(member) =
                    store::meta::<JoinedMember>(&*self.replica.lock()?, "first_member")?
                    && entry.log_id.index >= member.log_id.index
                {
                    if member.node == self.local
                        && third::registration(&m, self.creator, member.node)
                    {
                        continue;
                    }
                    return Err(invalid("unrequested change to joined voting membership"));
                }
                let valid_targets = if entry.log_id.index == 0 {
                    m.non_write_voter_ids().next().is_none()
                } else {
                    m.non_write_voter_ids().eq([self.local])
                };
                if !valid_targets
                    || m.get_joint_config().len() != 1
                    || !m.voter_ids().eq([self.creator])
                {
                    return Err(invalid("unsupported learner replication configuration"));
                }
            }
        }
        self.raft
            .append_entries(request)
            .await
            .map_err(io::Error::other)
    }
}
fn signed_admission(
    session: &[u8],
    root: &[u8; 32],
    actor: &[u8],
    id: ReplicaId,
    key: &SigningKey,
) -> Vec<u8> {
    signed(
        &message(&[
            (1, ADMIT),
            (2, session),
            (3, root),
            (4, actor),
            (5, key.verifying_key().as_bytes()),
            (6, &id.0),
        ]),
        key,
    )
}
impl Learner {
    pub fn id(&self) -> ReplicaId {
        self.id
    }
    pub fn replication(&self) -> LearnerReplication {
        LearnerReplication {
            raft: self.node.raft.clone(),
            replica: self.node.replica.clone(),
            creator: self.creator.node,
            local: self.id,
        }
    }
    pub async fn shutdown(&self) -> io::Result<()> {
        self.node.raft.shutdown().await.map_err(io::Error::other)
    }
    pub fn admission(&self, key: &SigningKey) -> io::Result<Vec<u8>> {
        if key.verifying_key().to_bytes() != self.key {
            return Err(invalid("learner signing identity mismatch"));
        }
        Ok(signed_admission(
            &self.node.replica.session,
            &self.root,
            &self.actor,
            self.id,
            key,
        ))
    }
    /// Issue a fresh challenge at the first unverified index. Only the latest
    /// outstanding challenge on this handle may deliver a response.
    pub fn request(&mut self, key: &SigningKey) -> io::Result<Vec<u8>> {
        let admission = self.admission(key)?;
        let db = self.node.replica.lock()?;
        let nonce = fresh::<32>()?;
        let next = history::cursor(&db)?;
        let route = store::meta::<Vec<u8>>(&db, "local_recovery_route")?;
        let body = message(&[
            (1, REQUEST),
            (2, route.as_deref().unwrap_or(&admission)),
            (3, &nonce),
            (4, &next.to_be_bytes()),
        ]);
        self.pending = Some(body.clone());
        Ok(signed(&body, key))
    }
}

fn admission_fields<'a>(
    r: &Replica,
    packet: &'a [u8],
    creator: &Creator,
) -> io::Result<BTreeMap<u32, &'a [u8]>> {
    if packet.len() > 4096 {
        return Err(invalid("admission too large"));
    }
    let body = fields(packet, &[1, 2])?[&1];
    let f = fields(body, &[1, 2, 3, 4, 5, 6])?;
    let key = fixed(f[&5])?;
    authenticate(packet, &key)?;
    if f[&1] != ADMIT
        || f[&2] != r.session
        || Some(&fixed(f[&3])?) != r.bound_root.get()
        || f[&4].is_empty()
        || f[&4].len() > 64
        || f[&4] == creator.actor
        || key == creator.key
        || ReplicaId(fixed(f[&6])?) == creator.node
    {
        return Err(invalid("invalid learner identity or lobby binding"));
    }
    Ok(f)
}
impl CreatorGame {
    /// Share only after the native adapter authenticates and authorizes the peer.
    pub fn learner_invitation(&self) -> io::Result<Vec<u8>> {
        let r = &self.node.replica;
        if r.lobby_format != Some(lobby::LobbyFormat::SemanticLinks) {
            return Err(invalid("unsupported recovery profile"));
        }
        let db = r.lock()?;
        r.require_lobby_genesis(&db)?;
        let proof = store::meta::<SignedGenesis>(&db, "signed_genesis")?
            .ok_or(invalid("missing genesis"))?;
        Ok(message(&[
            (1, INVITE),
            (2, &proof.body),
            (3, &proof.signature),
            (4, &proof.fingerprint),
        ]))
    }
    /// The trusted admission adapter supplies a verified peer's signed intent.
    /// This adds one replication target under the existing sole voter.
    pub async fn admit_learner(&self, admission: &[u8]) -> io::Result<()> {
        self.node
            .raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let r = &self.node.replica;
        let id = {
            let mut db = r.lock()?;
            let tx = db.transaction().map_err(io::Error::other)?;
            r.require_lobby_genesis(&tx)?;
            let creator =
                store::meta::<Creator>(&tx, "creator")?.ok_or(invalid("missing creator"))?;
            if r.lobby_format != Some(lobby::LobbyFormat::SemanticLinks)
                || store::meta::<Vec<u8>>(&tx, "lobby")?.is_none()
                || r.local_node != Some(creator.node)
            {
                return Err(invalid(
                    "learner admission requires the original lobby host",
                ));
            }
            let f = admission_fields(r, admission, &creator)?;
            let id = ReplicaId(fixed(f[&6])?);
            match store::meta::<Vec<u8>>(&tx, "learner_admission")? {
                Some(saved) if saved != admission => {
                    return Err(invalid("another learner owns admission"));
                }
                Some(_) => (),
                None => store::put(&tx, "learner_admission", &admission)?,
            }
            let m = history::membership(&tx)?;
            if !m.membership().voter_ids().eq([creator.node]) {
                return Err(invalid("unsupported voters"));
            }
            let present = m.membership().non_write_voter_ids().eq([id]);
            if !present && m.membership().non_write_voter_ids().next().is_some() {
                return Err(invalid("different learner already registered"));
            }
            tx.commit().map_err(io::Error::other)?;
            if present {
                return Ok(());
            }
            id
        };
        self.node
            .raft
            .add_learner(id, (), false)
            .await
            .map_err(io::Error::other)?;
        Ok(())
    }

    /// A bounded single-index archival proof, or a fresh final checkpoint.
    pub async fn recovery_chunk(&self, request: &[u8], key: &SigningKey) -> io::Result<Vec<u8>> {
        let body = authenticate(request, &{
            if request.len() > 8192 {
                return Err(invalid("request too large"));
            }
            let db = self.node.replica.lock()?;
            let admission = store::meta::<Vec<u8>>(&db, "learner_admission")?
                .ok_or(invalid("no admitted learner"))?;
            fixed(fields(fields(&admission, &[1, 2])?[&1], &[1, 2, 3, 4, 5, 6])?[&5])?
        })?;
        let f = fields(body, &[1, 2, 3, 4])?;
        if f[&1] != REQUEST || f[&3].len() != 32 {
            return Err(invalid("invalid challenge"));
        }
        let index = u64::from_be_bytes(fixed(f[&4])?);
        self.node
            .raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let r = &self.node.replica;
        let mut db = r.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        r.require_lobby_genesis(&tx)?;
        let creator = store::meta::<Creator>(&tx, "creator")?.ok_or(invalid("missing creator"))?;
        let admission = admission_fields(r, f[&2], &creator)?;
        let m = history::membership(&tx)?;
        if creator.key != key.verifying_key().to_bytes()
            || r.local_node != Some(creator.node)
            || !m.membership().voter_ids().eq([creator.node])
            || !m
                .membership()
                .non_write_voter_ids()
                .eq([ReplicaId(fixed(admission[&6])?)])
            || store::meta::<Vec<u8>>(&tx, "learner_admission")?.as_deref() != Some(f[&2])
        {
            return Err(invalid("ineligible recovery peer"));
        }
        let high = history::boundary(&tx)?;
        let end = high.index.checked_add(1).ok_or(invalid("log exhausted"))?;
        if index > end {
            return Err(invalid("cursor beyond applied history"));
        }
        let packet = if index == end {
            r.verify_replay(&tx)?;
            history::checkpoint(r, &tx, high.index)?
        } else {
            history::transfer_piece(r, &tx, index, key)?
        };
        let response = signed(
            &message(&[
                (1, RESPONSE),
                (2, &Sha256::digest(body)),
                (3, &log_key(high)),
                (4, &[u8::from(index == end)]),
                (5, &packet),
            ]),
            key,
        );
        if response.len() > LIMIT {
            return Err(invalid("recovery response exceeds limit"));
        }
        tx.commit().map_err(io::Error::other)?;
        Ok(response)
    }
}
