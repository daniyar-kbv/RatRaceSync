//! Recover a nonvoting installation across the first committed Join.
use super::*;
use openraft::{
    entry::RaftPayload,
    raft::{AppendEntriesRequest, Precondition},
};
mod transfer;
pub(super) use transfer::response_body;

const ROUTE: &[u8] = b"RatRaceSync/learner/two-voter-route/v1";

/// The creator authenticates the second transport identity for bootstrap.
/// The original two-voter certificate is separately checked against local replay.
pub(crate) struct RecoveryRoute {
    learner: ReplicaId,
    learner_key: [u8; 32],
    pub(super) admission: Vec<u8>,
    pub(super) joined: ReplicaId,
    pub(super) joined_key: [u8; 32],
    pub(crate) join: LogId,
    certificate: Vec<u8>,
}

pub(crate) fn registration(m: &Members, creator: ReplicaId, joined: ReplicaId) -> bool {
    m.non_write_voter_ids().next().is_some_and(|learner| {
        m == &Members::new_with_defaults(vec![[creator, joined].into()], [learner])
    })
}

fn creator(db: &Connection) -> io::Result<Creator> {
    store::meta(db, "creator")?.ok_or(invalid("missing creator"))
}
fn member(db: &Connection) -> io::Result<JoinedMember> {
    store::meta(db, "first_member")?.ok_or(invalid("missing first joined voter"))
}

fn require_open_place(db: &Connection) -> io::Result<()> {
    let lobby = seating::layout_at(db, u64::MAX)?;
    if seating::departure::left_at(db, u64::MAX)?.is_some()
        || lobby.seats.capacity().count() <= 2
        || store::meta::<JoinedMember>(db, "third_member")?.is_some()
    {
        return Err(invalid("no open place for an additional player"));
    }
    Ok(())
}
fn support(raw: &[u8]) -> Vec<u8> {
    message(&[
        (1, b"RatRaceSync/nonvoting-recovery-support/v1"),
        (2, &Sha256::digest(raw)),
    ])
}

impl RecoveryRoute {
    pub(super) fn parse(r: &Replica, creator: &Creator, raw: &[u8]) -> io::Result<Self> {
        if raw.len() > 32768 {
            return Err(invalid("oversized recovery route"));
        }
        let f = fields(authenticate(raw, &creator.key)?, &[1, 2, 3, 4, 5, 6])?;
        let admission = admission_fields(r, f[&2], creator)?;
        let learner_key = fixed(admission[&5])?;
        let learner = ReplicaId(fixed(admission[&6])?);
        let joined = ReplicaId(fixed(f[&3])?);
        let joined_key = fixed(f[&4])?;
        if f[&1] != ROUTE
            || learner == joined
            || joined == creator.node
            || learner_key == joined_key
            || joined_key == creator.key
        {
            return Err(invalid("invalid recovery admission or voter bindings"));
        }
        Ok(Self {
            learner,
            learner_key,
            admission: f[&2].to_vec(),
            joined,
            joined_key,
            join: store::decode(f[&5])?,
            certificate: f[&6].to_vec(),
        })
    }
    pub(super) fn check_member(&self, db: &Connection) -> io::Result<()> {
        let m = member(db)?;
        let signed = fields(&self.admission, &[1, 2])?;
        let learner = fields(signed[&1], &[1, 2, 3, 4, 5, 6])?;
        if m.node != self.joined
            || m.key != self.joined_key
            || m.log_id != self.join
            || learner[&4] == m.actor
        {
            return Err(invalid("route differs from replayed membership"));
        }
        Ok(())
    }
    pub(crate) fn verify_historical_join(
        &self,
        r: &Replica,
        db: &Connection,
        k: LogId,
    ) -> io::Result<()> {
        self.check_member(db)?;
        if k != self.join {
            return Err(invalid("unexpected recovery Join"));
        }
        quorum::verify_certificate(r, db, k.index, &self.certificate)
    }
    pub(super) fn check_replication(
        &self,
        creator: ReplicaId,
        sender: ReplicaId,
        req: &AppendEntriesRequest<Types>,
    ) -> io::Result<()> {
        if ![creator, self.joined].contains(&sender) || req.vote.leader_id.node_id != sender {
            return Err(invalid("unrecognized recovery leader"));
        }
        for e in &req.entries {
            // The replication handler separately verifies departures against the retained prefix.
            if e.payload.leave_source()?.is_some() {
                continue;
            }
            let Some(m) = e.payload.check_members()? else {
                continue;
            };
            let expected = if e.log_id == self.join {
                e.payload.join_command()?.is_some() && m == join::target(creator, self.joined)
            } else if e.log_id.index < self.join.index {
                let learners = if e.log_id.index == 0 {
                    vec![]
                } else {
                    vec![self.joined]
                };
                e.payload.join_command()?.is_none()
                    && m == Members::new_with_defaults(vec![[creator].into()], learners)
            } else if m == join::target(creator, self.learner) {
                e.payload.join_command()?.is_some()
            } else if m.voter_ids().count() == 3 {
                // The receiver verifies the complete signed promotion before this check.
                e.payload.join_command()?.is_some()
                    && m == Members::new_with_defaults(
                        vec![[creator, self.joined, self.learner].into()],
                        [],
                    )
            } else {
                e.payload.join_command()?.is_none()
                    && registration(&m, creator, self.joined)
                    && m.non_write_voter_ids().eq([self.learner])
            };
            if !expected {
                return Err(invalid("unexpected recovery membership"));
            }
        }
        Ok(())
    }
}
pub(crate) fn local_route(r: &Replica, db: &Connection) -> io::Result<Option<RecoveryRoute>> {
    let Some(raw) = store::meta::<Vec<u8>>(db, "local_recovery_route")? else {
        return Ok(None);
    };
    let route = RecoveryRoute::parse(r, &creator(db)?, &raw)?;
    if Some(route.learner) != r.local_node
        || store::meta::<Vec<u8>>(db, "local_learner_admission")?.as_ref() != Some(&route.admission)
    {
        return Err(invalid("route belongs to another learner"));
    }
    Ok(Some(route))
}
impl Learner {
    /// Pin bootstrap transport authority before accepting either voter's replication.
    pub fn authorize_recovery_route(&self, raw: &[u8]) -> io::Result<()> {
        let r = &self.node.replica;
        let route = RecoveryRoute::parse(r, &self.creator, raw)?;
        let mut db = r.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        if route.learner != self.id
            || store::meta::<Vec<u8>>(&tx, "local_learner_admission")?.as_ref()
                != Some(&route.admission)
        {
            return Err(invalid("wrong recipient for recovery route"));
        }
        if let Some(saved) = store::meta::<Vec<u8>>(&tx, "local_recovery_route")? {
            if saved == raw {
                return Ok(());
            }
            return Err(invalid("conflicting pinned recovery route"));
        }
        if store::meta::<LogId>(&tx, "applied")?.is_some()
            || store::meta::<Vec<u8>>(&tx, "local_join")?.is_some()
        {
            return Err(invalid("cannot replace prior learner participation"));
        }
        store::put(&tx, "local_recovery_route", &raw)?;
        tx.commit().map_err(io::Error::other)
    }
}
impl GameNode {
    /// Finish outstanding historical signatures and storage acknowledgments for
    /// the committed tail. Resume at the first unfinished checkpoint after Join.
    pub async fn certify_recovery_tail(
        &self,
        key: &SigningKey,
        mut peer: impl AsyncFnMut(VotingHistoryRequest) -> io::Result<Vec<u8>>,
    ) -> io::Result<()> {
        let r = &self.replica;
        let (join, high, reconcile_range) = {
            let db = r.lock()?;
            (
                member(&db)?.log_id,
                history::boundary(&db)?,
                store::meta::<JoinedMember>(&db, "third_member")?.is_some()
                    || seating::departure::last_guest_at(&db, u64::MAX)?.is_some(),
            )
        };
        if reconcile_range {
            return self.reconcile_voting_history(high, key, peer).await;
        }
        if !self.voting_history_complete(join)? {
            return Err(invalid("original Join history handoff incomplete"));
        }
        for i in join.index.saturating_add(1)..=high.index {
            let k = {
                let db = r.lock()?;
                let raw: Vec<u8> = db
                    .query_row(
                        "SELECT entry FROM raft_log WHERE idx=?",
                        [i.to_be_bytes()],
                        |row| row.get(0),
                    )
                    .map_err(io::Error::other)?;
                store::decode::<Entry>(&raw)?.log_id
            };
            if !self.voting_history_complete(k)? {
                self.reconcile_voting_history(k, key, &mut peer).await?;
            }
        }
        Ok(())
    }
    /// Issue a route for an authenticated prospective player in the open lobby.
    pub fn recovery_route(&self, admission: &[u8], key: &SigningKey) -> io::Result<Vec<u8>> {
        if admission.len() > 4096 {
            return Err(invalid("oversized learner admission"));
        }
        let r = &self.replica;
        let db = r.lock()?;
        let creator = creator(&db)?;
        if Some(creator.node) != r.local_node || &creator.key != key.verifying_key().as_bytes() {
            return Err(invalid("creator signature required"));
        }
        r.require_lobby_genesis(&db)?;
        r.verify_replay(&db)?;
        let m = member(&db)?;
        let cert = history::get(&db, m.log_id.index)?.ok_or(invalid("missing Join certificate"))?;
        let raw = signed(
            &message(&[
                (1, ROUTE),
                (2, admission),
                (3, &m.node.0),
                (4, &m.key),
                (5, &store::encode(&m.log_id)?),
                (6, &cert),
            ]),
            key,
        );
        let route = RecoveryRoute::parse(r, &creator, &raw)?;
        route.verify_historical_join(r, &db, m.log_id)?;
        require_open_place(&db)?;
        let slot = format!("issued_recovery_route_{}", route.learner);
        if let Some(saved) = store::meta::<Vec<u8>>(&db, &slot)? {
            if saved != raw {
                return Err(invalid("conflicting recipient for reserved node"));
            }
        } else {
            if history::membership(&db)?
                .membership()
                .non_write_voter_ids()
                .next()
                .is_some()
            {
                return Err(invalid("another recovery reservation is active"));
            }
            store::put(&db, &slot, &raw)?;
        }
        Ok(raw)
    }
    /// Confirm the joined voter's support for this recovery profile before a
    /// leader proposes a configuration an earlier implementation cannot apply.
    pub fn confirm_recovery_support(&self, raw: &[u8], key: &SigningKey) -> io::Result<Vec<u8>> {
        let r = &self.replica;
        let db = r.lock()?;
        let route = RecoveryRoute::parse(r, &creator(&db)?, raw)?;
        if Some(route.joined) != r.local_node || &route.joined_key != key.verifying_key().as_bytes()
        {
            return Err(invalid("joined voter support required"));
        }
        r.require_lobby_genesis(&db)?;
        r.verify_replay(&db)?;
        route.verify_historical_join(r, &db, route.join)?;
        require_open_place(&db)?;
        seating::departure::reject_departed(&db, route.joined, None)?;
        Ok(signed(&support(raw), key))
    }
    /// Add only a replication target. The two-member voting quorum stays intact.
    pub async fn admit_recovery_learner(
        &self,
        raw: &[u8],
        confirmation: &[u8],
    ) -> io::Result<LogId> {
        self.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let r = &self.replica;
        let (members, high, prior) = {
            let db = r.lock()?;
            let creator = creator(&db)?;
            let route = RecoveryRoute::parse(r, &creator, raw)?;
            if authenticate(confirmation, &route.joined_key)? != support(raw) {
                return Err(invalid(
                    "recovery capability differs from proposed registration",
                ));
            }
            require_open_place(&db)?;
            r.require_lobby_genesis(&db)?;
            r.verify_replay(&db)?;
            route.verify_historical_join(r, &db, route.join)?;
            let m = history::membership(&db)?;
            let prior = m.log_id().ok_or(invalid("missing effective membership"))?;
            let voters = join::target(creator.node, route.joined);
            let target =
                Members::new_with_defaults(voters.get_joint_config().clone(), [route.learner]);
            if m.membership() == &target {
                return Ok(prior);
            }
            if m.membership() != &voters {
                return Err(invalid("another learner or voter configuration is active"));
            }
            (target, history::boundary(&db)?, prior)
        };
        if !self.voting_history_complete(high)? {
            return Err(invalid("predecessor history handoff pending"));
        }
        let res = self
            .raft
            .append_membership(
                members,
                Source::blank(),
                [
                    Precondition::CommittedLeaderId {
                        committed_leader_id: high.leader_id,
                    },
                    Precondition::LastLogId {
                        last_log_id: Some(high),
                    },
                    Precondition::LastMembershipLogId {
                        last_membership_log_id: Some(prior),
                    },
                ],
            )
            .await
            .map_err(io::Error::other)?;
        Ok(res.log_id)
    }
}
