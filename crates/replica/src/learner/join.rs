//! Direct, source-bearing promotion of verified lobby learners.
use super::*;
mod authority;
pub use authority::PromotionAuthority;
mod delivery;
pub use delivery::ThirdJoinTransport;
mod election;
pub(super) mod promotion;
use crate::{
    application::ReceiptRecord,
    lobby::{frame, persist_link},
};
use openraft::{entry::RaftPayload, raft::Precondition, type_config::TypeConfigExt};
use serde::{Deserialize, Serialize};

const WITNESS: &[u8] = b"RatRaceSync/verified-join-prefix/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinedMember {
    pub actor: Vec<u8>,
    pub key: [u8; 32],
    pub node: ReplicaId,
    pub ordinal: u32,
    pub setup_revision: u64,
    pub layout_revision: u64,
    pub log_id: LogId,
    pub membership_before: LogId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinResult {
    pub log_id: LogId,
    pub member: JoinedMember,
    pub receipt: Vec<u8>,
}
pub struct JoinDelivery {
    pub join: JoinResult,
    /// A storage or transport failure here leaves the authentic Join committed.
    pub history: io::Result<()>,
}

struct Intent<'a> {
    // Present only in the learner-signed witness for a Join from the post-Leave singleton.
    recovery_route: Option<&'a [u8]>,
    approvals: Option<[&'a [u8]; 2]>,
    actor: &'a [u8],
    key: [u8; 32],
    node: ReplicaId,
    request: [u8; 16],
    admission: &'a [u8],
    membership: &'a [u8],
    setup: u64,
    layout: u64,
    fingerprint: [u8; 32],
    prefix: &'a [u8],
    sealed: &'a [u8],
}
fn parse<'a>(r: &Replica, raw: &'a [u8]) -> io::Result<Intent<'a>> {
    if raw.len() > 16384 {
        return Err(invalid("oversized Join"));
    }
    let outer = fields(raw, &[1, 2]).or_else(|_| fields(raw, &[1, 2, 3, 4]))?;
    let envelope = fields(outer[&1], &[1, 2])?;
    let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12])?;
    let action = fields(fields(body[&12], &[202])?[&202], &[1, 2])?;
    let admission = action[&2];
    let binding = fields(fields(admission, &[1, 2])?[&1], &[1, 2, 3, 4, 5, 6])?;
    let actor = body[&3];
    let node = ReplicaId(fixed(action[&1])?);
    let key = fixed(binding[&5])?;
    let root = r.bound_root.get().ok_or(invalid("unverified Join root"))?;
    let request = fixed::<16>(body[&4])?;
    if !r
        .lobby_format
        .is_some_and(lobby::LobbyFormat::semantic_links)
        || body[&1] != r.profile()
        || body[&2] != r.session
        || actor.is_empty()
        || actor.len() > 64
        || request[6] >> 4 != 4
        || request[8] >> 6 != 2
        || binding[&1] != ADMIT
        || binding[&2] != r.session
        || binding[&3] != root
        || binding[&4] != actor
        || binding[&6] != node.0
    {
        return Err(invalid("Join identity, request or profile mismatch"));
    }
    authenticate(admission, &key)?;
    authenticate(outer[&1], &key)?;
    let guard = fields(body[&5], &[1, 2, 3])?;
    let setup = u64::from_be_bytes(fixed(guard[&1])?);
    let layout = u64::from_be_bytes(fixed(guard[&2])?);
    let membership = guard[&3];
    let fp = wire::hash(
        b"join-intent/v1",
        &[
            r.profile(),
            &r.session,
            root,
            actor,
            &key,
            &node.0,
            &request,
            guard[&1],
            guard[&2],
            membership,
            &202u16.to_be_bytes(),
        ],
    );
    let signed_witness = authenticate(outer[&2], &key)?;
    let witness = fields(signed_witness, &[1, 2, 3, 4])
        .or_else(|_| fields(signed_witness, &[1, 2, 3, 4, 5]))?;
    if membership.len() != 32
        || witness[&1] != WITNESS
        || witness[&2] != fp
        || witness[&3].len() != 32
        || witness[&4].len() != 32
    {
        return Err(invalid("invalid verified Join prefix witness"));
    }
    Ok(Intent {
        recovery_route: witness.get(&5).copied(),
        approvals: outer.get(&3).map(|a| [*a, outer[&4]]),
        actor,
        key,
        node,
        request,
        admission,
        membership,
        setup,
        layout,
        fingerprint: fp,
        prefix: witness[&3],
        sealed: witness[&4],
    })
}

pub(super) fn sealed_range(
    r: &Replica,
    db: &Connection,
    key: &[u8; 32],
    high: LogId,
) -> io::Result<[u8; 32]> {
    history::verify_prefix(r, db, key, high)?;
    let mut sha = Sha256::new();
    sha.update(b"RatRaceSync/sealed-prefix/1");
    let mut stmt = db
        .prepare("SELECT certificate FROM historic_seal WHERE idx<=? ORDER BY idx")
        .map_err(io::Error::other)?;
    let mut rows = stmt
        .query([high.index.to_be_bytes()])
        .map_err(io::Error::other)?;
    while let Some(row) = rows.next().map_err(io::Error::other)? {
        sha.update(Sha256::digest(
            row.get::<_, Vec<u8>>(0).map_err(io::Error::other)?,
        ));
    }
    Ok(sha.finalize().into())
}
fn retired_join_key(request: [u8; 16]) -> String {
    format!("retired_join_{:032x}", u128::from_be_bytes(request))
}

impl InstallationCatalog {
    /// Deliver Join when the creator is the sole voter, including after a departure. Both
    /// exchanges use already authenticated peer transports. Repeating this
    /// operation after a disconnect reuses the durable player request.
    pub async fn join_first_player(
        &self,
        learner: &Learner,
        key: &SigningKey,
        request: [u8; 16],
        profile_complete: bool,
        submit: impl AsyncFnOnce(Vec<u8>) -> io::Result<JoinResult>,
        exchange: impl AsyncFnMut(VotingHistoryRequest) -> io::Result<Vec<u8>>,
    ) -> io::Result<JoinDelivery> {
        let raw = self.prepare_join(learner, key, request, profile_complete)?;
        let reported = submit(raw.clone()).await?;
        self.finish_join(learner, key, &raw, reported, exchange)
            .await
    }
    async fn finish_join(
        &self,
        learner: &Learner,
        key: &SigningKey,
        raw: &[u8],
        reported: JoinResult,
        exchange: impl AsyncFnMut(VotingHistoryRequest) -> io::Result<Vec<u8>>,
    ) -> io::Result<JoinDelivery> {
        learner
            .node
            .raft
            .wait(Some(std::time::Duration::from_secs(10)))
            .applied_index_at_least(Some(reported.log_id.index), "local Join")
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?;
        let node = learner.joined_node()?;
        let original = original_join(&*node.replica.lock()?, &parse(&node.replica, raw)?)?
            .ok_or(invalid("missing local Join receipt"))?;
        if original != reported {
            return Err(invalid(
                "leader and joining voter disagree on original receipt",
            ));
        }
        let history = node
            .reconcile_voting_history(original.log_id, key, exchange)
            .await;
        Ok(JoinDelivery {
            join: original,
            history,
        })
    }
    /// Persist the player's original signed intent before exposing it to transport.
    /// A newer verified protocol prefix may refresh its separate readiness witness.
    pub fn prepare_join(
        &self,
        learner: &Learner,
        key: &SigningKey,
        request: [u8; 16],
        profile_complete: bool,
    ) -> io::Result<Vec<u8>> {
        self.prepare_intent(learner, key, request, profile_complete, false)
    }
    fn prepare_intent(
        &self,
        learner: &Learner,
        key: &SigningKey,
        request: [u8; 16],
        profile_complete: bool,
        third_player: bool,
    ) -> io::Result<Vec<u8>> {
        let verified = self.verified_join_prefix(learner)?;
        let admission = learner.admission(key)?;
        let r = &learner.node.replica;
        let mut db = r.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        let routed = third::local_route(r, &tx)?.is_some();
        let replacement =
            routed && seating::departure::last_guest_at(&tx, verified.index)?.is_some();
        if (routed && !replacement) != third_player {
            return Err(invalid("incorrect admission for this Join"));
        }
        let saved = store::meta::<Vec<u8>>(&tx, "local_join")?;
        let previous = saved.as_deref().map(|raw| parse(r, raw)).transpose()?;
        let promotion = store::meta::<Vec<u8>>(&tx, "third_proposal")?;
        if let Some(approved) = &promotion {
            let approved = parse(r, approved)?;
            if !(third_player || replacement)
                || previous
                    .as_ref()
                    .is_none_or(|draft| draft.fingerprint != approved.fingerprint)
            {
                return Err(invalid("promotion lacks its matching reserved intent"));
            }
            approved.verify_approvals(&tx, &learner.creator, 3)?;
        }
        let occupied = store::meta::<JoinedMember>(
            &tx,
            if routed {
                "third_member"
            } else {
                "first_member"
            },
        )?
        .is_some();
        if let (Some(raw), Some(original)) = (&saved, &previous) {
            if original.admission != admission {
                return Err(invalid("unexpected reserved Join identity"));
            }
            if occupied {
                if original.request != request {
                    return Err(invalid("another Join owns this reservation"));
                }
                return Ok(raw.clone());
            }
        }
        let replacing = previous.as_ref().is_some_and(|old| old.request != request);
        if (previous.is_none() || replacing) && !profile_complete {
            return Err(invalid("complete local profile required"));
        }
        if history::boundary(&tx)? != verified {
            return Err(invalid("refresh verified learner prefix"));
        }
        let lobby = seating::layout_at(&tx, verified.index)?;
        if r.lobby_format.is_some_and(lobby::LobbyFormat::resizable) {
            if store::meta::<Vec<u8>>(&tx, &retired_join_key(request))?.is_some() {
                return Err(invalid("obsolete Join request"));
            }
            if third_player && lobby.seats.capacity().count() < 3 {
                return Err(invalid("no open place for an additional player"));
            }
        }
        if let Some(old) = previous.as_ref().filter(|_| replacing) {
            // A newer layout, or a newer setup for a replacement Join, invalidates the old guard.
            // The original request remains retired once the new intent takes its place.
            if r.lobby_format.is_none_or(|f| !f.resizable())
                || (old.layout >= lobby.layout_revision
                    && !(replacement && old.setup < seating::setup_revision(&tx)?))
                || original_join(&tx, old)?.is_some()
            {
                return Err(invalid("another Join owns this reservation"));
            }
            let old_raw = saved.as_deref().ok_or(invalid("missing reserved Join"))?;
            if promotion.is_some() {
                tx.execute("DELETE FROM meta WHERE name='third_proposal'", [])
                    .map_err(io::Error::other)?;
            }
            store::put(
                &tx,
                &retired_join_key(old.request),
                &promotion.as_deref().unwrap_or(old_raw),
            )?;
        }
        let m = history::membership(&tx)?;
        let membership = log_key(m.log_id().ok_or(invalid("missing membership source"))?);
        let setup = seating::setup_revision(&tx)?.to_be_bytes();
        let layout = lobby.layout_revision.to_be_bytes();
        let guard = message(&[(1, &setup), (2, &layout), (3, &membership)]);
        let leaf = message(&[(1, &learner.id.0), (2, &admission)]);
        let intent = signed(
            &message(&[
                (1, r.profile()),
                (2, &r.session),
                (3, &learner.actor),
                (4, &request),
                (5, &guard),
                (12, &message(&[(202, &leaf)])),
            ]),
            key,
        );
        let fp = wire::hash(
            b"join-intent/v1",
            &[
                r.profile(),
                &r.session,
                &learner.root,
                &learner.actor,
                &learner.key,
                &learner.id.0,
                &request,
                &setup,
                &layout,
                &membership,
                &202u16.to_be_bytes(),
            ],
        );
        let coverage = sealed_range(r, &tx, &learner.creator.key, verified)?;
        let mut witness = message(&[
            (1, WITNESS),
            (2, &fp),
            (3, &log_key(verified)),
            (4, &coverage),
        ]);
        if replacement {
            let route = store::meta::<Vec<u8>>(&tx, "local_recovery_route")?
                .ok_or(invalid("missing recovery route"))?;
            wire::field(&mut witness, 5, &route);
        }
        let witness = signed(&witness, key);
        let raw = message(&[(1, &intent), (2, &witness)]);
        let checked = parse(r, &raw)?;
        if !replacing && previous.is_some_and(|old| old.fingerprint != checked.fingerprint) {
            return Err(invalid("original Join guard changed"));
        }
        store::put(&tx, "local_join", &raw)?;
        tx.commit().map_err(io::Error::other)?;
        Ok(raw)
    }
    pub fn pending_join(&self, learner: &Learner) -> io::Result<Vec<u8>> {
        self.verified_join_prefix(learner)?;
        let db = learner.node.replica.lock()?;
        learner
            .saved_proposal(&db)?
            .ok_or(invalid("no pending Join"))
    }
}
impl Learner {
    fn saved_proposal(&self, db: &Connection) -> io::Result<Option<Vec<u8>>> {
        let r = &self.node.replica;
        let draft = store::meta::<Vec<u8>>(db, "local_join")?;
        let route = third::local_route(r, db)?;
        let raw = match (route.as_ref(), draft.as_ref()) {
            (Some(_), Some(raw)) if parse(r, raw)?.recovery_route.is_none() => {
                store::meta(db, "third_proposal")?
            }
            _ => draft,
        };
        if let Some(raw) = &raw {
            let intent = parse(r, raw)?;
            intent.verify_approvals(db, &self.creator, if route.is_some() { 3 } else { 2 })?;
        }
        Ok(raw)
    }
}

pub(super) fn target(creator: ReplicaId, peer: ReplicaId) -> Members {
    Members::new_with_defaults(vec![[creator, peer].into()], [])
}

impl Intent<'_> {
    fn check_creator_recovery(
        &self,
        r: &Replica,
        db: &Connection,
        creator: &Creator,
        high: LogId,
    ) -> io::Result<()> {
        if let Some(route) = self.recovery_route {
            let saved =
                store::meta::<Vec<u8>>(db, &format!("issued_recovery_route_{}", self.node))?;
            if r.local_node != Some(creator.node) || saved.as_deref() != Some(route) {
                return Err(invalid("unrecognized registered learner"));
            }
            if !quorum::history_complete(r, db, high)? {
                return Err(invalid("predecessor history handoff pending"));
            }
        }
        Ok(())
    }
    fn validate(&self, r: &Replica, db: &Connection, creator: &Creator) -> io::Result<Transition> {
        let prev = history::membership(db)?;
        let prior = prev
            .log_id()
            .ok_or(invalid("missing committed membership"))?;
        let lobby = seating::layout_at(db, u64::MAX)?;
        let first = store::meta::<JoinedMember>(db, "first_member")?;
        let (prior_voters, target, ordinal, slot) = if let Some(member) = first {
            if self.actor == member.actor
                || self.key == member.key
                || self.node == member.node
                || store::meta::<JoinedMember>(db, "third_member")?.is_some()
            {
                return Err(invalid("occupied third player identity or slot"));
            }
            if let Some(raw) = self.recovery_route {
                // Keep the first guest's binding and ordinal in history. Only the creator
                // and the registered learner belong to the successor voting configuration.
                let route = third::RecoveryRoute::parse(r, creator, raw)?;
                route.verify_historical_join(r, db, member.log_id)?;
                let departure = seating::departure::last_guest_at(db, u64::MAX)?
                    .ok_or(invalid("missing singleton departure"))?;
                if departure.node != member.node
                    || prior != departure.log_id
                    || route.admission != self.admission
                    || self.approvals.is_some()
                {
                    return Err(invalid("invalid post-departure admission"));
                }
                (
                    Members::new_with_defaults(vec![[creator.node].into()], []),
                    target(creator.node, self.node),
                    3,
                    "third_member",
                )
            } else {
                (
                    target(creator.node, member.node),
                    promotion::roster(creator.node, member.node, self.node),
                    3,
                    "third_member",
                )
            }
        } else {
            if self.recovery_route.is_some() {
                return Err(invalid("unexpected post-departure admission"));
            }
            (
                Members::new_with_defaults(vec![[creator.node].into()], []),
                target(creator.node, self.node),
                2,
                "first_member",
            )
        };
        if prev.membership().get_joint_config().len() != 1
            || prev.membership().get_joint_config() != prior_voters.get_joint_config()
            || !prev.membership().non_write_voter_ids().eq([self.node])
            || self.actor == creator.actor
            || self.key == creator.key
            || self.node == creator.node
            || self.membership != log_key(prior)
            || self.setup != seating::setup_revision(db)?
            || self.layout != lobby.layout_revision
            || usize::from(lobby.seats.capacity().count()) < target.voter_ids().count()
        {
            return Err(invalid("stale or ineligible Join"));
        }
        Ok(Transition {
            prior,
            target,
            ordinal,
            slot,
        })
    }
}
struct Transition {
    prior: LogId,
    target: Members,
    ordinal: u32,
    slot: &'static str,
}

impl GameNode {
    /// Submit to the established leader, or reconcile the immutable receipt after lost delivery.
    pub async fn join_lobby(&self, raw: &[u8]) -> io::Result<JoinResult> {
        let r = &self.replica;
        let intent = parse(r, raw)?;
        let permit = self
            .lock_request((intent.actor.to_vec(), intent.request))
            .await?;
        self.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let (high, prior, members) = {
            let db = r.lock()?;
            r.require_lobby_genesis(&db)?;
            r.verify_replay(&db)?;
            if let Some(result) = original_join(&db, &intent)? {
                return Ok(result);
            }
            let creator =
                store::meta::<Creator>(&db, "creator")?.ok_or(invalid("missing creator"))?;
            let change = intent.validate(r, &db, &creator)?;
            intent.verify_approvals(&db, &creator, change.ordinal)?;
            let high = history::boundary(&db)?;
            if change.ordinal == 3 && intent.prefix != log_key(high) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "refresh verified learner prefix",
                ));
            }
            if (change.ordinal == 2
                && (r.local_node != Some(creator.node)
                    || store::meta::<Vec<u8>>(&db, "learner_admission")?.as_deref()
                        != Some(intent.admission)))
                || intent.prefix != log_key(high)
                || intent.sealed != sealed_range(r, &db, &creator.key, high)?
            {
                return Err(invalid("Join lacks matching verified prefix and admission"));
            }
            intent.check_creator_recovery(r, &db, &creator, high)?;
            (high, change.prior, change.target)
        };
        let raft = self.raft.clone();
        let source = Source::blank().with_normal(Signed(raw.to_vec()));
        let response = Types::spawn(async move {
            let _permit = permit;
            raft.append_membership(
                members,
                source,
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
        })
        .await
        .map_err(io::Error::other)?
        .map_err(io::Error::other)?;
        let db = r.lock()?;
        let result = original_join(&db, &intent)?.ok_or(invalid("missing applied Join"))?;
        if response.log_id != result.log_id
            || response.data != Reply::Receipt(result.receipt.clone())
        {
            return Err(invalid("Join response differs from durable apply"));
        }
        Ok(result)
    }
}
fn original_join(db: &Connection, intent: &Intent<'_>) -> io::Result<Option<JoinResult>> {
    let row = db
        .query_row(
            "SELECT fingerprint,record FROM receipt WHERE actor=? AND request=?",
            params![intent.actor, intent.request],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(io::Error::other)?;
    let Some((fp, receipt)) = row else {
        return Ok(None);
    };
    if fp != intent.fingerprint {
        return Err(invalid("Join request ID conflict"));
    }
    let member = member_for(db, intent.node)?.ok_or(invalid("missing joined member"))?;
    Ok(Some(JoinResult {
        log_id: member.log_id,
        member,
        receipt,
    }))
}
pub(super) fn member_for(db: &Connection, node: ReplicaId) -> io::Result<Option<JoinedMember>> {
    for slot in ["first_member", "third_member"] {
        if let Some(m) = store::meta::<JoinedMember>(db, slot)?
            && m.node == node
        {
            return Ok(Some(m));
        }
    }
    Ok(None)
}

impl Replica {
    pub(super) fn check_join_catalog_coverage(
        &self,
        db: &Connection,
        local: ReplicaId,
        verified: Option<LogId>,
    ) -> io::Result<()> {
        // An installation can stage recovery before activation. Signing a Join or
        // becoming a member requires an independently verified catalog prefix.
        if let Some(raw) = store::meta::<Vec<u8>>(db, "local_join")? {
            let intent = parse(self, &raw)?;
            let index = u64::from_be_bytes(fixed(&intent.prefix[24..])?);
            if intent.node != local
                || verified.is_none_or(|k| {
                    k.index < index || (k.index == index && log_key(k) != intent.prefix)
                })
            {
                return Err(invalid("reserved Join exceeds verified catalog prefix"));
            }
        }
        if let Some(member) = member_for(db, local)?
            && verified.is_none_or(|k| k.index < member.log_id.index.saturating_sub(1))
        {
            return Err(invalid("local membership exceeds verified catalog prefix"));
        }
        Ok(())
    }

    pub(crate) fn has_first_join_source(&self) -> io::Result<bool> {
        let db = self.lock()?;
        if store::meta::<JoinedMember>(&db, "first_member")?.is_some() {
            return Ok(true);
        }
        let applied =
            store::meta::<LogId>(&db, "applied")?.ok_or(invalid("missing applied lobby"))?;
        let mut stmt = db
            .prepare("SELECT entry FROM raft_log WHERE idx>? ORDER BY idx")
            .map_err(io::Error::other)?;
        let mut rows = stmt
            .query([applied.index.to_be_bytes()])
            .map_err(io::Error::other)?;
        while let Some(row) = rows.next().map_err(io::Error::other)? {
            let raw: Vec<u8> = row.get(0).map_err(io::Error::other)?;
            if store::decode::<Entry>(&raw)?
                .payload
                .join_command()?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn verify_join_coverage(&self, db: &Connection, raw: &[u8]) -> io::Result<()> {
        let intent = parse(self, raw)?;
        let creator = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
        let index = u64::from_be_bytes(fixed(&intent.prefix[24..])?);
        let bytes: Vec<u8> = db
            .query_row(
                "SELECT entry FROM raft_log WHERE idx=?",
                [index.to_be_bytes()],
                |r| r.get(0),
            )
            .map_err(io::Error::other)?;
        let high = store::decode::<Entry>(&bytes)?.log_id;
        if log_key(high) != intent.prefix
            || sealed_range(self, db, &creator.key, high)? != intent.sealed
        {
            return Err(invalid("verified Join history differs from signed prefix"));
        }
        Ok(())
    }
    pub(super) fn verify_local_promotion(&self, raw: &[u8], payload: &Source) -> io::Result<()> {
        let intent = parse(self, raw)?;
        let db = self.lock()?;
        self.require_lobby_genesis(&db)?;
        self.verify_join_coverage(&db, raw)?;
        let saved = store::meta::<Vec<u8>>(&db, "local_join")?
            .ok_or(invalid("unrequested voter promotion"))?;
        let approved = parse(self, &saved)?;
        let creator =
            store::meta::<Creator>(&db, "creator")?.ok_or(invalid("missing original creator"))?;
        if intent.fingerprint != approved.fingerprint
            || intent.prefix != approved.prefix
            || intent.sealed != approved.sealed
            || self.local_node != Some(intent.node)
            || payload.check_members()?.as_ref() != Some(&target(creator.node, intent.node))
        {
            return Err(invalid("unexpected voter promotion"));
        }
        Ok(())
    }
    pub(crate) fn apply_join(
        &self,
        db: &Connection,
        k: LogId,
        m: &Members,
        raw: &[u8],
        digest: &[u8],
    ) -> io::Result<Vec<u8>> {
        let command = parse(self, raw)?;
        let creator = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
        let change = command.validate(self, db, &creator)?;
        command.verify_approvals(db, &creator, change.ordinal)?;
        let prior = change.prior;
        let prev = store::meta::<LogId>(db, "applied")?.ok_or(invalid("no verified prefix"))?;
        if (command.recovery_route.is_some() && k.leader_id.node_id != creator.node)
            || k.leader_id != prev.leader_id
            || command.prefix != log_key(prev)
            || m != &change.target
            || original_join(db, &command)?.is_some()
        {
            return Err(invalid("invalid committed Join transition"));
        }
        let member = JoinedMember {
            actor: command.actor.into(),
            key: command.key,
            node: command.node,
            ordinal: change.ordinal,
            setup_revision: command
                .setup
                .checked_add(1)
                .ok_or(invalid("setup revision overflow"))?,
            layout_revision: command.layout,
            log_id: k,
            membership_before: prior,
        };
        let kbytes = log_key(k);
        // Playing disposition and seat eligibility. No claimed seat, private selection or Ready.
        let outcome = message(&[
            (1, &member.actor),
            (2, &member.ordinal.to_be_bytes()),
            (3, &[1]),
            (4, &[1]),
            (5, &kbytes),
            (
                6,
                &message(&[
                    (1, &member.key),
                    (2, &member.node.0),
                    (3, &1u64.to_be_bytes()),
                ]),
            ),
            (7, &member.setup_revision.to_be_bytes()),
            (8, &member.layout_revision.to_be_bytes()),
            (9, &log_key(prior)),
            (10, &store::encode(m)?),
        ]);
        let (events, prev_event) = self.tip(db, "event")?;
        let (receipts, prev_receipt) = self.tip(db, "receipt")?;
        if !self.seating_enabled()
            && (events, receipts) != (i64::from(change.ordinal) - 1, i64::from(change.ordinal) - 1)
        {
            return Err(invalid("unexpected history before Join"));
        }
        let sequence = events.checked_add(1).ok_or(invalid("event range"))?;
        let receipt_seq = receipts.checked_add(1).ok_or(invalid("receipt range"))?;
        let seq = sequence.to_be_bytes();
        let id = wire::hash(b"event-id", &[&self.session, &kbytes, &seq]);
        let mut facts = vec![
            self.profile(),
            self.session.as_slice(),
            command.actor,
            &command.request,
            &command.fingerprint,
            &kbytes,
            &seq,
            &id,
        ];
        let op = 202u16.to_be_bytes();
        let voter_ids: Vec<_> = m.voter_ids().collect();
        let ordered = frame(&voter_ids.iter().map(|v| v.0.as_slice()).collect::<Vec<_>>());
        let result_facts = frame(&[
            &member.actor,
            &member.ordinal.to_be_bytes(),
            &[1],
            &[1],
            &kbytes,
            &member.key,
            &member.node.0,
            &1u64.to_be_bytes(),
            &member.setup_revision.to_be_bytes(),
            &member.layout_revision.to_be_bytes(),
            &log_key(prior),
            &ordered,
        ]);
        facts.extend_from_slice(&[&op, &result_facts]);
        let semantic = frame(&facts);
        let et = persist_link(
            db,
            "event",
            sequence,
            b"event-step/v2",
            &prev_event,
            &frame(&[b"MemberJoined/v1", &semantic]),
        )?;
        let receipt_fields = if self.seating_enabled() {
            frame(&[
                b"JoinReceipt/v2",
                &receipt_seq.to_be_bytes(),
                &12u16.to_be_bytes(),
                &semantic,
            ])
        } else {
            frame(&[b"JoinReceipt/v1", &12u16.to_be_bytes(), &semantic])
        };
        let rt = persist_link(
            db,
            "receipt",
            receipt_seq,
            b"receipt-step/v2",
            &prev_receipt,
            &receipt_fields,
        )?;
        let event = message(&[
            (1, &self.session),
            (2, &kbytes),
            (3, &seq),
            (4, &id),
            (5, &command.fingerprint),
            (6, &outcome),
            (7, digest),
        ]);
        let result = message(&[(12, &message(&[(202, &outcome)]))]);
        let receipt = ReceiptRecord {
            session: &self.session,
            actor: command.actor,
            request: &command.request,
            fingerprint: &command.fingerprint,
            log: &kbytes,
            seq: receipt_seq,
            outcome: &result,
            refs: &id,
            source_digest: digest,
        }
        .record();
        db.execute(
            "INSERT INTO event(seq,actor,record,digest,tip) VALUES(?,?,?,?,?)",
            params![
                sequence,
                command.actor,
                event,
                Sha256::digest(&event).as_slice(),
                et
            ],
        )
        .map_err(io::Error::other)?;
        db.execute(
            "INSERT INTO receipt VALUES(?,?,?,?,?,?)",
            params![
                receipt_seq,
                command.actor,
                command.request,
                command.fingerprint,
                receipt,
                rt
            ],
        )
        .map_err(io::Error::other)?;
        store::put(db, change.slot, &member)?;
        if self.seating_enabled() {
            self.advance_setup(db, k.index, member.setup_revision)?;
        }
        Ok(receipt)
    }
}
