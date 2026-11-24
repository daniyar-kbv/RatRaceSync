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
use openraft::{entry::RaftPayload, raft::Precondition};
use prost::Message;
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
    if r.lobby_format != Some(lobby::LobbyFormat::SemanticLinks)
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
    let witness = fields(authenticate(outer[&2], &key)?, &[1, 2, 3, 4])?;
    if membership.len() != 32
        || witness[&1] != WITNESS
        || witness[&2] != fp
        || witness[&3].len() != 32
        || witness[&4].len() != 32
    {
        return Err(invalid("invalid verified Join prefix witness"));
    }
    Ok(Intent {
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
pub(super) fn created(db: &Connection) -> io::Result<LobbyCreated> {
    let bytes = store::meta::<Vec<u8>>(db, "lobby")?.ok_or(invalid("missing open lobby"))?;
    LobbyCreated::decode(&*bytes).map_err(io::Error::other)
}
impl InstallationCatalog {
    /// Normal adapter entry point for the first additional player. Both
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
        if third::local_route(r, &tx)?.is_some() != third_player {
            return Err(invalid("incorrect admission for this Join"));
        }
        let saved = store::meta::<Vec<u8>>(&tx, "local_join")?;
        if let Some(raw) = &saved {
            let original = parse(r, raw)?;
            if original.request != request {
                return Err(invalid("another Join owns this reservation"));
            }
            if store::meta::<JoinedMember>(
                &tx,
                if third_player {
                    "third_member"
                } else {
                    "first_member"
                },
            )?
            .is_some()
            {
                return Ok(raw.clone());
            }
        } else if !profile_complete {
            return Err(invalid("complete local profile required"));
        }
        if history::boundary(&tx)? != verified {
            return Err(invalid("refresh verified learner prefix"));
        }
        let lobby = created(&tx)?;
        let m = history::membership(&tx)?;
        let membership = log_key(m.log_id().ok_or(invalid("missing membership source"))?);
        let setup = store::meta::<JoinedMember>(&tx, "first_member")?
            .map_or(lobby.setup_revision, |m| m.setup_revision)
            .to_be_bytes();
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
        let witness = signed(
            &message(&[
                (1, WITNESS),
                (2, &fp),
                (3, &log_key(verified)),
                (4, &coverage),
            ]),
            key,
        );
        let raw = message(&[(1, &intent), (2, &witness)]);
        let checked = parse(r, &raw)?;
        if let Some(saved) = saved
            && parse(r, &saved)?.fingerprint != checked.fingerprint
        {
            return Err(invalid("original Join guard changed"));
        }
        store::put(&tx, "local_join", &raw)?;
        tx.commit().map_err(io::Error::other)?;
        Ok(raw)
    }
    pub fn pending_join(&self, learner: &Learner) -> io::Result<Vec<u8>> {
        self.verified_join_prefix(learner)?;
        let db = learner.node.replica.lock()?;
        let third = third::local_route(&learner.node.replica, &db)?.is_some();
        let raw = store::meta::<Vec<u8>>(
            &db,
            if third {
                "third_proposal"
            } else {
                "local_join"
            },
        )?
        .ok_or(invalid("no pending Join"))?;
        let intent = parse(&learner.node.replica, &raw)?;
        intent.verify_approvals(&db, &learner.creator, if third { 3 } else { 2 })?;
        Ok(raw)
    }
}

pub(super) fn target(creator: ReplicaId, peer: ReplicaId) -> Members {
    Members::new_with_defaults(vec![[creator, peer].into()], [])
}

impl Intent<'_> {
    fn validate(&self, db: &Connection, creator: &Creator) -> io::Result<Transition> {
        let prev = history::membership(db)?;
        let prior = prev
            .log_id()
            .ok_or(invalid("missing committed membership"))?;
        let lobby = created(db)?;
        let first = store::meta::<JoinedMember>(db, "first_member")?;
        let (prior_voters, target, revision, ordinal, slot) = if let Some(member) = first {
            if self.actor == member.actor
                || self.key == member.key
                || self.node == member.node
                || store::meta::<JoinedMember>(db, "third_member")?.is_some()
            {
                return Err(invalid("occupied third player identity or slot"));
            }
            (
                target(creator.node, member.node),
                promotion::roster(creator.node, member.node, self.node),
                member.setup_revision,
                3,
                "third_member",
            )
        } else {
            (
                Members::new_with_defaults(vec![[creator.node].into()], []),
                target(creator.node, self.node),
                lobby.setup_revision,
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
            || self.setup != revision
            || self.layout != lobby.layout_revision
            || lobby.target < ordinal
            || lobby.stage != LobbyStage::Open as i32
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
            let change = intent.validate(&db, &creator)?;
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
            (high, change.prior, change.target)
        };
        let response = self
            .raft
            .append_membership(
                members,
                Source::blank().with_normal(Signed(raw.to_vec())),
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
        let change = command.validate(db, &creator)?;
        command.verify_approvals(db, &creator, change.ordinal)?;
        let prior = change.prior;
        let prev = store::meta::<LogId>(db, "applied")?.ok_or(invalid("no verified prefix"))?;
        if k.leader_id != prev.leader_id
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
        let sequence = i64::from(change.ordinal);
        if (events, receipts) != (sequence - 1, sequence - 1) {
            return Err(invalid("unexpected history before Join"));
        }
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
        let rt = persist_link(
            db,
            "receipt",
            sequence,
            b"receipt-step/v2",
            &prev_receipt,
            &frame(&[b"JoinReceipt/v1", &12u16.to_be_bytes(), &semantic]),
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
            seq: sequence,
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
                sequence,
                command.actor,
                command.request,
                command.fingerprint,
                receipt,
                rt
            ],
        )
        .map_err(io::Error::other)?;
        store::put(db, change.slot, &member)?;
        Ok(receipt)
    }
}
