//! Direct lobby departures retain the predecessor quorum's certified history.
//! Only the committed membership entry creates the receipt.
use super::*;
use openraft::{
    alias::StoredMembershipOf, entry::RaftPayload, raft::Precondition, type_config::TypeConfigExt,
};

pub(crate) mod confirmation;
const SOURCE: &[u8] = b"RatRaceSync/leave-membership/v1";
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Departure {
    pub actor: Vec<u8>,
    pub node: ReplicaId,
    pub log_id: LogId,
}

pub(crate) fn locally_retired(db: &Connection) -> io::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE name=?)",
        [confirmation::LOCAL],
        |r| r.get(0),
    )
    .map_err(io::Error::other)
}
pub(crate) fn reject_departed(
    db: &Connection,
    local: ReplicaId,
    peer: Option<ReplicaId>,
) -> io::Result<()> {
    if locally_retired(db)?
        || departures_at(db, u64::MAX)?
            .iter()
            .any(|d| d.node == local || Some(d.node) == peer)
    {
        return Err(invalid("departed voter"));
    }
    Ok(())
}

pub(crate) fn last_guest_at(db: &Connection, index: u64) -> io::Result<Option<Departure>> {
    for slot in ["replacement_departure", "last_guest_departure"] {
        if let Some(d) = store::meta::<Departure>(db, slot)?.filter(|d| d.log_id.index <= index) {
            return Ok(Some(d));
        }
    }
    Ok(None)
}

pub(crate) fn departures_at(db: &Connection, index: u64) -> io::Result<Vec<Departure>> {
    let mut departures = Vec::new();
    for name in [
        "departed_member",
        "last_guest_departure",
        "replacement_departure",
    ] {
        if let Some(d) = store::meta::<Departure>(db, name)?.filter(|d| d.log_id.index <= index) {
            departures.push(d);
        }
    }
    Ok(departures)
}

pub(crate) fn left_at(db: &Connection, index: u64) -> io::Result<Option<Departure>> {
    Ok(departures_at(db, index)?.pop())
}
pub(super) fn successors(db: &Connection, actor: &[u8], index: u64) -> io::Result<Vec<Creator>> {
    let host = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
    if actor == host.actor {
        return Err(invalid("creator cannot use guest Leave"));
    }
    let mut survivors = vec![host];
    let mut joined = false;
    let departed = departures_at(db, index)?;
    for name in ["first_member", "third_member"] {
        if let Some(m) = store::meta::<JoinedMember>(db, name)?
            && m.log_id.index <= index
            && !departed.iter().any(|d| d.node == m.node)
        {
            if m.actor == actor {
                joined = true;
            } else {
                survivors.push(Creator {
                    node: m.node,
                    actor: m.actor,
                    key: m.key,
                });
            }
        }
    }
    if !joined {
        return Err(invalid("Leave requires a joined guest"));
    }
    Ok(survivors)
}

fn authorizers(
    db: &Connection,
    guard: &SeatCommandGuard,
    index: u64,
    survivors: &[Creator],
) -> io::Result<[Creator; 2]> {
    let other = match survivors {
        [_, guest] => guest.clone(),
        [_] => {
            let (node, key) = member(db, &guard.actor, index)?;
            Creator {
                node,
                actor: guard.actor.clone(),
                key,
            }
        }
        _ => return Err(invalid("unsupported Leave membership")),
    };
    Ok([survivors[0].clone(), other])
}
fn command(r: &Replica, db: &Connection, raw: &[u8]) -> io::Result<SeatCommand> {
    let cmd = SeatCommand::verify(r, db, raw)?;
    if !matches!(cmd.guard.action, TableAction::Leave) {
        return Err(invalid("expected Leave intent"));
    }
    Ok(cmd)
}
fn support(r: &Replica, db: &Connection, high: LogId, raw: &[u8]) -> io::Result<Vec<u8>> {
    let (digest, events, receipts): ([u8; 32], [u8; 32], [u8; 32]) = db
        .query_row(
            "SELECT digest,event_tip,receipt_tip FROM archive WHERE log_id=?",
            [log_key(high)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(io::Error::other)?;
    Ok(message(&[
        (1, b"successor-stored-leave-prefix/v1"),
        (2, &r.session),
        (3, &log_key(high)),
        (4, &Sha256::digest(raw)),
        (5, &digest),
        (6, &events),
        (7, &receipts),
        (
            8,
            r.bound_root
                .get()
                .ok_or(invalid("missing verified Leave root"))?,
        ),
    ]))
}
pub(crate) fn is_source(raw: &[u8]) -> bool {
    raw.len() <= 4096 && fields(raw, &[1, 2, 3, 4]).is_ok_and(|f| f[&1] == SOURCE)
}
fn verify_proposal(
    r: &Replica,
    db: &Connection,
    packet: &[u8],
    high: LogId,
) -> io::Result<Members> {
    let f = fields(packet, &[1, 2, 3, 4])?;
    let cmd = command(r, db, f[&2])?;
    if cmd.original(db)?.is_some() || !matches!(cmd.current(r, db)?, Some(Change::Leave)) {
        return Err(invalid("superseded Leave proposal"));
    }
    let survivors = successors(db, &cmd.guard.actor, high.index)?;
    let previous = store::meta::<StoredMembershipOf<Types>>(db, "membership")?
        .ok_or(invalid("missing predecessor membership"))?;
    // A registered learner has no vote. Preserve its replication role across
    // the change without counting it as an approver or historical signer.
    let learners: Vec<_> = previous.membership().non_write_voter_ids().collect();
    let old = Members::new_with_defaults(
        vec![
            survivors
                .iter()
                .map(|s| s.node)
                .chain([cmd.guard.node])
                .collect(),
        ],
        learners.iter().copied(),
    );
    if previous.membership() != &old {
        return Err(invalid("unexpected predecessor voter set"));
    }
    let body = support(r, db, high, f[&2])?;
    let prior = confirmation::prior_body(r, db, high.index)?;
    for (who, packet) in authorizers(db, &cmd.guard, high.index, &survivors)?
        .iter()
        .zip([f[&3], f[&4]])
    {
        let proof = fields(packet, if prior.is_some() { &[1, 2, 3] } else { &[1, 2] })?;
        if let Some((_, prior_body)) = &prior {
            VerifyingKey::from_bytes(&who.key)
                .map_err(io::Error::other)?
                .verify_strict(
                    prior_body,
                    &Signature::from_slice(proof[&3]).map_err(io::Error::other)?,
                )
                .map_err(io::Error::other)?;
        }
        if proof[&1] != body {
            return Err(invalid("stale successor history acknowledgment"));
        }
        VerifyingKey::from_bytes(&who.key)
            .map_err(io::Error::other)?
            .verify_strict(
                &body,
                &Signature::from_slice(proof[&2]).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
    }
    Ok(Members::new_with_defaults(
        vec![survivors.iter().map(|v| v.node).collect()],
        learners,
    ))
}
pub(crate) fn verify_entry<'a>(
    r: &Replica,
    db: &Connection,
    e: &Entry,
    packet: &'a [u8],
) -> io::Result<(&'a [u8], Members)> {
    let prev = store::meta::<LogId>(db, "applied")?.ok_or(invalid("missing predecessor"))?;
    if prev.index.checked_add(1) != Some(e.log_id.index) || prev.leader_id != e.log_id.leader_id {
        return Err(invalid("unexpected Leave log position"));
    }
    let members = verify_proposal(r, db, packet, prev)?;
    if e.payload.check_members()?.as_ref() != Some(&members) {
        return Err(invalid("Leave configuration differs from signed intent"));
    }
    Ok((fields(packet, &[1, 2, 3, 4])?[&2], members))
}

pub(crate) fn check_retained(
    r: &Replica,
    db: &Connection,
    e: &Entry,
    raw: &[u8],
) -> io::Result<()> {
    r.require_lobby_genesis(db)?;
    r.verify_replay(db)?;
    if let Some(d) = departures_at(db, u64::MAX)?
        .iter()
        .find(|d| d.log_id.index == e.log_id.index)
    {
        let bytes: Vec<u8> = db
            .query_row(
                "SELECT source FROM archive WHERE log_id=?",
                [log_key(d.log_id)],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        if e.log_id != d.log_id || e.payload.bytes != bytes {
            return Err(invalid("conflicting retained Leave"));
        }
        return Ok(());
    }
    verify_entry(r, db, e, raw).map(|_| ())
}
struct DepartureOutcome {
    vacancy: Option<(SeatId, u64)>,
    setup: u64,
    effect: effect::Effect,
}

fn outcome_at(
    db: &Connection,
    index: u64,
    g: &SeatCommandGuard,
    effective: &[u8],
) -> io::Result<DepartureOutcome> {
    let Dependencies::Membership {
        configuration,
        setup: before,
    } = g.material
    else {
        return Err(invalid("missing Leave dependencies"));
    };
    let state = layout_at(db, index)?;
    let snapshot = Snapshot::at(true, db, &state, index)?;
    let occupied = snapshot
        .seating()
        .seats()
        .find(|(_, p)| p.is_some_and(|p| p.as_ref() == g.actor))
        .map(|(id, _)| id);
    let seat = occupied.map(SeatId::get);
    let revision = occupied.map(|id| snapshot.revision(id));
    let next_revision = revision
        .map(|v| v.checked_add(1).ok_or(invalid("seat revision exhausted")))
        .transpose()?;
    let after = before
        .checked_add(1)
        .ok_or(invalid("setup revision exhausted"))?;
    let mut resets = Vec::new();
    let mut acknowledgment_facts = Vec::new();
    // Read the pre-entry history, including acknowledgments of the remaining voters.
    let others = successors(db, &g.actor, index)?;
    for actor in std::iter::once(&g.actor).chain(others.iter().map(|other| &other.actor)) {
        let h = preference::history(db, actor, index)?;
        if actor == &g.actor || h.ack.is_some() {
            let ack = h.ack.map(u64::to_be_bytes);
            let previous_ack = ack.as_ref().map_or(&[][..], |n| n.as_slice());
            let was_ready = [u8::from(h.ready)];
            acknowledgment_facts.extend(frame(&[actor, &was_ready, &[0], previous_ack, &[]]));
            wire::field(
                &mut resets,
                1,
                &message(&[
                    (1, actor),
                    (2, &was_ready),
                    (3, &[0]),
                    (4, previous_ack),
                    (5, &[]),
                ]),
            );
        }
    }
    let member = message(&[(1, &g.node.0), (2, &[1]), (3, &[2])]);
    let revision_bytes = revision.map(u64::to_be_bytes);
    let next_bytes = next_revision.map(u64::to_be_bytes);
    let old_revision = revision_bytes.as_ref().map_or(&[][..], |n| n.as_slice());
    let new_revision = next_bytes.as_ref().map_or(&[][..], |n| n.as_slice());
    let closure = message(&[
        (1, seat.as_slice()),
        (2, &[]),
        (3, &resets),
        (4, &before.to_be_bytes()),
        (5, &after.to_be_bytes()),
        (6, old_revision),
        (7, new_revision),
    ]);
    let refs = message(&[(1, &configuration), (2, effective)]);
    let effect = effect::Effect {
        record: message(&[
            (1, &g.actor),
            (2, &member),
            (3, &closure),
            (4, &[]),
            (5, &refs),
        ]),
        facts: frame(&[
            &g.actor,
            &g.node.0,
            &[1],
            &[2],
            seat.as_slice(),
            &[],
            old_revision,
            new_revision,
            &acknowledgment_facts,
            &before.to_be_bytes(),
            &after.to_be_bytes(),
            &[],
            &configuration,
            effective,
        ]),
    };
    Ok(DepartureOutcome {
        vacancy: occupied.zip(next_revision),
        setup: after,
        effect,
    })
}

pub(super) fn commit(
    r: &Replica,
    db: &Transaction<'_>,
    k: LogId,
    g: &SeatCommandGuard,
) -> io::Result<effect::Effect> {
    let outcome = outcome_at(db, k.index - 1, g, &log_key(k))?;
    if let Some((seat, revision)) = outcome.vacancy {
        db.execute(
            "INSERT INTO seat_history(seat,idx,revision,changed_by,occupant) VALUES(?,?,?,?,NULL)",
            params![
                seat.get(),
                k.index.to_be_bytes(),
                revision.to_be_bytes(),
                g.actor
            ],
        )
        .map_err(io::Error::other)?;
    }
    r.advance_setup(db, k.index, outcome.setup)?;
    store::put(
        db,
        if last_guest_at(db, k.index - 1)?.is_some() {
            "replacement_departure"
        } else if successors(db, &g.actor, k.index - 1)?.len() == 1 {
            "last_guest_departure"
        } else {
            "departed_member"
        },
        &Departure {
            node: g.node,
            actor: g.actor.clone(),
            log_id: k,
        },
    )?;
    Ok(outcome.effect)
}

impl Learner {
    /// Recover the member's original request while its local participation release is pending.
    pub fn pending_lobby_leave(&self, request: [u8; 16], key: &SigningKey) -> io::Result<Signed> {
        let raw = self
            .node
            .saved_seat_command(&self.actor, request, key)?
            .ok_or(invalid("no reserved Leave"))?;
        command(&self.node.replica, &*self.node.replica.lock()?, &raw.0)?;
        Ok(raw)
    }
}
impl GameNode {
    pub async fn leave_lobby_witness(&self, actor: &[u8]) -> io::Result<Vec<u8>> {
        Ok(self
            .seat_guard(actor, TableAction::Leave)
            .await?
            .detached_guard())
    }
    pub fn prepare_leave_lobby(
        &self,
        actor: &[u8],
        witness: &[u8],
        request: [u8; 16],
        key: &SigningKey,
    ) -> io::Result<Signed> {
        self.prepare_member_command(actor, witness, request, key, 209)
    }
    pub fn leave_approval(&self, cmd: &Signed, key: &SigningKey) -> io::Result<Vec<u8>> {
        let r = &self.replica;
        let high = crate::learner::history::boundary(&*r.lock()?)?;
        if !self.voting_history_complete(high)? {
            return Err(invalid("successor history handoff incomplete"));
        }
        let db = r.lock()?;
        reject_departed(
            &db,
            r.local_node.ok_or(invalid("missing local voter"))?,
            None,
        )?;
        let c = command(r, &db, &cmd.0)?;
        let voters = successors(&db, &c.guard.actor, high.index)?;
        if !matches!(c.current(r, &db)?, Some(Change::Leave))
            || !authorizers(&db, &c.guard, high.index, &voters)?
                .iter()
                .any(|v| Some(v.node) == r.local_node && v.key == key.verifying_key().to_bytes())
        {
            return Err(invalid("ineligible successor approval"));
        }
        let body = support(r, &db, high, &cmd.0)?;
        let signature = key.sign(&body).to_bytes();
        if let Some((_, prior)) = confirmation::prior_body(r, &db, high.index)? {
            return Ok(message(&[
                (1, &body),
                (2, &signature),
                (3, &key.sign(&prior).to_bytes()),
            ]));
        }
        Ok(message(&[(1, &body), (2, &signature)]))
    }
    /// The source-bearing membership entry is the only owner of the Leave receipt.
    /// The creator signs first. The other signer is the surviving guest, or the departing
    /// guest when the old quorum consists of two. A committed retry needs only the intent.
    pub async fn leave_lobby(&self, cmd: &Signed, approvals: [&[u8]; 2]) -> io::Result<Vec<u8>> {
        let permit = self.request_permit(cmd).await?;
        self.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let r = &self.replica;
        let (high, prior, members, packet) = {
            let db = r.lock()?;
            r.require_lobby_genesis(&db)?;
            r.verify_replay(&db)?;
            let c = command(r, &db, &cmd.0)?;
            if let Some(original) = c.committed_receipt(&db)? {
                return Ok(original);
            }
            if approvals.iter().any(|p| p.len() > 512) {
                return Err(invalid("oversize Leave approval"));
            }
            let packet = message(&[
                (1, SOURCE),
                (2, &cmd.0),
                (3, approvals[0]),
                (4, approvals[1]),
            ]);
            let high = crate::learner::history::boundary(&db)?;
            let prior = crate::learner::history::membership(&db)?
                .log_id()
                .ok_or(invalid("missing membership"))?;
            (high, prior, verify_proposal(r, &db, &packet, high)?, packet)
        };
        let raft = self.raft.clone();
        // A disconnected caller cannot release this request while its membership write is pending.
        let response = Types::spawn(async move {
            let _permit = permit;
            raft.append_membership(
                members,
                Source::blank().with_normal(Signed(packet)),
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
        match response.data {
            Reply::Receipt(receipt) => Ok(receipt),
            _ => Err(invalid("missing Leave receipt")),
        }
    }
}
