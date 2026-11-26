//! One direct three-to-two transition. Both successor voters retain the old
//! prefix before authorizing a proposal. Only committed application creates the receipt.
use super::*;
use openraft::{alias::StoredMembershipOf, entry::RaftPayload, raft::Precondition};

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
pub(crate) fn left_at(db: &Connection, index: u64) -> io::Result<Option<Departure>> {
    Ok(store::meta::<Departure>(db, "departed_member")?.filter(|d| d.log_id.index <= index))
}
pub(super) fn successors(db: &Connection, actor: &[u8], index: u64) -> io::Result<[Creator; 2]> {
    let host = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
    if actor == host.actor || left_at(db, index)?.is_some() {
        return Err(invalid(
            "Leave requires an active guest in a three-player lobby",
        ));
    }
    let joined = |name| -> io::Result<Creator> {
        let m = store::meta::<JoinedMember>(db, name)?
            .filter(|m| m.log_id.index <= index)
            .ok_or(invalid("three joined voters required"))?;
        Ok(Creator {
            actor: m.actor,
            key: m.key,
            node: m.node,
        })
    };
    let first = joined("first_member")?;
    let third = joined("third_member")?;
    let other = if first.actor == actor {
        third
    } else if third.actor == actor {
        first
    } else {
        return Err(invalid("unknown departing member"));
    };
    Ok([host, other])
}
fn target(s: &[Creator; 2]) -> Members {
    Members::new_with_defaults(vec![[s[0].node, s[1].node].into()], [])
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
    let old = Members::new_with_defaults(
        vec![[survivors[0].node, survivors[1].node, cmd.guard.node].into()],
        [],
    );
    if previous.membership() != &old {
        return Err(invalid("unexpected predecessor voter set"));
    }
    let body = support(r, db, high, f[&2])?;
    for (who, packet) in survivors.iter().zip([f[&3], f[&4]]) {
        let proof = fields(packet, &[1, 2])?;
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
    Ok(target(&survivors))
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
    if let Some(d) = left_at(db, u64::MAX)? {
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
pub(super) fn commit(
    r: &Replica,
    db: &Transaction<'_>,
    k: LogId,
    g: &SeatCommandGuard,
) -> io::Result<effect::Effect> {
    let Dependencies::Membership { configuration, .. } = g.material else {
        return Err(invalid("missing Leave dependencies"));
    };
    let state = layout_at(db, u64::MAX)?;
    let seats = Snapshot::at(r, db, &state, u64::MAX)?.view();
    let old = seats
        .iter()
        .find(|s| s.occupant.as_deref() == Some(&g.actor));
    let seat = old.map(|s| s.id.get());
    let before = setup_revision(db)?;
    let after = before
        .checked_add(1)
        .ok_or(invalid("setup revision exhausted"))?;
    let mut revisions = None;
    if let Some(s) = old {
        let rev = s
            .revision
            .checked_add(1)
            .ok_or(invalid("seat revision exhausted"))?;
        revisions = Some((s.revision.to_be_bytes(), rev.to_be_bytes()));
        db.execute(
            "INSERT INTO seat_history(seat,idx,revision,changed_by,occupant) VALUES(?,?,?,?,NULL)",
            params![
                s.id.get(),
                k.index.to_be_bytes(),
                rev.to_be_bytes(),
                g.actor
            ],
        )
        .map_err(io::Error::other)?;
    }
    let mut resets = Vec::new();
    let mut acknowledgment_facts = Vec::new();
    // Read the pre-entry history, including acknowledgments of the remaining voters.
    let others = successors(db, &g.actor, k.index - 1)?;
    for actor in [&g.actor, &others[0].actor, &others[1].actor] {
        let h = preference::history(db, actor, k.index - 1)?;
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
    r.advance_setup(db, k.index, after)?;
    store::put(
        db,
        "departed_member",
        &Departure {
            node: g.node,
            actor: g.actor.clone(),
            log_id: k,
        },
    )?;
    let member = message(&[(1, &g.node.0), (2, &[1]), (3, &[2])]);
    let (old_revision, new_revision) =
        revisions.as_ref().map_or((&[][..], &[][..]), |(old, new)| {
            (old.as_slice(), new.as_slice())
        });
    let closure = message(&[
        (1, seat.as_slice()),
        (2, &[]),
        (3, &resets),
        (4, &before.to_be_bytes()),
        (5, &after.to_be_bytes()),
        (6, old_revision),
        (7, new_revision),
    ]);
    let effective = log_key(k);
    let refs = message(&[(1, &configuration), (2, &effective)]);
    Ok(effect::Effect {
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
            &effective,
        ]),
    })
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
        let c = command(r, &db, &cmd.0)?;
        let voters = successors(&db, &c.guard.actor, high.index)?;
        if !matches!(c.current(r, &db)?, Some(Change::Leave))
            || !voters
                .iter()
                .any(|v| Some(v.node) == r.local_node && v.key == key.verifying_key().to_bytes())
        {
            return Err(invalid("ineligible successor approval"));
        }
        let body = support(r, &db, high, &cmd.0)?;
        Ok(message(&[(1, &body), (2, &key.sign(&body).to_bytes())]))
    }
    /// The source-bearing membership entry is the only owner of the Leave receipt.
    /// Approvals are supplied in creator, surviving guest order. A retry needs only the intent.
    pub async fn leave_lobby(&self, cmd: &Signed, approvals: [&[u8]; 2]) -> io::Result<Vec<u8>> {
        self.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let r = &self.replica;
        if cmd.0.len() > 2048 {
            return Err(invalid("oversized Leave command"));
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
        let (high, prior, members) = {
            let db = r.lock()?;
            r.require_lobby_genesis(&db)?;
            r.verify_replay(&db)?;
            let c = command(r, &db, &cmd.0)?;
            if let Some(original) = c.committed_receipt(&db)? {
                return Ok(original);
            }
            let high = crate::learner::history::boundary(&db)?;
            let prior = crate::learner::history::membership(&db)?
                .log_id()
                .ok_or(invalid("missing membership"))?;
            (high, prior, verify_proposal(r, &db, &packet, high)?)
        };
        let response = self
            .raft
            .append_membership(
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
            .map_err(io::Error::other)?;
        match response.data {
            Reply::Receipt(receipt) => Ok(receipt),
            _ => Err(invalid("missing Leave receipt")),
        }
    }
}
