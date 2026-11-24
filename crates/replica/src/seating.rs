//! Signed seat commands against committed, public lobby occupancy.
mod effect;
mod state;
use crate::{
    application::ReceiptRecord,
    genesis::Creator,
    lobby::{frame, persist_link},
    wire::{fields, hash, message},
    *,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use rat_race_engine::{LobbyCapacity, LobbySeating, PlayerId, SeatAction, SeatId, SeatTransition};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use state::{Material, Snapshot};

/// The command signer keeps the key locally. The observed Raft ID proves
/// the command was eligible at a specific committed state if it later races.
#[derive(Clone)]
pub struct SeatCommandGuard {
    profile: Vec<u8>,
    session: Vec<u8>,
    actor: Vec<u8>,
    node: ReplicaId,
    observed: [u8; 32],
    layout: u64,
    action: SeatAction,
    material: Option<Material>,
}
pub type SeatClaimGuard = SeatCommandGuard;
impl SeatCommandGuard {
    fn guard(&self) -> Vec<u8> {
        let mut bytes = message(&[
            (1, &self.node.0),
            (2, &1u64.to_be_bytes()),
            (3, &self.observed),
            (4, &self.layout.to_be_bytes()),
        ]);
        if let Some(material) = &self.material {
            material.append_guard(&mut bytes);
        } else {
            wire::field(&mut bytes, 5, &0u64.to_be_bytes());
        }
        bytes
    }
    pub(crate) fn sign(&self, request: [u8; 16], key: &SigningKey) -> Signed {
        let (tag, target) = operation(self.action);
        let leaf = target.map_or_else(Vec::new, |id| message(&[(1, &[id.get()])]));
        let body = message(&[
            (1, &self.profile),
            (2, &self.session),
            (3, &self.actor),
            (4, &request),
            (5, &self.guard()),
            (12, &message(&[(tag, &leaf)])),
        ]);
        Signed(message(&[(1, &body), (2, &key.sign(&body).to_bytes())]))
    }
    fn fingerprint(&self, request: &[u8; 16]) -> [u8; 32] {
        let (tag, target) = operation(self.action);
        if let Some(m) = &self.material {
            return hash(
                b"seat-command-intent/v2",
                &[
                    &self.profile,
                    &self.session,
                    &self.actor,
                    request,
                    &self.node.0,
                    &1u64.to_be_bytes(),
                    &self.observed,
                    &self.layout.to_be_bytes(),
                    &m.target_revision.to_be_bytes(),
                    m.from.map(SeatId::get).as_slice(),
                    &m.source_revision.to_be_bytes(),
                    &m.actor_index.to_be_bytes(),
                    &(tag as u16).to_be_bytes(),
                    target.map(SeatId::get).as_slice(),
                ],
            );
        }
        hash(
            b"seat-claim-intent/v1",
            &[
                &self.profile,
                &self.session,
                &self.actor,
                request,
                &self.node.0,
                &1u64.to_be_bytes(),
                &self.observed,
                &self.layout.to_be_bytes(),
                &0u64.to_be_bytes(),
                &204u16.to_be_bytes(),
                target.map(SeatId::get).as_slice(),
            ],
        )
    }
}

#[derive(Serialize, Deserialize)]
struct Occupancy {
    seat: u8,
    actor: Vec<u8>,
    index: u64,
}
fn claims(db: &Connection) -> io::Result<Vec<Occupancy>> {
    Ok(store::meta(db, "seat_claims")?.unwrap_or_default())
}
pub(crate) fn setup_revision(db: &Connection) -> io::Result<u64> {
    if let Some(revision) = store::meta::<u64>(db, "setup_revision")? {
        return Ok(revision);
    }
    // Earlier lobby profiles stored the revision in each immutable Create/Join.
    for name in ["third_member", "first_member"] {
        if let Some(member) = store::meta::<JoinedMember>(db, name)? {
            return Ok(member.setup_revision);
        }
    }
    Ok(lobby(db)?.setup_revision)
}
fn lobby(db: &Connection) -> io::Result<LobbyCreated> {
    let bytes = store::meta::<Vec<u8>>(db, "lobby")?.ok_or(invalid("lobby not created"))?;
    let lobby = LobbyCreated::decode(bytes.as_slice()).map_err(io::Error::other)?;
    if lobby.stage != LobbyStage::Open as i32 {
        return Err(invalid("lobby is closed"));
    }
    Ok(lobby)
}
fn member(db: &Connection, actor: &[u8], index: u64) -> io::Result<(ReplicaId, [u8; 32])> {
    let creator = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
    if actor == creator.actor {
        return Ok((creator.node, creator.key));
    }
    for name in ["first_member", "third_member"] {
        if let Some(joined) = store::meta::<JoinedMember>(db, name)?
            && joined.actor == actor
            && joined.log_id.index <= index
        {
            return Ok((joined.node, joined.key));
        }
    }
    Err(invalid("seat operation requires a joined player"))
}
fn player(actor: &[u8]) -> io::Result<PlayerId> {
    PlayerId::try_from(actor).map_err(|_| invalid("invalid player"))
}
fn operation(action: SeatAction) -> (u32, Option<SeatId>) {
    match action {
        SeatAction::Claim(seat) => (204, Some(seat)),
        SeatAction::Release => (205, None),
        SeatAction::Change(seat) => (206, Some(seat)),
    }
}
fn action(bytes: &[u8]) -> io::Result<SeatAction> {
    for tag in [204, 205, 206] {
        if let Ok(operation) = fields(bytes, &[tag]) {
            if tag == 205 {
                fields(operation[&tag], &[])?;
                return Ok(SeatAction::Release);
            }
            let leaf = fields(operation[&tag], &[1])?;
            let &[id] = leaf[&1] else {
                return Err(invalid("invalid seat ID"));
            };
            let seat = SeatId::new(id).ok_or(invalid("invalid seat ID"))?;
            return Ok(if tag == 204 {
                SeatAction::Claim(seat)
            } else {
                SeatAction::Change(seat)
            });
        }
    }
    Err(invalid("unrecognized seat operation"))
}
pub(crate) fn is_seat_command(raw: &[u8]) -> bool {
    if raw.len() > 2048 {
        return false;
    }
    (|| -> io::Result<()> {
        let envelope = fields(raw, &[1, 2])?;
        let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12])?;
        action(body[&12])?;
        Ok(())
    })()
    .is_ok()
}

struct SeatCommand {
    guard: SeatCommandGuard,
    request: [u8; 16],
}
impl SeatCommand {
    fn verify(r: &Replica, db: &Connection, raw: &[u8]) -> io::Result<Self> {
        if raw.len() > 2048 || !r.seating_enabled() {
            return Err(invalid("unsupported seat command profile or size"));
        }
        let envelope = fields(raw, &[1, 2])?;
        let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12])?;
        let action = action(body[&12])?;
        if !r.seat_changes() && !matches!(action, SeatAction::Claim(_)) {
            return Err(invalid("seat change outside pinned profile"));
        }
        let tags = if r.seat_changes() {
            &[1, 2, 3, 4, 5, 6, 7, 8][..]
        } else {
            &[1, 2, 3, 4, 5][..]
        };
        let guard = fields(body[&5], tags)?;
        let request: [u8; 16] = body[&4].try_into().map_err(io::Error::other)?;
        let observed: [u8; 32] = guard[&3].try_into().map_err(io::Error::other)?;
        let layout = u64::from_be_bytes(guard[&4].try_into().map_err(io::Error::other)?);
        if body[&1] != r.profile()
            || body[&2] != r.session
            || body[&3].is_empty()
            || body[&3].len() > 64
            || request[6] >> 4 != 4
            || request[8] >> 6 != 2
            || guard[&2] != 1u64.to_be_bytes()
        {
            return Err(invalid("invalid seat command envelope"));
        }
        let index: [u8; 8] = db
            .query_row(
                "SELECT idx FROM archive WHERE log_id=? AND event_count>=1",
                [&observed[..]],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        let index = u64::from_be_bytes(index);
        let (node, key) = member(db, body[&3], index)?;
        if guard[&1] != node.0 {
            return Err(invalid("wrong player incarnation"));
        }
        VerifyingKey::from_bytes(&key)
            .map_err(io::Error::other)?
            .verify_strict(
                envelope[&1],
                &Signature::from_slice(envelope[&2]).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
        let state = lobby(db)?;
        if layout != state.layout_revision {
            return Err(invalid("invalid observed layout revision"));
        }
        let table = Snapshot::at(r, db, &state, index)?;
        let tr = table.transition(body[&3], action)?;
        let material = r
            .seat_changes()
            .then(|| Material::at(db, &table, body[&3], index, tr))
            .transpose()?;
        let expected = SeatCommandGuard {
            profile: r.profile().into(),
            session: r.session.clone(),
            actor: body[&3].into(),
            node,
            observed,
            layout,
            action,
            material,
        };
        if guard != fields(&expected.guard(), tags)? {
            return Err(invalid("incorrect observed seat dependencies"));
        }
        Ok(Self {
            request,
            guard: expected,
        })
    }
    fn current(&self, r: &Replica, db: &Connection) -> io::Result<Option<SeatTransition>> {
        let g = &self.guard;
        let table = Snapshot::at(r, db, &lobby(db)?, u64::MAX)?;
        let tr = match table.transition(&g.actor, g.action) {
            Ok(tr) => tr,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
            Err(e) => return Err(e),
        };
        if let Some(expected) = &g.material
            && Material::at(db, &table, &g.actor, u64::MAX, tr)? != *expected
        {
            return Ok(None);
        }
        Ok(Some(tr))
    }
    fn committed_receipt(&self, db: &Connection) -> io::Result<Option<Vec<u8>>> {
        match self.original(db)? {
            Some(Reply::Receipt(record)) => Ok(Some(record)),
            Some(_) => Err(invalid("another committed intent owns the seat request ID")),
            None => Ok(None),
        }
    }
    fn original(&self, db: &Connection) -> io::Result<Option<Reply>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = db
            .query_row(
                "SELECT fingerprint,record FROM receipt WHERE actor=? AND request=?",
                params![self.guard.actor, self.request],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(io::Error::other)?;
        Ok(row.map(|(fp, bytes)| {
            if fp == self.guard.fingerprint(&self.request) {
                Reply::Receipt(bytes)
            } else {
                Reply::RequestIdConflict
            }
        }))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LobbySeat {
    pub id: SeatId,
    pub occupant: Option<Vec<u8>>,
    pub revision: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub struct LobbySeatView {
    pub seats: Vec<LobbySeat>,
    pub layout_revision: u64,
    pub setup_revision: u64,
}

fn local_request_key(node: ReplicaId, request: [u8; 16]) -> String {
    format!("local_seat_claim_{node}_{}", u128::from_be_bytes(request))
}

impl GameNode {
    pub fn prepare_seat_claim(
        &self,
        guard: &SeatClaimGuard,
        request: [u8; 16],
        key: &SigningKey,
    ) -> io::Result<Signed> {
        if !matches!(guard.action, SeatAction::Claim(_)) {
            return Err(invalid("expected claim"));
        }
        self.prepare_seat_command(guard, request, key)
    }
    /// Persist the original on the actor's installation before sending it to the leader.
    pub fn prepare_seat_command(
        &self,
        guard: &SeatCommandGuard,
        request: [u8; 16],
        key: &SigningKey,
    ) -> io::Result<Signed> {
        let r = &self.replica;
        let mut db = r.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        r.require_lobby_genesis(&tx)?;
        r.verify_replay(&tx)?;
        let raw = guard.sign(request, key);
        let command = SeatCommand::verify(r, &tx, &raw.0)?;
        if r.local_node != Some(command.guard.node) {
            return Err(invalid("seat command belongs to another installation"));
        }
        let committed = command.committed_receipt(&tx)?;
        let name = local_request_key(command.guard.node, request);
        if let Some(saved) = store::meta::<Signed>(&tx, &name)? {
            let original = SeatCommand::verify(r, &tx, &saved.0)?;
            if original.request != request
                || original.guard.fingerprint(&request) != command.guard.fingerprint(&request)
            {
                return Err(invalid(
                    "seat request already reserved with different intent",
                ));
            }
            return Ok(saved);
        }
        // A recovered installation may have the consensus history before it has a local
        // reservation. Preserve the original signed bytes even for alternate field order.
        let raw = if let Some(record) = committed {
            let receipt = fields(&record, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
            let source: Vec<u8> = tx
                .query_row(
                    "SELECT source FROM archive WHERE log_id=?",
                    [receipt[&5]],
                    |row| row.get(0),
                )
                .map_err(io::Error::other)?;
            Signed(
                source
                    .strip_prefix(&[1])
                    .ok_or(invalid("expected committed seat command"))?
                    .to_vec(),
            )
        } else {
            raw
        };
        store::put(&tx, &name, &raw)?;
        tx.commit().map_err(io::Error::other)?;
        Ok(raw)
    }
    pub fn saved_seat_claim(
        &self,
        actor: &[u8],
        request: [u8; 16],
        key: &SigningKey,
    ) -> io::Result<Option<Signed>> {
        let saved = self.saved_seat_command(actor, request, key)?;
        if let Some(raw) = &saved {
            let envelope = fields(&raw.0, &[1, 2])?;
            let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12])?;
            if !matches!(action(body[&12])?, SeatAction::Claim(_)) {
                return Err(invalid("reserved request is not a claim"));
            }
        }
        Ok(saved)
    }
    /// Recover the locally signed bytes even if no current leader is reachable.
    pub fn saved_seat_command(
        &self,
        actor: &[u8],
        request: [u8; 16],
        key: &SigningKey,
    ) -> io::Result<Option<Signed>> {
        let r = &self.replica;
        let db = r.lock()?;
        r.require_lobby_genesis(&db)?;
        r.verify_replay(&db)?;
        let (node, public) = member(&db, actor, u64::MAX)?;
        if r.local_node != Some(node) || public != key.verifying_key().to_bytes() {
            return Err(invalid("incorrect local seat signer"));
        }
        let saved = store::meta::<Signed>(&db, &local_request_key(node, request))?;
        if let Some(raw) = &saved {
            let command = SeatCommand::verify(r, &db, &raw.0)?;
            command.committed_receipt(&db)?;
            if command.request != request
                || command.guard.node != node
                || command.guard.actor != actor
            {
                return Err(invalid("wrong saved seat intent"));
            }
        }
        Ok(saved)
    }
    /// The transport authenticates the requesting actor; only joined participants may read.
    pub async fn lobby_seating(&self, actor: &[u8]) -> io::Result<LobbySeatView> {
        self.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let r = &self.replica;
        if !r.seating_enabled() {
            return Err(invalid("seating outside pinned profile"));
        }
        let db = r.lock()?;
        r.require_lobby_genesis(&db)?;
        r.verify_replay(&db)?;
        member(&db, actor, u64::MAX)?;
        let state = lobby(&db)?;
        let seats = Snapshot::at(r, &db, &state, u64::MAX)?.view();
        Ok(LobbySeatView {
            seats,
            setup_revision: setup_revision(&db)?,
            layout_revision: state.layout_revision,
        })
    }
    /// Issue only to an authenticated current participant authorized to act as actor.
    pub async fn seat_claim_guard(&self, actor: &[u8], seat: SeatId) -> io::Result<SeatClaimGuard> {
        self.seat_guard(actor, SeatAction::Claim(seat)).await
    }
    pub async fn seat_release_guard(&self, actor: &[u8]) -> io::Result<SeatCommandGuard> {
        self.seat_guard(actor, SeatAction::Release).await
    }
    pub async fn seat_change_guard(
        &self,
        actor: &[u8],
        seat: SeatId,
    ) -> io::Result<SeatCommandGuard> {
        self.seat_guard(actor, SeatAction::Change(seat)).await
    }
    async fn seat_guard(&self, actor: &[u8], action: SeatAction) -> io::Result<SeatCommandGuard> {
        self.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let r = &self.replica;
        if !r.seating_enabled() {
            return Err(invalid("seating outside pinned profile"));
        }
        let db = r.lock()?;
        r.require_lobby_genesis(&db)?;
        r.verify_replay(&db)?;
        let k = store::meta::<LogId>(&db, "applied")?.ok_or(invalid("missing lobby checkpoint"))?;
        let (node, _) = member(&db, actor, k.index)?;
        let state = lobby(&db)?;
        if !r.seat_changes() && !matches!(action, SeatAction::Claim(_)) {
            return Err(invalid("seat change outside pinned profile"));
        }
        let table = Snapshot::at(r, &db, &state, k.index)?;
        let tr = table.transition(actor, action)?;
        let material = r
            .seat_changes()
            .then(|| Material::at(&db, &table, actor, k.index, tr))
            .transpose()?;
        Ok(SeatCommandGuard {
            profile: r.profile().into(),
            session: r.session.clone(),
            actor: actor.into(),
            observed: log_key(k)
                .try_into()
                .map_err(|_| invalid("invalid log ID"))?,
            layout: state.layout_revision,
            node,
            action,
            material,
        })
    }
}
impl Replica {
    pub(crate) fn seating_enabled(&self) -> bool {
        self.lobby_format.is_some_and(lobby::LobbyFormat::seating)
    }
    fn seat_changes(&self) -> bool {
        self.lobby_format == Some(lobby::LobbyFormat::SeatChanges)
    }
    pub(crate) fn inspect_seat(&self, db: &Connection, raw: &[u8]) -> io::Result<Option<Reply>> {
        self.require_lobby_genesis(db)?;
        self.verify_replay(db)?;
        let command = SeatCommand::verify(self, db, raw)?;
        if let Some(reply) = command.original(db)? {
            return Ok(Some(reply));
        }
        if command.current(self, db)?.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "seat dependencies changed",
            ));
        }
        Ok(None)
    }
    pub(crate) fn apply_seat(
        &self,
        db: &Transaction<'_>,
        k: LogId,
        raw: &[u8],
        source_digest: &[u8],
    ) -> io::Result<Reply> {
        let command = SeatCommand::verify(self, db, raw)?;
        if let Some(reply) = command.original(db)? {
            return Ok(reply);
        }
        let g = &command.guard;
        let fp = g.fingerprint(&command.request);
        let log = log_key(k);
        let op = operation(g.action).0;
        let op_bytes = (op as u16).to_be_bytes();
        let (receipt_count, previous_receipt) = self.tip(db, "receipt")?;
        let receipt_seq = receipt_count
            .checked_add(1)
            .ok_or(invalid("receipt range"))?;
        let mut refs = Vec::new();
        let (outcome, semantic) = if let Some(tr) = command.current(self, db)? {
            let effect::Effect {
                record: effect,
                facts,
            } = effect::commit(self, db, k.index, g, tr)?;
            let (count, prev) = self.tip(db, "event")?;
            let seq = count.checked_add(1).ok_or(invalid("event range"))?;
            let id = hash(b"event-id", &[&self.session, &log, &seq.to_be_bytes()]);
            let event_effect = if self.seat_changes() {
                message(&[(op, &effect)])
            } else {
                effect.clone()
            };
            let event = message(&[
                (1, &self.session),
                (2, &log),
                (3, &seq.to_be_bytes()),
                (4, &id),
                (5, &fp),
                (6, &event_effect),
                (7, source_digest),
            ]);
            let tip = persist_link(
                db,
                "event",
                seq,
                b"event-step/v2",
                &prev,
                &frame(&[
                    b"SeatChanged/v1",
                    self.profile(),
                    &self.session,
                    &log,
                    &seq.to_be_bytes(),
                    &id,
                    &g.actor,
                    &command.request,
                    &fp,
                    &op_bytes,
                    &facts,
                ]),
            )?;
            db.execute(
                "INSERT INTO event(seq,actor,record,digest,tip) VALUES(?,?,?,?,?)",
                params![seq, g.actor, event, Sha256::digest(&event).as_slice(), tip],
            )
            .map_err(io::Error::other)?;
            refs.extend(id);
            (
                message(&[(12, &message(&[(op, &effect)]))]),
                frame(&[&12u16.to_be_bytes(), &op_bytes, &facts]),
            )
        } else {
            (
                message(&[(13, &[8, 1])]),
                frame(&[&13u16.to_be_bytes(), b"material-dependency-changed"]),
            )
        };
        let record = ReceiptRecord {
            session: &self.session,
            actor: &g.actor,
            request: &command.request,
            fingerprint: &fp,
            log: &log,
            seq: receipt_seq,
            outcome: &outcome,
            refs: &refs,
            source_digest,
        }
        .record();
        let tip = persist_link(
            db,
            "receipt",
            receipt_seq,
            b"receipt-step/v2",
            &previous_receipt,
            &frame(&[
                if self.seat_changes() {
                    b"SeatCommandReceipt/v2"
                } else {
                    b"SeatClaimReceipt/v1"
                },
                self.profile(),
                &self.session,
                &g.actor,
                &command.request,
                &log,
                &receipt_seq.to_be_bytes(),
                &fp,
                &refs,
                &semantic,
            ]),
        )?;
        db.execute(
            "INSERT INTO receipt VALUES(?,?,?,?,?,?)",
            params![receipt_seq, g.actor, command.request, fp, record, tip],
        )
        .map_err(io::Error::other)?;
        Ok(Reply::Receipt(record))
    }
}
