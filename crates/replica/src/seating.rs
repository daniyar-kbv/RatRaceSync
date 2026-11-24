//! Operation 204 on committed, public lobby occupancy.
use crate::{
    application::ReceiptRecord,
    genesis::Creator,
    lobby::{frame, persist_link},
    wire::{fields, hash, message},
    *,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use rat_race_engine::{LobbyCapacity, LobbySeating, PlayerId, SeatId};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The command signer keeps the key locally. The observed Raft ID proves
/// the claim was eligible at a specific committed state if it later races.
#[derive(Clone)]
pub struct SeatClaimGuard {
    profile: Vec<u8>,
    session: Vec<u8>,
    actor: Vec<u8>,
    node: ReplicaId,
    observed: [u8; 32],
    layout: u64,
    seat: SeatId,
}
impl SeatClaimGuard {
    fn guard(&self) -> Vec<u8> {
        message(&[
            (1, &self.node.0),
            (2, &1u64.to_be_bytes()),
            (3, &self.observed),
            (4, &self.layout.to_be_bytes()),
            (5, &0u64.to_be_bytes()),
        ])
    }
    pub(crate) fn sign(&self, request: [u8; 16], key: &SigningKey) -> Signed {
        let leaf = message(&[(1, &[self.seat.get()])]);
        let body = message(&[
            (1, &self.profile),
            (2, &self.session),
            (3, &self.actor),
            (4, &request),
            (5, &self.guard()),
            (12, &message(&[(204, &leaf)])),
        ]);
        Signed(message(&[(1, &body), (2, &key.sign(&body).to_bytes())]))
    }
    fn fingerprint(&self, request: &[u8; 16]) -> [u8; 32] {
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
                &[self.seat.get()],
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
    Err(invalid("seat claim requires a joined player"))
}
fn table_at(lobby: &LobbyCreated, claims: &[Occupancy], index: u64) -> io::Result<LobbySeating> {
    let count = u8::try_from(lobby.target)
        .ok()
        .and_then(LobbyCapacity::new)
        .ok_or(invalid("invalid lobby size"))?;
    let mut seats = LobbySeating::new(count);
    for row in claims.iter().filter(|row| row.index <= index) {
        let seat = SeatId::new(row.seat).ok_or(invalid("invalid stored seat"))?;
        seats
            .claim(&player(&row.actor)?, seat)
            .map_err(|_| invalid("inconsistent stored occupancy"))?;
    }
    Ok(seats)
}
fn player(actor: &[u8]) -> io::Result<PlayerId> {
    PlayerId::try_from(actor).map_err(|_| invalid("invalid player"))
}
fn check_available(table: &mut LobbySeating, actor: &[u8], seat: SeatId) -> io::Result<()> {
    use rat_race_engine::ClaimError::*;
    table.claim(&player(actor)?, seat).map_err(|e| match e {
        AlreadySeated => io::Error::new(io::ErrorKind::AlreadyExists, "player already seated"),
        SeatUnavailable => io::Error::new(io::ErrorKind::AlreadyExists, "seat unavailable"),
        UnknownSeat => invalid("seat outside layout"),
    })
}
pub(crate) fn is_claim(raw: &[u8]) -> bool {
    if raw.len() > 2048 {
        return false;
    }
    (|| -> io::Result<()> {
        let envelope = fields(raw, &[1, 2])?;
        let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12])?;
        fields(body[&12], &[204])?;
        Ok(())
    })()
    .is_ok()
}

struct Claim {
    guard: SeatClaimGuard,
    request: [u8; 16],
}
impl Claim {
    fn verify(r: &Replica, db: &Connection, raw: &[u8]) -> io::Result<Self> {
        if raw.len() > 2048 || !r.seating_enabled() {
            return Err(invalid("unsupported claim profile or size"));
        }
        let envelope = fields(raw, &[1, 2])?;
        let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12])?;
        let guard = fields(body[&5], &[1, 2, 3, 4, 5])?;
        let leaf = fields(fields(body[&12], &[204])?[&204], &[1])?;
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
            || guard[&5] != 0u64.to_be_bytes()
        {
            return Err(invalid("invalid seat claim envelope"));
        }
        let &[id] = leaf[&1] else {
            return Err(invalid("invalid seat ID"));
        };
        let seat = SeatId::new(id).ok_or(invalid("invalid seat ID"))?;
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
        check_available(&mut table_at(&state, &claims(db)?, index)?, body[&3], seat)?;
        Ok(Self {
            request,
            guard: SeatClaimGuard {
                profile: r.profile().into(),
                session: r.session.clone(),
                actor: body[&3].into(),
                node,
                observed,
                layout,
                seat,
            },
        })
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
    /// Persist the original on the actor's installation before sending it to the leader.
    pub fn prepare_seat_claim(
        &self,
        guard: &SeatClaimGuard,
        request: [u8; 16],
        key: &SigningKey,
    ) -> io::Result<Signed> {
        let r = &self.replica;
        let mut db = r.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        r.require_lobby_genesis(&tx)?;
        r.verify_replay(&tx)?;
        let raw = guard.sign(request, key);
        let claim = Claim::verify(r, &tx, &raw.0)?;
        if r.local_node != Some(claim.guard.node) {
            return Err(invalid("claim belongs to another installation"));
        }
        let name = local_request_key(claim.guard.node, request);
        if let Some(saved) = store::meta::<Signed>(&tx, &name)? {
            let original = Claim::verify(r, &tx, &saved.0)?;
            if original.request != request
                || original.guard.fingerprint(&request) != claim.guard.fingerprint(&request)
            {
                return Err(invalid(
                    "seat request already reserved with different intent",
                ));
            }
            return Ok(saved);
        }
        store::put(&tx, &name, &raw)?;
        tx.commit().map_err(io::Error::other)?;
        Ok(raw)
    }
    /// Recover the locally signed bytes even if no current leader is reachable.
    pub fn saved_seat_claim(
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
            let claim = Claim::verify(r, &db, &raw.0)?;
            if claim.request != request || claim.guard.node != node || claim.guard.actor != actor {
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
        let occupied = claims(&db)?;
        let table = table_at(&state, &occupied, u64::MAX)?;
        let seats = table
            .seats()
            .map(|(id, player)| LobbySeat {
                id,
                revision: u64::from(player.is_some()),
                occupant: player.map(|p| p.as_ref().to_vec()),
            })
            .collect();
        Ok(LobbySeatView {
            seats,
            setup_revision: setup_revision(&db)?,
            layout_revision: state.layout_revision,
        })
    }
    /// Issue only to an authenticated current participant authorized to act as actor.
    pub async fn seat_claim_guard(&self, actor: &[u8], seat: SeatId) -> io::Result<SeatClaimGuard> {
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
        check_available(&mut table_at(&state, &claims(&db)?, k.index)?, actor, seat)?;
        Ok(SeatClaimGuard {
            profile: r.profile().into(),
            session: r.session.clone(),
            actor: actor.into(),
            observed: log_key(k)
                .try_into()
                .map_err(|_| invalid("invalid log ID"))?,
            layout: state.layout_revision,
            node,
            seat,
        })
    }
}
impl Replica {
    fn seating_enabled(&self) -> bool {
        self.lobby_format == Some(lobby::LobbyFormat::Seating)
    }
    pub(crate) fn inspect_claim(&self, db: &Connection, raw: &[u8]) -> io::Result<Option<Reply>> {
        self.require_lobby_genesis(db)?;
        self.verify_replay(db)?;
        let claim = Claim::verify(self, db, raw)?;
        if let Some(reply) = claim.original(db)? {
            return Ok(Some(reply));
        }
        check_available(
            &mut table_at(&lobby(db)?, &claims(db)?, u64::MAX)?,
            &claim.guard.actor,
            claim.guard.seat,
        )?;
        Ok(None)
    }
    pub(crate) fn apply_claim(
        &self,
        db: &Transaction<'_>,
        k: LogId,
        raw: &[u8],
        source_digest: &[u8],
    ) -> io::Result<Reply> {
        let claim = Claim::verify(self, db, raw)?;
        if let Some(reply) = claim.original(db)? {
            return Ok(reply);
        }
        let g = &claim.guard;
        let fp = g.fingerprint(&claim.request);
        let log = log_key(k);
        let mut occupied = claims(db)?;
        let mut table = table_at(&lobby(db)?, &occupied, k.index)?;
        let (receipt_count, previous_receipt) = self.tip(db, "receipt")?;
        let receipt_seq = receipt_count
            .checked_add(1)
            .ok_or(invalid("receipt range"))?;
        let mut refs = Vec::new();
        let (outcome, semantic) = if table.claim(&player(&g.actor)?, g.seat).is_ok() {
            let before = setup_revision(db)?;
            let after = before
                .checked_add(1)
                .ok_or(invalid("setup revision overflow"))?;
            occupied.push(Occupancy {
                actor: g.actor.clone(),
                seat: g.seat.get(),
                index: k.index,
            });
            store::put(db, "seat_claims", &occupied)?;
            store::put(db, "setup_revision", &after)?;
            let revisions = message(&[
                (1, &g.layout.to_be_bytes()),
                (2, &g.layout.to_be_bytes()),
                (3, &0u64.to_be_bytes()),
                (4, &1u64.to_be_bytes()),
                (5, &before.to_be_bytes()),
                (6, &after.to_be_bytes()),
            ]);
            // Ready requires an owned seat. An unseated claimant has no valid acknowledgment.
            let ready = message(&[(1, &[0]), (2, &[0])]);
            let effect = message(&[
                (1, &g.actor),
                (2, &[]),
                (3, &[g.seat.get()]),
                (4, &revisions),
                (5, &ready),
            ]);
            let facts = frame(&[
                &g.actor,
                &[],
                &[g.seat.get()],
                &g.layout.to_be_bytes(),
                &g.layout.to_be_bytes(),
                &0u64.to_be_bytes(),
                &1u64.to_be_bytes(),
                &before.to_be_bytes(),
                &after.to_be_bytes(),
                &[0],
                &[0],
            ]);
            let (count, prev) = self.tip(db, "event")?;
            let seq = count.checked_add(1).ok_or(invalid("event range"))?;
            let id = hash(b"event-id", &[&self.session, &log, &seq.to_be_bytes()]);
            let event = message(&[
                (1, &self.session),
                (2, &log),
                (3, &seq.to_be_bytes()),
                (4, &id),
                (5, &fp),
                (6, &effect),
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
                    &claim.request,
                    &fp,
                    &204u16.to_be_bytes(),
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
                message(&[(12, &message(&[(204, &effect)]))]),
                frame(&[&12u16.to_be_bytes(), &204u16.to_be_bytes(), &facts]),
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
            request: &claim.request,
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
                b"SeatClaimReceipt/v1",
                self.profile(),
                &self.session,
                &g.actor,
                &claim.request,
                &log,
                &receipt_seq.to_be_bytes(),
                &fp,
                &refs,
                &semantic,
            ]),
        )?;
        db.execute(
            "INSERT INTO receipt VALUES(?,?,?,?,?,?)",
            params![receipt_seq, g.actor, claim.request, fp, record, tip],
        )
        .map_err(io::Error::other)?;
        Ok(Reply::Receipt(record))
    }
}
