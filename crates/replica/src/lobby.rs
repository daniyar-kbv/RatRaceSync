use crate::{
    application::ReceiptRecord,
    genesis::Creator,
    wire::{fields, hash, message},
    *,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use rat_race_engine::LobbyCapacity;
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LobbyFormat {
    Legacy,
    SemanticLinks,
}

impl LobbyFormat {
    pub fn profile(self) -> &'static [u8] {
        match self {
            Self::Legacy => b"RatRaceSync/Classic101/lobby/v1",
            Self::SemanticLinks => b"RatRaceSync/Classic101/lobby/v2",
        }
    }
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        [Self::Legacy, Self::SemanticLinks]
            .into_iter()
            .find(|f| f.profile() == bytes)
            .ok_or(invalid("unsupported Create profile"))
    }
}

/// Local profile and entitlement checks come from the trusted installation
/// adapter. They are needed to reserve a new Create, and stay off the log.
#[derive(Clone, Copy)]
pub struct CreateLobby<'a> {
    pub request: [u8; 16],
    pub actor: &'a [u8],
    pub target: u8,
    pub profile_complete: bool,
    pub can_host: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum LobbyStage {
    Open = 1,
}

/// Original committed LobbyCreated facts. Seats are in physical order and
/// vacant. Joining the lobby as Host does not claim a seat or make it Ready.
#[derive(Clone, PartialEq, Message)]
pub struct LobbyCreated {
    #[prost(bytes = "vec", tag = "1")]
    pub session: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub creator: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub host: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub target: u32,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub seats: Vec<Vec<u8>>,
    #[prost(uint64, tag = "6")]
    pub setup_revision: u64,
    #[prost(enumeration = "LobbyStage", tag = "7")]
    pub stage: i32,
    #[prost(bytes = "vec", tag = "8")]
    pub genesis: Vec<u8>,
    #[prost(uint64, tag = "9")]
    pub layout_revision: u64,
    #[prost(uint32, tag = "10")]
    pub join_ordinal: u32,
    #[prost(bytes = "vec", tag = "11")]
    pub creator_voter: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    pub profile: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LobbyCreation {
    pub created: LobbyCreated,
    /// Original receipt envelope, including the archived Raft source digest.
    pub receipt: Vec<u8>,
}

// Explicit typed records for v2. Lengths and integers use network byte order.
// The original signed protobuf and its payload checksum belong to the archive.
fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let mut record = Vec::new();
    for part in parts {
        record.extend_from_slice(&(part.len() as u64).to_be_bytes());
        record.extend_from_slice(part);
    }
    record
}

impl LobbyCreated {
    fn semantic_facts(&self) -> Vec<u8> {
        let ordered_seats = frame(&self.seats.iter().map(Vec::as_slice).collect::<Vec<_>>());
        frame(&[
            &self.profile,
            &self.session,
            &self.creator,
            &self.host,
            &self.target.to_be_bytes(),
            &ordered_seats,
            &self.setup_revision.to_be_bytes(),
            &self.stage.to_be_bytes(),
            &self.genesis,
            &self.layout_revision.to_be_bytes(),
            &self.join_ordinal.to_be_bytes(),
            &self.creator_voter,
        ])
    }
}

fn persist_link(
    db: &Connection,
    ledger: &str,
    seq: i64,
    domain: &[u8],
    previous: &[u8],
    record: &[u8],
) -> io::Result<[u8; 32]> {
    db.execute(
        "INSERT INTO semantic_link(ledger,seq,previous_tip,record) VALUES(?,?,?,?)",
        params![ledger, seq, previous, record],
    )
    .map_err(io::Error::other)?;
    Ok(hash(domain, &[previous, record]))
}

pub(crate) struct LobbyCommand<'a> {
    pub format: LobbyFormat,
    pub session: &'a [u8],
    pub actor: &'a [u8],
    pub request: [u8; 16],
    pub node: ReplicaId,
    pub capacity: LobbyCapacity,
}
impl LobbyCommand<'_> {
    fn body(&self) -> Vec<u8> {
        let guard = message(&[(1, b"new-session"), (2, &self.node.0)]);
        let leaf = message(&[(1, &[self.capacity.count()])]);
        message(&[
            (1, self.format.profile()),
            (2, self.session),
            (3, self.actor),
            (4, &self.request),
            (5, &guard),
            (12, &message(&[(201, &leaf)])),
        ])
    }
    pub fn sign(&self, key: &SigningKey) -> Vec<u8> {
        let body = self.body();
        message(&[(1, &body), (2, &key.sign(&body).to_bytes())])
    }
    pub fn verify<'a>(
        raw: &'a [u8],
        session: &[u8],
        creator: &Creator,
    ) -> io::Result<LobbyCommand<'a>> {
        if raw.len() > 2048 {
            return Err(invalid("oversized Create"));
        }
        let envelope = fields(raw, &[1, 2])?;
        let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12])?;
        let guard = fields(body[&5], &[1, 2])?;
        let format = LobbyFormat::parse(body[&1])?;
        if body[&2] != session
            || body[&3] != creator.actor
            || guard[&1] != b"new-session"
            || guard[&2] != creator.node.0
        {
            return Err(invalid("unexpected Create identity, guard or profile"));
        }
        let request: [u8; 16] = body[&4].try_into().map_err(io::Error::other)?;
        if request[6] >> 4 != 4 || request[8] >> 6 != 2 {
            return Err(invalid("invalid Create request"));
        }
        let leaf = fields(fields(body[&12], &[201])?[&201], &[1])?;
        let [count] = leaf[&1] else {
            return Err(invalid("invalid Create capacity encoding"));
        };
        let capacity = LobbyCapacity::new(*count).ok_or(invalid("invalid lobby capacity"))?;
        VerifyingKey::from_bytes(&creator.key)
            .map_err(io::Error::other)?
            .verify_strict(
                envelope[&1],
                &Signature::from_slice(envelope[&2]).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
        Ok(LobbyCommand {
            format,
            session: body[&2],
            actor: body[&3],
            request,
            node: creator.node,
            capacity,
        })
    }
    fn fingerprint(&self) -> [u8; 32] {
        hash(
            b"semantic-intent",
            &[
                self.format.profile(),
                self.session,
                self.actor,
                &self.request,
                b"new-session",
                &self.node.0,
                &201u16.to_be_bytes(),
                &[self.capacity.count()],
            ],
        )
    }
    fn created(&self, g: LogId) -> LobbyCreated {
        LobbyCreated {
            session: self.session.into(),
            creator: self.actor.into(),
            host: self.actor.into(),
            target: self.capacity.count().into(),
            seats: self.capacity.ordered_seats().map(|id| vec![id]).collect(),
            genesis: log_key(g),
            setup_revision: 1,
            layout_revision: 1,
            stage: LobbyStage::Open as i32,
            join_ordinal: 1,
            creator_voter: self.node.0.to_vec(),
            profile: self.format.profile().to_vec(),
        }
    }
}

impl Replica {
    /// An installation can only have proposed its reserved original command
    /// after durably signing genesis. Check even the committed-but-unapplied tail.
    pub(crate) fn verify_pending_create(&self, signed: &Signed, has_root: bool) -> io::Result<()> {
        let db = self.lock()?;
        let mut statement = db
            .prepare("SELECT entry FROM raft_log ORDER BY idx")
            .map_err(io::Error::other)?;
        let mut rows = statement.query([]).map_err(io::Error::other)?;
        while let Some(row) = rows.next().map_err(io::Error::other)? {
            let entry: Entry = store::decode(&row.get::<_, Vec<u8>>(0).map_err(io::Error::other)?)?;
            if let Some(raw) = entry.payload.bytes.strip_prefix(&[1])
                && (!has_root || raw != signed.0)
            {
                return Err(invalid(
                    "logged Create lacks matching original reservation or genesis",
                ));
            }
        }
        Ok(())
    }

    fn lobby_command<'a>(&self, db: &Connection, raw: &'a [u8]) -> io::Result<LobbyCommand<'a>> {
        let creator = store::meta::<Creator>(db, "creator")?.ok_or(invalid("no creator"))?;
        let command = LobbyCommand::verify(raw, &self.session, &creator)?;
        if Some(command.format) != self.lobby_format {
            return Err(invalid("Create differs from pinned profile"));
        }
        Ok(command)
    }

    // Replay re-verifies the signed source and reconstructs the projection,
    // event and receipt from the retained committed prefix before returning them.
    pub(crate) fn inspect_lobby(
        &self,
        db: &Connection,
        signed: &Signed,
    ) -> io::Result<Option<Reply>> {
        let c = self.lobby_command(db, &signed.0)?;
        self.require_lobby_genesis(db)?;
        self.verify_replay(db)?;
        self.known_create(db, &c)
    }

    fn known_create(&self, db: &Connection, c: &LobbyCommand<'_>) -> io::Result<Option<Reply>> {
        let saved: Option<(Vec<u8>, Vec<u8>)> = db
            .query_row(
                "SELECT fingerprint, record FROM receipt WHERE actor=? AND request=?",
                params![c.actor, c.request],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(io::Error::other)?;
        match saved {
            Some((fp, record)) if fp == c.fingerprint() => Ok(Some(Reply::Receipt(record))),
            Some(_) => Ok(Some(Reply::RequestIdConflict)),
            None if store::meta::<Vec<u8>>(db, "lobby")?.is_some() => {
                Err(invalid("lobby already created"))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn apply_lobby(
        &self,
        tx: &Transaction<'_>,
        k: &[u8],
        raw: &[u8],
        digest: &[u8],
    ) -> io::Result<Reply> {
        let c = self.lobby_command(tx, raw)?;
        if let Some(reply) = self.known_create(tx, &c)? {
            return Ok(reply);
        }
        let g = store::meta::<LogId>(tx, "genesis_log")?
            .ok_or(invalid("missing creator membership"))?;
        let created = c.created(g);
        let data = created.encode_to_vec();
        let (events, prev_event) = self.tip(tx, "event")?;
        let (receipts, prev_receipt) = self.tip(tx, "receipt")?;
        if events != 0 || receipts != 0 {
            return Err(invalid("Create requires an empty domain history"));
        }
        let seq = 1_i64;
        let id = hash(b"event-id", &[c.session, k, &seq.to_be_bytes()]);
        let fp = c.fingerprint();
        let event = message(&[
            (1, c.session),
            (2, k),
            (3, &seq.to_be_bytes()),
            (4, &id),
            (5, &fp),
            (6, &c.body()),
            (7, &data),
            (8, digest),
        ]);
        let outcome = message(&[(12, &message(&[(201, &data)]))]);
        let receipt = ReceiptRecord {
            session: c.session,
            actor: c.actor,
            request: &c.request,
            fingerprint: &fp,
            log: k,
            seq,
            outcome: &outcome,
            refs: &id,
            source_digest: digest,
        };
        let (record, tip, event_tip) = match c.format {
            LobbyFormat::Legacy => {
                let seats: Vec<u8> = c.capacity.ordered_seats().collect();
                let result_digest = hash(
                    b"lobby-created/v1",
                    &[
                        c.format.profile(),
                        c.session,
                        c.actor,
                        &created.host,
                        &created.target.to_be_bytes(),
                        &seats,
                        &created.setup_revision.to_be_bytes(),
                        &created.stage.to_be_bytes(),
                        &created.genesis,
                        &created.layout_revision.to_be_bytes(),
                        &created.join_ordinal.to_be_bytes(),
                        &created.creator_voter,
                    ],
                );
                let legacy_event_tip = hash(
                    b"event-step",
                    &[
                        &prev_event,
                        &seq.to_be_bytes(),
                        k,
                        &id,
                        &fp,
                        digest,
                        &result_digest,
                    ],
                );
                let (record, tip) = receipt.encode(&prev_receipt, &result_digest);
                (record, tip, legacy_event_tip)
            }
            LobbyFormat::SemanticLinks => {
                let facts = created.semantic_facts();
                let sequence = seq.to_be_bytes();
                let operation = 201u16.to_be_bytes();
                let event_record = frame(&[
                    b"LobbyCreated/v2",
                    c.format.profile(),
                    c.session,
                    k,
                    &sequence,
                    &id,
                    &operation,
                    c.actor,
                    &c.request,
                    &fp,
                    &facts,
                ]);
                let receipt_record = frame(&[
                    b"CreateReceipt/v2",
                    c.format.profile(),
                    c.session,
                    c.actor,
                    &c.request,
                    k,
                    &sequence,
                    &operation,
                    &fp,
                    &12u16.to_be_bytes(),
                    &facts,
                    &id,
                ]);
                let event_tip = persist_link(
                    tx,
                    "event",
                    seq,
                    b"event-step/v2",
                    &prev_event,
                    &event_record,
                )?;
                let tip = persist_link(
                    tx,
                    "receipt",
                    seq,
                    b"receipt-step/v2",
                    &prev_receipt,
                    &receipt_record,
                )?;
                (receipt.record(), tip, event_tip)
            }
        };
        tx.execute(
            "INSERT INTO event(seq,actor,record,digest,tip) VALUES(?,?,?,?,?)",
            params![
                seq,
                c.actor,
                event,
                Sha256::digest(&event).as_slice(),
                event_tip
            ],
        )
        .map_err(io::Error::other)?;
        store::put(tx, "lobby", &data)?;
        tx.execute(
            "INSERT INTO receipt VALUES(?,?,?,?,?,?)",
            params![seq, c.actor, c.request, fp, record, tip],
        )
        .map_err(io::Error::other)?;
        Ok(Reply::Receipt(record))
    }

    pub(crate) fn original_lobby(&self, signed: &Signed) -> io::Result<LobbyCreation> {
        let db = self.lock()?;
        let Some(Reply::Receipt(receipt)) = self.inspect_lobby(&db, signed)? else {
            return Err(invalid("missing original Create receipt"));
        };
        LobbyCreation::from_receipt(receipt)
    }
}
impl LobbyCreation {
    pub(crate) fn from_receipt(receipt: Vec<u8>) -> io::Result<Self> {
        let outcome = fields(&receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
        let leaf = fields(fields(outcome[&7], &[12])?[&12], &[201])?;
        let created = LobbyCreated::decode(leaf[&201]).map_err(io::Error::other)?;
        Ok(LobbyCreation { created, receipt })
    }
}
