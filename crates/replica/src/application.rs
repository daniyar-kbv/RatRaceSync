use crate::{
    store::{meta, put},
    wire::{fields, hash, message},
    *,
};
use ed25519_dalek::{Signature, VerifyingKey};
use futures::{Stream, TryStreamExt};
use openraft::{
    OptionalSend,
    alias::{SnapshotMetaOf, SnapshotOf, StoredMembershipOf},
    storage::{EntryResponder, RaftStateMachine},
};
use prost::Message;
use rat_race_engine::{
    CertificateLot, CertificateSource, Integer, PlayerId, Portfolio, PositionId, RedeemCertificate,
};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

fn number(text: &str) -> io::Result<Integer> {
    text.parse()
        .map_err(|_| invalid("invalid persisted integer"))
}
fn last_event(db: &Connection) -> io::Result<i64> {
    db.query_row("SELECT coalesce(max(seq),0) FROM event", [], |r| r.get(0))
        .map_err(io::Error::other)
}

struct Material {
    principal: i32,
    units: Integer,
    cash: Integer,
    digest: [u8; 32],
}
fn material(db: &Connection, actor: &[u8], pos: &[u8], seq: i64) -> io::Result<Material> {
    let (principal,units,cash,revision):(i32,String,String,i64)=db.query_row(
        "SELECT c.principal,coalesce((SELECT units_after FROM event WHERE actor=?1 AND position=?2 AND seq<=?3 ORDER BY seq DESC LIMIT 1),c.opening_units),
         coalesce((SELECT cash_after FROM event WHERE actor=?1 AND seq<=?3 ORDER BY seq DESC LIMIT 1),p.opening_cash),
         coalesce((SELECT max(seq) FROM event WHERE actor=?1 AND seq<=?3),0)
         FROM participant p JOIN certificate c ON c.actor=p.actor WHERE p.actor=?1 AND c.position=?2",
         params![actor,pos,seq],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(io::Error::other)?;
    let digest = hash(
        b"redemption-material-v1",
        &[
            actor,
            pos,
            &principal.to_be_bytes(),
            units.as_bytes(),
            cash.as_bytes(),
            &revision.to_be_bytes(),
        ],
    );
    Ok(Material {
        principal,
        units: number(&units)?,
        cash: number(&cash)?,
        digest,
    })
}
impl Replica {
    fn verify_checkpoint(&self, db: &Connection) -> io::Result<()> {
        let last = meta::<LogId>(db, "applied")?;
        let checkpoint=db.query_row("SELECT log_id,event_count,event_tip,receipt_count,receipt_tip FROM archive ORDER BY idx DESC LIMIT 1",[],|r|
            Ok((r.get::<_,Vec<u8>>(0)?,(r.get::<_,i64>(1)?,r.get::<_,Vec<u8>>(2)?),(r.get::<_,i64>(3)?,r.get::<_,Vec<u8>>(4)?)))).optional().map_err(io::Error::other)?;
        let events = tip(db, "event", &self.session)?;
        let receipts = tip(db, "receipt", &self.session)?;
        match (last, checkpoint) {
            (Some(k), Some((stored, e, r)))
                if stored == log_key(k) && e == events && r == receipts =>
            {
                Ok(())
            }
            (None, None) if events.0 == 0 && receipts.0 == 0 => Ok(()),
            _ => Err(invalid("applied checkpoint mismatch")),
        }
    }
    /// Internal projection for a caller that has already established read authority.
    /// The consensus-facing caller must obtain a linearizable read before issuing this guard.
    pub(crate) fn redemption_guard(
        &self,
        actor: &[u8],
        position: &[u8],
    ) -> io::Result<(i64, [u8; 32])> {
        let db = self.lock()?;
        self.verify_checkpoint(&db)?;
        let seq = last_event(&db)?;
        let m = material(&db, actor, position, seq)?;
        if m.units <= 0.into() {
            return Err(invalid("closed position"));
        }
        Ok((seq, m.digest))
    }
    pub(crate) fn inspect(
        &self,
        db: &Connection,
        signed: &[u8],
    ) -> io::Result<(Command, Option<Reply>)> {
        if signed.len() > 2048 {
            return Err(invalid("oversized redemption"));
        }
        let envelope = fields(signed, &[1, 2])?;
        let c = Command::parse(envelope[&1])?;
        if c.session != self.session {
            return Err(invalid("wrong game"));
        }
        let key: Vec<u8> = db
            .query_row(
                "SELECT key FROM participant WHERE actor=?",
                [&c.actor],
                |r| r.get(0),
            )
            .map_err(io::Error::other)?;
        VerifyingKey::from_bytes(key.as_slice().try_into().map_err(io::Error::other)?)
            .map_err(io::Error::other)?
            .verify_strict(
                envelope[&1],
                &Signature::from_slice(envelope[&2]).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
        let original = db
            .query_row(
                "SELECT seq,fingerprint,record,tip FROM receipt WHERE actor=? AND request=?",
                params![c.actor, c.request],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(io::Error::other)?;
        let reply = if let Some((seq, fp, record, stored_tip)) = original {
            if seq < 1 {
                return Err(invalid("invalid receipt sequence"));
            }
            let f = fields(&record, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
            let (source,digest,checkpoint):(Vec<u8>,Vec<u8>,Vec<u8>)=db.query_row(
                "SELECT source,digest,receipt_tip FROM archive WHERE log_id=? AND receipt_count=?",params![f[&5],seq],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(io::Error::other)?;
            let previous = if seq == 1 {
                hash(b"genesis", &[wire::PROFILE, &self.session, b"receipt"]).to_vec()
            } else {
                db.query_row("SELECT tip FROM receipt WHERE seq=?", [seq - 1], |r| {
                    r.get(0)
                })
                .map_err(io::Error::other)?
            };
            let expected = hash(
                b"receipt-step",
                &[
                    &previous,
                    &c.session,
                    &c.actor,
                    &c.request,
                    &fp,
                    f[&5],
                    &seq.to_be_bytes(),
                    f[&8],
                    &digest,
                    &outcome_digest(f[&7])?,
                ],
            );
            if f[&1] != c.session
                || f[&2] != c.actor
                || f[&3] != c.request
                || f[&4] != fp
                || f[&6] != seq.to_be_bytes()
                || f[&9] != digest
                || checkpoint != expected
                || stored_tip != expected
                || digest != Sha256::digest(&source).as_slice()
            {
                return Err(invalid("original receipt integrity mismatch"));
            }
            Some(if fp == c.fingerprint() {
                Reply::Receipt(record)
            } else {
                Reply::RequestIdConflict
            })
        } else {
            None
        };
        Ok((c, reply))
    }
    fn verify_observation(&self, db: &Connection, c: &Command) -> io::Result<Material> {
        if meta::<bool>(db, "finance_open")? != Some(true) {
            return Err(invalid("finance gate closed"));
        }
        if c.observed < 0 || c.observed > last_event(db)? {
            return Err(invalid("invalid observation"));
        }
        let m = material(db, &c.actor, &c.position, c.observed)?;
        if m.digest != c.guard || c.units > m.units {
            return Err(invalid("ineligible original redemption"));
        }
        Ok(m)
    }
    /// Returns the original response for a known request, or admits a new command.
    /// Call at a quorum-confirmed read boundary. Apply independently repeats validation.
    pub(crate) fn preflight(&self, signed: &Signed) -> io::Result<Option<Reply>> {
        let db = self.lock()?;
        self.verify_checkpoint(&db)?;
        let (c, reply) = self.inspect(&db, &signed.0)?;
        if reply.is_none() {
            self.verify_observation(&db, &c)?;
            if material(&db, &c.actor, &c.position, last_event(&db)?)?.digest != c.guard {
                return Err(invalid("stale observation"));
            }
        }
        Ok(reply)
    }
    fn apply_command(
        &self,
        tx: &Transaction<'_>,
        k: &[u8],
        raw: &[u8],
        parent: &[u8],
    ) -> io::Result<Reply> {
        let (c, known) = self.inspect(tx, raw)?;
        if let Some(reply) = known {
            return Ok(reply);
        }
        let old = self.verify_observation(tx, &c)?;
        let current = material(tx, &c.actor, &c.position, last_event(tx)?)?;
        let fp = c.fingerprint();
        let mut refs = vec![];
        let outcome = if old.digest != current.digest {
            message(&[(13, &[8, 1])])
        } else {
            let applied = reduce(tx, &c, &current)?;
            let data = applied.encode_to_vec();
            let seq = last_event(tx)?
                .checked_add(1)
                .ok_or(invalid("event range"))?;
            let id = hash(b"event-id", &[&c.session, k, &seq.to_be_bytes()]);
            let record = message(&[
                (1, &c.session),
                (2, k),
                (3, &seq.to_be_bytes()),
                (4, &id),
                (5, &fp),
                (6, &c.body()),
                (7, &data),
                (8, parent),
            ]);
            let prev = tip(tx, "event", &c.session)?.1;
            let next = hash(
                b"event-step",
                &[
                    &prev,
                    &seq.to_be_bytes(),
                    k,
                    &id,
                    &fp,
                    parent,
                    &economic_transcript(&applied),
                ],
            );
            tx.execute(
                "INSERT INTO event VALUES(?,?,?,?,?,?,?,?)",
                params![
                    seq,
                    c.actor,
                    c.position,
                    applied.cash_after,
                    applied.units_after,
                    record,
                    Sha256::digest(&record).as_slice(),
                    next
                ],
            )
            .map_err(io::Error::other)?;
            refs.extend(id);
            message(&[(11, &message(&[(109, &data)]))])
        };
        let (prev_seq, prev) = tip(tx, "receipt", &c.session)?;
        let seq = prev_seq.checked_add(1).ok_or(invalid("receipt range"))?;
        let record = message(&[
            (1, &c.session),
            (2, &c.actor),
            (3, &c.request),
            (4, &fp),
            (5, k),
            (6, &seq.to_be_bytes()),
            (7, &outcome),
            (8, &refs),
            (9, parent),
        ]);
        let next = hash(
            b"receipt-step",
            &[
                &prev,
                &c.session,
                &c.actor,
                &c.request,
                &fp,
                k,
                &seq.to_be_bytes(),
                &refs,
                parent,
                &outcome_digest(&outcome)?,
            ],
        );
        tx.execute(
            "INSERT INTO receipt VALUES(?,?,?,?,?,?)",
            params![seq, c.actor, c.request, fp, record, next],
        )
        .map_err(io::Error::other)?;
        Ok(Reply::Receipt(record))
    }
    fn apply_entry(&self, e: Entry) -> io::Result<Reply> {
        let mut db = self.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        self.verify_checkpoint(&tx)?;
        let prev = meta::<LogId>(&tx, "applied")?;
        if prev.map(|id| id.index.checked_add(1)).unwrap_or(Some(0)) != Some(e.log_id.index) {
            return Err(invalid("noncontiguous apply"));
        }
        let k = log_key(e.log_id);
        let src = &e.payload.bytes;
        let digest = Sha256::digest(src);
        let reply = if let Some(m) = e.payload.check_members()? {
            let mut stmt = tx
                .prepare("SELECT node FROM participant ORDER BY node")
                .map_err(io::Error::other)?;
            let voters = stmt
                .query_map([], |row| row.get::<_, [u8; 16]>(0))
                .map_err(io::Error::other)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(io::Error::other)?;
            if meta::<StoredMembershipOf<Types>>(&tx, "membership")?.is_some()
                || m.get_joint_config().len() != 1
                || !(2..=10).contains(&m.voter_ids().count())
                || m.non_write_voter_ids().next().is_some()
                || !voters.into_iter().map(ReplicaId).eq(m.voter_ids())
            {
                return Err(invalid("unsupported fixed membership"));
            }
            put(
                &tx,
                "membership",
                &StoredMembershipOf::<Types>::new(Some(e.log_id), m),
            )?;
            Reply::Protocol
        } else if src == &[0] {
            Reply::Protocol
        } else if let Some(raw) = src.strip_prefix(&[1]) {
            self.apply_command(&tx, &k, raw, &digest)?
        } else {
            return Err(invalid("unknown raft source"));
        };
        let (events, et) = tip(&tx, "event", &self.session)?;
        let (receipts, rt) = tip(&tx, "receipt", &self.session)?;
        tx.execute(
            "INSERT INTO archive VALUES(?,?,?,?,?,?,?,?)",
            params![
                e.log_id.index.to_be_bytes(),
                k,
                src,
                digest.as_slice(),
                events,
                et,
                receipts,
                rt
            ],
        )
        .map_err(io::Error::other)?;
        put(&tx, "applied", &e.log_id)?;
        #[cfg(test)]
        if src.first() == Some(&1) && self.crash.load(std::sync::atomic::Ordering::Acquire) == 1 {
            std::process::exit(81)
        }
        tx.commit().map_err(io::Error::other)?;
        #[cfg(test)]
        if src.first() == Some(&1) && self.crash.load(std::sync::atomic::Ordering::Acquire) == 2 {
            std::process::exit(82)
        }
        Ok(reply)
    }
}
fn reduce(tx: &Transaction<'_>, c: &Command, m: &Material) -> io::Result<Applied> {
    let(cash,monthly,units):(String,String,String)=tx.query_row("SELECT cash,monthly,units FROM participant JOIN certificate USING(actor) WHERE actor=? AND position=?",
        params![c.actor,c.position],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(io::Error::other)?;
    if number(&units)? != m.units || number(&cash)? != m.cash {
        return Err(invalid("financial projection mismatch"));
    }
    let owner = PlayerId::try_from(c.actor.as_slice()).map_err(|_| invalid("actor"))?;
    let pos = PositionId::try_from(c.position.as_slice()).map_err(|_| invalid("position"))?;
    let source = match m.principal {
        4000 => CertificateSource::Principal4000,
        5000 => CertificateSource::Principal5000,
        _ => return Err(invalid("unknown certificate")),
    };
    let mut portfolio = Portfolio {
        owner: owner.clone(),
        cash: number(&cash)?,
        monthly_income: number(&monthly)?,
        certificates: [(
            pos.clone(),
            CertificateLot {
                source,
                units: m.units.clone(),
            },
        )]
        .into(),
    };
    let a = portfolio
        .redeem_certificate(
            &owner,
            &RedeemCertificate {
                position: pos,
                units: c.units.clone(),
            },
        )
        .map_err(|_| invalid("invalid committed redemption"))?;
    tx.execute(
        "UPDATE participant SET cash=?,monthly=? WHERE actor=?",
        params![
            a.cash.after.to_string(),
            a.player_monthly_income.after.to_string(),
            c.actor
        ],
    )
    .map_err(io::Error::other)?;
    tx.execute(
        "UPDATE certificate SET units=? WHERE actor=? AND position=?",
        params![a.units.after.to_string(), c.actor, c.position],
    )
    .map_err(io::Error::other)?;
    Ok(Applied {
        position: c.position.clone(),
        principal_per_unit: m.principal,
        units_redeemed: a.units_redeemed.to_string(),
        principal_returned: a.principal_returned.to_string(),
        units_before: a.units.before.to_string(),
        units_after: a.units.after.to_string(),
        cash_before: a.cash.before.to_string(),
        cash_after: a.cash.after.to_string(),
        monthly_removed: a.monthly_income_removed.to_string(),
        lot_income_before: a.lot_monthly_income.before.to_string(),
        lot_income_after: a.lot_monthly_income.after.to_string(),
        total_income_before: a.player_monthly_income.before.to_string(),
        total_income_after: a.player_monthly_income.after.to_string(),
    })
}
fn economic_transcript(a: &Applied) -> [u8; 32] {
    hash(
        b"redemption-effects",
        &[
            &a.position,
            &a.principal_per_unit.to_be_bytes(),
            a.units_redeemed.as_bytes(),
            a.principal_returned.as_bytes(),
            a.units_before.as_bytes(),
            a.units_after.as_bytes(),
            a.cash_before.as_bytes(),
            a.cash_after.as_bytes(),
            a.monthly_removed.as_bytes(),
            a.lot_income_before.as_bytes(),
            a.lot_income_after.as_bytes(),
            a.total_income_before.as_bytes(),
            a.total_income_after.as_bytes(),
        ],
    )
}
fn outcome_digest(outcome: &[u8]) -> io::Result<[u8; 32]> {
    if let Ok(f) = fields(outcome, &[13]) {
        if f[&13] != [8, 1] {
            return Err(invalid("unknown guard conflict"));
        }
        return Ok(hash(b"guard-conflict", &[b"material-dependency-changed"]));
    }
    let nested = fields(outcome, &[11])?;
    let applied = fields(nested[&11], &[109])?;
    let decoded = Applied::decode(applied[&109]).map_err(io::Error::other)?;
    if decoded.encode_to_vec() != applied[&109] {
        return Err(invalid("invalid stored economic result"));
    }
    Ok(economic_transcript(&decoded))
}
fn tip(db: &Connection, kind: &str, session: &[u8]) -> io::Result<(i64, Vec<u8>)> {
    let sql = match kind {
        "event" => "SELECT seq,tip FROM event ORDER BY seq DESC LIMIT 1",
        "receipt" => "SELECT seq,tip FROM receipt ORDER BY seq DESC LIMIT 1",
        _ => unreachable!(),
    };
    Ok(db
        .query_row(sql, [], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()
        .map_err(io::Error::other)?
        .unwrap_or_else(|| {
            (
                0,
                hash(b"genesis", &[wire::PROFILE, session, kind.as_bytes()]).to_vec(),
            )
        }))
}
impl RaftStateMachine<Types> for Replica {
    type SnapshotData = ();
    type SnapshotBuilder = Self;
    async fn applied_state(&mut self) -> io::Result<(Option<LogId>, StoredMembershipOf<Types>)> {
        let db = self.lock()?;
        self.verify_checkpoint(&db)?;
        let complete: bool = db
            .query_row(
                "SELECT (SELECT count(*)=coalesce(max(seq),0) FROM receipt) AND
                    (SELECT count(*)=coalesce(max(seq),0) FROM event)",
                [],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        if !complete {
            return Err(invalid("incomplete history sequence"));
        }
        Ok((
            meta(&db, "applied")?,
            meta(&db, "membership")?.unwrap_or_default(),
        ))
    }
    async fn apply<S>(&mut self, mut entries: S) -> io::Result<()>
    where
        S: Stream<Item = io::Result<EntryResponder<Types>>> + Unpin + OptionalSend,
    {
        while let Some((e, responder)) = entries.try_next().await? {
            let r = self.apply_entry(e)?;
            if let Some(resp) = responder {
                resp.send(r)
            }
        }
        Ok(())
    }
    async fn try_create_snapshot_builder(&mut self, _: bool) -> Option<Self> {
        None
    }
    async fn get_snapshot_builder(&mut self) -> Self {
        self.clone()
    }
    async fn get_current_snapshot(&mut self) -> io::Result<Option<SnapshotOf<Types, ()>>> {
        Ok(None)
    }
    async fn install_snapshot(&mut self, _: &SnapshotMetaOf<Types>, _: ()) -> io::Result<()> {
        Err(invalid("unauthenticated snapshot"))
    }
}

impl openraft::RaftSnapshotBuilder<Types> for Replica {
    type SnapshotData = ();
    async fn build_snapshot(&mut self) -> io::Result<SnapshotOf<Types, ()>> {
        Err(invalid("snapshot transfer unavailable"))
    }
}
