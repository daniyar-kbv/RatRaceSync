use super::*;
use openraft::alias::StoredMembershipOf;
const ROW: &[u8] = b"RatRaceSync/history/row/v2";
const ISSUE: &[u8] = b"RatRaceSync/history/issue/v2";
const SIGNER: &[u8] = b"RatRaceSync/history/signer/v2";

pub(crate) fn membership(db: &Connection) -> io::Result<StoredMembershipOf<Types>> {
    store::meta(db, "membership")?.ok_or(invalid("missing committed membership"))
}
pub(crate) fn boundary(db: &Connection) -> io::Result<LogId> {
    let applied = store::meta::<LogId>(db, "applied")?.ok_or(invalid("no applied checkpoint"))?;
    if store::meta::<Option<LogId>>(db, "committed")?.flatten() != Some(applied) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "waiting for applied commit boundary",
        ));
    }
    Ok(applied)
}
fn config_at(db: &Connection, idx: u64, inclusive: bool) -> io::Result<Option<Vec<u8>>> {
    let entry:Option<Vec<u8>>=db.query_row(
        "SELECT l.entry FROM archive a JOIN raft_log l USING(idx)
        WHERE (a.idx<?1 OR (?2 AND a.idx=?1)) AND substr(a.source,1,1) IN(x'02',x'03') ORDER BY a.idx DESC LIMIT 1",
        params![idx.to_be_bytes(),inclusive],|r|r.get(0)).optional().map_err(io::Error::other)?;
    entry
        .map(|bytes| {
            let entry = store::decode::<Entry>(&bytes)?;
            let members = entry
                .payload
                .check_members()?
                .ok_or(invalid("invalid historical membership"))?;
            let creator =
                store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
            let valid = if let Some(d) = seating::departure::left_at(db, entry.log_id.index)? {
                let voters = super::quorum::voters(db, entry.log_id.index)?;
                entry.log_id == d.log_id
                    && entry.payload.leave_source()?.is_some()
                    && members
                        == Members::new_with_defaults(
                            vec![voters.iter().map(|v| v.node).collect()],
                            [],
                        )
            } else if let Some(third) = third_at(db, entry.log_id.index)? {
                let first = joined_at(db, entry.log_id.index)?
                    .ok_or(invalid("missing predecessor voter"))?;
                entry.log_id == third.log_id
                    && members == join::promotion::roster(creator.node, first.node, third.node)
                    && entry.payload.join_command()?.is_some()
            } else if let Some(member) = joined_at(db, entry.log_id.index)? {
                (entry.log_id == member.log_id
                    && members == join::target(creator.node, member.node)
                    && entry.payload.join_command()?.is_some())
                    || (entry.log_id.index > member.log_id.index
                        && third::registration(&members, creator.node, member.node)
                        && entry.payload.join_command()?.is_none())
            } else {
                members.voter_ids().eq([creator.node])
            };
            if members.get_joint_config().len() != 1
                || !valid
                || members.non_write_voter_ids().count() > 1
            {
                return Err(invalid("unsupported historical signer configuration"));
            }
            Ok(message(&[
                (1, &log_key(entry.log_id)),
                (2, &store::encode(&members)?),
            ]))
        })
        .transpose()
}
struct AppliedCheckpoint {
    id: Vec<u8>,
    source: Vec<u8>,
    digest: [u8; 32],
    events: i64,
    event_tip: [u8; 32],
    receipts: i64,
    receipt_tip: [u8; 32],
    raw: Vec<u8>,
}
pub(super) fn checkpoint(r: &Replica, db: &Connection, index: u64) -> io::Result<Vec<u8>> {
    let AppliedCheckpoint{id,source,digest,events,event_tip,receipts,receipt_tip,raw}=db.query_row(
        "SELECT a.log_id,a.source,a.digest,a.event_count,a.event_tip,a.receipt_count,a.receipt_tip,l.entry
         FROM archive a JOIN raft_log l USING(idx) WHERE a.idx=?",[index.to_be_bytes()],
        |r|Ok(AppliedCheckpoint{id:r.get(0)?,source:r.get(1)?,digest:r.get(2)?,events:r.get(3)?,event_tip:r.get(4)?,receipts:r.get(5)?,receipt_tip:r.get(6)?,raw:r.get(7)?})).map_err(io::Error::other)?;
    let entry = store::decode::<Entry>(&raw)?;
    let kind = source
        .first()
        .filter(|k| **k <= 3)
        .ok_or(invalid("unknown archived payload"))?;
    if entry.log_id.index != index
        || id != log_key(entry.log_id)
        || source != entry.payload.bytes
        || Sha256::digest(&source)[..] != digest
    {
        return Err(invalid(
            "historical source differs from retained Raft entry",
        ));
    }
    let genesis = store::meta::<SignedGenesis>(db, "signed_genesis")?
        .ok_or(invalid("missing historical genesis"))?;
    let predecessor = config_at(db, index, false)?;
    if predecessor.is_none() != (index == 0) {
        return Err(invalid("missing predecessor membership"));
    }
    let effective = config_at(db, index, true)?.ok_or(invalid("missing effective membership"))?;
    let creator =
        store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing signer binding"))?;
    let binding = if let Some(member) = joined_at(db, index)? {
        let mut bindings = vec![
            (
                creator.node,
                binding(&creator.actor, &creator.key, creator.node),
            ),
            (
                member.node,
                binding(&member.actor, &member.key, member.node),
            ),
        ];
        if let Some(third) = third_at(db, index)? {
            bindings.push((third.node, binding(&third.actor, &third.key, third.node)));
        }
        if let Some(d) = seating::departure::left_at(db, index)? {
            bindings.retain(|(id, _)| *id != d.node);
        }
        bindings.sort_by_key(|x| x.0);
        message(
            &bindings
                .iter()
                .enumerate()
                .map(|(i, (_, b))| ((i + 1) as u32, b.as_slice()))
                .collect::<Vec<_>>(),
        )
    } else {
        binding(&creator.actor, &creator.key, creator.node)
    };
    Ok(message(&[
        (1, ROW),
        (2, &r.session),
        (3, &id),
        (4, &[1, *kind]),
        (5, &digest),
        (6, &events.to_be_bytes()),
        (7, &event_tip),
        (8, &receipts.to_be_bytes()),
        (9, &receipt_tip),
        (10, r.profile()),
        (11, &genesis.body),
        (12, &genesis.signature),
        (13, &[u8::from(predecessor.is_some())]),
        (14, predecessor.as_deref().unwrap_or_default()),
        (15, &effective),
        (16, &binding),
    ]))
}
fn binding(actor: &[u8], key: &[u8; 32], node: ReplicaId) -> Vec<u8> {
    message(&[(1, actor), (2, key), (3, &node.0), (4, &1u64.to_be_bytes())])
}
pub(super) fn joined_at(db: &Connection, index: u64) -> io::Result<Option<JoinedMember>> {
    Ok(store::meta::<JoinedMember>(db, "first_member")?.filter(|m| m.log_id.index <= index))
}
pub(super) fn third_at(db: &Connection, index: u64) -> io::Result<Option<JoinedMember>> {
    Ok(store::meta::<JoinedMember>(db, "third_member")?.filter(|m| m.log_id.index <= index))
}
pub(super) fn signer_record(
    r: &Replica,
    db: &Connection,
    index: u64,
    creator: &Creator,
) -> io::Result<Vec<u8>> {
    let row = checkpoint(r, db, index)?;
    let issue = message(&[(1, ISSUE), (2, &r.session), (3, &row)]);
    Ok(message(&[
        (1, SIGNER),
        (2, &issue),
        (3, &creator.actor),
        (4, &creator.node.0),
        (5, &1u64.to_be_bytes()),
        (6, &creator.key),
    ]))
}
fn transcript(r: &Replica, db: &Connection, index: u64) -> io::Result<Vec<u8>> {
    let signer = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing signer"))?;
    if joined_at(db, index)?.is_some() {
        return Err(invalid("two historical voters required"));
    }
    signer_record(r, db, index, &signer)
}

pub(super) fn archive_piece(db: &Connection, index: u64) -> io::Result<Vec<u8>> {
    let (source, events, receipts): (Vec<u8>, i64, i64) = db
        .query_row(
            "SELECT source,event_count,receipt_count FROM archive WHERE idx=?",
            [index.to_be_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(io::Error::other)?;
    let before: (i64, i64) = if let Some(prev) = index.checked_sub(1) {
        db.query_row(
            "SELECT event_count,receipt_count FROM archive WHERE idx=?",
            [prev.to_be_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(io::Error::other)?
    } else {
        (0, 0)
    };
    let mut out = message(&[(1, &source)]);
    for (tag, ledger, count, previous) in [
        (2, "event", events, before.0),
        (3, "receipt", receipts, before.1),
    ] {
        if previous == count {
            wire::field(&mut out, tag, &[]);
            continue;
        }
        if previous.checked_add(1) != Some(count) || count <= 0 {
            return Err(invalid("unsupported lobby archive delta"));
        }
        let sql = format!(
            "SELECT a.record,l.record,l.previous_tip,a.tip FROM {ledger} a JOIN semantic_link l USING(seq) WHERE l.ledger=? AND a.seq=?"
        );
        let record = db
            .query_row(&sql, params![ledger, count], |r| {
                let bytes = (0..4)
                    .map(|i| r.get::<_, Vec<u8>>(i))
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(message(&[
                    (1, &bytes[0]),
                    (2, &bytes[1]),
                    (3, &bytes[2]),
                    (4, &bytes[3]),
                ]))
            })
            .map_err(io::Error::other)?;
        wire::field(&mut out, tag, &record);
    }
    Ok(out)
}
pub(super) fn schema(db: &Connection) -> io::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS historic_seal(idx BLOB PRIMARY KEY CHECK(length(idx)=8), certificate BLOB NOT NULL) STRICT").map_err(io::Error::other)
}
pub(super) fn cursor(db: &Connection) -> io::Result<u64> {
    let last: Option<[u8; 8]> = db
        .query_row(
            "SELECT idx FROM historic_seal ORDER BY idx DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(io::Error::other)?;
    let next = last.map_or(Ok(0), |k| {
        u64::from_be_bytes(k)
            .checked_add(1)
            .ok_or(invalid("cursor exhausted"))
    })?;
    if store::meta::<u64>(db, "sealed_count")?.unwrap_or(0) != next {
        return Err(invalid("sealed coverage differs from its durable cursor"));
    }
    Ok(next)
}
pub(super) fn get(db: &Connection, index: u64) -> io::Result<Option<Vec<u8>>> {
    db.query_row(
        "SELECT certificate FROM historic_seal WHERE idx=?",
        [index.to_be_bytes()],
        |r| r.get(0),
    )
    .optional()
    .map_err(io::Error::other)
}
pub(super) fn save(db: &Connection, index: u64, cert: &[u8]) -> io::Result<()> {
    if cursor(db)? != index {
        return Err(invalid("cannot advance over a certificate gap"));
    }
    db.execute(
        "INSERT INTO historic_seal VALUES(?,?)",
        params![index.to_be_bytes(), cert],
    )
    .map_err(io::Error::other)?;
    store::put(
        db,
        "sealed_count",
        &index.checked_add(1).ok_or(invalid("cursor exhausted"))?,
    )
}
pub(super) fn transfer_piece(
    r: &Replica,
    db: &Connection,
    index: u64,
    key: &SigningKey,
) -> io::Result<Vec<u8>> {
    schema(db)?;
    if get(db, index)?.is_none() {
        r.verify_replay(db)?;
    }
    let cert = seal(r, db, index, key)?;
    Ok(message(&[(1, &cert), (2, &archive_piece(db, index)?)]))
}
pub(super) fn seal(
    r: &Replica,
    db: &Connection,
    index: u64,
    key: &SigningKey,
) -> io::Result<Vec<u8>> {
    let original = transcript(r, db, index)?;
    let cert = if let Some(cert) = get(db, index)? {
        if authenticate(&cert, key.verifying_key().as_bytes())? != original {
            return Err(invalid("stored historical signature mismatch"));
        }
        cert
    } else {
        let cert = signed(&original, key);
        save(db, index, &cert)?;
        cert
    };
    Ok(cert)
}
pub(super) fn stage(
    learner: &Learner,
    db: &Connection,
    index: u64,
    packet: &[u8],
) -> io::Result<()> {
    let f = fields(packet, &[1, 2])?;
    let r = &learner.node.replica;
    if store::meta::<LogId>(db, "applied")?.is_none_or(|k| k.index < index) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "waiting for local Raft apply",
        ));
    }
    verify_seal(r, db, &learner.creator.key, index, f[&1])?;
    if joined_at(db, index)?.is_some_and(|m| m.log_id.index == index) {
        let raw: Vec<u8> = db
            .query_row(
                "SELECT entry FROM raft_log WHERE idx=?",
                [index.to_be_bytes()],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        let entry = store::decode::<Entry>(&raw)?;
        r.verify_join_coverage(
            db,
            entry
                .payload
                .join_command()?
                .ok_or(invalid("missing original Join"))?,
        )?;
    }
    if f[&2] != archive_piece(db, index)? {
        return Err(invalid(
            "archive or historical evidence differs from applied replica",
        ));
    }
    if let Some(existing) = get(db, index)? {
        if existing != f[&1] {
            return Err(invalid("conflicting staged certificate"));
        }
    } else {
        save(db, index, f[&1])?;
    }
    Ok(())
}
pub(super) fn verify_all(learner: &Learner, db: &Connection, high: LogId) -> io::Result<()> {
    let r = &learner.node.replica;
    r.require_lobby_genesis(db)?;
    r.verify_replay(db)?;
    verify_prefix(r, db, &learner.creator.key, high)
}
pub(super) fn verify_prefix(
    r: &Replica,
    db: &Connection,
    key: &[u8; 32],
    high: LogId,
) -> io::Result<()> {
    for i in 0..=high.index {
        let cert = get(db, i)?.ok_or(invalid("historical certificate gap"))?;
        verify_seal(r, db, key, i, &cert)?;
    }
    Ok(())
}
pub(super) fn verify_seal(
    r: &Replica,
    db: &Connection,
    key: &[u8; 32],
    i: u64,
    cert: &[u8],
) -> io::Result<()> {
    if joined_at(db, i)?.is_some() {
        quorum::verify_certificate(r, db, i, cert)
    } else if authenticate(cert, key)? == transcript(r, db, i)? {
        Ok(())
    } else {
        Err(invalid("invalid retained historical evidence"))
    }
}
