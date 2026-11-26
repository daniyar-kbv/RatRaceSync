//! Different lawful pairs may certify the same three-voter checkpoint. Keep
//! each original certificate and its exact predecessor chain for storage acks.
use super::*;
use rusqlite::Transaction;

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn link(previous: &[u8; 32], k: LogId, cert: &[u8]) -> [u8; 32] {
    wire::hash(
        b"three-voter-certificate-range/v1",
        &[previous, &log_key(k), cert],
    )
}
fn slot(digest: &[u8; 32]) -> String {
    format!("certificate_range_{}", hex(digest))
}
fn log_id(db: &Connection, i: u64) -> io::Result<LogId> {
    let raw: Vec<u8> = db
        .query_row(
            "SELECT entry FROM raft_log WHERE idx=?",
            [i.to_be_bytes()],
            |row| row.get(0),
        )
        .map_err(io::Error::other)?;
    let k = store::decode::<Entry>(&raw)?.log_id;
    if k.index != i {
        return Err(invalid("wrong certificate range index"));
    }
    Ok(k)
}
fn anchor(r: &Replica, db: &Connection, first: LogId) -> io::Result<[u8; 32]> {
    range_digest(
        r,
        db,
        log_id(
            db,
            first
                .index
                .checked_sub(1)
                .ok_or(invalid("missing old quorum prefix"))?,
        )?,
    )
}
pub(super) fn default_parent(
    r: &Replica,
    db: &Connection,
    first: LogId,
    k: LogId,
) -> io::Result<[u8; 32]> {
    if first == k {
        return anchor(r, db, first);
    }
    store::meta(db, &format!("primary_range_{}", k.index - 1))?
        .ok_or(invalid("previous certificate range missing"))
}
fn verify(
    r: &Replica,
    db: &Connection,
    first: LogId,
    end: u64,
    mut digest: [u8; 32],
) -> io::Result<()> {
    history::cursor(db)?;
    for i in (first.index..=end).rev() {
        let (previous, cert): ([u8; 32], Vec<u8>) = store::meta(db, &slot(&digest))?
            .ok_or(invalid("missing retained certificate range"))?;
        let k = log_id(db, i)?;
        if link(&previous, k, &cert) != digest {
            return Err(invalid("changed certificate range"));
        }
        let primary: [u8; 32] = store::meta(db, &format!("primary_range_{i}"))?
            .ok_or(invalid("missing original certificate range"))?;
        let original = history::get(db, i)?.ok_or(invalid("missing original certificate"))?;
        if digest == primary {
            if original != cert {
                return Err(invalid("changed original certificate"));
            }
        } else {
            let (parent, retained): ([u8; 32], Vec<u8>) = store::meta(db, &slot(&primary))?
                .ok_or(invalid("missing original certificate range"))?;
            if retained != original || link(&parent, k, &original) != primary {
                return Err(invalid("changed original certificate range"));
            }
            verify_certificate(r, db, i, &original)?;
        }
        verify_certificate(r, db, i, &cert)?;
        digest = previous;
    }
    if digest != anchor(r, db, first)? {
        return Err(invalid("range differs from original two-voter prefix"));
    }
    Ok(())
}
pub(super) fn ack_digest(
    r: &Replica,
    db: &Connection,
    k: LogId,
    packet: &[u8],
    voters: &[Creator],
) -> io::Result<[u8; 32]> {
    let Some(first) = history::third_at(db, k.index)? else {
        return range_digest(r, db, k);
    };
    let body = voters
        .iter()
        .find_map(|v| authenticate(packet, &v.key).ok())
        .ok_or(invalid("unknown range signer"))?;
    let digest = fixed(fields(body, &[1, 2, 3, 4, 5, 6, 7, 8])?[&4])?;
    verify(r, db, first.log_id, k.index, digest)?;
    Ok(digest)
}
pub(super) fn store(
    r: &Replica,
    tx: Transaction<'_>,
    k: LogId,
    parent: [u8; 32],
    cert: &[u8],
    local: &Creator,
    key: &SigningKey,
) -> io::Result<Vec<u8>> {
    let first = history::third_at(&tx, k.index)?.ok_or(invalid("not a three-voter checkpoint"))?;
    verify(r, &tx, first.log_id, k.index - 1, parent)?;
    verify_certificate(r, &tx, k.index, cert)?;
    if let Some(original) = history::get(&tx, k.index)? {
        verify_certificate(r, &tx, k.index, &original)?;
    } else {
        history::save(&tx, k.index, cert)?;
    }
    let digest = link(&parent, k, cert);
    let record = (parent, cert.to_vec());
    let name = slot(&digest);
    if let Some(existing) = store::meta(&tx, &name)? {
        if record != existing {
            return Err(invalid("conflicting retained range"));
        }
    } else {
        store::put(&tx, &name, &record)?;
    }
    let primary = format!("primary_range_{}", k.index);
    if store::meta::<[u8; 32]>(&tx, &primary)?.is_none() {
        store::put(&tx, &primary, &digest)?;
    }
    tx.commit().map_err(io::Error::other)?;
    Ok(signed(&storage_ack(r, k, &digest, local), key))
}
impl GameNode {
    pub(super) fn retained_certificate(&self, k: LogId) -> io::Result<Vec<u8>> {
        let r = &self.replica;
        let db = r.lock()?;
        committed(r, &db, k)?;
        if let Some(cert) = history::get(&db, k.index)? {
            verify_certificate(r, &db, k.index, &cert)?;
            Ok(cert)
        } else {
            Ok(Vec::new())
        }
    }
    pub(super) fn store_bundle(
        &self,
        k: LogId,
        parent: [u8; 32],
        cert: &[u8],
        key: &SigningKey,
    ) -> io::Result<Vec<u8>> {
        let r = &self.replica;
        let mut db = r.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        let voters = committed(r, &tx, k)?;
        let local = signer(r, &tx, &voters, key)?;
        store(r, tx, k, parent, cert, local, key)
    }
    pub(super) async fn reconcile_bundle(
        &self,
        first: LogId,
        end: LogId,
        key: &SigningKey,
        mut exchange: impl AsyncFnMut(VotingHistoryRequest) -> io::Result<Vec<u8>>,
    ) -> io::Result<()> {
        let r = &self.replica;
        let mut previous = anchor(r, &*r.lock()?, first)?;
        for i in first.index..=end.index {
            let k = log_id(&*r.lock()?, i)?;
            if i == end.index && k != end {
                return Err(invalid("wrong final checkpoint"));
            }
            let mut cert = self.retained_certificate(k)?;
            if cert.is_empty() {
                cert = exchange(VotingHistoryRequest::Retained(k)).await?;
            }
            if cert.is_empty() {
                let a = self.sign_voting_checkpoint(k, key)?;
                let b = exchange(VotingHistoryRequest::Attest(k)).await?;
                cert = certificate(r, &*r.lock()?, i, &a, &b)?;
            }
            let local_ack = self.store_bundle(k, previous, &cert, key)?;
            let digest = link(&previous, k, &cert);
            let remote_ack = exchange(VotingHistoryRequest::StoreRange {
                checkpoint: k,
                previous,
                certificate: cert,
            })
            .await?;
            self.confirm_voting_checkpoint(k, &local_ack, &remote_ack)?;
            if !exchange(VotingHistoryRequest::Confirm {
                checkpoint: k,
                acknowledgments: [local_ack, remote_ack],
            })
            .await?
            .is_empty()
            {
                return Err(invalid("unexpected range confirmation response"));
            }
            previous = digest;
        }
        Ok(())
    }
}
