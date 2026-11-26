use super::*;

const SOLE_SUCCESSOR: &[u8] = b"RatRaceSync/sole-successor-lobby-departure/v1";
const DOMAIN: &[u8] = b"RatRaceSync/committed-lobby-departure/v1";
pub(crate) const LOCAL: &str = "local_leave_confirmation";

#[derive(Serialize, Deserialize)]
pub(crate) struct Evidence {
    pub command: Signed,
    pub confirmations: [Vec<u8>; 2],
}
fn confirmation(
    domain: &[u8],
    session: &[u8],
    pin: &[u8; 32],
    raw: &Signed,
    receipt: &[u8],
) -> Vec<u8> {
    message(&[
        (1, domain),
        (2, session),
        (3, pin),
        (4, &Sha256::digest(&raw.0)),
        (5, receipt),
    ])
}
// Read the original command even during deterministic replay, when only the
// already-applied archive prefix exists in the verification database.
fn archived_leave(db: &Connection, d: &Departure) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let (bytes, receipt): (Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT a.source,r.record FROM archive a JOIN receipt r ON r.seq=a.receipt_count WHERE a.log_id=?",
        [log_key(d.log_id)], |row| Ok((row.get(0)?,row.get(1)?))
    ).map_err(io::Error::other)?;
    let voters = successors(db, &d.actor, d.log_id.index - 1)?;
    let members = Members::new_with_defaults(vec![voters.iter().map(|v| v.node).collect()], []);
    let source = Source::retained_membership(bytes, members);
    let record = fields(&receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    if record[&5] != log_key(d.log_id) || record[&2] != d.actor {
        return Err(invalid("archived receipt differs from Leave"));
    }
    Ok((
        source
            .leave_source()?
            .ok_or(invalid("missing archived Leave source"))?
            .to_vec(),
        receipt,
    ))
}

pub(super) fn prior_body(
    r: &Replica,
    db: &Connection,
    index: u64,
) -> io::Result<Option<(Signed, Vec<u8>)>> {
    let Some(first) =
        store::meta::<Departure>(db, "departed_member")?.filter(|d| d.log_id.index <= index)
    else {
        return Ok(None);
    };
    let (packet, receipt) = archived_leave(db, &first)?;
    let cmd = Signed(fields(&packet, &[1, 2, 3, 4])?[&2].to_vec());
    let body = confirmation(
        DOMAIN,
        &r.session,
        r.bound_root.get().ok_or(invalid("missing root"))?,
        &cmd,
        &receipt,
    );
    Ok(Some((cmd, body)))
}

impl GameNode {
    /// Recover both historical confirmations for a guest who missed the first
    /// Leave and returned after the last guest retired. Requires its signed intent.
    pub fn retained_leave_confirmations(&self, raw: &Signed) -> io::Result<(Signed, [Vec<u8>; 2])> {
        let r = &self.replica;
        let db = r.lock()?;
        r.require_lobby_genesis(&db)?;
        r.verify_replay(&db)?;
        let last = store::meta::<Departure>(&db, "last_guest_departure")?
            .ok_or(invalid("last guest has not left"))?;
        let (original, body) = prior_body(r, &db, last.log_id.index - 1)?
            .ok_or(invalid("no earlier guest departure"))?;
        let signed = command(r, &db, &raw.0)?;
        if signed.committed_receipt(&db)?.as_deref() != Some(fields(&body, &[1, 2, 3, 4, 5])?[&5]) {
            return Err(invalid("wrong earlier Leave request"));
        }
        let (source, _) = archived_leave(&db, &last)?;
        let packet = fields(&source, &[1, 2, 3, 4])?;
        let proof = |approval| -> io::Result<Vec<u8>> {
            Ok(message(&[
                (1, &body),
                (2, fields(approval, &[1, 2, 3])?[&3]),
            ]))
        };
        Ok((original, [proof(packet[&3])?, proof(packet[&4])?]))
    }
    /// Sign the original applied receipt after the successor quorum has retained its checkpoint.
    pub fn leave_confirmation(&self, raw: &Signed, key: &SigningKey) -> io::Result<Vec<u8>> {
        let r = &self.replica;
        let d = {
            let db = r.lock()?;
            let c = command(r, &db, &raw.0)?;
            departures_at(&db, u64::MAX)?
                .into_iter()
                .find(|d| d.node == c.guard.node)
                .ok_or(invalid("departure has not applied"))?
        };
        if !self.voting_history_complete(d.log_id)? {
            return Err(invalid("departure history handoff pending"));
        }
        let db = r.lock()?;
        reject_departed(
            &db,
            r.local_node.ok_or(invalid("missing local node"))?,
            None,
        )?;
        let c = command(r, &db, &raw.0)?;
        let receipt = c
            .committed_receipt(&db)?
            .ok_or(invalid("missing original departure receipt"))?;
        let f = fields(&receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
        if f[&5] != log_key(d.log_id) || c.guard.node != d.node {
            return Err(invalid("wrong departure receipt"));
        }
        let voters = successors(&db, &d.actor, d.log_id.index - 1)?;
        if !voters
            .iter()
            .any(|v| Some(v.node) == r.local_node && v.key == key.verifying_key().to_bytes())
        {
            return Err(invalid("successor signer required"));
        }
        let body = confirmation(
            if voters.len() == 1 {
                SOLE_SUCCESSOR
            } else {
                DOMAIN
            },
            &r.session,
            r.bound_root.get().ok_or(invalid("missing root"))?,
            raw,
            &receipt,
        );
        Ok(message(&[(1, &body), (2, &key.sign(&body).to_bytes())]))
    }
}
fn verify_predecessor(
    db: &Connection,
    guard: &SeatCommandGuard,
    survivors: &[Creator],
) -> io::Result<()> {
    let Dependencies::Membership { configuration, .. } = guard.material else {
        return Err(invalid("missing predecessor membership reference"));
    };
    let (retained, source, digest): (Vec<u8>,Vec<u8>,[u8;32]) = db.query_row(
        "SELECT l.entry,a.source,a.digest FROM raft_log l JOIN archive a USING(idx) WHERE a.log_id=?",
        [configuration], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))
    ).map_err(io::Error::other)?;
    let entry: Entry = store::decode(&retained)?;
    let voters = entry
        .payload
        .check_members()?
        .ok_or(invalid("missing predecessor configuration"))?;
    let expected = Members::new_with_defaults(
        vec![
            survivors
                .iter()
                .map(|v| v.node)
                .chain([guard.node])
                .collect(),
        ],
        voters.non_write_voter_ids(),
    );
    if voters != expected
        || log_key(entry.log_id) != configuration
        || entry.payload.bytes != source
        || Sha256::digest(&source)[..] != digest
    {
        return Err(invalid("retained predecessor differs from signed Leave"));
    }
    Ok(())
}

impl Evidence {
    pub(crate) fn verify(
        &self,
        format: lobby::LobbyFormat,
        db: &Connection,
        session: &[u8],
        pin: &[u8; 32],
        local: ReplicaId,
    ) -> io::Result<Vec<u8>> {
        if self.command.0.len() > 2048 || self.confirmations.iter().any(|p| p.len() > 8192) {
            return Err(invalid("oversized departure proof"));
        }
        let verify = |signed: &Signed| SeatCommand::verify_in_game(format, session, db, &signed.0);
        let intent = verify(&self.command)?;
        let guard = &intent.guard;
        if !matches!(guard.action, TableAction::Leave) || guard.node != local {
            return Err(invalid("wrong departing installation or operation"));
        }
        let request = intent.request;
        let fingerprint = guard.fingerprint(&request);
        let index: [u8; 8] = db
            .query_row(
                "SELECT idx FROM archive WHERE log_id=?",
                [guard.observed],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        let index = u64::from_be_bytes(index);
        let first = fields(&self.confirmations[0], &[1, 2])?;
        let body = fields(first[&1], &[1, 2, 3, 4, 5])?;
        let receipt = body[&5];
        let record = fields(receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
        let outcome = fields(record[&7], &[12])?;
        let leave = fields(outcome[&12], &[209])?;
        let effective: &[u8; 32] = record[&5].try_into().map_err(io::Error::other)?;
        let sequence = i64::from_be_bytes(record[&6].try_into().map_err(io::Error::other)?);
        if record[&1] != session
            || record[&2] != guard.actor
            || record[&3] != request
            || record[&4] != fingerprint
            || sequence <= 0
            || record[&8].len() != 32
            || record[&9].len() != 32
            || effective[24..] <= guard.observed[24..]
            || effective[..8] < guard.observed[..8]
            || outcome_at(db, index, guard, effective)?.effect.record != leave[&209]
        {
            return Err(invalid("wrong confirmed departure outcome"));
        }
        let applied: Option<Vec<u8>> = db
            .query_row(
                "SELECT record FROM receipt WHERE actor=? AND request=?",
                params![guard.actor.as_slice(), request],
                |row| row.get(0),
            )
            .optional()
            .map_err(io::Error::other)?;
        let original = match applied {
            Some(bytes) if bytes == receipt => archived_seat_command(db, &bytes)?,
            Some(_) => return Err(invalid("confirmed departure differs from local receipt")),
            None => store::meta::<Signed>(db, &local_request_key(local, request))?,
        };
        let reserved = verify(&original.ok_or(invalid("missing local Leave command"))?)?;
        if reserved.request != request || reserved.guard.fingerprint(&request) != fingerprint {
            return Err(invalid("missing original local Leave command"));
        }
        let survivors = successors(db, guard.actor.as_slice(), index)?;
        verify_predecessor(db, guard, &survivors)?;
        let domain = if survivors.len() == 1 {
            SOLE_SUCCESSOR
        } else {
            DOMAIN
        };
        if confirmation(domain, session, pin, &self.command, receipt) != first[&1] {
            return Err(invalid("wrong confirmed game or command"));
        }
        if survivors.len() == 1 && !self.confirmations[1].is_empty() {
            return Err(invalid("unexpected second confirmation for sole survivor"));
        }
        for (proof, who) in self.confirmations.iter().zip(survivors) {
            let f = fields(proof, &[1, 2])?;
            if f[&1] != first[&1] {
                return Err(invalid("successors disagree on original receipt"));
            }
            VerifyingKey::from_bytes(&who.key)
                .map_err(io::Error::other)?
                .verify_strict(
                    f[&1],
                    &Signature::from_slice(f[&2]).map_err(io::Error::other)?,
                )
                .map_err(io::Error::other)?;
        }
        Ok(receipt.to_vec())
    }
}
