use super::*;

const DOMAIN: &[u8] = b"RatRaceSync/committed-lobby-departure/v1";
pub(crate) const LOCAL: &str = "local_leave_confirmation";

#[derive(Serialize, Deserialize)]
pub(crate) struct Evidence {
    pub command: Signed,
    pub confirmations: [Vec<u8>; 2],
}
fn confirmation(session: &[u8], pin: &[u8; 32], raw: &Signed, receipt: &[u8]) -> Vec<u8> {
    message(&[
        (1, DOMAIN),
        (2, session),
        (3, pin),
        (4, &Sha256::digest(&raw.0)),
        (5, receipt),
    ])
}
impl GameNode {
    /// Sign the original applied receipt after the successor quorum has retained its checkpoint.
    pub fn leave_confirmation(&self, raw: &Signed, key: &SigningKey) -> io::Result<Vec<u8>> {
        let r = &self.replica;
        let d = left_at(&*r.lock()?, u64::MAX)?.ok_or(invalid("departure has not applied"))?;
        if !self.voting_history_complete(d.log_id)? {
            return Err(invalid("departure history handoff pending"));
        }
        let db = r.lock()?;
        let c = command(r, &db, &raw.0)?;
        let receipt = c
            .committed_receipt(&db)?
            .ok_or(invalid("missing original departure receipt"))?;
        let f = fields(&receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
        if f[&5] != log_key(d.log_id)
            || c.guard.node != d.node
            || !archived_seat_command(&db, &receipt)?.is_some_and(|s| s.0 == raw.0)
        {
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
            &r.session,
            r.bound_root.get().ok_or(invalid("missing root"))?,
            raw,
            &receipt,
        );
        Ok(message(&[(1, &body), (2, &key.sign(&body).to_bytes())]))
    }
}
impl Evidence {
    pub(crate) fn verify(
        &self,
        db: &Connection,
        session: &[u8],
        pin: &[u8; 32],
        local: ReplicaId,
    ) -> io::Result<Vec<u8>> {
        if self.command.0.len() > 2048 || self.confirmations.iter().any(|p| p.len() > 8192) {
            return Err(invalid("oversized departure proof"));
        }
        let env = fields(&self.command.0, &[1, 2])?;
        let intent = fields(env[&1], &[1, 2, 3, 4, 5, 12])?;
        if intent[&1] != lobby::LobbyFormat::Departure.profile()
            || intent[&2] != session
            || !matches!(action(intent[&12])?, TableAction::Leave)
        {
            return Err(invalid("wrong departure intent"));
        }
        let request = intent[&4].try_into().map_err(io::Error::other)?;
        let guard = fields(intent[&5], &[1, 2, 3, 4, 5, 6])?;
        let index: [u8; 8] = db
            .query_row("SELECT idx FROM archive WHERE log_id=?", [guard[&3]], |r| {
                r.get(0)
            })
            .map_err(io::Error::other)?;
        let index = u64::from_be_bytes(index);
        let (id, key) = member(db, intent[&3], index)?;
        if local != id || guard[&1] != local.0 {
            return Err(invalid("wrong departing installation"));
        }
        VerifyingKey::from_bytes(&key)
            .map_err(io::Error::other)?
            .verify_strict(
                env[&1],
                &Signature::from_slice(env[&2]).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
        let first = fields(&self.confirmations[0], &[1, 2])?;
        let body = fields(first[&1], &[1, 2, 3, 4, 5])?;
        let receipt = body[&5];
        let record = fields(receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
        let outcome = fields(record[&7], &[12])?;
        let leave = fields(outcome[&12], &[209])?;
        let effect = fields(leave[&209], &[1, 2, 3, 4, 5])?;
        let membership = fields(effect[&2], &[1, 2, 3])?;
        if record[&1] != session
            || record[&2] != intent[&3]
            || record[&3] != request
            || effect[&1] != intent[&3]
            || membership[&1] != local.0
            || membership[&2] != [1]
            || membership[&3] != [2]
        {
            return Err(invalid("wrong confirmed departure outcome"));
        }
        let applied: Option<Vec<u8>> = db
            .query_row(
                "SELECT record FROM receipt WHERE actor=? AND request=?",
                params![intent[&3], request],
                |row| row.get(0),
            )
            .optional()
            .map_err(io::Error::other)?;
        let original = match applied {
            Some(bytes) if bytes == receipt => archived_seat_command(db, &bytes)?,
            Some(_) => return Err(invalid("confirmed departure differs from local receipt")),
            None => store::meta::<Signed>(db, &local_request_key(local, request))?,
        };
        if !original.is_some_and(|saved| saved.0 == self.command.0) {
            return Err(invalid("missing original local Leave command"));
        }
        if confirmation(session, pin, &self.command, receipt) != first[&1] {
            return Err(invalid("wrong confirmed game or command"));
        }
        for (proof, who) in self
            .confirmations
            .iter()
            .zip(successors(db, intent[&3], index)?)
        {
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
