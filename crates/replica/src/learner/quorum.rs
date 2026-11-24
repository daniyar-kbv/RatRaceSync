use super::*;
mod bundles;
const ACK: &[u8] = b"RatRaceSync/history/durable-range-ack/v1";

#[derive(Debug, Clone)]
pub enum VotingHistoryRequest {
    Attest(LogId),
    Retained(LogId),
    StoreRange {
        checkpoint: LogId,
        previous: [u8; 32],
        certificate: Vec<u8>,
    },
    Store {
        checkpoint: LogId,
        signatures: [Vec<u8>; 2],
    },
    Confirm {
        checkpoint: LogId,
        acknowledgments: [Vec<u8>; 2],
    },
}

impl GameNode {
    /// The transport supplies the independently authenticated sending incarnation.
    pub fn answer_history_request(
        &self,
        sender: ReplicaId,
        request: VotingHistoryRequest,
        key: &SigningKey,
    ) -> io::Result<Vec<u8>> {
        let index = match &request {
            VotingHistoryRequest::Attest(k)
            | VotingHistoryRequest::Retained(k)
            | VotingHistoryRequest::StoreRange { checkpoint: k, .. }
            | VotingHistoryRequest::Store { checkpoint: k, .. }
            | VotingHistoryRequest::Confirm { checkpoint: k, .. } => k.index,
        };
        let voters = voters(&*self.replica.lock()?, index)?;
        if self.replica.local_node == Some(sender) || !voters.iter().any(|v| v.node == sender) {
            return Err(invalid("unauthorized history peer"));
        }
        match request {
            VotingHistoryRequest::Retained(k) => self.retained_certificate(k),
            VotingHistoryRequest::StoreRange {
                checkpoint,
                previous,
                certificate,
            } => self.store_bundle(checkpoint, previous, &certificate, key),
            VotingHistoryRequest::Attest(k) => self.sign_voting_checkpoint(k, key),
            VotingHistoryRequest::Store {
                checkpoint,
                signatures: [a, b],
            } => self.store_voting_checkpoint(checkpoint, &a, &b, key),
            VotingHistoryRequest::Confirm {
                checkpoint,
                acknowledgments: [a, b],
            } => {
                self.confirm_voting_checkpoint(checkpoint, &a, &b)?;
                Ok(vec![])
            }
        }
    }
    /// Safe to restart after loss of any request or response. Either voter
    /// can drive the exchange, including after leadership changes.
    pub async fn reconcile_voting_history(
        &self,
        k: LogId,
        key: &SigningKey,
        mut exchange: impl AsyncFnMut(VotingHistoryRequest) -> io::Result<Vec<u8>>,
    ) -> io::Result<()> {
        let third = history::third_at(&*self.replica.lock()?, k.index)?;
        if let Some(m) = third {
            return self.reconcile_bundle(m.log_id, k, key, exchange).await;
        }
        let a = self.sign_voting_checkpoint(k, key)?;
        let b = exchange(VotingHistoryRequest::Attest(k)).await?;
        let local_ack = self.store_voting_checkpoint(k, &a, &b, key)?;
        let peer_ack = exchange(VotingHistoryRequest::Store {
            checkpoint: k,
            signatures: [a, b],
        })
        .await?;
        self.confirm_voting_checkpoint(k, &local_ack, &peer_ack)?;
        let response = exchange(VotingHistoryRequest::Confirm {
            checkpoint: k,
            acknowledgments: [local_ack, peer_ack],
        })
        .await?;
        if !response.is_empty() {
            return Err(invalid("unexpected confirmation response"));
        }
        Ok(())
    }
}

fn voters(db: &Connection, index: u64) -> io::Result<Vec<Creator>> {
    let creator = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
    let joined =
        history::joined_at(db, index)?.ok_or(invalid("Join has not applied at this checkpoint"))?;
    let mut voters = vec![
        creator,
        Creator {
            actor: joined.actor,
            key: joined.key,
            node: joined.node,
        },
    ];
    if let Some(m) = history::third_at(db, index)? {
        voters.push(Creator {
            actor: m.actor,
            key: m.key,
            node: m.node,
        });
    }
    voters.sort_by_key(|v| v.node);
    Ok(voters)
}
fn committed(r: &Replica, db: &Connection, k: LogId) -> io::Result<Vec<Creator>> {
    r.require_lobby_genesis(db)?;
    let last = store::meta::<LogId>(db, "applied")?.ok_or(invalid("no applied history"))?;
    let commit = store::meta::<Option<LogId>>(db, "committed")?
        .flatten()
        .ok_or(invalid("no committed history"))?;
    if last.index < k.index || commit.index < k.index {
        return Err(invalid("checkpoint not yet committed and applied"));
    }
    let id: Vec<u8> = db
        .query_row(
            "SELECT log_id FROM archive WHERE idx=?",
            [k.index.to_be_bytes()],
            |row| row.get(0),
        )
        .map_err(io::Error::other)?;
    if id != log_key(k) {
        return Err(invalid("wrong full checkpoint LogId"));
    }
    r.verify_replay(db)?;
    voters(db, k.index)
}
fn signer<'a>(r: &Replica, voters: &'a [Creator], key: &SigningKey) -> io::Result<&'a Creator> {
    voters
        .iter()
        .find(|v| r.local_node == Some(v.node) && &v.key == key.verifying_key().as_bytes())
        .ok_or(invalid("ineligible local voter signer"))
}
fn pair(
    left: &[u8],
    right: &[u8],
    voters: &[Creator],
    body: impl Fn(&Creator) -> io::Result<Vec<u8>>,
) -> io::Result<Vec<u8>> {
    let mut signed = Vec::with_capacity(2);
    for packet in [left, right] {
        let (v, actual) = voters
            .iter()
            .find_map(|v| authenticate(packet, &v.key).ok().map(|a| (v, a)))
            .ok_or(invalid("ineligible historical signer"))?;
        if actual != body(v)? {
            return Err(invalid("incorrect signed historical record"));
        }
        signed.push((v.node, packet));
    }
    signed.sort_by_key(|x| x.0);
    if signed[0].0 == signed[1].0 {
        return Err(invalid("duplicate quorum signer"));
    }
    Ok(message(&[(1, signed[0].1), (2, signed[1].1)]))
}
fn certificate(
    r: &Replica,
    db: &Connection,
    index: u64,
    a: &[u8],
    b: &[u8],
) -> io::Result<Vec<u8>> {
    pair(a, b, &voters(db, index)?, |v| {
        history::signer_record(r, db, index, v)
    })
}
pub(super) fn verify_certificate(
    r: &Replica,
    db: &Connection,
    index: u64,
    cert: &[u8],
) -> io::Result<()> {
    let f = fields(cert, &[1, 2])?;
    if certificate(r, db, index, f[&1], f[&2])? != cert {
        return Err(invalid("noncanonical certificate set"));
    }
    Ok(())
}
fn range_digest(r: &Replica, db: &Connection, k: LogId) -> io::Result<[u8; 32]> {
    let creator = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing history root"))?;
    join::sealed_range(r, db, &creator.key, k)
}
fn storage_ack(r: &Replica, k: LogId, digest: &[u8; 32], v: &Creator) -> Vec<u8> {
    message(&[
        (1, ACK),
        (2, &r.session),
        (3, &log_key(k)),
        (4, digest),
        (5, &v.actor),
        (6, &v.node.0),
        (7, &v.key),
        (8, &1u64.to_be_bytes()),
    ])
}
impl Learner {
    /// Trusted participant adapter, only after the local durable Join commits.
    pub fn joined_node(&self) -> io::Result<&GameNode> {
        let db = self.node.replica.lock()?;
        self.node.replica.require_lobby_genesis(&db)?;
        self.node.replica.verify_replay(&db)?;
        let member = join::member_for(&db, self.id)?.ok_or(invalid("learner has not joined"))?;
        if member.actor != self.actor || member.node != self.id || member.key != self.key {
            return Err(invalid("joined incarnation differs from installation"));
        }
        Ok(&self.node)
    }
}
impl GameNode {
    /// The Raft commit and application precede both historical signatures.
    pub fn sign_voting_checkpoint(&self, k: LogId, key: &SigningKey) -> io::Result<Vec<u8>> {
        let r = &self.replica;
        let db = r.lock()?;
        let voters = committed(r, &db, k)?;
        let local = signer(r, &voters, key)?;
        Ok(signed(
            &history::signer_record(r, &db, k.index, local)?,
            key,
        ))
    }
    /// Persist both historical signatures and verify the entire retained prefix
    /// before issuing the local incarnation's durable storage acknowledgment.
    pub fn store_voting_checkpoint(
        &self,
        k: LogId,
        a: &[u8],
        b: &[u8],
        key: &SigningKey,
    ) -> io::Result<Vec<u8>> {
        let r = &self.replica;
        let mut db = r.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        let voters = committed(r, &tx, k)?;
        let local = signer(r, &voters, key)?;
        let cert = certificate(r, &tx, k.index, a, b)?;
        if let Some(third) = history::third_at(&tx, k.index)? {
            let parent = bundles::default_parent(r, &tx, third.log_id, k)?;
            return bundles::store(r, tx, k, parent, &cert, local, key);
        }
        match history::get(&tx, k.index)? {
            Some(existing) if existing == cert => (),
            Some(_) => return Err(invalid("conflicting historical certificate")),
            None => history::save(&tx, k.index, &cert)?,
        }
        let digest = range_digest(r, &tx, k)?;
        tx.commit().map_err(io::Error::other)?;
        Ok(signed(&storage_ack(r, k, &digest, local), key))
    }
    pub fn confirm_voting_checkpoint(&self, k: LogId, a: &[u8], b: &[u8]) -> io::Result<()> {
        let r = &self.replica;
        let mut db = r.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        let voters = committed(r, &tx, k)?;
        let digest = bundles::ack_digest(r, &tx, k, a, &voters)?;
        let record = pair(a, b, &voters, |v| Ok(storage_ack(r, k, &digest, v)))?;
        let slot = format!("handoff_{}", k.index);
        if let Some(original) = store::meta::<Vec<u8>>(&tx, &slot)? {
            verify_handoff(r, &tx, k, &original, &voters)?;
            if original != record {
                store::put(
                    &tx,
                    &format!(
                        "handoff_extra_{}_{}",
                        k.index,
                        bundles::hex(&Sha256::digest(&record))
                    ),
                    &record,
                )?;
            }
        } else {
            store::put(&tx, &slot, &record)?;
        }
        tx.commit().map_err(io::Error::other)
    }
    pub fn voting_history_complete(&self, k: LogId) -> io::Result<bool> {
        let r = &self.replica;
        let db = r.lock()?;
        let voters = committed(r, &db, k)?;
        let Some(record) = store::meta::<Vec<u8>>(&db, &format!("handoff_{}", k.index))? else {
            return Ok(false);
        };
        verify_handoff(r, &db, k, &record, &voters)?;
        Ok(true)
    }
}
fn verify_handoff(
    r: &Replica,
    db: &Connection,
    k: LogId,
    record: &[u8],
    voters: &[Creator],
) -> io::Result<()> {
    let f = fields(record, &[1, 2])?;
    let digest = bundles::ack_digest(r, db, k, f[&1], voters)?;
    if pair(f[&1], f[&2], voters, |v| Ok(storage_ack(r, k, &digest, v)))? != record {
        return Err(invalid("invalid durable handoff"));
    }
    Ok(())
}
