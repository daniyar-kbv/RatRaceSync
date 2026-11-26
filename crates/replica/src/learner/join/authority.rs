use super::*;
use openraft::{
    async_runtime::watch::WatchReceiver,
    raft::{AppendEntriesRequest, VoteRequest},
};

/// Outbound evidence for an authenticated peer which missed the direct promotion.
/// The retained entry establishes eligibility only. OpenRaft decides the RPC.
#[derive(Clone)]
pub struct PromotionAuthority {
    raft: Raft,
    replica: Replica,
    verified: Arc<Mutex<Option<VerifiedSource>>>,
}
struct VerifiedSource {
    entry: Vec<u8>,
    signer: [u8; 32],
}
impl GameNode {
    pub fn promotion_authority(&self) -> PromotionAuthority {
        PromotionAuthority {
            raft: self.raft.clone(),
            replica: self.replica.clone(),
            verified: Default::default(),
        }
    }
}
impl Learner {
    pub fn promotion_authority(&self) -> PromotionAuthority {
        self.node.promotion_authority()
    }
}
fn transcript(r: &Replica, kind: u8, request: &[u8], entry: &[u8]) -> io::Result<Vec<u8>> {
    Ok(message(&[
        (1, b"RatRaceSync/promotion-rpc/v1"),
        (2, &r.session),
        (
            3,
            r.bound_root
                .get()
                .ok_or(invalid("missing promotion root"))?,
        ),
        (4, &[kind]),
        (5, &Sha256::digest(request)),
        (6, entry),
    ]))
}
fn sender_key(r: &Replica, e: &Entry, sender: ReplicaId) -> io::Result<[u8; 32]> {
    let db = r.lock()?;
    let creator = store::meta::<Creator>(&db, "creator")?.ok_or(invalid("missing creator"))?;
    let second =
        store::meta::<JoinedMember>(&db, "first_member")?.ok_or(invalid("missing joined voter"))?;
    let third = parse(
        r,
        e.payload
            .join_command()?
            .ok_or(invalid("missing promotion source"))?,
    )?;
    [
        (creator.node, creator.key),
        (second.node, second.key),
        (third.node, third.key),
    ]
    .into_iter()
    .find(|(id, _)| *id == sender)
    .map(|(_, k)| k)
    .ok_or(invalid("unrecognized promotion sender"))
}
impl PromotionAuthority {
    pub fn election(
        &self,
        request: &VoteRequest<Types>,
        pre_vote: bool,
        key: &SigningKey,
    ) -> io::Result<Option<Vec<u8>>> {
        let Some(tip) = request.last_log_id else {
            return Ok(None);
        };
        self.proof(
            request.vote.leader_id.node_id,
            Some(tip),
            u8::from(pre_vote),
            &store::encode(request)?,
            key,
        )
    }
    pub fn replication(
        &self,
        request: &AppendEntriesRequest<Types>,
        key: &SigningKey,
    ) -> io::Result<Option<Vec<u8>>> {
        self.proof(
            request.vote.leader_id.node_id,
            None,
            2,
            &store::encode(request)?,
            key,
        )
    }
    fn proof(
        &self,
        sender: ReplicaId,
        tip: Option<LogId>,
        kind: u8,
        request: &[u8],
        key: &SigningKey,
    ) -> io::Result<Option<Vec<u8>>> {
        let config = self
            .raft
            .metrics()
            .borrow_watched()
            .membership_config
            .clone();
        let voters = config.membership().voter_ids().count();
        if voters != 3
            && !(voters == 2
                && seating::departure::last_guest_at(&*self.replica.lock()?, u64::MAX)?.is_some())
        {
            return Ok(None);
        }
        let k = config
            .log_id()
            .ok_or(invalid("missing effective promotion"))?;
        let r = &self.replica;
        let (bytes, last): (Vec<u8>, Vec<u8>) = r.lock()?
            .query_row(
                "SELECT entry,(SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1) FROM raft_log WHERE idx=?",
                [k.index.to_be_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(io::Error::other)?;
        let entry = store::decode::<Entry>(&bytes)?;
        if voters == 2
            && !entry
                .payload
                .join_command()?
                .map(|raw| parse(r, raw))
                .transpose()?
                .is_some_and(|intent| intent.recovery_route.is_some())
        {
            return Ok(None);
        }
        if r.local_node != Some(sender)
            || entry.log_id != k
            || entry.payload.check_members()?.as_ref() != Some(config.membership())
            || tip.is_some_and(|id| id.index < k.index)
            || (tip.is_some() && tip != Some(store::decode::<Entry>(&last)?.log_id))
        {
            return Err(invalid("RPC differs from effective promotion"));
        }
        // Replication heartbeats refer to the same immutable entry. Recheck the
        // effective membership and retained bytes above for every outbound RPC.
        let signer = key.verifying_key().to_bytes();
        let mut verified = self
            .verified
            .lock()
            .map_err(|_| invalid("promotion verifier unavailable"))?;
        if !verified
            .as_ref()
            .is_some_and(|v| v.entry == bytes && v.signer == signer)
        {
            if sender_key(r, &entry, sender)? != signer {
                return Err(invalid("wrong promotion signer"));
            }
            r.verify_third_entry(&entry)?;
            *verified = Some(VerifiedSource {
                entry: bytes.clone(),
                signer,
            });
        }
        // A partitioned installation may retain the old effective configuration after
        // receiving its local Leave confirmation. Fence cached proofs at signing time.
        let db = r.lock()?;
        seating::departure::reject_departed(&db, sender, None)?;
        Ok(Some(signed(&transcript(r, kind, request, &bytes)?, key)))
    }
}
impl Replica {
    pub(in crate::learner) fn verify_promotion_rpc(
        &self,
        sender: ReplicaId,
        kind: u8,
        request: &[u8],
        proof: &[u8],
    ) -> io::Result<LogId> {
        if proof.len() > 32768 {
            return Err(invalid("oversized promotion evidence"));
        }
        let packet = fields(proof, &[1, 2])?;
        let body = fields(packet[&1], &[1, 2, 3, 4, 5, 6])?;
        let entry = store::decode::<Entry>(body[&6])?;
        if authenticate(proof, &sender_key(self, &entry, sender)?)?
            != transcript(self, kind, request, body[&6])?
        {
            return Err(invalid("promotion proof does not match RPC"));
        }
        self.verify_third_entry(&entry)?;
        Ok(entry.log_id)
    }
}
