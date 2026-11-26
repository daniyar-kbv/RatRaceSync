use super::*;
use openraft::{async_runtime::watch::WatchReceiver, raft::VoteRequest};

const DOMAIN: &[u8] = b"RatRaceSync/first-join-election-source/v1";
fn context(
    r: &Replica,
    request: &VoteRequest<Types>,
    pre_vote: bool,
    entry: &[u8],
) -> io::Result<Vec<u8>> {
    Ok(message(&[
        (1, DOMAIN),
        (2, &r.session),
        (
            3,
            r.bound_root
                .get()
                .ok_or(invalid("unverified election root"))?,
        ),
        (4, &[u8::from(pre_vote)]),
        (5, &store::encode(request)?),
        (6, entry),
    ]))
}
impl GameNode {
    /// Attach to the genuine outbound Raft election RPC only when the
    /// proposed first Join is this candidate's retained effective membership.
    /// Another interrupted election may already have appended a later blank.
    pub fn pending_join_election_source(
        &self,
        request: &VoteRequest<Types>,
        pre_vote: bool,
        key: &SigningKey,
    ) -> io::Result<Option<Vec<u8>>> {
        let Some(last) = request.last_log_id else {
            return Ok(None);
        };
        let effective = self
            .raft
            .metrics()
            .borrow_watched()
            .membership_config
            .clone();
        let Some(membership_id) = *effective.log_id() else {
            return Ok(None);
        };
        if store::meta::<JoinedMember>(&*self.replica.lock()?, "third_member")?.is_some() {
            return Ok(None);
        }
        if effective.membership().voter_ids().count() != 2
            || effective
                .membership()
                .non_write_voter_ids()
                .next()
                .is_some()
            || membership_id.index > last.index
        {
            return Ok(None);
        }
        let r = &self.replica;
        let db = r.lock()?;
        let creator =
            store::meta::<Creator>(&db, "creator")?.ok_or(invalid("no creator binding"))?;
        if r.local_node != Some(creator.node)
            || request.vote.leader_id.node_id != creator.node
            || membership_id.leader_id.node_id != creator.node
            || &creator.key != key.verifying_key().as_bytes()
        {
            return Err(invalid("invalid election source signer"));
        }
        r.require_lobby_genesis(&db)?;
        let (bytes, tip): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT entry,(SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1) FROM raft_log WHERE idx=?",
                [membership_id.index.to_be_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(io::Error::other)?;
        let entry = store::decode::<Entry>(&bytes)?;
        let Some(raw) = entry.payload.join_command()? else {
            return Ok(None);
        };
        if store::decode::<Entry>(&tip)?.log_id != last
            || entry.log_id != membership_id
            || entry.payload.check_members()?.as_ref() != Some(effective.membership())
        {
            return Err(invalid(
                "election no longer references original effective Join",
            ));
        }
        r.verify_join_coverage(&db, raw)?;
        Ok(Some(signed(&context(r, request, pre_vote, &bytes)?, key)))
    }
}
impl Replica {
    pub(crate) fn verify_candidate_join(
        &self,
        request: &VoteRequest<Types>,
        pre_vote: bool,
        source: &[u8],
    ) -> io::Result<()> {
        let creator = store::meta::<Creator>(&*self.lock()?, "creator")?
            .ok_or(invalid("no creator binding"))?;
        if source.len() > 32768 {
            return Err(invalid("oversized candidate Join evidence"));
        }
        let body = authenticate(source, &creator.key)?;
        let f = fields(body, &[1, 2, 3, 4, 5, 6])?;
        if body != context(self, request, pre_vote, f[&6])? {
            return Err(invalid("election source context mismatch"));
        }
        let entry = store::decode::<Entry>(f[&6])?;
        let raw = entry
            .payload
            .join_command()?
            .ok_or(invalid("candidate lacks source-bearing Join"))?;
        let tip = request
            .last_log_id
            .ok_or(invalid("missing candidate tip"))?;
        if tip.index < entry.log_id.index
            || (tip.index == entry.log_id.index && tip != entry.log_id)
            || tip.leader_id.term < entry.log_id.leader_id.term
            || entry.log_id.leader_id.node_id != creator.node
            || request.vote.leader_id.node_id != creator.node
            || request.vote.leader_id.term <= tip.leader_id.term
        {
            return Err(invalid("invalid candidate Join log identity"));
        }
        self.verify_local_promotion(raw, &entry.payload)?;
        let db = self.lock()?;
        let intent = parse(self, raw)?;
        intent.validate(&db, &creator)?;
        let prev = history::boundary(&db)?;
        if log_key(prev) != intent.prefix || prev.index.checked_add(1) != Some(entry.log_id.index) {
            return Err(invalid("candidate Join does not extend verified prefix"));
        }
        Ok(())
    }
}
