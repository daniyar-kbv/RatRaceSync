use super::*;

fn report(
    node: &GameNode,
    request: &[u8],
    key: &SigningKey,
    final_only: bool,
) -> io::Result<(Vec<u8>, bool, RecoveryRoute)> {
    if request.len() > 65536 {
        return Err(invalid("oversized recovery challenge"));
    }
    let r = &node.replica;
    let db = r.lock()?;
    let creator = creator(&db)?;
    let body = fields(request, &[1, 2])?[&1];
    let query = fields(body, &[1, 2, 3, 4])?;
    let route = RecoveryRoute::parse(r, &creator, query[&2])?;
    authenticate(request, &route.learner_key)?;
    if query[&1] != REQUEST || query[&3].len() != 32 {
        return Err(invalid("invalid recovery challenge"));
    }
    let signer = key.verifying_key().to_bytes();
    if ![
        (Some(creator.node), creator.key),
        (Some(route.joined), route.joined_key),
    ]
    .contains(&(r.local_node, signer))
    {
        return Err(invalid("not an eligible recovery donor"));
    }
    seating::departure::reject_departed(
        &db,
        r.local_node.ok_or(invalid("missing recovery donor"))?,
        Some(route.learner),
    )?;
    r.require_lobby_genesis(&db)?;
    route.check_member(&db)?;
    let m = history::membership(&db)?;
    if !registration(m.membership(), creator.node, route.joined)
        || !m.membership().non_write_voter_ids().eq([route.learner])
    {
        return Err(invalid("learner has no committed recovery admission"));
    }
    let high = history::boundary(&db)?;
    let next = u64::from_be_bytes(fixed(query[&4])?);
    let end = high.index.checked_add(1).ok_or(invalid("log exhausted"))?;
    let done = next == end;
    if next > end || (final_only && !done) {
        return Err(invalid("requested checkpoint differs from current history"));
    }
    let data = if done {
        r.verify_replay(&db)?;
        history::verify_prefix(r, &db, &creator.key, high)?;
        history::checkpoint(r, &db, high.index)?
    } else {
        let cert =
            history::get(&db, next)?.ok_or(invalid("missing original historical certificate"))?;
        history::verify_seal(r, &db, &creator.key, next, &cert)?;
        message(&[(1, &cert), (2, &history::archive_piece(&db, next)?)])
    };
    let reply = signed(
        &message(&[
            (1, RESPONSE),
            (2, &Sha256::digest(body)),
            (3, &log_key(high)),
            (4, &[u8::from(done)]),
            (5, &data),
        ]),
        key,
    );
    if reply.len() > LIMIT {
        return Err(invalid("recovery report too large"));
    }
    Ok((reply, done, route))
}
fn quorum_body<'a>(
    packet: &'a [u8],
    creator: &Creator,
    route: &RecoveryRoute,
) -> io::Result<&'a [u8]> {
    if packet.len() > LIMIT {
        return Err(invalid("oversized final report"));
    }
    let pair = fields(packet, &[1, 2])?;
    let body = authenticate(pair[&1], &creator.key)?;
    if authenticate(pair[&2], &route.joined_key)? != body
        || fields(body, &[1, 2, 3, 4, 5])?[&4] != [1]
    {
        return Err(invalid("voters disagree on recovery checkpoint"));
    }
    Ok(body)
}
pub(in crate::learner) fn response_body<'a>(
    packet: &'a [u8],
    creator: &Creator,
    route: Option<&RecoveryRoute>,
) -> io::Result<&'a [u8]> {
    let Some(route) = route else {
        return authenticate(packet, &creator.key);
    };
    // Each archive transfer needs a fresh donor signature. Completion needs
    // two independently generated signatures for the very same challenge.
    if let Ok(body) =
        authenticate(packet, &creator.key).or_else(|_| authenticate(packet, &route.joined_key))
    {
        if fields(body, &[1, 2, 3, 4, 5])?[&4] == [0] {
            return Ok(body);
        }
        return Err(invalid("one voter cannot confirm a two-voter checkpoint"));
    }
    quorum_body(packet, creator, route)
}
impl GameNode {
    /// Verify the signed learner request and report this voter's own current checkpoint.
    pub fn attest_recovery(&self, request: &[u8], key: &SigningKey) -> io::Result<Vec<u8>> {
        Ok(report(self, request, key, true)?.0)
    }
    /// Serve an original archive piece, or obtain both fresh reports at completion.
    /// The final exchange is driven by the established leader after a quorum read.
    pub async fn voter_recovery_chunk(
        &self,
        request: &[u8],
        key: &SigningKey,
        peer: impl AsyncFnOnce(Vec<u8>) -> io::Result<Vec<u8>>,
    ) -> io::Result<Vec<u8>> {
        let (local, done, _) = report(self, request, key, false)?;
        if !done {
            return Ok(local);
        }
        self.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        let remote = peer(request.to_vec()).await?;
        let (local, _, route) = report(self, request, key, true)?;
        let creator = creator(&*self.replica.lock()?)?;
        let (a, b) = if self.replica.local_node == Some(creator.node) {
            (local, remote)
        } else {
            (remote, local)
        };
        let result = message(&[(1, &a), (2, &b)]);
        quorum_body(&result, &creator, &route)?;
        Ok(result)
    }
}
