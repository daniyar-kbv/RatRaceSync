use super::*;

pub(in crate::learner) fn roster(
    creator: ReplicaId,
    second: ReplicaId,
    third: ReplicaId,
) -> Members {
    Members::new_with_defaults(vec![[creator, second, third].into()], [])
}
impl Intent<'_> {
    fn support(&self) -> Vec<u8> {
        message(&[
            (1, b"RatRaceSync/direct-third-join/v1"),
            (2, &self.fingerprint),
            (3, self.prefix),
            (4, self.sealed),
        ])
    }
    pub(super) fn verify_approvals(
        &self,
        db: &Connection,
        creator: &Creator,
        ordinal: u32,
    ) -> io::Result<()> {
        match (ordinal, self.approvals) {
            (2, None) => Ok(()),
            (3, Some([a, b])) => {
                let second = store::meta::<JoinedMember>(db, "first_member")?
                    .ok_or(invalid("missing predecessor voter"))?;
                let expected = self.support();
                if authenticate(a, &creator.key)? != expected
                    || authenticate(b, &second.key)? != expected
                {
                    return Err(invalid("predecessor voter capability mismatch"));
                }
                Ok(())
            }
            _ => Err(invalid("unsupported Join capability set")),
        }
    }
}
impl GameNode {
    /// Confirm support for the proposed operation at this already sealed prefix.
    /// This signature confers no vote, commit, receipt or historical certificate.
    pub fn confirm_third_promotion(
        &self,
        draft: &[u8],
        route: &[u8],
        key: &SigningKey,
    ) -> io::Result<Vec<u8>> {
        let r = &self.replica;
        let intent = parse(r, draft)?;
        let high = {
            let db = r.lock()?;
            r.require_lobby_genesis(&db)?;
            r.verify_replay(&db)?;
            let creator =
                store::meta::<Creator>(&db, "creator")?.ok_or(invalid("missing creator"))?;
            let route = third::RecoveryRoute::parse(r, &creator, route)?;
            route.check_member(&db)?;
            if route.admission != intent.admission
                || intent.approvals.is_some()
                || ![
                    (Some(creator.node), creator.key),
                    (Some(route.joined), route.joined_key),
                ]
                .contains(&(r.local_node, key.verifying_key().to_bytes()))
                || intent.validate(&db, &creator)?.ordinal != 3
            {
                return Err(invalid("unexpected third promotion request"));
            }
            let high = history::boundary(&db)?;
            if intent.prefix != log_key(high) {
                return Err(invalid("refresh verified learner prefix"));
            }
            r.verify_join_coverage(&db, draft)?;
            high
        };
        if !self.voting_history_complete(high)? {
            return Err(invalid("predecessor handoff pending"));
        }
        let db = r.lock()?;
        seating::departure::reject_departed(
            &db,
            r.local_node.ok_or(invalid("missing promotion signer"))?,
            None,
        )?;
        if history::boundary(&db)? != high {
            return Err(invalid("promotion checkpoint changed before signing"));
        }
        Ok(signed(&intent.support(), key))
    }
}
impl Replica {
    // OpenRaft restores its effective membership from the retained log before
    // application resumes. Validate any pending change beyond the first Join
    // before the restored process can participate in an election.
    pub(crate) fn verify_pending_lobby_membership(&self, db: &Connection) -> io::Result<()> {
        let Some(second) = store::meta::<JoinedMember>(db, "first_member")? else {
            return Ok(());
        };
        let creator = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
        let applied =
            store::meta::<LogId>(db, "applied")?.ok_or(invalid("missing applied boundary"))?;
        let mut promoted = store::meta::<JoinedMember>(db, "third_member")?.is_some();
        let mut query = db
            .prepare("SELECT idx,entry FROM raft_log WHERE idx>? ORDER BY idx")
            .map_err(io::Error::other)?;
        let mut rows = query
            .query([applied.index.to_be_bytes()])
            .map_err(io::Error::other)?;
        let mut leaving = false;
        while let Some(row) = rows.next().map_err(io::Error::other)? {
            let entry =
                store::decode::<Entry>(&row.get::<_, Vec<u8>>(1).map_err(io::Error::other)?)?;
            let Some(m) = entry.payload.check_members()? else {
                continue;
            };
            if let Some(raw) = entry.payload.leave_source()? {
                if leaving
                    || row.get::<_, [u8; 8]>(0).map_err(io::Error::other)?
                        != entry.log_id.index.to_be_bytes()
                {
                    return Err(invalid("invalid pending Leave"));
                }
                seating::departure::check_retained(self, db, &entry, raw)?;
                leaving = true;
                continue;
            }
            if leaving
                || seating::departure::left_at(db, applied.index)?.is_some()
                || promoted
                || row.get::<_, [u8; 8]>(0).map_err(io::Error::other)?
                    != entry.log_id.index.to_be_bytes()
            {
                return Err(invalid("unexpected retained membership"));
            }
            if entry.payload.join_command()?.is_some() {
                self.check_third_entry(db, &entry)?;
                promoted = true;
            } else if !third::registration(&m, creator.node, second.node) {
                return Err(invalid("unsupported retained membership"));
            }
        }
        Ok(())
    }
    pub(in crate::learner) fn verify_third_entry(&self, e: &Entry) -> io::Result<()> {
        self.check_third_entry(&*self.lock()?, e)
    }
    fn check_third_entry(&self, db: &Connection, e: &Entry) -> io::Result<()> {
        let raw = e
            .payload
            .join_command()?
            .ok_or(invalid("missing third Join source"))?;
        let intent = parse(self, raw)?;
        self.require_lobby_genesis(db)?;
        self.verify_replay(db)?;
        let creator = store::meta::<Creator>(db, "creator")?.ok_or(invalid("missing creator"))?;
        intent.verify_approvals(db, &creator, 3)?;
        self.verify_join_coverage(db, raw)?;
        if let Some(m) = store::meta::<JoinedMember>(db, "third_member")? {
            let original: Vec<u8> = db
                .query_row(
                    "SELECT source FROM archive WHERE idx=?",
                    [m.log_id.index.to_be_bytes()],
                    |row| row.get(0),
                )
                .map_err(io::Error::other)?;
            if e.log_id != m.log_id || original != e.payload.bytes {
                return Err(invalid("conflicting third Join entry"));
            }
            return Ok(());
        }
        let change = intent.validate(db, &creator)?;
        let prev = store::meta::<LogId>(db, "applied")?.ok_or(invalid("missing predecessor"))?;
        let second = store::meta::<JoinedMember>(db, "first_member")?
            .ok_or(invalid("missing predecessor voter"))?;
        if ![creator.node, second.node].contains(&e.log_id.leader_id.node_id)
            || e.log_id.leader_id != prev.leader_id
            || change.ordinal != 3
            || e.payload.check_members()? != Some(change.target)
            || log_key(prev) != intent.prefix
            || prev.index.checked_add(1) != Some(e.log_id.index)
        {
            return Err(invalid("unexpected third voter configuration"));
        }
        if self.local_node == Some(intent.node) {
            let saved = store::meta::<Vec<u8>>(db, "third_proposal")?
                .ok_or(invalid("missing local promotion consent"))?;
            let approved = parse(self, &saved)?;
            if intent.fingerprint != approved.fingerprint
                || intent.prefix != approved.prefix
                || intent.sealed != approved.sealed
            {
                return Err(invalid("wrong local Join intent"));
            }
        }
        Ok(())
    }
}
impl InstallationCatalog {
    /// Prepare and durably retain the complete request before its first submission.
    /// The exchange returns the original creator's and second voter's capability
    /// signatures in that order. A saved proposal survives a lost response.
    pub async fn prepare_third_join(
        &self,
        learner: &Learner,
        key: &SigningKey,
        request: [u8; 16],
        profile_complete: bool,
        confirm: impl AsyncFnOnce(Vec<u8>, Vec<u8>) -> io::Result<[Vec<u8>; 2]>,
    ) -> io::Result<Vec<u8>> {
        let draft = self.prepare_intent(learner, key, request, profile_complete, true)?;
        let r = &learner.node.replica;
        let route = {
            let db = r.lock()?;
            if let Some(raw) = store::meta::<Vec<u8>>(&db, "third_proposal")? {
                let saved = parse(r, &raw)?;
                let new = parse(r, &draft)?;
                if saved.fingerprint == new.fingerprint
                    && saved.prefix == new.prefix
                    && saved.sealed == new.sealed
                {
                    saved.verify_approvals(&db, &learner.creator, 3)?;
                    return Ok(raw);
                }
            }
            store::meta::<Vec<u8>>(&db, "local_recovery_route")?
                .ok_or(invalid("missing third recovery route"))?
        };
        let [a, b] = confirm(draft.clone(), route).await?;
        let f = fields(&draft, &[1, 2])?;
        let raw = message(&[(1, f[&1]), (2, f[&2]), (3, &a), (4, &b)]);
        let mut db = r.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        let intent = parse(r, &raw)?;
        intent.verify_approvals(&tx, &learner.creator, 3)?;
        if store::meta::<Vec<u8>>(&tx, "local_join")?.as_deref() != Some(&draft)
            || log_key(history::boundary(&tx)?) != intent.prefix
        {
            return Err(invalid(
                "recovery checkpoint changed during promotion preparation",
            ));
        }
        store::put(&tx, "third_proposal", &raw)?;
        tx.commit().map_err(io::Error::other)?;
        Ok(raw)
    }
}
