use super::*;

impl RecoveryRoute {
    pub(crate) fn singleton_target(&self, creator: ReplicaId) -> Members {
        Members::new_with_defaults(vec![[creator].into()], [self.learner])
    }
    pub(in crate::learner) fn matches_registration(&self, raw: &[u8]) -> bool {
        self.departure.is_some() && self.route_hash == <[u8; 32]>::from(Sha256::digest(raw))
    }
    pub(super) fn check_departure(&self, db: &Connection) -> io::Result<()> {
        seating::layout_at(db, u64::MAX)?;
        let left = seating::departure::last_guest_at(db, u64::MAX)?
            .ok_or(invalid("missing guest departure"))?;
        if Some(left.log_id) != self.departure
            || left.node != self.joined
            || store::meta::<JoinedMember>(db, "third_member")?.is_some()
        {
            return Err(invalid("wrong predecessor for fresh registration"));
        }
        Ok(())
    }
    pub(super) fn is_registered(&self, db: &Connection, creator: &Creator) -> io::Result<bool> {
        let entry = history::membership_entry(db, u64::MAX, true)?
            .ok_or(invalid("missing membership source"))?;
        Ok(entry
            .payload
            .registration_source()?
            .is_some_and(|raw| self.matches_registration(raw))
            && entry.payload.check_members()? == Some(self.singleton_target(creator.node)))
    }
}

/// Check the original signed registration against the last applied membership.
/// This protocol entry adds one replication target and has no domain receipt.
pub(crate) fn verify_registration(
    r: &Replica,
    db: &Connection,
    e: &Entry,
    raw: &[u8],
) -> io::Result<Members> {
    let creator = creator(db)?;
    let route = RecoveryRoute::parse(r, &creator, raw)?;
    route.check_departure(db)?;
    route.verify_historical_join(r, db, route.join)?;
    let m = history::membership(db)?;
    let target = route.singleton_target(creator.node);
    let high =
        store::meta::<LogId>(db, "applied")?.ok_or(invalid("missing applied predecessor"))?;
    if *m.log_id() != route.departure
        || m.membership() != &Members::new_with_defaults(vec![[creator.node].into()], [])
        || e.log_id.leader_id.node_id != creator.node
        || e.log_id.leader_id != high.leader_id
        || high.index.checked_add(1) != Some(e.log_id.index)
        || e.payload.check_members()?.as_ref() != Some(&target)
    {
        return Err(invalid("invalid fresh learner configuration"));
    }
    Ok(target)
}

pub(crate) fn check_retained_registration(
    r: &Replica,
    db: &Connection,
    e: &Entry,
    raw: &[u8],
) -> io::Result<()> {
    r.require_lobby_genesis(db)?;
    r.verify_replay(db)?;
    let creator = creator(db)?;
    let route = RecoveryRoute::parse(r, &creator, raw)?;
    let slot = if r.local_node == Some(creator.node) {
        format!("issued_recovery_route_{}", route.learner)
    } else if r.local_node == Some(route.learner) {
        String::from("local_recovery_route")
    } else {
        return Err(invalid("wrong installation for fresh registration"));
    };
    if store::meta::<Vec<u8>>(db, &slot)?.as_deref() != Some(raw) {
        return Err(invalid("unreserved registration source"));
    }
    let high =
        store::meta::<LogId>(db, "applied")?.ok_or(invalid("missing applied predecessor"))?;
    if high.index >= e.log_id.index {
        let source: Vec<u8> = db
            .query_row(
                "SELECT source FROM archive WHERE log_id=?",
                [log_key(e.log_id)],
                |r| r.get(0),
            )
            .map_err(io::Error::other)?;
        if e.payload.bytes != source {
            return Err(invalid("conflicting registration source"));
        }
        return Ok(());
    }
    verify_registration(r, db, e, raw)?;
    if r.local_node == Some(creator.node) && !quorum::history_complete(r, db, high)? {
        return Err(invalid("registration predecessor handoff pending"));
    }
    Ok(())
}
