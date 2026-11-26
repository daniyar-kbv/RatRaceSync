use super::*;
use openraft::{
    Config,
    network::{NetSnapshot, RaftNetworkFactory},
};

pub(super) struct Reservation {
    id: ReplicaId,
    session: Vec<u8>,
    invitation: Vec<u8>,
    actor: Vec<u8>,
    key: [u8; 32],
    prepared: bool,
    verified: Option<LogId>,
}
fn read(db: &Connection) -> io::Result<Reservation> {
    let (id, session, invitation, actor, key, prepared, verified) = db
        .query_row(
            "SELECT node,session,invitation,actor,key,prepared,verified FROM learner WHERE slot=1",
            [],
            |r| {
                Ok((
                    ReplicaId(r.get(0)?),
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get::<_, Option<Vec<u8>>>(6)?,
                ))
            },
        )
        .map_err(io::Error::other)?;
    Ok(Reservation {
        id,
        session,
        invitation,
        actor,
        key,
        prepared,
        verified: verified.map(|k| store::decode(&k)).transpose()?,
    })
}
pub(crate) fn create_learner_table(db: &Connection) -> io::Result<()> {
    db.execute_batch("CREATE TABLE learner(slot INTEGER PRIMARY KEY CHECK(slot=1),session BLOB NOT NULL, invitation BLOB NOT NULL,
                node BLOB UNIQUE NOT NULL CHECK(length(node)=16),actor BLOB NOT NULL,key BLOB NOT NULL CHECK(length(key)=32),
                prepared INTEGER NOT NULL DEFAULT 0 CHECK(prepared IN(0,1)), verified BLOB) STRICT").map_err(io::Error::other)
}

pub(crate) fn cancellation_generation(
    db: &Connection,
) -> io::Result<Option<catalog::cancellation::CancellationGeneration>> {
    let s = read(db)?;
    let (creator, proof, format) = invitation(&s.session, &s.invitation)?;
    Ok((s.prepared && format.cancellable()).then_some(
        catalog::cancellation::CancellationGeneration {
            session: s.session,
            creator,
            node: s.id,
            pin: proof.fingerprint,
        },
    ))
}
pub(crate) fn check_cancellation_binding(
    catalog: &Connection,
    r: &Replica,
    game: &Connection,
    root: &[u8; 32],
) -> io::Result<()> {
    let s = read(catalog)?;
    let (creator, proof, format) = invitation(&s.session, &s.invitation)?;
    if !s.prepared
        || !format.cancellable()
        || s.session != r.session
        || Some(s.id) != r.local_node
        || proof.fingerprint != *root
    {
        return Err(invalid(
            "terminal decision differs from learner reservation",
        ));
    }
    let binding = store::meta::<Vec<u8>>(game, "local_learner_admission")?
        .ok_or(invalid("missing learner identity"))?;
    let f = admission_fields(r, &binding, &creator)?;
    if f[&4] != s.actor || f[&5] != s.key || f[&6] != s.id.0 {
        return Err(invalid("learner identity mismatch"));
    }
    Ok(())
}
pub(crate) fn check_inventory(db: &Connection) -> io::Result<()> {
    let state = read(db)?;
    let (creator, _, _) = invitation(&state.session, &state.invitation)?;
    let other: bool = db
        .query_row("SELECT EXISTS(SELECT 1 FROM participation)", [], |r| {
            r.get(0)
        })
        .map_err(io::Error::other)?;
    if other
        || state.id == creator.node
        || state.key == creator.key
        || state.actor == creator.actor
        || (!state.prepared && state.verified.is_some())
    {
        return Err(invalid("inconsistent learner reservation"));
    }
    Ok(())
}

impl InstallationCatalog {
    /// Original Join at the catalog's verified checkpoint, including after an offline restart.
    pub fn recovered_join(&self, learner: &Learner) -> io::Result<Option<JoinResult>> {
        if self.recovered_lobby(learner)?.is_none() {
            return Ok(None);
        }
        let high = self
            .reserved_learner(learner)?
            .verified
            .ok_or(invalid("missing recovery checkpoint"))?;
        let db = learner.node.replica.lock()?;
        let Some(member) = history::joined_at(&db, high.index)? else {
            return Ok(None);
        };
        let receipt = db
            .query_row(
                "SELECT r.record FROM receipt r JOIN archive a ON a.receipt_count=r.seq WHERE a.log_id=? AND r.actor=?",
                params![log_key(member.log_id),&member.actor],
                |r| r.get(0),
            )
            .map_err(io::Error::other)?;
        Ok(Some(JoinResult {
            log_id: member.log_id,
            member,
            receipt,
        }))
    }
    pub(crate) fn verified_learner_pin(&self) -> io::Result<Option<[u8; 32]>> {
        let state = read(&self.db)?;
        let (_, pin, _) = invitation(&state.session, &state.invitation)?;
        Ok(state.verified.map(|_| pin.fingerprint))
    }
    pub(super) fn reserved_learner(&self, learner: &Learner) -> io::Result<Reservation> {
        let state = read(&self.db)?;
        let (_, pin, _) = invitation(&state.session, &state.invitation)?;
        let path = self
            .directory
            .join(format!("learner-{}-g1.sqlite", state.id));
        if learner
            .node
            .replica
            .lock()?
            .path()
            .map(std::path::Path::new)
            != Some(path.as_path())
            || !state.prepared
            || state.actor != learner.actor
            || state.session != learner.node.replica.session
            || state.id != learner.id
            || state.key != learner.key
            || pin.fingerprint != learner.root
        {
            return Err(invalid("wrong recovery installation"));
        }
        Ok(state)
    }
    pub(super) fn verified_join_prefix(&self, learner: &Learner) -> io::Result<LogId> {
        let high = self
            .reserved_learner(learner)?
            .verified
            .ok_or(invalid("learner recovery is incomplete"))?;
        self.recovered_lobby(learner)?
            .ok_or(invalid("missing verified lobby"))?;
        Ok(high)
    }
    /// Resume the catalog-owned generation after restart, including when the
    /// donor is offline. A missing catalog cannot discover or adopt an orphan.
    pub async fn resume_learner<N>(
        &mut self,
        key: &SigningKey,
        config: Config,
        network: N,
    ) -> io::Result<Learner>
    where
        N: RaftNetworkFactory<Types>,
        N::Network: NetSnapshot<Types, SnapshotData = ()>,
    {
        let state = read(&self.db)?;
        self.open_learner(
            &state.session,
            &state.invitation,
            &state.actor,
            key,
            config,
            network,
        )
        .await
    }
    /// The original lobby at a previously verified checkpoint, available offline.
    pub fn recovered_lobby(&self, learner: &Learner) -> io::Result<Option<LobbyCreation>> {
        let Some(high) = self.reserved_learner(learner)?.verified else {
            return Ok(None);
        };
        let r = &learner.node.replica;
        let db = r.lock()?;
        r.require_lobby_genesis(&db)?;
        r.verify_replay(&db)?;
        let binding = store::meta::<Vec<u8>>(&db, "local_learner_admission")?
            .ok_or(invalid("missing learner binding"))?;
        validate_completion(r, &db, &learner.creator, &binding, high)?;
        persisted_lobby(&db).map(Some)
    }
    /// Drive the authenticated exchange from the durable cursor. Transport
    /// disconnects and storage errors return to the adapter for its reconnect
    /// policy. Calling again uses a new challenge at the same durable prefix.
    pub async fn recover_learner(
        &mut self,
        learner: &mut Learner,
        key: &SigningKey,
        mut exchange: impl AsyncFnMut(Vec<u8>) -> io::Result<Vec<u8>>,
    ) -> io::Result<LobbyCreation> {
        self.reserved_learner(learner)?;
        loop {
            let response = exchange(learner.request(key)?).await?;
            let route = third::local_route(&learner.node.replica, &*learner.node.replica.lock()?)?;
            let body = third::response_body(
                &*learner.node.replica.lock()?,
                &response,
                &learner.creator,
                route.as_ref(),
            )?;
            let f = fields(body, &[1, 2, 3, 4, 5])?;
            let pending = learner
                .pending
                .as_ref()
                .ok_or(invalid("missing transfer challenge"))?;
            if f[&1] != RESPONSE || f[&2] != Sha256::digest(pending).as_slice() {
                return Err(invalid("stale transfer"));
            }
            let high = fixed::<32>(f[&3])?;
            let index = u64::from_be_bytes(fixed(&high[24..])?);
            // Genesis must also be durable before any piece is accepted.
            let needed = match f[&4] {
                [0] => u64::from_be_bytes(fixed(fields(pending, &[1, 2, 3, 4])?[&4])?).min(index),
                [1] => index,
                _ => return Err(invalid("unknown recovery response")),
            };
            learner
                .node
                .raft
                .wait(Some(std::time::Duration::from_secs(10)))
                .applied_index_at_least(Some(needed), "learner replication")
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?;
            if f[&4] == [1]
                && store::meta::<LogId>(&*learner.node.replica.lock()?, "applied")?
                    .is_some_and(|k| k.index > index)
            {
                continue;
            }
            if let Some(lobby) = self.accept_chunk(learner, &response)? {
                return Ok(lobby);
            }
        }
    }
    /// Reserve a distinct nonvoting incarnation on first authenticated admission.
    /// The adapter must authorize the selected game and bind its peer to the
    /// invitation. A reserved generation can only reopen with the same identity.
    pub async fn open_learner<N>(
        &mut self,
        session: &[u8],
        invite: &[u8],
        actor: &[u8],
        key: &SigningKey,
        config: Config,
        network: N,
    ) -> io::Result<Learner>
    where
        N: RaftNetworkFactory<Types>,
        N::Network: NetSnapshot<Types, SnapshotData = ()>,
    {
        let (creator, proof, format) = invitation(session, invite)?;
        if actor.is_empty()
            || actor.len() > 64
            || actor == creator.actor
            || key.verifying_key().as_bytes() == &creator.key
        {
            return Err(invalid("distinct learner identity required"));
        }
        let tx = self.db.transaction().map_err(io::Error::other)?;
        let version = database_version(&tx)?;
        if version >= 4 {
            let query = if version == 5 {
                "SELECT EXISTS(SELECT 1 FROM closed_game WHERE session=?1
                 UNION ALL SELECT 1 FROM departed_game WHERE session=?1)"
            } else {
                "SELECT EXISTS(SELECT 1 FROM closed_game WHERE session=?)"
            };
            let closed: bool = tx
                .query_row(query, [session], |row| row.get(0))
                .map_err(io::Error::other)?;
            if closed {
                return Err(invalid("session is closed on this installation"));
            }
        }
        if version == 2 || (version >= 4 && !catalog::has_active_learner(&tx)?) {
            let occupied: bool = tx
                .query_row("SELECT EXISTS(SELECT 1 FROM participation)", [], |r| {
                    r.get(0)
                })
                .map_err(io::Error::other)?;
            if occupied {
                return Err(invalid("another game owns the participation slot"));
            }
            catalog::check_new_inventory(&tx, &self.directory)?;
            if version == 2 {
                create_learner_table(&tx)?;
                tx.pragma_update(None, "user_version", 3)
                    .map_err(io::Error::other)?;
            }
            tx.execute(
                "INSERT INTO learner(slot,session,invitation,node,actor,key) VALUES(1,?,?,?,?,?)",
                params![
                    session,
                    invite,
                    fresh::<16>()?,
                    actor,
                    key.verifying_key().as_bytes()
                ],
            )
            .map_err(io::Error::other)?;
        }
        let state = read(&tx)?;
        if state.session != session
            || state.invitation != invite
            || state.actor != actor
            || &state.key != key.verifying_key().as_bytes()
            || state.id == creator.node
        {
            return Err(invalid(
                "learner differs from pinned installation identity or root",
            ));
        }
        tx.commit().map_err(io::Error::other)?;
        #[cfg(test)]
        self.interrupt_learner(15);
        let path = self
            .directory
            .join(format!("learner-{}-g1.sqlite", state.id));
        if path.is_symlink() {
            return Err(invalid("invalid learner generation path"));
        }
        let replica = Replica::open_reserved_generation(
            &path,
            session,
            &creator,
            state.id,
            !state.prepared,
            Some(format),
        )
        .await?;
        {
            let mut db = replica.lock()?;
            let tx = db.transaction().map_err(io::Error::other)?;
            match store::meta::<SignedGenesis>(&tx, "signed_genesis")? {
                Some(saved) if store::encode(&saved)? == store::encode(&proof)? => (),
                None if !state.prepared => store::put(&tx, "signed_genesis", &proof)?,
                _ => return Err(invalid("learner genesis differs from catalog pin")),
            }
            let binding = signed_admission(session, &proof.fingerprint, actor, state.id, key);
            match store::meta::<Vec<u8>>(&tx, "local_learner_admission")? {
                Some(saved) if saved == binding => (),
                None if !state.prepared => store::put(&tx, "local_learner_admission", &binding)?,
                _ => {
                    return Err(invalid(
                        "learner signing identity differs from reserved generation",
                    ));
                }
            }
            if !state.prepared {
                history::schema(&tx)?;
            }
            let next = history::cursor(&tx)?;
            replica
                .bound_root
                .set(proof.fingerprint)
                .map_err(|_| invalid("duplicate root initialization"))?;
            if store::meta::<LogId>(&tx, "genesis_log")?.is_some() {
                replica.require_lobby_genesis(&tx)?;
            }
            let first_unverified = if let Some(high) = state.verified {
                if high.index >= next {
                    return Err(invalid("verified checkpoint exceeds durable cursor"));
                }
                validate_completion(&replica, &tx, &creator, &binding, high)?;
                high.index + 1
            } else {
                0
            };
            history::verify_seals(&replica, &tx, &creator.key, first_unverified..next)?;
            replica.check_join_catalog_coverage(&tx, state.id, state.verified)?;
            tx.commit().map_err(io::Error::other)?;
        }
        if !state.prepared {
            #[cfg(test)]
            self.interrupt_learner(16);
            self.db
                .execute("UPDATE learner SET prepared=1 WHERE slot=1", [])
                .map_err(io::Error::other)?;
        }
        #[cfg(test)]
        self.interrupt_learner(17);
        let node = GameNode::start(state.id, replica, config, network).await?;
        Ok(Learner {
            node,
            id: state.id,
            actor: actor.to_vec(),
            key: state.key,
            root: proof.fingerprint,
            creator,
            pending: None,
        })
    }

    /// Commit one response to this installation. Some returns the verified
    /// original lobby result at the authenticated quorum checkpoint.
    pub fn accept_chunk(
        &mut self,
        learner: &mut Learner,
        response: &[u8],
    ) -> io::Result<Option<LobbyCreation>> {
        let pending = learner
            .pending
            .as_ref()
            .ok_or(invalid("no outstanding challenge"))?;
        self.reserved_learner(learner)?;
        let r = &learner.node.replica;
        let mut db = r.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        let route = third::local_route(r, &tx)?;
        let body = third::response_body(&tx, response, &learner.creator, route.as_ref())?;
        let f = fields(body, &[1, 2, 3, 4, 5])?;
        if f[&1] != RESPONSE || f[&2] != Sha256::digest(pending).as_slice() {
            return Err(invalid("stale recovery response"));
        }
        let request = fields(pending, &[1, 2, 3, 4])?;
        let index = u64::from_be_bytes(fixed(request[&4])?);
        r.require_lobby_genesis(&tx)?;
        let result = match f[&4] {
            [0] => {
                if f[&3].len() != 32 || index > u64::from_be_bytes(fixed(&f[&3][24..])?) {
                    return Err(invalid("range beyond attested high water"));
                }
                history::stage(learner, &tx, index, f[&5])?;
                #[cfg(test)]
                self.interrupt_learner(11);
                None
            }
            [1] => {
                let high = history::boundary(&tx)?;
                if history::joined_at(&tx, high.index)?.is_some() != route.is_some() {
                    return Err(invalid("checkpoint signer configuration mismatch"));
                }
                if let Some(route) = &route {
                    route.verify_historical_join(r, &tx, route.join)?;
                }
                if f[&3] != log_key(high)
                    || high.index.checked_add(1) != Some(index)
                    || history::cursor(&tx)? != index
                    || history::checkpoint(r, &tx, high.index)? != f[&5]
                {
                    return Err(invalid("final checkpoint differs from current replication"));
                }
                history::verify_all(learner, &tx, high)?;
                if !history::membership(&tx)?
                    .membership()
                    .non_write_voter_ids()
                    .eq([learner.id])
                {
                    return Err(invalid("not an admitted learner"));
                }
                let lobby = persisted_lobby(&tx)?;
                // Save the exact fresh request and donor response before catalog activation.
                store::put(
                    &tx,
                    &format!("learner_completion_{}", high.index),
                    &(pending, response),
                )?;
                Some((high, lobby))
            }
            _ => return Err(invalid("unknown recovery response")),
        };
        tx.commit().map_err(io::Error::other)?;
        #[cfg(test)]
        self.interrupt_learner(if result.is_some() { 13 } else { 12 });
        if let Some((high, lobby)) = result {
            // Retain the game mutex across the catalog commit. Replication
            // cannot move the local applied boundary during activation.
            let updated = self
                .db
                .execute(
                    "UPDATE learner SET verified=? WHERE slot=1 AND node=?",
                    params![store::encode(&high)?, learner.id.0],
                )
                .map_err(io::Error::other)?;
            if updated != 1 {
                return Err(invalid("learner activation slot changed"));
            }
            #[cfg(test)]
            self.interrupt_learner(14);
            Ok(Some(lobby))
        } else {
            Ok(None)
        }
    }
    #[cfg(test)]
    fn interrupt_learner(&self, stage: u8) {
        if self.crash_stage == stage {
            std::process::exit(100 + i32::from(stage));
        }
    }
}

fn persisted_lobby(db: &Connection) -> io::Result<LobbyCreation> {
    let receipt = db
        .query_row("SELECT record FROM receipt WHERE seq=1", [], |row| {
            row.get(0)
        })
        .map_err(io::Error::other)?;
    LobbyCreation::from_receipt(receipt)
}
fn validate_completion(
    r: &Replica,
    db: &Connection,
    creator: &Creator,
    binding: &[u8],
    high: LogId,
) -> io::Result<()> {
    let (request, response) =
        store::meta::<(Vec<u8>, Vec<u8>)>(db, &format!("learner_completion_{}", high.index))?
            .ok_or(invalid("verified learner lost its completion evidence"))?;
    let route = third::local_route(r, db)?;
    if history::joined_at(db, high.index)?.is_some() != route.is_some() {
        return Err(invalid("wrong recovery authority for pinned checkpoint"));
    }
    if let Some(route) = &route {
        route.verify_historical_join(r, db, route.join)?;
    }
    let fresh = fields(
        third::response_body(db, &response, creator, route.as_ref())?,
        &[1, 2, 3, 4, 5],
    )?;
    let query = fields(&request, &[1, 2, 3, 4])?;
    if fresh[&1] != RESPONSE
        || fresh[&2] != Sha256::digest(&request).as_slice()
        || fresh[&3] != log_key(high)
        || fresh[&4] != [1]
        || fresh[&5] != history::checkpoint(r, db, high.index)?
        || query[&1] != REQUEST
        || query[&2]
            != store::meta::<Vec<u8>>(db, "local_recovery_route")?
                .as_deref()
                .unwrap_or(binding)
        || query[&3].len() != 32
        || Some(u64::from_be_bytes(fixed(query[&4])?)) != high.index.checked_add(1)
    {
        return Err(invalid(
            "activation evidence differs from catalog checkpoint",
        ));
    }
    history::verify_prefix(r, db, &creator.key, high)
}
