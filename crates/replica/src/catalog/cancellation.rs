use super::*;
use crate::seating::cancellation::at;

pub(crate) fn has_learner(db: &Connection) -> io::Result<bool> {
    match database_version(db)? {
        3 => Ok(true),
        4 => db
            .query_row("SELECT EXISTS(SELECT 1 FROM learner)", [], |r| r.get(0))
            .map_err(io::Error::other),
        _ => Ok(false),
    }
}
pub(super) fn check_schema(db: &Connection) -> io::Result<()> {
    db.prepare(
        "SELECT session,node,host,pin,actor,create_request,receipt,creator FROM closed_game",
    )
    .map_err(io::Error::other)?;
    Ok(())
}
pub(super) fn reject_closed_create(
    db: &Connection,
    actor: &[u8],
    request: &[u8; 16],
) -> io::Result<()> {
    if database_version(db)? != 4 {
        return Ok(());
    }
    let closed:bool=db.query_row(
        "SELECT EXISTS(SELECT 1 FROM closed_game WHERE host=1 AND actor=? AND create_request=?)",
        params![actor,request], |row|row.get(0)
    ).map_err(io::Error::other)?;
    if closed {
        return Err(invalid("Create request belongs to a closed lobby"));
    }
    Ok(())
}
fn filename(host: bool, node: ReplicaId) -> String {
    let kind = if host { "game" } else { "learner" };
    format!("{kind}-{node}-g1.sqlite")
}
pub(crate) fn check_new_inventory(db: &Connection, directory: &Path) -> io::Result<()> {
    if database_version(db)? != 4 {
        return ensure_empty_inventory(directory);
    }
    let mut allowed = std::collections::HashSet::from(
        [
            "installation.writer",
            "installation.sqlite",
            "installation.sqlite-wal",
            "installation.sqlite-shm",
        ]
        .map(String::from),
    );
    let mut rows = db
        .prepare("SELECT node,host FROM closed_game")
        .map_err(io::Error::other)?;
    let files = rows
        .query_map([], |r| Ok(filename(r.get(1)?, ReplicaId(r.get(0)?))))
        .map_err(io::Error::other)?;
    for file in files {
        let name = file.map_err(io::Error::other)?;
        for suffix in ["", ".writer", "-wal", "-shm"] {
            allowed.insert(format!("{name}{suffix}"));
        }
    }
    for file in fs::read_dir(directory)? {
        let file = file?;
        if !file
            .file_name()
            .to_str()
            .is_some_and(|n| allowed.contains(n))
            || !file.file_type()?.is_file()
        {
            return Err(invalid("unknown game inventory requires explicit recovery"));
        }
    }
    Ok(())
}

pub(crate) struct CancellationGeneration {
    pub session: Vec<u8>,
    pub creator: Creator,
    pub node: ReplicaId,
    pub pin: [u8; 32],
}

impl CancellationGeneration {
    fn path(&self, directory: &Path) -> io::Result<PathBuf> {
        let path = directory.join(filename(self.node == self.creator.node, self.node));
        if path.is_symlink() {
            return Err(invalid("invalid cancellation generation path"));
        }
        Ok(path)
    }
}

fn terminal_receipt(game: &Connection) -> io::Result<Option<Vec<u8>>> {
    let Some(k) = at(game, u64::MAX)? else {
        return Ok(None);
    };
    let commit = store::meta::<Option<LogId>>(game, "committed")?
        .flatten()
        .ok_or(invalid("missing commitment"))?;
    if commit.index < k.index || (commit.index == k.index && commit != k) {
        return Err(invalid("terminal decision not committed locally"));
    }
    let record:Vec<u8>=game.query_row(
            "SELECT r.record FROM archive a JOIN receipt r ON r.seq=a.receipt_count WHERE a.log_id=?",
            [log_key(k)],|row| row.get(0),
        ).map_err(io::Error::other)?;

    Ok(Some(record))
}

impl InstallationCatalog {
    fn closed_generation(
        &self,
        session: &[u8],
    ) -> io::Result<Option<(CancellationGeneration, Vec<u8>)>> {
        if database_version(&self.db)? != 4 {
            return Ok(None);
        }
        let row = self
            .db
            .query_row(
                "SELECT node,host,pin,creator,receipt FROM closed_game WHERE session=?",
                [session],
                |r| {
                    Ok((
                        ReplicaId(r.get(0)?),
                        r.get::<_, bool>(1)?,
                        r.get(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(io::Error::other)?;
        let Some((node, host, pin, creator, record)) = row else {
            return Ok(None);
        };
        let creator = store::decode::<Creator>(&creator)?;
        if host != (node == creator.node) {
            return Err(invalid("invalid closed generation role"));
        }
        Ok(Some((
            CancellationGeneration {
                session: session.to_vec(),
                creator,
                node,
                pin,
            },
            record,
        )))
    }

    /// Compare the retained game receipt to the confirmation recorded with the slot release.
    pub fn confirmed_cancellation(&self, session: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let Some((g, expected)) = self.closed_generation(session)? else {
            return Ok(None);
        };
        let path = g.path(&self.directory)?;
        let mut db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(io::Error::other)?;
        let tx = db.transaction().map_err(io::Error::other)?;
        verify_game_identity(&tx, session, Some(&g.creator), Some(g.node))?;
        let proof = store::meta::<genesis::SignedGenesis>(&tx, "signed_genesis")?
            .ok_or(invalid("missing signed genesis"))?;
        proof.verify(&proof.body, &g.creator)?;
        if proof.fingerprint != g.pin || terminal_receipt(&tx)?.as_ref() != Some(&expected) {
            return Err(invalid("terminal receipt differs from pinned history"));
        }
        Ok(Some(expected))
    }

    /// Restore a closed generation for replication, original requests and history delivery.
    /// The archived generation never occupies the current participation slot.
    pub async fn open_cancelled_lobby<N>(
        &mut self,
        session: &[u8],
        config: Config,
        network: N,
    ) -> io::Result<GameNode>
    where
        N: RaftNetworkFactory<Types>,
        N::Network: NetSnapshot<Types, SnapshotData = ()>,
    {
        let (generation, _) = self
            .closed_generation(session)?
            .ok_or(invalid("no closed generation"))?;
        let path = generation.path(&self.directory)?;
        let CancellationGeneration {
            node: id,
            creator,
            pin,
            ..
        } = generation;
        let replica = Replica::open_reserved_generation(
            &path,
            session,
            &creator,
            id,
            false,
            Some(LobbyFormat::Cancellable),
        )
        .await?;
        if replica.root(&creator, None)? != Some(pin)
            || self.reconcile_generation(&replica)?.is_none()
        {
            return Err(invalid("closed history differs from catalog"));
        }
        let voters = store::meta::<openraft::alias::StoredMembershipOf<Types>>(
            &*replica.lock()?,
            "membership",
        )?
        .ok_or(invalid("missing terminal membership"))?;
        if !voters.membership().voter_ids().any(|voter| voter == id) {
            return Err(invalid(
                "nonvoting installation cannot serve as a historical voter",
            ));
        }
        GameNode::start(id, replica, config, network).await
    }

    pub(super) fn resume_cancellation(&mut self) -> io::Result<()> {
        let generation = if has_learner(&self.db)? {
            crate::learner::cancellation_generation(&self.db)?
        } else if let Some(r) = Self::reservation(&self.db)? {
            match (r.pin, r.lobby_command) {
                (Some(pin), Some(cmd))
                    if LobbyCommand::verify(&cmd.0, &r.session, &r.creator)?.format
                        == LobbyFormat::Cancellable =>
                {
                    Some(CancellationGeneration {
                        session: r.session,
                        node: r.creator.node,
                        creator: r.creator,
                        pin,
                    })
                }
                _ => None,
            }
        } else {
            None
        };
        let Some(g) = generation else { return Ok(()) };
        let path = g.path(&self.directory)?;
        let r = match Replica::open_generation(
            &path,
            &g.session,
            Some(&g.creator),
            Some(g.node),
            false,
            Some(LobbyFormat::Cancellable),
        ) {
            Ok(r) => r,
            // A live owner reconciles using its existing handle.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e),
        };
        if at(&*r.lock()?, u64::MAX)?.is_none() {
            return Ok(());
        }
        if r.root(&g.creator, None)? != Some(g.pin) {
            return Err(invalid("terminal generation differs from catalog pin"));
        }
        self.reconcile_generation(&r)?;
        Ok(())
    }
    /// Finish the local half of cancellation from this installation's pinned, applied history.
    /// A retry for a closed generation cannot release a later game's slot.
    pub fn reconcile_cancellation(&mut self, node: &GameNode) -> io::Result<Option<Vec<u8>>> {
        self.reconcile_generation(&node.replica)
    }

    /// A receiver can reconcile its own terminal copy without acquiring voter authority.
    pub fn reconcile_learner_cancellation(
        &mut self,
        learner: &Learner,
    ) -> io::Result<Option<Vec<u8>>> {
        self.reconcile_generation(&learner.node.replica)
    }

    fn reconcile_generation(&mut self, replica: &Replica) -> io::Result<Option<Vec<u8>>> {
        if replica.lobby_format != Some(LobbyFormat::Cancellable) {
            return Ok(None);
        }
        let game = replica.lock()?;
        replica.require_lobby_genesis(&game)?;
        replica.verify_replay(&game)?;
        let Some(record) = terminal_receipt(&game)? else {
            return Ok(None);
        };
        let id = replica
            .local_node
            .ok_or(invalid("missing installation identity"))?;
        let creator =
            store::meta::<Creator>(&game, "creator")?.ok_or(invalid("missing creator"))?;
        let host = creator.node == id;
        let path = self.directory.join(filename(host, id));
        if game.path().map(Path::new) != Some(path.as_path()) {
            return Err(invalid("wrong installation generation"));
        }
        let root = replica
            .bound_root
            .get()
            .ok_or(invalid("missing pinned root"))?;
        let session = replica.session.as_slice();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        let version = database_version(&tx)?;
        if version == 4 {
            let old: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT receipt FROM closed_game WHERE session=? AND node=? AND pin=?",
                    params![session, id.0, root],
                    |r| r.get(0),
                )
                .optional()
                .map_err(io::Error::other)?;
            if let Some(bytes) = old {
                if bytes != record {
                    return Err(invalid("terminal receipt differs from pinned history"));
                }
                return Ok(Some(record));
            }
        }
        let create_request = if host {
            let r = Self::reservation(&tx)?.ok_or(invalid("missing creator reservation"))?;
            if r.session != session || r.creator != creator || r.pin.as_ref() != Some(root) {
                return Err(invalid("wrong cancellation reservation"));
            }
            Some(r.request)
        } else {
            if !has_learner(&tx)? {
                return Err(invalid("missing learner reservation"));
            }
            crate::learner::check_cancellation_binding(&tx, replica, &game, root)?;
            None
        };
        if version != 4 {
            tx.execute_batch("CREATE TABLE closed_game(session BLOB PRIMARY KEY,node BLOB UNIQUE NOT NULL CHECK(length(node)=16),host INTEGER NOT NULL CHECK(host IN(0,1)),
                pin BLOB NOT NULL CHECK(length(pin)=32),actor BLOB NOT NULL,create_request BLOB,receipt BLOB NOT NULL,creator BLOB NOT NULL) STRICT;
                PRAGMA user_version=4").map_err(io::Error::other)?;
            if version == 2 {
                crate::learner::create_learner_table(&tx)?;
            }
        }
        tx.execute(
            "INSERT INTO closed_game VALUES(?,?,?,?,?,?,?,?)",
            params![
                session,
                id.0,
                host,
                root,
                creator.actor,
                create_request,
                record,
                store::encode(&creator)?
            ],
        )
        .map_err(io::Error::other)?;
        let removed = tx
            .execute(
                if host {
                    "DELETE FROM participation WHERE slot=1 AND session=? AND node=?"
                } else {
                    "DELETE FROM learner WHERE slot=1 AND session=? AND node=?"
                },
                params![session, id.0],
            )
            .map_err(io::Error::other)?;
        if removed != 1 {
            return Err(invalid("reservation changed during cancellation"));
        }
        #[cfg(test)]
        if self.crash_stage == 41 {
            std::process::exit(141);
        }
        tx.commit().map_err(io::Error::other)?;
        #[cfg(test)]
        self.interrupt_at(42);
        if host {
            self.running = Weak::new();
        }
        Ok(Some(record))
    }
}
