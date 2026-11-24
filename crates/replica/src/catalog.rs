//! Installation-local Create reservation and independent trust-root pin.
use crate::lobby::{LobbyCommand, LobbyFormat};
use crate::{genesis::Creator, *};
use ed25519_dalek::SigningKey;
use openraft::{
    Config,
    network::{NetSnapshot, RaftNetworkFactory},
};
use rat_race_engine::LobbyCapacity;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::{fs, path::PathBuf, sync::Weak, time::Duration};

pub struct CreatorGame {
    pub session: Vec<u8>,
    pub fingerprint: [u8; 32],
    pub creator_node: ReplicaId,
    pub node: Arc<GameNode>,
    pub lobby: Option<LobbyCreation>,
}

pub struct InstallationCatalog {
    pub(crate) directory: PathBuf,
    pub(crate) db: Connection,
    _writer: fs::File,
    running: Weak<GameNode>,
    #[cfg(test)]
    pub(crate) crash_stage: u8,
}

struct Reservation {
    request: [u8; 16],
    session: Vec<u8>,
    creator: Creator,
    prepared: bool,
    pin: Option<[u8; 32]>,
    lobby_command: Option<Signed>,
}

pub(crate) fn ensure_empty_inventory(directory: &Path) -> io::Result<()> {
    for file in fs::read_dir(directory)? {
        if !matches!(
            file?.file_name().to_str(),
            Some(
                "installation.writer"
                    | "installation.sqlite"
                    | "installation.sqlite-wal"
                    | "installation.sqlite-shm"
            )
        ) {
            return Err(invalid(
                "installation catalog missing; explicit recovery required",
            ));
        }
    }
    Ok(())
}

impl InstallationCatalog {
    /// Use a private directory dedicated to this installation's game inventory.
    pub fn open(directory: &Path) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        let directory = directory.canonicalize()?;
        let writer = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("installation.writer"))?;
        writer.try_lock().map_err(io::Error::other)?;
        let path = directory.join("installation.sqlite");
        if path.is_symlink() {
            return Err(invalid("invalid installation catalog path"));
        }
        check_sqlite_files(&path)?;
        if !path.exists() {
            ensure_empty_inventory(&directory)?
        }
        let db = Connection::open(&path).map_err(io::Error::other)?;
        let version = database_version(&db)?;
        match version {
            0 => ensure_empty_inventory(&directory)?,
            1 => {
                db.prepare("SELECT request,session,actor,public_key,node,stage,pin FROM participation WHERE slot=1")
                    .map_err(io::Error::other)?;
            }
            2 | 3 => {
                Self::reservation(&db)?;
                if version == 3 {
                    crate::learner::check_inventory(&db)?;
                }
            }
            _ => return Err(invalid("unsupported installation catalog")),
        }
        let mode: String = db
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(io::Error::other)?;
        if mode != "wal" {
            return Err(invalid("catalog WAL unavailable"));
        }
        db.execute_batch("PRAGMA synchronous=FULL")
            .map_err(io::Error::other)?;
        if version == 0 {
            db.execute_batch("BEGIN IMMEDIATE;
                CREATE TABLE participation (
                    slot INTEGER PRIMARY KEY CHECK(slot=1), request BLOB NOT NULL CHECK(length(request)=16),
                    session BLOB NOT NULL CHECK(length(session)=16), actor BLOB NOT NULL,
                    public_key BLOB NOT NULL CHECK(length(public_key)=32), node BLOB NOT NULL CHECK(length(node)=16),
                    stage INTEGER NOT NULL DEFAULT 0 CHECK(stage IN(0,1,2)),pin BLOB,lobby_command BLOB,
                    CHECK((stage<2 AND pin IS NULL) OR (stage=2 AND pin IS NOT NULL AND length(pin)=32))
                ) STRICT;
                PRAGMA user_version=2; COMMIT").map_err(io::Error::other)?;
        } else if version == 1 {
            db.execute_batch(
                "BEGIN IMMEDIATE;
                ALTER TABLE participation ADD COLUMN lobby_command BLOB;
                PRAGMA user_version=2; COMMIT",
            )
            .map_err(io::Error::other)?;
        }
        Ok(Self {
            directory,
            db,
            _writer: writer,
            running: Weak::new(),
            #[cfg(test)]
            crash_stage: 0,
        })
    }
    fn reservation(db: &Connection) -> io::Result<Option<Reservation>> {
        let row = db.query_row(
            "SELECT request,session,actor,public_key,node,stage,pin,lobby_command FROM participation WHERE slot=1", [],
            |row| {
                let stage: i32 = row.get(5)?;
                let reservation = Reservation {
                    request: row.get(0)?,
                    session: row.get(1)?,
                    creator: Creator {
                        actor: row.get(2)?,
                        key: row.get(3)?,
                        node: ReplicaId(row.get(4)?),
                    },
                    prepared: stage != 0,
                    pin: row.get(6)?,
                    lobby_command: row.get::<_, Option<Vec<u8>>>(7)?.map(Signed),
                };
                Ok((stage, reservation))
            }
        ).optional().map_err(io::Error::other)?;
        match row {
            Some((stage, r)) if !(0..=2).contains(&stage) || (stage == 2) != r.pin.is_some() => {
                Err(invalid("catalog phase and pin disagree"))
            }
            Some((_, r)) => {
                if let Some(signed) = &r.lobby_command {
                    let command = LobbyCommand::verify(&signed.0, &r.session, &r.creator)?;
                    if command.request != r.request {
                        return Err(invalid("Create reservation request mismatch"));
                    }
                }
                Ok(Some(r))
            }
            None => Ok(None),
        }
    }
    /// Local catalog state. Opening an active game verifies its independent pin again.
    pub fn active_pin(&self) -> io::Result<Option<[u8; 32]>> {
        if database_version(&self.db)? == 3 {
            return self.verified_learner_pin();
        }
        Ok(Self::reservation(&self.db)?.and_then(|r| r.pin))
    }
    fn game_path(&self, r: &Reservation) -> PathBuf {
        self.directory
            .join(format!("game-{}-g1.sqlite", r.creator.node))
    }
    fn reserve(
        &mut self,
        request: [u8; 16],
        actor: &[u8],
        key: &SigningKey,
        lobby: Option<(CreateLobby<'_>, LobbyFormat)>,
    ) -> io::Result<Reservation> {
        if database_version(&self.db)? == 3 {
            return Err(invalid("learner owns the participation slot"));
        }
        if actor.is_empty() || actor.len() > 64 || request[6] >> 4 != 4 || request[8] >> 6 != 2 {
            return Err(invalid("invalid creator or Create request ID"));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        let capacity = lobby
            .map(|(input, _)| {
                LobbyCapacity::new(input.target).ok_or(invalid("invalid lobby capacity"))
            })
            .transpose()?;
        let existing = Self::reservation(&tx)?;
        let r = if let Some(existing) = existing {
            existing
        } else {
            if lobby.is_some_and(|(input, _)| !input.profile_complete || !input.can_host) {
                return Err(invalid("local profile or hosting eligibility unavailable"));
            }
            ensure_empty_inventory(&self.directory)?;
            tx.execute("INSERT INTO participation(slot,request,session,actor,public_key,node) VALUES(1,?,randomblob(16),?,?,randomblob(16))",
            params![request,actor,key.verifying_key().as_bytes()]).map_err(io::Error::other)?;
            let mut r = Self::reservation(&tx)?.ok_or(invalid("missing reservation"))?;
            if let (Some(capacity), Some((_, format))) = (capacity, lobby) {
                let signed = LobbyCommand {
                    format,
                    session: &r.session,
                    actor,
                    request,
                    node: r.creator.node,
                    capacity,
                }
                .sign(key);
                tx.execute(
                    "UPDATE participation SET lobby_command=? WHERE slot=1",
                    [&signed],
                )
                .map_err(io::Error::other)?;
                r.lobby_command = Some(Signed(signed));
            }
            r
        };
        if r.request != request
            || r.creator.actor != actor
            || r.creator.key != key.verifying_key().to_bytes()
        {
            return Err(invalid("another Create owns the participation slot"));
        }
        let original_capacity = r
            .lobby_command
            .as_ref()
            .map(|s| LobbyCommand::verify(&s.0, &r.session, &r.creator).map(|c| c.capacity))
            .transpose()?;
        if original_capacity != capacity {
            return Err(invalid("conflicting Create intent"));
        }
        tx.commit().map_err(io::Error::other)?;
        Ok(r)
    }

    /// The caller retains its UUIDv4 request across retries and holds the existing
    /// installation signing key. Neither database receives secret key material.
    pub async fn create<N>(
        &mut self,
        request: [u8; 16],
        actor: &[u8],
        key: &SigningKey,
        config: Config,
        network: N,
    ) -> io::Result<CreatorGame>
    where
        N: RaftNetworkFactory<Types>,
        N::Network: NetSnapshot<Types, SnapshotData = ()>,
    {
        let r = self.reserve(request, actor, key, None)?;
        #[cfg(test)]
        self.interrupt_at(1);
        self.resume(r, Some(key), config, network).await
    }

    /// Reserve and sign the original operation, bootstrap its genuine creator
    /// membership, and return only after both the lobby and local pin are durable.
    pub async fn create_lobby<N>(
        &mut self,
        input: CreateLobby<'_>,
        key: &SigningKey,
        config: Config,
        network: N,
    ) -> io::Result<CreatorGame>
    where
        N: RaftNetworkFactory<Types>,
        N::Network: NetSnapshot<Types, SnapshotData = ()>,
    {
        self.create_lobby_for_profile(input, key, config, network, LobbyFormat::Seating)
            .await
    }

    pub(crate) async fn create_lobby_for_profile<N>(
        &mut self,
        input: CreateLobby<'_>,
        key: &SigningKey,
        config: Config,
        network: N,
        format: LobbyFormat,
    ) -> io::Result<CreatorGame>
    where
        N: RaftNetworkFactory<Types>,
        N::Network: NetSnapshot<Types, SnapshotData = ()>,
    {
        let r = self.reserve(input.request, input.actor, key, Some((input, format)))?;
        #[cfg(test)]
        self.interrupt_at(1);
        self.resume(r, Some(key), config, network).await
    }

    /// Reconcile an already-authorized Create after process restart using its
    /// durable signed intent and the installation's existing creator identity.
    pub async fn resume_lobby_create<N>(
        &mut self,
        key: &SigningKey,
        config: Config,
        network: N,
    ) -> io::Result<CreatorGame>
    where
        N: RaftNetworkFactory<Types>,
        N::Network: NetSnapshot<Types, SnapshotData = ()>,
    {
        let r = Self::reservation(&self.db)?
            .filter(|r| r.lobby_command.is_some())
            .ok_or(invalid("no reserved lobby Create"))?;
        if r.creator.key != key.verifying_key().to_bytes() {
            return Err(invalid("Create belongs to another signing identity"));
        }
        self.resume(r, Some(key), config, network).await
    }

    /// Reopen the pinned generation without the creator's private key.
    pub async fn open_active<N>(&mut self, config: Config, network: N) -> io::Result<CreatorGame>
    where
        N: RaftNetworkFactory<Types>,
        N::Network: NetSnapshot<Types, SnapshotData = ()>,
    {
        let r = Self::reservation(&self.db)?
            .filter(|r| r.pin.is_some())
            .ok_or(invalid("no pinned game"))?;
        self.resume(r, None, config, network).await
    }

    async fn resume<N>(
        &mut self,
        r: Reservation,
        key: Option<&SigningKey>,
        config: Config,
        network: N,
    ) -> io::Result<CreatorGame>
    where
        N: RaftNetworkFactory<Types>,
        N::Network: NetSnapshot<Types, SnapshotData = ()>,
    {
        let format = r
            .lobby_command
            .as_ref()
            .map(|s| LobbyCommand::verify(&s.0, &r.session, &r.creator).map(|c| c.format))
            .transpose()?;
        if let Some(node) = self.running.upgrade() {
            let pin = r.pin.ok_or(invalid("live game requires an active pin"))?;
            if node.replica.session != r.session
                || node.replica.lobby_format != format
                || node.replica.root(&r.creator, None)? != Some(pin)
            {
                return Err(invalid("active catalog pin mismatch"));
            }
            if !node.raft.is_initialized().await.map_err(io::Error::other)? {
                return Err(invalid("active game has no initialized Raft node"));
            }
            if r.lobby_command.is_some() {
                confirm_pinned_lobby(&node, key.is_some()).await?;
            }
            if format.is_some_and(LobbyFormat::semantic_links)
                && let Some(key) = key
            {
                node.enable_sealer(key)?;
            }
            return Ok(CreatorGame {
                lobby: r
                    .lobby_command
                    .as_ref()
                    .map(|s| node.replica.original_lobby(s))
                    .transpose()?,
                node,
                session: r.session,
                creator_node: r.creator.node,
                fingerprint: pin,
            });
        }
        let path = self.game_path(&r);
        if path.is_symlink() {
            return Err(invalid("invalid game generation path"));
        }
        let replica = Replica::open_reserved_generation(
            &path,
            &r.session,
            &r.creator,
            r.creator.node,
            !r.prepared,
            format,
        )
        .await?;
        // A pending reservation may already own a signed record. Verify it
        // before Raft can campaign or append on a recovered generation.
        let original = replica.root(&r.creator, None)?;
        if r.pin.is_none()
            && let Some(signed) = &r.lobby_command
        {
            replica.verify_pending_create(signed, original.is_some())?;
        }
        if r.pin.is_some() && original != r.pin {
            return Err(invalid("game genesis does not match catalog pin"));
        }
        let pinned_lobby = match (&r.pin, &r.lobby_command) {
            (Some(_), Some(signed)) => Some(replica.original_lobby(signed)?),
            _ => None,
        };
        if !r.prepared {
            #[cfg(test)]
            self.interrupt_at(8); // Game file durable, catalog still reserved.
            let updated = self
                .db
                .execute(
                    "UPDATE participation SET stage=1
                 WHERE slot=1 AND request=? AND stage=0 AND pin IS NULL",
                    [r.request],
                )
                .map_err(io::Error::other)?;
            if updated != 1 {
                return Err(invalid("preparation reservation changed"));
            }
        }
        #[cfg(test)]
        {
            self.interrupt_at(2);
            if matches!(self.crash_stage, 6 | 7 | 9 | 10) {
                replica.crash.store(
                    match self.crash_stage {
                        9 => 1,
                        10 => 2,
                        stage => stage,
                    },
                    std::sync::atomic::Ordering::Release,
                );
            }
        }
        let node = GameNode::start(r.creator.node, replica, config, network).await?;
        let result = if let Some(pin) = r.pin {
            if pinned_lobby.is_some() {
                confirm_pinned_lobby(&node, key.is_some())
                    .await
                    .map(|()| (pin, pinned_lobby))
            } else {
                Ok((pin, None))
            }
        } else {
            self.finish_create(&r, &node, key).await
        };
        let (pin, lobby) = match result {
            Ok(result) => result,
            Err(e) => {
                let _ = node.raft.shutdown().await;
                return Err(e);
            }
        };
        let node = Arc::new(node);
        if format.is_some_and(LobbyFormat::semantic_links)
            && let Some(key) = key
            && let Err(error) = node.enable_sealer(key)
        {
            let _ = node.raft.shutdown().await;
            return Err(error);
        }
        self.running = Arc::downgrade(&node);
        Ok(CreatorGame {
            lobby,
            node,
            session: r.session,
            creator_node: r.creator.node,
            fingerprint: pin,
        })
    }
    async fn finish_create(
        &self,
        r: &Reservation,
        node: &GameNode,
        key: Option<&SigningKey>,
    ) -> io::Result<([u8; 32], Option<LobbyCreation>)> {
        if !node.raft.is_initialized().await.map_err(io::Error::other)? {
            node.raft
                .initialize(std::collections::BTreeMap::from([(r.creator.node, ())]))
                .await
                .map_err(io::Error::other)?;
        }
        confirm_creator_read(node).await?;
        #[cfg(test)]
        self.interrupt_at(3);
        let pin = node
            .replica
            .root(&r.creator, key)?
            .ok_or(invalid("original genesis certificate missing"))?;
        #[cfg(test)]
        self.interrupt_at(4);
        let lobby = if let Some(signed) = &r.lobby_command {
            match node
                .submit(signed.clone())
                .await
                .map_err(|e| io::Error::other(format!("Create submission: {e:?}")))?
            {
                Reply::Receipt(receipt) => {
                    let original = node.replica.original_lobby(signed)?;
                    if receipt != original.receipt {
                        return Err(invalid("Create reply differs from durable original"));
                    }
                    Some(original)
                }
                _ => return Err(invalid("Create did not produce its original receipt")),
            }
        } else {
            None
        };
        // Pin and activate generation one in a single catalog commit. No update
        // can replace an earlier pin, including a conflicting retry.
        let updated = self
            .db
            .execute(
                "UPDATE participation SET stage=2,pin=?
             WHERE slot=1 AND request=? AND session=? AND node=? AND actor=? AND public_key=?
               AND lobby_command IS ? AND stage=1 AND pin IS NULL",
                params![
                    pin,
                    r.request,
                    r.session,
                    r.creator.node.0,
                    r.creator.actor,
                    r.creator.key,
                    r.lobby_command.as_ref().map(|cmd| cmd.0.as_slice())
                ],
            )
            .map_err(io::Error::other)?;
        if updated != 1 {
            return Err(invalid("activation reservation changed"));
        }
        #[cfg(test)]
        self.interrupt_at(5);
        Ok((pin, lobby))
    }
    #[cfg(test)]
    fn interrupt_at(&self, stage: u8) {
        if self.crash_stage == stage {
            std::process::exit(90 + stage as i32)
        }
    }
}

async fn confirm_pinned_lobby(node: &GameNode, submitting_create: bool) -> io::Result<()> {
    // A keyless reopen returns the immutable, replay-verified creation receipt.
    // Once a Join is in the log, transport must start before a quorum can elect.
    if !submitting_create && node.replica.has_first_join_source()? {
        return Ok(());
    }
    confirm_creator_read(node).await
}

async fn confirm_creator_read(node: &GameNode) -> io::Result<()> {
    node.raft
        .wait(Some(Duration::from_secs(10)))
        .state(openraft::ServerState::Leader, "creator election")
        .await
        .map_err(io::Error::other)?;
    node.raft
        .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
        .await
        .map_err(io::Error::other)?;
    Ok(())
}
