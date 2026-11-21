//! Installation-local Create reservation and independent trust-root pin.
use crate::{genesis::Creator, *};
use ed25519_dalek::SigningKey;
use openraft::{
    Config,
    network::{NetSnapshot, RaftNetworkFactory},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::{fs, path::PathBuf, sync::Weak, time::Duration};

pub struct CreatorGame {
    pub session: Vec<u8>,
    pub fingerprint: [u8; 32],
    pub creator_node: ReplicaId,
    pub node: Arc<GameNode>,
}

pub struct InstallationCatalog {
    directory: PathBuf,
    db: Connection,
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
}

fn ensure_empty_inventory(directory: &Path) -> io::Result<()> {
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
        if !path.exists() {
            ensure_empty_inventory(&directory)?
        }
        let db = Connection::open(&path).map_err(io::Error::other)?;
        let mode: String = db
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(io::Error::other)?;
        if mode != "wal" {
            return Err(invalid("catalog WAL unavailable"));
        }
        db.execute_batch("PRAGMA synchronous=FULL")
            .map_err(io::Error::other)?;
        let version: i32 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(io::Error::other)?;
        if version == 0 {
            ensure_empty_inventory(&directory)?;
            db.execute_batch("BEGIN IMMEDIATE;
                CREATE TABLE participation (
                    slot INTEGER PRIMARY KEY CHECK(slot=1), request BLOB NOT NULL CHECK(length(request)=16),
                    session BLOB NOT NULL CHECK(length(session)=16), actor BLOB NOT NULL,
                    public_key BLOB NOT NULL CHECK(length(public_key)=32), node BLOB NOT NULL CHECK(length(node)=16),
                    stage INTEGER NOT NULL DEFAULT 0 CHECK(stage IN(0,1,2)),pin BLOB,
                    CHECK((stage<2 AND pin IS NULL) OR (stage=2 AND pin IS NOT NULL AND length(pin)=32))
                ) STRICT;
                PRAGMA user_version=1; COMMIT").map_err(io::Error::other)?;
        } else if version != 1 {
            return Err(invalid("unsupported installation catalog"));
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
            "SELECT request,session,actor,public_key,node,stage,pin FROM participation WHERE slot=1", [],
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
                };
                Ok((stage, reservation))
            }
        ).optional().map_err(io::Error::other)?;
        match row {
            Some((stage, r)) if !(0..=2).contains(&stage) || (stage == 2) != r.pin.is_some() => {
                Err(invalid("catalog phase and pin disagree"))
            }
            other => Ok(other.map(|(_, r)| r)),
        }
    }
    /// Local catalog state. Opening an active game verifies its independent pin again.
    pub fn active_pin(&self) -> io::Result<Option<[u8; 32]>> {
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
    ) -> io::Result<Reservation> {
        if actor.is_empty() || actor.len() > 64 || request[6] >> 4 != 4 || request[8] >> 6 != 2 {
            return Err(invalid("invalid creator or Create request ID"));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        if Self::reservation(&tx)?.is_none() {
            ensure_empty_inventory(&self.directory)?;
        }
        tx.execute("INSERT INTO participation(slot,request,session,actor,public_key,node) VALUES(1,?,randomblob(16),?,?,randomblob(16)) ON CONFLICT(slot) DO NOTHING",
            params![request,actor,key.verifying_key().as_bytes()]).map_err(io::Error::other)?;
        let r = Self::reservation(&tx)?.ok_or(invalid("missing reservation"))?;
        if r.request != request
            || r.creator.actor != actor
            || r.creator.key != key.verifying_key().to_bytes()
        {
            return Err(invalid("another Create owns the participation slot"));
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
        let r = self.reserve(request, actor, key)?;
        #[cfg(test)]
        self.interrupt_at(1);
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
        if let Some(node) = self.running.upgrade() {
            let pin = node.replica.root(&r.creator, None)?;
            if Some(pin) != r.pin {
                return Err(invalid("active catalog pin mismatch"));
            }
            return Ok(CreatorGame {
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
        let replica = Replica::open_game(&path, &r.session, Some(&r.creator), !r.prepared)?;
        if let Some(pin) = r.pin
            && replica.root(&r.creator, None)? != pin
        {
            return Err(invalid("game genesis does not match catalog pin"));
        }
        if !r.prepared {
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
            if matches!(self.crash_stage, 6 | 7) {
                replica
                    .crash
                    .store(self.crash_stage, std::sync::atomic::Ordering::Release);
            }
        }
        let node = GameNode::start(r.creator.node, replica, config, network).await?;
        let result = if let Some(pin) = r.pin {
            Ok(pin)
        } else {
            self.finish_create(&r, &node, key).await
        };
        let pin = match result {
            Ok(pin) => pin,
            Err(e) => {
                let _ = node.raft.shutdown().await;
                return Err(e);
            }
        };
        let node = Arc::new(node);
        self.running = Arc::downgrade(&node);
        Ok(CreatorGame {
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
    ) -> io::Result<[u8; 32]> {
        if !node.raft.is_initialized().await.map_err(io::Error::other)? {
            node.raft
                .initialize(std::collections::BTreeMap::from([(r.creator.node, ())]))
                .await
                .map_err(io::Error::other)?;
        }
        node.raft
            .wait(Some(Duration::from_secs(10)))
            .state(openraft::ServerState::Leader, "creator election")
            .await
            .map_err(io::Error::other)?;
        node.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .map_err(io::Error::other)?;
        #[cfg(test)]
        self.interrupt_at(3);
        let pin = node.replica.root(&r.creator, key)?;
        #[cfg(test)]
        self.interrupt_at(4);
        // Pin and activate generation one in a single catalog commit. No update
        // can replace an earlier pin, including a conflicting retry.
        let updated = self
            .db
            .execute(
                "UPDATE participation SET stage=2,pin=?
             WHERE slot=1 AND request=? AND session=? AND stage=1 AND pin IS NULL",
                params![pin, r.request, r.session],
            )
            .map_err(io::Error::other)?;
        if updated != 1 {
            return Err(invalid("activation reservation changed"));
        }
        #[cfg(test)]
        self.interrupt_at(5);
        Ok(pin)
    }
    #[cfg(test)]
    fn interrupt_at(&self, stage: u8) {
        if self.crash_stage == stage {
            std::process::exit(90 + stage as i32)
        }
    }
}
