//! Durable command application, lobby membership and receipt recovery.
mod application;
mod catalog;
mod genesis;
mod learner;
pub use learner::{
    JoinDelivery, JoinResult, JoinedMember, Learner, LearnerReplication, PromotionAuthority,
    ThirdJoinTransport, VotingHistoryRequest,
};
mod lobby;
pub use catalog::{CreatorGame, InstallationCatalog};
pub use lobby::{CreateLobby, LobbyCreated, LobbyCreation, LobbyStage};
mod node;
mod recovery;
mod seating;
pub use rat_race_engine::SeatId;
pub use seating::{
    LobbyIntent, LobbyPreference, LobbySeat, LobbySeatView, OwnLobbyPreference, OwnPreferenceRead,
    SeatClaimGuard, SeatCommandGuard,
};
mod store;
mod types;
mod wire;
pub use node::{GameNode, Raft, SubmitError};
#[cfg(test)]
mod cluster;
use rusqlite::Connection;
use std::{
    io,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};
pub use types::*;
pub use wire::{Applied, Command};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Opening a new main file can cause SQLite to discard an older journal at
// that path. Preserve the surviving files for explicit recovery.
fn check_sqlite_files(path: &Path) -> io::Result<()> {
    if !path.try_exists()? {
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut journal = path.as_os_str().to_owned();
            journal.push(suffix);
            match std::fs::symlink_metadata(journal) {
                Ok(_) => return Err(invalid("missing database with surviving SQLite files")),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

// SQLite uses version zero for both an empty database and an application
// that never set user_version. Only the former is available for provisioning.
fn database_version(db: &Connection) -> io::Result<i32> {
    let version = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(io::Error::other)?;
    if version == 0 {
        let occupied: bool = db
            .query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema)", [], |row| {
                row.get(0)
            })
            .map_err(io::Error::other)?;
        if occupied {
            return Err(invalid("unrecognized database at reserved path"));
        }
    }
    Ok(version)
}

fn verify_game_identity(
    db: &Connection,
    session: &[u8],
    creator: Option<&genesis::Creator>,
    local_node: Option<ReplicaId>,
) -> io::Result<()> {
    if store::meta::<Vec<u8>>(db, "session")?.as_deref() != Some(session)
        || store::meta::<genesis::Creator>(db, "creator")?.as_ref() != creator
    {
        return Err(invalid("unexpected game database identity"));
    }
    if let Some(local) = local_node
        && store::meta::<ReplicaId>(db, "local_node")? != Some(local)
    {
        return Err(invalid("original creator replica binding missing"));
    }
    Ok(())
}

#[derive(Clone)]
pub struct Replica {
    db: Arc<Mutex<Connection>>,
    _writer: Arc<std::fs::File>,
    started: Arc<std::sync::atomic::AtomicBool>,
    session: Vec<u8>,
    local_node: Option<ReplicaId>,
    lobby_format: Option<lobby::LobbyFormat>,
    bound_root: Arc<std::sync::OnceLock<[u8; 32]>>,
    seal_wake: Arc<Mutex<Option<std::sync::mpsc::SyncSender<()>>>>,
    #[cfg(test)]
    crash: Arc<std::sync::atomic::AtomicU8>,
}
impl Replica {
    pub fn open(path: &Path, session: &[u8]) -> io::Result<Self> {
        Self::open_generation(path, session, None, None, true, None)
    }
    async fn open_reserved_generation(
        path: &Path,
        session: &[u8],
        creator: &genesis::Creator,
        local: ReplicaId,
        allow_create: bool,
        lobby_format: Option<lobby::LobbyFormat>,
    ) -> io::Result<Self> {
        use openraft::AsyncRuntime;
        use std::time::{Duration, Instant};
        // Raft storage workers can outlive core shutdown briefly. Always
        // acquire the kernel lock, including on a catalog-owned clean restart.
        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            match Self::open_generation(
                path,
                session,
                Some(creator),
                Some(local),
                allow_create,
                lobby_format,
            ) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    openraft::alias::AsyncRuntimeOf::<Types>::sleep(Duration::from_millis(10)).await
                }
                result => return result,
            }
        }
    }
    fn open_generation(
        path: &Path,
        session: &[u8],
        creator: Option<&genesis::Creator>,
        local_node: Option<ReplicaId>,
        allow_create: bool,
        lobby_format: Option<lobby::LobbyFormat>,
    ) -> io::Result<Self> {
        if session.is_empty() || session.len() > 64 {
            return Err(invalid("invalid session"));
        }
        if rusqlite::version_number() < 3051003 {
            return Err(invalid("unsupported SQLite"));
        }
        let path = if path.exists() {
            path.canonicalize()?
        } else {
            path.to_owned()
        };
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".writer");
        let writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_name)?;
        writer.try_lock().map_err(io::Error::from)?;
        check_sqlite_files(&path)?;
        let mut flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE;
        if allow_create {
            flags |= rusqlite::OpenFlags::SQLITE_OPEN_CREATE;
        }
        let mut db = Connection::open_with_flags(path, flags).map_err(io::Error::other)?;
        let version = database_version(&db)?;
        let expected_version = match lobby_format {
            Some(lobby::LobbyFormat::SemanticLinks) => 4,
            Some(lobby::LobbyFormat::Resizable) => 7,
            Some(lobby::LobbyFormat::DreamReady) => 8,
            Some(lobby::LobbyFormat::Cancellable) => 9,
            Some(lobby::LobbyFormat::SeatChanges) => 6,
            Some(lobby::LobbyFormat::Seating) => 5,
            Some(lobby::LobbyFormat::Legacy) => 3,
            None if creator.is_some() => 2,
            None => 1,
        };
        if version != expected_version && !(version == 0 && allow_create) {
            return Err(invalid("unexpected game database version"));
        }
        let mode: String = db
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(io::Error::other)?;
        if mode != "wal" {
            return Err(invalid("WAL unavailable"));
        }
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")
            .map_err(io::Error::other)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        if version == 0 {
            store::create_schema(&tx, lobby_format)?;
            store::put(&tx, "session", &session)?;
            if let Some(c) = creator {
                store::put(&tx, "creator", &c)?;
                store::put(
                    &tx,
                    "local_node",
                    &local_node.ok_or(invalid("missing replica identity"))?,
                )?;
            }
            tx.pragma_update(None, "user_version", expected_version)
                .map_err(io::Error::other)?;
        }
        verify_game_identity(&tx, session, creator, local_node)?;
        tx.commit().map_err(io::Error::other)?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            _writer: Arc::new(writer),
            started: Default::default(),
            session: session.into(),
            local_node,
            lobby_format,
            bound_root: Default::default(),
            seal_wake: Default::default(),
            #[cfg(test)]
            crash: Default::default(),
        })
    }
    fn lock(&self) -> io::Result<MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| io::Error::other("database lock poisoned"))
    }
    fn profile(&self) -> &'static [u8] {
        self.lobby_format
            .map_or(wire::PROFILE, lobby::LobbyFormat::profile)
    }
}
