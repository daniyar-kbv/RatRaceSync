//! Fixed-membership command application.
mod application;
mod catalog;
mod genesis;
pub use catalog::{CreatorGame, InstallationCatalog};
mod node;
mod recovery;
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
#[derive(Clone)]
pub struct Replica {
    db: Arc<Mutex<Connection>>,
    _writer: Arc<std::fs::File>,
    started: Arc<std::sync::atomic::AtomicBool>,
    session: Vec<u8>,
    #[cfg(test)]
    crash: Arc<std::sync::atomic::AtomicU8>,
}
impl Replica {
    pub fn open(path: &Path, session: &[u8]) -> io::Result<Self> {
        Self::open_game(path, session, None, true)
    }
    fn open_game(
        path: &Path,
        session: &[u8],
        creator: Option<&genesis::Creator>,
        allow_create: bool,
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
        writer.try_lock().map_err(io::Error::other)?;
        let mut flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE;
        if allow_create {
            flags |= rusqlite::OpenFlags::SQLITE_OPEN_CREATE;
        }
        let mut db = Connection::open_with_flags(path, flags).map_err(io::Error::other)?;
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
        let version: i32 = tx
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(io::Error::other)?;
        let expected_version = if creator.is_some() { 2 } else { 1 };
        if version == 0 && allow_create {
            tx.execute_batch(include_str!("schema.sql"))
                .map_err(io::Error::other)?;
            store::put(&tx, "session", &session)?;
            if let Some(c) = creator {
                store::put(&tx, "creator", &c)?;
                store::put(&tx, "local_node", &c.node)?;
            }
            tx.pragma_update(None, "user_version", expected_version)
                .map_err(io::Error::other)?;
        } else if version != expected_version
            || store::meta::<genesis::Creator>(&tx, "creator")?.as_ref() != creator
            || store::meta::<Vec<u8>>(&tx, "session")?.as_deref() != Some(session)
        {
            return Err(invalid("unexpected database identity or version"));
        }
        if let Some(c) = creator
            && store::meta::<ReplicaId>(&tx, "local_node")? != Some(c.node)
        {
            return Err(invalid("original creator replica binding missing"));
        }
        tx.commit().map_err(io::Error::other)?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            _writer: Arc::new(writer),
            started: Default::default(),
            session: session.into(),
            #[cfg(test)]
            crash: Default::default(),
        })
    }
    fn lock(&self) -> io::Result<MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| io::Error::other("database lock poisoned"))
    }
}
