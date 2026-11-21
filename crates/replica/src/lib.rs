//! Fixed-membership command application.
mod application;
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
        let mut db = Connection::open(path).map_err(io::Error::other)?;
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
        if version == 0 {
            tx.execute_batch(include_str!("schema.sql"))
                .map_err(io::Error::other)?;
            store::put(&tx, "session", &session)?;
            tx.execute_batch("PRAGMA user_version=1")
                .map_err(io::Error::other)?;
        } else if version != 1
            || store::meta::<Vec<u8>>(&tx, "session")?.as_deref() != Some(session)
        {
            return Err(invalid("unexpected database identity or version"));
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
