use super::*;
use openraft::{
    LogState, RaftLogReader,
    storage::{IOFlushed, RaftLogStorage},
};
use rusqlite::OptionalExtension;
use std::{
    fmt::Debug,
    ops::{Bound, RangeBounds},
};

pub(crate) fn encode<T: serde::Serialize>(v: &T) -> io::Result<Vec<u8>> {
    postcard::to_allocvec(v).map_err(io::Error::other)
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(v: &[u8]) -> io::Result<T> {
    let (value, rest) = postcard::take_from_bytes(v).map_err(io::Error::other)?;
    if !rest.is_empty() {
        return Err(invalid("trailing stored data"));
    }
    Ok(value)
}
pub(crate) fn meta<T: serde::de::DeserializeOwned>(
    db: &Connection,
    key: &str,
) -> io::Result<Option<T>> {
    db.query_row("SELECT value FROM meta WHERE name=?", [key], |r| {
        r.get::<_, Vec<u8>>(0)
    })
    .optional()
    .map_err(io::Error::other)?
    .map(|v| decode(&v))
    .transpose()
}
pub(crate) fn put<T: serde::Serialize>(db: &Connection, key: &str, v: &T) -> io::Result<()> {
    db.execute(
        "INSERT INTO meta VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
        rusqlite::params![key, encode(v)?],
    )
    .map_err(io::Error::other)?;
    Ok(())
}
impl RaftLogReader<Types> for Replica {
    async fn read_vote(&mut self) -> io::Result<Option<Vote>> {
        meta(&*self.lock()?, "vote")
    }
    async fn try_get_log_entries<R: RangeBounds<u64> + Clone + Debug>(
        &mut self,
        r: R,
    ) -> io::Result<Vec<Entry>> {
        let low = match r.start_bound() {
            Bound::Included(k) => *k,
            Bound::Excluded(k) => match k.checked_add(1) {
                Some(n) => n,
                None => return Ok(vec![]),
            },
            Bound::Unbounded => 0,
        };
        let high = match r.end_bound() {
            Bound::Included(k) => *k,
            Bound::Excluded(k) => match k.checked_sub(1) {
                Some(n) => n,
                None => return Ok(vec![]),
            },
            Bound::Unbounded => u64::MAX,
        };
        let db = self.lock()?;
        let mut stmt = db
            .prepare("SELECT entry FROM raft_log WHERE idx BETWEEN ? AND ? ORDER BY idx")
            .map_err(io::Error::other)?;
        stmt.query_map([low.to_be_bytes(), high.to_be_bytes()], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .map_err(io::Error::other)?
        .map(|v| decode(&v.map_err(io::Error::other)?))
        .collect()
    }
}
impl RaftLogStorage<Types> for Replica {
    type LogReader = Self;
    async fn get_log_reader(&mut self) -> Self {
        self.clone()
    }
    async fn get_log_state(&mut self) -> io::Result<LogState<Types>> {
        let db = self.lock()?;
        let last = db
            .query_row(
                "SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(io::Error::other)?;
        let purged = meta(&db, "purged")?;
        Ok(LogState {
            last_log_id: last
                .map(|v| decode::<Entry>(&v).map(|e| e.log_id))
                .transpose()?
                .or(purged),
            last_purged_log_id: purged,
        })
    }
    async fn save_vote(&mut self, v: &Vote) -> io::Result<()> {
        put(&*self.lock()?, "vote", v)
    }
    async fn save_committed(&mut self, v: Option<LogId>) -> io::Result<()> {
        put(&*self.lock()?, "committed", &v)
    }
    async fn read_committed(&mut self) -> io::Result<Option<LogId>> {
        Ok(meta::<Option<LogId>>(&*self.lock()?, "committed")?.flatten())
    }
    async fn append<I: IntoIterator<Item = Entry>>(
        &mut self,
        es: I,
        cb: IOFlushed<Types>,
    ) -> io::Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        for e in es {
            tx.execute(
                "INSERT INTO raft_log VALUES(?,?)",
                rusqlite::params![e.log_id.index.to_be_bytes(), encode(&e)?],
            )
            .map_err(io::Error::other)?;
        }
        tx.commit().map_err(io::Error::other)?;
        cb.io_completed(Ok(()));
        Ok(())
    }
    async fn truncate_after(&mut self, id: Option<LogId>) -> io::Result<()> {
        let db = self.lock()?;
        for protected in [
            meta::<LogId>(&db, "applied")?,
            meta::<Option<LogId>>(&db, "committed")?.flatten(),
        ]
        .into_iter()
        .flatten()
        {
            if id.is_none_or(|keep| {
                keep.index < protected.index || (keep.index == protected.index && keep != protected)
            }) {
                return Err(invalid("truncation crosses a durable log boundary"));
            }
        }
        if let Some(keep) = id {
            let bytes: Vec<u8> = db
                .query_row(
                    "SELECT entry FROM raft_log WHERE idx=?",
                    [keep.index.to_be_bytes()],
                    |r| r.get(0),
                )
                .map_err(io::Error::other)?;
            if decode::<Entry>(&bytes)?.log_id != keep {
                return Err(invalid("truncation predecessor mismatch"));
            }
        }
        db.execute(
            "DELETE FROM raft_log WHERE ?1 IS NULL OR idx>?1",
            [id.map(|v| v.index.to_be_bytes())],
        )
        .map_err(io::Error::other)?;
        Ok(())
    }
    async fn purge(&mut self, _: LogId) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "log purge requires a verified snapshot and recoverable original history",
        ))
    }
}
/// Used for both a pristine generation and its independent replay database.
pub(crate) fn create_schema(db: &Connection, lobby_enabled: bool) -> io::Result<()> {
    let event_table = if lobby_enabled {
        "CREATE TABLE event (seq INTEGER PRIMARY KEY, actor BLOB NOT NULL, position BLOB,
         cash_after TEXT, units_after TEXT, record BLOB NOT NULL, digest BLOB NOT NULL, tip BLOB NOT NULL,
         CHECK ((position IS NULL) = (cash_after IS NULL) AND (position IS NULL) = (units_after IS NULL))) STRICT"
    } else {
        "CREATE TABLE event (seq INTEGER PRIMARY KEY, actor BLOB NOT NULL, position BLOB NOT NULL,
         cash_after TEXT NOT NULL, units_after TEXT NOT NULL, record BLOB NOT NULL, digest BLOB NOT NULL, tip BLOB NOT NULL) STRICT"
    };
    db.execute_batch(event_table).map_err(io::Error::other)?;
    db.execute_batch(include_str!("schema.sql"))
        .map_err(io::Error::other)
}
