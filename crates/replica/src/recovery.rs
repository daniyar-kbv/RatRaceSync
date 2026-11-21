//! Verify the retained fixed-membership prefix before serving a reopened game.
use crate::{Entry, LogId, Replica, application::historical_income, invalid, store};
use rusqlite::{Connection, params};
use std::io;

impl Replica {
    pub(crate) fn verify_replay(&self, db: &Connection) -> io::Result<()> {
        let last = store::meta::<LogId>(db, "applied")?;
        // This package retains the complete protocol log. Archive-only recovery
        // requires separate proof of historical membership and commit authority.
        if store::meta::<LogId>(db, "purged")?.is_some() {
            return Err(invalid("full retained log required for local replay"));
        }
        // An unnamed SQLite file is temporary, can spill to disk, and is deleted
        // on close. No verification write touches the game database.
        let mut scratch = Connection::open("").map_err(io::Error::other)?;
        scratch
            .execute_batch(include_str!("schema.sql"))
            .map_err(io::Error::other)?;
        let replay = scratch.transaction().map_err(io::Error::other)?;
        seed_opening_state(db, &replay)?;
        if let Some(k) = last {
            let mut statement = db
                .prepare("SELECT idx,entry FROM raft_log WHERE idx<=? ORDER BY idx")
                .map_err(io::Error::other)?;
            let mut rows = statement
                .query([k.index.to_be_bytes()])
                .map_err(io::Error::other)?;
            while let Some(row) = rows.next().map_err(io::Error::other)? {
                let idx: [u8; 8] = row.get(0).map_err(io::Error::other)?;
                let entry: Entry = store::decode(
                    row.get_ref(1)
                        .map_err(io::Error::other)?
                        .as_blob()
                        .map_err(io::Error::other)?,
                )?;
                if entry.log_id.index.to_be_bytes() != idx {
                    return Err(invalid("raft log index mismatch"));
                }
                self.apply_in_transaction(&replay, &entry)?;
            }
        }
        for sql in [
            "SELECT * FROM archive ORDER BY idx",
            "SELECT * FROM event ORDER BY seq",
            "SELECT * FROM receipt ORDER BY seq",
            "SELECT * FROM participant ORDER BY actor",
            "SELECT * FROM certificate ORDER BY actor,position",
            "SELECT name,value FROM meta WHERE name IN ('applied','membership') ORDER BY name",
        ] {
            if !same_rows(db, &replay, sql).map_err(io::Error::other)? {
                return Err(invalid(
                    "persisted history or state differs from committed replay",
                ));
            }
        }
        Ok(())
    }
}

// The v1 schema persisted opening cash and units. For a player who has
// redeemed, the first immutable applied event also records the prior income.
fn seed_opening_state(source: &Connection, target: &Connection) -> io::Result<()> {
    if let Some(open) = store::meta::<bool>(source, "finance_open")? {
        store::put(target, "finance_open", &open)?;
    }
    let mut statement = source
        .prepare("SELECT actor,key,node,opening_cash FROM participant")
        .map_err(io::Error::other)?;
    let mut rows = statement.query([]).map_err(io::Error::other)?;
    while let Some(row) = rows.next().map_err(io::Error::other)? {
        let actor: Vec<u8> = row.get(0).map_err(io::Error::other)?;
        let key: Vec<u8> = row.get(1).map_err(io::Error::other)?;
        let node: Vec<u8> = row.get(2).map_err(io::Error::other)?;
        let cash: String = row.get(3).map_err(io::Error::other)?;
        let monthly = historical_income(source, &actor, 0)?;
        target
            .execute(
                "INSERT INTO participant VALUES(?1,?2,?3,?4,?4,?5)",
                params![actor, key, node, cash, monthly],
            )
            .map_err(io::Error::other)?;
    }
    let mut lots = source
        .prepare("SELECT actor,position,principal,opening_units FROM certificate")
        .map_err(io::Error::other)?;
    let mut rows = lots.query([]).map_err(io::Error::other)?;
    while let Some(row) = rows.next().map_err(io::Error::other)? {
        let values = row_values(row, 4).map_err(io::Error::other)?;
        target
            .execute(
                "INSERT INTO certificate VALUES(?1,?2,?3,?4,?4)",
                rusqlite::params_from_iter(values),
            )
            .map_err(io::Error::other)?;
    }
    Ok(())
}

fn row_values(
    row: &rusqlite::Row<'_>,
    columns: usize,
) -> rusqlite::Result<Vec<rusqlite::types::Value>> {
    (0..columns).map(|i| row.get(i)).collect()
}

fn same_rows(actual: &Connection, replayed: &Connection, sql: &str) -> rusqlite::Result<bool> {
    let mut actual = actual.prepare(sql)?;
    let mut replayed = replayed.prepare(sql)?;
    let columns = actual.column_count();
    let mut left = actual.query([])?;
    let mut right = replayed.query([])?;
    loop {
        match (left.next()?, right.next()?) {
            (Some(a), Some(b)) => {
                for i in 0..columns {
                    if a.get_ref(i)? != b.get_ref(i)? {
                        return Ok(false);
                    }
                }
            }
            (None, None) => return Ok(true),
            _ => return Ok(false),
        }
    }
}
