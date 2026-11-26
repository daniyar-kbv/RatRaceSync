use super::*;
use crate::seating::departure::confirmation::{Evidence, LOCAL};

impl InstallationCatalog {
    /// Release only the departing installation, using confirmations by both successor voters.
    pub fn finish_lobby_leave(
        &mut self,
        learner: &Learner,
        command: &Signed,
        confirmations: [&[u8]; 2],
    ) -> io::Result<Vec<u8>> {
        if command.0.len() > 2048 || confirmations.iter().any(|p| p.len() > 8192) {
            return Err(invalid("oversized departure proof"));
        }
        let proof = Evidence {
            command: command.clone(),
            confirmations: confirmations.map(<[u8]>::to_vec),
        };
        self.reconcile_departure(&learner.node.replica, Some(proof))
    }
    pub(super) fn reconcile_departure(
        &mut self,
        r: &Replica,
        supplied: Option<Evidence>,
    ) -> io::Result<Vec<u8>> {
        let game = r.lock()?;
        r.require_lobby_genesis(&game)?;
        r.verify_replay(&game)?;
        let id = r.local_node.ok_or(invalid("missing local node"))?;
        let pin = r.bound_root.get().ok_or(invalid("missing root pin"))?;
        let path = self.directory.join(format!("learner-{id}-g1.sqlite"));
        if game.path().map(Path::new) != Some(&path) {
            return Err(invalid("wrong installation generation"));
        }
        let prior = store::meta::<Evidence>(&game, LOCAL)?;
        let evidence = supplied
            .as_ref()
            .or(prior.as_ref())
            .ok_or(invalid("missing departure evidence"))?;
        let receipt = evidence.verify(&game, &r.session, pin, id)?;
        if let Some(prior) = &prior
            && prior.verify(&game, &r.session, pin, id)? != receipt
        {
            return Err(invalid("different confirmed departure"));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(io::Error::other)?;
        let version = database_version(&tx)?;
        if version == 5 {
            let old: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT receipt FROM departed_game WHERE session=? AND node=? AND pin=?",
                    params![r.session, id.0, pin],
                    |row| row.get(0),
                )
                .optional()
                .map_err(io::Error::other)?;
            if let Some(old) = old {
                if receipt != old {
                    return Err(invalid("departure receipt differs from catalog"));
                }
                return Ok(old);
            }
        }
        crate::learner::check_cancellation_binding(&tx, r, &game, pin)?;
        if prior.is_none() {
            store::put(&game, LOCAL, evidence)?;
        }

        cancellation::ensure_closed_schema(&tx, version)?;
        if version < 5 {
            tx.execute_batch("CREATE TABLE departed_game(session BLOB PRIMARY KEY,node BLOB UNIQUE NOT NULL CHECK(length(node)=16),pin BLOB NOT NULL CHECK(length(pin)=32),receipt BLOB NOT NULL) STRICT; PRAGMA user_version=5").map_err(io::Error::other)?;
        }
        tx.execute(
            "INSERT INTO departed_game VALUES(?,?,?,?)",
            params![r.session, id.0, pin, receipt],
        )
        .map_err(io::Error::other)?;
        if tx
            .execute(
                "DELETE FROM learner WHERE slot=1 AND node=? AND session=?",
                params![id.0, r.session],
            )
            .map_err(io::Error::other)?
            != 1
        {
            return Err(invalid("departure slot changed"));
        }
        tx.commit().map_err(io::Error::other)?;
        Ok(receipt)
    }

    /// Recover a locally confirmed Leave without contacting the former coordinator.
    pub fn departure_receipt(&self, session: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if database_version(&self.db)? != 5 {
            return Ok(None);
        }
        let row = self
            .db
            .query_row(
                "SELECT node,pin,receipt FROM departed_game WHERE session=?",
                [session],
                |row| {
                    Ok((
                        ReplicaId(row.get(0)?),
                        row.get::<_, [u8; 32]>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(io::Error::other)?;
        let Some((id, pin, receipt)) = row else {
            return Ok(None);
        };
        let path = self.directory.join(format!("learner-{id}-g1.sqlite"));
        if path.is_symlink() {
            return Err(invalid("invalid departure generation path"));
        }
        let mut db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(io::Error::other)?;
        let tx = db.transaction().map_err(io::Error::other)?;
        let creator = store::meta::<Creator>(&tx, "creator")?.ok_or(invalid("missing creator"))?;
        verify_game_identity(&tx, session, Some(&creator), Some(id))?;
        let genesis = store::meta::<genesis::SignedGenesis>(&tx, "signed_genesis")?
            .ok_or(invalid("missing signed root"))?;
        genesis.verify(&genesis.body, &creator)?;
        let evidence =
            store::meta::<Evidence>(&tx, LOCAL)?.ok_or(invalid("missing local departure proof"))?;
        if genesis.fingerprint != pin || evidence.verify(&tx, session, &pin, id)? != receipt {
            return Err(invalid("departure proof differs from catalog"));
        }
        Ok(Some(receipt))
    }
}
