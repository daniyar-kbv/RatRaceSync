//! The creator attests to the original membership only after Raft applies it.
use crate::{store, wire, *};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::OptionalExtension;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Creator {
    pub actor: Vec<u8>,
    pub key: [u8; 32],
    pub node: ReplicaId,
}

#[derive(Serialize, Deserialize)]
struct SignedGenesis {
    body: Vec<u8>,
    fingerprint: [u8; 32],
    signature: Vec<u8>,
}

fn fingerprint(body: &[u8], signature: &[u8]) -> [u8; 32] {
    wire::hash(b"RatRaceSync/genesis-root/v1", &[body, signature])
}

// A pending Create can legitimately have an empty log or only the initial
// term-zero membership. Later log terms require a surviving durable vote.
fn verify_raft_lineage(db: &Connection) -> io::Result<()> {
    let last: Option<Vec<u8>> = db
        .query_row(
            "SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(io::Error::other)?;
    if let Some(bytes) = last {
        let term = store::decode::<Entry>(&bytes)?.log_id.leader_id.term;
        let vote = store::meta::<Vote>(db, "vote")?;
        if term > vote.map_or(0, |v| v.leader_id.term) {
            return Err(invalid("retained log exceeds the durable vote term"));
        }
    }
    for boundary in [
        store::meta::<Option<LogId>>(db, "committed")?.flatten(),
        store::meta::<LogId>(db, "applied")?,
    ]
    .into_iter()
    .flatten()
    {
        let entry: Vec<u8> = db
            .query_row(
                "SELECT entry FROM raft_log WHERE idx=?",
                [boundary.index.to_be_bytes()],
                |row| row.get(0),
            )
            .map_err(io::Error::other)?;
        if store::decode::<Entry>(&entry)?.log_id != boundary {
            return Err(invalid("durable boundary disagrees with retained log"));
        }
    }
    Ok(())
}

impl Replica {
    fn genesis_body(&self, db: &Connection, creator: &Creator) -> io::Result<Vec<u8>> {
        let k = store::meta::<LogId>(db, "genesis_log")?
            .ok_or(invalid("initial membership has not applied"))?;
        verify_game_identity(db, &self.session, Some(creator))?;
        let committed = store::meta::<Option<LogId>>(db, "committed")?
            .flatten()
            .ok_or(invalid("missing commit boundary"))?;
        let applied =
            store::meta::<LogId>(db, "applied")?.ok_or(invalid("missing apply boundary"))?;
        for boundary in [committed, applied] {
            if boundary.index < k.index || (boundary.index == k.index && boundary != k) {
                return Err(invalid("genesis is outside committed history"));
            }
        }
        let (entry, log_id, source, digest): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT l.entry,a.log_id,a.source,a.digest
                 FROM raft_log l JOIN archive a USING(idx) WHERE idx=?",
                [k.index.to_be_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(io::Error::other)?;
        let entry: Entry = store::decode(&entry)?;
        let members = entry
            .payload
            .check_members()?
            .ok_or(invalid("missing original genesis membership"))?;
        if k.index != 0
            || members.get_joint_config().len() != 1
            || !members.voter_ids().eq([creator.node])
            || members.non_write_voter_ids().next().is_some()
        {
            return Err(invalid("not the creator-only initialization"));
        }
        if entry.log_id != k
            || log_id != log_key(k)
            || entry.payload.bytes != source
            || Sha256::digest(&source).as_slice() != digest
        {
            return Err(invalid(
                "genesis source disagrees with the committed membership",
            ));
        }
        // A versioned profile manifest binds the Classic rules, content, reducer,
        // money and identity encodings without depending on platform metadata.
        let profiles = wire::message(&[
            (1, b"protocol-1"),
            (2, b"opaque-id-1"),
            (3, b"Classic101-rules-1"),
            (4, b"Classic101-content-1"),
            (5, wire::PROFILE),
            (6, b"whole-usd-128-decimal-digits-1"),
        ]);
        Ok(wire::message(&[
            (1, b"RatRaceSync/genesis/v1"),
            (2, &self.session),
            (3, &creator.actor),
            (4, &creator.key),
            (5, &creator.node.0),
            (6, &1u64.to_be_bytes()),
            (7, &log_id),
            (8, &digest),
            (9, b"membership-source-1"),
            (10, &store::encode(&members)?),
            (11, &profiles),
        ]))
    }

    pub(crate) fn root(
        &self,
        creator: &Creator,
        sign_if_absent: Option<&SigningKey>,
    ) -> io::Result<Option<[u8; 32]>> {
        let mut db = self.lock()?;
        let tx = db.transaction().map_err(io::Error::other)?;
        verify_raft_lineage(&tx)?;
        let original = store::meta::<SignedGenesis>(&tx, "signed_genesis")?;
        if original.is_none() && sign_if_absent.is_none() {
            return Ok(None);
        }
        let expected = self.genesis_body(&tx, creator)?;
        let proof = match original {
            Some(proof) => proof,
            None => {
                let key = sign_if_absent.ok_or(invalid("original genesis certificate missing"))?;
                let signature = key.sign(&expected).to_bytes().to_vec();
                let proof = SignedGenesis {
                    fingerprint: fingerprint(&expected, &signature),
                    signature,
                    body: expected.clone(),
                };
                store::put(&tx, "signed_genesis", &proof)?;
                proof
            }
        };
        if proof.body != expected {
            return Err(invalid("signed genesis body mismatch"));
        }
        VerifyingKey::from_bytes(&creator.key)
            .map_err(io::Error::other)?
            .verify_strict(
                &proof.body,
                &Signature::from_slice(&proof.signature).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
        if fingerprint(&proof.body, &proof.signature) != proof.fingerprint {
            return Err(invalid("stored genesis fingerprint mismatch"));
        }
        tx.commit().map_err(io::Error::other)?;
        Ok(Some(proof.fingerprint))
    }
}
