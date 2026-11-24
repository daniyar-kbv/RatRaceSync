use super::*;
mod join;
mod third;
use crate::wire::{fields, message};
use std::process::Command;

fn change_invite(invite: &[u8], tag: u32, replacement: &[u8]) -> Vec<u8> {
    let frame = fields(invite, &[1, 2, 3, 4]).unwrap();
    let mut genesis = fields(frame[&2], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]).unwrap();
    genesis.insert(tag, replacement);
    let body = message(&genesis.into_iter().collect::<Vec<_>>());
    let signature = key().sign(&body).to_bytes();
    let root = wire::hash(b"RatRaceSync/genesis-root/v1", &[&body, &signature]);
    message(&[(1, frame[&1]), (2, &body), (3, &signature), (4, &root)])
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receiver_checks_the_whole_profile_and_keeps_its_first_root() {
    let dir = tempfile::tempdir().unwrap();
    let p = Peers::open(dir.path()).await;
    let original = p.game.learner_invitation().unwrap();
    let source = fields(&original, &[1, 2, 3, 4]).unwrap();
    let body = fields(source[&2], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]).unwrap();
    let mut profiles = fields(body[&11], &[1, 2, 3, 4, 5, 6]).unwrap();
    profiles.insert(4, b"unsupported-content-version");
    let incompatible = change_invite(
        &original,
        11,
        &message(&profiles.into_iter().collect::<Vec<_>>()),
    );
    let mut fresh = InstallationCatalog::open(&dir.path().join("empty")).unwrap();
    assert!(
        fresh
            .open_learner(
                &p.game.session,
                &incompatible,
                b"peer",
                &p.identity,
                Config::default(),
                Bus::default()
            )
            .await
            .is_err()
    );
    assert_eq!(database_version(&fresh.db).unwrap(), 2);
    let mut p = p;
    p.finish().await;
    let substituted = change_invite(&original, 3, b"different-creator");
    let session = p.game.session.clone();
    let root = p.game.fingerprint;
    p.shutdown().await;
    drop(p);
    let mut receiver = InstallationCatalog::open(&dir.path().join("receiver")).unwrap();
    let key = SigningKey::from_bytes(&[41; 32]);
    for (session, invite) in [
        (&session[..], &substituted),
        (b"different-session" as &[u8], &original),
    ] {
        assert!(
            receiver
                .open_learner(
                    session,
                    invite,
                    b"guest",
                    &key,
                    Config::default(),
                    Bus::default()
                )
                .await
                .is_err()
        );
    }
    assert_eq!(receiver.active_pin().unwrap(), Some(root));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn catalog_edits_cannot_substitute_the_recovering_player() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::open(dir.path()).await;
    p.finish().await;
    let invite = p.game.learner_invitation().unwrap();
    let session = p.game.session.clone();
    p.shutdown().await;
    drop(p);
    let mut catalog = InstallationCatalog::open(&dir.path().join("receiver")).unwrap();
    let substitute = SigningKey::from_bytes(&[83; 32]);
    catalog
        .db
        .execute(
            "UPDATE learner SET actor=?,key=?",
            rusqlite::params![b"substitute", substitute.verifying_key().as_bytes()],
        )
        .unwrap();
    let reopened = catalog
        .open_learner(
            &session,
            &invite,
            b"substitute",
            &substitute,
            Config::default(),
            Bus::default(),
        )
        .await;
    assert!(
        reopened.is_err(),
        "substituted identity reopened a verified generation"
    );
}

struct Peers {
    bus: Bus,
    _host: InstallationCatalog,
    game: CreatorGame,
    catalog: InstallationCatalog,
    learner: Learner,
    identity: SigningKey,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clean_restart_waits_for_the_previous_generation_to_release_its_lock() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::open(dir.path()).await;
    p.finish().await;
    let id = p.learner.id();
    p.shutdown().await;
    drop(p);
    let root = dir.path().join("receiver");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(root.join(format!("learner-{id}-g1.sqlite.writer")))
        .unwrap();
    file.lock().unwrap();
    let mut catalog = InstallationCatalog::open(&root).unwrap();
    let key = SigningKey::from_bytes(&[41; 32]);
    let (reopened, ()) = tokio::join!(
        catalog.resume_learner(&key, Config::default(), Bus::default()),
        async {
            sleep(Duration::from_millis(25)).await;
            drop(file);
        }
    );
    reopened.unwrap().shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfer_resumes_after_disconnect_and_reopens_without_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::open(dir.path()).await;
    let mut sent = 0;
    let result = p
        .catalog
        .recover_learner(&mut p.learner, &p.identity, async |request: Vec<u8>| {
            sent += 1;
            if sent == 2 {
                return Err(io::Error::from(io::ErrorKind::ConnectionReset));
            }
            p.game.recovery_chunk(&request, &key()).await
        })
        .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(p.catalog.active_pin().unwrap(), None);
    let lobby = p
        .catalog
        .recover_learner(&mut p.learner, &p.identity, async |request: Vec<u8>| {
            p.game.recovery_chunk(&request, &key()).await
        })
        .await
        .unwrap();
    assert_eq!(Some(lobby.clone()), p.game.lobby);
    let id = p.learner.id();
    p.shutdown().await;
    drop(p);
    let mut catalog = InstallationCatalog::open(&dir.path().join("receiver")).unwrap();
    let key = SigningKey::from_bytes(&[41; 32]);
    let learner = catalog
        .resume_learner(&key, Config::default(), Bus::default())
        .await
        .unwrap();
    assert_eq!(id, learner.id());
    assert_eq!(catalog.recovered_lobby(&learner).unwrap(), Some(lobby));
    learner.shutdown().await.unwrap();
}
impl Peers {
    async fn open(dir: &Path) -> Self {
        Self::with_capacity(dir, 4).await
    }
    async fn with_capacity(dir: &Path, capacity: u8) -> Self {
        Self::with_profile(dir, capacity, crate::lobby::LobbyFormat::SemanticLinks).await
    }
    async fn with_profile(dir: &Path, capacity: u8, format: crate::lobby::LobbyFormat) -> Self {
        let mut host = InstallationCatalog::open(&dir.join("creator")).unwrap();
        let bus = Bus::default();
        let game = host
            .create_lobby_for_profile(
                intent(capacity),
                &key(),
                Config::default(),
                bus.clone(),
                format,
            )
            .await
            .unwrap();
        bus.0
            .lock()
            .unwrap()
            .insert(game.creator_node, game.node.raft.clone());
        let mut catalog = InstallationCatalog::open(&dir.join("receiver")).unwrap();
        if let Ok(stage) = std::env::var("LEARNER_CRASH_STAGE") {
            catalog.crash_stage = stage.parse().unwrap();
        }
        let identity = SigningKey::from_bytes(&[41; 32]);
        let invite = game.learner_invitation().unwrap();
        let learner = catalog
            .open_learner(
                &game.session,
                &invite,
                b"guest",
                &identity,
                Config::default(),
                bus.clone(),
            )
            .await
            .unwrap();
        bus.1
            .lock()
            .unwrap()
            .insert(learner.id(), (game.creator_node, learner.replication()));
        game.admit_learner(&learner.admission(&identity).unwrap())
            .await
            .unwrap();
        let peers = Self {
            bus,
            _host: host,
            game,
            catalog,
            learner,
            identity,
        };
        peers.catch_up().await;
        peers
    }
    async fn catch_up(&self) {
        let high = self
            .game
            .node
            .raft
            .metrics()
            .borrow_watched()
            .last_applied
            .map(|k| k.index);
        self.learner
            .node
            .raft
            .wait(Some(Duration::from_secs(8)))
            .applied_index_at_least(high, "replication")
            .await
            .unwrap();
    }
    async fn chunk(&mut self) -> Vec<u8> {
        let req = self.learner.request(&self.identity).unwrap();
        self.game.recovery_chunk(&req, &key()).await.unwrap()
    }
    fn accept(&mut self, response: &[u8]) -> io::Result<Option<LobbyCreation>> {
        self.catalog.accept_chunk(&mut self.learner, response)
    }
    async fn finish(&mut self) {
        for _ in 0..20 {
            let bytes = self.chunk().await;
            if let Some(lobby) = self.accept(&bytes).unwrap() {
                assert_eq!(Some(lobby), self.game.lobby);
                assert_eq!(
                    self.catalog.active_pin().unwrap(),
                    Some(self.game.fingerprint)
                );
                return;
            }
        }
        panic!("did not finish");
    }
    async fn shutdown(&self) {
        self.learner.shutdown().await.unwrap();
        self.game.node.raft.shutdown().await.unwrap();
    }
}
fn response_fields(packet: &[u8]) -> BTreeMap<u32, &[u8]> {
    fields(fields(packet, &[1, 2]).unwrap()[&1], &[1, 2, 3, 4, 5]).unwrap()
}
// A legitimate current donor still needs valid, independently verified old evidence.
fn deliver(f: &BTreeMap<u32, &[u8]>, high: &[u8], piece: &[u8]) -> Vec<u8> {
    let body = message(&[(1, f[&1]), (2, f[&2]), (3, high), (4, f[&4]), (5, piece)]);
    message(&[(1, &body), (2, &key().sign(&body).to_bytes())])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn membership_certificate_names_the_genuine_predecessor_and_effective_nonvoter() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::open(dir.path()).await;
    let invitation = p.game.learner_invitation().unwrap();
    let genesis = fields(&invitation, &[1, 2, 3, 4]).unwrap();
    let initial = fields(genesis[&2], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]).unwrap();
    loop {
        let response = p.chunk().await;
        let envelope = response_fields(&response);
        let packet = fields(envelope[&5], &[1, 2]).unwrap();
        let cert = fields(packet[&1], &[1, 2]).unwrap();
        key()
            .verifying_key()
            .verify_strict(
                cert[&1],
                &ed25519_dalek::Signature::from_slice(cert[&2]).unwrap(),
            )
            .unwrap();
        let signer = fields(cert[&1], &[1, 2, 3, 4, 5, 6]).unwrap();
        let issue = fields(signer[&2], &[1, 2, 3]).unwrap();
        let row = fields(issue[&3], &(1..=16).collect::<Vec<_>>()).unwrap();
        assert_eq!((row[&11], row[&12]), (genesis[&2], genesis[&3]));
        assert_eq!(signer[&3], ACTOR);
        assert_eq!(signer[&4], p.game.creator_node.0);
        assert_eq!(signer[&6], key().verifying_key().as_bytes());
        let source = fields(packet[&2], &[1, 2, 3]).unwrap();
        assert_eq!(row[&5], Sha256::digest(source[&1]).as_slice());
        if row[&4] == [1, 2] && row[&13] == [1] {
            let before = fields(row[&14], &[1, 2]).unwrap();
            let after = fields(row[&15], &[1, 2]).unwrap();
            assert_eq!(before[&1], initial[&7]);
            assert_eq!(before[&2], initial[&10]);
            assert_eq!(after[&1], row[&3]);
            let members = store::decode::<Members>(after[&2]).unwrap();
            assert!(members.voter_ids().eq([p.game.creator_node]));
            assert!(members.non_write_voter_ids().eq([p.learner.id()]));
            assert_eq!(row[&6], 1u64.to_be_bytes());
            assert_eq!(row[&8], 1u64.to_be_bytes());
            assert!(source[&2].is_empty() && source[&3].is_empty());
            break;
        }
        p.accept(&response).unwrap();
    }
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_cursor_rejects_conflicts_stale_challenges_and_storage_failure() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::open(dir.path()).await;
    let stale = p.chunk().await;
    let first = p.chunk().await;
    assert!(p.accept(&stale).is_err());
    let f = response_fields(&first);
    let packet = fields(f[&5], &[1, 2]).unwrap();
    let cert = fields(packet[&1], &[1, 2]).unwrap();
    let not_a_voter = message(&[(1, cert[&1]), (2, &p.identity.sign(cert[&1]).to_bytes())]);
    for bad in [
        message(&[(1, &not_a_voter), (2, packet[&2])]),
        message(&[(1, packet[&1]), (2, b"incomplete source")]),
        message(&[(1, packet[&1]), (1, packet[&1]), (2, packet[&2])]),
    ] {
        assert!(p.accept(&deliver(&f, f[&3], &bad)).is_err());
    }
    {
        let db = p.learner.node.replica.lock().unwrap();
        let pages: i64 = db.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        db.pragma_update(None, "max_page_count", pages).unwrap();
        db.execute_batch(
            "CREATE TEMP TRIGGER simulate_pressure AFTER INSERT ON historic_seal BEGIN
            INSERT INTO meta VALUES('space-test',zeroblob(4194304)); END",
        )
        .unwrap();
    }
    let err = p.accept(&first).unwrap_err();
    assert!(err.to_string().contains("full"), "{err}");
    {
        let db = p.learner.node.replica.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM historic_seal", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        db.execute_batch("DROP TRIGGER simulate_pressure; PRAGMA max_page_count=1073741823")
            .unwrap();
    }
    assert!(p.catalog.active_pin().unwrap().is_none());
    assert!(p.accept(&first).unwrap().is_none());
    assert!(p.accept(&first).unwrap().is_none());
    let next = p.chunk().await;
    assert!(p.accept(&first).is_err());
    assert!(p.accept(&next).unwrap().is_none());
    p.finish().await;
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activation_requires_the_complete_history_at_the_current_full_log_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::open(dir.path()).await;
    let old = loop {
        let chunk = p.chunk().await;
        if response_fields(&chunk)[&4] == [1] {
            break chunk;
        }
        p.accept(&chunk).unwrap();
    };
    let original: Vec<u8> = p
        .game
        .node
        .replica
        .lock()
        .unwrap()
        .query_row(
            "SELECT source FROM archive WHERE substr(source,1,1)=x'01' ORDER BY idx LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // The original command is committed again at a genuine, later K without
    // generating a second lobby, event or receipt.
    let appended = p
        .game
        .node
        .raft
        .client_write(Signed(original[1..].to_vec()))
        .await
        .unwrap();
    p.learner
        .node
        .raft
        .wait(Some(Duration::from_secs(8)))
        .applied_index_at_least(Some(appended.log_id.index), "newly committed duplicate")
        .await
        .unwrap();
    assert!(p.accept(&old).is_err());
    let tail = p.chunk().await;
    p.accept(&tail).unwrap();
    let end = p.chunk().await;
    let f = response_fields(&end);
    let mut wrong = f[&3].to_vec();
    wrong[8] ^= 1;
    assert!(p.accept(&deliver(&f, &wrong, f[&5])).is_err());
    for (table, sql) in [
        ("event", "UPDATE event SET record=x'00'"),
        ("receipt", "UPDATE receipt SET record=x'00'"),
        (
            "archive",
            "UPDATE archive SET source=x'00' WHERE idx=x'0000000000000000'",
        ),
        (
            "semantic_link",
            "DELETE FROM semantic_link WHERE ledger='receipt'",
        ),
        (
            "historic_seal",
            "DELETE FROM historic_seal WHERE idx=x'0000000000000001'",
        ),
    ] {
        {
            let db = p.learner.node.replica.lock().unwrap();
            db.execute_batch(&format!("CREATE TEMP TABLE saved AS SELECT * FROM {table}"))
                .unwrap();
            db.execute_batch(sql).unwrap();
        }
        assert!(p.accept(&end).is_err(), "{sql}");
        assert!(p.catalog.active_pin().unwrap().is_none());
        {
            let db = p.learner.node.replica.lock().unwrap();
            db.execute_batch(&format!(
                "DELETE FROM {table}; INSERT INTO {table} SELECT * FROM saved; DROP TABLE saved"
            ))
            .unwrap();
        }
    }
    assert_eq!(p.accept(&end).unwrap(), p.game.lobby);
    assert_eq!(p.accept(&end).unwrap(), p.game.lobby);
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn learner_process_worker() {
    let Ok(dir) = std::env::var("LEARNER_CRASH_DIRECTORY") else {
        return;
    };
    let mut p = Peers::open(Path::new(&dir)).await;
    p.catalog.crash_stage = std::env::var("LEARNER_CRASH_STAGE")
        .unwrap()
        .parse()
        .unwrap();
    p.finish().await;
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_boundaries_resume_the_original_learner_generation() {
    for stage in 11..=17 {
        let dir = tempfile::tempdir().unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cluster::lobby::learner::failures::learner_process_worker",
            ])
            .env("LEARNER_CRASH_DIRECTORY", dir.path())
            .env("LEARNER_CRASH_STAGE", stage.to_string())
            .status()
            .unwrap();
        assert_eq!(result.code(), Some(100 + stage));
        let catalog = Connection::open(dir.path().join("receiver/installation.sqlite")).unwrap();
        let (id, verified): ([u8; 16], bool) = catalog
            .query_row("SELECT node,verified IS NOT NULL FROM learner", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(verified, stage == 14);
        let path = dir
            .path()
            .join(format!("receiver/learner-{}-g1.sqlite", ReplicaId(id)));
        if stage == 15 {
            assert!(!path.exists());
        } else {
            let game = Connection::open(path).unwrap();
            let sealed: i64 = game
                .query_row("SELECT count(*) FROM historic_seal", [], |r| r.get(0))
                .unwrap();
            if stage == 11 || stage >= 16 {
                assert_eq!(sealed, 0);
            } else {
                assert!(sealed > 0);
            }
            drop(game);
        }
        drop(catalog);
        let mut p = Peers::open(dir.path()).await;
        assert_eq!(p.learner.id(), ReplicaId(id));
        p.finish().await;
        p.shutdown().await;
    }
}
