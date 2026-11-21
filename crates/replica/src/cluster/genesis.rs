use super::*;
use rusqlite::OptionalExtension;
mod recovery;

const CREATE: [u8; 16] = [1, 1, 1, 1, 1, 1, 0x41, 1, 0x81, 1, 1, 1, 1, 1, 1, 1];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_reopens_the_same_signed_committed_root() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let game = catalog
        .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
        .await
        .unwrap();
    let pin = game.fingerprint;
    let session = game.session.clone();
    assert_eq!(catalog.active_pin().unwrap(), Some(pin));
    assert_eq!(
        game.node.raft.current_leader().await,
        Some(game.creator_node)
    );
    game.node.raft.shutdown().await.unwrap();
    drop(game);
    let mut other = CREATE;
    other[0] = 2;
    assert!(
        catalog
            .create(other, ACTOR, &key(), Config::default(), Bus::default())
            .await
            .is_err()
    );
    assert!(
        catalog
            .create(CREATE, b"other", &key(), Config::default(), Bus::default())
            .await
            .is_err()
    );
    let retry = catalog
        .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
        .await
        .unwrap();
    assert_eq!((retry.session.clone(), retry.fingerprint), (session, pin));
    retry.node.raft.shutdown().await.unwrap();
}

fn catalog_row(dir: &Path) -> (Vec<u8>, ReplicaId, Option<[u8; 32]>) {
    Connection::open(dir.join("installation.sqlite"))
        .unwrap()
        .query_row("SELECT session,node,pin FROM participation", [], |row| {
            Ok((row.get(0)?, ReplicaId(row.get(1)?), row.get(2)?))
        })
        .unwrap()
}
fn game_file(dir: &Path, id: ReplicaId) -> std::path::PathBuf {
    dir.join(format!("game-{id}-g1.sqlite"))
}

fn interrupted(dir: &Path, stage: u8) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cluster::genesis::interrupted_create_worker"])
        .env("GENESIS_FIXTURE_DIRECTORY", dir)
        .env("GENESIS_FIXTURE_STAGE", stage.to_string())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(90 + i32::from(stage)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_create_worker() {
    let Some(dir) = std::env::var_os("GENESIS_FIXTURE_DIRECTORY") else {
        return;
    };
    let mut catalog = InstallationCatalog::open(Path::new(&dir)).unwrap();
    catalog.crash_stage = std::env::var("GENESIS_FIXTURE_STAGE")
        .unwrap()
        .parse()
        .unwrap();
    let _ = catalog
        .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
        .await
        .unwrap();
    panic!("missed process interruption");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_durable_create_boundary_recovers_one_game_and_one_original_root() {
    for stage in 1..=8 {
        let dir = tempfile::tempdir().unwrap();
        interrupted(dir.path(), stage);
        let (session, id, original_pin) = catalog_row(dir.path());
        assert_eq!(original_pin.is_some(), stage == 5);
        let path = game_file(dir.path(), id);
        let before = if stage >= 2 {
            let db = Connection::open(&path).unwrap();
            let proof: Option<Vec<u8>> = db
                .query_row(
                    "SELECT value FROM meta WHERE name='signed_genesis'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .unwrap();
            assert_eq!(proof.is_some(), matches!(stage, 4 | 5));
            assert_eq!(
                store::meta::<LogId>(&db, "applied").unwrap().is_some(),
                matches!(stage, 3..=5 | 7)
            );
            proof
        } else {
            assert!(!path.exists());
            None
        };
        let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
        if stage != 5 {
            assert!(
                catalog
                    .open_active(Config::default(), Bus::default())
                    .await
                    .is_err()
            );
        }
        let game = catalog
            .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
            .await
            .unwrap();
        assert_eq!(game.session, session);
        assert_eq!(game.creator_node, id);
        assert_eq!(catalog.active_pin().unwrap(), Some(game.fingerprint));
        {
            let db = game.node.replica.lock().unwrap();
            let cert: Vec<u8> = db
                .query_row(
                    "SELECT value FROM meta WHERE name='signed_genesis'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            if let Some(before) = before {
                assert_eq!(cert, before)
            }
            if let Some(pin) = original_pin {
                assert_eq!(game.fingerprint, pin)
            }
            // Decode persisted original signature independently of root issuance.
            let (body, stored_root, sig): (Vec<u8>, [u8; 32], Vec<u8>) =
                store::decode(&cert).unwrap();
            assert_eq!(stored_root, game.fingerprint);
            assert_eq!(
                wire::hash(b"RatRaceSync/genesis-root/v1", &[&body, &sig]),
                stored_root
            );
            key()
                .verifying_key()
                .verify_strict(&body, &ed25519_dalek::Signature::from_slice(&sig).unwrap())
                .unwrap();
            let f = wire::fields(&body, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]).unwrap();
            assert_eq!(f[&2], session);
            assert_eq!(f[&3], ACTOR);
            assert_eq!(f[&4], key().verifying_key().as_bytes());
            assert_eq!(f[&5], id.0);
            let (g, digest): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT log_id,digest FROM archive WHERE idx=?",
                    [0u64.to_be_bytes()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(f[&7], g);
            assert_eq!(f[&8], digest);
            assert_eq!(
                db.query_row("SELECT count(*) FROM receipt", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        game.node.raft.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_catalog_row_cannot_create_over_an_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let game = catalog
        .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
        .await
        .unwrap();
    game.node.raft.shutdown().await.unwrap();
    drop(game);
    drop(catalog);
    Connection::open(dir.path().join("installation.sqlite"))
        .unwrap()
        .execute("DELETE FROM participation", [])
        .unwrap();
    if let Ok(mut empty) = InstallationCatalog::open(dir.path()) {
        assert!(
            empty
                .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
                .await
                .is_err()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_valid_same_session_substitute_cannot_replace_the_installed_pin() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(first.path()).unwrap();
    let original = catalog
        .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
        .await
        .unwrap();
    let live_retry = catalog
        .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&original.node, &live_retry.node));
    drop(live_retry);
    let session = original.session.clone();
    let pin = original.fingerprint;
    let original_path = game_file(first.path(), original.creator_node);
    original.node.raft.shutdown().await.unwrap();
    drop(original);
    // Stage an independent, legitimate Create in a separate installation using the same session ID.
    interrupted(second.path(), 1);
    Connection::open(second.path().join("installation.sqlite"))
        .unwrap()
        .execute("UPDATE participation SET session=?", [&session])
        .unwrap();
    let mut other = InstallationCatalog::open(second.path()).unwrap();
    let substitute = other
        .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
        .await
        .unwrap();
    assert_eq!(substitute.session, session);
    assert_ne!(substitute.fingerprint, pin);
    let alternative_pin = substitute.fingerprint;
    let alternative_path = game_file(second.path(), substitute.creator_node);
    substitute.node.raft.shutdown().await.unwrap();
    drop(substitute);
    // Wrong independent pin with an otherwise fully valid game database.
    let local = Connection::open(first.path().join("installation.sqlite")).unwrap();
    local
        .execute("UPDATE participation SET pin=?", [alternative_pin])
        .unwrap();
    assert!(
        catalog
            .open_active(Config::default(), Bus::default())
            .await
            .is_err()
    );
    assert_eq!(catalog.active_pin().unwrap(), Some(alternative_pin));
    local
        .execute("UPDATE participation SET pin=?", [pin])
        .unwrap();
    assert!(Replica::open(&original_path, &session).is_err());
    // A different genuinely signed file cannot be activated by filename replacement.
    std::fs::copy(alternative_path, &original_path).unwrap();
    assert!(
        catalog
            .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
            .await
            .is_err()
    );
    assert_eq!(catalog.active_pin().unwrap(), Some(pin));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_game_rejects_damaged_or_missing_evidence_without_resigning() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let game = catalog
        .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
        .await
        .unwrap();
    let pin = game.fingerprint;
    let path = game_file(dir.path(), game.creator_node);
    game.node.raft.shutdown().await.unwrap();
    drop(game);
    let db = Connection::open(&path).unwrap();
    let cert: Vec<u8> = db
        .query_row(
            "SELECT value FROM meta WHERE name='signed_genesis'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut altered = cert.clone();
    *altered.last_mut().unwrap() ^= 1;
    db.execute(
        "UPDATE meta SET value=? WHERE name='signed_genesis'",
        [altered],
    )
    .unwrap();
    assert!(
        catalog
            .open_active(Config::default(), Bus::default())
            .await
            .is_err()
    );
    db.execute("DELETE FROM meta WHERE name='signed_genesis'", [])
        .unwrap();
    assert!(
        catalog
            .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
            .await
            .is_err()
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM meta WHERE name='signed_genesis'",
            [],
            |r| r.get::<_, i32>(0)
        )
        .unwrap(),
        0
    );
    db.execute("INSERT INTO meta VALUES('signed_genesis',?)", [cert])
        .unwrap();
    let reopened = catalog
        .open_active(Config::default(), Bus::default())
        .await
        .unwrap();
    assert_eq!(reopened.fingerprint, pin);
    reopened.node.raft.shutdown().await.unwrap();
    drop(reopened);
    drop(db);
    std::fs::rename(&path, path.with_extension("saved")).unwrap();
    assert!(
        catalog
            .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
            .await
            .is_err()
    );
    assert!(!path.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_game_with_a_lost_local_identity_stays_pending() {
    let dir = tempfile::tempdir().unwrap();
    interrupted(dir.path(), 3);
    let (_, id, pin) = catalog_row(dir.path());
    assert!(pin.is_none());
    let db = Connection::open(game_file(dir.path(), id)).unwrap();
    assert_eq!(
        db.execute("DELETE FROM meta WHERE name='local_node'", [])
            .unwrap(),
        1
    );
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    assert!(
        catalog
            .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
            .await
            .is_err()
    );
    assert_eq!(catalog.active_pin().unwrap(), None);
}
