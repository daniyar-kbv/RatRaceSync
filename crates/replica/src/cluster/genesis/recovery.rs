use super::*;

async fn create_game(catalog: &mut InstallationCatalog) -> io::Result<CreatorGame> {
    catalog
        .create(CREATE, ACTOR, &key(), Config::default(), Bus::default())
        .await
}

async fn release_generation(game: CreatorGame) {
    let writer = Arc::downgrade(&game.node.replica._writer);
    drop(game);
    // OpenRaft joins core/tick on shutdown. Its storage worker releases the
    // generation lock separately after the last handle is gone.
    timeout(Duration::from_secs(2), async {
        while writer.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn live_retry_checks_the_catalog_session_and_node_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let game = create_game(&mut catalog).await.unwrap();
    let db = Connection::open(dir.path().join("installation.sqlite")).unwrap();
    let mut other_session = game.session.clone();
    other_session[0] ^= 1;
    db.execute("UPDATE participation SET session=?", [other_session])
        .unwrap();
    assert!(
        create_game(&mut catalog).await.is_err(),
        "returned a different session with the original pin"
    );
    db.execute("UPDATE participation SET session=?", [&game.session])
        .unwrap();
    let generation = Connection::open(game_file(dir.path(), game.creator_node)).unwrap();
    store::put(&generation, "session", &b"different session".to_vec()).unwrap();
    assert!(
        create_game(&mut catalog).await.is_err(),
        "returned a live game with a different stored session"
    );
    store::put(&generation, "session", &game.session).unwrap();
    game.node.raft.shutdown().await.unwrap();
    assert!(
        catalog
            .open_active(Config::default(), Bus::default())
            .await
            .is_err(),
        "returned a stopped node"
    );
    let pin = game.fingerprint;
    release_generation(game).await;
    let reopened = catalog
        .open_active(Config::default(), Bus::default())
        .await
        .unwrap();
    assert_eq!(reopened.fingerprint, pin);
    reopened.node.raft.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_damaged_pending_signature_is_rejected_before_raft_resumes() {
    let dir = tempfile::tempdir().unwrap();
    interrupted(dir.path(), 4);
    let (_, id, pin) = catalog_row(dir.path());
    assert!(pin.is_none());
    let db = Connection::open(game_file(dir.path(), id)).unwrap();
    let before: i64 = db
        .query_row("SELECT count(*) FROM raft_log", [], |row| row.get(0))
        .unwrap();
    let mut cert: Vec<u8> = db
        .query_row(
            "SELECT value FROM meta WHERE name='signed_genesis'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    *cert.last_mut().unwrap() ^= 1;
    db.execute(
        "UPDATE meta SET value=? WHERE name='signed_genesis'",
        [cert],
    )
    .unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    assert!(create_game(&mut catalog).await.is_err());
    assert_eq!(catalog.active_pin().unwrap(), None);
    let after: i64 = db
        .query_row("SELECT count(*) FROM raft_log", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        before, after,
        "suspect generation participated in a new term"
    );
}

#[tokio::test]
async fn signed_root_requires_original_vote_and_a_matching_commit_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let game = create_game(&mut catalog).await.unwrap();
    game.node.raft.shutdown().await.unwrap();
    let db = Connection::open(game_file(dir.path(), game.creator_node)).unwrap();
    let pin = game.fingerprint;
    release_generation(game).await;
    let committed = store::meta::<Option<LogId>>(&db, "committed")
        .unwrap()
        .flatten()
        .unwrap();
    assert!(committed.index > 0);
    let mut wrong = committed;
    wrong.leader_id.node_id.0[0] ^= 1;
    store::put(&db, "committed", &Some(wrong)).unwrap();
    let err = catalog
        .open_active(Config::default(), Bus::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    store::put(&db, "committed", &Some(committed)).unwrap();
    db.execute("DELETE FROM meta WHERE name='vote'", [])
        .unwrap();
    let err = catalog
        .open_active(Config::default(), Bus::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(catalog.active_pin().unwrap(), Some(pin));
    assert!(store::meta::<Vote>(&db, "vote").unwrap().is_none());
}

#[tokio::test]
async fn unrecognized_database_is_preserved_at_reserved_paths() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("installation.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE unrelated(value INTEGER)")
        .unwrap();
    assert!(InstallationCatalog::open(dir.path()).is_err());
    let version = |db: &Connection| {
        db.query_row("PRAGMA user_version", [], |row| row.get::<_, i32>(0))
            .unwrap()
    };
    assert_eq!(version(&db), 0);
    db.pragma_update(None, "user_version", 1).unwrap();
    assert!(
        InstallationCatalog::open(dir.path()).is_err(),
        "catalog version alone cannot identify a database"
    );

    let dir = tempfile::tempdir().unwrap();
    interrupted(dir.path(), 1);
    let (_, id, _) = catalog_row(dir.path());
    let db = Connection::open(game_file(dir.path(), id)).unwrap();
    db.execute_batch("CREATE TABLE unrelated(value INTEGER)")
        .unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    assert!(create_game(&mut catalog).await.is_err());
    assert_eq!(version(&db), 0);
    assert_eq!(catalog.active_pin().unwrap(), None);
}

#[tokio::test]
async fn missing_database_with_surviving_sqlite_journal_requires_recovery() {
    for suffix in ["-wal", "-shm", "-journal"] {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join(format!("installation.sqlite{suffix}"));
        std::fs::write(&journal, b"retained evidence").unwrap();
        assert!(InstallationCatalog::open(dir.path()).is_err());
        assert_eq!(std::fs::read(journal).unwrap(), b"retained evidence");
        assert!(!dir.path().join("installation.sqlite").exists());
    }
    let dir = tempfile::tempdir().unwrap();
    interrupted(dir.path(), 1);
    let (_, id, _) = catalog_row(dir.path());
    let path = game_file(dir.path(), id);
    let journal = path.with_extension("sqlite-wal");
    std::fs::write(&journal, b"retained evidence").unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    assert!(create_game(&mut catalog).await.is_err());
    assert_eq!(std::fs::read(journal).unwrap(), b"retained evidence");
    assert!(!path.exists());
    assert_eq!(catalog.active_pin().unwrap(), None);
}
