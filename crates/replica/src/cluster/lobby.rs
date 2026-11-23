use super::*;
use ed25519_dalek::Signer;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
mod learner;
mod review;

const REQUEST: [u8; 16] = [2, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];

fn intent(target: u8) -> CreateLobby<'static> {
    CreateLobby {
        request: REQUEST,
        actor: ACTOR,
        target,
        profile_complete: true,
        can_host: true,
    }
}

async fn create(
    catalog: &mut InstallationCatalog,
    input: CreateLobby<'_>,
) -> io::Result<CreatorGame> {
    catalog
        .create_lobby(input, &key(), Config::default(), Bus::default())
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_lobby_at_both_limits_recovers_the_original_result() {
    for target in [2, 10] {
        let dir = tempfile::tempdir().unwrap();
        let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
        let game = create(&mut catalog, intent(target)).await.unwrap();
        let original = game.lobby.clone().unwrap();
        let state = &original.created;
        assert_eq!(state.session, game.session);
        assert_eq!(state.host, ACTOR);
        assert_eq!(state.creator, ACTOR);
        assert_eq!(state.join_ordinal, 1);
        assert_eq!(state.stage, LobbyStage::Open as i32);
        assert_eq!(state.target, u32::from(target));
        assert_eq!(state.seats.len(), usize::from(target));
        assert_eq!(
            state
                .seats
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            state.seats.len()
        );
        {
            let db = game.node.replica.lock().unwrap();
            assert_eq!(
                state.genesis,
                log_key(store::meta::<LogId>(&db, "genesis_log").unwrap().unwrap())
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM event", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM receipt", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM participant", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        assert!(
            create(&mut catalog, intent(if target == 2 { 10 } else { 2 }))
                .await
                .is_err()
        );
        game.node.raft.shutdown().await.unwrap();
        drop(game);
        drop(catalog);
        let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
        let reopened = catalog
            .open_active(Config::default(), Bus::default())
            .await
            .unwrap();
        assert_eq!(reopened.lobby, Some(original.clone()));
        let retry = create(
            &mut catalog,
            CreateLobby {
                can_host: false,
                ..intent(target)
            },
        )
        .await
        .unwrap();
        assert_eq!(retry.lobby, Some(original));
        retry.node.raft.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn rejected_create_leaves_the_participation_slot_available() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    for bad in [
        intent(1),
        intent(11),
        CreateLobby {
            profile_complete: false,
            ..intent(2)
        },
        CreateLobby {
            can_host: false,
            ..intent(2)
        },
    ] {
        assert!(create(&mut catalog, bad).await.is_err());
        assert!(catalog.active_pin().unwrap().is_none());
        assert_eq!(
            Connection::open(dir.path().join("installation.sqlite"))
                .unwrap()
                .query_row("SELECT count(*) FROM participation", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    create(&mut catalog, intent(3))
        .await
        .unwrap()
        .node
        .raft
        .shutdown()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_lobby_worker() {
    let Some(path) = std::env::var_os("LOBBY_TEST_DIRECTORY") else {
        return;
    };
    let mut catalog = InstallationCatalog::open(Path::new(&path)).unwrap();
    catalog.crash_stage = std::env::var("LOBBY_TEST_STAGE").unwrap().parse().unwrap();
    create(&mut catalog, intent(4)).await.unwrap();
    panic!("missed process interruption");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retries_finish_the_reserved_signed_command_across_both_databases() {
    for (stage, exit) in [(1, 91), (8, 98), (4, 94), (9, 81), (10, 82), (5, 95)] {
        let dir = tempfile::tempdir().unwrap();
        review::interrupt(dir.path(), stage, exit);
        let inventory = Connection::open(dir.path().join("installation.sqlite")).unwrap();
        let (session, node, signed, pin): (Vec<u8>, [u8; 16], Vec<u8>, Option<Vec<u8>>) = inventory
            .query_row(
                "SELECT session,node,lobby_command,pin FROM participation",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(pin.is_some(), stage == 5);
        let path = dir
            .path()
            .join(format!("game-{}-g1.sqlite", ReplicaId(node)));
        let prior = if path.exists() {
            let db = Connection::open(&path).unwrap();
            let receipt: Option<Vec<u8>> = db
                .query_row("SELECT record FROM receipt", [], |r| r.get(0))
                .optional()
                .unwrap();
            assert_eq!(receipt.is_some(), matches!(stage, 5 | 10));
            assert_eq!(
                store::meta::<Vec<u8>>(&db, "lobby").unwrap().is_some(),
                receipt.is_some()
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM event", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                i64::from(receipt.is_some())
            );
            receipt
        } else {
            assert_eq!(stage, 1);
            None
        };
        let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
        assert!(create(&mut catalog, intent(6)).await.is_err());
        assert!(
            create(
                &mut catalog,
                CreateLobby {
                    request: {
                        let mut other = REQUEST;
                        other[0] ^= 1;
                        other
                    },
                    ..intent(4)
                }
            )
            .await
            .is_err()
        );
        if pin.is_none() {
            assert!(
                catalog
                    .open_active(Config::default(), Bus::default())
                    .await
                    .is_err()
            );
        }
        let game = create(
            &mut catalog,
            CreateLobby {
                can_host: false,
                ..intent(4)
            },
        )
        .await
        .unwrap();
        let lobby = game.lobby.as_ref().unwrap();
        assert_eq!(lobby.created.session, session);
        assert_eq!(
            lobby.created.seats,
            vec![vec![1], vec![2], vec![3], vec![4]]
        );
        if let Some(prior) = prior {
            assert_eq!(lobby.receipt, prior);
        }
        let db = Connection::open(&path).unwrap();
        let f = wire::fields(&lobby.receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        let (source, digest, events, receipts): (Vec<u8>, Vec<u8>, i64, i64) = db
            .query_row(
                "SELECT source,digest,event_count,receipt_count FROM archive WHERE log_id=?",
                [f[&5]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_ne!(f[&5], lobby.created.genesis);
        assert_eq!((events, receipts), (1, 1));
        assert_eq!(source.strip_prefix(&[1]), Some(signed.as_slice()));
        assert_eq!(digest, Sha256::digest(&source).as_slice());
        assert_eq!(digest, f[&9]);
        assert_eq!(
            db.query_row("SELECT count(*) FROM receipt", [], |r| r.get::<_, u32>(0))
                .unwrap(),
            1
        );
        assert_eq!(db.query_row("SELECT count(*) FROM event WHERE position IS NULL AND cash_after IS NULL AND units_after IS NULL",[],|r|r.get::<_,u32>(0)).unwrap(),1);
        game.node.raft.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_authentication_and_duplicate_committed_entries_preserve_history() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let game = create(&mut catalog, intent(4)).await.unwrap();
    let receipt = game.lobby.as_ref().unwrap().receipt.clone();
    let raw: Vec<u8> = Connection::open(dir.path().join("installation.sqlite"))
        .unwrap()
        .query_row("SELECT lobby_command FROM participation", [], |r| r.get(0))
        .unwrap();
    let original = wire::fields(&raw, &[1, 2]).unwrap();
    let sign = |body: &[u8], key: &SigningKey| {
        Signed(wire::message(&[(1, body), (2, &key.sign(body).to_bytes())]))
    };
    assert!(
        game.node
            .submit(sign(original[&1], &SigningKey::from_bytes(&[3; 32])))
            .await
            .is_err()
    );
    let mut extra = original[&1].to_vec();
    wire::field(&mut extra, 31, b"unknown");
    assert!(game.node.submit(sign(&extra, &key())).await.is_err());
    let f = wire::fields(original[&1], &[1, 2, 3, 4, 5, 12]).unwrap();
    let body = |session: &[u8], kind: &[u8]| {
        wire::message(&[
            (12, kind),
            (5, f[&5]),
            (4, f[&4]),
            (3, f[&3]),
            (2, session),
            (1, f[&1]),
        ])
    };
    assert!(
        game.node
            .submit(sign(&body(b"other", f[&12]), &key()))
            .await
            .is_err()
    );
    let changed = wire::message(&[(201, &wire::message(&[(1, &[5])]))]);
    assert_eq!(
        game.node
            .submit(sign(&body(f[&2], &changed), &key()))
            .await
            .unwrap(),
        Reply::RequestIdConflict
    );
    // Semantically equal signed fields with a different original wire order.
    let retry = sign(&body(f[&2], f[&12]), &key());
    assert_eq!(
        game.node.raft.client_write(retry).await.unwrap().data,
        Reply::Receipt(receipt)
    );
    {
        let db = game.node.replica.lock().unwrap();
        game.node.replica.verify_replay(&db).unwrap();
        let counts: (u32, u32) = db
            .query_row(
                "SELECT (SELECT count(*) FROM event),(SELECT count(*) FROM receipt)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(counts, (1, 1));
    }
    game.node.raft.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn damaged_original_cannot_be_confirmed_by_a_committed_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let game = create(&mut catalog, intent(2)).await.unwrap();
    let original: Vec<u8> = Connection::open(dir.path().join("installation.sqlite"))
        .unwrap()
        .query_row("SELECT lobby_command FROM participation", [], |r| r.get(0))
        .unwrap();
    let previous = store::meta::<LogId>(&game.node.replica.lock().unwrap(), "applied").unwrap();
    game.node
        .replica
        .lock()
        .unwrap()
        .execute("UPDATE receipt SET record=x'01'", [])
        .unwrap();
    let result = timeout(
        Duration::from_secs(4),
        game.node.raft.client_write(Signed(original)),
    )
    .await;
    assert!(
        !matches!(result, Ok(Ok(_))),
        "damaged receipt was returned by committed apply"
    );
    assert_eq!(
        store::meta::<LogId>(&game.node.replica.lock().unwrap(), "applied").unwrap(),
        previous
    );
    game.node.raft.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_catalog_activation_preserves_the_committed_lobby_for_retry() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let inventory = Connection::open(dir.path().join("installation.sqlite")).unwrap();
    inventory
        .execute_batch(
            "CREATE TRIGGER fail_activation BEFORE UPDATE OF pin ON participation
        BEGIN SELECT RAISE(ABORT,'test storage failure'); END;",
        )
        .unwrap();
    assert!(create(&mut catalog, intent(3)).await.is_err());
    assert_eq!(catalog.active_pin().unwrap(), None);
    let node: [u8; 16] = inventory
        .query_row("SELECT node FROM participation", [], |r| r.get(0))
        .unwrap();
    let db = Connection::open(
        dir.path()
            .join(format!("game-{}-g1.sqlite", ReplicaId(node))),
    )
    .unwrap();
    let receipt: Vec<u8> = db
        .query_row("SELECT record FROM receipt", [], |r| r.get(0))
        .unwrap();
    inventory
        .execute_batch("DROP TRIGGER fail_activation")
        .unwrap();
    let game = create(&mut catalog, intent(3)).await.unwrap();
    assert_eq!(game.lobby.as_ref().unwrap().receipt, receipt);
    assert_eq!(catalog.active_pin().unwrap(), Some(game.fingerprint));
    game.node.raft.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_catalog_migration_preserves_the_existing_genesis_only_game() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let game = catalog
        .create(REQUEST, ACTOR, &key(), Config::default(), Bus::default())
        .await
        .unwrap();
    let pin = game.fingerprint;
    assert!(
        game.node
            .replica
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO event(seq,actor,record,digest,tip) VALUES(1,x'01',x'01',x'01',x'01')",
                []
            )
            .is_err(),
        "legacy financial event projections must stay required"
    );
    game.node.raft.shutdown().await.unwrap();
    drop(game);
    drop(catalog);
    let inventory = Connection::open(dir.path().join("installation.sqlite")).unwrap();
    inventory
        .execute_batch("ALTER TABLE participation DROP COLUMN lobby_command; PRAGMA user_version=1")
        .unwrap();
    inventory
        .execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE participation SET stage=1")
        .unwrap();
    assert!(
        InstallationCatalog::open(dir.path()).is_err(),
        "invalid legacy pin was migrated"
    );
    assert_eq!(database_version(&inventory).unwrap(), 1);
    inventory
        .execute_batch("UPDATE participation SET stage=2; PRAGMA ignore_check_constraints=OFF")
        .unwrap();
    let mut migrated = InstallationCatalog::open(dir.path()).unwrap();
    assert!(create(&mut migrated, intent(2)).await.is_err());
    let reopened = migrated
        .open_active(Config::default(), Bus::default())
        .await
        .unwrap();
    assert_eq!(reopened.fingerprint, pin);
    assert!(reopened.lobby.is_none());
    reopened.node.raft.shutdown().await.unwrap();
}
