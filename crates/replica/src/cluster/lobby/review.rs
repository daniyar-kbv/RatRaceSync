use super::*;

pub(super) fn interrupt(dir: &Path, stage: u8, exit: i32) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cluster::lobby::interrupted_lobby_worker"])
        .env("LOBBY_TEST_DIRECTORY", dir)
        .env("LOBBY_TEST_STAGE", stage.to_string())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(exit));
}

fn reserved_db(dir: &Path) -> Connection {
    let inventory = Connection::open(dir.join("installation.sqlite")).unwrap();
    let node: [u8; 16] = inventory
        .query_row("SELECT node FROM participation", [], |r| r.get(0))
        .unwrap();
    Connection::open(dir.join(format!("game-{}-g1.sqlite", ReplicaId(node)))).unwrap()
}

fn decode_frames(mut record: &[u8]) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    while !record.is_empty() {
        let (prefix, rest) = record.split_at(8);
        let len = usize::try_from(u64::from_be_bytes(prefix.try_into().unwrap())).unwrap();
        let (value, rest) = rest.split_at(len);
        parts.push(value);
        record = rest;
    }
    parts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independently_verify_complete_lobby_records_at_the_original_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let game = create(&mut catalog, intent(3)).await.unwrap();
    let db = reserved_db(dir.path());
    let lobby = game.lobby.as_ref().unwrap();
    let envelope = wire::fields(&lobby.receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    let (idx, event_tip, receipt_tip): ([u8; 8], Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT idx,event_tip,receipt_tip FROM archive WHERE log_id=?",
            [envelope[&5]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let (prev_event, prev_receipt): (Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT event_tip,receipt_tip FROM archive WHERE idx=?",
            [(u64::from_be_bytes(idx) - 1).to_be_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    for (ledger, domain, previous, expected) in [
        ("event", b"event-step/v2".as_slice(), prev_event, event_tip),
        (
            "receipt",
            b"receipt-step/v2".as_slice(),
            prev_receipt,
            receipt_tip,
        ),
    ] {
        let (stored_prev, record): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT previous_tip,record FROM semantic_link WHERE ledger=? AND seq=1",
                [ledger],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(previous, stored_prev);
        let mut sha = Sha256::new();
        for value in [domain, &previous, &record] {
            sha.update((value.len() as u64).to_be_bytes());
            sha.update(value);
        }
        assert_eq!(sha.finalize().as_slice(), expected);
        let outer = decode_frames(&record);
        let facts = decode_frames(outer[10]);
        let profile = b"RatRaceSync/Classic101/lobby/v8";
        assert_eq!(outer[1], profile);
        assert_eq!(outer[2], game.session);
        if ledger == "event" {
            assert_eq!(outer.len(), 11);
            assert_eq!(
                (outer[3], outer[4], outer[5]),
                (envelope[&5], envelope[&6], envelope[&8])
            );
            assert_eq!(
                (outer[7], outer[8], outer[9]),
                (ACTOR, REQUEST.as_slice(), envelope[&4])
            );
        } else {
            assert_eq!(outer.len(), 12);
            assert_eq!(
                (outer[3], outer[4], outer[5]),
                (ACTOR, REQUEST.as_slice(), envelope[&5])
            );
            assert_eq!(
                (outer[6], outer[8], outer[11]),
                (envelope[&6], envelope[&4], envelope[&8])
            );
            assert_eq!(outer[9], 12u16.to_be_bytes());
        }
        assert_eq!(
            outer[if ledger == "event" { 6 } else { 7 }],
            201u16.to_be_bytes()
        );
        assert_eq!(facts.len(), 12);
        assert_eq!(facts[0], profile);
        assert_eq!(
            (facts[1], facts[2], facts[3]),
            (game.session.as_slice(), ACTOR, ACTOR)
        );
        assert_eq!(facts[4], 3u32.to_be_bytes());
        assert_eq!(decode_frames(facts[5]), vec![&[1], &[2], &[3]]);
        assert_eq!(facts[6], 1u64.to_be_bytes());
        assert_eq!(facts[7], 1i32.to_be_bytes());
        assert_eq!(facts[8], lobby.created.genesis);
        assert_ne!(facts[8], envelope[&5]);
        assert_eq!(facts[9], 1u64.to_be_bytes());
        assert_eq!(facts[10], 1u32.to_be_bytes());
        assert_eq!(facts[11], game.creator_node.0);
    }
    game.node.raft.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pending_create_with_a_logged_command_must_keep_its_original_genesis() {
    for (stage, exit) in [(9, 81), (10, 82)] {
        let dir = tempfile::tempdir().unwrap();
        interrupt(dir.path(), stage, exit);
        let db = reserved_db(dir.path());
        assert_eq!(
            db.execute("DELETE FROM meta WHERE name='signed_genesis'", [])
                .unwrap(),
            1
        );
        let before: i64 = db
            .query_row("SELECT count(*) FROM raft_log", [], |r| r.get(0))
            .unwrap();
        let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
        assert!(
            create(&mut catalog, intent(4)).await.is_err(),
            "re-signed a root after Create entered the log"
        );
        assert!(catalog.active_pin().unwrap().is_none());
        assert_eq!(
            db.query_row("SELECT count(*) FROM raft_log", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            before
        );
        assert!(
            store::meta::<Vec<u8>>(&db, "signed_genesis")
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_receipt_requires_the_signed_genesis_and_unfunded_opening_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
    let game = create(&mut catalog, intent(3)).await.unwrap();
    let signed = Signed(
        Connection::open(dir.path().join("installation.sqlite"))
            .unwrap()
            .query_row("SELECT lobby_command FROM participation", [], |r| r.get(0))
            .unwrap(),
    );
    for damage in [
        "DELETE FROM meta WHERE name='signed_genesis'",
        "INSERT INTO meta VALUES('finance_open',x'01')",
        "UPDATE semantic_link SET record=x'00' WHERE ledger='receipt'",
        "UPDATE semantic_link SET previous_tip=zeroblob(32) WHERE ledger='event'",
    ] {
        {
            let db = game.node.replica.lock().unwrap();
            db.execute_batch("SAVEPOINT damage").unwrap();
            db.execute_batch(damage).unwrap();
        }
        assert!(
            game.node.submit(signed.clone()).await.is_err(),
            "confirmed receipt after {damage}"
        );
        game.node
            .replica
            .lock()
            .unwrap()
            .execute_batch("ROLLBACK TO damage; RELEASE damage")
            .unwrap();
    }
    game.node.raft.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_can_finish_the_signed_catalog_intent_without_the_original_form() {
    for (stage, exit) in [(1, 91), (4, 94), (9, 81), (10, 82), (5, 95)] {
        let dir = tempfile::tempdir().unwrap();
        interrupt(dir.path(), stage, exit);
        let mut catalog = InstallationCatalog::open(dir.path()).unwrap();
        let wrong_key = SigningKey::from_bytes(&[3; 32]);
        assert!(
            catalog
                .resume_lobby_create(&wrong_key, Config::default(), Bus::default())
                .await
                .is_err()
        );
        let saved: Option<Vec<u8>> = if matches!(stage, 5 | 10) {
            Some(
                reserved_db(dir.path())
                    .query_row("SELECT record FROM receipt", [], |r| r.get(0))
                    .unwrap(),
            )
        } else {
            None
        };
        let game = catalog
            .resume_lobby_create(&key(), Config::default(), Bus::default())
            .await
            .unwrap();
        let lobby = game.lobby.as_ref().unwrap();
        assert_eq!(
            lobby.created.seats,
            vec![vec![1], vec![2], vec![3], vec![4]]
        );
        if let Some(saved) = saved {
            assert_eq!(lobby.receipt, saved);
        }
        assert_eq!(catalog.active_pin().unwrap(), Some(game.fingerprint));
        game.node.raft.shutdown().await.unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let mut empty = InstallationCatalog::open(dir.path()).unwrap();
    assert!(
        empty
            .resume_lobby_create(&key(), Config::default(), Bus::default())
            .await
            .is_err()
    );
    assert_eq!(
        Connection::open(dir.path().join("installation.sqlite"))
            .unwrap()
            .query_row("SELECT count(*) FROM participation", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

// Re-run the same reserved synthetic game in two isolated transports. Only
// the original signed field order differs. Neither instance contacts the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn equivalent_create_encodings_have_distinct_source_hashes_and_identical_semantic_links() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    interrupt(a.path(), 1, 91);
    let inventory = Connection::open(a.path().join("installation.sqlite")).unwrap();
    inventory
        .execute(
            "VACUUM INTO ?",
            [b.path().join("installation.sqlite").to_str().unwrap()],
        )
        .unwrap();
    let other = Connection::open(b.path().join("installation.sqlite")).unwrap();
    let wire: Vec<u8> = other
        .query_row("SELECT lobby_command FROM participation", [], |r| r.get(0))
        .unwrap();
    let f = wire::fields(
        wire::fields(&wire, &[1, 2]).unwrap()[&1],
        &[1, 2, 3, 4, 5, 12],
    )
    .unwrap();
    let mut body = Vec::new();
    for tag in [12, 5, 4, 3, 2, 1] {
        wire::field(&mut body, tag, f[&tag]);
    }
    let reordered = wire::message(&[(1, &body), (2, &key().sign(&body).to_bytes())]);
    other
        .execute("UPDATE participation SET lobby_command=?", [reordered])
        .unwrap();
    let mut rows = Vec::new();
    for dir in [a.path(), b.path()] {
        let mut catalog = InstallationCatalog::open(dir).unwrap();
        let game = create(&mut catalog, intent(4)).await.unwrap();
        let db = reserved_db(dir);
        let row:(Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>)=db.query_row(
            "SELECT log_id,digest,event_tip,receipt_tip FROM archive WHERE receipt_count=1 ORDER BY idx LIMIT 1",
            [],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        rows.push(row);
        game.node.raft.shutdown().await.unwrap();
    }
    assert_eq!(rows[0].0, rows[1].0);
    assert_ne!(rows[0].1, rows[1].1);
    assert_eq!(
        rows[0].2, rows[1].2,
        "event chain included the raw payload hash"
    );
    assert_eq!(
        rows[0].3, rows[1].3,
        "receipt chain included the raw payload hash"
    );
}
