use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_crash_worker() {
    let Ok(root) = std::env::var("SEAT_TEST_ROOT") else {
        return;
    };
    let stage: u8 = std::env::var("SEAT_TEST_STAGE").unwrap().parse().unwrap();
    let op: u16 = std::env::var("SEAT_TEST_OP").unwrap().parse().unwrap();
    let format = if op == 204 {
        crate::lobby::LobbyFormat::Seating
    } else {
        crate::lobby::LobbyFormat::SeatChanges
    };
    let (p, _) = finish_pair(Peers::with_profile(Path::new(&root), 3, format).await).await;
    let host = &p.game.node;
    let guard = host
        .seat_claim_guard(ACTOR, SeatId::new(2).unwrap())
        .await
        .unwrap();
    let guard = if op == 204 {
        guard
    } else {
        host.submit(guard.sign(request(29), &key())).await.unwrap();
        match op {
            205 => host.seat_release_guard(ACTOR).await.unwrap(),
            206 => host
                .seat_change_guard(ACTOR, SeatId::new(3).unwrap())
                .await
                .unwrap(),
            _ => panic!("unexpected operation"),
        }
    };
    let raw = host
        .prepare_seat_command(&guard, request(30), &key())
        .unwrap();
    host.replica
        .crash
        .store(stage, std::sync::atomic::Ordering::Release);
    host.submit(raw).await.unwrap();
    panic!("SQLite crash boundary not reached")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_original_claim_reopens_on_both_sides_of_sql_commit() {
    check_restart(204).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_seat_changes_reopen_atomically_on_both_sides_of_sql_commit() {
    for op in [205, 206] {
        check_restart(op).await;
    }
}
async fn check_restart(op: u16) {
    let seq = if op == 204 { 3 } else { 4 };
    for stage in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cluster::lobby::learner::failures::third::seating::restart::claim_crash_worker",
            ])
            .env("SEAT_TEST_ROOT", dir.path())
            .env("SEAT_TEST_OP", op.to_string())
            .env("SEAT_TEST_STAGE", stage.to_string())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(80 + stage));
        let mut hc = InstallationCatalog::open(&dir.path().join("creator")).unwrap();
        let mut pc = InstallationCatalog::open(&dir.path().join("receiver")).unwrap();
        let id: ReplicaId = hc
            .db
            .query_row("SELECT node FROM participation", [], |row| {
                row.get(0).map(ReplicaId)
            })
            .unwrap();
        let original = {
            let db = Connection::open(
                dir.path()
                    .join("creator")
                    .join(format!("game-{id}-g1.sqlite")),
            )
            .unwrap();
            let receipt: Option<Vec<u8>> = db
                .query_row("SELECT record FROM receipt WHERE seq=?", [seq], |row| {
                    row.get(0)
                })
                .optional()
                .unwrap();
            assert_eq!(receipt.is_some(), stage == 2);
            if op != 204 {
                let changed: i64 = db
                    .query_row(
                        "SELECT count(*) FROM seat_history WHERE revision<>? OR seat=3",
                        [1u64.to_be_bytes()],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(
                    changed,
                    if stage == 1 {
                        0
                    } else if op == 205 {
                        1
                    } else {
                        2
                    }
                );
            }
            let bytes: Vec<u8> = db
                .query_row(
                    "SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            (store::decode::<Entry>(&bytes).unwrap(), receipt)
        };
        let bus = Bus::default();
        let h = hc
            .open_active(Config::default(), bus.clone())
            .await
            .unwrap();
        let key_b = SigningKey::from_bytes(&[41; 32]);
        let p = pc
            .resume_learner(&key_b, Config::default(), bus.clone())
            .await
            .unwrap();
        let pending = h
            .node
            .saved_seat_command(ACTOR, request(30), &key())
            .unwrap()
            .unwrap();
        assert_eq!(
            original.0.payload.bytes.strip_prefix(&[1]),
            Some(pending.0.as_slice())
        );
        bus.0.lock().unwrap().insert(id, h.node.raft.clone());
        bus.1.lock().unwrap().insert(p.id(), (id, p.replication()));
        let out = timeout(Duration::from_secs(8), async {
            loop {
                for node in [h.node.as_ref(), &p.node] {
                    if let Ok(reply) = node.submit(pending.clone()).await {
                        return receipt(reply);
                    }
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let rf = fields(&out, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert_eq!(rf[&5], log_key(original.0.log_id));
        if let Some(prior) = original.1 {
            assert_eq!(out, prior)
        }
        for node in [h.node.as_ref(), &p.node] {
            node.raft
                .wait(Some(Duration::from_secs(5)))
                .applied_index_at_least(Some(original.0.log_id.index), "claim restored")
                .await
                .unwrap();
            let db = node.replica.lock().unwrap();
            node.replica.verify_replay(&db).unwrap();
            if op != 204 {
                let rows: Vec<(i64, Option<Vec<u8>>)> = db
                    .prepare("SELECT seat,occupant FROM seat_history WHERE idx=? ORDER BY seat")
                    .unwrap()
                    .query_map([original.0.log_id.index.to_be_bytes()], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap();
                let mut expected = vec![(2, None)];
                if op == 206 {
                    expected.push((3, Some(ACTOR.to_vec())));
                }
                assert_eq!(rows, expected);
            }
            assert_eq!(node.replica.tip(&db, "event").unwrap().0, seq);
            assert_eq!(node.replica.tip(&db, "receipt").unwrap().0, seq);
        }
        p.shutdown().await.unwrap();
        h.node.raft.shutdown().await.unwrap();
    }
}
