use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_crash_worker() {
    let Ok(root) = std::env::var("SEAT_TEST_ROOT") else {
        return;
    };
    let stage: u8 = std::env::var("SEAT_TEST_STAGE").unwrap().parse().unwrap();
    let op: u16 = std::env::var("SEAT_TEST_OP").unwrap().parse().unwrap();
    let outcome = std::env::var("SEAT_TEST_OUTCOME").unwrap();
    let format = if matches!(op, 207 | 208) {
        crate::lobby::LobbyFormat::DreamReady
    } else if op == 203 {
        crate::lobby::LobbyFormat::Resizable
    } else if op == 204 {
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
            203 => host
                .player_count_guard(ACTOR, rat_race_engine::LobbyCapacity::new(2).unwrap())
                .await
                .unwrap(),
            205 => host.seat_release_guard(ACTOR).await.unwrap(),
            206 => host
                .seat_change_guard(ACTOR, SeatId::new(3).unwrap())
                .await
                .unwrap(),
            207 => super::readiness::guard(
                host,
                ACTOR,
                &key(),
                30,
                LobbyPreference::Dream(rat_race_engine::DreamId::new(4).unwrap()),
                &key(),
            )
            .await
            .unwrap(),
            208 => {
                let g = super::readiness::guard(
                    host,
                    ACTOR,
                    &key(),
                    32,
                    LobbyPreference::Dream(rat_race_engine::DreamId::new(4).unwrap()),
                    &key(),
                )
                .await
                .unwrap();
                host.submit_preference(p.game.creator_node, g.sign(request(32), &key()))
                    .await
                    .unwrap();
                if outcome == "unchanged" {
                    let g = super::readiness::guard(
                        host,
                        ACTOR,
                        &key(),
                        33,
                        LobbyPreference::Ready(true),
                        &key(),
                    )
                    .await
                    .unwrap();
                    host.submit_preference(p.game.creator_node, g.sign(request(33), &key()))
                        .await
                        .unwrap();
                }
                super::readiness::guard(
                    host,
                    ACTOR,
                    &key(),
                    30,
                    LobbyPreference::Ready(true),
                    &key(),
                )
                .await
                .unwrap()
            }
            _ => panic!("unexpected operation"),
        }
    };
    let raw = host
        .prepare_seat_command(&guard, request(30), &key())
        .unwrap();
    if outcome == "conflict" {
        assert!(host.replica.preflight(&raw).unwrap().is_none());
        let claim = host
            .seat_claim_guard(b"guest", SeatId::new(3).unwrap())
            .await
            .unwrap();
        host.submit(claim.sign(request(31), &p.identity))
            .await
            .unwrap();
    }
    host.replica
        .crash
        .store(stage, std::sync::atomic::Ordering::Release);
    if outcome != "applied" {
        host.raft.client_write(raw).await.unwrap();
    } else if matches!(op, 207 | 208) {
        host.submit_preference(p.game.creator_node, raw)
            .await
            .unwrap();
    } else {
        host.submit(raw).await.unwrap();
    }
    panic!("SQLite crash boundary not reached")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_original_claim_reopens_on_both_sides_of_sql_commit() {
    check_restart(204, "applied").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_seat_changes_reopen_atomically_on_both_sides_of_sql_commit() {
    for op in [205, 206] {
        check_restart(op, "applied").await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resize_recovers_original_command_and_receipt_across_sql_commit() {
    for outcome in ["applied", "conflict"] {
        check_restart(203, outcome).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dream_and_ready_recover_on_either_side_of_sql_commit() {
    for op in [207, 208] {
        check_restart(op, "applied").await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ready_receipt_only_outcomes_recover_across_commit() {
    for outcome in ["conflict", "unchanged"] {
        check_restart(208, outcome).await;
    }
}
async fn check_restart(op: u16, outcome: &str) {
    let conflict = outcome == "conflict";
    let unchanged = outcome == "unchanged";
    let seq = if op == 204 {
        3
    } else {
        4 + i64::from(conflict || unchanged) + i64::from(op == 208)
    };
    for stage in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cluster::lobby::learner::failures::third::seating::restart::claim_crash_worker",
            ])
            .env("SEAT_TEST_ROOT", dir.path())
            .env("SEAT_TEST_OP", op.to_string())
            .env("SEAT_TEST_OUTCOME", outcome)
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
            if matches!(op, 205 | 206) {
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
            if matches!(op, 207 | 208) {
                let table = if op == 207 {
                    "dream_history"
                } else {
                    "ready_history"
                };
                let count: i64 = db
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, i64::from(unchanged || (stage == 2 && !conflict)));
                if stage == 2 {
                    assert_eq!(
                        db.execute("DELETE FROM meta WHERE name GLOB 'local_seat_claim_*'", [])
                            .unwrap(),
                        1
                    );
                }
            }
            if op == 203 {
                let layouts: i64 = db
                    .query_row("SELECT count(*) FROM layout_history", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(layouts, i64::from(stage == 2 && !conflict));
                if stage == 2 {
                    // Reopen with the committed archive but without the outgoing local copy.
                    let removed = db
                        .execute("DELETE FROM meta WHERE name GLOB 'local_seat_claim_*'", [])
                        .unwrap();
                    assert_eq!(removed, 1);
                }
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
                    let delivered = if matches!(op, 207 | 208) {
                        node.submit_preference(id, pending.clone()).await
                    } else {
                        node.submit(pending.clone()).await
                    };
                    if let Ok(reply) = delivered {
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
        if conflict {
            assert_eq!(fields(rf[&7], &[13]).unwrap()[&13], [8, 1]);
            assert!(rf[&8].is_empty());
        }
        if unchanged {
            assert!(fields(rf[&7], &[14]).is_ok() && rf[&8].is_empty());
        }
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
            if matches!(op, 205 | 206) {
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
            if op == 203 {
                let state = crate::seating::layout_at(&db, u64::MAX).unwrap();
                assert_eq!(
                    (state.seats.capacity().count(), state.layout_revision),
                    if conflict { (3, 1) } else { (2, 2) }
                );
                assert_eq!(
                    crate::seating::setup_revision(&db).unwrap(),
                    3 + u64::from(conflict)
                );
            }
            assert_eq!(
                node.replica.tip(&db, "event").unwrap().0,
                seq - i64::from(conflict || unchanged)
            );
            assert_eq!(node.replica.tip(&db, "receipt").unwrap().0, seq);
        }
        p.shutdown().await.unwrap();
        h.node.raft.shutdown().await.unwrap();
    }
}
