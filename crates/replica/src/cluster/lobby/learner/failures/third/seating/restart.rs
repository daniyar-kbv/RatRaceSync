use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_crash_worker() {
    let Ok(root) = std::env::var("SEAT_TEST_ROOT") else {
        return;
    };
    let stage: u8 = std::env::var("SEAT_TEST_STAGE").unwrap().parse().unwrap();
    let (p, _) = finish_pair(
        Peers::with_profile(Path::new(&root), 3, crate::lobby::LobbyFormat::Seating).await,
    )
    .await;
    let host = &p.game.node;
    let guard = host
        .seat_claim_guard(ACTOR, SeatId::new(2).unwrap())
        .await
        .unwrap();
    let raw = host
        .prepare_seat_claim(&guard, request(30), &key())
        .unwrap();
    host.replica
        .crash
        .store(stage, std::sync::atomic::Ordering::Release);
    host.submit(raw).await.unwrap();
    panic!("SQLite crash boundary not reached")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_original_claim_reopens_on_both_sides_of_sql_commit() {
    for stage in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cluster::lobby::learner::failures::third::seating::restart::claim_crash_worker",
            ])
            .env("SEAT_TEST_ROOT", dir.path())
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
                .query_row("SELECT record FROM receipt WHERE seq=3", [], |row| {
                    row.get(0)
                })
                .optional()
                .unwrap();
            assert_eq!(receipt.is_some(), stage == 2);
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
            .saved_seat_claim(ACTOR, request(30), &key())
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
            assert_eq!(node.replica.tip(&db, "event").unwrap().0, 3);
            assert_eq!(node.replica.tip(&db, "receipt").unwrap().0, 3);
        }
        p.shutdown().await.unwrap();
        h.node.raft.shutdown().await.unwrap();
    }
}
