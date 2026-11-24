use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promotion_crash_worker() {
    let Ok(path) = std::env::var("PROMOTION_ROOT") else {
        return;
    };
    let stage: u8 = std::env::var("PROMOTION_CRASH").unwrap().parse().unwrap();
    let mut r = admitted_third(Path::new(&path)).await;
    r.recover().await;
    let raw = r.proposal().await.unwrap();
    let offline = if stage == 1 {
        r.third.id()
    } else {
        r.p.learner.id()
    };
    r.p.bus.4.lock().unwrap().push(offline);
    if stage == 5 {
        r.p.bus.4.lock().unwrap().push(r.third.id());
        assert!(
            timeout(Duration::from_millis(450), r.p.game.node.join_lobby(&raw))
                .await
                .is_err()
        );
        assert_eq!(
            r.p.game.node.raft.metrics().borrow_watched().last_applied,
            Some(r.admitted)
        );
        std::process::exit(115);
    }
    if stage >= 3 {
        r.p.game
            .node
            .replica
            .crash
            .store(stage - 1, std::sync::atomic::Ordering::Release);
    }
    let out = r.p.game.node.join_lobby(&raw).await.unwrap();
    let peer = if stage == 1 {
        &r.p.learner.node
    } else {
        &r.third.node
    };
    peer.raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(out.log_id.index), "durable majority")
        .await
        .unwrap();
    std::process::exit(100);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_validates_the_retained_uncommitted_promotion_before_elections() {
    let dir = tempfile::tempdir().unwrap();
    run_worker(dir.path(), 5);
    let root = dir.path().join("creator");
    let mut catalog = InstallationCatalog::open(&root).unwrap();
    let id: ReplicaId = catalog
        .db
        .query_row("SELECT node FROM participation", [], |row| {
            row.get(0).map(ReplicaId)
        })
        .unwrap();
    {
        let db = Connection::open(root.join(format!("game-{id}-g1.sqlite"))).unwrap();
        let bytes: Vec<u8> = db
            .query_row(
                "SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut entry = store::decode::<Entry>(&bytes).unwrap();
        *entry.payload.bytes.last_mut().unwrap() ^= 1;
        db.execute(
            "UPDATE raft_log SET entry=? WHERE idx=?",
            rusqlite::params![
                store::encode(&entry).unwrap(),
                entry.log_id.index.to_be_bytes()
            ],
        )
        .unwrap();
    }
    assert!(
        catalog
            .open_active(Config::default(), Bus::default())
            .await
            .is_err(),
        "reopened with invalid promotion signature"
    );
}
fn run_worker(path: &Path, stage: u8) {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cluster::lobby::learner::failures::third::promotion::restart::promotion_crash_worker",
        ])
        .env("PROMOTION_ROOT", path)
        .env("PROMOTION_CRASH", stage.to_string())
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(match stage {
            3 => 112,
            4 => 113,
            5 => 115,
            _ => 100,
        })
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_surviving_pair_recovers_after_crash_and_one_never_commits() {
    // Some pairs contain the installation which missed the entire promotion.
    for (stage, absent) in [
        (1, 2),
        (2, 1),
        (1, 0),
        (2, 0),
        (3, 1),
        (4, 1),
        (5, 1),
        (5, 2),
    ] {
        let dir = tempfile::tempdir().unwrap();
        run_worker(dir.path(), stage);
        let root = dir.path();
        let mut hc = InstallationCatalog::open(&root.join("creator")).unwrap();
        let mut sc = InstallationCatalog::open(&root.join("receiver")).unwrap();
        let mut tc = InstallationCatalog::open(&root.join("third")).unwrap();
        let prior = {
            let id: ReplicaId = hc
                .db
                .query_row("SELECT node FROM participation", [], |row| {
                    row.get(0).map(ReplicaId)
                })
                .unwrap();
            let db = Connection::open(root.join("creator").join(format!("game-{id}-g1.sqlite")))
                .unwrap();
            let entry: Vec<u8> = db
                .query_row(
                    "SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let entry = store::decode::<Entry>(&entry).unwrap();
            let signed = entry.payload.join_command().unwrap().unwrap().to_vec();
            let receipt: Option<Vec<u8>> = db
                .query_row("SELECT record FROM receipt WHERE seq=3", [], |row| {
                    row.get(0)
                })
                .optional()
                .unwrap();
            assert_eq!(receipt.is_some(), !matches!(stage, 3 | 5));
            (entry.log_id, signed, receipt)
        };
        let bus = Bus::default();
        let second_key = SigningKey::from_bytes(&[41; 32]);
        let third_key = SigningKey::from_bytes(&[57; 32]);
        let host = if absent != 0 {
            Some(
                hc.open_active(Config::default(), bus.clone())
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let second = if absent != 1 {
            Some(
                sc.resume_learner(&second_key, Config::default(), bus.clone())
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let third = if absent != 2 {
            Some(
                tc.resume_learner(&third_key, Config::default(), bus.clone())
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let nodes: Vec<_> = host
            .iter()
            .map(|h| (h.node.as_ref(), key()))
            .chain(second.iter().map(|s| (&s.node, second_key.clone())))
            .chain(third.iter().map(|t| (&t.node, third_key.clone())))
            .collect();
        let ids: Vec<_> = nodes
            .iter()
            .map(|(n, _)| n.replica.local_node.unwrap())
            .collect();
        for (n, _) in &nodes {
            assert!(!matches!(
                timeout(Duration::from_millis(250), n.join_lobby(&prior.1)).await,
                Ok(Ok(_))
            ));
        }
        for (n, k) in &nodes {
            bus.5.lock().unwrap().insert(
                n.replica.local_node.unwrap(),
                (n.promotion_authority(), k.clone()),
            );
        }
        if let Some(h) = &host {
            bus.0
                .lock()
                .unwrap()
                .insert(h.creator_node, h.node.raft.clone());
        }
        for l in second.iter().chain(third.iter()) {
            let sender = *ids.iter().find(|id| **id != l.id()).unwrap();
            bus.1
                .lock()
                .unwrap()
                .insert(l.id(), (sender, l.replication()));
        }
        let leader = timeout(Duration::from_secs(7), async {
            loop {
                for (i, (n, _)) in nodes.iter().enumerate() {
                    if n.raft.metrics().borrow_watched().state == openraft::ServerState::Leader
                        && n.raft
                            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
                            .await
                            .is_ok()
                    {
                        return i;
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no quorum for stage {stage}, absent {absent}"));
        let (owner, owner_key) = &nodes[leader];
        let (other, other_key) = &nodes[1 - leader];
        let result = owner.join_lobby(&prior.1).await.unwrap();
        assert_eq!(result.log_id, prior.0);
        if let Some(receipt) = prior.2 {
            assert_eq!(result.receipt, receipt);
        }
        other
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(Some(result.log_id.index), "recovered Join")
            .await
            .unwrap();
        owner
            .reconcile_voting_history(result.log_id, owner_key, async |q| {
                other.answer_history_request(ids[leader], q, other_key)
            })
            .await
            .unwrap();
        let elected = *owner
            .raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .unwrap()
            .log_id();
        assert!(
            elected.index > result.log_id.index
                && elected.leader_id.term > result.log_id.leader_id.term
        );
        other
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(Some(elected.index), "new-term checkpoint")
            .await
            .unwrap();
        other
            .certify_recovery_tail(other_key, async |q| {
                owner.answer_history_request(ids[1 - leader], q, owner_key)
            })
            .await
            .unwrap();
        for (n, _) in nodes {
            assert!(n.voting_history_complete(elected).unwrap());
            assert!(n.voting_history_complete(result.log_id).unwrap());
            assert_eq!(
                n.replica
                    .lock()
                    .unwrap()
                    .query_row("SELECT count(*) FROM receipt", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                3
            );
            n.raft.shutdown().await.unwrap();
        }
    }
}
