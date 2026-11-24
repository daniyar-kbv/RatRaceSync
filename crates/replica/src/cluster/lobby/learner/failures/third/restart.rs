use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn third_recovery_crash_worker() {
    let Ok(path) = std::env::var("THIRD_RECOVERY_ROOT") else {
        return;
    };
    let Recovery {
        p,
        mut catalog,
        mut third,
        identity,
        ..
    } = admitted_third(Path::new(&path)).await;
    catalog.crash_stage = std::env::var("THIRD_RECOVERY_STAGE")
        .unwrap()
        .parse()
        .unwrap();
    catalog
        .recover_learner(&mut third, &identity, async |q| {
            p.game
                .node
                .voter_recovery_chunk(&q, &key(), async |q| {
                    p.learner.node.attest_recovery(&q, &p.identity)
                })
                .await
        })
        .await
        .unwrap();
    panic!("crash boundary not reached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crashes_before_and_after_archive_and_catalog_commits_survive_new_leader() {
    for stage in 11..=14 {
        let dir = tempfile::tempdir().unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cluster::lobby::learner::failures::third::restart::third_recovery_crash_worker",
            ])
            .env("THIRD_RECOVERY_ROOT", dir.path())
            .env("THIRD_RECOVERY_STAGE", stage.to_string())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(100 + stage));
        let mut host_catalog = InstallationCatalog::open(&dir.path().join("creator")).unwrap();
        let mut second_catalog = InstallationCatalog::open(&dir.path().join("receiver")).unwrap();
        let mut third_catalog = InstallationCatalog::open(&dir.path().join("third")).unwrap();
        assert_eq!(third_catalog.active_pin().unwrap().is_some(), stage == 14);
        let second_key = SigningKey::from_bytes(&[41; 32]);
        let third_key = SigningKey::from_bytes(&[57; 32]);
        let bus = Bus::default();
        let host = host_catalog
            .open_active(Config::default(), bus.clone())
            .await
            .unwrap();
        host.node.raft.runtime_config().elect(false);
        host.node.raft.runtime_config().heartbeat(false);
        let second = second_catalog
            .resume_learner(&second_key, Config::default(), bus.clone())
            .await
            .unwrap();
        let mut third = third_catalog
            .resume_learner(&third_key, Config::default(), bus.clone())
            .await
            .unwrap();
        let peer = second.joined_node().unwrap();
        bus.0
            .lock()
            .unwrap()
            .insert(host.creator_node, host.node.raft.clone());
        bus.1
            .lock()
            .unwrap()
            .insert(second.id(), (host.creator_node, second.replication()));
        bus.1
            .lock()
            .unwrap()
            .insert(third.id(), (second.id(), third.replication()));
        peer.raft
            .wait(Some(Duration::from_secs(10)))
            .state(openraft::ServerState::Leader, "second voter elected")
            .await
            .unwrap();
        peer.raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .unwrap();
        let high = peer.raft.metrics().borrow_watched().last_applied.unwrap();
        for node in [&*host.node, &third.node] {
            node.raft
                .wait(Some(Duration::from_secs(5)))
                .applied_index_at_least(Some(high.index), "new leader tail")
                .await
                .unwrap();
        }
        peer.certify_recovery_tail(&second_key, async |req| {
            host.node.answer_history_request(second.id(), req, &key())
        })
        .await
        .unwrap();
        let creation = third_catalog
            .recover_learner(&mut third, &third_key, async |request| {
                peer.voter_recovery_chunk(&request, &second_key, async |q| {
                    host.node.attest_recovery(&q, &key())
                })
                .await
            })
            .await
            .unwrap();
        assert_eq!(Some(creation), host.lobby);
        let join = third_catalog.recovered_join(&third).unwrap().unwrap();
        let original: Vec<u8> = host
            .node
            .replica
            .lock()
            .unwrap()
            .query_row("SELECT record FROM receipt WHERE seq=2", [], |r| r.get(0))
            .unwrap();
        assert_eq!(join.receipt, original);
        assert_eq!(join.member.node, second.id());
        assert!(third.joined_node().is_err());
        assert_eq!(third.node.raft.voter_ids().count(), 2);
        assert!(!third.node.raft.voter_ids().any(|id| id == third.id()));
        third.shutdown().await.unwrap();
        second.shutdown().await.unwrap();
        host.node.raft.shutdown().await.unwrap();
    }
}
