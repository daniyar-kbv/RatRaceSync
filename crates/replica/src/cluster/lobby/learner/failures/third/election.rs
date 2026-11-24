use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registration_by_second_leader_preserves_later_creator_elections() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = joined_pair(dir.path(), 3).await;
    let host = &p.game.node;
    let peer = p.learner.joined_node().unwrap();
    host.raft.runtime_config().elect(false);
    host.raft.runtime_config().heartbeat(false);
    peer.raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "second voter elected")
        .await
        .unwrap();
    let mut catalog = InstallationCatalog::open(&dir.path().join("third")).unwrap();
    let identity = SigningKey::from_bytes(&[57; 32]);
    let mut third = catalog
        .open_learner(
            &p.game.session,
            &p.game.learner_invitation().unwrap(),
            b"new",
            &identity,
            Config::default(),
            p.bus.clone(),
        )
        .await
        .unwrap();
    let route = host
        .recovery_route(&third.admission(&identity).unwrap(), &key())
        .unwrap();
    third.authorize_recovery_route(&route).unwrap();
    let confirm = peer.confirm_recovery_support(&route, &p.identity).unwrap();
    p.bus
        .1
        .lock()
        .unwrap()
        .insert(third.id(), (p.learner.id(), third.replication()));
    let elected = peer.raft.metrics().borrow_watched().last_applied.unwrap();
    host.raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(elected.index), "election prefix")
        .await
        .unwrap();
    assert!(
        peer.admit_recovery_learner(&route, &confirm).await.is_err(),
        "registered learner over unsealed predecessor"
    );
    peer.certify_recovery_tail(&p.identity, async |q| {
        host.answer_history_request(p.learner.id(), q, &key())
    })
    .await
    .unwrap();
    let k = peer.admit_recovery_learner(&route, &confirm).await.unwrap();
    for node in [&**host, &third.node] {
        node.raft
            .wait(Some(Duration::from_secs(8)))
            .applied_index_at_least(Some(k.index), "third admitted")
            .await
            .unwrap();
    }
    // The customary candidate transport attaches pending Join evidence only
    // when the first Join itself is still the effective membership.
    *p.bus.2.lock().unwrap() = Some(Arc::downgrade(host));
    p.bus
        .1
        .lock()
        .unwrap()
        .insert(third.id(), (p.game.creator_node, third.replication()));
    peer.raft.runtime_config().heartbeat(false);
    peer.raft.runtime_config().elect(false);
    host.raft.runtime_config().elect(true);
    host.raft.runtime_config().heartbeat(true);
    host.raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "creator elected")
        .await
        .unwrap();
    host.raft
        .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
        .await
        .unwrap();
    let high = host.raft.metrics().borrow_watched().last_applied.unwrap();
    peer.raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(high.index), "current voter tail")
        .await
        .unwrap();
    host.certify_recovery_tail(&key(), async |q| {
        peer.answer_history_request(p.game.creator_node, q, &p.identity)
    })
    .await
    .unwrap();
    let received = catalog
        .recover_learner(&mut third, &identity, async |q| {
            host.voter_recovery_chunk(&q, &key(), async |q| peer.attest_recovery(&q, &p.identity))
                .await
        })
        .await
        .unwrap();
    assert_eq!(Some(received), p.game.lobby);
    assert!(third.joined_node().is_err());
    third.shutdown().await.unwrap();
    p.shutdown().await;
}
