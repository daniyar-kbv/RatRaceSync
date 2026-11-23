use super::*;
use openraft::async_runtime::watch::WatchReceiver;
mod failures;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creator_seals_its_applied_prefix_before_any_learner_exists() {
    let host = tempfile::tempdir().unwrap();
    let mut catalog = InstallationCatalog::open(host.path()).unwrap();
    let game = create(&mut catalog, intent(4)).await.unwrap();
    timeout(Duration::from_secs(2),async {
        loop {
            let complete=game.node.replica.lock().unwrap().query_row(
                "SELECT count(*)=(SELECT count(*) FROM archive) AND count(*)>=2 FROM historic_seal",[],|r|r.get::<_,bool>(0)).unwrap_or(false);
            if complete { break; }
            sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    game.node.raft.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independently_recovers_lobby_without_a_second_vote() {
    let host = tempfile::tempdir().unwrap();
    let peer = tempfile::tempdir().unwrap();
    let bus = Bus::default();
    let mut host_catalog = InstallationCatalog::open(host.path()).unwrap();
    let game = host_catalog
        .create_lobby(intent(4), &key(), Config::default(), bus.clone())
        .await
        .unwrap();
    bus.0
        .lock()
        .unwrap()
        .insert(game.creator_node, game.node.raft.clone());
    let invite = game.learner_invitation().unwrap();
    let identity = SigningKey::from_bytes(&[13; 32]);
    let mut catalog = InstallationCatalog::open(peer.path()).unwrap();
    let mut learner = catalog
        .open_learner(
            &game.session,
            &invite,
            b"guest",
            &identity,
            Config::default(),
            bus.clone(),
        )
        .await
        .unwrap();
    assert_ne!(learner.id(), game.creator_node);
    bus.1
        .lock()
        .unwrap()
        .insert(learner.id(), (game.creator_node, learner.replication()));
    game.admit_learner(&learner.admission(&identity).unwrap())
        .await
        .unwrap();
    let member = game
        .node
        .raft
        .metrics()
        .borrow_watched()
        .membership_config
        .clone();
    assert!(member.membership().voter_ids().eq([game.creator_node]));
    assert!(member.membership().non_write_voter_ids().eq([learner.id()]));
    let mut verified = None;
    for _ in 0..16 {
        let request = learner.request(&identity).unwrap();
        let chunk = game.recovery_chunk(&request, &key()).await.unwrap();
        let index = game
            .node
            .raft
            .metrics()
            .borrow_watched()
            .last_applied
            .map(|k| k.index);
        learner
            .node
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(index, "catch up")
            .await
            .unwrap();
        verified = catalog.accept_chunk(&mut learner, &chunk).unwrap();
        if verified.is_some() {
            break;
        }
    }
    assert_eq!(verified.unwrap(), game.lobby.unwrap());
    assert_eq!(catalog.active_pin().unwrap(), Some(game.fingerprint));
    game.node.raft.shutdown().await.unwrap();
    let db = &learner.node.replica;
    let original: Vec<u8> = db
        .lock()
        .unwrap()
        .query_row(
            "SELECT source FROM archive WHERE substr(source,1,1)=x'01' ORDER BY idx LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        learner
            .node
            .raft
            .client_write(Signed(original[1..].to_vec()))
            .await
            .is_err()
    );
    assert!(
        learner
            .node
            .raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .is_err()
    );
    let counts:(i64,i64,i64)=db.lock().unwrap().query_row("SELECT (SELECT count(*) FROM event),(SELECT count(*) FROM receipt),(SELECT count(*) FROM participant)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(counts, (1, 1, 0));
    learner.shutdown().await.unwrap();
}
