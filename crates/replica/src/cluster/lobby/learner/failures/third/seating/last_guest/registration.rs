use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_registration_after_leave_races_and_recovers_its_historical_prefix() {
    let root = tempfile::tempdir().unwrap();
    let (mut p, join) =
        finish_pair(Peers::with_profile(root.path(), 2, LobbyFormat::LastGuest).await).await;
    let host = &p.game.node;
    let old = p.learner.admission(&p.identity).unwrap();
    let (_, receipt) = last_guest(host, &p.learner, &p.identity, &mut p.catalog, &p.bus).await;
    p.bus.6.lock().unwrap().take();
    assert!(host.recovery_route(&old, &key()).is_err());
    let invitation = p.game.learner_invitation().unwrap();
    let mut candidates = Vec::new();
    for n in [57u8, 58] {
        let path = root.path().join(format!("candidate-{n}"));
        let mut catalog = InstallationCatalog::open(&path).unwrap();
        let identity = SigningKey::from_bytes(&[n; 32]);
        let learner = catalog
            .open_learner(
                &p.game.session,
                &invitation,
                &[n],
                &identity,
                Config::default(),
                p.bus.clone(),
            )
            .await
            .unwrap();
        let admission = learner.admission(&identity).unwrap();
        let route = host
            .recovery_route(&admission, &key())
            .expect("fresh route from sole creator");
        learner.authorize_recovery_route(&route).unwrap();
        candidates.push((path, catalog, identity, learner, route));
    }
    let counts = |node: &GameNode| -> (i64, i64) {
        node.replica
            .lock()
            .unwrap()
            .query_row(
                "SELECT (SELECT count(*) FROM event), (SELECT count(*) FROM receipt)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    };
    let before = counts(host);
    let (a, b) = tokio::join!(
        host.admit_recovery_learner(&candidates[0].4, &[]),
        host.admit_recovery_learner(&candidates[1].4, &[])
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let winner = usize::from(b.is_ok());
    let registered = a.or(b).unwrap();
    let (path, mut catalog, identity, mut learner, route) = candidates.swap_remove(winner);
    let (_, losing_catalog, _, loser, losing_route) = candidates.pop().unwrap();
    assert!(
        host.admit_recovery_learner(&losing_route, &[])
            .await
            .is_err()
    );
    assert!(losing_catalog.active_pin().unwrap().is_none());
    loser.shutdown().await.unwrap();
    let id = learner.id();
    assert_eq!(
        host.admit_recovery_learner(&route, &[]).await.unwrap(),
        registered
    );
    assert_eq!(counts(host), before);
    assert_eq!(
        host.raft.voter_ids().collect::<Vec<_>>(),
        [p.game.creator_node]
    );
    p.bus
        .1
        .lock()
        .unwrap()
        .insert(id, (p.game.creator_node, learner.replication()));
    host.certify_recovery_tail(&key(), async |_| panic!("retired quorum"))
        .await
        .unwrap();
    learner
        .node
        .raft
        .wait(Some(Duration::from_secs(8)))
        .applied_index_at_least(Some(registered.index), "fresh registration")
        .await
        .unwrap();
    let index = join.log_id.index.to_be_bytes();
    let original: Vec<u8> = host
        .replica
        .lock()
        .unwrap()
        .query_row(
            "SELECT certificate FROM historic_seal WHERE idx=?",
            [index],
            |row| row.get(0),
        )
        .unwrap();
    let request = learner.request(&identity).unwrap();
    let chunk = host
        .voter_recovery_chunk(&request, &key(), async |_| panic!("retired voter"))
        .await
        .unwrap();
    let chunk_body = fields(&chunk, &[1, 2]).unwrap()[&1];
    let retired_chunk = message(&[
        (1, chunk_body),
        (2, &p.identity.sign(chunk_body).to_bytes()),
    ]);
    assert!(catalog.accept_chunk(&mut learner, &retired_chunk).is_err());
    assert!(catalog.active_pin().unwrap().is_none());
    assert!(
        catalog
            .accept_chunk(&mut learner, &chunk)
            .unwrap()
            .is_none()
    );
    assert!(catalog.active_pin().unwrap().is_none());
    host.replica
        .lock()
        .unwrap()
        .execute("DELETE FROM historic_seal WHERE idx=?", [index])
        .unwrap();
    let missing = catalog
        .recover_learner(&mut learner, &identity, async |q| {
            host.voter_recovery_chunk(&q, &key(), async |_| panic!("retired voter"))
                .await
        })
        .await
        .unwrap_err();
    assert!(
        missing
            .to_string()
            .contains("missing original historical certificate"),
        "{missing}"
    );
    let stalled = learner.request(&identity).unwrap();
    assert_eq!(
        fields(fields(&stalled, &[1, 2]).unwrap()[&1], &[1, 2, 3, 4]).unwrap()[&4],
        index
    );
    assert!(catalog.active_pin().unwrap().is_none());
    host.replica
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO historic_seal(idx,certificate) VALUES(?,?)",
            rusqlite::params![index, original],
        )
        .unwrap();
    learner.shutdown().await.unwrap();
    p.shutdown().await;
    drop(learner);
    drop(catalog);
    drop(p);
    let bus = Bus::default();
    let mut hc = InstallationCatalog::open(&root.path().join("creator")).unwrap();
    let game = hc
        .open_active(Config::default(), bus.clone())
        .await
        .unwrap();
    game.node.raft.trigger().elect(true).await.unwrap();
    game.node
        .raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "sole creator")
        .await
        .unwrap();
    assert_eq!(
        game.node.admit_recovery_learner(&route, &[]).await.unwrap(),
        registered
    );
    game.node
        .raft
        .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
        .await
        .unwrap();
    game.node
        .certify_recovery_tail(&key(), async |_| panic!("retired voter"))
        .await
        .unwrap();
    let mut catalog = InstallationCatalog::open(&path).unwrap();
    let mut learner = catalog
        .resume_learner(&identity, Config::default(), bus.clone())
        .await
        .unwrap();
    assert_eq!(learner.id(), id);
    bus.1
        .lock()
        .unwrap()
        .insert(id, (game.creator_node, learner.replication()));
    let lobby = catalog
        .recover_learner(&mut learner, &identity, async |q| {
            game.node
                .voter_recovery_chunk(&q, &key(), async |_| panic!("retired voter"))
                .await
        })
        .await
        .unwrap();
    assert!(learner.joined_node().is_err());
    {
        let db = learner.node.replica.lock().unwrap();
        let cert: Vec<u8> = db
            .query_row(
                "SELECT certificate FROM historic_seal WHERE idx=?",
                [index],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(cert, original);
        let last: Vec<u8> = db
            .query_row(
                "SELECT record FROM receipt ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(last, receipt);
    }
    bus.1.lock().unwrap().remove(&id);
    learner.shutdown().await.unwrap();
    game.node.raft.shutdown().await.unwrap();
    drop(learner);
    drop(catalog);
    let mut catalog = InstallationCatalog::open(&path).unwrap();
    let learner = catalog
        .resume_learner(&identity, Config::default(), Bus::default())
        .await
        .unwrap();
    assert_eq!(catalog.recovered_lobby(&learner).unwrap(), Some(lobby));
    assert!(learner.joined_node().is_err());
    learner.shutdown().await.unwrap();
}
