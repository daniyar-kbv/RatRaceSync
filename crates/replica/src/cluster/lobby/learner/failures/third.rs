use super::*;
mod election;
mod restart;

struct Recovery {
    p: Peers,
    catalog: InstallationCatalog,
    third: Learner,
    identity: SigningKey,
    admitted: LogId,
    join: JoinResult,
}
async fn joined_pair(root: &Path, capacity: u8) -> (Peers, JoinResult) {
    let mut p = Peers::with_capacity(root, capacity).await;
    p.finish().await;
    let host = &*p.game.node;
    let join = p
        .catalog
        .join_first_player(
            &p.learner,
            &p.identity,
            REQUEST,
            true,
            async |cmd| host.join_lobby(&cmd).await,
            async |req| host.answer_history_request(p.learner.id(), req, &key()),
        )
        .await
        .unwrap();
    join.history.unwrap();
    (p, join.join)
}
async fn admitted_third(root: &Path) -> Recovery {
    let (p, join) = joined_pair(root, 4).await;
    let host = &*p.game.node;
    let other = &p.learner.node;
    let path = root.join("third");
    let mut catalog = InstallationCatalog::open(&path).unwrap();
    let identity = SigningKey::from_bytes(&[57; 32]);
    let third = catalog
        .open_learner(
            &p.game.session,
            &p.game.learner_invitation().unwrap(),
            b"next-player",
            &identity,
            Config::default(),
            p.bus.clone(),
        )
        .await
        .unwrap();
    let route = host
        .recovery_route(&third.admission(&identity).unwrap(), &key())
        .unwrap();
    // A distinct signed identity cannot reuse this reserved replication ID.
    let admission = third.admission(&identity).unwrap();
    let body = fields(&admission, &[1, 2]).unwrap();
    let mut values = fields(body[&1], &[1, 2, 3, 4, 5, 6]).unwrap();
    let alternate = SigningKey::from_bytes(&[67; 32]);
    let alternate_key = alternate.verifying_key().to_bytes();
    values.insert(4, b"alternate");
    values.insert(5, &alternate_key);
    let body = message(&values.into_iter().collect::<Vec<_>>());
    let replacement = message(&[(1, &body), (2, &alternate.sign(&body).to_bytes())]);
    assert!(
        host.recovery_route(&replacement, &key()).is_err(),
        "reissued a reserved node to a second identity"
    );
    third.authorize_recovery_route(&route).unwrap();
    p.bus
        .1
        .lock()
        .unwrap()
        .insert(third.id(), (p.game.creator_node, third.replication()));
    let confirmation = other.confirm_recovery_support(&route, &p.identity).unwrap();
    assert!(host.admit_recovery_learner(&route, &[]).await.is_err());
    let admitted = host
        .admit_recovery_learner(&route, &confirmation)
        .await
        .unwrap();
    assert_eq!(
        admitted,
        host.admit_recovery_learner(&route, &confirmation)
            .await
            .unwrap()
    );
    for node in [other, &third.node] {
        node.raft
            .wait(Some(Duration::from_secs(6)))
            .applied_index_at_least(Some(admitted.index), "nonvoting replication")
            .await
            .unwrap();
    }
    assert!(!third.node.raft.voter_ids().any(|id| id == third.id()));
    assert!(third.joined_node().is_err());
    host.certify_recovery_tail(&key(), async |req| {
        other.answer_history_request(p.game.creator_node, req, &p.identity)
    })
    .await
    .unwrap();
    Recovery {
        p,
        catalog,
        third,
        identity,
        admitted,
        join,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_lobby_declines_new_recovery_admission() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = joined_pair(dir.path(), 2).await;
    let mut catalog = InstallationCatalog::open(&dir.path().join("third")).unwrap();
    let identity = SigningKey::from_bytes(&[57; 32]);
    let learner = catalog
        .open_learner(
            &p.game.session,
            &p.game.learner_invitation().unwrap(),
            b"third",
            &identity,
            Config::default(),
            p.bus.clone(),
        )
        .await
        .unwrap();
    assert!(
        p.game
            .node
            .recovery_route(&learner.admission(&identity).unwrap(), &key())
            .is_err()
    );
    assert!(catalog.active_pin().unwrap().is_none());
    learner.shutdown().await.unwrap();
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn third_replays_both_receipts_and_resumes_without_a_vote() {
    let dir = tempfile::tempdir().unwrap();
    let Recovery {
        p,
        mut catalog,
        mut third,
        identity,
        join,
        ..
    } = admitted_third(dir.path()).await;
    let path = dir.path().join("third");
    let host = &*p.game.node;
    let other = &p.learner.node;
    let mut calls = 0;
    assert!(
        catalog
            .recover_learner(&mut third, &identity, async |request| {
                calls += 1;
                if calls == 3 {
                    return Err(io::Error::from(io::ErrorKind::ConnectionReset));
                }
                host.voter_recovery_chunk(&request, &key(), async |q| {
                    other.attest_recovery(&q, &p.identity)
                })
                .await
            })
            .await
            .is_err()
    );
    assert_eq!(calls, 3);
    assert!(catalog.active_pin().unwrap().is_none());
    let id = third.id();
    p.bus.1.lock().unwrap().remove(&id);
    third.shutdown().await.unwrap();
    drop(third);
    drop(catalog);
    let mut catalog = InstallationCatalog::open(&path).unwrap();
    let mut third = catalog
        .resume_learner(&identity, Config::default(), p.bus.clone())
        .await
        .unwrap();
    p.bus
        .1
        .lock()
        .unwrap()
        .insert(id, (p.game.creator_node, third.replication()));
    let creation = catalog
        .recover_learner(&mut third, &identity, async |request| {
            host.voter_recovery_chunk(&request, &key(), async |q| {
                other.attest_recovery(&q, &p.identity)
            })
            .await
        })
        .await
        .unwrap();
    assert_eq!(Some(creation), p.game.lobby);
    assert_eq!(catalog.recovered_join(&third).unwrap(), Some(join));
    assert!(
        catalog
            .prepare_join(&third, &identity, REQUEST, true)
            .is_err(),
        "a recovery-only third cannot prepare a first-player promotion"
    );
    assert_eq!(catalog.active_pin().unwrap(), Some(p.game.fingerprint));
    assert!(!third.node.raft.voter_ids().any(|v| v == id));
    assert!(third.joined_node().is_err());
    p.bus.1.lock().unwrap().remove(&id);
    third.shutdown().await.unwrap();
    drop(third);
    drop(catalog);
    let mut catalog = InstallationCatalog::open(&path).unwrap();
    let db = Connection::open(path.join(format!("learner-{id}-g1.sqlite"))).unwrap();
    db.execute("DELETE FROM receipt WHERE seq=2", []).unwrap();
    drop(db);
    assert!(
        catalog
            .resume_learner(&identity, Config::default(), p.bus.clone())
            .await
            .is_err(),
        "reopened verified generation after original Join receipt loss"
    );
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_evidence_never_activates_the_third_installation() {
    let dir = tempfile::tempdir().unwrap();
    let Recovery {
        p,
        mut catalog,
        mut third,
        identity,
        join,
        admitted,
    } = admitted_third(dir.path()).await;
    let host = &*p.game.node;
    let peer = &p.learner.node;
    for i in 0..=admitted.index {
        let request = third.request(&identity).unwrap();
        let reply = host
            .voter_recovery_chunk(&request, &key(), async |_| unreachable!())
            .await
            .unwrap();
        if i == join.log_id.index {
            let r = &third.node.replica;
            r.lock().unwrap().execute_batch("CREATE TRIGGER full_store BEFORE INSERT ON historic_seal BEGIN SELECT RAISE(ABORT,'fixture write failure'); END").unwrap();
            assert!(catalog.accept_chunk(&mut third, &reply).is_err());
            assert!(catalog.active_pin().unwrap().is_none());
            third
                .node
                .replica
                .lock()
                .unwrap()
                .execute_batch("DROP TRIGGER full_store")
                .unwrap();
            let outer = response_fields(&reply);
            let proof = fields(outer[&5], &[1, 2]).unwrap();
            let signatures = fields(proof[&1], &[1, 2]).unwrap();
            let original = fields(proof[&2], &[1, 2, 3]).unwrap();
            for bad in [
                message(&[(1, signatures[&1]), (2, proof[&2])]),
                message(&[
                    (1, &message(&[(1, signatures[&2]), (2, signatures[&2])])),
                    (2, proof[&2]),
                ]),
                message(&[
                    (1, proof[&1]),
                    (
                        2,
                        &message(&[(1, &[]), (2, original[&2]), (3, original[&3])]),
                    ),
                ]),
                message(&[
                    (1, proof[&1]),
                    (
                        2,
                        &message(&[(1, original[&1]), (2, original[&2]), (3, &[])]),
                    ),
                ]),
            ] {
                let body = message(&[
                    (1, outer[&1]),
                    (2, outer[&2]),
                    (3, outer[&3]),
                    (4, outer[&4]),
                    (5, &bad),
                ]);
                let packet = message(&[(1, &body), (2, &key().sign(&body).to_bytes())]);
                assert!(catalog.accept_chunk(&mut third, &packet).is_err());
                assert!(catalog.active_pin().unwrap().is_none());
            }
        }
        assert!(catalog.accept_chunk(&mut third, &reply).unwrap().is_none());
    }
    let req = third.request(&identity).unwrap();
    let single = peer.attest_recovery(&req, &p.identity).unwrap();
    let local = host.attest_recovery(&req, &key()).unwrap();
    for bad in [single, message(&[(1, &local), (2, &local)])] {
        assert!(catalog.accept_chunk(&mut third, &bad).is_err());
    }
    let old = host
        .voter_recovery_chunk(&req, &key(), async |q| {
            peer.attest_recovery(&q, &p.identity)
        })
        .await
        .unwrap();
    let fresh = third.request(&identity).unwrap();
    assert!(catalog.accept_chunk(&mut third, &old).is_err());
    assert!(catalog.active_pin().unwrap().is_none());
    // Loss of an original at either voter prevents its fresh checkpoint attestation.
    peer.replica
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM raft_log WHERE idx=?",
            [join.log_id.index.to_be_bytes()],
        )
        .unwrap();
    assert!(
        host.voter_recovery_chunk(&fresh, &key(), async |q| peer
            .attest_recovery(&q, &p.identity))
            .await
            .is_err()
    );
    assert!(catalog.active_pin().unwrap().is_none());
    assert!(third.joined_node().is_err());
    third.shutdown().await.unwrap();
    p.shutdown().await;
}
