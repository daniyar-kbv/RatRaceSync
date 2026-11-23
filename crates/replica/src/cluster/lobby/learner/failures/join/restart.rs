use super::*;

async fn reconcile(
    k: LogId,
    host: &GameNode,
    peer: &GameNode,
    identity: &SigningKey,
) -> io::Result<()> {
    let sender = host.replica.local_node.unwrap();
    host.reconcile_voting_history(k, &key(), async |request| {
        peer.answer_history_request(sender, request, identity)
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withheld_replication_cannot_commit_join_or_issue_its_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::open(dir.path()).await;
    p.finish().await;
    let proposal = p
        .catalog
        .prepare_join(&p.learner, &p.identity, REQUEST, true)
        .unwrap();
    let route = p.bus.1.lock().unwrap().remove(&p.learner.id()).unwrap();
    assert!(
        timeout(
            Duration::from_millis(350),
            p.game.node.join_lobby(&proposal)
        )
        .await
        .is_err()
    );
    let proposed = {
        let db = p.game.node.replica.lock().unwrap();
        let bytes: Vec<u8> = db
            .query_row(
                "SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let entry: Entry = store::decode(&bytes).unwrap();
        assert_eq!(
            entry.payload.join_command().unwrap(),
            Some(proposal.as_slice())
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM receipt", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        entry.log_id
    };
    assert!(
        p.game
            .node
            .sign_voting_checkpoint(proposed, &key())
            .is_err()
    );
    assert!(p.learner.joined_node().is_err());
    p.bus.1.lock().unwrap().insert(p.learner.id(), route);
    for node in [&*p.game.node, &p.learner.node] {
        node.raft
            .wait(Some(Duration::from_secs(8)))
            .applied_index_at_least(Some(proposed.index), "reconnected voter")
            .await
            .unwrap();
    }
    let result = p.game.node.join_lobby(&proposal).await.unwrap();
    assert_eq!(result.log_id, proposed);
    assert!(!p.game.node.voting_history_complete(proposed).unwrap());
    reconcile(proposed, &p.game.node, &p.learner.node, &p.identity)
        .await
        .unwrap();
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_crash_worker() {
    let Ok(dir) = std::env::var("JOIN_CRASH_DIR") else {
        return;
    };
    let stage: u8 = std::env::var("JOIN_CRASH_STAGE").unwrap().parse().unwrap();
    if stage == 10 {
        // Lose the creator immediately after its next election appends a blank.
        // The learner heard the election but still has not received the Join.
        assert_eq!(crash_run(Path::new(&dir), 6), Some(116));
        let root = Path::new(&dir);
        let mut hc = InstallationCatalog::open(&root.join("creator")).unwrap();
        let mut pc = InstallationCatalog::open(&root.join("receiver")).unwrap();
        let bus = Bus::default();
        bus.3.store(true, std::sync::atomic::Ordering::Release);
        let host = hc
            .open_active(Config::default(), bus.clone())
            .await
            .unwrap()
            .node;
        let id = host.replica.local_node.unwrap();
        *bus.2.lock().unwrap() = Some(Arc::downgrade(&host));
        bus.0.lock().unwrap().insert(id, host.raft.clone());
        let peer = pc
            .resume_learner(
                &SigningKey::from_bytes(&[41; 32]),
                Config::default(),
                bus.clone(),
            )
            .await
            .unwrap();
        bus.1
            .lock()
            .unwrap()
            .insert(peer.id(), (id, peer.replication()));
        timeout(Duration::from_secs(8), async {
            loop {
                let blank = {
                    let db = host.replica.lock().unwrap();
                    let bytes: Vec<u8> = db
                        .query_row(
                            "SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    store::decode::<Entry>(&bytes).unwrap().payload.bytes == [0]
                };
                if blank {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(peer.joined_node().is_err());
        std::process::exit(120);
    }
    let mut p = Peers::open(Path::new(&dir)).await;
    p.finish().await;
    let cmd = p
        .catalog
        .prepare_join(&p.learner, &p.identity, REQUEST, true)
        .unwrap();
    if stage == 1 {
        std::process::exit(111);
    }
    if stage == 6 {
        p.bus.1.lock().unwrap().remove(&p.learner.id());
        assert!(
            timeout(Duration::from_millis(350), p.game.node.join_lobby(&cmd))
                .await
                .is_err()
        );
        let db = p.game.node.replica.lock().unwrap();
        let raw: Vec<u8> = db
            .query_row(
                "SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            store::decode::<Entry>(&raw)
                .unwrap()
                .payload
                .join_command()
                .unwrap(),
            Some(cmd.as_slice())
        );
        assert!(
            store::meta::<JoinedMember>(&db, "first_member")
                .unwrap()
                .is_none()
        );
        std::process::exit(116);
    }
    p.game
        .node
        .replica
        .crash
        .store(stage, std::sync::atomic::Ordering::Release);
    let r = p.game.node.join_lobby(&cmd).await.unwrap();
    if stage == 4 {
        std::process::exit(114);
    }
    p.learner
        .node
        .raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(r.log_id.index), "follower durable")
        .await
        .unwrap();
    if (7..=9).contains(&stage) {
        let host = &p.game.node;
        let peer = &p.learner.node;
        let a = host.sign_voting_checkpoint(r.log_id, &key()).unwrap();
        let b = peer.sign_voting_checkpoint(r.log_id, &p.identity).unwrap();
        let ack_a = host
            .store_voting_checkpoint(r.log_id, &a, &b, &key())
            .unwrap();
        if stage == 7 {
            std::process::exit(117);
        }
        let ack_b = peer
            .store_voting_checkpoint(r.log_id, &a, &b, &p.identity)
            .unwrap();
        if stage == 8 {
            std::process::exit(118);
        }
        peer.confirm_voting_checkpoint(r.log_id, &ack_a, &ack_b)
            .unwrap();
        std::process::exit(119);
    }
    reconcile(r.log_id, &p.game.node, &p.learner.node, &p.identity)
        .await
        .unwrap();
    std::process::exit(115);
}

fn crash_run(path: &Path, stage: u8) -> Option<i32> {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cluster::lobby::learner::failures::join::restart::join_crash_worker",
        ])
        .env("JOIN_CRASH_DIR", path)
        .env("JOIN_CRASH_STAGE", stage.to_string())
        .status()
        .unwrap()
        .code()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_reply_recovers_original_join_and_finishes_quorum_handoff_after_restart() {
    for stage in 1..=10 {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(crash_run(dir.path(), stage), Some(i32::from(110 + stage)));
        let before = {
            let root = dir.path().join("creator");
            let catalog = Connection::open(root.join("installation.sqlite")).unwrap();
            let id = catalog
                .query_row("SELECT node FROM participation", [], |r| {
                    r.get(0).map(ReplicaId)
                })
                .unwrap();
            let game = Connection::open(root.join(format!("game-{id}-g1.sqlite"))).unwrap();
            let receipt: Option<Vec<u8>> = game
                .query_row("SELECT record FROM receipt WHERE seq=2", [], |r| r.get(0))
                .optional()
                .unwrap();
            assert_eq!(receipt.is_some(), !matches!(stage, 1 | 2 | 6 | 10));
            let mut stmt = game
                .prepare("SELECT entry FROM raft_log ORDER BY idx")
                .unwrap();
            let source = stmt
                .query_map([], |r| r.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|x| store::decode::<Entry>(&x.unwrap()).unwrap())
                .find(|e| e.payload.join_command().unwrap().is_some());
            assert_eq!(source.is_some(), stage != 1);
            (source, receipt)
        };
        let mut hc = InstallationCatalog::open(&dir.path().join("creator")).unwrap();
        let mut pc = InstallationCatalog::open(&dir.path().join("receiver")).unwrap();
        let identity = SigningKey::from_bytes(&[41; 32]);
        let bus = Bus::default();
        let host = timeout(
            Duration::from_secs(3),
            hc.open_active(Config::default(), bus.clone()),
        )
        .await
        .expect("opening the pinned creator must allow both transports to register before election")
        .unwrap()
        .node;
        *bus.2.lock().unwrap() = Some(Arc::downgrade(&host));
        let id = host.replica.local_node.unwrap();
        bus.0.lock().unwrap().insert(id, host.raft.clone());
        let mut peer = pc
            .resume_learner(&identity, Config::default(), bus.clone())
            .await
            .unwrap();
        bus.1
            .lock()
            .unwrap()
            .insert(peer.id(), (id, peer.replication()));
        let leader = timeout(Duration::from_secs(12), async {
            loop {
                for node in [host.as_ref(), &peer.node] {
                    if node.raft.metrics().borrow_watched().state == openraft::ServerState::Leader
                        && node
                            .raft
                            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
                            .await
                            .is_ok()
                    {
                        return node.replica.local_node.unwrap();
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let mut cmd = pc.pending_join(&peer).unwrap();
        if stage == 1 {
            // Election appended a protocol entry. Refresh only the separate prefix witness.
            let game = hc
                .open_active(Config::default(), bus.clone())
                .await
                .unwrap();
            pc.recover_learner(&mut peer, &identity, async |req: Vec<u8>| {
                game.recovery_chunk(&req, &key()).await
            })
            .await
            .unwrap();
            cmd = pc.prepare_join(&peer, &identity, REQUEST, true).unwrap();
            drop(game);
        }
        let leader = if leader == id {
            host.as_ref()
        } else {
            &peer.node
        };
        let result = leader.join_lobby(&cmd).await.unwrap();
        if let Some(receipt) = before.1 {
            assert_eq!(result.receipt, receipt);
        }
        if let Some(source) = before.0 {
            assert_eq!(result.log_id, source.log_id);
            assert_eq!(source.payload.join_command().unwrap(), Some(cmd.as_slice()));
        }
        for node in [host.as_ref(), &peer.node] {
            node.raft
                .wait(Some(Duration::from_secs(8)))
                .applied_index_at_least(Some(result.log_id.index), "original Join applied")
                .await
                .unwrap();
        }
        reconcile(result.log_id, &host, &peer.node, &identity)
            .await
            .unwrap();
        assert!(host.voting_history_complete(result.log_id).unwrap());
        assert!(peer.node.voting_history_complete(result.log_id).unwrap());
        assert_eq!(leader.join_lobby(&cmd).await.unwrap(), result);
        assert_eq!(result.member.ordinal, 2);
        peer.shutdown().await.unwrap();
        host.raft.shutdown().await.unwrap();
    }
}
