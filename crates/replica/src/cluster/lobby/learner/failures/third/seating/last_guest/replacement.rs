use super::*;

struct CreatorTransport<'a> {
    host: &'a GameNode,
    learner: ReplicaId,
    allow_recovery: bool,
}
impl ThirdJoinTransport for CreatorTransport<'_> {
    async fn recover(&mut self, request: Vec<u8>) -> io::Result<Vec<u8>> {
        assert!(
            self.allow_recovery,
            "committed Join retry attempted to register again"
        );
        self.host
            .voter_recovery_chunk(&request, &key(), async |_| panic!("retired voter"))
            .await
    }
    async fn confirm(&mut self, _: Vec<u8>, _: Vec<u8>) -> io::Result<[Vec<u8>; 2]> {
        panic!("requested retired voter approval")
    }
    async fn submit(&mut self, raw: Vec<u8>) -> io::Result<JoinResult> {
        self.host.join_lobby(&raw).await
    }
    async fn history(&mut self, q: VotingHistoryRequest) -> io::Result<Vec<u8>> {
        self.host.answer_history_request(self.learner, q, &key())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovered_learner_joins_after_departure_and_resumes_handoff() {
    let root = tempfile::tempdir().unwrap();
    let pair = finish_pair(Peers::with_profile(root.path(), 3, LobbyFormat::LastGuest).await).await;
    let mut r = admit_to_pair(root.path(), pair).await;
    let host = &r.p.game.node;
    let id = r.third.id();
    let (original_leave, leave) = last_guest(
        host,
        &r.p.learner,
        &r.p.identity,
        &mut r.p.catalog,
        &r.p.bus,
    )
    .await;
    r.p.bus.6.lock().unwrap().take();
    assert!(
        r.catalog
            .prepare_join(&r.third, &r.identity, REQUEST, true)
            .is_err()
    );
    r.catalog
        .recover_learner(&mut r.third, &r.identity, async |q| {
            host.voter_recovery_chunk(&q, &key(), async |_| panic!("retired voter"))
                .await
        })
        .await
        .unwrap();
    let raw = r
        .catalog
        .prepare_join(&r.third, &r.identity, REQUEST, true)
        .unwrap();
    let resize = host
        .player_count_guard(ACTOR, rat_race_engine::LobbyCapacity::new(2).unwrap())
        .await
        .unwrap();
    host.submit(resize.sign(request(180), &key()))
        .await
        .unwrap();
    assert!(host.join_lobby(&raw).await.is_err());
    host.certify_recovery_tail(&key(), async |_| panic!("retired voter"))
        .await
        .unwrap();
    r.catalog
        .recover_learner(&mut r.third, &r.identity, async |q| {
            host.voter_recovery_chunk(&q, &key(), async |_| panic!("retired voter"))
                .await
        })
        .await
        .unwrap();
    let request_id = request(181);
    let raw = r
        .catalog
        .prepare_join(&r.third, &r.identity, request_id, true)
        .unwrap();
    let earlier_checkpoint: Vec<u8> = r
        .catalog
        .db
        .query_row("SELECT verified FROM learner WHERE slot=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    let release = host.seat_release_guard(ACTOR).await.unwrap();
    host.submit(release.sign(request(184), &key()))
        .await
        .unwrap();
    assert!(host.join_lobby(&raw).await.is_err());
    host.certify_recovery_tail(&key(), async |_| panic!("retired voter"))
        .await
        .unwrap();
    r.catalog
        .recover_learner(&mut r.third, &r.identity, async |q| {
            host.voter_recovery_chunk(&q, &key(), async |_| panic!("retired voter"))
                .await
        })
        .await
        .unwrap();
    assert!(
        r.catalog
            .prepare_join(&r.third, &r.identity, request_id, true)
            .is_err()
    );
    let request_id = request(185);
    let raw = r
        .catalog
        .prepare_join(&r.third, &r.identity, request_id, true)
        .expect("fresh Join after a setup-only revision");
    assert_eq!(r.catalog.pending_join(&r.third).unwrap(), raw);
    let offline = r.p.bus.1.lock().unwrap().remove(&id).unwrap();
    assert!(!matches!(
        timeout(Duration::from_millis(400), host.join_lobby(&raw)).await,
        Ok(Ok(_))
    ));
    assert!(r.third.joined_node().is_err());
    r.p.bus.1.lock().unwrap().insert(id, offline);
    let join = timeout(Duration::from_secs(8), host.join_lobby(&raw))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(join.member.ordinal, 3);
    assert_eq!(join.member.node, id);
    assert_eq!(
        host.raft
            .voter_ids()
            .collect::<std::collections::BTreeSet<_>>(),
        [id, r.p.game.creator_node].into()
    );
    let pending = r
        .catalog
        .join_first_player(
            &r.third,
            &r.identity,
            request_id,
            true,
            async |q| host.join_lobby(&q).await,
            async |_| Err(io::ErrorKind::ConnectionReset.into()),
        )
        .await
        .unwrap();
    assert_eq!(pending.join, join);
    assert!(pending.history.is_err());
    assert!(!host.voting_history_complete(join.log_id).unwrap());
    let only = host.sign_voting_checkpoint(join.log_id, &key()).unwrap();
    assert!(
        host.store_voting_checkpoint(join.log_id, &only, &only, &key())
            .is_err()
    );
    let view = host.lobby_seating(&r.third.actor).await.unwrap();
    assert!(view.seats[1].occupant.is_none() && !view.seats[1].ready);
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
    let identity = r.identity.clone();
    drop(r);
    let bus = Bus::default();
    let mut hc = InstallationCatalog::open(&root.path().join("creator")).unwrap();
    let mut lc = InstallationCatalog::open(&root.path().join("third")).unwrap();
    let game = hc
        .open_active(Config::default(), bus.clone())
        .await
        .unwrap();
    let checkpoint: Vec<u8> = lc
        .db
        .query_row("SELECT verified FROM learner WHERE slot=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    for damaged in [None, Some(earlier_checkpoint)] {
        lc.db
            .execute("UPDATE learner SET verified=? WHERE slot=1", [damaged])
            .unwrap();
        assert!(
            lc.resume_learner(&identity, Config::default(), bus.clone())
                .await
                .is_err(),
            "joined voter resumed without catalog coverage for its signed prefix"
        );
    }
    lc.db
        .execute("UPDATE learner SET verified=? WHERE slot=1", [checkpoint])
        .unwrap();
    let mut learner = lc
        .resume_learner(&identity, Config::default(), bus.clone())
        .await
        .unwrap();
    bus.0
        .lock()
        .unwrap()
        .insert(game.creator_node, game.node.raft.clone());
    bus.1
        .lock()
        .unwrap()
        .insert(id, (game.creator_node, learner.replication()));
    game.node.raft.trigger().elect(true).await.unwrap();
    game.node
        .raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "creator with new voter")
        .await
        .unwrap();
    let result = lc
        .join_third_player(
            &mut learner,
            &identity,
            request_id,
            true,
            &mut CreatorTransport {
                host: &game.node,
                learner: id,
                allow_recovery: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(result.join, join);
    result.history.unwrap();
    for node in [game.node.as_ref(), learner.joined_node().unwrap()] {
        assert!(node.voting_history_complete(join.log_id).unwrap());
        let db = node.replica.lock().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM receipt WHERE record IN (?,?)",
                rusqlite::params![leave, join.receipt],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }
    let host = &game.node;
    let peer = learner.joined_node().unwrap();
    seal(host, &learner, &identity).await;
    let guard = host.leave_lobby_witness(&learner.actor).await.unwrap();
    let cmd = peer
        .prepare_leave_lobby(&learner.actor, &guard, request(182), &identity)
        .unwrap();
    let a = host.leave_approval(&cmd, &key()).unwrap();
    let b = peer.leave_approval(&cmd, &identity).unwrap();
    host.leave_lobby(&cmd, [&a, &b]).await.unwrap();
    assert_eq!(
        host.leave_lobby(&original_leave, [&[], &[]]).await.unwrap(),
        leave
    );
    assert!(host.voting_history_complete(join.log_id).unwrap());
    host.leave_confirmation(&original_leave, &key()).unwrap();
    learner.shutdown().await.unwrap();
    game.node.raft.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_replacement_join_recovers_with_its_original_learner_consent() {
    let root = tempfile::tempdir().unwrap();
    let pair = finish_pair(Peers::with_profile(root.path(), 3, LobbyFormat::LastGuest).await).await;
    let mut r = admit_to_pair(root.path(), pair).await;
    r.recover().await;
    let obsolete = r.proposal().await.unwrap();
    let host = &r.p.game.node;
    let id = r.third.id();
    last_guest(
        host,
        &r.p.learner,
        &r.p.identity,
        &mut r.p.catalog,
        &r.p.bus,
    )
    .await;
    r.p.bus.6.lock().unwrap().take();
    assert!(host.join_lobby(&obsolete).await.is_err());
    let k = crate::learner::history::boundary(&host.replica.lock().unwrap()).unwrap();
    r.third
        .node
        .raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(k.index), "registered learner has Leave")
        .await
        .unwrap();
    r.p.bus.1.lock().unwrap().remove(&id);
    let req = request(183);
    let mut transport = CreatorTransport {
        host,
        learner: id,
        allow_recovery: true,
    };
    // Drop delivery at the durable append, while the successor quorum is disconnected.
    {
        let delivery =
            r.catalog
                .join_third_player(&mut r.third, &r.identity, req, true, &mut transport);
        let appended = async {
            loop {
                let retained: bool = host
                    .replica
                    .lock()
                    .unwrap()
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM raft_log WHERE idx>?)",
                        [k.index.to_be_bytes()],
                        |row| row.get(0),
                    )
                    .unwrap();
                if retained && host.raft.voter_ids().any(|node| node == id) {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::select! {
            _ = delivery => panic!("Join completed without the learner"),
            observed = timeout(Duration::from_secs(8), appended) => observed.unwrap(),
        }
    }
    let raw = r.catalog.pending_join(&r.third).unwrap();
    let pending = host
        .raft
        .metrics()
        .borrow_watched()
        .membership_config
        .clone();
    assert!(pending.membership().voter_ids().any(|node| node == id));
    assert_eq!(
        crate::learner::history::boundary(&host.replica.lock().unwrap()).unwrap(),
        k
    );
    let identity = r.identity.clone();
    let game_path = root
        .path()
        .join("creator")
        .join(format!("game-{}-g1.sqlite", r.p.game.creator_node));
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
    drop(r);
    let mut hc = InstallationCatalog::open(&root.path().join("creator")).unwrap();
    let mut lc = InstallationCatalog::open(&root.path().join("third")).unwrap();
    let bus = Bus::default();
    let db = rusqlite::Connection::open(&game_path).unwrap();
    for name in [
        format!("handoff_{}", k.index),
        format!("issued_recovery_route_{id}"),
    ] {
        let saved: Vec<u8> = db
            .query_row("SELECT value FROM meta WHERE name=?", [&name], |row| {
                row.get(0)
            })
            .unwrap();
        db.execute("DELETE FROM meta WHERE name=?", [&name])
            .unwrap();
        assert!(
            hc.open_active(Config::default(), bus.clone())
                .await
                .is_err(),
            "pending replacement reopened without {name}"
        );
        db.execute(
            "INSERT INTO meta VALUES(?,?)",
            rusqlite::params![name, saved],
        )
        .unwrap();
    }
    drop(db);
    let game = hc
        .open_active(Config::default(), bus.clone())
        .await
        .unwrap();
    let mut learner = lc
        .resume_learner(&identity, Config::default(), bus.clone())
        .await
        .unwrap();
    assert!(learner.joined_node().is_err());
    assert_eq!(lc.pending_join(&learner).unwrap(), raw);
    bus.0
        .lock()
        .unwrap()
        .insert(game.creator_node, game.node.raft.clone());
    bus.5
        .lock()
        .unwrap()
        .insert(game.creator_node, (game.node.promotion_authority(), key()));
    bus.1
        .lock()
        .unwrap()
        .insert(id, (game.creator_node, learner.replication()));
    game.node.raft.trigger().elect(true).await.unwrap();
    game.node
        .raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "recover pending Join")
        .await
        .unwrap();
    let mut transport = CreatorTransport {
        host: &game.node,
        learner: id,
        allow_recovery: false,
    };
    let result = lc
        .join_third_player(&mut learner, &identity, req, true, &mut transport)
        .await
        .unwrap();
    assert_eq!(Some(result.join.log_id), *pending.log_id());
    result.history.unwrap();
    assert_eq!(game.node.join_lobby(&raw).await.unwrap(), result.join);
    learner.shutdown().await.unwrap();
    game.node.raft.shutdown().await.unwrap();
}
