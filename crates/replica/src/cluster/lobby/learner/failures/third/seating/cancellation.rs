use super::*;
use crate::lobby::LobbyFormat;
use rat_race_engine::DreamId;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn elected_guest_requires_creator_signature_and_commit_order() {
    let dir = tempfile::tempdir().unwrap();
    let pair =
        finish_pair(Peers::with_profile(dir.path(), 3, LobbyFormat::Cancellable).await).await;
    let mut r = admit_to_pair(dir.path(), pair).await;
    r.recover().await;
    super::super::promotion::elect_second(&r).await;
    let leader = &r.p.learner.node;
    let host = &r.p.game.node;
    assert_eq!(leader.lobby_stage().await.unwrap(), LobbyStage::Open);
    let guard = leader.cancellation_witness(ACTOR).await.unwrap();
    assert!(
        leader
            .prepare_cancellation(ACTOR, &guard, request(125), &r.p.identity)
            .is_err()
    );
    let stale = host
        .prepare_cancellation(ACTOR, &guard, request(125), &key())
        .unwrap();
    let claim = leader
        .seat_claim_guard(b"guest", SeatId::new(2).unwrap())
        .await
        .unwrap()
        .sign(request(126), &r.p.identity);
    leader.submit(claim).await.unwrap();
    assert!(leader.submit(stale.clone()).await.is_err());
    let lost = receipt(leader.raft.client_write(stale).await.unwrap().data);
    assert!(
        fields(
            fields(&lost, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap()[&7],
            &[13]
        )
        .is_ok()
    );
    assert_eq!(leader.lobby_stage().await.unwrap(), LobbyStage::Open);
    let guard = leader.cancellation_witness(ACTOR).await.unwrap();
    let k = leader.raft.metrics().borrow_watched().last_applied.unwrap();
    host.raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(k.index), "creator has witnessed history")
        .await
        .unwrap();
    let cmd = host
        .prepare_cancellation(ACTOR, &guard, request(127), &key())
        .unwrap();
    let original = receipt(leader.submit(cmd.clone()).await.unwrap());
    assert_eq!(receipt(leader.submit(cmd).await.unwrap()), original);
    assert_eq!(leader.lobby_stage().await.unwrap(), LobbyStage::Cancelled);
    let end = leader.raft.metrics().borrow_watched().last_applied.unwrap();
    r.third
        .node
        .raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(end.index), "nonvoter learns terminal decision")
        .await
        .unwrap();
    assert_eq!(
        r.catalog.reconcile_learner_cancellation(&r.third).unwrap(),
        Some(original)
    );
    let session = r.p.game.session.clone();
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
    drop(r);
    let mut c = InstallationCatalog::open(&dir.path().join("third")).unwrap();
    assert!(
        c.open_cancelled_lobby(&session, Config::default(), Bus::default())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn catalog_crash_worker() {
    let Ok(path) = std::env::var("LOBBY_CANCEL_TEST_ROOT") else {
        return;
    };
    let mut catalog = InstallationCatalog::open(Path::new(&path)).unwrap();
    let h = create(&mut catalog, intent(2)).await.unwrap();
    let guard = h.node.cancel_lobby_guard(ACTOR).await.unwrap();
    let cmd = h
        .node
        .prepare_seat_command(&guard, request(119), &key())
        .unwrap();
    catalog.crash_stage = std::env::var("LOBBY_CANCEL_CRASH")
        .unwrap()
        .parse()
        .unwrap();
    if matches!(catalog.crash_stage, 1 | 2) {
        h.node
            .replica
            .crash
            .store(catalog.crash_stage, std::sync::atomic::Ordering::Release);
    }
    let record = receipt(h.node.submit(cmd).await.unwrap());
    std::fs::write(Path::new(&path).parent().unwrap().join("expected"), record).unwrap();
    catalog.reconcile_cancellation(&h.node).unwrap();
    panic!("catalog interruption was not reached");
}

fn crash_at(path: &Path, stage: u8, exit: i32) {
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(
            "cluster::lobby::learner::failures::third::seating::cancellation::catalog_crash_worker",
        )
        .env("LOBBY_CANCEL_TEST_ROOT", path)
        .env("LOBBY_CANCEL_CRASH", stage.to_string())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(exit));
}

#[tokio::test]
async fn lost_cancellation_reply_recovers_the_original_raft_entry_across_game_commit() {
    for stage in [1, 2] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("install");
        crash_at(&path, stage, 80 + i32::from(stage));
        let db = Connection::open(path.join("installation.sqlite")).unwrap();
        let (session, id): (Vec<u8>, [u8; 16]) = db
            .query_row("SELECT session,node FROM participation", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let game =
            Connection::open(path.join(format!("game-{}-g1.sqlite", ReplicaId(id)))).unwrap();
        let raw: Vec<u8> = game
            .query_row(
                "SELECT entry FROM raft_log ORDER BY idx DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let entry = store::decode::<Entry>(&raw).unwrap();
        let saved = Signed(entry.payload.bytes.strip_prefix(&[1]).unwrap().to_vec());
        let original: Option<Vec<u8>> = game
            .query_row(
                "SELECT record FROM receipt WHERE request=?",
                [request(119)],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(original.is_some(), stage == 2);
        drop(game);
        drop(db);
        let mut c = InstallationCatalog::open(&path).unwrap();
        let node = if stage == 1 {
            assert!(c.active_pin().unwrap().is_some());
            c.open_active(Config::default(), Bus::default())
                .await
                .unwrap()
                .node
        } else {
            assert!(c.active_pin().unwrap().is_none());
            Arc::new(
                c.open_cancelled_lobby(&session, Config::default(), Bus::default())
                    .await
                    .unwrap(),
            )
        };
        node.raft
            .wait(Some(Duration::from_secs(6)))
            .state(
                openraft::ServerState::Leader,
                "recover original cancellation",
            )
            .await
            .unwrap();
        let recovered = receipt(node.submit(saved).await.unwrap());
        assert_eq!(
            fields(&recovered, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap()[&5],
            log_key(entry.log_id)
        );
        if let Some(original) = original {
            assert_eq!(original, recovered);
        }
        assert_eq!(c.reconcile_cancellation(&node).unwrap(), Some(recovered));
        assert_eq!(c.active_pin().unwrap(), None);
        node.raft.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn catalog_restart_recovers_terminal_receipt_before_reusing_slot() {
    for (stage, exit) in [(41, 141), (42, 132)] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("install");
        crash_at(&path, stage, exit);
        let db = Connection::open(path.join("installation.sqlite")).unwrap();
        let table = if stage == 41 {
            "participation"
        } else {
            "closed_game"
        };
        let session: Vec<u8> = db
            .query_row(&format!("SELECT session FROM {table}"), [], |r| r.get(0))
            .unwrap();
        if stage == 41 {
            let pin: [u8; 32] = db
                .query_row("SELECT pin FROM participation", [], |r| r.get(0))
                .unwrap();
            db.execute("UPDATE participation SET pin=zeroblob(32)", [])
                .unwrap();
            assert!(InstallationCatalog::open(&path).is_err());
            assert_eq!(
                db.query_row("SELECT count(*) FROM participation", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
            db.execute("UPDATE participation SET pin=?", [pin]).unwrap();
        }
        drop(db);
        let mut c = InstallationCatalog::open(&path).unwrap();
        assert_eq!(c.active_pin().unwrap(), None);
        assert_eq!(
            c.confirmed_cancellation(&session).unwrap(),
            Some(std::fs::read(temp.path().join("expected")).unwrap())
        );
        let expected = std::fs::read(temp.path().join("expected")).unwrap();
        c.db.execute(
            "UPDATE closed_game SET receipt=x'00' WHERE session=?",
            [&session],
        )
        .unwrap();
        assert!(c.confirmed_cancellation(&session).is_err());
        c.db.execute(
            "UPDATE closed_game SET receipt=? WHERE session=?",
            rusqlite::params![expected, session],
        )
        .unwrap();
        let old = c
            .open_cancelled_lobby(&session, Config::default(), Bus::default())
            .await
            .unwrap();
        let cmd = old
            .saved_seat_command(ACTOR, request(119), &key())
            .unwrap()
            .unwrap();
        old.raft
            .wait(Some(Duration::from_secs(6)))
            .state(openraft::ServerState::Leader, "retained singleton history")
            .await
            .unwrap();
        assert_eq!(
            receipt(old.submit(cmd).await.unwrap()),
            c.confirmed_cancellation(&session).unwrap().unwrap()
        );
        assert!(old.cancel_lobby_guard(ACTOR).await.is_err());
        assert!(create(&mut c, intent(2)).await.is_err());
        let h = create(
            &mut c,
            CreateLobby {
                request: request(118),
                ..intent(2)
            },
        )
        .await
        .unwrap();
        assert_ne!(h.session, session);
        assert_eq!(
            c.reconcile_cancellation(&old).unwrap(),
            c.confirmed_cancellation(&session).unwrap()
        );
        assert_eq!(c.active_pin().unwrap(), Some(h.fingerprint));
        old.raft.shutdown().await.unwrap();
        h.node.raft.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creator_cancels_a_ready_lobby_and_each_installation_releases_its_own_slot() {
    let dir = tempfile::tempdir().unwrap();
    let pair =
        finish_pair(Peers::with_profile(dir.path(), 3, LobbyFormat::Cancellable).await).await;
    let mut r = admit_to_pair(dir.path(), pair).await;
    r.recover().await;
    let join = r.proposal().await.unwrap();
    let h = &r.p.game.node;
    let joined = h.join_lobby(&join).await.unwrap();
    assert_eq!(joined.member.ordinal, 3);
    let seat = SeatId::new(2).unwrap();
    h.submit(
        h.seat_claim_guard(ACTOR, seat)
            .await
            .unwrap()
            .sign(request(120), &key()),
    )
    .await
    .unwrap();
    for (n, action) in [
        (121, LobbyPreference::Dream(DreamId::new(4).unwrap())),
        (122, LobbyPreference::Ready(true)),
    ] {
        let cmd = super::readiness::guard(h, ACTOR, &key(), n, action, &key())
            .await
            .unwrap()
            .sign(request(n), &key());
        h.submit_preference(r.p.game.creator_node, cmd)
            .await
            .unwrap();
    }
    let guest = b"guest".as_slice();
    h.submit(
        h.seat_claim_guard(guest, SeatId::new(1).unwrap())
            .await
            .unwrap()
            .sign(request(130), &r.p.identity),
    )
    .await
    .unwrap();
    for (id, action) in [
        (131, LobbyPreference::Dream(DreamId::new(2).unwrap())),
        (132, LobbyPreference::Ready(true)),
    ] {
        let cmd = super::readiness::guard(h, guest, &r.p.identity, id, action, &key())
            .await
            .unwrap()
            .sign(request(id), &r.p.identity);
        h.submit_preference(r.p.learner.id(), cmd).await.unwrap();
    }
    let withdrawal = super::readiness::guard(
        h,
        guest,
        &r.p.identity,
        133,
        LobbyPreference::Ready(false),
        &key(),
    )
    .await
    .unwrap()
    .sign(request(133), &r.p.identity);
    assert!(h.cancel_lobby_guard(b"guest").await.is_err());
    let g = h.cancel_lobby_guard(ACTOR).await.unwrap();
    let raw = h.prepare_seat_command(&g, request(123), &key()).unwrap();
    let late = h
        .seat_release_guard(ACTOR)
        .await
        .unwrap()
        .sign(request(124), &key());
    let attempted = Arc::new(tokio::sync::Notify::new());
    *r.p.bus.6.lock().unwrap() = Some(PausedReplication {
        command: raw.0.clone(),
        attempted: attempted.clone(),
    });
    let pending = tokio::spawn({
        let h = h.clone();
        let cmd = raw.clone();
        async move { h.submit(cmd).await }
    });
    timeout(Duration::from_secs(5), attempted.notified())
        .await
        .unwrap();
    assert!(!pending.is_finished());
    assert_eq!(r.p._host.reconcile_cancellation(h).unwrap(), None);
    assert_eq!(r.p._host.active_pin().unwrap(), Some(r.p.game.fingerprint));
    // The third voter misses the decision. A connected majority still commits it.
    let link = r.p.bus.1.lock().unwrap().remove(&r.third.id()).unwrap();
    *r.p.bus.6.lock().unwrap() = None;
    let receipt0 = receipt(
        timeout(Duration::from_secs(6), pending)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        r.catalog.reconcile_cancellation(&r.third.node).unwrap(),
        None
    );
    assert_eq!(r.catalog.active_pin().unwrap(), Some(r.p.game.fingerprint));
    assert!(r.catalog.reconcile_cancellation(h).is_err());
    r.p.bus.1.lock().unwrap().insert(r.third.id(), link);
    assert_eq!(h.lobby_stage().await.unwrap(), LobbyStage::Cancelled);
    let effect = fields(
        super::changes::seat_effect(&receipt0, 210),
        &[1, 2, 3, 4, 5],
    )
    .unwrap();
    #[derive(Clone, PartialEq, prost::Message)]
    struct Closures {
        #[prost(bytes = "vec", repeated, tag = "1")]
        rows: Vec<Vec<u8>>,
    }
    let rows = <Closures as prost::Message>::decode(effect[&3])
        .unwrap()
        .rows;
    let expected = [
        (ACTOR, r.p.game.creator_node),
        (b"guest".as_slice(), r.p.learner.id()),
        (b"next-player".as_slice(), r.third.id()),
    ];
    assert_eq!(rows.len(), expected.len());
    for (i, (row, (actor, id))) in rows.iter().zip(expected).enumerate() {
        let f = fields(row, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]).unwrap();
        assert_eq!(
            (f[&1], f[&2], f[&3]),
            (
                actor,
                id.0.as_slice(),
                ((i + 1) as u32).to_be_bytes().as_slice()
            )
        );
        assert_eq!((f[&4], f[&5]), ([1].as_slice(), [2].as_slice()));
        assert!(f[&7].is_empty() && f[&12].is_empty() && f[&10] == [0]);
        if i < 2 {
            assert_eq!(f[&6], [2 - i as u8]);
            assert_eq!(f[&8], 1u64.to_be_bytes());
            assert_eq!(f[&9], [1]);
            assert_eq!(f[&11].len(), 8);
        } else {
            assert!(f[&6].is_empty() && f[&8].is_empty() && f[&11].is_empty() && f[&9] == [0]);
        }
    }
    assert_eq!(effect[&4], log_key(joined.log_id));
    assert_eq!(effect[&5], [0]);
    assert_eq!(effect[&1], [LobbyStage::Open as u8]);
    assert_eq!(effect[&2], [LobbyStage::Cancelled as u8]);
    assert!(h.lobby_seating(ACTOR).await.is_err());
    assert!(r.p.game.learner_invitation().is_err());
    assert!(h.submit(late.clone()).await.is_err());
    assert!(
        h.submit_preference(r.p.learner.id(), withdrawal.clone())
            .await
            .is_err()
    );
    for pending in [late, withdrawal] {
        let lost = receipt(h.raft.client_write(pending).await.unwrap().data);
        let f = fields(&lost, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert!(fields(f[&7], &[13]).is_ok() && f[&8].is_empty());
    }
    assert_eq!(receipt(h.submit(raw).await.unwrap()), receipt0);
    let k = h.raft.metrics().borrow_watched().last_applied.unwrap();
    for (node, catalog) in [
        (h.as_ref(), &mut r.p._host),
        (&r.p.learner.node, &mut r.p.catalog),
        (&r.third.node, &mut r.catalog),
    ] {
        node.raft
            .wait(Some(Duration::from_secs(6)))
            .applied_index_at_least(Some(k.index), "terminal replicated")
            .await
            .unwrap();
        assert_eq!(
            catalog.reconcile_cancellation(node).unwrap(),
            Some(receipt0.clone())
        );
        assert_eq!(
            catalog.reconcile_cancellation(node).unwrap(),
            Some(receipt0.clone())
        );
        assert_eq!(catalog.active_pin().unwrap(), None);
    }
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
}
