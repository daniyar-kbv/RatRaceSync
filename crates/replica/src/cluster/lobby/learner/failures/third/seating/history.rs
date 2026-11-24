use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn newer_player_replays_claims_and_receipt_only_races_before_joining() {
    let dir = tempfile::tempdir().unwrap();
    let p = Peers::with_profile(dir.path(), 3, crate::lobby::LobbyFormat::Seating).await;
    let host = &p.game.node;
    let first = SeatId::new(1).unwrap();
    let second = SeatId::new(2).unwrap();
    // The unjoined guest cannot claim a seat; the host can claim before Join.
    assert!(host.seat_claim_guard(b"guest", first).await.is_err());
    let g = host.seat_claim_guard(ACTOR, first).await.unwrap();
    let alternative = host.seat_claim_guard(ACTOR, second).await.unwrap();
    let a = host.prepare_seat_claim(&g, request(40), &key()).unwrap();
    let b = host
        .prepare_seat_claim(&alternative, request(41), &key())
        .unwrap();
    host.submit(a).await.unwrap();
    let late = host.raft.client_write(b).await.unwrap();
    let reply = receipt(late.data);
    let f = fields(&reply, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    assert!(fields(f[&7], &[13]).is_ok());
    let (p, join) = finish_pair(p).await;
    assert_eq!(join.member.ordinal, 2);
    assert_eq!(join.member.setup_revision, 3);
    let host = &p.game.node;
    let signed = host.seat_claim_guard(b"guest", second).await.unwrap();
    let raw = p
        .learner
        .joined_node()
        .unwrap()
        .prepare_seat_claim(&signed, request(42), &p.identity)
        .unwrap();
    let original = host.submit(raw.clone()).await.unwrap();
    let k = host.raft.metrics().borrow_watched().last_applied.unwrap();
    p.learner
        .node
        .raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(k.index), "seat replicated")
        .await
        .unwrap();
    host.certify_recovery_tail(&key(), async |q| {
        p.learner
            .node
            .answer_history_request(p.game.creator_node, q, &p.identity)
    })
    .await
    .unwrap();
    let mut r = admit_to_pair(dir.path(), (p, join.clone())).await;
    r.recover().await;
    assert_eq!(r.catalog.recovered_join(&r.third).unwrap().unwrap(), join);
    let third = r.proposal().await.unwrap();
    let host = &r.p.game.node;
    let added = host.join_lobby(&third).await.unwrap();
    assert_eq!((added.member.ordinal, added.member.setup_revision), (3, 5));
    r.third
        .node
        .raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(added.log_id.index), "third applied")
        .await
        .unwrap();
    assert_eq!(host.submit(raw).await.unwrap(), original);
    let state = host.lobby_seating(ACTOR).await.unwrap();
    assert_eq!(state.setup_revision, 5);
    assert_eq!(state.seats[0].occupant.as_deref(), Some(ACTOR));
    assert_eq!(
        state.seats[1].occupant.as_deref(),
        Some(b"guest".as_slice())
    );
    assert_eq!(state.seats[2].revision, 0);
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn older_lobby_rejects_claims_and_preserves_its_signed_root() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = joined_pair(dir.path(), 2).await;
    assert!(
        p.game
            .node
            .seat_claim_guard(ACTOR, SeatId::new(1).unwrap())
            .await
            .is_err()
    );
    let pin = p.game.fingerprint;
    p.shutdown().await;
    p.bus.0.lock().unwrap().clear();
    p.bus.1.lock().unwrap().clear();
    drop(p);
    let mut catalog = InstallationCatalog::open(&dir.path().join("creator")).unwrap();
    let reopened = catalog
        .open_active(Config::default(), Bus::default())
        .await
        .unwrap();
    assert_eq!(reopened.fingerprint, pin);
    assert_eq!(
        reopened.node.replica.profile(),
        b"RatRaceSync/Classic101/lobby/v2"
    );
    reopened.node.raft.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn learner_recovers_winning_occupancy_and_receipt_only_loser_after_a_move_race() {
    let dir = tempfile::tempdir().unwrap();
    let (p, join) = finish_pair(
        Peers::with_profile(dir.path(), 3, crate::lobby::LobbyFormat::SeatChanges).await,
    )
    .await;
    let host = &p.game.node;
    let one = SeatId::new(1).unwrap();
    let two = SeatId::new(2).unwrap();
    let three = SeatId::new(3).unwrap();
    let host_claim = host
        .seat_claim_guard(ACTOR, one)
        .await
        .unwrap()
        .sign(request(65), &key());
    // Acquiring and releasing an unrelated seat leaves this original eligible.
    host.submit(
        host.seat_claim_guard(b"guest", three)
            .await
            .unwrap()
            .sign(request(66), &p.identity),
    )
    .await
    .unwrap();
    host.submit(
        host.seat_release_guard(b"guest")
            .await
            .unwrap()
            .sign(request(67), &p.identity),
    )
    .await
    .unwrap();
    host.submit(host_claim).await.unwrap();
    let change = host
        .seat_change_guard(ACTOR, two)
        .await
        .unwrap()
        .sign(request(68), &key());
    let claim = host
        .seat_claim_guard(b"guest", two)
        .await
        .unwrap()
        .sign(request(69), &p.identity);
    for cmd in [&change, &claim] {
        assert!(host.replica.preflight(cmd).unwrap().is_none());
    }
    let (m, c) = tokio::join!(
        host.raft.client_write(change),
        host.raft.client_write(claim)
    );
    let (m, c) = (m.unwrap(), c.unwrap());
    let moved = m.log_id.index < c.log_id.index;
    let (winner, loser, op, owner) = if moved {
        (m, c, 206, ACTOR)
    } else {
        (c, m, 204, b"guest".as_slice())
    };
    let won = receipt(winner.data);
    let lost = receipt(loser.data);
    let f = fields(&lost, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    assert_eq!(fields(f[&7], &[13]).unwrap()[&13], [8, 1]);
    assert!(f[&8].is_empty());
    let view = host.lobby_seating(ACTOR).await.unwrap();
    assert_eq!(
        view.seats[0].occupant.as_deref(),
        if moved { None } else { Some(ACTOR) }
    );
    assert_eq!(view.seats[1].occupant.as_deref(), Some(owner));
    assert_eq!((view.seats[2].revision, view.setup_revision), (2, 6));
    p.learner
        .node
        .raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(loser.log_id.index), "seat race applied")
        .await
        .unwrap();
    host.certify_recovery_tail(&key(), async |req| {
        p.learner
            .node
            .answer_history_request(p.game.creator_node, req, &p.identity)
    })
    .await
    .unwrap();
    let mut r = admit_to_pair(dir.path(), (p, join)).await;
    r.recover().await;
    assert!(r.third.joined_node().is_err());
    {
        let db = r.third.node.replica.lock().unwrap();
        r.third.node.replica.verify_replay(&db).unwrap();
        for (seq, original) in [(6, &won), (7, &lost)] {
            let actual: Vec<u8> = db
                .query_row("SELECT record FROM receipt WHERE seq=?", [seq], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(&actual, original);
        }
        let actual: Vec<u8> = db
            .query_row("SELECT record FROM event WHERE seq=6", [], |row| row.get(0))
            .unwrap();
        let event = fields(&actual, &[1, 2, 3, 4, 5, 6, 7]).unwrap();
        assert_eq!(
            fields(event[&6], &[op]).unwrap()[&op],
            super::changes::seat_effect(&won, op)
        );
        assert_eq!(r.third.node.replica.tip(&db, "event").unwrap().0, 6);
    }
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
}
