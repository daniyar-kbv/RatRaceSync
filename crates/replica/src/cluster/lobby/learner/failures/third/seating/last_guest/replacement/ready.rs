use super::*;
use crate::OwnPreferenceRead;
use rat_race_engine::DreamId;

async fn prepare(
    leader: &GameNode,
    owner: &GameNode,
    actor: &[u8],
    signer: &SigningKey,
    n: u8,
    action: LobbyPreference,
) -> io::Result<Signed> {
    let peer = owner.replica.local_node.unwrap();
    let intent = LobbyIntent::sign(&leader.replica.session, actor, request(n), action, signer);
    let witness = leader.preference_witness(peer, &intent, &key()).await?;
    let high = leader.raft.metrics().borrow_watched().last_applied.unwrap();
    owner
        .raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(high.index), "owner has witnessed setup")
        .await
        .unwrap();
    owner.prepare_preference(&intent, &witness, signer)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replacement_owns_its_seat_dream_and_ready_across_restart() {
    let root = tempfile::tempdir().unwrap();
    let (p, first) =
        finish_pair(Peers::with_profile(root.path(), 3, LobbyFormat::LastGuest).await).await;
    let vacancy = SeatId::new(2).unwrap();
    let retired_claim = p
        .game
        .node
        .seat_claim_guard(&p.learner.actor, vacancy)
        .await
        .unwrap();
    let (mut r, _) = admit_after_leave(root.path(), p, first).await;
    let host = &r.p.game.node;
    let retired = &r.p.learner;
    assert!(
        retired
            .node
            .saved_seat_claim(&retired.actor, request(170), &r.p.identity)
            .unwrap()
            .is_some()
    );
    assert!(
        retired
            .node
            .prepare_seat_claim(&retired_claim, request(191), &r.p.identity)
            .is_err(),
        "retired installation reserved a new seat claim"
    );
    assert!(
        host.submit(retired_claim.sign(request(191), &r.p.identity))
            .await
            .is_err()
    );
    let id = r.third.id();
    let creator = r.p.game.creator_node;
    let joined = r
        .catalog
        .join_third_player(
            &mut r.third,
            &r.identity,
            request(192),
            true,
            &mut CreatorTransport {
                host,
                learner: id,
                allow_recovery: true,
            },
        )
        .await
        .unwrap();
    joined.history.unwrap();
    let owner = r.third.joined_node().unwrap();
    let actor = r.third.actor.clone();
    let identity = r.identity.clone();
    let own_read = OwnPreferenceRead::sign(&host.replica.session, &actor, request(193), &identity);
    let creator_read = OwnPreferenceRead::sign(&host.replica.session, ACTOR, request(194), &key());
    let ready = LobbyPreference::Ready(true);
    let dream = |v| LobbyPreference::Dream(DreamId::new(v).unwrap());
    assert_eq!(
        host.own_lobby_preference(id, &own_read)
            .await
            .unwrap()
            .dream,
        None
    );
    assert!(
        prepare(host, owner, &actor, &identity, 195, ready)
            .await
            .is_err()
    );
    let guard = host.seat_claim_guard(&actor, vacancy).await.unwrap();
    assert!(
        host.submit(guard.sign(request(196), &r.p.identity))
            .await
            .is_err()
    );
    let claim = owner
        .prepare_seat_claim(&guard, request(196), &identity)
        .unwrap();
    let claim_receipt = receipt(host.submit(claim.clone()).await.unwrap());
    let mut seat_receipts = vec![(196, claim, claim_receipt)];
    assert!(
        prepare(host, owner, &actor, &identity, 195, ready)
            .await
            .is_err()
    );
    let d = prepare(host, owner, &actor, &identity, 197, dream(5))
        .await
        .unwrap();
    let d_receipt = receipt(host.submit_preference(id, d.clone()).await.unwrap());
    assert!(host.submit_preference(creator, d.clone()).await.is_err());
    assert!(
        host.submit_preference(retired.id(), d.clone())
            .await
            .is_err()
    );
    assert!(host.own_lobby_preference(creator, &own_read).await.is_err());
    assert!(
        host.own_lobby_preference(retired.id(), &own_read)
            .await
            .is_err()
    );
    assert_eq!(
        host.own_lobby_preference(creator, &creator_read)
            .await
            .unwrap()
            .dream,
        DreamId::new(3)
    );
    let host_ready = prepare(host, host, ACTOR, &key(), 198, ready)
        .await
        .unwrap();
    host.submit_preference(creator, host_ready).await.unwrap();

    let mut private_receipts = vec![(197, d, d_receipt)];
    for (n, move_seat) in [(200, false), (204, true)] {
        let current = prepare(host, owner, &actor, &identity, n + 1, ready)
            .await
            .unwrap();
        let original = receipt(host.submit_preference(id, current.clone()).await.unwrap());
        private_receipts.push((n + 1, current, original));
        let stale = prepare(host, owner, &actor, &identity, n, ready)
            .await
            .unwrap();
        let view = host.lobby_seating(ACTOR).await.unwrap();
        assert!(view.seats[0].ready && view.seats[1].ready);
        if move_seat {
            let change = host
                .seat_change_guard(&actor, SeatId::new(3).unwrap())
                .await
                .unwrap();
            let moved = owner
                .prepare_seat_command(&change, request(n + 2), &identity)
                .unwrap();
            let original = receipt(host.submit(moved.clone()).await.unwrap());
            seat_receipts.push((n + 2, moved, original));
        } else {
            let changed = prepare(host, owner, &actor, &identity, n + 2, dream(6))
                .await
                .unwrap();
            let original = receipt(host.submit_preference(id, changed.clone()).await.unwrap());
            private_receipts.push((n + 2, changed, original));
        }
        assert!(host.submit_preference(id, stale.clone()).await.is_err());
        // A command already in flight can still reach apply after its guard expires.
        let original = receipt(host.raft.client_write(stale.clone()).await.unwrap().data);
        let record = fields(&original, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert!(record[&8].is_empty() && fields(record[&7], &[13]).is_ok());
        private_receipts.push((n, stale, original));
        let view = host.lobby_seating(ACTOR).await.unwrap();
        assert!(view.seats[0].ready);
        assert!(!view.seats.iter().skip(1).any(|s| s.ready));
    }
    let final_ready = prepare(host, owner, &actor, &identity, 208, ready)
        .await
        .unwrap();
    let original = receipt(
        host.submit_preference(id, final_ready.clone())
            .await
            .unwrap(),
    );
    private_receipts.push((208, final_ready, original));
    let view = host.lobby_seating(ACTOR).await.unwrap();
    let high = host.raft.metrics().borrow_watched().last_applied.unwrap();
    owner
        .raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(high.index), "final Ready durable")
        .await
        .unwrap();
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
    drop(r);

    let bus = Bus::default();
    let mut hc = InstallationCatalog::open(&root.path().join("creator")).unwrap();
    let mut lc = InstallationCatalog::open(&root.path().join("third")).unwrap();
    let game = hc
        .open_active(Config::default(), bus.clone())
        .await
        .unwrap();
    let player = lc
        .resume_learner(&identity, Config::default(), bus.clone())
        .await
        .unwrap();
    bus.0
        .lock()
        .unwrap()
        .insert(creator, game.node.raft.clone());
    bus.1
        .lock()
        .unwrap()
        .insert(id, (creator, player.replication()));
    game.node.raft.runtime_config().elect(false);
    game.node.raft.runtime_config().heartbeat(false);
    let leader = player.joined_node().unwrap();
    leader.raft.trigger().elect(true).await.unwrap();
    leader
        .raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "replacement elected")
        .await
        .unwrap();
    let tips = |node: &GameNode| {
        let db = node.replica.lock().unwrap();
        (
            node.replica.tip(&db, "event").unwrap(),
            node.replica.tip(&db, "receipt").unwrap(),
        )
    };
    let before = tips(leader);
    for (n, cmd, original) in seat_receipts {
        let saved = leader
            .saved_seat_command(&actor, request(n), &identity)
            .unwrap()
            .unwrap();
        assert_eq!(saved.0, cmd.0);
        assert_eq!(receipt(leader.submit(saved).await.unwrap()), original);
    }
    for (n, cmd, original) in private_receipts {
        let saved = leader
            .saved_seat_command(&actor, request(n), &identity)
            .unwrap()
            .unwrap();
        assert_eq!(saved.0, cmd.0);
        assert_eq!(
            receipt(leader.submit_preference(id, saved).await.unwrap()),
            original
        );
    }
    assert_eq!(tips(leader), before);
    assert_eq!(tips(&game.node), before);
    let public = leader.lobby_seating(&actor).await.unwrap();
    assert_eq!(public.seats, view.seats);
    assert!(public.seats[0].ready && public.seats[2].ready);
    assert!(public.seats[1].occupant.is_none());
    assert_eq!(public.seats[2].occupant.as_deref(), Some(actor.as_slice()));
    let own = leader.own_lobby_preference(id, &own_read).await.unwrap();
    assert!(own.ready);
    assert_eq!(own.dream, DreamId::new(6));
    assert!(
        leader
            .own_lobby_preference(id, &creator_read)
            .await
            .is_err()
    );
    player.shutdown().await.unwrap();
    game.node.raft.shutdown().await.unwrap();
}
