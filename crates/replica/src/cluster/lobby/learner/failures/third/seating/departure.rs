use super::*;
use crate::lobby::LobbyFormat;
use rat_race_engine::DreamId;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guest_leaves_three_voters_with_one_original_membership_receipt() {
    for second_leaves in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let pair =
            finish_pair(Peers::with_profile(root.path(), 3, LobbyFormat::Departure).await).await;
        let mut r = admit_to_pair(root.path(), pair).await;
        r.recover().await;
        let join = r.proposal().await.unwrap();
        let host = &r.p.game.node;
        let promotion = host.join_lobby(&join).await.unwrap();
        let (guest, key_g, actor, survivor, key_s) = if second_leaves {
            (
                &r.p.learner,
                &r.p.identity,
                b"guest".as_slice(),
                &r.third,
                &r.identity,
            )
        } else {
            (
                &r.third,
                &r.identity,
                b"next-player".as_slice(),
                &r.p.learner,
                &r.p.identity,
            )
        };
        host.submit(
            host.seat_claim_guard(actor, SeatId::new(2).unwrap())
                .await
                .unwrap()
                .sign(request(151), key_g),
        )
        .await
        .unwrap();
        for (n, act) in [
            (152, LobbyPreference::Dream(DreamId::new(3).unwrap())),
            (153, LobbyPreference::Ready(true)),
        ] {
            let intent = LobbyIntent::sign(&r.p.game.session, actor, request(n), act, key_g);
            let g = host
                .preference_guard(guest.id(), &intent, &key())
                .await
                .unwrap();
            host.submit_preference(guest.id(), g.sign(request(n), key_g))
                .await
                .unwrap();
        }
        host.submit(
            host.seat_claim_guard(ACTOR, SeatId::new(1).unwrap())
                .await
                .unwrap()
                .sign(request(146), &key()),
        )
        .await
        .unwrap();
        for (n, action) in [
            (147, LobbyPreference::Dream(DreamId::new(4).unwrap())),
            (148, LobbyPreference::Ready(true)),
        ] {
            let intent = LobbyIntent::sign(&r.p.game.session, ACTOR, request(n), action, &key());
            let guard = host
                .preference_guard(r.p.game.creator_node, &intent, &key())
                .await
                .unwrap();
            host.submit_preference(r.p.game.creator_node, guard.sign(request(n), &key()))
                .await
                .unwrap();
        }
        if second_leaves {
            let claim = host
                .seat_claim_guard(&survivor.actor, SeatId::new(3).unwrap())
                .await
                .unwrap();
            host.submit(claim.sign(request(149), key_s)).await.unwrap();
        }
        let before = host.lobby_seating(ACTOR).await.unwrap();
        let first_auditor = if second_leaves {
            survivor.actor.as_slice()
        } else {
            actor
        };
        assert_eq!(before.auditor_for(ACTOR), Some(first_auditor));
        assert_eq!(before.auditor_for(actor), Some(ACTOR));
        assert!(before.seats[0].ready && before.seats[1].ready);
        let high = crate::learner::history::boundary(&host.replica.lock().unwrap()).unwrap();
        for peer in [guest, survivor] {
            peer.node
                .raft
                .wait(Some(Duration::from_secs(6)))
                .applied_index_at_least(Some(high.index), "joined prefix")
                .await
                .unwrap();
        }
        assert!(host.leave_lobby_witness(ACTOR).await.is_err());
        let guard = host.leave_lobby_witness(actor).await.unwrap();
        let cmd = guest
            .joined_node()
            .unwrap()
            .prepare_leave_lobby(actor, &guard, request(154), key_g)
            .unwrap();
        assert!(host.submit(cmd.clone()).await.is_err());
        assert!(host.leave_approval(&cmd, &key()).is_err());
        host.reconcile_voting_history(high, &key(), async |q| {
            survivor
                .node
                .answer_history_request(r.p.game.creator_node, q, key_s)
        })
        .await
        .unwrap();
        let a = host.leave_approval(&cmd, &key()).unwrap();
        let b = survivor.node.leave_approval(&cmd, key_s).unwrap();
        assert!(guest.node.leave_approval(&cmd, key_g).is_err());
        assert!(host.leave_lobby(&cmd, [&a, &a]).await.is_err());
        let authority = guest.promotion_authority();
        let candidate =
            VoteRequest::<Types>::new(Vote::new(high.leader_id.term + 1, guest.id()), Some(high));
        if !second_leaves {
            // The departing installation can miss the membership entry entirely.
            guest.node.raft.runtime_config().elect(false);
            assert!(
                authority
                    .election(&candidate, true, key_g)
                    .unwrap()
                    .is_some()
            );
            r.p.bus.1.lock().unwrap().remove(&guest.id());
        }
        if second_leaves {
            let attempted = Arc::new(tokio::sync::Notify::new());
            *r.p.bus.6.lock().unwrap() = Some(PausedReplication {
                command: cmd.0.clone(),
                attempted: attempted.clone(),
            });
            let collision = host
                .seat_release_guard(actor)
                .await
                .unwrap()
                .sign(request(154), key_g);
            let pending = tokio::spawn({
                let (host, cmd, a, b) = (host.clone(), cmd.clone(), a.clone(), b.clone());
                async move { host.leave_lobby(&cmd, [&a, &b]).await }
            });
            timeout(Duration::from_secs(6), attempted.notified())
                .await
                .unwrap();
            pending.abort();
            assert!(pending.await.unwrap_err().is_cancelled());
            let delivery = host.submit(collision);
            tokio::pin!(delivery);
            assert!(
                timeout(Duration::from_millis(120), &mut delivery)
                    .await
                    .is_err()
            );
            r.p.bus.6.lock().unwrap().take();
            assert_eq!(
                timeout(Duration::from_secs(6), delivery)
                    .await
                    .unwrap()
                    .unwrap(),
                Reply::RequestIdConflict
            );
        }
        let (first, overlapping) = tokio::join!(
            host.leave_lobby(&cmd, [&a, &b]),
            host.leave_lobby(&cmd, [&a, &b])
        );
        let result = first.unwrap();
        assert_eq!(overlapping.unwrap(), result);
        assert_eq!(
            host.leave_lobby(&cmd, [&[0; 513], &[]]).await.unwrap(),
            result,
            "a committed retry does not depend on proposal attachments"
        );
        let view = host.lobby_seating(ACTOR).await.unwrap();
        assert!(view.seats.iter().all(|s| !s.ready));
        assert_eq!(view.seats[0].occupant.as_deref(), Some(ACTOR));
        assert_eq!(view.seats[0].revision, before.seats[0].revision);
        assert!(view.seats[1].occupant.is_none());
        assert_eq!(view.seats[1].revision, before.seats[1].revision + 1);
        assert_eq!(view.setup_revision, before.setup_revision + 1);
        assert_eq!(view.auditor_for(actor), None);
        assert_eq!(
            view.auditor_for(ACTOR),
            second_leaves.then_some(survivor.actor.as_slice())
        );
        assert_eq!(
            view.auditor_for(&survivor.actor),
            second_leaves.then_some(ACTOR)
        );
        assert!(host.lobby_seating(actor).await.is_err());
        assert!(
            host.answer_history_request(guest.id(), VotingHistoryRequest::Retained(high), &key())
                .is_err(),
            "a former voter cannot request old checkpoints from a surviving peer"
        );
        assert_eq!(host.raft.voter_ids().count(), 2);
        assert!(!host.raft.voter_ids().any(|v| v == guest.id()));
        assert_eq!(host.leave_lobby(&cmd, [&[], &[]]).await.unwrap(), result);
        let log = fields(&result, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap()[&5];
        let k = crate::learner::history::boundary(&host.replica.lock().unwrap()).unwrap();
        assert_eq!(log, log_key(k));
        let effect = fields(changes::seat_effect(&result, 209), &[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(effect[&1], actor);
        let membership = fields(effect[&2], &[1, 2, 3]).unwrap();
        assert_eq!(
            (membership[&1], membership[&2], membership[&3]),
            (guest.id().0.as_slice(), &[1][..], &[2][..])
        );
        let cleanup = fields(effect[&3], &[1, 2, 3, 4, 5, 6, 7]).unwrap();
        assert_eq!(cleanup[&1], &[2]);
        assert!(cleanup[&2].is_empty());
        assert_eq!(cleanup[&6], before.seats[1].revision.to_be_bytes());
        assert_eq!(cleanup[&7], view.seats[1].revision.to_be_bytes());
        let refs = fields(effect[&5], &[1, 2]).unwrap();
        assert_eq!(refs[&1], log_key(promotion.log_id));
        assert_eq!(refs[&2], log);
        {
            let mut db = host.replica.lock().unwrap();
            let entry: Vec<u8> = db
                .query_row(
                    "SELECT l.entry FROM raft_log l JOIN archive a USING(idx) WHERE a.log_id=?",
                    [log],
                    |row| row.get(0),
                )
                .unwrap();
            let entry: Entry = store::decode(&entry).unwrap();
            let packet = fields(
                entry.payload.leave_source().unwrap().unwrap(),
                &[1, 2, 3, 4],
            )
            .unwrap();
            assert_eq!(packet[&2], cmd.0);
            assert_eq!(packet[&3], a);
            assert_eq!(packet[&4], b);
            // A protocol-only registration cannot restore the departed incarnation.
            use openraft::entry::RaftPayload;
            let mut registration = entry;
            registration.log_id.index += 1;
            registration.payload = Source::blank().with_membership(Members::new_with_defaults(
                vec![[r.p.game.creator_node, survivor.id()].into()],
                [guest.id()],
            ));
            let tx = db.transaction().unwrap();
            assert!(
                host.replica
                    .apply_in_transaction(&tx, &registration)
                    .is_err()
            );
        }
        assert!(k.index > promotion.log_id.index);
        survivor
            .node
            .raft
            .wait(Some(Duration::from_secs(6)))
            .applied_index_at_least(Some(k.index), "survivor applies departure")
            .await
            .unwrap();
        host.reconcile_voting_history(k, &key(), async |q| {
            survivor
                .node
                .answer_history_request(r.p.game.creator_node, q, key_s)
        })
        .await
        .unwrap();
        assert!(host.voting_history_complete(k).unwrap());
        assert_eq!(
            guest.pending_lobby_leave(request(154), key_g).unwrap().0,
            cmd.0
        );
        let envelope = fields(&cmd.0, &[1, 2]).unwrap();
        let retry = Signed(message(&[(2, envelope[&2]), (1, envelope[&1])]));
        assert_ne!(retry.0, cmd.0);
        assert_eq!(host.leave_lobby(&retry, [&[], &[]]).await.unwrap(), result);
        let host_confirmation = host.leave_confirmation(&retry, &key()).unwrap();
        let guest_confirmation = survivor.node.leave_confirmation(&retry, key_s).unwrap();
        let catalog = if second_leaves {
            &mut r.p.catalog
        } else {
            &mut r.catalog
        };
        assert!(
            catalog
                .finish_lobby_leave(guest, &retry, [&host_confirmation, &host_confirmation])
                .is_err()
        );
        assert_eq!(catalog.active_pin().unwrap(), Some(r.p.game.fingerprint));
        if second_leaves {
            catalog
                .db
                .execute_batch(
                    "CREATE TEMP TRIGGER interrupt_release BEFORE DELETE ON learner
                BEGIN SELECT RAISE(ABORT, 'interrupted catalog write'); END",
                )
                .unwrap();
            assert!(
                catalog
                    .finish_lobby_leave(guest, &retry, [&host_confirmation, &guest_confirmation])
                    .is_err()
            );
            assert_eq!(catalog.active_pin().unwrap(), Some(r.p.game.fingerprint));
        } else {
            for attempt in 0..2 {
                if attempt == 1 {
                    let game = guest.node.replica.lock().unwrap();
                    assert_eq!(
                        game.execute(
                            "DELETE FROM meta WHERE name=?",
                            [crate::seating::departure::confirmation::LOCAL],
                        )
                        .unwrap(),
                        1
                    );
                }
                assert_eq!(
                    catalog
                        .finish_lobby_leave(
                            guest,
                            &retry,
                            [&host_confirmation, &guest_confirmation]
                        )
                        .unwrap(),
                    result
                );
            }
            assert!(catalog.active_pin().unwrap().is_none());
        }
        assert!(guest.joined_node().is_err());
        assert!(
            guest
                .node
                .answer_history_request(
                    r.p.game.creator_node,
                    VotingHistoryRequest::Retained(high),
                    key_g
                )
                .is_err(),
            "a released installation cannot continue serving voter RPCs"
        );
        assert!(guest.node.sign_voting_checkpoint(high, key_g).is_err());
        assert!(
            !matches!(authority.election(&candidate, true, key_g), Ok(Some(_))),
            "a cached promotion cannot sign a new election after local retirement"
        );
        drop(authority);
        let departed_id = guest.id();
        let departed_actor = actor.to_vec();
        let session = r.p.game.session.clone();
        let host_id = r.p.game.creator_node;
        let surviving_key = key_s.clone();
        let surviving_actor = survivor.actor.clone();
        let (remaining, departed) = if second_leaves {
            ("third", "receiver")
        } else {
            ("receiver", "third")
        };
        r.third.shutdown().await.unwrap();
        r.p.shutdown().await;
        drop(r);
        let mut departed_catalog = InstallationCatalog::open(&root.path().join(departed)).unwrap();
        assert_eq!(
            departed_catalog.departure_receipt(&session).unwrap(),
            Some(result.clone())
        );
        let game_path = root
            .path()
            .join(departed)
            .join(format!("learner-{departed_id}-g1.sqlite"));
        let game = rusqlite::Connection::open(&game_path).unwrap();
        assert_eq!(
            game.execute(
                "UPDATE seat_history SET revision=? WHERE occupant=?",
                rusqlite::params![99u64.to_be_bytes(), departed_actor]
            ),
            Ok(1)
        );
        assert!(
            departed_catalog.departure_receipt(&session).is_err(),
            "the confirmed seat closure must match the retained observation"
        );
        game.execute(
            "UPDATE seat_history SET revision=? WHERE occupant=?",
            rusqlite::params![before.seats[1].revision.to_be_bytes(), departed_actor],
        )
        .unwrap();
        game.execute(
            "UPDATE archive SET digest=zeroblob(32) WHERE idx=?",
            [0u64.to_be_bytes()],
        )
        .unwrap();
        assert!(
            departed_catalog.departure_receipt(&session).is_err(),
            "a saved signature cannot replace the retained genesis entry"
        );
        drop(game);
        let next = create(&mut departed_catalog, intent(2)).await.unwrap();
        assert_ne!(next.session, session);
        next.node.raft.shutdown().await.unwrap();

        // Lose the creator coordinator and its reply. The surviving guest alone
        // cannot confirm through Raft. The two restarted voters elect the guest.
        let bus = Bus::default();
        let mut sc = InstallationCatalog::open(&root.path().join(remaining)).unwrap();
        let survivor = sc
            .resume_learner(&surviving_key, Config::default(), bus.clone())
            .await
            .unwrap();
        let leader = survivor.joined_node().unwrap();
        assert!(!matches!(
            timeout(
                Duration::from_millis(350),
                leader.leave_lobby(&cmd, [&[], &[]])
            )
            .await,
            Ok(Ok(_))
        ));
        let mut hc = InstallationCatalog::open(&root.path().join("creator")).unwrap();
        let h = hc
            .open_active(
                Config {
                    enable_elect: false,
                    enable_heartbeat: false,
                    ..Config::default()
                },
                bus.clone(),
            )
            .await
            .unwrap();
        bus.0.lock().unwrap().insert(host_id, h.node.raft.clone());
        bus.1
            .lock()
            .unwrap()
            .insert(survivor.id(), (host_id, survivor.replication()));
        leader.raft.trigger().elect(true).await.unwrap();
        leader
            .raft
            .wait(Some(Duration::from_secs(8)))
            .state(openraft::ServerState::Leader, "surviving guest elected")
            .await
            .unwrap();
        assert_eq!(leader.leave_lobby(&cmd, [&[], &[]]).await.unwrap(), result);
        let target = SeatId::new(2).unwrap();
        let seat = if second_leaves {
            leader.seat_change_guard(&surviving_actor, target).await
        } else {
            leader.seat_claim_guard(&surviving_actor, target).await
        }
        .unwrap();
        leader
            .submit(seat.sign(request(155), &surviving_key))
            .await
            .unwrap();
        assert_eq!(
            leader.lobby_seating(ACTOR).await.unwrap().seats[1]
                .occupant
                .as_deref(),
            Some(surviving_actor.as_slice())
        );
        survivor.shutdown().await.unwrap();
        h.node.raft.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn departing_guest_leader_needs_both_successors_even_with_old_majority() {
    let root = tempfile::tempdir().unwrap();
    let pair = finish_pair(Peers::with_profile(root.path(), 3, LobbyFormat::Departure).await).await;
    let mut r = admit_to_pair(root.path(), pair).await;
    r.recover().await;
    let join = r.proposal().await.unwrap();
    let host = &r.p.game.node;
    let joining = host.join_lobby(&join).await.unwrap();
    let third = &r.third.node;
    let second = &r.p.learner.node;
    third
        .raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(joining.log_id.index), "third joined")
        .await
        .unwrap();
    third.raft.runtime_config().elect(false);
    super::super::promotion::elect_second(&r).await;
    let guard = second.leave_lobby_witness(b"guest").await.unwrap();
    let cmd = second
        .prepare_leave_lobby(b"guest", &guard, request(156), &r.p.identity)
        .unwrap();
    let high = crate::learner::history::boundary(&second.replica.lock().unwrap()).unwrap();
    host.reconcile_voting_history(high, &key(), async |q| {
        third.answer_history_request(r.p.game.creator_node, q, &r.identity)
    })
    .await
    .unwrap();
    let a = host.leave_approval(&cmd, &key()).unwrap();
    let b = third.leave_approval(&cmd, &r.identity).unwrap();
    let attempted = Arc::new(tokio::sync::Notify::new());
    *r.p.bus.6.lock().unwrap() = Some(PausedReplication {
        command: cmd.0.clone(),
        attempted: attempted.clone(),
    });
    let send = second.leave_lobby(&cmd, [&a, &b]);
    tokio::pin!(send);
    tokio::select! {
        reply = &mut send => panic!("Leave completed with the third voter partitioned: {reply:?}"),
        observed = timeout(Duration::from_secs(6), attempted.notified()) => observed.unwrap(),
    }
    for node in [&**host, second, third] {
        let db = node.replica.lock().unwrap();
        assert!(
            crate::seating::departure::left_at(&db, u64::MAX)
                .unwrap()
                .is_none()
        );
        let receipts: i64 = db
            .query_row(
                "SELECT count(*) FROM receipt WHERE actor=? AND request=?",
                rusqlite::params![b"guest".as_slice(), request(156)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(receipts, 0);
    }
    assert_eq!(
        r.p.catalog.active_pin().unwrap(),
        Some(r.p.game.fingerprint)
    );
    r.p.bus.6.lock().unwrap().take();
    // The requester can lose the reply when its coordinator steps down.
    let _reply = timeout(Duration::from_secs(8), &mut send).await;
    let next = high.index + 1;
    for node in [&**host, third] {
        node.raft
            .wait(Some(Duration::from_secs(8)))
            .log_index_at_least(Some(next), "survivor retains Leave")
            .await
            .unwrap();
    }
    r.p.learner.shutdown().await.unwrap();
    r.p.bus.1.lock().unwrap().remove(&r.p.learner.id());
    r.p.bus
        .1
        .lock()
        .unwrap()
        .insert(r.third.id(), (r.p.game.creator_node, r.third.replication()));
    host.raft.runtime_config().heartbeat(true);
    host.raft.runtime_config().elect(true);
    host.raft.trigger().elect(true).await.unwrap();
    host.raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "creator takes over")
        .await
        .unwrap();
    let original = host.leave_lobby(&cmd, [&[], &[]]).await.unwrap();
    let leave = fields(changes::seat_effect(&original, 209), &[1, 2, 3, 4, 5]).unwrap();
    let seat = fields(leave[&3], &[1, 2, 3, 4, 5, 6, 7]).unwrap();
    assert!(seat[&1].is_empty() && seat[&6].is_empty() && seat[&7].is_empty());
    let references = fields(leave[&5], &[1, 2]).unwrap();
    let ack = crate::lobby::frame(&[b"guest", &[0], &[0], &[], &[]]);
    let facts = crate::lobby::frame(&[
        b"guest",
        &r.p.learner.id().0,
        &[1],
        &[2],
        &[],
        &[],
        &[],
        &[],
        &ack,
        seat[&4],
        seat[&5],
        &[],
        references[&1],
        references[&2],
    ]);
    let link: Vec<u8> = host
        .replica
        .lock()
        .unwrap()
        .query_row(
            "SELECT record FROM semantic_link WHERE ledger='event' ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        link.ends_with(&crate::lobby::frame(&[&facts])),
        "event link must frame typed departure facts"
    );
    assert_eq!(host.raft.voter_ids().count(), 2);
    assert_eq!(host.leave_lobby(&cmd, [&[], &[]]).await.unwrap(), original);
    r.third.shutdown().await.unwrap();
    host.raft.shutdown().await.unwrap();
}
