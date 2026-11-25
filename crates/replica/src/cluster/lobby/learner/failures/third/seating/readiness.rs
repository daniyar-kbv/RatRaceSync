use super::*;
use crate::{LobbyIntent, LobbyPreference, lobby::LobbyFormat};
use rat_race_engine::{DreamId, LobbyCapacity};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certified_third_installation_replays_private_receipts_and_old_coordinator_witness() {
    let dir = tempfile::tempdir().unwrap();
    let (p, join) =
        finish_pair(Peers::with_profile(dir.path(), 3, LobbyFormat::DreamReady).await).await;
    let h = &p.game.node;
    let peer = p.game.creator_node;
    let choose = LobbyPreference::Dream(DreamId::new(3).unwrap());
    let cmd = guard(h, ACTOR, &key(), 60, choose, &key())
        .await
        .unwrap()
        .sign(request(60), &key());
    let receipt0 = receipt(h.submit_preference(peer, cmd.clone()).await.unwrap());
    h.submit(
        h.seat_claim_guard(ACTOR, SeatId::new(1).unwrap())
            .await
            .unwrap()
            .sign(request(61), &key()),
    )
    .await
    .unwrap();
    let initial = guard(h, ACTOR, &key(), 59, LobbyPreference::Ready(false), &key())
        .await
        .unwrap()
        .sign(request(59), &key());
    let initial_receipt = receipt(h.submit_preference(peer, initial.clone()).await.unwrap());
    let ready = guard(h, ACTOR, &key(), 62, LobbyPreference::Ready(true), &key())
        .await
        .unwrap();
    let k = h.raft.metrics().borrow_watched().last_applied.unwrap();
    p.learner
        .node
        .raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(k.index), "applied setup")
        .await
        .unwrap();
    h.certify_recovery_tail(&key(), async |q| {
        p.learner.node.answer_history_request(peer, q, &p.identity)
    })
    .await
    .unwrap();
    let mut r = admit_to_pair(dir.path(), (p, join)).await;
    r.recover().await;
    {
        let db = r.third.node.replica.lock().unwrap();
        r.third.node.replica.verify_replay(&db).unwrap();
        let original: Vec<u8> = db
            .query_row(
                "SELECT record FROM receipt WHERE actor=? AND request=?",
                rusqlite::params![ACTOR, request(60)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(original, receipt0);
        let log = fields(&initial_receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap()[&5];
        let (record, source): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT receipt.record,archive.source FROM receipt JOIN archive ON archive.log_id=?
                 WHERE receipt.actor=? AND receipt.request=?",
                rusqlite::params![log, ACTOR, request(59)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(record, initial_receipt);
        assert_eq!(source.strip_prefix(&[1]), Some(initial.0.as_slice()));
    }
    super::super::promotion::elect_second(&r).await;
    let second = &r.p.learner.node;
    assert_eq!(
        receipt(second.submit_preference(peer, cmd).await.unwrap()),
        receipt0
    );
    let raw = ready.sign(request(62), &key());
    assert!(
        second
            .submit_preference(peer, ready.sign(request(63), &key()))
            .await
            .is_err()
    );
    let ready_receipt = receipt(second.submit_preference(peer, raw.clone()).await.unwrap());
    assert!(
        guard(
            second,
            ACTOR,
            &key(),
            63,
            LobbyPreference::Ready(false),
            &key()
        )
        .await
        .is_err()
    );
    let off = guard(
        second,
        ACTOR,
        &key(),
        63,
        LobbyPreference::Ready(false),
        &r.p.identity,
    )
    .await
    .unwrap();
    let withdraw = receipt(
        second
            .submit_preference(peer, off.sign(request(63), &key()))
            .await
            .unwrap(),
    );
    let facts = fields(
        super::changes::seat_effect(&withdraw, 208),
        &[1, 2, 3, 4, 5, 6, 7],
    )
    .unwrap();
    assert_eq!((facts[&1], facts[&2]), (&[1][..], &[0][..]));
    assert_eq!(
        receipt(second.submit_preference(peer, raw).await.unwrap()),
        ready_receipt
    );
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_ready_after_dream_or_seat_change_consumes_one_receipt_only() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(dir.path(), 3, LobbyFormat::DreamReady).await).await;
    let h = &p.game.node;
    let peer = p.game.creator_node;
    let select = |n| LobbyPreference::Dream(DreamId::new(n).unwrap());
    let d = guard(h, ACTOR, &key(), 70, select(5), &key())
        .await
        .unwrap();
    h.submit_preference(peer, d.sign(request(70), &key()))
        .await
        .unwrap();
    h.submit(
        h.seat_claim_guard(ACTOR, SeatId::new(1).unwrap())
            .await
            .unwrap()
            .sign(request(71), &key()),
    )
    .await
    .unwrap();
    for (n, seat_race) in [(72, false), (75, true)] {
        let g = guard(h, ACTOR, &key(), n, LobbyPreference::Ready(true), &key())
            .await
            .unwrap();
        let raw = g.sign(request(n), &key());
        assert!(h.replica.preflight(&raw).unwrap().is_none());
        if seat_race {
            h.submit(
                h.seat_release_guard(ACTOR)
                    .await
                    .unwrap()
                    .sign(request(n + 1), &key()),
            )
            .await
            .unwrap();
        } else {
            let d = guard(h, ACTOR, &key(), n + 1, select(6), &key())
                .await
                .unwrap();
            h.submit_preference(peer, d.sign(request(n + 1), &key()))
                .await
                .unwrap();
        }
        let tips = || {
            let db = h.replica.lock().unwrap();
            (
                h.replica.tip(&db, "event").unwrap(),
                h.replica.tip(&db, "receipt").unwrap(),
            )
        };
        let before = tips();
        assert!(h.submit_preference(peer, raw.clone()).await.is_err());
        let original = receipt(h.raft.client_write(raw.clone()).await.unwrap().data);
        let r = fields(&original, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert!(r[&8].is_empty() && fields(r[&7], &[13]).is_ok());
        assert_eq!(
            receipt(h.submit_preference(peer, raw).await.unwrap()),
            original
        );
        let after = tips();
        assert_eq!(after.0, before.0);
        assert_eq!(after.1.0, before.1.0 + 1);
    }
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_setup_requires_explicit_boolean_and_request_bound_private_witness() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(dir.path(), 3, LobbyFormat::DreamReady).await).await;
    let h = &p.game.node;
    let peer = p.game.creator_node;
    let d = guard(
        h,
        ACTOR,
        &key(),
        80,
        LobbyPreference::Dream(DreamId::new(7).unwrap()),
        &key(),
    )
    .await
    .unwrap();
    h.submit_preference(peer, d.sign(request(80), &key()))
        .await
        .unwrap();
    h.submit(
        h.seat_claim_guard(ACTOR, SeatId::new(1).unwrap())
            .await
            .unwrap()
            .sign(request(81), &key()),
    )
    .await
    .unwrap();
    let g = guard(h, ACTOR, &key(), 82, LobbyPreference::Ready(false), &key())
        .await
        .unwrap();
    let raw = g.sign(request(82), &key());
    let env = fields(&raw.0, &[1, 2]).unwrap();
    let b = fields(env[&1], &[1, 2, 3, 4, 5, 12]).unwrap();
    let bad = |operation: Vec<u8>, material: &[u8]| {
        let body = message(&[
            (1, b[&1]),
            (2, b[&2]),
            (3, b[&3]),
            (4, b[&4]),
            (5, material),
            (12, &operation),
        ]);
        Signed(message(&[(1, &body), (2, &key().sign(&body).to_bytes())]))
    };
    let k = h.raft.metrics().borrow_watched().last_applied;
    for op in [
        message(&[(208, &[])]),
        message(&[(208, &message(&[(1, &[2])]))]),
        message(&[(207, &message(&[(1, &[24])]))]),
        message(&[(207, &message(&[(1, &[3])]))]),
        message(&[(208, &message(&[(1, &[1])]))]),
    ] {
        assert!(h.submit_preference(peer, bad(op, b[&5])).await.is_err());
    }
    let mut m = fields(b[&5], &[1, 2, 3, 4, 5, 6, 7]).unwrap();
    assert_eq!(m[&6].len(), 64);
    m.insert(6, &[0; 64]);
    assert!(
        h.submit_preference(
            peer,
            bad(
                b[&12].to_vec(),
                &message(&m.into_iter().collect::<Vec<_>>())
            )
        )
        .await
        .is_err()
    );
    assert!(
        h.submit_preference(peer, g.sign(request(83), &key()))
            .await
            .is_err()
    );
    assert_eq!(h.raft.metrics().borrow_watched().last_applied, k);
    // A first acknowledgment is a material change even when the effective Boolean is false.
    let ack = receipt(h.submit_preference(peer, raw).await.unwrap());
    assert!(
        fields(
            super::changes::seat_effect(&ack, 208),
            &[1, 2, 3, 4, 5, 6, 7]
        )
        .is_ok()
    );
    let eq = guard(h, ACTOR, &key(), 84, LobbyPreference::Ready(false), &key())
        .await
        .unwrap()
        .sign(request(84), &key());
    assert_eq!(
        h.submit_preference(peer, eq.clone()).await.unwrap(),
        Reply::AlreadyCurrent
    );
    let r = receipt(h.raft.client_write(eq).await.unwrap().data);
    let f = fields(&r, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    let w = fields(
        fields(fields(f[&7], &[14]).unwrap()[&14], &[208]).unwrap()[&208],
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    )
    .unwrap();
    assert_eq!((w[&2], w[&3], w[&4]), (&[0][..], &[0][..], &[0][..]));
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actor_installation_reserves_original_using_only_portable_witness() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(dir.path(), 3, LobbyFormat::DreamReady).await).await;
    let h = &p.game.node;
    let guest = p.learner.joined_node().unwrap();
    let choose = LobbyPreference::Dream(DreamId::new(13).unwrap());
    let intent = LobbyIntent::sign(
        &h.replica.session,
        b"guest",
        request(95),
        choose,
        &p.identity,
    );
    assert!(
        h.preference_witness(p.game.creator_node, &intent, &key())
            .await
            .is_err()
    );
    let witness = h
        .preference_witness(p.learner.id(), &intent, &key())
        .await
        .unwrap();
    // A viewer may know the initial signed Create and all 23 possible IDs.
    // A detached witness must not let that viewer verify a guess about a guest.
    let public = fields(&witness, &[1, 2, 3, 4, 5, 6]).unwrap();
    let sig = ed25519_dalek::Signature::from_slice(public[&6]).unwrap();
    let (revision, create): ([u8; 32], [u8; 32]) = h
        .replica
        .lock()
        .unwrap()
        .query_row(
            "SELECT log_id,digest FROM archive WHERE event_count=1 ORDER BY idx LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let mut expected_fingerprint = None;
    for guess in 1..=23 {
        let private_scope = crate::lobby::frame(&[
            b"setup-private-dependency/v1",
            h.replica.profile(),
            &h.replica.session,
            b"guest",
            &request(95),
            public[&1],
            public[&2],
            public[&3],
            public[&4],
            &207u16.to_be_bytes(),
            &[guess],
            public[&5],
            &[],
            &0u64.to_be_bytes(),
            &[],
            &[0],
            &[],
            &revision,
        ]);
        if guess == 13 {
            expected_fingerprint = Some(crate::wire::hash(
                b"player-setup-intent/v1",
                &[&private_scope],
            ));
        }
        assert!(
            key()
                .verifying_key()
                .verify_strict(&private_scope, &sig)
                .is_err(),
            "detached witness verifies guess {guess}"
        );
        let actual =
            crate::lobby::frame(&[b"setup-witness/v1", &private_scope, &create, &intent.0]);
        assert_eq!(
            key().verifying_key().verify_strict(&actual, &sig).is_ok(),
            guess == 13
        );
        let without_proof =
            crate::lobby::frame(&[b"setup-witness/v1", &private_scope, &create, &[]]);
        assert!(
            key()
                .verifying_key()
                .verify_strict(&without_proof, &sig)
                .is_err()
        );
    }
    let raw = guest
        .prepare_preference(&intent, &witness, &p.identity)
        .unwrap();
    assert_eq!(
        raw.0,
        guest
            .prepare_preference(&intent, &witness, &p.identity)
            .unwrap()
            .0
    );
    assert!(h.prepare_preference(&intent, &witness, &key()).is_err());
    let r = receipt(h.submit_preference(p.learner.id(), raw).await.unwrap());
    assert_eq!(
        fields(&r, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap()[&4],
        expected_fingerprint.unwrap()
    );
    let e = fields(super::changes::seat_effect(&r, 207), &[1, 2, 3, 4, 5]).unwrap();
    assert_eq!(e[&2], &[] as &[u8]);
    assert_eq!(e[&3], [13]);
    p.shutdown().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changing_an_acknowledged_dream_resets_only_its_owner_and_keeps_real_private_facts() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(dir.path(), 3, LobbyFormat::DreamReady).await).await;
    let h = &p.game.node;
    let host = p.game.creator_node;
    let guest = p.learner.id();
    for (actor, k, seat, peer, n) in [
        (ACTOR, key(), 1, host, 100),
        (b"guest".as_slice(), p.identity.clone(), 2, guest, 103),
    ] {
        let dream = LobbyPreference::Dream(DreamId::new(3).unwrap());
        let cmd = guard(h, actor, &k, n, dream, &key())
            .await
            .unwrap()
            .sign(request(n), &k);
        h.submit_preference(peer, cmd).await.unwrap();
        h.submit(
            h.seat_claim_guard(actor, SeatId::new(seat).unwrap())
                .await
                .unwrap()
                .sign(request(n + 1), &k),
        )
        .await
        .unwrap();
    }
    for (actor, k, peer, n) in [
        (ACTOR, key(), host, 106),
        (b"guest".as_slice(), p.identity.clone(), guest, 107),
    ] {
        let cmd = guard(h, actor, &k, n, LobbyPreference::Ready(true), &key())
            .await
            .unwrap()
            .sign(request(n), &k);
        h.submit_preference(peer, cmd).await.unwrap();
    }
    let before = h.lobby_seating(ACTOR).await.unwrap();
    assert!(before.seats[..2].iter().all(|s| s.ready));
    let change = guard(
        h,
        ACTOR,
        &key(),
        108,
        LobbyPreference::Dream(DreamId::new(4).unwrap()),
        &key(),
    )
    .await
    .unwrap()
    .sign(request(108), &key());
    let result = receipt(h.submit_preference(host, change).await.unwrap());
    let actual = fields(super::changes::seat_effect(&result, 207), &[1, 2, 3, 4, 5]).unwrap();
    let flags = fields(actual[&5], &[1, 2]).unwrap();
    assert_eq!(
        (actual[&2], actual[&3], flags[&1], flags[&2]),
        (&[3][..], &[4][..], &[1][..], &[0][..])
    );
    let view = h.lobby_seating(b"guest").await.unwrap();
    assert_eq!(view.setup_revision, before.setup_revision + 1);
    assert!(!view.seats[0].ready && view.seats[1].ready);
    let read =
        crate::OwnPreferenceRead::sign(&h.replica.session, b"guest", request(109), &p.identity);
    assert_eq!(
        h.own_lobby_preference(guest, &read).await.unwrap().dream,
        DreamId::new(3)
    );
    assert!(h.own_lobby_preference(host, &read).await.is_err());
    p.shutdown().await;
}

pub(super) async fn guard(
    h: &GameNode,
    actor: &[u8],
    signer: &SigningKey,
    n: u8,
    action: LobbyPreference,
    leader: &SigningKey,
) -> io::Result<SeatCommandGuard> {
    let intent = LobbyIntent::sign(&h.replica.session, actor, request(n), action, signer);
    let peer = {
        let db = h.replica.lock()?;
        if actor == ACTOR {
            store::meta::<crate::genesis::Creator>(&db, "creator")?
                .unwrap()
                .node
        } else {
            store::meta::<JoinedMember>(&db, "first_member")?
                .unwrap()
                .node
        }
    };
    h.preference_guard(peer, &intent, leader).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_dreams_and_ready_follow_the_player_through_resize_and_seat_change() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(dir.path(), 3, LobbyFormat::DreamReady).await).await;
    let h = &p.game.node;
    let choose = LobbyPreference::Dream(DreamId::new(23).unwrap());
    assert!(DreamId::new(24).is_none());
    let ready = LobbyPreference::Ready(true);
    assert!(guard(h, ACTOR, &key(), 40, ready, &key()).await.is_err());
    for (a, k, n) in [
        (ACTOR, key(), 40),
        (b"guest".as_slice(), p.identity.clone(), 41),
    ] {
        let g = guard(h, a, &k, n, choose, &key()).await.unwrap();
        let peer = if a == ACTOR {
            p.game.creator_node
        } else {
            p.learner.id()
        };
        let cmd = g.sign(request(n), &k);
        assert!(h.submit(cmd.clone()).await.is_err());
        h.submit_preference(peer, cmd).await.unwrap();
        assert!(guard(h, a, &k, 42, choose, &key()).await.is_err());
    }
    assert!(
        guard(h, ACTOR, &p.identity, 42, ready, &key())
            .await
            .is_err()
    );
    let seat = SeatId::new(1).unwrap();
    h.submit(
        h.seat_claim_guard(ACTOR, seat)
            .await
            .unwrap()
            .sign(request(43), &key()),
    )
    .await
    .unwrap();
    let g = guard(h, ACTOR, &key(), 44, ready, &key()).await.unwrap();
    let raw = h.prepare_seat_command(&g, request(44), &key()).unwrap();
    let original = receipt(
        h.submit_preference(p.game.creator_node, raw.clone())
            .await
            .unwrap(),
    );
    let g = h
        .player_count_guard(ACTOR, LobbyCapacity::new(2).unwrap())
        .await
        .unwrap();
    let resize = receipt(h.submit(g.sign(request(45), &key())).await.unwrap());
    let e = fields(
        super::changes::seat_effect(&resize, 203),
        &[1, 2, 3, 4, 5, 6],
    )
    .unwrap();
    assert_eq!(
        fields(fields(e[&6], &[1]).unwrap()[&1], &[1, 2, 3]).unwrap()[&3],
        [1]
    );
    let equal = guard(h, ACTOR, &key(), 46, ready, &key())
        .await
        .unwrap()
        .sign(request(46), &key());
    let tips = || {
        let db = h.replica.lock().unwrap();
        (
            h.replica.tip(&db, "event").unwrap(),
            h.replica.tip(&db, "receipt").unwrap(),
        )
    };
    let chains = tips();
    let before = h.raft.metrics().borrow_watched().last_applied;
    assert_eq!(
        h.submit_preference(p.game.creator_node, equal.clone())
            .await
            .unwrap(),
        Reply::AlreadyCurrent
    );
    assert_eq!(h.raft.metrics().borrow_watched().last_applied, before);
    let committed = receipt(h.raft.client_write(equal.clone()).await.unwrap().data);
    let r = fields(&committed, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    assert!(r[&8].is_empty());
    let w = fields(
        fields(fields(r[&7], &[14]).unwrap()[&14], &[208]).unwrap()[&208],
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    )
    .unwrap();
    assert_eq!(
        (w[&1], w[&2], w[&3], w[&4]),
        (ACTOR, &[1][..], &[1][..], &[1][..])
    );
    assert_eq!((w[&5], w[&6]), (&[1][..], &[23][..]));
    let acknowledged = fields(&original, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap()[&5];
    assert_eq!(w[&10], &acknowledged[24..]);
    assert!(w[&11].is_empty());
    let after = tips();
    assert_eq!(chains.0, after.0);
    assert_eq!(after.1.0, chains.1.0 + 1);
    assert_eq!(
        receipt(
            h.submit_preference(p.game.creator_node, equal)
                .await
                .unwrap()
        ),
        committed
    );
    let mv = h
        .seat_change_guard(ACTOR, SeatId::new(2).unwrap())
        .await
        .unwrap();
    h.submit(mv.sign(request(47), &key())).await.unwrap();
    assert!(!h.lobby_seating(b"guest").await.unwrap().seats[1].ready);
    let read = crate::OwnPreferenceRead::sign(&h.replica.session, ACTOR, request(48), &key());
    assert!(h.own_lobby_preference(p.learner.id(), &read).await.is_err());
    let forged =
        crate::OwnPreferenceRead::sign(&h.replica.session, ACTOR, request(48), &p.identity);
    assert!(
        h.own_lobby_preference(p.game.creator_node, &forged)
            .await
            .is_err()
    );
    assert_eq!(
        h.own_lobby_preference(p.game.creator_node, &read)
            .await
            .unwrap()
            .dream,
        DreamId::new(23)
    );
    assert_eq!(
        receipt(
            h.submit_preference(p.game.creator_node, raw.clone())
                .await
                .unwrap()
        ),
        original
    );
    assert!(h.submit_preference(p.learner.id(), raw).await.is_err());
    p.shutdown().await;
}
