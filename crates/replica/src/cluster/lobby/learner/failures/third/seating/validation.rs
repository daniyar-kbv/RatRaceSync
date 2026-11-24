use super::*;
use ed25519_dalek::Signer;
use openraft::entry::RaftPayload;

fn signed(body: &[u8], key: &SigningKey) -> Signed {
    Signed(message(&[(1, body), (2, &key.sign(body).to_bytes())]))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_genuinely_eligible_historical_claim_can_receive_a_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(dir.path(), 2, crate::lobby::LobbyFormat::Seating).await)
            .await;
    let host = &p.game.node;
    let seat = SeatId::new(1).unwrap();
    let guard = host.seat_claim_guard(ACTOR, seat).await.unwrap();
    let claim = host
        .prepare_seat_claim(&guard, request(48), &key())
        .unwrap();
    let envelope = fields(&claim.0, &[1, 2]).unwrap();
    let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12]).unwrap();
    let reordered = message(&body.iter().rev().map(|(t, b)| (*t, *b)).collect::<Vec<_>>());
    let valid = signed(&reordered, &key());
    assert_ne!(valid.0, claim.0);
    let original = host.submit(valid.clone()).await.unwrap();
    assert_eq!(host.submit(claim.clone()).await.unwrap(), original);
    assert!(
        host.player_count_guard(ACTOR, rat_race_engine::LobbyCapacity::new(3).unwrap())
            .await
            .is_err()
    );
    assert!(host.seat_release_guard(ACTOR).await.is_err());
    assert!(
        host.seat_change_guard(ACTOR, SeatId::new(2).unwrap())
            .await
            .is_err()
    );
    let k = host.raft.metrics().borrow_watched().last_applied.unwrap();
    let mut guard = fields(body[&5], &[1, 2, 3, 4, 5]).unwrap();
    let observed = log_key(k);
    guard.insert(3, &observed);
    let mut fresh = body.clone();
    let g = message(&guard.into_iter().collect::<Vec<_>>());
    let other_request = request(49);
    fresh.insert(5, &g);
    fresh.insert(4, &other_request);
    let illegal = message(&fresh.into_iter().collect::<Vec<_>>());
    let mut duplicate = envelope[&1].to_vec();
    wire::field(&mut duplicate, 4, &other_request);
    let mut unknown = envelope[&1].to_vec();
    wire::field(&mut unknown, 99, b"x");
    for raw in [
        signed(&illegal, &key()),
        signed(&duplicate, &key()),
        signed(&unknown, &key()),
        signed(&reordered, &p.identity),
    ] {
        assert!(host.submit(raw.clone()).await.is_err());
        let mut id = k;
        id.index += 1;
        let entry = Entry {
            log_id: id,
            payload: Source::blank().with_normal(raw),
        };
        let mut db = host.replica.lock().unwrap();
        let tx = db.transaction().unwrap();
        assert!(host.replica.apply_in_transaction(&tx, &entry).is_err());
    }
    let replay = host.raft.client_write(claim).await.unwrap();
    assert_eq!(replay.data, original);
    {
        let db = host.replica.lock().unwrap();
        assert_eq!(host.replica.tip(&db, "event").unwrap().0, 3);
        assert_eq!(host.replica.tip(&db, "receipt").unwrap().0, 3);
    }
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn release_requires_present_empty_input_and_proven_original_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = finish_pair(
        Peers::with_profile(dir.path(), 2, crate::lobby::LobbyFormat::SeatChanges).await,
    )
    .await;
    let host = &p.game.node;
    let s = SeatId::new(1).unwrap();
    host.submit(
        host.seat_claim_guard(ACTOR, s)
            .await
            .unwrap()
            .sign(request(61), &key()),
    )
    .await
    .unwrap();
    let release = host
        .seat_release_guard(ACTOR)
        .await
        .unwrap()
        .sign(request(62), &key());
    let envelope = fields(&release.0, &[1, 2]).unwrap();
    let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12]).unwrap();
    assert_eq!(fields(body[&12], &[205]).unwrap()[&205], &[] as &[u8]);
    let guard = fields(body[&5], &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    let mut fake = guard.clone();
    fake.insert(6, &[2]);
    let fake = message(&fake.into_iter().collect::<Vec<_>>());
    let extra = message(&[(205, &message(&[(1, &[1])]))]);
    let mixed = message(&[(205, &[]), (206, &message(&[(1, &[2])]))]);
    let absent_target = message(&[(206, &[])]);
    let mut k = host.raft.metrics().borrow_watched().last_applied.unwrap();
    k.index += 1;
    for (tag, value) in [
        (12, &[][..]),
        (12, &extra),
        (12, &mixed),
        (12, &absent_target),
        (5, &fake),
        (3, b"guest".as_slice()),
    ] {
        let mut forged = body.clone();
        forged.insert(tag, value);
        let signer = if tag == 3 { p.identity.clone() } else { key() };
        let raw = signed(&message(&forged.into_iter().collect::<Vec<_>>()), &signer);
        assert!(host.submit(raw.clone()).await.is_err());
        let entry = Entry {
            log_id: k,
            payload: Source::blank().with_normal(raw),
        };
        let mut db = host.replica.lock().unwrap();
        let tx = db.transaction().unwrap();
        assert!(host.replica.apply_in_transaction(&tx, &entry).is_err());
        assert_eq!(host.replica.tip(&tx, "receipt").unwrap().0, 3);
    }
    let reordered_guard = message(&guard.into_iter().rev().collect::<Vec<_>>());
    let mut reordered = body.clone();
    reordered.insert(5, &reordered_guard);
    let alternate = signed(
        &message(&reordered.into_iter().rev().collect::<Vec<_>>()),
        &key(),
    );
    assert_ne!(alternate.0, release.0);
    let original = host.submit(alternate).await.unwrap();
    assert_eq!(host.submit(release).await.unwrap(), original);
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_preparation_recovers_committed_source_and_refuses_uuid_rebinding() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = finish_pair(
        Peers::with_profile(dir.path(), 2, crate::lobby::LobbyFormat::SeatChanges).await,
    )
    .await;
    let host = &p.game.node;
    let req = request(72);
    let first = host
        .seat_claim_guard(ACTOR, SeatId::new(1).unwrap())
        .await
        .unwrap();
    let second = host
        .seat_claim_guard(ACTOR, SeatId::new(2).unwrap())
        .await
        .unwrap();
    let canonical = first.sign(req, &key());
    let envelope = fields(&canonical.0, &[1, 2]).unwrap();
    let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12]).unwrap();
    let committed = signed(
        &message(&body.into_iter().rev().collect::<Vec<_>>()),
        &key(),
    );
    assert_ne!(canonical.0, committed.0);
    host.submit(committed.clone()).await.unwrap();
    assert!(host.prepare_seat_command(&second, req, &key()).is_err());
    let recovered = host.prepare_seat_command(&first, req, &key()).unwrap();
    assert_eq!(recovered.0, committed.0);
    assert_eq!(
        host.saved_seat_command(ACTOR, req, &key())
            .unwrap()
            .unwrap()
            .0,
        committed.0
    );
    {
        let db = host.replica.lock().unwrap();
        let n = db
            .execute(
                "UPDATE meta SET value=? WHERE name GLOB 'local_seat_claim_*'",
                [store::encode(&second.sign(req, &key())).unwrap()],
            )
            .unwrap();
        assert_eq!(n, 1);
    }
    assert!(host.saved_seat_command(ACTOR, req, &key()).is_err());
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_destination_write_rolls_back_source_and_replay_detects_changed_history() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = finish_pair(
        Peers::with_profile(dir.path(), 2, crate::lobby::LobbyFormat::SeatChanges).await,
    )
    .await;
    let host = &p.game.node;
    let one = SeatId::new(1).unwrap();
    let two = SeatId::new(2).unwrap();
    host.submit(
        host.seat_claim_guard(ACTOR, one)
            .await
            .unwrap()
            .sign(request(74), &key()),
    )
    .await
    .unwrap();
    let mv = host
        .seat_change_guard(ACTOR, two)
        .await
        .unwrap()
        .sign(request(75), &key());
    let before = host.lobby_seating(ACTOR).await.unwrap();
    {
        let mut db = host.replica.lock().unwrap();
        let mut id = store::meta::<LogId>(&db, "applied").unwrap().unwrap();
        id.index += 1;
        let tx = db.transaction().unwrap();
        tx.execute_batch("CREATE TEMP TRIGGER fail_destination BEFORE INSERT ON seat_history WHEN NEW.seat=2 BEGIN SELECT RAISE(FAIL,'destination write failed'); END").unwrap();
        let e = Entry {
            log_id: id,
            payload: Source::blank().with_normal(mv.clone()),
        };
        let err = host.replica.apply_in_transaction(&tx, &e).unwrap_err();
        assert!(err.to_string().contains("destination write failed"));
        tx.rollback().unwrap();
        host.replica.verify_replay(&db).unwrap();
        let tx = db.transaction().unwrap();
        assert_eq!(
            tx.execute(
                "UPDATE seat_history SET revision=? WHERE seat=1",
                [0u64.to_be_bytes()]
            )
            .unwrap(),
            1
        );
        assert!(host.replica.verify_replay(&tx).is_err());
    }
    assert_eq!(before, host.lobby_seating(ACTOR).await.unwrap());
    assert!(matches!(host.submit(mv).await.unwrap(), Reply::Receipt(_)));
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_resize_inputs_and_false_historical_guards_cannot_mint_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(dir.path(), 3, crate::lobby::LobbyFormat::Resizable).await)
            .await;
    let host = &p.game.node;
    let capacity = rat_race_engine::LobbyCapacity::new(2).unwrap();
    let guard = host.player_count_guard(ACTOR, capacity).await.unwrap();
    let req = request(89);
    let cmd = guard.sign(req, &key());
    let envelope = fields(&cmd.0, &[1, 2]).unwrap();
    let body = fields(envelope[&1], &[1, 2, 3, 4, 5, 12]).unwrap();
    let material = fields(body[&5], &[1, 2, 3, 4, 5]).unwrap();
    let mut bad_setup = material.clone();
    bad_setup.insert(5, &[0; 8]);
    let guest_id = p.learner.id();
    let mut guest = material.clone();
    guest.insert(1, &guest_id.0);
    let wrap = |n: u8| message(&[(203, &message(&[(1, &[n])]))]);
    let wrong_setup = message(&bad_setup.into_iter().collect::<Vec<_>>());
    let guest_guard = message(&guest.into_iter().collect::<Vec<_>>());
    for (leaf, g, actor, signer) in [
        (wrap(1), body[&5], ACTOR, key()),
        (wrap(11), body[&5], ACTOR, key()),
        (wrap(3), body[&5], ACTOR, key()),
        (wrap(2), wrong_setup.as_slice(), ACTOR, key()),
        (
            wrap(2),
            guest_guard.as_slice(),
            b"guest".as_slice(),
            p.identity.clone(),
        ),
    ] {
        let mut altered = body.clone();
        altered.insert(3, actor);
        altered.insert(5, g);
        altered.insert(12, &leaf);
        let raw = signed(&message(&altered.into_iter().collect::<Vec<_>>()), &signer);
        assert!(host.submit(raw.clone()).await.is_err());
        let mut db = host.replica.lock().unwrap();
        let mut k = store::meta::<LogId>(&db, "applied").unwrap().unwrap();
        k.index += 1;
        let tx = db.transaction().unwrap();
        let entry = Entry {
            log_id: k,
            payload: Source::blank().with_normal(raw),
        };
        assert!(host.replica.apply_in_transaction(&tx, &entry).is_err());
        assert_eq!(host.replica.tip(&tx, "receipt").unwrap().0, 2);
    }
    let other = host
        .seat_claim_guard(ACTOR, SeatId::new(1).unwrap())
        .await
        .unwrap()
        .sign(req, &key());
    host.submit(cmd.clone()).await.unwrap();
    assert_eq!(host.submit(other).await.unwrap(), Reply::RequestIdConflict);
    {
        let mut db = host.replica.lock().unwrap();
        let tx = db.transaction().unwrap();
        assert_eq!(
            tx.execute("UPDATE layout_history SET seats=x'0201'", [])
                .unwrap(),
            1
        );
        assert!(host.replica.verify_replay(&tx).is_err());
    }
    assert!(matches!(host.submit(cmd).await.unwrap(), Reply::Receipt(_)));
    p.shutdown().await;
}
