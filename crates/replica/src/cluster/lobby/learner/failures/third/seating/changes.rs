use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn release_and_move_preserve_ownership_revisions_and_original_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) = finish_pair(
        Peers::with_profile(dir.path(), 3, crate::lobby::LobbyFormat::SeatChanges).await,
    )
    .await;
    let h = &p.game.node;
    let a = SeatId::new(1).unwrap();
    let b = SeatId::new(2).unwrap();
    assert!(h.seat_release_guard(ACTOR).await.is_err());
    assert!(h.seat_change_guard(ACTOR, b).await.is_err());
    let stale = h
        .seat_claim_guard(b"guest", a)
        .await
        .unwrap()
        .sign(request(52), &p.identity);
    let stale_actor = h
        .seat_claim_guard(ACTOR, SeatId::new(3).unwrap())
        .await
        .unwrap()
        .sign(request(60), &key());
    let claim = h
        .seat_claim_guard(ACTOR, a)
        .await
        .unwrap()
        .sign(request(53), &key());
    let original_claim = h.submit(claim.clone()).await.unwrap();
    assert!(h.seat_release_guard(b"guest").await.is_err());
    assert!(h.seat_change_guard(ACTOR, a).await.is_err());
    let old_release = h
        .seat_release_guard(ACTOR)
        .await
        .unwrap()
        .sign(request(54), &key());
    let move_guard = h.seat_change_guard(ACTOR, b).await.unwrap();
    let mv = h
        .prepare_seat_command(&move_guard, request(55), &key())
        .unwrap();
    let moved = receipt(h.submit(mv.clone()).await.unwrap());
    let effect = seat_effect(&moved, 206);
    let m = fields(effect, &[1, 2, 3, 4, 5]).unwrap();
    assert_eq!((m[&1], m[&2]), (&[1][..], &[2][..]));
    let occupancy = fields(m[&3], &[1, 2, 3, 4]).unwrap();
    assert_eq!(
        (occupancy[&1], occupancy[&2], occupancy[&3], occupancy[&4]),
        (ACTOR, &[][..], &[][..], ACTOR)
    );
    let rev = fields(m[&4], &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    for (tag, value) in [
        (1, 1u64),
        (2, 1),
        (3, 1),
        (4, 2),
        (5, 0),
        (6, 1),
        (7, 3),
        (8, 4),
    ] {
        assert_eq!(rev[&tag], value.to_be_bytes());
    }
    let release = h.seat_release_guard(ACTOR).await.unwrap();
    assert!(
        h.prepare_seat_command(&release, request(55), &key())
            .is_err()
    );
    assert_eq!(
        h.submit(release.sign(request(55), &key())).await.unwrap(),
        Reply::RequestIdConflict
    );
    let rel = h
        .prepare_seat_command(&release, request(56), &key())
        .unwrap();
    let released = receipt(h.submit(rel.clone()).await.unwrap());
    let r = fields(seat_effect(&released, 205), &[1, 2, 3, 4]).unwrap();
    assert_eq!((r[&1], r[&2]), (&[2][..], &[2][..]));
    let rev = fields(r[&3], &[1, 2, 3, 4, 5, 6]).unwrap();
    for (tag, value) in [(1, 1u64), (2, 1), (3, 1), (4, 2), (5, 4), (6, 5)] {
        assert_eq!(rev[&tag], value.to_be_bytes());
    }
    for ready in [m[&5], r[&4]] {
        let pair = fields(ready, &[1, 2]).unwrap();
        assert_eq!((pair[&1], pair[&2]), (&[0][..], &[0][..]));
    }
    let guest = h
        .seat_claim_guard(b"guest", a)
        .await
        .unwrap()
        .sign(request(57), &p.identity);
    for command in [old_release, stale, stale_actor] {
        assert!(h.submit(command.clone()).await.is_err());
        let lost = receipt(h.raft.client_write(command.clone()).await.unwrap().data);
        let f = fields(&lost, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert_eq!(fields(f[&7], &[13]).unwrap()[&13], [8, 1]);
        assert!(f[&8].is_empty());
        assert_eq!(receipt(h.submit(command).await.unwrap()), lost);
    }
    let view = h.lobby_seating(ACTOR).await.unwrap();
    assert_eq!((view.setup_revision, view.layout_revision), (5, 1));
    assert!(view.seats.iter().all(|s| s.occupant.is_none()));
    assert_eq!(
        view.seats.iter().map(|s| s.revision).collect::<Vec<_>>(),
        [2, 2, 0]
    );
    h.submit(guest).await.unwrap();
    h.raft.runtime_config().elect(false);
    h.raft.runtime_config().heartbeat(false);
    let peer = &p.learner.node;
    peer.raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "new leader")
        .await
        .unwrap();
    assert_eq!(peer.submit(claim).await.unwrap(), original_claim);
    assert_eq!(receipt(peer.submit(mv).await.unwrap()), moved);
    assert_eq!(receipt(peer.submit(rel).await.unwrap()), released);
    assert_eq!(
        peer.lobby_seating(ACTOR).await.unwrap().seats[0].revision,
        3
    );
    p.shutdown().await;
}
pub(super) fn seat_effect(receipt: &[u8], op: u32) -> &[u8] {
    let f = fields(receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    assert_eq!(f[&8].len(), 32);
    fields(fields(f[&7], &[12]).unwrap()[&12], &[op]).unwrap()[&op]
}
