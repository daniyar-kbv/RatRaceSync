use super::*;
use crate::lobby::LobbyFormat;
use rat_race_engine::LobbyCapacity;

fn count(n: u8) -> LobbyCapacity {
    LobbyCapacity::new(n).unwrap()
}
fn ids(view: &LobbySeatView) -> Vec<u8> {
    view.seats.iter().map(|seat| seat.id.get()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resize_preserves_high_occupied_seat_and_appends_new_vacancies() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(dir.path(), 4, LobbyFormat::Resizable).await).await;
    let h = &p.game.node;
    assert!(h.player_count_guard(b"guest", count(2)).await.is_err());
    assert!(h.player_count_guard(ACTOR, count(4)).await.is_err());
    let high = SeatId::new(4).unwrap();
    let claim = h
        .seat_claim_guard(b"guest", high)
        .await
        .unwrap()
        .sign(request(80), &p.identity);
    let claimed = h.submit(claim.clone()).await.unwrap();
    let shrink = h.player_count_guard(ACTOR, count(2)).await.unwrap();
    let raw = h
        .prepare_seat_command(&shrink, request(81), &key())
        .unwrap();
    let result = receipt(h.submit(raw.clone()).await.unwrap());
    let effect = fields(
        super::changes::seat_effect(&result, 203),
        &[1, 2, 3, 4, 5, 6],
    )
    .unwrap();
    assert_eq!((effect[&1], effect[&2]), (&[4][..], &[2][..]));
    assert_eq!(effect[&3], 1u64.to_be_bytes());
    assert_eq!(effect[&4], 2u64.to_be_bytes());
    assert_eq!(effect[&5], [1, 4]);
    let retained = fields(effect[&6], &[1]).unwrap();
    let member = fields(retained[&1], &[1, 2, 3]).unwrap();
    assert_eq!(
        (member[&1], member[&2], member[&3]),
        (&[4][..], b"guest".as_slice(), &[0][..])
    );
    let view = h.lobby_seating(ACTOR).await.unwrap();
    assert_eq!(ids(&view), [1, 4]);
    assert_eq!((view.setup_revision, view.layout_revision), (3, 2));
    assert_eq!(view.seats[1].occupant.as_deref(), Some(b"guest".as_slice()));
    let grow = h
        .player_count_guard(ACTOR, count(10))
        .await
        .unwrap()
        .sign(request(82), &key());
    h.submit(grow).await.unwrap();
    let view = h.lobby_seating(ACTOR).await.unwrap();
    assert_eq!(ids(&view), [1, 4, 2, 3, 5, 6, 7, 8, 9, 10]);
    assert_eq!(
        (
            view.setup_revision,
            view.layout_revision,
            view.seats[1].revision
        ),
        (3, 3, 1)
    );
    assert_eq!(h.submit(claim).await.unwrap(), claimed);
    assert_eq!(receipt(h.submit(raw).await.unwrap()), result);
    let creation = &p.game.lobby.as_ref().unwrap().created;
    assert_eq!((creation.target, creation.layout_revision), (4, 1));
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_committed_orders_of_resize_and_claim_resolve_without_displacement() {
    for resize_first in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let (p, _) =
            finish_pair(Peers::with_profile(dir.path(), 3, LobbyFormat::Resizable).await).await;
        let h = &p.game.node;
        let resize = h
            .player_count_guard(ACTOR, count(2))
            .await
            .unwrap()
            .sign(request(83), &key());
        let claim = h
            .seat_claim_guard(b"guest", SeatId::new(3).unwrap())
            .await
            .unwrap()
            .sign(request(84), &p.identity);
        for cmd in [&resize, &claim] {
            assert!(h.replica.preflight(cmd).unwrap().is_none());
        }
        let (first, late) = if resize_first {
            (resize, claim)
        } else {
            (claim, resize)
        };
        h.raft.client_write(first).await.unwrap();
        assert!(h.submit(late.clone()).await.is_err());
        let loser = receipt(h.raft.client_write(late.clone()).await.unwrap().data);
        let f = fields(&loser, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert_eq!(fields(f[&7], &[13]).unwrap()[&13], [8, 1]);
        assert!(f[&8].is_empty());
        let view = h.lobby_seating(ACTOR).await.unwrap();
        if resize_first {
            assert_eq!(ids(&view), [1, 2]);
            assert_eq!(view.setup_revision, 2);
        } else {
            assert_eq!(ids(&view), [1, 2, 3]);
            assert_eq!(view.seats[2].occupant.as_deref(), Some(b"guest".as_slice()));
        }
        assert_eq!(receipt(h.submit(late).await.unwrap()), loser);
        p.shutdown().await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resized_lobby_recovers_on_a_third_installation_and_counts_unseated_members() {
    let dir = tempfile::tempdir().unwrap();
    let (p, join) =
        finish_pair(Peers::with_profile(dir.path(), 2, LobbyFormat::Resizable).await).await;
    let h = &p.game.node;
    let grow = h
        .player_count_guard(ACTOR, count(4))
        .await
        .unwrap()
        .sign(request(86), &key());
    let original = h.submit(grow.clone()).await.unwrap();
    let shrink = h
        .player_count_guard(ACTOR, count(2))
        .await
        .unwrap()
        .sign(request(87), &key());
    let k = h.raft.metrics().borrow_watched().last_applied.unwrap();
    p.learner
        .node
        .raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(k.index), "resize replicated")
        .await
        .unwrap();
    h.certify_recovery_tail(&key(), async |q| {
        p.learner
            .node
            .answer_history_request(p.game.creator_node, q, &p.identity)
    })
    .await
    .unwrap();
    let mut r = admit_to_pair(dir.path(), (p, join)).await;
    r.recover().await;
    let proposal = r.proposal().await.unwrap();
    let h = &r.p.game.node;
    let joined = h.join_lobby(&proposal).await.unwrap();
    assert_eq!(
        (
            joined.member.ordinal,
            joined.member.setup_revision,
            joined.member.layout_revision
        ),
        (3, 3, 2)
    );
    assert!(h.player_count_guard(ACTOR, count(2)).await.is_err());
    assert!(h.submit(shrink.clone()).await.is_err());
    let lost = receipt(h.raft.client_write(shrink).await.unwrap().data);
    let f = fields(&lost, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    assert!(f[&8].is_empty());
    assert!(fields(f[&7], &[13]).is_ok());
    assert_eq!(h.submit(grow).await.unwrap(), original);
    let view = h.lobby_seating(ACTOR).await.unwrap();
    assert!(view.seats.iter().all(|s| s.occupant.is_none()));
    assert_eq!(
        (view.seats.len(), view.setup_revision, view.layout_revision),
        (4, 3, 2)
    );
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resize_allows_a_fresh_first_join_only_after_verified_layout_change() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::with_profile(dir.path(), 3, LobbyFormat::Resizable).await;
    p.finish().await;
    let original = p
        .catalog
        .prepare_join(&p.learner, &p.identity, REQUEST, true)
        .unwrap();
    let fresh = request(93);
    assert!(
        p.catalog
            .prepare_join(&p.learner, &p.identity, fresh, true)
            .is_err()
    );
    let h = &p.game.node;
    let resize = h
        .player_count_guard(ACTOR, count(2))
        .await
        .unwrap()
        .sign(request(92), &key());
    h.submit(resize).await.unwrap();
    assert!(h.join_lobby(&original).await.is_err());
    let k = h.raft.metrics().borrow_watched().last_applied.unwrap();
    p.learner
        .node
        .raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(k.index), "resize applied")
        .await
        .unwrap();
    p.finish().await;
    assert!(
        p.catalog
            .prepare_join(&p.learner, &p.identity, REQUEST, true)
            .is_err()
    );
    assert!(
        p.catalog
            .prepare_join(&p.learner, &p.identity, fresh, false)
            .is_err()
    );
    let pending = p
        .catalog
        .prepare_join(&p.learner, &p.identity, fresh, true)
        .unwrap();
    // Returning to the old capacity cannot make its retired request ID available again.
    let host = &p.game.node;
    let grow = host
        .player_count_guard(ACTOR, count(3))
        .await
        .unwrap()
        .sign(request(97), &key());
    host.submit(grow).await.unwrap();
    let k = host.raft.metrics().borrow_watched().last_applied.unwrap();
    p.learner
        .node
        .raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(k.index), "second resize applied")
        .await
        .unwrap();
    p.finish().await;
    assert!(
        p.catalog
            .prepare_join(&p.learner, &p.identity, REQUEST, true)
            .is_err()
    );
    assert_eq!(p.catalog.pending_join(&p.learner).unwrap(), pending);
    let node = &p.game.node;
    let joined = p
        .catalog
        .join_first_player(
            &p.learner,
            &p.identity,
            request(98),
            true,
            async |raw| node.join_lobby(&raw).await,
            async |q| node.answer_history_request(p.learner.id(), q, &key()),
        )
        .await
        .unwrap();
    assert_eq!(
        (
            joined.join.member.ordinal,
            joined.join.member.layout_revision
        ),
        (2, 3)
    );
    assert!(
        p.catalog
            .prepare_join(&p.learner, &p.identity, REQUEST, true)
            .is_err()
    );
    assert!(node.join_lobby(&original).await.is_err());
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resize_restores_success_and_conflict_by_id_without_a_local_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(dir.path(), 3, LobbyFormat::Resizable).await).await;
    let h = &p.game.node;
    let a = h
        .player_count_guard(ACTOR, count(2))
        .await
        .unwrap()
        .sign(request(94), &key());
    let b = h
        .player_count_guard(ACTOR, count(4))
        .await
        .unwrap()
        .sign(request(95), &key());
    assert!(h.replica.preflight(&b).unwrap().is_none());
    let won = h.submit(a.clone()).await.unwrap();
    let lost = h.raft.client_write(b.clone()).await.unwrap().data;
    for (id, raw, result) in [(94, a, won), (95, b, lost)] {
        assert!(
            h.saved_seat_command(ACTOR, request(id), &p.identity)
                .is_err()
        );
        let saved = h
            .saved_seat_command(ACTOR, request(id), &key())
            .unwrap()
            .expect("missing committed resize");
        assert_eq!(saved.0, raw.0);
        assert_eq!(h.submit(saved).await.unwrap(), result);
    }
    assert!(
        h.saved_seat_command(ACTOR, request(96), &key())
            .unwrap()
            .is_none()
    );
    assert!(
        h.saved_seat_command(ACTOR, REQUEST, &key())
            .unwrap()
            .is_none()
    );
    p.shutdown().await;
}
