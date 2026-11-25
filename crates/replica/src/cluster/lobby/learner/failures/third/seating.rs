use super::*;
mod changes;
mod history;
mod readiness;
mod resize;
mod restart;
mod validation;
use rat_race_engine::SeatId;

fn request(n: u8) -> [u8; 16] {
    let mut id = REQUEST;
    id[15] = n;
    id
}
fn receipt(reply: Reply) -> Vec<u8> {
    let Reply::Receipt(r) = reply else {
        panic!("expected receipt")
    };
    r
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn competing_seat_claims_recover_only_the_first_occupant() {
    let dir = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(dir.path(), 3, crate::lobby::LobbyFormat::Seating).await)
            .await;
    let host = &p.game.node;
    let seat = SeatId::new(2).unwrap();
    let scoped = host
        .seat_claim_guard(ACTOR, SeatId::new(3).unwrap())
        .await
        .unwrap();
    assert!(host.seat_claim_guard(b"non-member", seat).await.is_err());
    let mismatched_key = scoped.sign(request(23), &p.identity);
    assert!(host.submit(mismatched_key).await.is_err());
    let a = host
        .seat_claim_guard(ACTOR, seat)
        .await
        .unwrap()
        .sign(request(20), &key());
    let b = host
        .seat_claim_guard(b"guest", seat)
        .await
        .unwrap()
        .sign(request(21), &p.identity);
    assert!(host.replica.preflight(&a).unwrap().is_none());
    assert!(host.replica.preflight(&b).unwrap().is_none());
    // Both requests passed preflight before either entered the log.
    let (ra, rb) = tokio::join!(
        host.raft.client_write(a.clone()),
        host.raft.client_write(b.clone())
    );
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    let (winner, loser, win_cmd, lose_cmd, actor) = if ra.log_id.index < rb.log_id.index {
        (ra, rb, a, b, ACTOR)
    } else {
        (rb, ra, b, a, b"guest".as_slice())
    };
    let won = receipt(winner.data);
    let lost = receipt(loser.data);
    let rf = fields(&won, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    let outcome = fields(fields(rf[&7], &[12]).unwrap()[&12], &[204]).unwrap();
    let effect = fields(outcome[&204], &[1, 2, 3, 4, 5]).unwrap();
    assert_eq!(effect[&1], actor);
    assert!(effect[&2].is_empty());
    assert_eq!(effect[&3], [2]);
    let revisions = fields(effect[&4], &[1, 2, 3, 4, 5, 6]).unwrap();
    for (field, value) in [(1, 1u64), (2, 1), (3, 0), (4, 1), (5, 2), (6, 3)] {
        assert_eq!(revisions[&field], value.to_be_bytes());
    }
    let ready = fields(effect[&5], &[1, 2]).unwrap();
    assert_eq!((ready[&1], ready[&2]), ([0].as_slice(), [0].as_slice()));
    assert_eq!(rf[&5], log_key(winner.log_id));
    assert_eq!(rf[&8].len(), 32);
    let cf = fields(&lost, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    assert_eq!(fields(cf[&7], &[13]).unwrap()[&13], [8, 1]);
    assert!(cf[&8].is_empty());
    let peer = &p.learner.node;
    peer.raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(loser.log_id.index), "both applied")
        .await
        .unwrap();
    for node in [host.as_ref(), peer] {
        let db = node.replica.lock().unwrap();
        assert_eq!(node.replica.tip(&db, "event").unwrap().0, 3);
        assert_eq!(node.replica.tip(&db, "receipt").unwrap().0, 4);
    }
    host.raft.runtime_config().elect(false);
    host.raft.runtime_config().heartbeat(false);
    peer.raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "new leader")
        .await
        .unwrap();
    assert_eq!(receipt(peer.submit(win_cmd).await.unwrap()), won);
    assert_eq!(receipt(peer.submit(lose_cmd).await.unwrap()), lost);
    let view = peer.lobby_seating(ACTOR).await.unwrap();
    assert_eq!((view.setup_revision, view.layout_revision), (3, 1));
    assert_eq!(view.seats[1].occupant.as_deref(), Some(actor));
    assert_eq!(
        view.seats.iter().map(|s| s.id.get()).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(view.seats[0].occupant.is_none() && view.seats[2].occupant.is_none());
    assert!(peer.lobby_seating(b"outsider").await.is_err());
    assert_eq!(
        peer.submit(scoped.sign(request(20), &key())).await.unwrap(),
        Reply::RequestIdConflict
    );
    assert!(peer.seat_claim_guard(ACTOR, seat).await.is_err());
    assert!(peer.seat_claim_guard(b"guest", seat).await.is_err());
    p.shutdown().await;
}
