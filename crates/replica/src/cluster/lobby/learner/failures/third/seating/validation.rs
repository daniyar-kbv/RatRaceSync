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
