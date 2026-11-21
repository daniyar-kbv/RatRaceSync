use super::*;
use openraft::storage::RaftStateMachine;
use rusqlite::OptionalExtension;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_committed_source_stops_apply_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let c = Cluster::open(dir.path(), true).await;
    let n = c.leader().await;
    let mut ineligible = command(n, 1).await;
    ineligible.units = 3.into();
    let bad = ineligible.sign(&key());
    assert!(n.replica.preflight(&bad).is_err());
    let target = n.raft.current_leader().await.unwrap();
    let mut store = n.replica.clone();
    let before = store.applied_state().await.unwrap().0.unwrap();
    let write = timeout(Duration::from_secs(4), n.raft.client_write(bad)).await;
    assert!(!matches!(write, Ok(Ok(_))));
    let path = dir.path().join(format!("{target}.db"));
    let check = || {
        let db = Connection::open(&path).unwrap();
        let applied: LogId = store::meta(&db, "applied").unwrap().unwrap();
        assert_eq!(applied, before);
        assert_eq!(
            db.query_row("SELECT count(*) FROM receipt", [], |r| r.get::<_, i32>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM event", [], |r| r.get::<_, i32>(0))
                .unwrap(),
            0
        );
        let source: Option<Vec<u8>> = db
            .query_row(
                "SELECT entry FROM raft_log WHERE idx=?",
                [(before.index + 1).to_be_bytes()],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        assert!(source.is_some());
        let committed = store::meta::<Option<LogId>>(&db, "committed")
            .unwrap()
            .flatten()
            .unwrap();
        assert!(committed.index > before.index);
    };
    check();
    for node in &c.nodes {
        let _ = node.raft.shutdown().await;
    }
    c.bus.0.lock().unwrap().clear();
    drop(c);
    drop(store);
    let reopened = Replica::open(&path, GAME).unwrap();
    let restart = GameNode::start(target, reopened, Config::default(), Bus::default()).await;
    match restart {
        Err(reason) => assert!(
            reason
                .to_string()
                .contains("ineligible original redemption"),
            "{reason}"
        ),
        Ok(_) => panic!("persisted invalid command did not prevent service startup"),
    }
    check();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_receipt_insert_rolls_back_entire_apply() {
    let dir = tempfile::tempdir().unwrap();
    let c = Cluster::open(dir.path(), true).await;
    let n = c.leader().await;
    let before = store::meta::<LogId>(&n.replica.lock().unwrap(), "applied").unwrap();
    n.replica.lock().unwrap().execute_batch("CREATE TEMP TRIGGER fail_receipt BEFORE INSERT ON receipt BEGIN SELECT RAISE(ABORT,'injected write failure'); END;").unwrap();
    let result = timeout(
        Duration::from_secs(4),
        n.submit(command(n, 1).await.sign(&key())),
    )
    .await;
    assert!(!matches!(result, Ok(Ok(_))));
    assert_eq!(counts(n), ("10000".into(), 0, 0));
    assert_eq!(
        store::meta::<LogId>(&n.replica.lock().unwrap(), "applied").unwrap(),
        before
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_corruption_must_not_return_a_fabricated_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let c = Cluster::open(dir.path(), true).await;
    let n = c.leader().await;
    let signed = command(n, 1).await.sign(&key());
    n.submit(signed.clone()).await.unwrap();
    n.replica
        .lock()
        .unwrap()
        .execute("UPDATE receipt SET record=x'01'", [])
        .unwrap();
    assert!(n.submit(signed).await.is_err());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_receipt_must_not_become_a_new_request() {
    let dir = tempfile::tempdir().unwrap();
    let c = Cluster::open(dir.path(), true).await;
    let n = c.leader().await;
    let signed = command(n, 1).await.sign(&key());
    n.submit(signed.clone()).await.unwrap();
    n.replica
        .lock()
        .unwrap()
        .execute("DELETE FROM receipt", [])
        .unwrap();
    let result = n.replica.preflight(&signed).unwrap_err();
    assert!(result.to_string().contains("checkpoint"), "{result}");
}
#[test]
fn nonminimal_field_keys_and_lengths_are_rejected() {
    for raw in [&[0x8a, 0, 1, 7][..], &[10, 0x81, 0, 7][..]] {
        assert!(wire::fields(raw, &[1]).is_err());
    }
}

#[test]
fn raft_node_identity_has_fixed_width_in_storage() {
    type Id = <Types as openraft::RaftTypeConfig>::NodeId;
    assert_eq!(store::encode(&Id::default()).unwrap(), [0; 16]);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_semantics_survive_field_reordering_but_tampering_fails() {
    use ed25519_dalek::Signer;
    let dir = tempfile::tempdir().unwrap();
    let cluster = Cluster::open(dir.path(), true).await;
    let node = cluster.leader().await;
    let cmd = command(node, 1).await;
    let signed = cmd.sign(&key());
    let original = node.submit(signed.clone()).await.unwrap();
    let body = cmd.body();
    let f = wire::fields(&body, &[1, 2, 3, 4, 5, 11]).unwrap();
    let mut reordered = vec![];
    for tag in [11, 5, 4, 3, 2, 1] {
        wire::field(&mut reordered, tag, f[&tag]);
    }
    let frame = |b: &[u8]| Signed(wire::message(&[(1, b), (2, &key().sign(b).to_bytes())]));
    assert_eq!(node.submit(frame(&reordered)).await.unwrap(), original);
    for tag in [1, 77] {
        let mut invalid = reordered.clone();
        wire::field(&mut invalid, tag, b"x");
        assert!(node.submit(frame(&invalid)).await.is_err());
    }
    let mut bad = signed;
    *bad.0.last_mut().unwrap() ^= 1;
    assert!(node.submit(bad).await.is_err());
    assert_eq!(counts(node), ("15000".into(), 1, 1));
}

#[tokio::test]
async fn cloned_storage_cannot_start_a_second_raft_owner() {
    let dir = tempfile::tempdir().unwrap();
    let replica = Replica::open(&dir.path().join("one.db"), GAME).unwrap();
    let id = ReplicaId([1; 16]);
    let first = GameNode::start(id, replica.clone(), Config::default(), Bus::default())
        .await
        .unwrap();
    let second = GameNode::start(id, replica, Config::default(), Bus::default()).await;
    assert!(second.is_err());
    first.raft.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_verifies_interior_history_and_financial_projection() {
    let dir = tempfile::tempdir().unwrap();
    let cluster = Cluster::open(dir.path(), true).await;
    let node = cluster.leader().await;
    for nonce in [1, 2] {
        node.submit(command(node, nonce).await.sign(&key()))
            .await
            .unwrap();
    }
    let mut replica = node.replica.clone();
    replica.applied_state().await.unwrap();
    for damage in [
        "DELETE FROM archive WHERE idx=(SELECT min(idx) FROM archive)",
        "UPDATE archive SET source=x'00' WHERE receipt_count=1",
        "UPDATE receipt SET record=x'01' WHERE seq=1",
        "UPDATE event SET record=x'01' WHERE seq=1",
        "UPDATE event SET units_after='8' WHERE seq=1",
        "UPDATE participant SET monthly='999' WHERE actor=x'706c61796572'",
        "DELETE FROM meta WHERE name='membership'",
    ] {
        replica
            .lock()
            .unwrap()
            .execute_batch("SAVEPOINT damage")
            .unwrap();
        replica.lock().unwrap().execute_batch(damage).unwrap();
        let result = replica.applied_state().await;
        replica
            .lock()
            .unwrap()
            .execute_batch("ROLLBACK TO damage; RELEASE damage")
            .unwrap();
        assert!(result.is_err(), "accepted {damage}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overflow_is_refused_before_submission_to_raft() {
    let dir = tempfile::tempdir().unwrap();
    let cluster = Cluster::open(dir.path(), true).await;
    let node = cluster.leader().await;
    let max = "9".repeat(128);
    node.replica
        .lock()
        .unwrap()
        .execute(
            "UPDATE participant SET opening_cash=?1,cash=?1 WHERE actor=?2",
            rusqlite::params![max, ACTOR],
        )
        .unwrap();
    let signed = command(node, 1).await.sign(&key());
    assert!(node.replica.preflight(&signed).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receipt_recovery_checks_its_original_event_before_replying() {
    let dir = tempfile::tempdir().unwrap();
    let cluster = Cluster::open(dir.path(), true).await;
    let node = cluster.leader().await;
    let signed = command(node, 1).await.sign(&key());
    node.submit(signed.clone()).await.unwrap();
    node.submit(command(node, 2).await.sign(&key()))
        .await
        .unwrap();
    node.replica
        .lock()
        .unwrap()
        .execute("UPDATE event SET record=x'00' WHERE seq=1", [])
        .unwrap();
    assert!(node.submit(signed).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_log_recovery_refuses_unprotected_purge() {
    use openraft::storage::RaftLogStorage;
    let dir = tempfile::tempdir().unwrap();
    let cluster = Cluster::open(dir.path(), true).await;
    let node = cluster.leader().await;
    node.submit(command(node, 1).await.sign(&key()))
        .await
        .unwrap();
    let mut store = node.replica.clone();
    let k = store.applied_state().await.unwrap().0.unwrap();
    assert!(store.purge(k).await.is_err());
    store.applied_state().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_never_returns_reencoded_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let cluster = Cluster::open(dir.path(), true).await;
    let node = cluster.leader().await;
    let signed = command(node, 1).await.sign(&key());
    let Reply::Receipt(record) = node.submit(signed.clone()).await.unwrap() else {
        panic!("missing receipt")
    };
    let f = wire::fields(&record, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    let mut reordered = vec![];
    for (tag, value) in f.iter().rev() {
        wire::field(&mut reordered, *tag, value);
    }
    node.replica
        .lock()
        .unwrap()
        .execute("UPDATE receipt SET record=? WHERE seq=1", [reordered])
        .unwrap();
    assert!(node.submit(signed).await.is_err());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preflight_rejects_disagreement_with_prior_recurring_income() {
    let dir = tempfile::tempdir().unwrap();
    let cluster = Cluster::open(dir.path(), true).await;
    let node = cluster.leader().await;
    node.submit(command(node, 1).await.sign(&key()))
        .await
        .unwrap();
    let signed = command(node, 2).await.sign(&key());
    node.replica
        .lock()
        .unwrap()
        .execute(
            "UPDATE participant SET monthly='400' WHERE actor=?",
            [ACTOR],
        )
        .unwrap();
    assert!(node.replica.preflight(&signed).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn suffix_truncation_preserves_the_durable_commit_boundary() {
    use openraft::storage::RaftLogStorage;
    let dir = tempfile::tempdir().unwrap();
    let cluster = Cluster::open(dir.path(), true).await;
    let node = cluster.leader().await;
    node.submit(command(node, 1).await.sign(&key()))
        .await
        .unwrap();
    let mut store = node.replica.clone();
    let committed = store.read_committed().await.unwrap().unwrap();
    assert!(store.truncate_after(None).await.is_err());
    let wrong = LogId::new(
        openraft::impls::leader_id_adv::LeaderId {
            term: committed.leader_id.term,
            node_id: ReplicaId([255; 16]),
        },
        committed.index,
    );
    assert!(store.truncate_after(Some(wrong)).await.is_err());
    store.truncate_after(Some(committed)).await.unwrap();
    store.applied_state().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_guard_cannot_turn_an_original_overflow_into_a_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let cluster = Cluster::open(dir.path(), true).await;
    let node = cluster.leader().await;
    // Only one more principal credit fits in the numeric profile.
    let cash = format!("{}4999", "9".repeat(124));
    for peer in &cluster.nodes {
        peer.replica
            .lock()
            .unwrap()
            .execute(
                "UPDATE participant SET opening_cash=?1,cash=?1 WHERE actor=?2",
                rusqlite::params![cash, ACTOR],
            )
            .unwrap();
    }
    let mut impossible = command(node, 2).await;
    impossible.units = 2.into();
    node.submit(command(node, 1).await.sign(&key()))
        .await
        .unwrap();
    let reply = node.raft.client_write(impossible.sign(&key())).await;
    assert!(reply.is_err());
    assert_eq!(counts(node).2, 1);
}
