use super::*;
mod restart;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn elected_second_voter_returns_original_join_after_creator_loses_reply() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::open(dir.path()).await;
    p.finish().await;
    let proposal = p
        .catalog
        .prepare_join(&p.learner, &p.identity, REQUEST, true)
        .unwrap();
    let original = p.game.node.join_lobby(&proposal).await.unwrap();
    let peer = &p.learner.node;
    peer.raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(original.log_id.index), "Join applied")
        .await
        .unwrap();
    p.game.node.raft.runtime_config().heartbeat(false);
    p.game.node.raft.runtime_config().elect(false);
    peer.raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "joined peer elected")
        .await
        .unwrap();
    assert_eq!(peer.join_lobby(&proposal).await.unwrap(), original);
    assert!(!peer.voting_history_complete(original.log_id).unwrap());
    let sender = p.learner.id();
    peer.reconcile_voting_history(original.log_id, &p.identity, async |request| {
        p.game.node.answer_history_request(sender, request, &key())
    })
    .await
    .unwrap();
    for node in [peer, p.game.node.as_ref()] {
        assert!(node.voting_history_complete(original.log_id).unwrap());
    }
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_join_reports_pending_proof_and_resumes_without_another_membership() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::open(dir.path()).await;
    p.finish().await;
    let host = &p.game.node;
    let first = p
        .catalog
        .join_first_player(
            &p.learner,
            &p.identity,
            REQUEST,
            true,
            async |raw: Vec<u8>| host.join_lobby(&raw).await,
            async |_| Err(io::Error::from(io::ErrorKind::ConnectionReset)),
        )
        .await
        .unwrap();
    assert!(first.history.is_err());
    let sender = p.learner.id();
    let retry = p
        .catalog
        .join_first_player(
            &p.learner,
            &p.identity,
            REQUEST,
            false,
            async |raw: Vec<u8>| host.join_lobby(&raw).await,
            async |req| host.answer_history_request(sender, req, &key()),
        )
        .await
        .unwrap();
    retry.history.unwrap();
    assert_eq!(first.join, retry.join);
    for node in [host.as_ref(), &p.learner.node] {
        assert!(node.voting_history_complete(retry.join.log_id).unwrap());
    }
    p.shutdown().await;
}
use openraft::entry::RaftPayload;

#[test]
fn combined_source_retains_signed_command_and_exact_configuration() {
    let id = ReplicaId([5; 16]);
    let members = Members::new_with_defaults(vec![[id].into()], []);
    let command = Signed(vec![0x42, 0, 0xff]);
    let source = Source::blank()
        .with_normal(command.clone())
        .with_membership(members.clone());
    assert_eq!(source.check_members().unwrap(), Some(members));
    assert_eq!(source.join_command().unwrap(), Some(command.0.as_slice()));
    let mut altered = source;
    altered.bytes[1] ^= 1;
    assert!(altered.check_members().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_join_uses_one_genuine_two_voter_entry_and_one_original_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = Peers::open(dir.path()).await;
    assert!(
        p.catalog
            .prepare_join(&p.learner, &p.identity, REQUEST, true)
            .is_err()
    );
    p.finish().await;
    let command = p
        .catalog
        .prepare_join(&p.learner, &p.identity, REQUEST, true)
        .unwrap();
    assert!(
        p.catalog
            .prepare_join(&p.learner, &p.identity, [0; 16], true)
            .is_err()
    );
    let mut invalid_command = command.clone();
    *invalid_command.last_mut().unwrap() ^= 1;
    assert!(p.game.node.join_lobby(&invalid_command).await.is_err());
    let outer = fields(&command, &[1, 2]).unwrap();
    let signed = fields(outer[&1], &[1, 2]).unwrap();
    let body = fields(signed[&1], &[1, 2, 3, 4, 5, 12]).unwrap();
    let reordered = message(&body.into_iter().rev().collect::<Vec<_>>());
    let alternate = message(&[
        (1, &reordered),
        (2, &p.identity.sign(&reordered).to_bytes()),
    ]);
    let submitted = message(&[(1, &alternate), (2, outer[&2])]);
    assert_ne!(submitted, command);
    let result = p.game.node.join_lobby(&submitted).await.unwrap();
    p.learner
        .node
        .raft
        .wait(Some(Duration::from_secs(5)))
        .applied_index_at_least(Some(result.log_id.index), "join applied at both voters")
        .await
        .unwrap();
    assert_eq!(p.game.node.join_lobby(&command).await.unwrap(), result);
    for r in [&p.game.node.replica, &p.learner.node.replica] {
        let db = r.lock().unwrap();
        let (source, events, receipts): (Vec<u8>, i64, i64) = db
            .query_row(
                "SELECT source,event_count,receipt_count FROM archive WHERE idx=?",
                [result.log_id.index.to_be_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(source[0], 3);
        assert!(source.ends_with(&submitted));
        assert_eq!((events, receipts), (2, 2));
        let receipt: Vec<u8> = db
            .query_row(
                "SELECT record FROM receipt WHERE actor=? AND request=?",
                rusqlite::params![b"guest", REQUEST],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(receipt, result.receipt);
        let envelope = fields(&receipt, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert_eq!(envelope[&5], log_key(result.log_id));
        assert_eq!(envelope[&9], Sha256::digest(&source).as_slice());
        let outcome = fields(fields(envelope[&7], &[12]).unwrap()[&12], &[202]).unwrap();
        let joined = fields(outcome[&202], &(1..=10).collect::<Vec<_>>()).unwrap();
        assert_eq!(joined[&1], b"guest");
        assert_eq!(joined[&2], 2u32.to_be_bytes());
        assert_eq!(joined[&3], &[1]);
        assert_eq!(joined[&4], &[1]);
        assert_eq!(joined[&5], envelope[&5]);
        assert_eq!(joined[&7], 2u64.to_be_bytes());
        assert_eq!(joined[&8], 1u64.to_be_bytes());
        for ledger in ["event", "receipt"] {
            let semantic: Vec<u8> = db
                .query_row(
                    "SELECT record FROM semantic_link WHERE ledger=? AND seq=2",
                    [ledger],
                    |row| row.get(0),
                )
                .unwrap();
            let mut voters = [p.game.creator_node, p.learner.id()];
            voters.sort();
            let ordered = crate::lobby::frame(&[&voters[0].0, &voters[1].0]);
            let binding = fields(joined[&6], &[1, 2, 3]).unwrap();
            let result_facts = crate::lobby::frame(&[
                joined[&1],
                joined[&2],
                joined[&3],
                joined[&4],
                joined[&5],
                binding[&1],
                binding[&2],
                binding[&3],
                joined[&7],
                joined[&8],
                joined[&9],
                &ordered,
            ]);
            assert!(
                semantic.ends_with(&result_facts),
                "{ledger} must bind the typed Join result"
            );
        }
        let membership =
            store::meta::<openraft::alias::StoredMembershipOf<Types>>(&db, "membership")
                .unwrap()
                .unwrap();
        assert_eq!(*membership.log_id(), Some(result.log_id));
        assert_eq!(
            membership
                .membership()
                .voter_ids()
                .collect::<std::collections::BTreeSet<_>>(),
            [p.learner.id(), p.game.creator_node].into()
        );
        r.verify_replay(&db).unwrap();
    }
    let peer = p.learner.joined_node().unwrap();
    {
        let r = &peer.replica;
        let mut db = r.lock().unwrap();
        let tx = db.transaction().unwrap();
        let mut next = result.log_id;
        next.index += 1;
        let old = Members::new_with_defaults(vec![[p.game.creator_node].into()], [p.learner.id()]);
        let demotion = Entry {
            log_id: next,
            payload: Source::blank().with_membership(old),
        };
        assert!(
            r.apply_in_transaction(&tx, &demotion).is_err(),
            "protocol-only entry removed the newly joined voter"
        );
        assert_eq!(
            store::meta::<LogId>(&tx, "applied").unwrap(),
            Some(result.log_id)
        );
    }
    let host = &p.game.node;
    let a = host.sign_voting_checkpoint(result.log_id, &key()).unwrap();
    let b = peer
        .sign_voting_checkpoint(result.log_id, &p.identity)
        .unwrap();
    assert!(
        host.store_voting_checkpoint(result.log_id, &a, &a, &key())
            .is_err()
    );
    let ack_a = host
        .store_voting_checkpoint(result.log_id, &a, &b, &key())
        .unwrap();
    let ack_b = peer
        .store_voting_checkpoint(result.log_id, &b, &a, &p.identity)
        .unwrap();
    assert!(
        host.confirm_voting_checkpoint(result.log_id, &ack_a, &ack_a)
            .is_err()
    );
    for node in [host.as_ref(), peer] {
        node.confirm_voting_checkpoint(result.log_id, &ack_a, &ack_b)
            .unwrap();
        assert!(node.voting_history_complete(result.log_id).unwrap());
    }
    p.shutdown().await;
}
