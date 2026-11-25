use super::*;
mod delivery;
pub(super) use delivery::elect_second;
mod restart;

impl Recovery {
    pub(super) async fn recover(&mut self) {
        let host = &self.p.game.node;
        let other = &self.p.learner.node;
        self.catalog
            .recover_learner(&mut self.third, &self.identity, async |q| {
                host.voter_recovery_chunk(&q, &key(), async |q| {
                    other.attest_recovery(&q, &self.p.identity)
                })
                .await
            })
            .await
            .unwrap();
    }
    pub(super) async fn proposal(&self) -> io::Result<Vec<u8>> {
        self.catalog
            .prepare_third_join(
                &self.third,
                &self.identity,
                REQUEST,
                true,
                async |draft, route| {
                    Ok([
                        self.p
                            .game
                            .node
                            .confirm_third_promotion(&draft, &route, &key())?,
                        self.p.learner.node.confirm_third_promotion(
                            &draft,
                            &route,
                            &self.p.identity,
                        )?,
                    ])
                },
            )
            .await
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn third_join_is_one_original_entry_and_three_player_projection() {
    let dir = tempfile::tempdir().unwrap();
    let mut r = admitted_third(dir.path()).await;
    assert!(r.proposal().await.is_err());
    r.recover().await;
    let proposal = r.proposal().await.unwrap();
    let host = &r.p.game.node;
    let f = fields(&proposal, &[1, 2, 3, 4]).unwrap();
    for incomplete in [
        message(&[(1, f[&1]), (2, f[&2])]),
        message(&[(1, f[&1]), (2, f[&2]), (3, f[&3]), (4, f[&3])]),
    ] {
        assert!(host.join_lobby(&incomplete).await.is_err());
        assert_eq!(host.raft.voter_ids().count(), 2);
        assert_eq!(
            host.raft.metrics().borrow_watched().last_applied,
            Some(r.admitted)
        );
    }
    // The guarded append belongs to the leader which owns the signed prefix.
    // A different term cannot supply a new origin for the same source.
    {
        use openraft::entry::RaftPayload;
        let mut k = r.admitted;
        k.index += 1;
        k.leader_id.term += 1;
        let membership = Members::new_with_defaults(
            vec![[r.p.game.creator_node, r.p.learner.id(), r.third.id()].into()],
            [],
        );
        let entry = Entry {
            log_id: k,
            payload: Source::blank()
                .with_normal(Signed(proposal.clone()))
                .with_membership(membership),
        };
        let mut db = host.replica.lock().unwrap();
        let tx = db.transaction().unwrap();
        assert!(host.replica.apply_in_transaction(&tx, &entry).is_err());
    }
    let result = host.join_lobby(&proposal).await.unwrap();
    assert_eq!(
        (
            result.member.ordinal,
            result.member.setup_revision,
            result.member.layout_revision
        ),
        (3, 3, 1)
    );
    assert_eq!(result.member.membership_before, r.admitted);
    assert_eq!(result.member.node, r.third.id());
    for node in [&**host, &r.p.learner.node, &r.third.node] {
        node.raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(Some(result.log_id.index), "third Joined")
            .await
            .unwrap();
        let db = node.replica.lock().unwrap();
        let (source, n, m): (Vec<u8>, i64, i64) = db
            .query_row(
                "SELECT source,event_count,receipt_count FROM archive WHERE idx=?",
                [result.log_id.index.to_be_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((n, m), (3, 3));
        assert_eq!(source[0], 3);
        assert!(source.ends_with(&proposal));
        let original: Vec<u8> = db
            .query_row("SELECT record FROM receipt WHERE seq=3", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(original, result.receipt);
        assert_eq!(node.raft.voter_ids().count(), 3);
    }
    assert_eq!(host.join_lobby(&proposal).await.unwrap(), result);
    let original = r.p.catalog.pending_join(&r.p.learner).unwrap();
    assert_eq!(host.join_lobby(&original).await.unwrap(), r.join);
    assert!(r.third.joined_node().is_ok());
    let current = [
        (&**host, key()),
        (&r.p.learner.node, r.p.identity.clone()),
        (&r.third.node, r.identity.clone()),
    ];
    assert!(
        current[2]
            .0
            .sign_voting_checkpoint(r.admitted, &current[2].1)
            .is_err()
    );
    // Each installation can retain a different lawful original for the same K.
    for (i, j) in [(0, 1), (1, 2), (2, 0)] {
        let (n, k) = &current[i];
        let (p, pk) = &current[j];
        let a = n.sign_voting_checkpoint(result.log_id, k).unwrap();
        let b = p.sign_voting_checkpoint(result.log_id, pk).unwrap();
        n.store_voting_checkpoint(result.log_id, &a, &b, k).unwrap();
    }
    for (i, j) in [(0, 1), (1, 2), (2, 0)] {
        let (local, lkey) = &current[i];
        let (peer, pkey) = &current[j];
        let a = local.sign_voting_checkpoint(result.log_id, lkey).unwrap();
        assert!(
            local
                .store_voting_checkpoint(result.log_id, &a, &a, lkey)
                .is_err()
        );
        local
            .reconcile_voting_history(result.log_id, lkey, async |q| {
                peer.answer_history_request(local.replica.local_node.unwrap(), q, pkey)
            })
            .await
            .unwrap();
        assert!(local.voting_history_complete(result.log_id).unwrap());
        assert!(peer.voting_history_complete(result.log_id).unwrap());
    }
    let (n, k) = &current[0];
    let (peer, pk) = &current[1];
    n.replica
        .lock()
        .unwrap()
        .execute(
            "UPDATE historic_seal SET certificate=x'01' WHERE idx=?",
            [result.log_id.index.to_be_bytes()],
        )
        .unwrap();
    assert!(
        n.voting_history_complete(result.log_id).is_err(),
        "acknowledged a damaged primary certificate"
    );
    assert!(
        n.certify_recovery_tail(k, async |q| peer.answer_history_request(
            n.replica.local_node.unwrap(),
            q,
            pk
        ))
        .await
        .is_err()
    );
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
}
