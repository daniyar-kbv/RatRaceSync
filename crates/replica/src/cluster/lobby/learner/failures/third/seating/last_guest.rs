use super::*;
use crate::lobby::LobbyFormat;

async fn seal(host: &GameNode, peer: &Learner, identity: &SigningKey) -> LogId {
    let k = crate::learner::history::boundary(&host.replica.lock().unwrap()).unwrap();
    peer.node
        .raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(k.index), "guest applied prefix")
        .await
        .unwrap();
    host.certify_recovery_tail(&key(), async |q| {
        peer.node
            .answer_history_request(host.replica.local_node.unwrap(), q, identity)
    })
    .await
    .unwrap();
    k
}

async fn last_guest(
    host: &GameNode,
    guest: &Learner,
    identity: &SigningKey,
    catalog: &mut InstallationCatalog,
    bus: &Bus,
) -> (Signed, Vec<u8>) {
    let seat = SeatId::new(2).unwrap();
    let claim = host.seat_claim_guard(&guest.actor, seat).await.unwrap();
    host.submit(claim.sign(request(170), identity))
        .await
        .unwrap();
    let host_id = host.replica.local_node.unwrap();
    let host_claim = host
        .seat_claim_guard(ACTOR, SeatId::new(1).unwrap())
        .await
        .unwrap();
    host.submit(host_claim.sign(request(172), &key()))
        .await
        .unwrap();
    for (actor, node, signer) in [
        (ACTOR, host_id, &key()),
        (guest.actor.as_slice(), guest.id(), identity),
    ] {
        for (id, action) in [
            (
                173,
                LobbyPreference::Dream(rat_race_engine::DreamId::new(3).unwrap()),
            ),
            (174, LobbyPreference::Ready(true)),
        ] {
            let intent =
                LobbyIntent::sign(&host.replica.session, actor, request(id), action, signer);
            let guard = host.preference_guard(node, &intent, &key()).await.unwrap();
            host.submit_preference(node, guard.sign(request(id), signer))
                .await
                .unwrap();
        }
    }
    let high = seal(host, guest, identity).await;
    let before = host.lobby_seating(ACTOR).await.unwrap();
    assert!(before.seats[0].ready && before.seats[1].ready);
    assert_eq!(before.auditor_for(ACTOR), Some(guest.actor.as_slice()));
    let guard = host.leave_lobby_witness(&guest.actor).await.unwrap();
    let cmd = guest
        .node
        .prepare_leave_lobby(&guest.actor, &guard, request(171), identity)
        .unwrap();
    let a = host.leave_approval(&cmd, &key()).unwrap();
    let b = guest.node.leave_approval(&cmd, identity).unwrap();
    assert!(host.leave_lobby(&cmd, [&a, &a]).await.is_err());
    guest.node.raft.runtime_config().elect(false);
    let route = bus.1.lock().unwrap().remove(&guest.id()).unwrap();
    assert!(!matches!(
        timeout(Duration::from_millis(400), host.leave_lobby(&cmd, [&a, &b])).await,
        Ok(Ok(_))
    ));
    assert!(catalog.active_pin().unwrap().is_some());
    assert_eq!(
        crate::learner::history::boundary(&host.replica.lock().unwrap()).unwrap(),
        high
    );
    bus.1.lock().unwrap().insert(guest.id(), route);
    // Confirmation must also retire an installation that never applies Leave.
    *bus.6.lock().unwrap() = Some(PausedReplication {
        command: cmd.0.clone(),
        attempted: Default::default(),
    });
    let receipt = host.leave_lobby(&cmd, [&a, &b]).await.unwrap();
    assert_eq!(
        host.raft.voter_ids().collect::<Vec<_>>(),
        [host.replica.local_node.unwrap()]
    );
    let after = host.lobby_seating(ACTOR).await.unwrap();
    assert_eq!(after.seats.len(), before.seats.len());
    assert!(after.seats[1].occupant.is_none());
    assert!(after.seats.iter().all(|s| !s.ready));
    assert_eq!(after.setup_revision, before.setup_revision + 1);
    assert!(after.auditor_for(ACTOR).is_none());

    let k = crate::learner::history::boundary(&host.replica.lock().unwrap()).unwrap();
    assert!(host.leave_confirmation(&cmd, &key()).is_err());
    host.reconcile_voting_history(k, &key(), async |_| panic!("single voter contacted peer"))
        .await
        .unwrap();
    assert!(host.voting_history_complete(high).unwrap());
    assert!(host.voting_history_complete(k).unwrap());
    let confirm = host.leave_confirmation(&cmd, &key()).unwrap();
    assert!(
        catalog
            .finish_lobby_leave(guest, &cmd, [&confirm, &confirm])
            .is_err()
    );
    assert_eq!(
        catalog
            .finish_lobby_leave(guest, &cmd, [&confirm, &[]])
            .unwrap(),
        receipt
    );
    assert!(catalog.active_pin().unwrap().is_none());
    assert!(guest.joined_node().is_err());
    let sig = host.sign_voting_checkpoint(high, &key()).unwrap();
    assert!(
        host.store_voting_checkpoint(high, &sig, &[], &key())
            .is_err()
    );
    (cmd, receipt)
}

async fn restart_creator(
    root: &Path,
    cmd: &Signed,
    receipt: &[u8],
    earlier: Option<(&Signed, &[u8])>,
) {
    let mut catalog = InstallationCatalog::open(&root.join("creator")).unwrap();
    let game = catalog
        .open_active(Config::default(), Bus::default())
        .await
        .unwrap();
    game.node.raft.trigger().elect(true).await.unwrap();
    game.node
        .raft
        .wait(Some(Duration::from_secs(6)))
        .state(openraft::ServerState::Leader, "creator elected alone")
        .await
        .unwrap();
    assert_eq!(
        game.node.leave_lobby(cmd, [&[], &[]]).await.unwrap(),
        receipt
    );
    assert!(game.node.leave_confirmation(cmd, &key()).is_ok());
    if let Some((old, expected)) = earlier {
        let (_, proofs) = game.node.retained_leave_confirmations(old).unwrap();
        for proof in proofs {
            let envelope = fields(&proof, &[1, 2]).unwrap();
            let body = fields(envelope[&1], &[1, 2, 3, 4, 5]).unwrap();
            assert_eq!(body[&5], expected);
        }
    }
    game.node.raft.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_guest_requires_a_capable_pinned_profile() {
    let root = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(root.path(), 2, LobbyFormat::Departure).await).await;
    assert!(
        p.game
            .node
            .leave_lobby_witness(&p.learner.actor)
            .await
            .is_err()
    );
    assert_eq!(p.game.node.raft.voter_ids().count(), 2);
    p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_guest_leaves_original_pair_with_quorum_and_recovers_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let (mut p, _) =
        finish_pair(Peers::with_profile(root.path(), 2, LobbyFormat::LastGuest).await).await;
    let (cmd, receipt) = last_guest(
        &p.game.node,
        &p.learner,
        &p.identity,
        &mut p.catalog,
        &p.bus,
    )
    .await;
    let old_admission = p.learner.admission(&p.identity).unwrap();
    let before = crate::learner::history::boundary(&p.game.node.replica.lock().unwrap()).unwrap();
    assert!(
        timeout(Duration::from_secs(2), p.game.admit_learner(&old_admission))
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(
        p.game
            .node
            .raft
            .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
            .await
            .unwrap()
            .index(),
        before.index
    );
    let original_entry: Vec<u8> = p
        .game
        .node
        .replica
        .lock()
        .unwrap()
        .query_row(
            "SELECT entry FROM raft_log WHERE idx=?",
            [before.index.to_be_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let guest_id = p.learner.id();
    let session = p.game.session.clone();
    p.shutdown().await;
    drop(p);
    restart_creator(root.path(), &cmd, &receipt, None).await;
    let catalog = InstallationCatalog::open(&root.path().join("receiver")).unwrap();
    assert_eq!(catalog.departure_receipt(&session).unwrap(), Some(receipt));
    let db = rusqlite::Connection::open(
        root.path()
            .join("receiver")
            .join(format!("learner-{guest_id}-g1.sqlite")),
    )
    .unwrap();
    let observed = crate::learner::history::boundary(&db).unwrap();
    assert!(observed.index < before.index);
    db.execute(
        "INSERT INTO raft_log(idx,entry) VALUES(?,?)",
        rusqlite::params![before.index.to_be_bytes(), original_entry],
    )
    .unwrap();
    store::put(&db, "committed", &Some(before)).unwrap();
    store::put(&db, "applied", &before).unwrap();
    assert!(
        catalog.departure_receipt(&session).is_err(),
        "a reserved request masked a missing applied Leave"
    );
    store::put(&db, "applied", &observed).unwrap();
    store::put(&db, "committed", &Some(observed)).unwrap();
    db.execute(
        "DELETE FROM raft_log WHERE idx=?",
        [before.index.to_be_bytes()],
    )
    .unwrap();
    let saved_digest: Vec<u8> = db
        .query_row(
            "SELECT digest FROM archive WHERE idx=?",
            [observed.index.to_be_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    db.execute(
        "UPDATE archive SET digest=zeroblob(32) WHERE idx=?",
        [observed.index.to_be_bytes()],
    )
    .unwrap();
    assert!(
        catalog.departure_receipt(&session).is_err(),
        "changed observation returned an offline Leave receipt"
    );
    db.execute(
        "UPDATE archive SET digest=? WHERE idx=?",
        rusqlite::params![saved_digest, observed.index.to_be_bytes()],
    )
    .unwrap();
    let joined = store::meta::<JoinedMember>(&db, "first_member")
        .unwrap()
        .unwrap();
    let mut source: Vec<u8> = db
        .query_row(
            "SELECT source FROM archive WHERE idx=?",
            [joined.log_id.index.to_be_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    *source.last_mut().unwrap() ^= 1;
    db.execute(
        "UPDATE archive SET source=? WHERE idx=?",
        rusqlite::params![source, joined.log_id.index.to_be_bytes()],
    )
    .unwrap();
    assert!(
        catalog.departure_receipt(&session).is_err(),
        "offline release accepted a changed predecessor membership source"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_guest_leaves_after_either_guest_left_three_voters() {
    for first_guest_leaves in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let pair =
            finish_pair(Peers::with_profile(root.path(), 3, LobbyFormat::LastGuest).await).await;
        let mut r = admit_to_pair(root.path(), pair).await;
        r.recover().await;
        let join = r.proposal().await.unwrap();
        let host = &r.p.game.node;
        host.join_lobby(&join).await.unwrap();
        let (first, first_key, remaining, remaining_key, remaining_catalog) = if first_guest_leaves
        {
            (
                &r.p.learner,
                &r.p.identity,
                &r.third,
                &r.identity,
                &mut r.catalog,
            )
        } else {
            (
                &r.third,
                &r.identity,
                &r.p.learner,
                &r.p.identity,
                &mut r.p.catalog,
            )
        };
        seal(host, first, first_key).await;
        seal(host, remaining, remaining_key).await;
        let witness = host.leave_lobby_witness(&first.actor).await.unwrap();
        let cmd = first
            .node
            .prepare_leave_lobby(&first.actor, &witness, request(169), first_key)
            .unwrap();
        let a = host.leave_approval(&cmd, &key()).unwrap();
        let b = remaining.node.leave_approval(&cmd, remaining_key).unwrap();
        let prior = host.leave_lobby(&cmd, [&a, &b]).await.unwrap();
        seal(host, remaining, remaining_key).await;
        let (last, receipt) =
            last_guest(host, remaining, remaining_key, remaining_catalog, &r.p.bus).await;
        assert_eq!(host.leave_lobby(&cmd, [&[], &[]]).await.unwrap(), prior);
        assert!(host.leave_lobby_witness(&first.actor).await.is_err());
        let (original, proofs) = host.retained_leave_confirmations(&cmd).unwrap();
        let first_catalog = if first_guest_leaves {
            &mut r.p.catalog
        } else {
            &mut r.catalog
        };
        assert_eq!(
            first_catalog
                .finish_lobby_leave(first, &original, [&proofs[0], &proofs[1]])
                .unwrap(),
            prior
        );
        r.third.shutdown().await.unwrap();
        r.p.shutdown().await;
        drop(r);
        restart_creator(root.path(), &last, &receipt, Some((&cmd, &prior))).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_guest_preserves_a_registered_nonvoting_learner() {
    let root = tempfile::tempdir().unwrap();
    let pair = finish_pair(Peers::with_profile(root.path(), 3, LobbyFormat::LastGuest).await).await;
    let mut r = admit_to_pair(root.path(), pair).await;
    let (cmd, receipt) = last_guest(
        &r.p.game.node,
        &r.p.learner,
        &r.p.identity,
        &mut r.p.catalog,
        &r.p.bus,
    )
    .await;
    let roster =
        crate::learner::history::membership(&r.p.game.node.replica.lock().unwrap()).unwrap();
    assert!(roster.membership().non_write_voter_ids().eq([r.third.id()]));
    let old_route = store::meta::<Vec<u8>>(
        &r.third.node.replica.lock().unwrap(),
        "local_recovery_route",
    )
    .unwrap()
    .unwrap();
    assert!(
        r.p.learner
            .node
            .confirm_recovery_support(&old_route, &r.p.identity)
            .is_err(),
        "retired voter signed learner admission support"
    );
    let challenge = r.third.request(&r.identity).unwrap();
    assert!(
        r.p.learner
            .node
            .voter_recovery_chunk(&challenge, &r.p.identity, async |_| panic!(
                "archive piece contacted peer"
            ))
            .await
            .is_err(),
        "retired donor served an archive piece"
    );
    assert!(r.third.joined_node().is_err());
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
    drop(r);
    restart_creator(root.path(), &cmd, &receipt, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_guest_registered_learner_resumes_from_creator_alone() {
    let root = tempfile::tempdir().unwrap();
    let pair = finish_pair(Peers::with_profile(root.path(), 3, LobbyFormat::LastGuest).await).await;
    let mut r = admit_to_pair(root.path(), pair).await;
    let host = &r.p.game.node;
    let guest = &r.p.learner;
    let first = r.third.request(&r.identity).unwrap();
    let piece = host
        .voter_recovery_chunk(&first, &key(), async |_| panic!("piece contacted peer"))
        .await
        .unwrap();
    r.catalog.accept_chunk(&mut r.third, &piece).unwrap();
    let id = r.third.id();
    r.p.bus.1.lock().unwrap().remove(&id);
    r.third.shutdown().await.unwrap();
    drop(r.third);
    drop(r.catalog);
    let (_, receipt) = last_guest(host, guest, &r.p.identity, &mut r.p.catalog, &r.p.bus).await;
    r.p.bus.6.lock().unwrap().take();
    let path = root.path().join("third");
    let mut catalog = InstallationCatalog::open(&path).unwrap();
    let mut learner = catalog
        .resume_learner(&r.identity, Config::default(), r.p.bus.clone())
        .await
        .unwrap();
    r.p.bus
        .1
        .lock()
        .unwrap()
        .insert(id, (r.p.game.creator_node, learner.replication()));
    // Replace the two-voter Join certificate with a genuine creator-only signature.
    // Even a freshly signed donor envelope cannot authorize that historical entry.
    let join = r.join.log_id;
    let solo = host.sign_voting_checkpoint(join, &key()).unwrap();
    let mut injected = false;
    let attempt = catalog
        .recover_learner(&mut learner, &r.identity, async |request| {
            let body = fields(fields(&request, &[1, 2])?[&1], &[1, 2, 3, 4])?;
            let response = host
                .voter_recovery_chunk(&request, &key(), async |_| panic!("retired peer"))
                .await?;
            if body[&4] != join.index.to_be_bytes() {
                return Ok(response);
            }
            injected = true;
            let mut record = response_fields(&response);
            let data = fields(record[&5], &[1, 2])?;
            let cert = message(&[(1, &solo)]);
            let substituted = message(&[(1, &cert), (2, data[&2])]);
            record.insert(5, &substituted);
            let body = message(&record.into_iter().collect::<Vec<_>>());
            Ok(message(&[(1, &body), (2, &key().sign(&body).to_bytes())]))
        })
        .await;
    assert!(injected && attempt.is_err());
    assert!(catalog.active_pin().unwrap().is_none());
    let resume = learner.request(&r.identity).unwrap();
    assert_eq!(
        fields(fields(&resume, &[1, 2]).unwrap()[&1], &[1, 2, 3, 4]).unwrap()[&4],
        join.index.to_be_bytes()
    );
    let idx = join.index.to_be_bytes();
    let original: Vec<u8> = {
        let db = host.replica.lock().unwrap();
        let cert = db
            .query_row(
                "SELECT certificate FROM historic_seal WHERE idx=?",
                [idx],
                |row| row.get(0),
            )
            .unwrap();
        db.execute("DELETE FROM historic_seal WHERE idx=?", [idx])
            .unwrap();
        cert
    };
    assert!(
        host.voter_recovery_chunk(&resume, &key(), async |_| panic!("unexpected peer"))
            .await
            .is_err()
    );
    assert!(catalog.active_pin().unwrap().is_none());
    host.replica
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO historic_seal VALUES(?,?)",
            rusqlite::params![idx, original],
        )
        .unwrap();
    let mut lost_final = false;
    let attempt = catalog
        .recover_learner(&mut learner, &r.identity, async |request| {
            let response = host
                .voter_recovery_chunk(&request, &key(), async |_| {
                    panic!("retired voter contacted")
                })
                .await?;
            if response_fields(&response)[&4] == [1] {
                lost_final = true;
                return Err(io::ErrorKind::ConnectionReset.into());
            }
            Ok(response)
        })
        .await;
    assert!(
        lost_final,
        "did not reach verified final response: {attempt:?}"
    );
    assert!(catalog.active_pin().unwrap().is_none());
    let retry = learner.request(&r.identity).unwrap();
    let final_reply = host
        .voter_recovery_chunk(&retry, &key(), async |_| panic!("unexpected peer"))
        .await
        .unwrap();
    let other = root.path().join("other-installation");
    std::fs::create_dir(&other).unwrap();
    catalog
        .db
        .execute(
            "VACUUM INTO ?",
            [other.join("installation.sqlite").to_str().unwrap()],
        )
        .unwrap();
    learner
        .node
        .replica
        .lock()
        .unwrap()
        .execute(
            "VACUUM INTO ?",
            [other
                .join(format!("learner-{id}-g1.sqlite"))
                .to_str()
                .unwrap()],
        )
        .unwrap();
    let mut copied = InstallationCatalog::open(&other).unwrap();
    assert!(
        copied.accept_chunk(&mut learner, &final_reply).is_err(),
        "another catalog activated this learner handle"
    );
    assert!(copied.active_pin().unwrap().is_none());
    let envelope = fields(&final_reply, &[1, 2]).unwrap();
    let retired = message(&[
        (1, envelope[&1]),
        (2, &r.p.identity.sign(envelope[&1]).to_bytes()),
    ]);
    assert!(catalog.accept_chunk(&mut learner, &retired).is_err());
    assert!(catalog.active_pin().unwrap().is_none());
    learner.shutdown().await.unwrap();
    r.p.bus.1.lock().unwrap().remove(&id);
    drop(learner);
    drop(catalog);
    let file = path.join(format!("learner-{id}-g1.sqlite"));
    let db = rusqlite::Connection::open(&file).unwrap();
    let prior: Vec<u8> = db
        .query_row(
            "SELECT certificate FROM historic_seal WHERE idx=?",
            [idx],
            |row| row.get(0),
        )
        .unwrap();
    db.execute(
        "UPDATE historic_seal SET certificate=x'00' WHERE idx=?",
        [idx],
    )
    .unwrap();
    let mut partial = InstallationCatalog::open(&path).unwrap();
    assert!(
        partial
            .resume_learner(&r.identity, Config::default(), r.p.bus.clone())
            .await
            .is_err(),
        "restart trusted a damaged staged two-voter certificate"
    );
    assert!(partial.active_pin().unwrap().is_none());
    db.execute(
        "UPDATE historic_seal SET certificate=? WHERE idx=?",
        rusqlite::params![prior, idx],
    )
    .unwrap();
    drop(db);
    drop(partial);
    r.p.shutdown().await;
    drop(r.p);
    let bus = Bus::default();
    let mut creator = InstallationCatalog::open(&root.path().join("creator")).unwrap();
    let game = creator
        .open_active(Config::default(), bus.clone())
        .await
        .unwrap();
    let host = &game.node;
    host.raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "sole creator restart")
        .await
        .unwrap();
    host.raft
        .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
        .await
        .unwrap();
    host.certify_recovery_tail(&key(), async |_| panic!("retired guest"))
        .await
        .unwrap();
    let mut catalog = InstallationCatalog::open(&path).unwrap();
    let mut learner = catalog
        .resume_learner(&r.identity, Config::default(), bus.clone())
        .await
        .unwrap();
    bus.1
        .lock()
        .unwrap()
        .insert(id, (game.creator_node, learner.replication()));
    let lobby = catalog
        .recover_learner(&mut learner, &r.identity, async |request| {
            host.voter_recovery_chunk(&request, &key(), async |_| panic!("unexpected peer"))
                .await
        })
        .await
        .unwrap();
    let again = catalog
        .recover_learner(&mut learner, &r.identity, async |request| {
            let reply = host
                .voter_recovery_chunk(&request, &key(), async |_| panic!("unexpected peer"))
                .await?;
            assert_eq!(response_fields(&reply)[&4], [1]);
            Ok(reply)
        })
        .await
        .unwrap();
    assert_eq!(lobby, again);
    assert_eq!(catalog.recovered_lobby(&learner).unwrap(), Some(lobby));
    assert!(learner.joined_node().is_err());
    {
        let db = learner.node.replica.lock().unwrap();
        let roster = crate::learner::history::membership(&db).unwrap();
        assert!(roster.membership().voter_ids().eq([game.creator_node]));
        assert!(roster.membership().non_write_voter_ids().eq([id]));
        let saved: Vec<u8> = db
            .query_row(
                "SELECT record FROM receipt ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(saved, receipt);
    }
    learner.shutdown().await.unwrap();
    host.raft.shutdown().await.unwrap();
}

mod replacement;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_guest_cannot_sign_a_prepared_promotion_after_release() {
    let root = tempfile::tempdir().unwrap();
    let pair = finish_pair(Peers::with_profile(root.path(), 3, LobbyFormat::LastGuest).await).await;
    let mut r = admit_to_pair(root.path(), pair).await;
    r.recover().await;
    let host = &r.p.game.node;
    let guest = &r.p.learner;
    let mut prepared = None;
    r.catalog
        .prepare_third_join(
            &r.third,
            &r.identity,
            REQUEST,
            true,
            async |draft, route| {
                let proofs = [
                    host.confirm_third_promotion(&draft, &route, &key())?,
                    guest
                        .node
                        .confirm_third_promotion(&draft, &route, &r.p.identity)?,
                ];
                prepared = Some((draft, route));
                Ok(proofs)
            },
        )
        .await
        .unwrap();
    let (draft, route) = prepared.unwrap();
    let witness = host.leave_lobby_witness(&guest.actor).await.unwrap();
    let cmd = guest
        .node
        .prepare_leave_lobby(&guest.actor, &witness, request(181), &r.p.identity)
        .unwrap();
    let a = host.leave_approval(&cmd, &key()).unwrap();
    let b = guest.node.leave_approval(&cmd, &r.p.identity).unwrap();
    guest.node.raft.runtime_config().elect(false);
    *r.p.bus.6.lock().unwrap() = Some(PausedReplication {
        command: cmd.0.clone(),
        attempted: Default::default(),
    });
    host.leave_lobby(&cmd, [&a, &b]).await.unwrap();
    let k = crate::learner::history::boundary(&host.replica.lock().unwrap()).unwrap();
    host.reconcile_voting_history(k, &key(), async |_| panic!("unexpected peer"))
        .await
        .unwrap();
    let confirmation = host.leave_confirmation(&cmd, &key()).unwrap();
    r.p.catalog
        .finish_lobby_leave(guest, &cmd, [&confirmation, &[]])
        .unwrap();
    assert!(
        guest
            .node
            .confirm_third_promotion(&draft, &route, &r.p.identity)
            .is_err(),
        "retired guest signed a pending promotion"
    );
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn last_guest_leader_loses_reply_and_creator_recovers_alone() {
    let root = tempfile::tempdir().unwrap();
    let (p, _) =
        finish_pair(Peers::with_profile(root.path(), 2, LobbyFormat::LastGuest).await).await;
    let host = &p.game.node;
    let guest = &p.learner.node;
    host.raft.runtime_config().heartbeat(false);
    host.raft.runtime_config().elect(false);
    guest.raft.trigger().elect(true).await.unwrap();
    guest
        .raft
        .wait(Some(Duration::from_secs(6)))
        .state(openraft::ServerState::Leader, "guest leader")
        .await
        .unwrap();
    let k = guest
        .raft
        .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
        .await
        .unwrap();
    host.raft
        .wait(Some(Duration::from_secs(6)))
        .applied_index_at_least(Some(k.index()), "creator has elected prefix")
        .await
        .unwrap();
    let high = seal(host, &p.learner, &p.identity).await;
    let witness = guest.leave_lobby_witness(&p.learner.actor).await.unwrap();
    let cmd = guest
        .prepare_leave_lobby(&p.learner.actor, &witness, request(179), &p.identity)
        .unwrap();
    let approvals = [
        host.leave_approval(&cmd, &key()).unwrap(),
        guest.leave_approval(&cmd, &p.identity).unwrap(),
    ];
    // Lose the client response once the creator has durably accepted the original entry.
    let send = guest.leave_lobby(&cmd, [&approvals[0], &approvals[1]]);
    let retained = host.raft.wait(Some(Duration::from_secs(8)));
    let observe = retained.log_index_at_least(Some(high.index + 1), "creator retains final Leave");
    tokio::pin!(observe);
    tokio::select! {
        _ = send => (&mut observe).await.unwrap(),
        result = &mut observe => result.unwrap(),
    };
    let session = p.game.session.clone();
    let identity = p.identity.clone();
    p.shutdown().await;
    drop(p);
    let mut creator = InstallationCatalog::open(&root.path().join("creator")).unwrap();
    let game = creator
        .open_active(Config::default(), Bus::default())
        .await
        .unwrap();
    game.node.raft.trigger().elect(true).await.unwrap();
    game.node
        .raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "creator recovers alone")
        .await
        .unwrap();
    let receipt = game.node.leave_lobby(&cmd, [&[], &[]]).await.unwrap();
    let latest = crate::learner::history::boundary(&game.node.replica.lock().unwrap()).unwrap();
    game.node
        .certify_recovery_tail(&key(), async |_| panic!("old voter is offline"))
        .await
        .unwrap();
    assert!(game.node.voting_history_complete(latest).unwrap());
    let confirm = game.node.leave_confirmation(&cmd, &key()).unwrap();
    let mut catalog = InstallationCatalog::open(&root.path().join("receiver")).unwrap();
    let guest = catalog
        .resume_learner(&identity, Config::default(), Bus::default())
        .await
        .unwrap();
    assert_eq!(
        catalog
            .finish_lobby_leave(&guest, &cmd, [&confirm, &[]])
            .unwrap(),
        receipt
    );
    guest.shutdown().await.unwrap();
    assert_eq!(catalog.departure_receipt(&session).unwrap(), Some(receipt));
    game.node.raft.shutdown().await.unwrap();
}
