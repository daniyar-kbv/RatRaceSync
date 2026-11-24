use super::*;

struct Transport<'a> {
    host: &'a GameNode,
    second: &'a GameNode,
    second_key: &'a SigningKey,
    third: ReplicaId,
    refreshed: usize,
    dropped: bool,
}
impl ThirdJoinTransport for Transport<'_> {
    async fn recover(&mut self, q: Vec<u8>) -> io::Result<Vec<u8>> {
        self.refreshed += 1;
        self.second
            .voter_recovery_chunk(&q, self.second_key, async |q| {
                self.host.attest_recovery(&q, &key())
            })
            .await
    }
    async fn confirm(&mut self, draft: Vec<u8>, route: Vec<u8>) -> io::Result<[Vec<u8>; 2]> {
        Ok([
            self.host.confirm_third_promotion(&draft, &route, &key())?,
            self.second
                .confirm_third_promotion(&draft, &route, self.second_key)?,
        ])
    }
    async fn submit(&mut self, raw: Vec<u8>) -> io::Result<JoinResult> {
        let result = self.second.join_lobby(&raw).await?;
        if !self.dropped {
            self.dropped = true;
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "lost committed response",
            ));
        }
        Ok(result)
    }
    async fn history(&mut self, q: VotingHistoryRequest) -> io::Result<Vec<u8>> {
        self.second
            .answer_history_request(self.third, q, self.second_key)
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_prefix_refresh_preserves_original_request_and_retry_skips_old_voters() {
    let dir = tempfile::tempdir().unwrap();
    let mut r = admitted_third(dir.path()).await;
    r.recover().await;
    let initial = r.proposal().await.unwrap();
    let first = fields(&initial, &[1, 2, 3, 4]).unwrap()[&1].to_vec();
    let host = &r.p.game.node;
    let second = &r.p.learner.node;
    host.raft.runtime_config().elect(false);
    host.raft.runtime_config().heartbeat(false);
    r.p.bus
        .1
        .lock()
        .unwrap()
        .insert(r.third.id(), (r.p.learner.id(), r.third.replication()));
    second
        .raft
        .wait(Some(Duration::from_secs(8)))
        .state(openraft::ServerState::Leader, "new leader")
        .await
        .unwrap();
    let k = second
        .raft
        .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
        .await
        .unwrap();
    for n in [&**host, &r.third.node] {
        n.raft
            .wait(Some(Duration::from_secs(6)))
            .applied_index_at_least(Some(k.index()), "new leader prefix")
            .await
            .unwrap();
    }
    second
        .certify_recovery_tail(&r.p.identity, async |q| {
            host.answer_history_request(r.p.learner.id(), q, &key())
        })
        .await
        .unwrap();
    assert_eq!(
        second.join_lobby(&initial).await.unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let mut network = Transport {
        host,
        second,
        second_key: &r.p.identity,
        third: r.third.id(),
        refreshed: 0,
        dropped: false,
    };
    let err = r
        .catalog
        .join_third_player(&mut r.third, &r.identity, REQUEST, true, &mut network)
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    assert!(network.refreshed > 0);
    let raw = r.catalog.pending_join(&r.third).unwrap();
    assert_eq!(fields(&raw, &[1, 2, 3, 4]).unwrap()[&1], first);
    assert_ne!(initial, raw);
    let count = network.refreshed;
    let delivered = r
        .catalog
        .join_third_player(&mut r.third, &r.identity, REQUEST, true, &mut network)
        .await
        .unwrap();
    delivered.history.unwrap();
    assert_eq!(delivered.join, second.join_lobby(&initial).await.unwrap());
    assert_eq!(count, network.refreshed);
    r.third.shutdown().await.unwrap();
    r.p.shutdown().await;
}
