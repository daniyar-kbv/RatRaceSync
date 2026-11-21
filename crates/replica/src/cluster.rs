use super::*;
use ed25519_dalek::SigningKey;
use openraft::{
    Config, OptionalSend,
    alias::SnapshotOf,
    errors::{RPCError, ReplicationClosed, StreamingError, Unreachable},
    network::{RPCOption, RaftNetworkFactory, v2::RaftNetworkV2},
    raft::{AppendEntriesRequest, AppendResult, SnapshotResponse, VoteRequest, VoteResponse},
};
use std::{collections::BTreeMap, future::Future, time::Duration};
use tokio::time::{sleep, timeout};

#[derive(Clone, Default)]
struct Bus(Arc<Mutex<BTreeMap<ReplicaId, Raft>>>);
struct Peer {
    bus: Bus,
    id: ReplicaId,
}
impl Peer {
    fn raft(&self) -> Result<Raft, RPCError<Types>> {
        self.bus
            .0
            .lock()
            .unwrap()
            .get(&self.id)
            .cloned()
            .ok_or_else(|| Unreachable::from_string("peer disconnected").into())
    }
}
impl RaftNetworkFactory<Types> for Bus {
    type Network = Peer;
    async fn new_client(&mut self, id: ReplicaId, _: &()) -> Peer {
        Peer {
            bus: self.clone(),
            id,
        }
    }
}
impl RaftNetworkV2<Types> for Peer {
    type SnapshotData = ();
    async fn append_entries(
        &mut self,
        r: AppendEntriesRequest<Types>,
        _: RPCOption,
    ) -> Result<AppendResult<Types>, RPCError<Types>> {
        self.raft()?
            .append_entries(r)
            .await
            .map_err(|e| Unreachable::new(&e).into())
    }
    async fn vote(
        &mut self,
        r: VoteRequest<Types>,
        _: RPCOption,
    ) -> Result<VoteResponse<Types>, RPCError<Types>> {
        self.raft()?
            .vote(r)
            .await
            .map_err(|e| Unreachable::new(&e).into())
    }
    async fn pre_vote(
        &mut self,
        r: VoteRequest<Types>,
        _: RPCOption,
    ) -> Result<VoteResponse<Types>, RPCError<Types>> {
        self.raft()?
            .pre_vote(r)
            .await
            .map_err(|e| Unreachable::new(&e).into())
    }
    async fn full_snapshot(
        &mut self,
        _: Vote,
        _: SnapshotOf<Types, ()>,
        _: impl Future<Output = ReplicationClosed> + OptionalSend + 'static,
        _: RPCOption,
    ) -> Result<SnapshotResponse<Types>, StreamingError<Types>> {
        Err(RPCError::Unreachable(Unreachable::from_string("disabled")).into())
    }
}
const GAME: &[u8] = b"fixture-game";
const ACTOR: &[u8] = b"player";
const LOT: &[u8] = b"certificate";
fn key() -> SigningKey {
    SigningKey::from_bytes(&[71; 32])
}
struct Cluster {
    nodes: Vec<GameNode>,
    bus: Bus,
}
impl Cluster {
    async fn open(dir: &Path, initialize: bool) -> Self {
        let bus = Bus::default();
        let mut nodes = vec![];
        for index in 1u128..=3 {
            let id = ReplicaId(index.to_be_bytes());
            let store = Replica::open(&dir.join(format!("{id}.db")), GAME).unwrap();
            if initialize {
                let db = store.lock().unwrap();
                db.execute(
                    "INSERT INTO participant VALUES(?,?,?,'10000','10000','40')",
                    rusqlite::params![ACTOR, key().verifying_key().as_bytes(), 1u128.to_be_bytes()],
                )
                .unwrap();
                for voter in [2u8, 3] {
                    let fixture_key = SigningKey::from_bytes(&[voter; 32]).verifying_key();
                    db.execute(
                        "INSERT INTO participant VALUES(?,?,?,'0','0','0')",
                        rusqlite::params![
                            [voter],
                            fixture_key.as_bytes(),
                            u128::from(voter).to_be_bytes()
                        ],
                    )
                    .unwrap();
                }
                store::put(&db, "finance_open", &true).unwrap();
                db.execute(
                    "INSERT INTO certificate VALUES(?,?,5000,'2','2')",
                    [ACTOR, LOT],
                )
                .unwrap();
            }
            let config = Config {
                heartbeat_interval: 50,
                election_timeout_min: 160,
                election_timeout_max: 320,
                ..Default::default()
            };
            let node = GameNode::start(id, store, config, bus.clone())
                .await
                .unwrap();
            bus.0.lock().unwrap().insert(id, node.raft.clone());
            nodes.push(node);
        }
        if initialize {
            nodes[0]
                .raft
                .initialize(
                    (1u128..=3)
                        .map(|i| (ReplicaId(i.to_be_bytes()), ()))
                        .collect::<BTreeMap<_, _>>(),
                )
                .await
                .unwrap();
        }
        Self { nodes, bus }
    }
    async fn leader(&self) -> &GameNode {
        timeout(Duration::from_secs(8), async {
            loop {
                for node in &self.nodes {
                    if node
                        .raft
                        .ensure_linearizable(openraft::ReadPolicy::ReadIndex)
                        .await
                        .is_ok()
                    {
                        return node;
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap()
    }
}
async fn command(n: &GameNode, nonce: u8) -> Command {
    let (observed, guard) = n.redemption_guard(ACTOR, LOT).await.unwrap();
    let mut request = [nonce; 16];
    request[6] = 0x40;
    request[8] = 0x80;
    Command {
        session: GAME.into(),
        actor: ACTOR.into(),
        position: LOT.into(),
        request,
        observed,
        guard,
        units: 1.into(),
    }
}
fn counts(node: &GameNode) -> (String, u64, u64) {
    node.replica.lock().unwrap().query_row("SELECT cash,(SELECT count(*) FROM event),(SELECT count(*) FROM receipt) FROM participant WHERE actor=?",[ACTOR],|r|Ok((r.get(0)?,r.get::<_,u32>(1)?.into(),r.get::<_,u32>(2)?.into()))).unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quorum_commit_conflict_and_original_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let c = Cluster::open(dir.path(), true).await;
    let n = c.leader().await;
    let cmd = command(n, 1).await;
    let signed = cmd.sign(&key());
    let stale = command(n, 2).await.sign(&key());
    assert!(n.replica.preflight(&stale).unwrap().is_none());
    let original = n.submit(signed.clone()).await.unwrap();
    let Reply::Receipt(ref original_record) = original else {
        panic!("missing applied receipt")
    };
    let receipt = wire::fields(original_record, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    assert_eq!(receipt[&8].len(), 32);
    let finance = wire::fields(receipt[&7], &[11]).unwrap();
    let leaf = wire::fields(finance[&11], &[109]).unwrap();
    let effects = <Applied as prost::Message>::decode(leaf[&109]).unwrap();
    assert_eq!(
        (
            effects.cash_before.as_str(),
            effects.cash_after.as_str(),
            effects.units_after.as_str(),
            effects.total_income_after.as_str()
        ),
        ("10000", "15000", "1", "20")
    );
    assert_eq!(counts(n), ("15000".into(), 1, 1));
    // Already admitted before the first write, then committed after it.
    let conflict = n.raft.client_write(stale.clone()).await.unwrap().data;
    let Reply::Receipt(ref bytes) = conflict else {
        panic!("missing conflict receipt")
    };
    let record = wire::fields(bytes, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
    assert!(record[&8].is_empty());
    assert_eq!(wire::fields(record[&7], &[13]).unwrap()[&13], [8, 1]);
    assert_eq!(counts(n), ("15000".into(), 1, 2));
    assert_eq!(n.submit(stale).await.unwrap(), conflict);
    let mut changed = cmd;
    changed.units = 2.into();
    assert_eq!(
        n.submit(changed.sign(&key())).await.unwrap(),
        Reply::RequestIdConflict
    );
    n.submit(command(n, 3).await.sign(&key())).await.unwrap();
    assert_eq!(n.submit(signed.clone()).await.unwrap(), original);
    for node in &c.nodes {
        timeout(Duration::from_secs(3), async {
            while counts(node) != ("20000".into(), 2, 3) {
                sleep(Duration::from_millis(15)).await
            }
        })
        .await
        .unwrap();
        use sha2::{Digest, Sha256};
        let db = node.replica.lock().unwrap();
        let (source, digest, tip): (Vec<u8>, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT source,digest,receipt_tip FROM archive WHERE log_id=?",
                [receipt[&5]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(source.strip_prefix(&[1]), Some(signed.0.as_slice()));
        assert_eq!(digest, Sha256::digest(&source).as_slice());
        let (stored, stored_tip): (Vec<u8>, Vec<u8>) = db
            .query_row("SELECT record,tip FROM receipt WHERE seq=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(&stored, original_record);
        assert_eq!(stored_tip, tip);
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn minority_cannot_apply() {
    let dir = tempfile::tempdir().unwrap();
    let c = Cluster::open(dir.path(), true).await;
    let n = c.leader().await;
    let signed = command(n, 1).await.sign(&key());
    c.bus.0.lock().unwrap().clear();
    let result = timeout(Duration::from_secs(1), n.raft.client_write(signed)).await;
    assert!(!matches!(result, Ok(Ok(_))));
    assert_eq!(counts(n), ("10000".into(), 0, 0));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_worker() {
    let Some(path) = std::env::var_os("REDEMPTION_TEST_DIR") else {
        return;
    };
    let dir = Path::new(&path);
    let c = Cluster::open(dir, true).await;
    let n = c.leader().await;
    let signed = command(n, 1).await.sign(&key());
    std::fs::write(dir.join("signed"), &signed.0).unwrap();
    std::fs::write(
        dir.join("leader"),
        n.raft.current_leader().await.unwrap().to_string(),
    )
    .unwrap();
    let mode = std::env::var("REDEMPTION_CRASH").unwrap().parse().unwrap();
    n.replica
        .crash
        .store(mode, std::sync::atomic::Ordering::Release);
    let _ = n.submit(signed).await;
    panic!("crash point missed")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_process_loss_before_and_after_sql_commit() {
    for mode in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "cluster::crash_worker"])
            .env("REDEMPTION_TEST_DIR", dir.path())
            .env("REDEMPTION_CRASH", mode.to_string())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(80 + mode));
        let leader = std::fs::read_to_string(dir.path().join("leader")).unwrap();
        let original_on_disk = {
            use rusqlite::OptionalExtension;
            let db = Connection::open(dir.path().join(format!("{leader}.db"))).unwrap();
            let cash: String = db
                .query_row("SELECT cash FROM participant WHERE actor=?", [ACTOR], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(cash, if mode == 1 { "10000" } else { "15000" });
            let record = db
                .query_row("SELECT record FROM receipt", [], |r| r.get::<_, Vec<u8>>(0))
                .optional()
                .unwrap();
            assert_eq!(record.is_some(), mode == 2);
            record
        };
        let c = Cluster::open(dir.path(), false).await;
        let n = c.leader().await;
        let signed = Signed(std::fs::read(dir.path().join("signed")).unwrap());
        let original = n
            .replica
            .preflight(&signed)
            .unwrap()
            .expect("committed effect recovered before retry");
        assert_eq!(n.submit(signed).await.unwrap(), original);
        if let Some(record) = original_on_disk {
            assert_eq!(original, Reply::Receipt(record));
        }
        assert_eq!(counts(n), ("15000".into(), 1, 1));
    }
}
mod failure;
