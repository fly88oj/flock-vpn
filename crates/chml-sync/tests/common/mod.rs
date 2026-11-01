//! 测试共享 harness（admission/forward 用；cluster.rs 自带同构副本）。
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use flock_protocol::session::{ClusterId, ServerEntry, ServerId, ServerIdentity};
use flock_protocol::trust::ClusterDirectory;
use ed25519_dalek::SigningKey;

use chml_sync::hooks::HookRecorder;
use chml_sync::proto::{NodeId, ReadQuery, ReadView, SyncRequest, SyncResponse};
use chml_sync::testutil::{FabricRegistry, MemoryFabric};
use chml_sync::{SyncNode, SyncNodeBuilder, SyncSettings};

/// 每方向 50ms ⇒ RTT 100ms（§7-M4 注入校准）。
pub const RTT_HALF: Duration = Duration::from_millis(50);

/// NodeId ↔ ServerId（与 chml_sync::wire::sid_of 同映射）。
pub fn sid(n: NodeId) -> ServerId {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&n.to_be_bytes());
    ServerId(b)
}

/// 节点身份+目录签发材料。
pub struct Fixture {
    pub root: SigningKey,
    pub cluster_id: ClusterId,
}

impl Fixture {
    pub fn new() -> Self {
        Fixture {
            root: SigningKey::from_bytes(&[7u8; 32]),
            cluster_id: ClusterId([9u8; 16]),
        }
    }

    /// enroll 一个新服务器身份（运维签发入群凭证，§4-1）。
    pub fn enroll(&self, n: NodeId) -> Arc<ServerIdentity> {
        Arc::new(ServerIdentity::enroll(
            &self.root,
            self.cluster_id,
            sid(n),
            &format!("node-{n}.test:9443"),
        ))
    }

    /// 根签目录（dir_version 递增）。
    pub fn directory(&self, version: u64, idents: &[Arc<ServerIdentity>]) -> ClusterDirectory {
        let entries: Vec<ServerEntry> = idents.iter().map(|i| i.entry.clone()).collect();
        ClusterDirectory::issue(&self.root, self.cluster_id, version, entries)
    }
}

/// 集群（共享织物注册表；可后置加节点——准入流水）。
pub struct TestCluster {
    pub fx: Fixture,
    pub nodes: Vec<SyncNode>,
    pub recorders: Vec<Arc<HookRecorder>>,
    pub reg: FabricRegistry,
    pub idents: Vec<Arc<ServerIdentity>>,
    tmp: tempfile::TempDir,
    next_db: usize,
}

impl TestCluster {
    /// 初始 voters 集群（成员初始化 + 选主等就绪）。
    pub async fn new(voters: &[NodeId]) -> TestCluster {
        let fx = Fixture::new();
        let reg = MemoryFabric::registry();
        let tmp = tempfile::tempdir().expect("tmpdir");
        let mut c = TestCluster {
            fx,
            nodes: Vec::new(),
            recorders: Vec::new(),
            reg,
            idents: Vec::new(),
            tmp,
            next_db: 0,
        };
        let idents: Vec<Arc<ServerIdentity>> = voters.iter().map(|n| c.fx.enroll(*n)).collect();
        let dir = c.fx.directory(1, &idents);
        for ident in &idents {
            c.build_node(ident, &dir, Some(voters)).await;
        }
        c
    }

    /// 构建/加入一个节点（learner 加入用 `members=None` 不做 initialize）。
    pub async fn build_node(
        &mut self,
        ident: &Arc<ServerIdentity>,
        directory: &ClusterDirectory,
        members: Option<&[NodeId]>,
    ) -> usize {
        let fabric = MemoryFabric::new(ident.server_id, &self.reg, RTT_HALF, 2 * 1024 * 1024);
        let rec = HookRecorder::new();
        self.next_db += 1;
        let idx = self.nodes.len();
        let mut b = SyncNodeBuilder::new(
            SyncSettings::default(),
            ident.clone(),
            directory.clone(),
            fabric,
            self.tmp
                .path()
                .join(format!("db-{}-{}.redb", ident.server_id.0[0], self.next_db)),
        )
        .hook(rec.clone());
        if let Some(m) = members {
            b = b.voters(m);
        }
        let node = b.build().await.expect("node build");
        self.nodes.push(node);
        self.recorders.push(rec);
        self.idents.push(ident.clone());
        idx
    }

    /// 等 leader 出现并返回**其自身**下标（≤15s）。
    pub async fn leader(&self) -> (usize, NodeId) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            for n in &self.nodes {
                if let Some(l) = n.current_leader().await {
                    if l == n.id()
                        && matches!(
                            n.raft().metrics().borrow().state,
                            openraft::ServerState::Leader
                        )
                    {
                        let idx = self
                            .nodes
                            .iter()
                            .position(|x| x.id() == l)
                            .expect("leader in nodes");
                        return (idx, l);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("15s 内未选出 leader");
    }

    pub fn node_of(&self, id: NodeId) -> &SyncNode {
        self.nodes.iter().find(|n| n.id() == id).expect("node")
    }

    /// 等指定节点线性一致读出目标状态（快照同步/复制收敛断言用）。
    pub async fn wait_state(
        &self,
        idx: usize,
        check: impl Fn(&ReadView) -> bool,
        budget: Duration,
        what: &str,
    ) -> ReadView {
        let deadline = Instant::now() + budget;
        loop {
            if let Ok(v) = self.nodes[idx].read_linearizable(ReadQuery::State).await {
                if check(&v) {
                    return v;
                }
            }
            assert!(
                Instant::now() < deadline,
                "等待 {what} 超时（{}s）",
                budget.as_secs()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// 引导集群身份（票据密钥根进 Raft）。
pub async fn bootstrap(c: &TestCluster, idx: usize) -> SyncResponse {
    c.nodes[idx]
        .write(SyncRequest::bootstrap_signed(&c.fx.root, [9; 16], [42; 32]))
        .await
        .expect("bootstrap")
}

/// 等某节点的**本地 apply** 追上（转发面读本地注册表——远端提交后需等本地 apply，
/// 正常 < 心跳 500ms + RTT）。
pub async fn wait_local_row(n: &SyncNode, device: &[u8; 32], what: &str) -> [u8; 4] {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(vip) = n.sm().vip_of(device) {
            return vip;
        }
        assert!(Instant::now() < deadline, "等本地 apply（{what}）超时");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
