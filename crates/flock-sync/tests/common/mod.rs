//! Shared test harness (used by admission/forward; cluster.rs carries its own
//! isomorphic copy).
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use flock_protocol::session::{ClusterId, ServerEntry, ServerId, ServerIdentity};
use flock_protocol::trust::ClusterDirectory;

use flock_sync::hooks::HookRecorder;
use flock_sync::proto::{NodeId, SyncRequest, SyncResponse};
use flock_sync::testutil::{FabricRegistry, MemoryFabric};
use flock_sync::{SyncNode, SyncNodeBuilder, SyncSettings};

/// 50ms per direction ⇒ RTT 100ms (§7-M4 injection calibration).
pub const RTT_HALF: Duration = Duration::from_millis(50);

/// NodeId ↔ ServerId (same mapping as flock_sync::wire::sid_of).
pub fn sid(n: NodeId) -> ServerId {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&n.to_be_bytes());
    ServerId(b)
}

/// Node identity + directory issuance material.
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

    /// Enroll a new server identity (operations issues the enrollment
    /// credential, §4-1).
    pub fn enroll(&self, n: NodeId) -> Arc<ServerIdentity> {
        Arc::new(ServerIdentity::enroll(
            &self.root,
            self.cluster_id,
            sid(n),
            &format!("node-{n}.test:9443"),
        ))
    }

    /// A root-signed directory (dir_version increasing).
    pub fn directory(&self, version: u64, idents: &[Arc<ServerIdentity>]) -> ClusterDirectory {
        let entries: Vec<ServerEntry> = idents.iter().map(|i| i.entry.clone()).collect();
        ClusterDirectory::issue(&self.root, self.cluster_id, version, entries)
    }
}

/// A cluster (shared fabric registry; nodes can be added later — the
/// admission pipeline).
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
    /// An initial-voters cluster (membership initialization + leader election
    /// etc. all ready).
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

    /// Build/join a node (learner joins with `members=None`, skipping
    /// initialize).
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

    /// Wait for a leader to appear and return **its own** index (≤15s).
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
        panic!("no leader elected within 15s");
    }

    pub fn node_of(&self, id: NodeId) -> &SyncNode {
        self.nodes.iter().find(|n| n.id() == id).expect("node")
    }
}

/// Bootstrap the cluster identity (the ticket key root goes into Raft).
pub async fn bootstrap(c: &TestCluster, idx: usize) -> SyncResponse {
    c.nodes[idx]
        .write(SyncRequest::bootstrap_signed(&c.fx.root, [9; 16], [42; 32]))
        .await
        .expect("bootstrap")
}

/// Wait for a node's **local apply** to catch up (the forwarding plane reads
/// the local registry — after a remote commit you must wait for the local
/// apply, normally < heartbeat 500ms + RTT).
pub async fn wait_local_row(n: &SyncNode, device: &[u8; 32], what: &str) -> [u8; 4] {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(vip) = n.sm().vip_of(device) {
            return vip;
        }
        assert!(
            Instant::now() < deadline,
            "waiting for local apply ({what}) timed out"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
