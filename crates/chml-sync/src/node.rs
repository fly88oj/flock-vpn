//! [`SyncNode`]：单服务器侧的同步装配（§3.10 第一部分的对外门面）。
//!
//! - **任意节点写**：本地 `client_write`，非 leader ⇒ ForwardToLeader ⇒ 经互连会话转发
//!   leader（§4「写转发 leader」，多一跳中转延迟）；
//! - **任意节点线性一致读**：leader 本机 `ensure_linearizable` 后读已 apply 状态；
//!   follower 转发 leader（`read_linearizable`）；
//! - **目录两级读**：[`crate::dir::SyncDirectory`]（缓存 + epoch + lag 熔断）；
//! - **租约 gossip**：publish 即时广播 + 反熵循环（§3.10 LeaseTable）；
//! - **票据签发**：密钥根来自 Raft 状态（Bootstrap 后可用）。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chml_protocol::session::ServerIdentity;
use chml_protocol::trust::ClusterDirectory;
use futures::future::BoxFuture;
use openraft::error::{CheckIsLeaderError, ClientWriteError, RaftError};
use openraft::{BasicNode, Raft};
use redb::Database;

use crate::dir::{DirHandle, LinearizableReader, SyncDirectory};
use crate::hooks::SyncHooks;
use crate::lease::{LeaseTable, ANTI_ENTROPY};
use crate::proto::{NodeId, ReadQuery, ReadView, SyncError, SyncRequest, SyncResponse};
use crate::raft_types::SyncConfig;
use crate::sm::{RedbStateMachine, SmCore};
use crate::store::RedbLogStore;
use crate::ticket::TicketIssuer;
use crate::wire::{Fabric, Interconnect, LagMonitor, RpcTarget, WireResp, WireRpc};

/// 集群运行参数（§4：心跳 500ms / 选举 1.5s~3s——按中转 RTT 100ms 校准；lag 熔断 2s）。
#[derive(Debug, Clone)]
pub struct SyncSettings {
    pub heartbeat_ms: u64,
    pub election_min_ms: u64,
    pub election_max_ms: u64,
    /// apply-lag 熔断阈值（A6 时序预算：2s）。
    pub lag_threshold: Duration,
    /// 单次互连 RPC 预算。
    pub rpc_timeout: Duration,
    /// 写/读转发重试总预算。
    pub forward_deadline: Duration,
    pub lease_ttl: Duration,
}

impl Default for SyncSettings {
    fn default() -> Self {
        SyncSettings {
            heartbeat_ms: 500,
            election_min_ms: 1500,
            election_max_ms: 3000,
            lag_threshold: Duration::from_secs(2),
            rpc_timeout: Duration::from_secs(5),
            forward_deadline: Duration::from_secs(12),
            lease_ttl: crate::lease::LEASE_TTL,
        }
    }
}

/// 节点构造入参。
pub struct SyncNodeBuilder {
    pub settings: SyncSettings,
    /// 本机入群身份（根签 ServerIdentity——enroll 产物）。
    pub ident: Arc<ServerIdentity>,
    /// 根签集群目录（对端接入材料；`verify` 在 build 时执行）。
    pub directory: ClusterDirectory,
    /// 原始织物（内存 duplex / TCP）。
    pub fabric: Arc<dyn Fabric>,
    /// redb 库文件路径。
    pub db_path: PathBuf,
    /// 本机钉扎的集群根公钥（缺省取 ident.root_pub）。
    pub pinned_root: Option<ed25519_dalek::VerifyingKey>,
    hooks: Vec<Arc<dyn SyncHooks>>,
    members: BTreeMap<NodeId, BasicNode>,
    node_id: NodeId,
}

impl SyncNodeBuilder {
    pub fn new(
        settings: SyncSettings,
        ident: Arc<ServerIdentity>,
        directory: ClusterDirectory,
        fabric: Arc<dyn Fabric>,
        db_path: PathBuf,
    ) -> Self {
        let node_id = node_id_of(&ident.server_id);
        SyncNodeBuilder {
            settings,
            ident,
            directory,
            fabric,
            db_path,
            pinned_root: None,
            hooks: Vec::new(),
            members: BTreeMap::new(),
            node_id,
        }
    }

    /// 初始成员集（全部 voter；`initialize` 用）。
    pub fn voters(mut self, ids: &[NodeId]) -> Self {
        self.members = ids
            .iter()
            .map(|id| (*id, BasicNode::new(format!("node-{id}"))))
            .collect();
        self
    }

    /// 注册 apply/租约钩子。
    pub fn hook(mut self, h: Arc<dyn SyncHooks>) -> Self {
        self.hooks.push(h);
        self
    }

    /// 钉扎根公钥（缺省 = ident.root_pub）。
    pub fn pinned_root(mut self, root: ed25519_dalek::VerifyingKey) -> Self {
        self.pinned_root = Some(root);
        self
    }

    /// 装配并启动（Raft 任务 + 互连服务循环 + 反熵循环 + 成员初始化）。
    pub async fn build(self) -> Result<SyncNode, SyncError> {
        // 根签目录验证（无签名/换根 ⇒ 拒装配）。
        if !self.directory.verify(&self.ident.root_pub) {
            return Err(SyncError::Raft("cluster directory failed root verification".into()));
        }
        let pinned = self.pinned_root.unwrap_or(self.ident.root_pub);

        let cfg = openraft::Config {
            cluster_name: "chml-sync".into(),
            heartbeat_interval: self.settings.heartbeat_ms,
            election_timeout_min: self.settings.election_min_ms,
            election_timeout_max: self.settings.election_max_ms,
            install_snapshot_timeout: 10_000,
            ..Default::default()
        };
        let cfg = Arc::new(cfg.validate().map_err(|e| SyncError::Raft(format!("config: {e}")))?);

        let db = Database::create(&self.db_path)
            .map_err(|e| SyncError::Raft(format!("redb open {}: {e}", self.db_path.display())))?;
        let db = Arc::new(db);
        RedbLogStore::init_tables(&db).map_err(|e| SyncError::Raft(format!("redb init: {e}")))?;
        let log_store = RedbLogStore::from_db(db.clone());
        let sm = SmCore::restore_or_empty(db.clone(), Some(pinned));
        for h in self.hooks {
            sm.register_hook(h);
        }

        let ic = Interconnect::new(self.ident.clone(), &self.directory, self.fabric.clone());
        let net = crate::network::SyncNetFactory { ic: ic.clone() };
        let ic_serve_ic = ic.clone();
        let raft = Raft::new(self.node_id, cfg, net, log_store, RedbStateMachine::new(sm.clone()))
            .await
            .map_err(|e| SyncError::Raft(format!("raft start: {e}")))?;

        let lag = LagMonitor::new(self.settings.lag_threshold, sm.applied_counter());
        let lease = LeaseTable::new(self.node_id, self.settings.lease_ttl, sm.shared_hooks());

        // 互连应答循环（无凭证对端在此层被拒）。
        let target = RpcTarget { raft: raft.clone(), sm: sm.clone(), lag: lag.clone(), lease: lease.clone() };
        tokio::spawn(async move {
            ic_serve_ic.serve_loop(target).await;
        });

        // 反熵循环（5s 全表摘要 fan-out）。
        tokio::spawn(anti_entropy_loop(ic.clone(), lease.clone()));

        // 成员初始化（同配置多节点并发 initialize 安全——openraft 契约）。
        if !self.members.is_empty() {
            let _ = raft.initialize(self.members.clone()).await;
        }

        let inner = Arc::new(NodeInner {
            id: self.node_id,
            raft,
            sm,
            lag,
            lease,
            ic,
            settings: self.settings,
            ticket_seq: AtomicU64::new(0),
        });
        let reader = Arc::new(NodeReader(inner.clone()));
        let dir = SyncDirectory::new(reader, inner.lag.clone(), inner.sm.epoch_watch());
        Ok(SyncNode { inner, dir })
    }
}

async fn anti_entropy_loop(ic: Arc<Interconnect>, lease: Arc<LeaseTable>) {
    let mut tick = tokio::time::interval(ANTI_ENTROPY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let msg = lease.anti_entropy_msg();
        for peer in ic_peer_ids(&ic) {
            let _ = ic.call(peer, WireRpc::Gossip(msg.clone()), Duration::from_secs(2)).await;
        }
    }
}

fn ic_peer_ids(ic: &Interconnect) -> Vec<NodeId> {
    ic.node_ids()
}

/// ServerId([u8;16]) ↔ NodeId(u64)（前 8B 大端）。
pub fn node_id_of(sid: &chml_protocol::session::ServerId) -> NodeId {
    u64::from_be_bytes(sid.0[..8].try_into().expect("8B"))
}

pub(crate) struct NodeInner {
    pub id: NodeId,
    pub raft: Raft<SyncConfig>,
    pub sm: Arc<SmCore>,
    pub lag: Arc<LagMonitor>,
    pub lease: Arc<LeaseTable>,
    pub ic: Arc<Interconnect>,
    pub settings: SyncSettings,
    ticket_seq: AtomicU64,
}

/// 目录的线性一致读句柄（`'static` future 要求——克隆内柄）。
struct NodeReader(Arc<NodeInner>);

impl LinearizableReader for NodeReader {
    fn read(&self, q: ReadQuery) -> BoxFuture<'static, Result<ReadView, SyncError>> {
        let me = self.0.clone();
        Box::pin(async move { me.read_linearizable(q).await })
    }
}

impl NodeInner {
    /// 写（leader 本机 / follower 转发；§4 写转发）。
    pub async fn write(&self, req: SyncRequest) -> Result<SyncResponse, SyncError> {
        let deadline = Instant::now() + self.settings.forward_deadline;
        loop {
            match self.raft.client_write(req.clone()).await {
                Ok(r) => return Ok(r.data),
                Err(RaftError::APIError(ClientWriteError::ForwardToLeader(f))) => {
                    if let Some(leader) = f.leader_id.filter(|l| *l != self.id) {
                        if let Ok(WireResp::Write(r)) = self
                            .ic
                            .call(leader, WireRpc::Write(req.clone()), self.settings.rpc_timeout)
                            .await
                        {
                            return r;
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(SyncError::NoLeader);
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                Err(RaftError::APIError(ClientWriteError::ChangeMembershipError(e))) => {
                    return Err(SyncError::Raft(format!("change membership: {e}")));
                }
                Err(RaftError::Fatal(f)) => return Err(SyncError::Raft(format!("fatal: {f}"))),
            }
        }
    }

    /// 线性一致读（leader 本机 ensure；follower 转发 leader）。
    pub async fn read_linearizable(&self, q: ReadQuery) -> Result<ReadView, SyncError> {
        let deadline = Instant::now() + self.settings.forward_deadline;
        loop {
            match self.raft.ensure_linearizable().await {
                Ok(_) => return Ok(crate::wire::read_view(&self.sm, q)),
                Err(RaftError::APIError(CheckIsLeaderError::ForwardToLeader(f))) => {
                    if let Some(leader) = f.leader_id.filter(|l| *l != self.id) {
                        if let Ok(WireResp::Read(r)) = self
                            .ic
                            .call(leader, WireRpc::Read(q.clone()), self.settings.rpc_timeout)
                            .await
                        {
                            return r;
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(SyncError::NoLeader);
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                Err(RaftError::APIError(CheckIsLeaderError::QuorumNotEnough(e))) => {
                    if Instant::now() >= deadline {
                        return Err(SyncError::Raft(format!("quorum: {e}")));
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                Err(RaftError::Fatal(f)) => return Err(SyncError::Raft(format!("fatal: {f}"))),
            }
        }
    }

    /// 票据签发器（密钥根在 Raft 状态内；Bootstrap 前为 None）。
    pub fn ticket_issuer(&self) -> Option<TicketIssuer> {
        self.sm.ticket_root().map(|r| TicketIssuer::from_root(&r))
    }

    fn next_ticket_seq(&self) -> u64 {
        self.ticket_seq.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// 服务器同步门面。
pub struct SyncNode {
    pub(crate) inner: Arc<NodeInner>,
    pub(crate) dir: Arc<SyncDirectory>,
}

impl SyncNode {
    /// 节点号。
    pub fn id(&self) -> NodeId {
        self.inner.id
    }

    /// NetState 写操作（任意节点进入；自动转发 leader）。
    pub async fn write(&self, req: SyncRequest) -> Result<SyncResponse, SyncError> {
        self.inner.write(req).await
    }

    /// 线性一致读（任意节点进入）。
    pub async fn read_linearizable(&self, q: ReadQuery) -> Result<ReadView, SyncError> {
        self.inner.read_linearizable(q).await
    }

    /// DeviceDirectory 接缝句柄（session::respond 注入）。
    pub fn directory(&self) -> DirHandle {
        DirHandle(self.dir.clone())
    }

    /// 目录本体（统计/失效缓存用）。
    pub fn dir(&self) -> &Arc<SyncDirectory> {
        &self.dir
    }

    /// 当前 leader（metrics 视图；None = 选举中）。
    pub async fn current_leader(&self) -> Option<NodeId> {
        self.inner.raft.current_leader().await
    }

    /// 等待 leader 出现（测试/装配用）。
    pub async fn wait_leader(&self, budget: Duration) -> Option<NodeId> {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if let Some(l) = self.inner.raft.current_leader().await {
                return Some(l);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    }

    /// 本地 epoch（随 apply 推进）。
    pub fn local_epoch(&self) -> u64 {
        self.inner.sm.epoch()
    }

    /// apply-lag 熔断状态。
    pub fn breaker_open(&self) -> bool {
        self.inner.lag.breaker_open()
    }

    /// 租约表（publish/observe；冲突新者胜 + 旧端踢出回调）。
    pub fn lease(&self) -> &Arc<LeaseTable> {
        &self.inner.lease
    }

    /// 签发本地票据（TTL 60s，绑定 device + 当前本地 epoch）。
    pub fn issue_ticket(&self, device: [u8; 32], now_unix: u64) -> Result<crate::ticket::Ticket, SyncError> {
        let issuer = self.inner.ticket_issuer().ok_or(SyncError::Raft("not bootstrapped".into()))?;
        Ok(issuer.issue(device, self.inner.sm.epoch(), now_unix, self.inner.next_ticket_seq()))
    }

    /// 校验票据（以本机当前 epoch——§2.2-3 清拒语义）。
    pub fn verify_ticket(
        &self,
        t: &crate::ticket::Ticket,
        device: &[u8; 32],
        now_unix: u64,
    ) -> Result<(), crate::ticket::TicketError> {
        let issuer = self.inner.ticket_issuer().ok_or(crate::ticket::TicketError::BadSignature)?;
        issuer.verify(t, device, self.inner.sm.epoch(), now_unix)
    }

    /// 发布本机设备租约（gossip 事件广播 ≤1s + 反熵兜底）。
    pub async fn publish_lease(&self, device: &[u8; 32]) -> Option<NodeId> {
        let prev = self.inner.lease.publish(device);
        let msg = crate::lease::GossipMsg::Publish {
            device: *device,
            holder: self.inner.id,
            term_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };
        for peer in self.inner.ic.node_ids() {
            if peer != self.inner.id {
                let ic = self.inner.ic.clone();
                let m = msg.clone();
                tokio::spawn(async move {
                    let _ = ic.call(peer, WireRpc::Gossip(m), Duration::from_secs(2)).await;
                });
            }
        }
        prev
    }

    /// Raft 句柄（membership 管理/快照触发等装配面）。
    pub fn raft(&self) -> &Raft<SyncConfig> {
        &self.inner.raft
    }

    /// SM 核（测试观察面：lag 注入器等）。
    pub fn sm(&self) -> &Arc<SmCore> {
        &self.inner.sm
    }

    /// 停机（Raft 关闭；互连织物由外部管理）。
    pub async fn shutdown(&self) -> Result<(), SyncError> {
        self.inner
            .raft
            .shutdown()
            .await
            .map_err(|e| SyncError::Raft(format!("shutdown: {e}")))
    }
}
