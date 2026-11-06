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
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use flock_protocol::session::ServerIdentity;
use flock_protocol::trust::ClusterDirectory;
use futures::future::BoxFuture;
use openraft::error::{CheckIsLeaderError, ClientWriteError, RaftError};
use openraft::{BasicNode, Raft};
use redb::Database;

use crate::dir::{DirHandle, LinearizableReader, SyncDirectory};
use crate::directory::Directory;
use crate::forward::{ForwardEnvelope, ForwardOutcome, ForwardPlane, ForwardTransport, PacketSink};
use crate::hooks::SyncHooks;
use crate::lease::{LeaseTable, LocateFanout, ANTI_ENTROPY};
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
            return Err(SyncError::Raft(
                "cluster directory failed root verification".into(),
            ));
        }
        let pinned = self.pinned_root.unwrap_or(self.ident.root_pub);

        let cfg = openraft::Config {
            cluster_name: "flock-sync".into(),
            heartbeat_interval: self.settings.heartbeat_ms,
            election_timeout_min: self.settings.election_min_ms,
            election_timeout_max: self.settings.election_max_ms,
            install_snapshot_timeout: 10_000,
            ..Default::default()
        };
        let cfg = Arc::new(
            cfg.validate()
                .map_err(|e| SyncError::Raft(format!("config: {e}")))?,
        );

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
        let raft = Raft::new(
            self.node_id,
            cfg,
            net,
            log_store,
            RedbStateMachine::new(sm.clone()),
        )
        .await
        .map_err(|e| SyncError::Raft(format!("raft start: {e}")))?;

        let lag = LagMonitor::new(
            self.settings.lag_threshold,
            Duration::from_millis(self.settings.election_max_ms),
            sm.applied_counter(),
        );
        let lease = LeaseTable::new(self.node_id, self.settings.lease_ttl, sm.shared_hooks());
        let directory = Arc::new(
            Directory::new(self.ident.root_pub, &self.directory)
                .map_err(|e| SyncError::Raft(format!("directory: {e}")))?,
        );
        let forward = ForwardPlane::new(self.node_id, sm.clone(), lease.clone());

        // 互连应答循环（无凭证对端在此层被拒）。
        let target = RpcTarget {
            raft: raft.clone(),
            sm: sm.clone(),
            lag: lag.clone(),
            lease: lease.clone(),
            forward: forward.clone(),
            directory: directory.clone(),
        };
        tokio::spawn(async move {
            ic_serve_ic.serve_loop(target).await;
        });

        // 反熵循环（5s 全表摘要 fan-out）+ 本地会话租约续期（TTL/3 重发布）+ EWMA
        // 折叠（1s 窗——M7）。
        tokio::spawn(anti_entropy_loop(ic.clone(), lease.clone()));
        tokio::spawn(lease_refresh_loop(
            ic.clone(),
            lease.clone(),
            forward.clone(),
            self.node_id,
        ));
        tokio::spawn(ewma_tick_loop(lease.clone()));

        // 成员初始化（同配置多节点并发 initialize 安全——openraft 契约）。
        if !self.members.is_empty() {
            if let Err(e) = raft.initialize(self.members.clone()).await {
                // NotAllowed = 集群已有日志/成员（他节点先初始化或本机重启再入）——正常
                // 收敛路径，静默放行；其余错误（NotInMembers 等）记日志：初成员集装配
                // 故障必须可观测，静默吞掉会让「带病启动」无迹可循。
                if !matches!(
                    e,
                    RaftError::APIError(openraft::error::InitializeError::NotAllowed(_))
                ) {
                    eprintln!("raft initialize failed: {e}");
                }
            }
        }

        // 转发面互连接缝（FRWD 流 + location_query 扇出）。
        let fwd_transport = Arc::new(IcForwardTransport { ic: ic.clone() });
        let fwd_fanout = Arc::new(IcLocateFanout {
            ic: ic.clone(),
            me: self.node_id,
        });
        forward.set_transport(fwd_transport, fwd_fanout);

        let inner = Arc::new(NodeInner {
            id: self.node_id,
            entry: self.ident.entry.clone(),
            raft,
            sm,
            lag,
            lease,
            ic,
            directory,
            forward,
            settings: self.settings,
            ticket_seq: AtomicU64::new(0),
        });
        let reader = Arc::new(NodeReader(inner.clone()));
        let dir = SyncDirectory::new(reader, inner.lag.clone(), inner.sm.epoch_watch());
        Ok(SyncNode { inner, dir })
    }
}

/// 本地会话租约续期：每 [`LEASE_REFRESH`]（TTL/3）把仍在本机在线的设备重新
/// publish + 广播（publish 建连时只发一次——无此循环则 30s 后租约全网蒸发）。
/// M7：同循环**自发布服务器自身租约**（合成设备键——名册 Server 条目的 ewma/在线
/// 状态经既有 gossip 通路全网可见）。
async fn lease_refresh_loop(
    ic: Arc<Interconnect>,
    lease: Arc<LeaseTable>,
    forward: Arc<crate::forward::ForwardPlane>,
    me: NodeId,
) {
    let mut tick = tokio::time::interval(crate::lease::LEASE_REFRESH);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let mut devices = forward.local_devices();
        devices.push(crate::lease::server_self_device_id(me));
        for device in devices {
            let _ = lease.publish(&device);
            broadcast_publish(&ic, &lease, me, device);
        }
    }
}

/// M7：EWMA 折叠循环（1s 窗，§7-M7.3）——持有者侧把 per-device 字节累加器折进行内
/// ewma（下一个续期/反熵携带出去）。
async fn ewma_tick_loop(lease: Arc<LeaseTable>) {
    let mut tick = tokio::time::interval(crate::lease::EWMA_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        lease.tick_ewma(now_ms());
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 单条租约事件广播（publish/续期共用）。M7：消息携带行内 ewma/last_seen（持有者
/// 权威值）；term 取刚 publish 落表的那条（消除旧实现「广播 term 与落表 term 各取
/// 一次时钟」的毫秒级错位）。
fn broadcast_publish(
    ic: &Arc<Interconnect>,
    lease: &Arc<LeaseTable>,
    me: NodeId,
    device: [u8; 32],
) {
    let Some(l) = lease.observe(&device) else {
        return;
    };
    let msg = crate::lease::GossipMsg::Publish {
        device,
        holder: me,
        term_ms: l.term_ms,
        tx_ewma: l.tx_ewma,
        rx_ewma: l.rx_ewma,
        last_seen_unix: l.last_seen_unix,
    };
    for peer in ic.node_ids() {
        if peer != me {
            let ic = ic.clone();
            let m = msg.clone();
            tokio::spawn(async move {
                let _ = ic
                    .call(peer, WireRpc::Gossip(m), Duration::from_secs(2))
                    .await;
            });
        }
    }
}

async fn anti_entropy_loop(ic: Arc<Interconnect>, lease: Arc<LeaseTable>) {
    let mut tick = tokio::time::interval(ANTI_ENTROPY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let msg = lease.anti_entropy_msg();
        for peer in ic_peer_ids(&ic) {
            let _ = ic
                .call(peer, WireRpc::Gossip(msg.clone()), Duration::from_secs(2))
                .await;
        }
    }
}

fn ic_peer_ids(ic: &Interconnect) -> Vec<NodeId> {
    ic.node_ids()
}

/// ServerId([u8;16]) ↔ NodeId(u64)（前 8B 大端）。
pub fn node_id_of(sid: &flock_protocol::session::ServerId) -> NodeId {
    u64::from_be_bytes(sid.0[..8].try_into().expect("8B"))
}

pub(crate) struct NodeInner {
    pub id: NodeId,
    pub entry: flock_protocol::session::ServerEntry,
    pub raft: Raft<SyncConfig>,
    pub sm: Arc<SmCore>,
    pub lag: Arc<LagMonitor>,
    pub lease: Arc<LeaseTable>,
    pub ic: Arc<Interconnect>,
    pub directory: Arc<Directory>,
    pub forward: Arc<ForwardPlane>,
    pub settings: SyncSettings,
    ticket_seq: AtomicU64,
}

/// FRWD 流发送接缝：ForwardEnvelope 经互连 E2E 会话（外层服务器间加密）。
struct IcForwardTransport {
    ic: Arc<Interconnect>,
}

impl ForwardTransport for IcForwardTransport {
    fn send(
        &self,
        peer: NodeId,
        env: ForwardEnvelope,
    ) -> BoxFuture<'static, io::Result<ForwardOutcome>> {
        let ic = self.ic.clone();
        Box::pin(async move {
            match ic
                .call(peer, WireRpc::Forward(env), Duration::from_secs(3))
                .await
            {
                Ok(WireResp::Forward(r)) => Ok(r),
                Ok(_) => Err(io::Error::other("forward rpc response mismatch")),
                Err(e) => Err(io::Error::from(e)),
            }
        })
    }
}

/// location_query 扇出接缝：问 ≤3 台互连服务器「谁在托管该设备」（一次性，不重试）。
struct IcLocateFanout {
    ic: Arc<Interconnect>,
    me: NodeId,
}

impl LocateFanout for IcLocateFanout {
    fn locate(&self, device: &[u8; 32]) -> BoxFuture<'static, Option<NodeId>> {
        let ic = self.ic.clone();
        let me = self.me;
        let device = *device;
        Box::pin(async move {
            let peers: Vec<NodeId> = ic
                .node_ids()
                .into_iter()
                .filter(|p| *p != me)
                .take(3)
                .collect();
            for peer in peers {
                if let Ok(WireResp::Locate(Some(holder))) = ic
                    .call(peer, WireRpc::Locate(device), Duration::from_secs(2))
                    .await
                {
                    return Some(holder);
                }
            }
            None
        })
    }
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
    ///
    /// 转发重试纪律：远端又回 `ForwardToLeader`（leader 更替中）或 `NoLeader` 时**不透传
    /// 给调用方**——回到循环在 `forward_deadline`（12s）预算内重试，与本地 client_write
    /// 路径一致；远端确定性错误（Raft fatal 等）才直接返回。
    pub async fn write(&self, req: SyncRequest) -> Result<SyncResponse, SyncError> {
        let deadline = Instant::now() + self.settings.forward_deadline;
        loop {
            match self.raft.client_write(req.clone()).await {
                Ok(r) => return Ok(r.data),
                Err(RaftError::APIError(ClientWriteError::ForwardToLeader(f))) => {
                    if let Some(leader) = f.leader_id.filter(|l| *l != self.id) {
                        match self
                            .ic
                            .call(
                                leader,
                                WireRpc::Write(req.clone()),
                                self.settings.rpc_timeout,
                            )
                            .await
                        {
                            Ok(WireResp::Write(Ok(resp))) => return Ok(resp),
                            // 远端也在 leader 更替中 ⇒ 回环重试（预算内），不透传。
                            Ok(WireResp::Write(Err(
                                SyncError::ForwardToLeader { .. } | SyncError::NoLeader,
                            ))) => {}
                            Ok(WireResp::Write(Err(other))) => return Err(other),
                            Ok(_) => {
                                return Err(SyncError::Wire("write rpc response mismatch".into()))
                            }
                            Err(e) => eprintln!("write forward to {leader} failed: {e}"),
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
    pub fn device_directory(&self) -> DirHandle {
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
    pub fn issue_ticket(
        &self,
        device: [u8; 32],
        now_unix: u64,
    ) -> Result<crate::ticket::Ticket, SyncError> {
        let issuer = self
            .inner
            .ticket_issuer()
            .ok_or(SyncError::Raft("not bootstrapped".into()))?;
        Ok(issuer.issue(
            device,
            self.inner.sm.epoch(),
            now_unix,
            self.inner.next_ticket_seq(),
        ))
    }

    /// 校验票据（以本机当前 epoch——§2.2-3 清拒语义）。
    pub fn verify_ticket(
        &self,
        t: &crate::ticket::Ticket,
        device: &[u8; 32],
        now_unix: u64,
    ) -> Result<(), crate::ticket::TicketError> {
        let issuer = self
            .inner
            .ticket_issuer()
            .ok_or(crate::ticket::TicketError::BadSignature)?;
        issuer.verify(t, device, self.inner.sm.epoch(), now_unix)
    }

    /// 发布本机设备租约（gossip 事件广播 ≤1s + 反熵兜底 + TTL/3 续期循环）。
    pub async fn publish_lease(&self, device: &[u8; 32]) -> Option<NodeId> {
        let prev = self.inner.lease.publish(device);
        broadcast_publish(&self.inner.ic, &self.inner.lease, self.inner.id, *device);
        prev
    }

    /// Raft 句柄（**仅 `test-util` 档**：本 crate 集成测试以外部 crate 视角用
    /// `.raft().metrics()` 断言成员收敛——tests/cluster、tests/admission 等）。
    ///
    /// 可见性收敛（评审项 13）：生产构建不存在裸 Raft 访问器——外部消费方
    /// （flock-server 等）所需能力经白名单方法（[`SyncNode::membership_voters`]/
    /// [`SyncNode::raft_state`] 等）；crate 内部直接持 `inner.raft`。
    #[cfg(feature = "test-util")]
    pub fn raft(&self) -> &Raft<SyncConfig> {
        &self.inner.raft
    }

    /// openraft 真实 membership 的 voter 集（白名单查询——外部对账用，替代裸句柄）。
    pub fn membership_voters(&self) -> std::collections::BTreeSet<NodeId> {
        self.inner
            .raft
            .metrics()
            .borrow()
            .membership_config
            .voter_ids()
            .collect()
    }

    /// Raft metrics 摘要：本节点 server state（Leader/Follower/Candidate/Learner）。
    pub fn raft_state(&self) -> openraft::ServerState {
        self.inner.raft.metrics().borrow().state
    }

    /// 本机入群凭证公开部分（ServerEntry——server_keys/rewrap 封装目标等用）。
    pub fn entry(&self) -> &flock_protocol::session::ServerEntry {
        &self.inner.entry
    }

    /// 应答侧握手拒绝计数（无凭证/伪造凭证在握手层被拒——admission 断言面）。
    pub fn rejected_handshakes(&self) -> u64 {
        self.inner.ic.rejected_handshakes()
    }

    /// 互连诊断计数（拨号 ok/err，RPC ok/err——M5 排障面）。
    pub fn interconnect_diag(&self) -> (u64, u64, u64, u64) {
        self.inner.ic.diag()
    }

    // ------------------------------------------------------------------
    // 集群准入（§4-3：learner → 快照同步 → add_voter 根签 → 提升；§3.10）
    // ------------------------------------------------------------------

    /// 安装根签新目录（根验签 + 版本回退拒；热更新互连映射——准入新服务器后全网可拨）。
    pub fn install_directory(&self, dir: &ClusterDirectory) -> Result<(), SyncError> {
        self.inner
            .directory
            .install(dir)
            .map_err(|e| SyncError::Raft(format!("install directory: {e}")))?;
        self.inner
            .ic
            .update_nodes(self.inner.directory.node_entries());
        Ok(())
    }

    /// 目录服务（dir_pull 下发根签 ClusterDirectory，§3.10 `Directory::serve`）。
    pub fn directory(&self) -> &Arc<Directory> {
        &self.inner.directory
    }

    /// 以 learner 加入集群（leader 侧调用；blocking = 等日志/快照追平）。
    pub async fn add_learner(&self, node_id: NodeId) -> Result<(), SyncError> {
        self.inner
            .raft
            .add_learner(
                node_id,
                openraft::BasicNode::new(format!("node-{node_id}")),
                true,
            )
            .await
            .map(|_| ())
            .map_err(|e| SyncError::Raft(format!("add_learner: {e}")))
    }

    /// 快照触发 + 日志压实（准入流水用：迫使新 learner 走快照同步路径）。
    ///
    /// **压实前置条件**：快照确认落盘且覆盖 `applied` 才 purge——快照未在预算内确认
    /// 即返回 [`SyncError::Raft`] 并**跳过 purge**（压实未落盘快照之下的日志 = 重启后
    /// 状态丢失；openraft 的 `get_snapshot` 可能返回旧快照，故校验其边界 ≥ applied）。
    pub async fn snapshot_and_purge(&self) -> Result<u64, SyncError> {
        let applied = self.inner.sm.applied_index();
        if applied == 0 {
            // 空日志无谓压实（也无状态可丢）。
            return Ok(0);
        }
        self.inner
            .raft
            .trigger()
            .snapshot()
            .await
            .map_err(|e| SyncError::Raft(format!("trigger snapshot: {e}")))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let confirmed = loop {
            let snap_idx = self
                .inner
                .raft
                .get_snapshot()
                .await
                .ok()
                .flatten()
                .and_then(|s| s.meta.last_log_id.map(|l| l.index));
            if snap_idx.is_some_and(|i| i >= applied) {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        if !confirmed {
            return Err(SyncError::Raft(format!(
                "snapshot covering index {applied} not confirmed within 5s; purge skipped"
            )));
        }
        self.inner
            .raft
            .trigger()
            .purge_log(applied)
            .await
            .map_err(|e| SyncError::Raft(format!("purge: {e}")))?;
        Ok(applied)
    }

    /// add_voter 管理操作（§4-3）：先经 Raft 状态机提交根签 AdminOp::AddVoter（验签后
    /// 记录 voters + config_version），再执行 openraft 成员提升（joint 共识）。
    /// 状态机拒绝（无根签名/未引导）⇒ 不提升，原样返回拒绝响应。
    ///
    /// **提升前对账**：状态机 voters 与 openraft 真实 membership（`raft.metrics()`）是
    /// 两个真相源，可能发散（错过的成员日志/部分完成的提升）。差异（超出本次新增的
    /// node_id）时告警，并以**真实 membership 为基准合并**（并集——状态机已提交的
    /// admin 准入不丢，openraft 已有的 voter 不误删；旧实现只看状态机副本，
    /// 发散时会静默丢 voter 或复活死节点）。
    pub async fn add_voter_signed(
        &self,
        root: &ed25519_dalek::SigningKey,
        node_id: NodeId,
    ) -> Result<SyncResponse, SyncError> {
        let resp = self
            .write(SyncRequest::add_voter_signed(root, node_id))
            .await?;
        if matches!(resp, SyncResponse::Error(_)) {
            return Ok(resp);
        }
        // 真实 membership（openraft metrics——Raft 实际共识的成员集）。
        let real: std::collections::BTreeSet<NodeId> = self
            .inner
            .raft
            .metrics()
            .borrow()
            .membership_config
            .voter_ids()
            .collect();
        let sm: std::collections::BTreeSet<NodeId> = self.inner.sm.with_data(|d| d.voters.clone());
        let drift: Vec<NodeId> = real
            .symmetric_difference(&sm)
            .copied()
            .filter(|id| *id != node_id)
            .collect();
        if !drift.is_empty() {
            eprintln!(
                "add_voter: SM voters 与 openraft membership 发散（{drift:?}）——\
                 以真实 membership 为基准合并提升集"
            );
        }
        let mut voters = real;
        voters.extend(sm);
        voters.insert(self.inner.id);
        voters.insert(node_id);
        self.inner
            .raft
            .change_membership(openraft::ChangeMembers::ReplaceAllVoters(voters), false)
            .await
            .map_err(|e| SyncError::Raft(format!("change membership: {e}")))?;
        Ok(resp)
    }

    // ------------------------------------------------------------------
    // 转发面 + 租约（§2.2/§3.10）
    // ------------------------------------------------------------------

    /// 转发面（本机投递/跨服转发/源 VIP 校验）。
    pub fn forward(&self) -> &Arc<ForwardPlane> {
        &self.inner.forward
    }

    /// 挂载本地设备会话投递 sink（装配层映射 PacketChannel）。
    pub fn attach_session(&self, device: [u8; 32], sink: Arc<dyn PacketSink>) {
        self.inner.forward.attach_session(device, sink);
    }

    /// 卸载本地设备会话。
    pub fn detach_session(&self, device: &[u8; 32]) {
        self.inner.forward.detach_session(device);
    }

    /// 会话入向处理（§2.2 转发判定序；装配层从 PacketChannel 读出后调用）。
    pub async fn ingest_packet(
        &self,
        device: &[u8; 32],
        pkt: &[u8],
    ) -> crate::forward::IngestResult {
        self.inner.forward.ingest(device, pkt).await
    }

    /// 挂载本机内核（服务器自身 peer 面，§2.2）：`vip` = 本机 tun VIP，`sink` = tun
    /// 写泵。dst = 自身 VIP 的入向包注入内核（A2 ping / A4 iperf 本服路径）。
    pub fn set_local_peer(
        &self,
        vip: std::net::Ipv4Addr,
        sink: Arc<dyn crate::forward::PacketSink>,
    ) {
        self.inner.forward.set_local_peer(vip, sink);
    }

    /// 本机内核出向（tun 读泵产出：ICMP 回程/本机协议栈流量）路由进 mesh。
    pub async fn route_outbound(&self, pkt: &[u8]) {
        self.inner.forward.route_outbound(pkt).await
    }

    /// 一次性位置询问（本地租约域优先；fan-out ≤3 台互连服务器）。
    pub async fn location_query(&self, device: &[u8; 32]) -> Option<NodeId> {
        let fanout = IcLocateFanout {
            ic: self.inner.ic.clone(),
            me: self.inner.id,
        };
        self.inner.lease.location_query(device, &fanout).await
    }

    /// SM 核（**仅 `test-util` 档**：本 crate 集成测试的观察面——lag 注入器
    /// （tests/cluster 的 apply-lag 熔断用例）/VIP 反查断言等。评审项 13 收敛：
    /// 生产构建不存在裸 SM 访问器——外部（flock-server）所需能力经下方白名单
    /// 方法（register_hook/oprf_b64/local_wrap）获得，不再直捣状态机核。
    #[cfg(feature = "test-util")]
    pub fn sm(&self) -> &Arc<SmCore> {
        &self.inner.sm
    }

    /// 注册 apply/租约钩子（[`SyncNodeBuilder::hook`] 的 build 后等价物——装配层
    /// （flock-server `open_sync`）在节点构建后才具备 hooks 所需的 sessions/node
    /// 句柄，无法全部前置到 builder；评审项 13 白名单方法）。
    pub fn register_hook(&self, h: Arc<dyn SyncHooks>) {
        self.inner.sm.register_hook(h);
    }

    /// 集群共享 OPRF key（b64；本地已 apply 视图，未登记 ⇒ None）。
    /// （评审项 13：原 `sm().oprf_b64()` 的白名单形态。）
    pub fn oprf_b64(&self) -> Option<String> {
        self.inner.sm.oprf_b64()
    }

    /// M7（§7-M7.4）：注册表快照——**本地已 apply 视图**（两级读缓存档即可，不强制
    /// 线性一致读：名册是展示面，允许 follower 视图的秒级陈旧）。评审项 13 白名单
    /// 方法（外部不经裸 SM 访问器取全表）。
    pub fn devices_snapshot(&self) -> Vec<([u8; 32], crate::proto::DeviceRow)> {
        self.inner
            .sm
            .with_data(|d| d.devices.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    /// M7（§7-M7.4）：server_keys 快照（本地已 apply 视图——名册 Server 条目的
    /// vip/节点号数据源）。
    pub fn server_keys_snapshot(&self) -> Vec<(NodeId, crate::proto::ServerKeyEntry)> {
        self.inner
            .sm
            .with_data(|d| d.server_keys.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    /// 本机已 apply 视图内某服务器的 secrets-rewrap 封装副本（OPRF 封装面：
    /// 各服务器启动时取自己的 wrap 用本机 hybrid sk 解封；None = 该服务器的
    /// 封装尚未在本节点 apply）。
    pub fn local_wrap(&self, server_id: NodeId) -> Option<Vec<u8>> {
        self.inner
            .sm
            .with_data(|d| d.wraps.get(&server_id).cloned())
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
