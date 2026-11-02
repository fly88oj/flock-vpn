//! 服务器-服务器 profile E2E 会话传输（§3.10 接缝 / §4-2 互连认证）+ RPC 分发 +
//! apply-lag 熔断监控（§4 读与缓存）。
//!
//! **互连认证**：服务器互连（Raft/gossip）跑 flock-protocol 会话协议的服务器-服务器
//! profile——双向入群凭证：
//! - 发起侧 `session::initiate`：以本机身份/静态密钥为「设备」材料，对端 ServerPin 来自
//!   根签 ClusterDirectory（I1 的 KEM 封给对端静态混合公钥；R1 身份签名按根签条目验证）；
//! - 应答侧 `session::respond` + [`PeerDirectory`]：只认根签 ClusterDirectory 内的
//!   服务器身份（设备目录三态查无 ⇒ 同一不透明 `DeviceRejected`）。
//!   ⇒ **无有效入群凭证的对端在握手层即被拒**（拿不到快照也进不了 Raft，R19 红线）。
//!
//! **RPC 帧协议**：一条互连会话（Tunnel）内每 RPC 开一条 yamux 流，帧 = `[u32 LE 长度]
//! postcard(WireRpc)`，响应同构。长连会话由 [`Interconnect`] 缓存复用（断流重建）。
//!
//! **apply-lag 熔断**：分发器在收到 AppendEntries 时观察 `leader_commit`（openraft 携带
//! leader 全局提交点），配合本机 SM 的 applied index，落后超过阈值（2s = A6 时序预算）
//! 即 [`LagMonitor::breaker_open`]——本地缓存路径停用、降级线性一致读（§4/R24）。
//! 完全分区（观察流消失）由「心跳静默」维度覆盖：距上一帧观察超过
//! max(lag_threshold, election_timeout) 同样开熔断（`LagMonitor` 文档）。

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flock_protocol::mux::{Prio, Stream as MuxStream};
use flock_protocol::session::{
    self, ClusterId, DeviceDirectory, DeviceId, DeviceRecord, DeviceStaticKeys, LookupVerdict,
    ServerEntry, ServerIdentity, ServerPin,
};
use flock_protocol::trust::ClusterDirectory;
use ed25519_dalek::VerifyingKey;
use futures::future::BoxFuture;
use openraft::error::{RPCError, RaftError, RemoteError, Timeout, Unreachable};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, Raft};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::lease::{GossipMsg, LeaseTable};
use crate::proto::{NodeId, ReadQuery, ReadView, SyncError, SyncRequest};
use crate::raft_types::SyncConfig;
use crate::sm::SmCore;

/// 帧上限（快照分片缺省 512KiB + 余量）。
const MAX_FRAME: usize = 8 * 1024 * 1024;

// ============================================================================
// 接缝：原始 IO 织物（内存 duplex / TCP——后者由服务器装配批次接）
// ============================================================================

/// 双向异步流对象类型。
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncReadWrite for T {}
/// 装箱的对端 IO。
pub type PeerIo = Box<dyn AsyncReadWrite + Unpin>;

/// 原始传输织物接缝：`dial` 拨对端、`accept` 收入连（生产 = TCP 监听；测试 = 内存
/// duplex 对，可叠加 RTT/故障注入）。
pub trait Fabric: Send + Sync + 'static {
    fn dial(
        &self,
        target: &flock_protocol::session::ServerId,
    ) -> BoxFuture<'static, io::Result<PeerIo>>;
    fn accept(&self) -> BoxFuture<'static, io::Result<PeerIo>>;
}

/// NodeId(u64) ↔ ServerId([u8;16]) 映射（前 8B 大端承载，低位补零——目录内一一对应）。
pub fn sid_of(node: NodeId) -> flock_protocol::session::ServerId {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&node.to_be_bytes());
    flock_protocol::session::ServerId(b)
}

// ============================================================================
// apply-lag 熔断监控（§4 读与缓存 / R24）
// ============================================================================

/// follower 侧 apply 滞后监控——两个维度，任一触发即熔断打开（停用本地缓存、降级
/// 线性一致读）：
///
/// 1. **apply-lag**：心跳/AppendEntries 携带的 leader commit index 与本地 applied index
///    之差持续超过 `threshold`（A6 时序预算 2s）；
/// 2. **心跳静默**：距上一帧 AppendEntries/心跳观察超过 `max(threshold,
///    election_timeout)`。完全分区下 `leader_commit` 冻结且等于本地 applied——「未落后」
///    是盲区（leader 可能已提交吊销而本机看不见），观察流本身消失才是可靠信号。
///    从未观察过的节点（启动后未入网/被隔离的原 leader）自监控构造时刻起算。
///
/// 静默的代价披露：稳定 leader 不收 AppendEntries，其自身熔断会因静默常开——语义安全
/// （降级路径 = leader 本机 `ensure_linearizable`，结果与缓存一致），代价是 leader 侧
/// 缓存不生效（R18 的风暴吸收由 follower 承担）。分区恢复首帧观察到 `leader_commit >
/// applied` 时，pending 窗起点回溯到静默起点（恢复即已超窗，立即熔断，不重新计时）。
pub struct LagMonitor {
    threshold: Duration,
    /// 静默上限 = max(threshold, election_timeout)。
    silence_limit: Duration,
    applied: Arc<AtomicU64>,
    st: Mutex<MonitorSt>,
}

struct MonitorSt {
    leader_commit: u64,
    pending_since: Option<Instant>,
    /// 最近一次收到 AppendEntries/心跳观察的时刻（构造时刻起算）。
    last_obs: Instant,
    open: bool,
}

impl LagMonitor {
    /// `applied` = SM 维护的已 apply 最高 index（`SmCore`）；`election_timeout` =
    /// 本机选举超时上限（静默判定第二维——小于它即选举窗口内，不构成失联证据）。
    pub fn new(
        threshold: Duration,
        election_timeout: Duration,
        applied: Arc<AtomicU64>,
    ) -> Arc<Self> {
        Arc::new(LagMonitor {
            threshold,
            silence_limit: threshold.max(election_timeout),
            applied,
            st: Mutex::new(MonitorSt {
                leader_commit: 0,
                pending_since: None,
                last_obs: Instant::now(),
                open: false,
            }),
        })
    }

    /// 分发器观察 leader commit index（AppendEntries 携带）。
    pub fn observe_leader_commit(&self, idx: u64) {
        let mut st = self.st.lock().expect("lag monitor");
        let prev_obs = st.last_obs;
        st.last_obs = Instant::now();
        if idx > st.leader_commit {
            st.leader_commit = idx;
        }
        let applied = self.applied.load(Ordering::SeqCst);
        // 回溯：观察到落后时，pending 窗起点不晚于上一帧观察时刻（静默起点）——
        // 分区期间攒下的落后在恢复首帧即视为已超窗。
        if st.leader_commit > applied {
            st.pending_since = Some(st.pending_since.unwrap_or(prev_obs).min(prev_obs));
        }
        self.recompute(&mut st);
    }

    /// 熔断是否打开（惰性评估时间窗）。
    pub fn breaker_open(&self) -> bool {
        let mut st = self.st.lock().expect("lag monitor");
        self.recompute(&mut st);
        st.open
    }

    /// 观察到的 leader commit index（诊断/断言）。
    pub fn leader_commit(&self) -> u64 {
        self.st.lock().expect("lag monitor").leader_commit
    }

    fn recompute(&self, st: &mut MonitorSt) {
        // 维度二：心跳静默——完全分区（观察流消失）即开熔断。静默期不开 pending 窗
        // （无从比较）；恢复首帧的回溯由 observe_leader_commit 完成。
        if st.last_obs.elapsed() > self.silence_limit {
            st.open = true;
            return;
        }
        // 维度一：apply-lag。
        let applied = self.applied.load(Ordering::SeqCst);
        if st.leader_commit > applied {
            match st.pending_since {
                None => {
                    st.pending_since = Some(Instant::now());
                    st.open = false;
                }
                Some(since) => {
                    if since.elapsed() > self.threshold {
                        st.open = true;
                    }
                }
            }
        } else {
            st.pending_since = None;
            st.open = false;
        }
    }
}

// ============================================================================
// 服务器-服务器 profile：目录与互连
// ============================================================================

/// 应答侧目录：只认根签 ClusterDirectory 内的服务器身份（入群凭证认证的对向半边）。
#[derive(Clone)]
pub struct PeerDirectory {
    entries: Arc<std::sync::RwLock<BTreeMap<NodeId, ServerEntry>>>,
}

impl PeerDirectory {
    pub fn new(entries: Arc<std::sync::RwLock<BTreeMap<NodeId, ServerEntry>>>) -> Self {
        PeerDirectory { entries }
    }
}

impl DeviceDirectory for PeerDirectory {
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict> {
        for e in self.entries.read().expect("peer dir").values() {
            if DeviceId::from_ed25519(&e.identity_pub) == *id {
                let rec = DeviceRecord {
                    device_x25519: *e.static_hybrid_pub.x25519_public(),
                    device_ed25519: e.identity_pub,
                };
                return Box::pin(async move { LookupVerdict::Active(rec) });
            }
        }
        // 查无 ⇒ NotFound（respond 汇入同一不透明 DeviceRejected——无凭证即拒）。
        Box::pin(async move { LookupVerdict::NotFound })
    }
}

/// 一条到对端的已认证互连会话（Tunnel；Drop 即终止）。
struct Pipe {
    tunnel: session::Tunnel,
}

impl Drop for Pipe {
    fn drop(&mut self) {}
}

impl Pipe {
    async fn open_stream(&self) -> io::Result<MuxStream> {
        self.tunnel.open_stream(Prio::Control).await
    }
}

/// 互连管理器：缓存到各对端的 E2E 会话，按 RPC 开流；应答侧 `serve_loop` 收会话/收流。
pub struct Interconnect {
    ident: Arc<ServerIdentity>,
    /// 本机作为发起方的「设备」材料 = 身份 Ed25519 + 静态混合 X25519（与入群凭证同源）。
    self_keys: DeviceStaticKeys,
    cluster_id: ClusterId,
    root_pub: VerifyingKey,
    nodes: Arc<std::sync::RwLock<BTreeMap<NodeId, ServerEntry>>>,
    fabric: Arc<dyn Fabric>,
    pipes: tokio::sync::Mutex<BTreeMap<NodeId, Arc<Pipe>>>,
    /// 每对端 RPC 门闩（同一互连会话至多一条在途 RPC——mux 驱动单待开流 +
    /// yamux ACK 积压按流计，串行化后每条 RPC 完整走完生命周期，不互相拆台）。
    gates: std::sync::Mutex<BTreeMap<NodeId, Arc<tokio::sync::Mutex<()>>>>,
    session_cfg: session::TunnelConfig,
    /// 会话建立/RPC 预算（缺省 5s）。
    pub rpc_timeout: Duration,
    /// 应答侧握手拒绝计数（无凭证/坏握手——对发起端表现为不透明的连接终止）。
    rejected_handshakes: AtomicU64,
    /// 互连诊断计数（M5 排障面：拨号/RPC 成败）。
    pub(crate) diag_dial_ok: AtomicU64,
    pub(crate) diag_dial_err: AtomicU64,
    pub(crate) diag_rpc_ok: AtomicU64,
    pub(crate) diag_rpc_err: AtomicU64,
}

impl Interconnect {
    /// 由根签目录与本机身份构造。`directory` 提供全部对端 ServerEntry（根验签由调用方
    /// 在装配期完成——`ClusterDirectory::verify`）。
    pub fn new(
        ident: Arc<ServerIdentity>,
        directory: &ClusterDirectory,
        fabric: Arc<dyn Fabric>,
    ) -> Arc<Self> {
        let mut nodes = BTreeMap::new();
        for e in &directory.servers {
            // ServerId ↔ NodeId 映射（前 8B）。
            let nid = u64::from_be_bytes(e.server_id.0[..8].try_into().expect("8B"));
            nodes.insert(nid, e.clone());
        }
        let nodes: Arc<std::sync::RwLock<BTreeMap<NodeId, ServerEntry>>> =
            Arc::new(std::sync::RwLock::new(nodes));
        // 发起方「设备」材料 = 本机静态 X25519 + 身份 Ed25519（与入群凭证同源——
        // 应答侧 PeerDirectory 按根签条目的同两把公钥比对）。
        let key_bytes = {
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(&ident.static_hybrid.x25519_secret().to_bytes());
            b[32..].copy_from_slice(&ident.identity.to_bytes());
            b
        };
        Arc::new(Interconnect {
            self_keys: DeviceStaticKeys::from_bytes(&key_bytes),
            cluster_id: directory.cluster_id,
            root_pub: ident.root_pub,
            ident,
            nodes,
            fabric,
            pipes: tokio::sync::Mutex::new(BTreeMap::new()),
            gates: std::sync::Mutex::new(BTreeMap::new()),
            session_cfg: session::TunnelConfig::default(),
            rpc_timeout: Duration::from_secs(5),
            rejected_handshakes: AtomicU64::new(0),
            diag_dial_ok: AtomicU64::new(0),
            diag_dial_err: AtomicU64::new(0),
            diag_rpc_ok: AtomicU64::new(0),
            diag_rpc_err: AtomicU64::new(0),
        })
    }

    /// 集群根公钥（入群凭证验证锚；与 `ServerIdentity::root_pub` 一致）。
    pub fn root_pub(&self) -> &VerifyingKey {
        &self.root_pub
    }

    /// 目录内全部节点号（gossip fan-out / location_query fan-out 用）。
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.nodes
            .read()
            .expect("ic nodes")
            .keys()
            .copied()
            .collect()
    }

    /// 热更新互连目录映射（准入新服务器：根签新目录全网 install 后调用）。
    pub fn update_nodes(&self, entries: BTreeMap<NodeId, ServerEntry>) {
        *self.nodes.write().expect("ic nodes") = entries;
    }

    /// 应答侧握手拒绝计数（无凭证/伪造凭证——admission 断言面）。
    pub fn rejected_handshakes(&self) -> u64 {
        self.rejected_handshakes.load(Ordering::Relaxed)
    }

    fn peer_entry(&self, peer: NodeId) -> io::Result<ServerEntry> {
        self.nodes
            .read()
            .expect("ic nodes")
            .get(&peer)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no directory entry for node {peer}"),
                )
            })
    }

    async fn connect_pipe(&self, peer: NodeId) -> io::Result<Arc<Pipe>> {
        let entry = self.peer_entry(peer)?;
        let io = match self.fabric.dial(&entry.server_id).await {
            Ok(io) => {
                self.diag_dial_ok.fetch_add(1, Ordering::Relaxed);
                io
            }
            Err(e) => {
                self.diag_dial_err.fetch_add(1, Ordering::Relaxed);
                eprintln!("interconnect: dial node {peer} failed: {e}");
                return Err(e);
            }
        };
        let pin = ServerPin {
            cluster_id: self.cluster_id,
            cluster_root_pub: self.root_pub,
            entry: entry.clone(),
        };
        let tunnel = tokio::time::timeout(
            self.rpc_timeout,
            session::initiate(io, &self.self_keys, &pin, self.session_cfg.clone()),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "interconnect handshake timeout"))?
        .map_err(|e| io::Error::other(format!("interconnect handshake: {e}")))?;
        Ok(Arc::new(Pipe { tunnel }))
    }

    /// 到对端开一条 RPC 流（缓存会话优先；失效重建一次）。
    ///
    /// **锁纪律（M5 e2e 实测教训）**：全局 pipes 锁不得跨任何网络 await——对端宕机时
    /// 其拨号（DNS NXDOMAIN 可达秒级）+ 握手会阻塞**所有**对端的 RPC（含 Raft 心跳），
    /// 500ms 心跳/1.5s 选举超时下即触发选举抖动（A7 窗口实测）。此处在锁外完成
    /// 开流/拨号/握手，回锁只做查插（竞态双连无害——后写者胜）。
    async fn open_stream(&self, peer: NodeId) -> io::Result<MuxStream> {
        let cached = self.pipes.lock().await.get(&peer).cloned();
        if let Some(pipe) = cached {
            match pipe.open_stream().await {
                Ok(s) => return Ok(s),
                Err(_) => {
                    self.pipes.lock().await.remove(&peer);
                }
            }
        }
        let pipe = self.connect_pipe(peer).await?;
        let s = pipe.open_stream().await?;
        self.pipes.lock().await.insert(peer, pipe.clone());
        Ok(s)
    }

    /// 每对端 RPC 门闩（无则建）。
    fn gate_of(&self, peer: NodeId) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self.gates.lock().expect("ic gates");
        gates
            .entry(peer)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// 逐出对端缓存会话（超时/IO 故障后由下一条 RPC 重建）。
    async fn evict(&self, peer: NodeId) {
        self.pipes.lock().await.remove(&peer);
    }

    /// 一次 RPC 往返（门闩内：开流 → 帧请求 → 帧响应；超时/IO 错误逐出会话重建）。
    pub async fn call(
        &self,
        peer: NodeId,
        rpc: WireRpc,
        timeout: Duration,
    ) -> Result<WireResp, WireCallError> {
        let gate = self.gate_of(peer);
        let _guard = gate.lock().await;
        let mut stream = match self.open_stream(peer).await {
            Ok(s) => s,
            Err(e) => {
                return Err(WireCallError::Io(e));
            }
        };
        let req = postcard::to_allocvec(&rpc)
            .map_err(|e| WireCallError::Io(io::Error::other(format!("encode: {e}"))))?;
        let fut = async {
            send_frame(&mut stream, &req).await?;
            let resp = recv_frame(&mut stream).await?;
            postcard::from_bytes::<WireResp>(&resp)
                .map_err(|e| io::Error::other(format!("decode: {e}")))
        };
        match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(resp)) => {
                self.diag_rpc_ok.fetch_add(1, Ordering::Relaxed);
                Ok(resp)
            }
            Ok(Err(e)) => {
                // 流级 IO 错误：会话可能半死——逐出，下一条 RPC 重握手。
                self.diag_rpc_err.fetch_add(1, Ordering::Relaxed);
                eprintln!("interconnect: rpc to {peer} io-error: {e}");
                self.evict(peer).await;
                Err(WireCallError::Io(e))
            }
            Err(_) => {
                self.diag_rpc_err.fetch_add(1, Ordering::Relaxed);
                eprintln!("interconnect: rpc to {peer} timed out ({timeout:?})");
                self.evict(peer).await;
                Err(WireCallError::TimedOut)
            }
        }
    }

    /// 互连诊断计数（M5 排障面）。
    pub fn diag(&self) -> (u64, u64, u64, u64) {
        (
            self.diag_dial_ok.load(Ordering::Relaxed),
            self.diag_dial_err.load(Ordering::Relaxed),
            self.diag_rpc_ok.load(Ordering::Relaxed),
            self.diag_rpc_err.load(Ordering::Relaxed),
        )
    }

    /// 应答侧主循环：收入连 → 服务器-服务器 profile 应答（无凭证即拒）→ 逐流分发。
    pub async fn serve_loop(self: Arc<Self>, target: RpcTarget) {
        loop {
            let io = match self.fabric.accept().await {
                Ok(io) => io,
                Err(_) => {
                    // 织物关闭（节点停机）——退出服务循环。
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    return;
                }
            };
            let this = self.clone();
            let target = target.clone();
            tokio::spawn(async move {
                let dir = PeerDirectory::new(this.nodes.clone());
                match session::respond(io, &this.ident, dir, this.session_cfg.clone()).await {
                    Ok(tunnel) => this.serve_tunnel(tunnel, target).await,
                    Err(_) => {
                        // 无凭证/坏握手 ⇒ 会话拒（§4-2：握手层即拒——拿不到快照也进不了
                        // Raft：分发器只存在于认证会话之内）。
                        this.rejected_handshakes.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    }

    async fn serve_tunnel(&self, tunnel: session::Tunnel, target: RpcTarget) {
        loop {
            match tunnel.accept_stream().await {
                Some(stream) => {
                    let target = target.clone();
                    // 每流一任务：IO 断裂/解码失败仅结束该流（会话保持）。
                    tokio::spawn(async move {
                        let _ = handle_stream(stream, target).await;
                    });
                }
                None => return,
            }
        }
    }
}

/// 单流处理：一请求一响应。
async fn handle_stream(mut stream: MuxStream, target: RpcTarget) -> io::Result<()> {
    let req = recv_frame(&mut stream).await?;
    let rpc: WireRpc =
        postcard::from_bytes(&req).map_err(|e| io::Error::other(format!("rpc decode: {e}")))?;
    let resp = dispatch(&target, rpc).await;
    let bytes =
        postcard::to_allocvec(&resp).map_err(|e| io::Error::other(format!("resp encode: {e}")))?;
    send_frame(&mut stream, &bytes).await?;
    stream.finish().await?;
    Ok(())
}

// ============================================================================
// 线格式
// ============================================================================

/// 互连 RPC 请求（Raft 三类 + 客户端写/读转发 + gossip 租约）。
/// 快照分片：`InstallSnapshotRequest.data` 即 `Vec<u8>`（openraft 0.9.25 非泛型快照
/// 传输形态），直接 serde 承载。
#[derive(Serialize, Deserialize)]
pub enum WireRpc {
    Append(AppendEntriesRequest<SyncConfig>),
    Vote(VoteRequest<u64>),
    Snapshot(InstallSnapshotRequest<SyncConfig>),
    Write(SyncRequest),
    Read(ReadQuery),
    Gossip(GossipMsg),
    /// 位置询问（location_query fan-out 的单跳：问「谁在托管该设备」）。
    Locate([u8; 32]),
    /// 跨服转发（FRWD 流承载 ForwardEnvelope，§2.2-3）。
    Forward(crate::forward::ForwardEnvelope),
    /// dir_pull（客户端经控制流发起；此处为服务器侧 serve 实现，§3.10）。
    DirPull {
        since: u64,
    },
}

/// 互连 RPC 响应（远端 Raft 致命错误统一折算 `Err(String)` → 调用方按 Unreachable 处理；
/// ForwardToLeader 语义在 Write/Read 路径以 [`SyncError`] 结构化保留）。
#[derive(Serialize, Deserialize)]
pub enum WireResp {
    Append(Result<AppendEntriesResponse<u64>, RaftError<u64>>),
    Vote(Result<VoteResponse<u64>, RaftError<u64>>),
    Snapshot(Result<InstallSnapshotResponse<u64>, String>),
    Write(Result<crate::proto::SyncResponse, SyncError>),
    Read(Result<ReadView, SyncError>),
    Gossip(bool),
    /// 持有者节点号（本地租约域命中才答）。
    Locate(Option<NodeId>),
    Forward(crate::forward::ForwardOutcome),
    DirPull(crate::directory::DirPullResp),
}

/// 互连调用失败。
#[derive(Debug)]
pub enum WireCallError {
    Io(io::Error),
    TimedOut,
    /// 响应形态与请求不匹配（协议错）。
    Mismatch,
}

impl std::fmt::Display for WireCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireCallError::Io(e) => write!(f, "wire io: {e}"),
            WireCallError::TimedOut => write!(f, "wire rpc timeout"),
            WireCallError::Mismatch => write!(f, "wire rpc response mismatch"),
        }
    }
}
impl std::error::Error for WireCallError {}
impl From<WireCallError> for io::Error {
    fn from(e: WireCallError) -> Self {
        match e {
            WireCallError::Io(e) => e,
            other => io::Error::other(other.to_string()),
        }
    }
}

/// 分发目标（Raft 句柄 + SM 核 + lag 监控 + 租约表 + 转发面 + 目录服务）。
#[derive(Clone)]
pub struct RpcTarget {
    pub raft: Raft<SyncConfig>,
    pub sm: Arc<SmCore>,
    pub lag: Arc<LagMonitor>,
    pub lease: Arc<LeaseTable>,
    pub forward: Arc<crate::forward::ForwardPlane>,
    pub directory: Arc<crate::directory::Directory>,
}

/// 入站 RPC 分发（应答侧核心）。
pub async fn dispatch(target: &RpcTarget, rpc: WireRpc) -> WireResp {
    match rpc {
        WireRpc::Append(req) => {
            // §4：心跳/AppendEntries 携带 leader commit index——follower 据此自监听 lag。
            target
                .lag
                .observe_leader_commit(req.leader_commit.map(|l| l.index).unwrap_or(0));
            WireResp::Append(target.raft.append_entries(req).await)
        }
        WireRpc::Vote(req) => WireResp::Vote(target.raft.vote(req).await),
        WireRpc::Snapshot(req) => {
            WireResp::Snapshot(match target.raft.install_snapshot(req).await {
                Ok(r) => Ok(r),
                Err(e) => Err(format!("{e}")),
            })
        }
        WireRpc::Write(req) => {
            let r = target
                .raft
                .client_write(req)
                .await
                .map(|r| r.data)
                .map_err(sync_error_from_write);
            WireResp::Write(r)
        }
        WireRpc::Read(q) => {
            // leader 侧线性一致读：ensure_linearizable 后读本机已 apply 状态。
            match target.raft.ensure_linearizable().await {
                Ok(_) => WireResp::Read(Ok(read_view(&target.sm, q))),
                Err(e) => WireResp::Read(Err(sync_error_from_check(e))),
            }
        }
        WireRpc::Gossip(m) => {
            target.lease.merge_remote(m);
            WireResp::Gossip(true)
        }
        WireRpc::Locate(device) => {
            // 「设备当前位置唯一真相源 = 租约域」：只按本地租约作答（TTL 内有效）。
            WireResp::Locate(target.lease.observe(&device).map(|l| l.holder))
        }
        WireRpc::Forward(env) => WireResp::Forward(target.forward.receive(env)),
        WireRpc::DirPull { since } => WireResp::DirPull(target.directory.dir_pull_response(since)),
    }
}

/// leader 侧线性一致读视图。
pub fn read_view(sm: &SmCore, q: ReadQuery) -> ReadView {
    use crate::proto::{ReadQuery as Q, ReadView as V};
    sm.with_data(|d| match q {
        Q::Lookup(id) => V::Verdict(d.lookup(&id)),
        Q::Epoch => V::Epoch(d.epoch),
        Q::DeviceRow(id) => V::Device(d.devices.get(&id).cloned()),
        Q::Wrap(server) => V::Wrap(d.wraps.get(&server).cloned()),
        Q::User(u) => V::User(d.users.get(&u).cloned()),
        Q::DevicesOf(owner) => V::Devices(
            d.devices
                .iter()
                .filter(|(_, r)| r.owner == *owner)
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        ),
        Q::State => V::State(d.state_view()),
    })
}

fn sync_error_from_write(
    e: RaftError<u64, openraft::error::ClientWriteError<u64, BasicNode>>,
) -> SyncError {
    match e {
        RaftError::APIError(openraft::error::ClientWriteError::ForwardToLeader(f)) => {
            SyncError::ForwardToLeader {
                leader: f.leader_id,
            }
        }
        other => SyncError::Raft(other.to_string()),
    }
}

fn sync_error_from_check(
    e: RaftError<u64, openraft::error::CheckIsLeaderError<u64, BasicNode>>,
) -> SyncError {
    match e {
        RaftError::APIError(openraft::error::CheckIsLeaderError::ForwardToLeader(f)) => {
            SyncError::ForwardToLeader {
                leader: f.leader_id,
            }
        }
        other => SyncError::Raft(other.to_string()),
    }
}

// ============================================================================
// 帧编解码
// ============================================================================

/// 帧发送（`[u32 LE 长度][payload]`；mux::Stream 实现 futures IO）。
async fn send_frame<W: futures::AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::other("frame too large"));
    }
    use futures::AsyncWriteExt;
    w.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    w.write_all(bytes).await?;
    w.flush().await?;
    Ok(())
}

/// 帧接收（读到声明长度；EOF 由对端 close 表达）。
async fn recv_frame<R: futures::AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    use futures::AsyncReadExt;
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame length"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

// ============================================================================
// RPCError 映射辅助（network.rs 消费）
// ============================================================================

/// 互连调用错误 → openraft RPCError（超时 ⇒ Timeout；其余 ⇒ Unreachable）。
pub fn rpc_error_of(peer: NodeId, e: WireCallError) -> RPCError<u64, BasicNode, RaftError<u64>> {
    match e {
        WireCallError::TimedOut => RPCError::Timeout(Timeout {
            action: openraft::network::RPCTypes::Vote, // 字段仅诊断用途
            id: peer,
            target: peer,
            timeout: Duration::ZERO,
        }),
        WireCallError::Io(e) => RPCError::Unreachable(Unreachable::new(&e)),
        WireCallError::Mismatch => {
            RPCError::Unreachable(Unreachable::new(&io::Error::other("rpc response mismatch")))
        }
    }
}

/// 远端 Raft 致命错误 → RemoteError 包装（Append/Vote 线格式已带 RaftError）。
pub fn remote_error(peer: NodeId, e: RaftError<u64>) -> RPCError<u64, BasicNode, RaftError<u64>> {
    RPCError::RemoteError(RemoteError {
        target: peer,
        target_node: None,
        source: e,
    })
}

// ============================================================================
// 单元测试：帧编解码 + LagMonitor 时序
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// 极简内存 futures IO 对（帧编解码单测载体）。
    struct MemIo {
        inbox: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>,
        outbox: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>,
        woken: std::sync::Arc<futures::task::AtomicWaker>,
    }

    impl futures::AsyncWrite for MemIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.outbox
                .lock()
                .expect("mem io")
                .extend(buf.iter().copied());
            self.woken.wake();
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl futures::AsyncRead for MemIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut inbox = self.inbox.lock().expect("mem io");
            if inbox.is_empty() {
                self.woken.register(cx.waker());
                return Poll::Pending;
            }
            let n = inbox.len().min(buf.len());
            for (i, b) in inbox.drain(..n).enumerate() {
                buf[i] = b;
            }
            Poll::Ready(Ok(n))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn frame_roundtrip() {
        use std::collections::VecDeque;
        let q1 = std::sync::Arc::new(std::sync::Mutex::new(VecDeque::<u8>::new()));
        let q2 = std::sync::Arc::new(std::sync::Mutex::new(VecDeque::<u8>::new()));
        let w1 = std::sync::Arc::new(futures::task::AtomicWaker::default());
        let w2 = std::sync::Arc::new(futures::task::AtomicWaker::default());
        let a = MemIo {
            inbox: q1.clone(),
            outbox: q2.clone(),
            woken: w2,
        };
        let b = MemIo {
            inbox: q2,
            outbox: q1,
            woken: w1,
        };
        let (mut a, mut b) = (a, b);
        send_frame(&mut a, b"hello wire").await.expect("send");
        let got = recv_frame(&mut b).await.expect("recv");
        assert_eq!(got, b"hello wire");
    }

    #[tokio::test]
    async fn lag_monitor_opens_after_threshold_and_closes_on_catchup() {
        let applied = Arc::new(AtomicU64::new(10));
        let mon = LagMonitor::new(
            Duration::from_millis(100),
            Duration::from_secs(1),
            applied.clone(),
        );
        mon.observe_leader_commit(12);
        assert!(!mon.breaker_open(), "刚观察到落后不立即熔断");
        assert_eq!(mon.leader_commit(), 12);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(mon.breaker_open(), "持续落后超阈值 ⇒ 熔断打开");
        // 追平 ⇒ 恢复。
        applied.store(12, Ordering::SeqCst);
        mon.observe_leader_commit(12);
        assert!(!mon.breaker_open(), "追平后熔断关闭");
    }

    /// 心跳静默维度：长时间无任何 AppendEntries/心跳观察（完全分区）⇒ 熔断开启。
    ///
    /// 旧断言（lag_monitor_not_open_without_observation）把「分区不熔断」固化成了错误
    /// 特性：完全分区下 `leader_commit` 冻结且等于本地 applied，判「未落后」是盲区
    /// ——分区期间吊销挡不住缓存路径放行（§4/R24）。本断言修正为正确语义：观察流
    /// 消失本身即失联证据，静默超过 max(threshold, election_timeout) 即开熔断。
    #[tokio::test]
    async fn lag_monitor_opens_on_heartbeat_silence() {
        let applied = Arc::new(AtomicU64::new(5));
        // silence_limit = max(50ms, 100ms) = 100ms。
        let mon = LagMonitor::new(
            Duration::from_millis(50),
            Duration::from_millis(100),
            applied,
        );
        assert!(!mon.breaker_open(), "构造时刻起算，静默未超限不开");
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(mon.breaker_open(), "长时间无观察（完全分区）⇒ 熔断开启");
    }

    /// 分区恢复：静默开熔断后，首帧观察到 leader_commit >> applied 时立即保持开启
    /// （pending_since 回溯到静默起点，不重新计时），追平后才关闭。
    #[tokio::test]
    async fn lag_monitor_recovery_backdates_pending_window() {
        let applied = Arc::new(AtomicU64::new(10));
        let mon = LagMonitor::new(
            Duration::from_millis(100),
            Duration::from_millis(150),
            applied.clone(),
        );
        mon.observe_leader_commit(10);
        assert!(!mon.breaker_open(), "健康（无落后）");
        // 完全分区 200ms > silence_limit(150ms) ⇒ 熔断。
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(mon.breaker_open(), "静默开熔断");
        // 分区恢复首帧：leader 已远走（commit 30 >> applied 10）⇒ 立即仍开
        // （pending 窗回溯到静默起点，elapsed 200ms > threshold 100ms）。
        mon.observe_leader_commit(30);
        assert!(
            mon.breaker_open(),
            "恢复首帧观察到大幅落后 ⇒ 立即保持开启（不重新计时）"
        );
        // 追平 ⇒ 关闭。
        applied.store(30, Ordering::SeqCst);
        mon.observe_leader_commit(30);
        assert!(!mon.breaker_open(), "追平后熔断关闭");
    }
}
