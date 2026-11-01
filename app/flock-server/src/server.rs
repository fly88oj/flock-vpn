//! 服务端装配核心（docs/design.md §2.2/§3.11）。
//!
//! 职责链：接入（每入连一个 E2E 会话，`session::respond` + redb NetState 目录适配器）→
//! 认证（控制流 OPAQUE 登录 + anchor）→ 注册表（NetState）→ 会话（票据/杀会话）→
//! （M4：转发/同步）。
//!
//! 吊销传播界（§2.2，单机形态）：revoke 在**同一进程内**推进 revocation_epoch + 杀本地该
//! 设备会话（[`LiveSessions::kill`]）；「票据 epoch < 当前 epoch 即拒」兜住跨连接重放。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

use flock_protocol::ed25519_dalek::{Signer, SigningKey};
use flock_protocol::kem::HybridKeypair;
use flock_protocol::pake::{server_setup_load, server_setup_new, Suite};
use flock_protocol::rand;
use flock_protocol::session::{
    respond, sign_server_entry, ClusterId, ServerEntry, ServerId, ServerIdentity, TunnelConfig,
};
use flock_protocol::trust::ClusterDirectory;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::backend::NetBackend;
use crate::config::{ListenerMode, ServerConfig};
use crate::control::{serve_control, CtrlGuard};
use crate::dataplane::PeerRouter;
use crate::netstate::{DirAdapter, StateStore};
use crate::ticket::TicketIssuer;

/// META 键（集群身份材料 + 票据根种子；bootstrap 一次写入）。
mod keys {
    pub const ROOT_SEED: &str = "root_seed";
    pub const IDENTITY_SEED: &str = "identity_seed";
    pub const HYBRID_SK: &str = "hybrid_sk";
    pub const CLUSTER_ID: &str = "cluster_id";
    pub const SERVER_ID: &str = "server_id";
    pub const OPRF_B64: &str = "oprf_b64";
    pub const TICKET_SEED: &str = "ticket_seed";
}

/// 每设备本地会话表（吊销即杀，§2.2 apply 回调语义的单机对应物）。
///
/// kill 经 `watch` 广播（保留状态，注册/通知竞态下不丢事件）；会话任务在
/// `serve_conn` 的 select 臂消费它并拆隧道。
#[derive(Default)]
pub struct LiveSessions {
    inner: Mutex<std::collections::HashMap<[u8; 32], Vec<tokio::sync::watch::Sender<bool>>>>,
}

impl LiveSessions {
    fn register(&self, device: [u8; 32]) -> tokio::sync::watch::Receiver<bool> {
        let (tx, rx) = tokio::sync::watch::channel(false);
        self.inner
            .lock()
            .expect("live sessions poisoned")
            .entry(device)
            .or_default()
            .push(tx);
        rx
    }

    fn deregister(&self, device: [u8; 32]) {
        let mut g = self.inner.lock().expect("live sessions poisoned");
        if let Some(v) = g.get_mut(&device) {
            v.retain(|tx| !tx.is_closed());
            if v.is_empty() {
                g.remove(&device);
            }
        }
    }

    /// 杀死该设备全部本地会话（revoke/disable 后由控制流/admin 调用）。
    pub fn kill(&self, device: &[u8; 32]) {
        if let Some(senders) = self
            .inner
            .lock()
            .expect("live sessions poisoned")
            .remove(device)
        {
            for tx in senders {
                let _ = tx.send(true);
            }
        }
    }

    /// 在线设备会话数（诊断/测试）。
    pub fn online(&self, device: &[u8; 32]) -> usize {
        self.inner
            .lock()
            .expect("live sessions poisoned")
            .get(device)
            .map(|v| v.iter().filter(|tx| !tx.is_closed()).count())
            .unwrap_or(0)
    }

    /// 在线设备数（M5 断言面：admin stats 的 sessions_online）。
    pub fn device_count(&self) -> usize {
        self.inner
            .lock()
            .expect("live sessions poisoned")
            .len()
    }
}

/// 多主 apply/租约钩子（§2.2 吊销传播界 + vpn-mesh §5.2 租约冲突）。
///
/// 每台服务器在**自己的日志 apply 现场**触发：(a) 杀死本地该设备会话（watch 广播 →
/// serve_conn 拆隧道）；(b) 票据清拒由「票据 epoch < 当前 epoch 即拒」承担（TicketAuthority
/// 以本机 apply 后的 epoch 校验）。
#[cfg(feature = "multi-primary")]
struct ServerSyncHooks {
    sessions: Arc<LiveSessions>,
    node: Arc<flock_sync::SyncNode>,
}

#[cfg(feature = "multi-primary")]
impl flock_sync::hooks::SyncHooks for ServerSyncHooks {
    fn on_revocation_applied(&self, ev: flock_sync::hooks::RevocationEvent) {
        eprintln!(
            "flock-server: revocation applied (epoch={}, log={}) killing local sessions",
            ev.new_epoch, ev.log_index
        );
        self.sessions.kill(&ev.device);
        self.node.detach_session(&ev.device);
    }
    fn on_lease_evicted(&self, device: &[u8; 32]) {
        // 租约冲突新者胜（设备已迁往他机）：旧端踢出（§3.10 LeaseTable）。
        eprintln!("flock-server: lease evicted (device moved) killing local session");
        self.sessions.kill(device);
    }
}

/// 服务端核心（装配期构建；Arc 共享给 accept/admin 任务）。
pub struct ServerCore {
    pub cfg: ServerConfig,
    /// 写读后端（§2.2/§3.11）：Single = 本地 redb（M2 形态）；Sync = flock-sync Raft
    /// （feature `multi-primary`——写转发 leader / 线性一致读 / 两级读目录）。
    pub net: NetBackend,
    /// 集群根密钥签名钥（单服 = 库内根；多主 = **None**——根密钥离线保管，目录/邀请
    /// 签发走运维侧 init-cluster 流程，服务器只持 root_pub）。
    pub root: Option<SigningKey>,
    pub identity: ServerIdentity,
    /// OPAQUE 服务端 OPRF key（§2.4：常驻；轮换使全部 pass.opaque 失效。
    /// 多主形态 = Raft 内共享（SetOprf 根签登记）——OPAQUE 记录全网可验）。
    pub oprf: flock_protocol::opaque_ke::ServerSetup<Suite>,
    /// 票据权威（Local = 状态库种子；Sync = Raft 内票据根，任何服务器都验得了）。
    pub guard: CtrlGuard,
    /// 本地会话表（Arc：SyncHooks 装配侧共享——apply 回调杀会话/租约冲突踢出）。
    pub sessions: Arc<LiveSessions>,
    /// 多主同步节点（feature `multi-primary`；单服 = None）。
    #[cfg(feature = "multi-primary")]
    pub sync: Option<Arc<flock_sync::SyncNode>>,
    /// M3 数据面路由器（run() 装配 tun 后注入；None = 控制流-only——宿主测试路径）。
    router: RwLock<Option<Arc<PeerRouter>>>,
}

impl ServerCore {
    /// 当前数据面路由器（未装配 ⇒ None）。
    pub fn router(&self) -> Option<Arc<PeerRouter>> {
        self.router.read().expect("router lock poisoned").clone()
    }

    /// 装配数据面（tun + 路由；失败在 [`PeerRouter::open`] 内降级并记日志）。
    pub fn set_router(&self, router: Arc<PeerRouter>) {
        *self.router.write().expect("router lock poisoned") = Some(router);
    }
}

impl ServerCore {
    /// 打开既有状态或引导新集群（`init-cluster` 语义；已初始化则原样加载）。
    /// 返回 `(core, created)`。
    pub fn open_or_init(cfg: ServerConfig) -> Result<(Arc<Self>, bool), String> {
        let db_path = cfg.state_dir.join("netstate.redb");
        let store = StateStore::open(&db_path).map_err(|e| e.to_string())?;
        let created = store.meta_get(keys::CLUSTER_ID).is_none();

        let cluster_id: ClusterId = match store.meta_get(keys::CLUSTER_ID) {
            Some(b) => ClusterId(b.try_into().map_err(|_| "cluster_id 长度")?),
            None => {
                let v: [u8; 16] = rand::random();
                store
                    .meta_put(keys::CLUSTER_ID, &v)
                    .map_err(|e| e.to_string())?;
                ClusterId(v)
            }
        };
        let server_id: ServerId = match store.meta_get(keys::SERVER_ID) {
            Some(b) => ServerId(b.try_into().map_err(|_| "server_id 长度")?),
            None => {
                let v: [u8; 16] = rand::random();
                store
                    .meta_put(keys::SERVER_ID, &v)
                    .map_err(|e| e.to_string())?;
                ServerId(v)
            }
        };
        let root = match store.meta_get(keys::ROOT_SEED) {
            Some(b) => SigningKey::from_bytes(&b.try_into().map_err(|_| "root_seed 长度")?),
            None => {
                let seed: [u8; 32] = rand::random();
                store
                    .meta_put(keys::ROOT_SEED, &seed)
                    .map_err(|e| e.to_string())?;
                SigningKey::from_bytes(&seed)
            }
        };
        let identity = match store.meta_get(keys::IDENTITY_SEED) {
            Some(b) => SigningKey::from_bytes(&b.try_into().map_err(|_| "identity_seed 长度")?),
            None => {
                let seed: [u8; 32] = rand::random();
                store
                    .meta_put(keys::IDENTITY_SEED, &seed)
                    .map_err(|e| e.to_string())?;
                SigningKey::from_bytes(&seed)
            }
        };
        let static_hybrid = match store.meta_get(keys::HYBRID_SK) {
            Some(b) => {
                let sk: [u8; 96] = b.try_into().map_err(|_| "hybrid_sk 长度")?;
                HybridKeypair::from_bytes(&sk).map_err(|e| e.to_string())?
            }
            None => {
                let kp = HybridKeypair::generate(&mut rand::rngs::OsRng);
                store
                    .meta_put(keys::HYBRID_SK, &kp.to_bytes())
                    .map_err(|e| e.to_string())?;
                kp
            }
        };
        let oprf = match store.meta_get(keys::OPRF_B64) {
            Some(b) => {
                let s = String::from_utf8(b).map_err(|_| "oprf_b64 编码")?;
                server_setup_load(&s).map_err(|e| format!("oprf key: {e}"))?
            }
            None => {
                let b64 = server_setup_new(&mut rand::rngs::OsRng);
                store
                    .meta_put(keys::OPRF_B64, b64.as_bytes())
                    .map_err(|e| e.to_string())?;
                server_setup_load(&b64).map_err(|e| format!("oprf key: {e}"))?
            }
        };
        let ticket_seed: [u8; 32] = match store.meta_get(keys::TICKET_SEED) {
            Some(b) => b.try_into().map_err(|_| "ticket_seed 长度")?,
            None => {
                let s = TicketIssuer::generate_seed();
                store
                    .meta_put(keys::TICKET_SEED, &s)
                    .map_err(|e| e.to_string())?;
                s
            }
        };

        // ServerEntry（advertise 端点；root 重签 entry_sig——根密钥在库，确定性重建）。
        let entry = ServerEntry {
            server_id,
            relay_endpoint: cfg.advertise_endpoint.clone(),
            identity_pub: identity.verifying_key(),
            static_hybrid_pub: static_hybrid.public(),
        };
        let sid = ServerIdentity {
            cluster_id,
            server_id,
            identity,
            static_hybrid,
            entry: entry.clone(),
            root_pub: root.verifying_key(),
            entry_sig: sign_server_entry(&root, &cluster_id, &entry),
        };

        let core = ServerCore {
            cfg,
            net: NetBackend::Single(Arc::new(store)),
            root: Some(root),
            identity: sid,
            oprf,
            guard: CtrlGuard::new(crate::ticket::TicketAuthority::Local(Box::new(
                TicketIssuer::from_seed(ticket_seed),
            ))),
            sessions: Arc::new(LiveSessions::default()),
            #[cfg(feature = "multi-primary")]
            sync: None,
            router: RwLock::new(None),
        };
        Ok((Arc::new(core), created))
    }

    /// 多主装配（feature `multi-primary`；§2.2/§3.11 M4 批次）。
    ///
    /// - 目录 = `session::respond` 注入 [`flock_sync::SyncNode::device_directory`]
    ///   （两级读：记录缓存 + epoch + apply-lag 熔断降级线性一致读，§4）；
    /// - 票据根 = Raft 状态内（Bootstrap 落库）；
    /// - OPRF key = Raft 内共享（SetOprf 根签登记——跨节点登录，§2.4）；
    /// - 吊销/租约冲突经 [`flock_sync::hooks::SyncHooks`] 在 apply 现场杀本地会话（§2.2）。
    ///
    /// 前置：集群已 Bootstrap（ticket_root + SetOprf 就位）——init-cluster/enroll 流程或
    /// 装配方（tests/multi_primary.rs）完成；等待窗口 15s。
    #[cfg(feature = "multi-primary")]
    pub async fn open_sync(
        cfg: ServerConfig,
        ident: Arc<ServerIdentity>,
        node: Arc<flock_sync::SyncNode>,
    ) -> Result<Arc<Self>, String> {
        // 等 Bootstrap + SetOprf 复制到位（本节点 apply 即可见——本地读）。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let oprf_b64 = loop {
            if let Some(o) = node.sm().oprf_b64() {
                break o;
            }
            if std::time::Instant::now() >= deadline {
                return Err("集群未就绪：15s 内未见 Bootstrap/SetOprf 在本节点 apply".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        };
        let oprf = flock_protocol::pake::server_setup_load(&oprf_b64)
            .map_err(|e| format!("集群 OPRF key: {e}"))?;
        let sessions = Arc::new(LiveSessions::default());
        node.sm().register_hook(Arc::new(ServerSyncHooks {
            sessions: sessions.clone(),
            node: node.clone(),
        }));
        let src = &*ident;
        let identity = ServerIdentity {
            cluster_id: src.cluster_id,
            server_id: src.server_id,
            identity: flock_protocol::ed25519_dalek::SigningKey::from_bytes(
                &src.identity.to_bytes(),
            ),
            static_hybrid: flock_protocol::kem::HybridKeypair::from_bytes(
                &src.static_hybrid.to_bytes(),
            )
            .map_err(|e| e.to_string())?,
            entry: src.entry.clone(),
            root_pub: src.root_pub,
            entry_sig: src.entry_sig,
        };
        let core = ServerCore {
            cfg,
            net: NetBackend::Sync(crate::backend::SyncNetState::new(node.clone())),
            root: None,
            identity,
            oprf,
            guard: CtrlGuard::new(crate::ticket::TicketAuthority::Sync(node.clone())),
            sessions,
            sync: Some(node),
            router: RwLock::new(None),
        };
        Ok(Arc::new(core))
    }

    /// 根签集群目录。
    ///
    /// - 单服：现签（advertise + extras——同一服务器的其他暴露口；根密钥在库）；
    /// - 多主：**已安装的根签目录**（init-cluster 全网分发；服务器不持根密钥，不可自签）。
    pub fn build_directory(&self) -> ClusterDirectory {
        #[cfg(feature = "multi-primary")]
        if let Some(node) = &self.sync {
            if let Some(dir) = node.directory().current() {
                return dir;
            }
        }
        self.local_directory()
    }

    /// 单服形态的现签目录。
    fn local_directory(&self) -> ClusterDirectory {
        let mut servers = vec![self.identity.entry.clone()];
        for ep in &self.cfg.extra_endpoints {
            servers.push(ServerEntry {
                server_id: self.identity.server_id,
                relay_endpoint: ep.clone(),
                identity_pub: self.identity.identity.verifying_key(),
                static_hybrid_pub: self.identity.static_hybrid.public(),
            });
        }
        let root = self
            .root
            .as_ref()
            .expect("单服形态根密钥在库（多主形态经已安装目录返回）");
        ClusterDirectory::issue(
            root,
            self.identity.cluster_id,
            self.cfg.dir_version,
            servers,
        )
    }

    /// 签发邀请（admin 路径；§1.3.3f 邀请生成 = 根密钥语境的管理操作）。
    ///
    /// 多主形态服务器**不持根密钥** ⇒ 拒绝（签发走运维侧 init-cluster 流程）；
    /// 邀请登记（Raft RecordInvite）仍可经 NetBackend 完成。
    pub async fn mint_invite(&self, ttl_secs: u64) -> Result<Vec<u8>, String> {
        let Some(root) = &self.root else {
            return Err("多主形态邀请签发需集群根密钥（运维侧 init-cluster 产物）".into());
        };
        let invite_id: [u8; 16] = rand::random();
        let expiry = flock_protocol::trust::now_unix() + ttl_secs;
        self.net
            .record_invite(&invite_id, expiry)
            .await
            .map_err(|e| e.to_string())?;
        let dir = self.build_directory();
        let inv = flock_protocol::trust::InviteFile::issue(
            root,
            self.identity.cluster_id,
            dir.dir_version,
            dir.servers.clone(),
            expiry,
            invite_id,
        );
        Ok(inv.to_bytes())
    }

    /// 单条入连：E2E 握手（respond）→ 会话登记（可被吊销信号杀）→ 流分派。
    ///
    /// 流分派（M3）：**首条**被接受的 yamux 流 = 控制流（M2 语义不变，客户端
    /// initiate 后先 `open_stream(Prio::Control)`——排序契约见 flock-client
    /// connector）；余流 = 数据面包通道（[`PeerRouter::serve_stream`]）。
    pub async fn serve_conn(self: Arc<Self>, io: TcpStream) {
        // respond 的目录注入分派：Single = redb 适配器；Sync = flock-sync 两级读
        // （缓存 + epoch + apply-lag 熔断降级线性一致读，§4——本批次的接入点）。
        let handshake = match &self.net {
            NetBackend::Single(store) => {
                respond(
                    io,
                    &self.identity,
                    DirAdapter(store.clone()),
                    TunnelConfig::default(),
                )
                .await
            }
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                respond(
                    io,
                    &self.identity,
                    s.node.device_directory(),
                    TunnelConfig::default(),
                )
                .await
            }
        };
        let tunnel = match handshake {
            Ok(t) => t,
            Err(e) => {
                eprintln!("flock-server: handshake rejected: {e}");
                return;
            }
        };
        let Some(device) = tunnel.peer_device_id() else {
            return;
        };
        let mut kill = self.sessions.register(device.0);
        // 该会话设备的注册行（VIP = 数据面源校验/路由键；查不到 ⇒ 仅控制流）。
        let device_row = self.net.device_row(&device).await;
        let device_vip = device_row.as_ref().map(|r| r.vip);
        // 多主：发布本机租约（gossip 事件 ≤1s + 反熵兜底；设备当前位置唯一真相源，§2.2-1）。
        #[cfg(feature = "multi-primary")]
        if let Some(node) = &self.sync {
            let _ = node.publish_lease(&device.0).await;
        }
        let mut handlers = Vec::new();
        loop {
            tokio::select! {
                // 吊销/禁用 ⇒ 杀本地会话（§2.2）：拆隧道即断记录层/复用器。
                _ = kill.changed() => break,
                stream = tunnel.accept_stream() => match stream {
                    Some(s) => {
                        // 流分派（M3）：按 yamux 流 ID 而非到达序——客户端首条流（id=1）
                        // = 控制流（M2 语义）；id≥3 = 数据面包通道。按 ID 分派对 yamux
                        // 惰性 SYN 免疫：被静默持有的控制流（M3 客户端不发控制业务）
                        // 不物化时，首个物化的数据流不会被误派给控制流处理器。
                        if s.id() == 1 {
                            let core = self.clone();
                            handlers.push(tokio::spawn(async move {
                                let mut s = s;
                                let _ = serve_control(&core, device, &mut s).await;
                            }));
                        } else {
                            // 多主：包通道走 flock-sync 转发面（attach_session sink +
                            // ingest：第 0 步源 VIP 校验 → 租约定位 → 本机投递或
                            // ForwardEnvelope 跨服，§2.2 判定序）。
                            #[cfg(feature = "multi-primary")]
                            if let Some(node) = self.sync.clone() {
                                let dev = device.0;
                                handlers.push(tokio::spawn(async move {
                                    crate::dataplane::serve_stream_sync(node, dev, s).await;
                                }));
                                continue;
                            }
                            // 单服：本机路由器（tun 注入/回程）。
                            let router = self.router();
                            let has_router = router.is_some();
                            match (router, device_vip) {
                                (Some(router), Some(vip)) => {
                                    handlers.push(tokio::spawn(async move {
                                        router.serve_stream(vip, s).await;
                                    }));
                                }
                                // 无数据面（宿主/无 NET_ADMIN）或注册表缺行：拆流
                                //（客户端数据面观察通道 EOF → 退避重连，控制流不受影响）。
                                _ => {
                                    eprintln!(
                                        "flock-server: 数据面流被拆（router={has_router} vip={}）",
                                        device_vip.is_some()
                                    );
                                    drop(s)
                                }
                            }
                        }
                    }
                    None => break,
                },
            }
        }
        // 优雅收尾（顺序关键——**不得 abort 数据面任务**）：先拆隧道（流全关 ⇒
        // serve_stream/serve_stream_sync 自然退出并 detach——abort 会跳过 detach，
        // forward.sessions 残留死会话；租约续期循环会把残留项当在线设备反复重发布，
        // 与新持有者打「租约战」互踢活会话——M5 e2e 实测风暴根因）。
        let close_reason = tunnel.stats().closed;
        tunnel.shutdown().await;
        for h in handlers {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h).await;
        }
        // 会话终止原因（A9 服务端侧：静默死链 ⇒ "dead-link" 可 grep）。
        let reason = close_reason;
        eprintln!(
            "flock-server: session ended device={device} reason={}",
            reason
                .map(|r| r.to_string())
                .unwrap_or_else(|| "none(io/fin)".into())
        );
        self.sessions.deregister(device.0);
    }

    /// accept 循环（每入连一个会话任务）。
    pub async fn serve_listener(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (io, _peer) = listener.accept().await?;
            let core = self.clone();
            tokio::spawn(async move {
                core.serve_conn(io).await;
            });
        }
    }
}

/// 运行中的监听端点（Direct 分支零 flock-frpc 类型；Frp 分支持托管句柄）。
pub enum RunningListener {
    Direct {
        local: SocketAddr,
    },
    Frp {
        local: SocketAddr,
        managed: crate::frp::Managed,
    },
}

impl RunningListener {
    /// 本地监听地址。
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            RunningListener::Direct { local } | RunningListener::Frp { local, .. } => *local,
        }
    }
}

/// 按模式起服（装配期分派；admin 端点随之启动；M3 起附带数据面装配）。
///
/// `serve_listener` 为无限循环——`run` 返回的 JoinHandle 正常不结束；abort 即停 accept。
pub async fn run(
    core: Arc<ServerCore>,
    mode: ListenerMode,
) -> Result<
    (
        RunningListener,
        JoinHandle<std::io::Result<()>>,
        JoinHandle<()>,
    ),
    String,
> {
    // M3 数据面（§2.2 服务端自身也是 peer）：tun + 路由；失败在 PeerRouter::open
    // 内降级控制流-only 并记日志（宿主测试路径即此形态）。
    // 多主形态（sync::run_raft）已按自身 peer 面装配 tun（router 预置）⇒ 此处跳过，
    // 避免二次开同名设备。
    if core.router().is_none() {
        core.set_router(PeerRouter::open(&core.cfg.tun_name, core.cfg.vip).await);
    }
    // admin loopback 端点（CLI 子命令的进程内单写者入口）。
    let admin = crate::admin::serve(core.clone(), core.cfg.admin_bind)
        .await
        .map_err(|e| format!("admin bind {}: {e}", core.cfg.admin_bind))?;
    match mode {
        ListenerMode::Direct { bind } => {
            // Direct 装配路径：bind 即监听——零 frp 逻辑（§2.1/§3.11 硬约束）。
            let listener = TcpListener::bind(bind)
                .await
                .map_err(|e| format!("bind {bind}: {e}"))?;
            let local = listener
                .local_addr()
                .map_err(|e| format!("local_addr: {e}"))?;
            let task = tokio::spawn(core.clone().serve_listener(listener));
            Ok((RunningListener::Direct { local }, task, admin))
        }
        ListenerMode::Frp { bind, plan } => {
            let (listener, managed) = crate::frp::start(plan, bind)
                .await
                .map_err(|e| format!("frp: {e}"))?;
            let local = listener
                .local_addr()
                .map_err(|e| format!("local_addr: {e}"))?;
            let task = tokio::spawn(core.clone().serve_listener(listener));
            Ok((RunningListener::Frp { local, managed }, task, admin))
        }
    }
}

/// 签名便利：根密钥对任意字节签名（邀请/目录扩展用；测试亦可断言）。
pub fn root_sign(root: &SigningKey, bytes: &[u8]) -> [u8; 64] {
    root.sign(bytes).to_bytes()
}
