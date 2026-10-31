//! 接入器（docs/design.md §2.3 / §3.12）：端点列表 → TCP 拨号 → `session::initiate`
//! （带 [`ServerPin`]）；断线指数退避（5s 起 + 抖动，wireguard-go RekeyTimeout 节奏，
//! crypto-2026 §6）+ 端点轮询切换。
//!
//! - 身份三件套（state 目录常驻）：设备静态密钥 `device.keys`（0600）、钉扎
//!   `pins.bin`（[`PinStore`]，cluster_id → 集群根公钥）、根签目录 `directory.bin`
//!   （[`ClusterDirectory`]——端点列表与凭证同签一份，§1.3.3f 方案②）。
//! - 邀请文件（`invite` 子命令）：v3 结构校验（根签）→ 过期检查 → 钉扎比对
//!   （变更 ⇒ 显式告警错误，**不静默**）→ `record_directory`（版本回退拒收）。
//! - 端点轮询：每次连接尝试取目录下一端点（Direct 直连地址或 Frp 中转用户口，
//!   对客户端无感知差异，§2.1）；任意端点均 1-RTT（钉扎材料齐全，§1.3.3c）。
//!
//! 控制流业务（OPAQUE 登录/票据/dir_pull 定期刷新）沿 M2 控制协议（§2.2），属
//! 后续里程碑装配；M3 数据面会话保持「首流 = 控制流」的排序契约（见
//! [`lib`]/server 分派），为该业务留位。

use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use chml_protocol::rand;
use chml_protocol::session::{
    initiate, CloseReason, DeviceStaticKeys, ServerPin, Tunnel, TunnelConfig,
};
use chml_protocol::trust::{ClusterDirectory, InviteFile, PinStore, PinVerdict, TrustError};
use tokio::net::TcpStream;

use crate::dataplane;
use crate::tun::TunIo;

/// 断线重连退避：5s 起步（§2.3），倍增，封顶 60s。
pub const BACKOFF_BASE: Duration = Duration::from_secs(5);
/// 退避封顶。
pub const BACKOFF_CAP: Duration = Duration::from_secs(60);
/// 抖动上限比例（+0..25%：避开多客户端同频重连风暴）。
pub const BACKOFF_JITTER: f64 = 0.25;
/// 单端点拨号超时（TCP connect + 握手整体；超时即换下一端点轮询）。
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(8);

// ============================================================================
// 错误
// ============================================================================

/// 客户端装配/接入错误。
#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    Session(chml_protocol::session::SessionError),
    Trust(TrustError),
    /// 状态目录/配置问题（消息自带上下文）。
    State(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "client: io: {e}"),
            ClientError::Session(e) => write!(f, "client: session: {e}"),
            ClientError::Trust(e) => write!(f, "client: trust: {e}"),
            ClientError::State(m) => write!(f, "client: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

impl From<TrustError> for ClientError {
    fn from(e: TrustError) -> Self {
        ClientError::Trust(e)
    }
}

impl From<chml_protocol::session::SessionError> for ClientError {
    fn from(e: chml_protocol::session::SessionError) -> Self {
        ClientError::Session(e)
    }
}

// ============================================================================
// 状态目录（身份三件套）
// ============================================================================

/// 客户端本地状态（state 目录三件套）。
#[derive(Debug)]
pub struct ClientState {
    /// 设备静态密钥（生成后永不出机，§2.4）。
    pub device: DeviceStaticKeys,
    /// 钉扎存储（cluster_id → 集群根公钥）。
    pub pins: PinStore,
    /// 根签集群目录（端点列表 + 全套接入材料）。
    pub directory: ClusterDirectory,
}

const DEVICE_KEYS: &str = "device.keys";
const PINS: &str = "pins.bin";
const DIRECTORY: &str = "directory.bin";
/// VIP 文件（部署编排写入；config.vip 为空时读它）。
pub const VIP_FILE: &str = "vip";

impl ClientState {
    /// 载入设备密钥；`create = true` 时缺失即生成并落盘（0600，unix）。
    /// （`gen-keys` 先于 `invite` 运行的部署序：密钥不依赖目录存在。）
    pub fn load_keys(state_dir: &Path, create: bool) -> Result<DeviceStaticKeys, ClientError> {
        let keys_path = state_dir.join(DEVICE_KEYS);
        match std::fs::read(&keys_path) {
            Ok(b) => {
                let arr: [u8; 64] =
                    b.try_into().map_err(|_| ClientError::State("device.keys 期望 64B".into()))?;
                Ok(DeviceStaticKeys::from_bytes(&arr))
            }
            Err(_) if create => {
                let d = DeviceStaticKeys::generate();
                std::fs::create_dir_all(state_dir)
                    .map_err(|e| ClientError::State(format!("mkdir {}: {e}", state_dir.display())))?;
                write_keys(state_dir, &d)?;
                Ok(d)
            }
            Err(e) => Err(ClientError::State(format!(
                "读 {}: {e}（先运行 gen-keys/invite 引导）",
                keys_path.display()
            ))),
        }
    }

    /// 载入完整状态（设备密钥 + 钉扎 + 目录；`create` 同 [`Self::load_keys`]）。
    pub fn load(state_dir: &Path, create: bool) -> Result<Self, ClientError> {
        let device = Self::load_keys(state_dir, create)?;
        let pins = match std::fs::read(state_dir.join(PINS)) {
            Ok(b) => PinStore::from_bytes(&b)
                .map_err(|e| ClientError::State(format!("pins.bin 解析: {e}")))?,
            Err(_) => PinStore::new(),
        };
        let directory = match std::fs::read(state_dir.join(DIRECTORY)) {
            Ok(b) => ClusterDirectory::from_bytes(&b)
                .map_err(|e| ClientError::State(format!("directory.bin 解析: {e}")))?,
            Err(_) => {
                return Err(ClientError::State(
                    "无根签目录（先运行 `chmlvpn-client invite <file>` 引导，§1.3.3f）".into(),
                ))
            }
        };
        Ok(ClientState { device, pins, directory })
    }

    /// 落盘三件套。
    pub fn save(&self, state_dir: &Path) -> Result<(), ClientError> {
        std::fs::create_dir_all(state_dir)
            .map_err(|e| ClientError::State(format!("mkdir {}: {e}", state_dir.display())))?;
        write_keys(state_dir, &self.device)?;
        self.pins
            .save(&state_dir.join(PINS))
            .map_err(|e| ClientError::State(format!("写 pins.bin: {e}")))?;
        std::fs::write(state_dir.join(DIRECTORY), self.directory.to_bytes())
            .map_err(|e| ClientError::State(format!("写 directory.bin: {e}")))?;
        Ok(())
    }

    /// 端点列表（目录序，去重）。
    pub fn endpoints(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for e in &self.directory.servers {
            if !out.contains(&e.relay_endpoint) {
                out.push(e.relay_endpoint.clone());
            }
        }
        out
    }

    /// 目标端点的接入 pin（集群根 = 钉扎；未钉扎 ⇒ None，调用方先引导）。
    pub fn pin_for(&self, endpoint: &str) -> Option<ServerPin> {
        let root = self.pins.pinned_root(&self.directory.cluster_id)?;
        let entry = self.directory.servers.iter().find(|e| e.relay_endpoint == endpoint)?;
        Some(ServerPin {
            cluster_id: self.directory.cluster_id,
            cluster_root_pub: *root,
            entry: entry.clone(),
        })
    }

    /// 本端 VIP（config 覆盖或 state 目录 `vip` 文件）。
    pub fn resolve_vip(&self, state_dir: &Path, cfg_vip: Option<Ipv4Addr>) -> Result<Ipv4Addr, ClientError> {
        if let Some(v) = cfg_vip {
            return Ok(v);
        }
        let text = std::fs::read_to_string(state_dir.join(VIP_FILE))
            .map_err(|e| ClientError::State(format!("读 {} : {e}（部署须写入 VIP）", VIP_FILE)))?;
        text.trim()
            .parse()
            .map_err(|e| ClientError::State(format!("{VIP_FILE} 内容非 IPv4：{e}")))
    }
}

/// 设备密钥落盘（0600，unix）。
fn write_keys(state_dir: &Path, device: &DeviceStaticKeys) -> Result<(), ClientError> {
    std::fs::write(state_dir.join(DEVICE_KEYS), device.to_bytes())
        .map_err(|e| ClientError::State(format!("写 device.keys: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(
            state_dir.join(DEVICE_KEYS),
            std::fs::Permissions::from_mode(0o600),
        );
    }
    Ok(())
}

/// 邀请文件落地（§1.3.3f）：结构验签 → 过期检查 → 钉扎（NotPinned 首钉 / Match 放行 /
/// Mismatch **显式告警拒绝**）→ `record_directory`（版本回退拒收）→ 落盘三件套。
pub fn ingest_invite(state_dir: &Path, invite: &InviteFile) -> Result<ClientState, ClientError> {
    invite
        .check(chml_protocol::trust::now_unix())
        .map_err(ClientError::Trust)?;
    let device = ClientState::load_keys(state_dir, true)?;
    let mut pins = match std::fs::read(state_dir.join(PINS)) {
        Ok(b) => PinStore::from_bytes(&b)
            .map_err(|e| ClientError::State(format!("pins.bin 解析: {e}")))?,
        Err(_) => PinStore::new(),
    };
    match pins.verify_pinned(&invite.directory.cluster_id, &invite.cluster_root_pub) {
        PinVerdict::NotPinned => {
            pins.pin(&invite.directory.cluster_id, &invite.cluster_root_pub);
        }
        PinVerdict::Match => {}
        PinVerdict::Mismatch { .. } => {
            return Err(ClientError::Trust(TrustError::RootChanged {
                cluster_id: invite.directory.cluster_id,
                pinned: Box::new(
                    pins.pinned_root(&invite.directory.cluster_id)
                        .copied()
                        .expect("Mismatch ⇒ 必有旧值"),
                ),
                presented: Box::new(invite.cluster_root_pub),
            }))
        }
    }
    pins.record_directory(&invite.cluster_root_pub, &invite.directory)
        .map_err(ClientError::Trust)?;
    let state = ClientState { device, pins, directory: invite.directory.clone() };
    state.save(state_dir)?;
    Ok(state)
}

// ============================================================================
// 退避与端点轮询
// ============================================================================

/// 指数退避（纯函数可测）：`min(cap, base · 2^attempt)`，叠加 `[0, 25%)` 抖动。
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff { base: BACKOFF_BASE, cap: BACKOFF_CAP, attempt: 0 }
    }
}

impl Backoff {
    pub fn new(base: Duration, cap: Duration) -> Self {
        Backoff { base, cap, attempt: 0 }
    }

    /// 成功后归零。
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// 下一次等待（`rnd ∈ [0,1)`；抖动比例 [`BACKOFF_JITTER`]）。返回未抖动的基数步长。
    pub fn next_jitter(&mut self, rnd: f64) -> Duration {
        let n = self.attempt.min(16);
        self.attempt += 1;
        let exp = self.base.saturating_mul(1u32 << n.min(16));
        let base = exp.min(self.cap);
        let jitter = 1.0 + BACKOFF_JITTER * rnd.clamp(0.0, 0.9999);
        base.mul_f64(jitter)
    }
}

/// 端点轮询（round-robin）：每次连接尝试取下一个端点（§2.3 端点轮询切换）。
#[derive(Debug, Clone)]
pub struct EndpointRing {
    endpoints: Vec<String>,
    next: usize,
}

impl EndpointRing {
    pub fn new(endpoints: Vec<String>) -> Self {
        EndpointRing { endpoints, next: 0 }
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// 取下一端点并前进（空 ⇒ None）。
    pub fn next_endpoint(&mut self) -> Option<String> {
        if self.endpoints.is_empty() {
            return None;
        }
        let ep = self.endpoints[self.next % self.endpoints.len()].clone();
        self.next = self.next.wrapping_add(1);
        Some(ep)
    }
}

// ============================================================================
// 拨号与守护循环
// ============================================================================

/// 单次拨号：TCP（带超时）→ `session::initiate`（1-RTT，已钉扎形态）。
pub async fn dial(pin: &ServerPin, device: &DeviceStaticKeys, cfg: TunnelConfig) -> Result<Tunnel, ClientError> {
    let io = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(&pin.entry.relay_endpoint))
        .await
        .map_err(|_| ClientError::State(format!("拨号超时 {}", pin.entry.relay_endpoint)))??;
    initiate(io, device, pin, cfg).await.map_err(ClientError::Session)
}

/// 守护循环事件（日志/断言面：A9 的「检测进入重连」由 [`ConnEvent::SessionEnded`] 携
/// `dead-link` 原因 + 下一跳时间构成可 grep 的记录）。
#[derive(Debug)]
pub enum ConnEvent {
    /// 正在尝试某端点（attempt 从 1 起）。
    Dialing { endpoint: String, attempt: u32 },
    /// 隧道建立（server = 对端服务器标识）。
    Connected { endpoint: String, server: chml_protocol::session::ServerId },
    /// 数据面结束（reason = 会话层终止原因；None = 通道 IO 错误先于会话判定）。
    SessionEnded { endpoint: String, reason: Option<CloseReason> },
}

/// 守护循环：拨号 → 隧道 → tun ↔ PacketChannel 数据面 → 结束即退避重连。
///
/// 永不正常返回（进程生命周期循环）；测试以 `tokio::select!`/abort 终止。
/// `backoff` 供测试注入小步长；`events` 回调承接 [`ConnEvent`]（进程入口转 eprintln）。
pub async fn supervise(
    state: &ClientState,
    tun: &TunIo,
    tunnel_cfg: TunnelConfig,
    mut backoff: Backoff,
    mut events: impl FnMut(ConnEvent),
) {
    let mut ring = EndpointRing::new(state.endpoints());
    loop {
        let Some(endpoint) = ring.next_endpoint() else {
            eprintln!("chmlvpn-client: 目录无端点，5s 后重查");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        let Some(pin) = state.pin_for(&endpoint) else {
            eprintln!("chmlvpn-client: 端点 {endpoint} 无接入材料/未钉扎，跳过");
            continue;
        };
        let attempt = backoff.attempt + 1;
        events(ConnEvent::Dialing { endpoint: endpoint.clone(), attempt });
        match dial(&pin, &state.device, tunnel_cfg.clone()).await {
            Ok(tunnel) => {
                // 首流 = 控制流（排序契约，见模块文档）：M3 不发控制业务，占位并**持有到
                // 会话结束**（保序 + 防止过早 Drop 引入的流生命周期变量）。
                // 控制流打不开 ⇒ 会话已坏，直接走退避（不得让包通道变成首流破坏分派）。
                let control = match tunnel.open_stream(chml_protocol::mux::Prio::Control).await {
                    Ok(s) => s,
                    Err(_) => {
                        events(ConnEvent::SessionEnded { endpoint: endpoint.clone(), reason: tunnel.stats().closed });
                        tunnel.shutdown().await;
                        let d = backoff.next_jitter(rand::random::<f64>());
                        eprintln!("chmlvpn-client: {d:?} 后重连（控制流开失败）");
                        tokio::time::sleep(d).await;
                        continue;
                    }
                };
                match tunnel.open_packet_channel().await {
                    Ok(mut ch) => {
                        backoff.reset();
                        if let Some(server) = tunnel.peer_server_id() {
                            events(ConnEvent::Connected { endpoint: endpoint.clone(), server });
                        }
                        let mut sess = tun.session();
                        let bridge_err = dataplane::bridge(&mut sess, &mut ch).await.err();
                        if let Some(e) = &bridge_err {
                            eprintln!("chmlvpn-client: dataplane ended: {e}");
                        }
                        drop(sess);
                        let reason = tunnel.stats().closed;
                        drop(control); // 控制流随会话结束（显式：先于 shutdown 的 FIN 次序）
                        events(ConnEvent::SessionEnded { endpoint: endpoint.clone(), reason });
                        tunnel.shutdown().await;
                    }
                    Err(e) => {
                        eprintln!("chmlvpn-client: 打开包通道失败: {e}");
                        tunnel.shutdown().await;
                    }
                }
            }
            Err(e) => {
                eprintln!("chmlvpn-client: 拨号失败（attempt {attempt}）: {e}");
            }
        }
        let d = backoff.next_jitter(rand::random::<f64>());
        eprintln!(
            "chmlvpn-client: {:?} 后重连（下一端点轮询）",
            d
        );
        tokio::time::sleep(d).await;
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::testutil::EchoPeer;
    use crate::tun::{MockTunDevice, TunDevice as _, TunIo, TunSpec};
    use chml_protocol::trust::PinStore;

    /// 守护循环集成：连接 → 数据面 → 对端拆链 → SessionEnded → 退避 → 重连成功
    /// （A9 客户端语义「检测进入重连」的宿主可跑对应物；静默死链计时在会话层 M1
    /// 已由 timer_deadlink_after_3x_keepalive_silence 覆盖，容器 A9 走真实 30s）。
    #[tokio::test]
    async fn supervise_reconnects_after_session_death() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = listener.local_addr().unwrap().to_string();
        let peer = std::sync::Arc::new(EchoPeer::new(&ep));
        let peer_serve = peer.clone();
        tokio::spawn(async move { peer_serve.serve(listener).await });

        let device = DeviceStaticKeys::generate();
        peer.register(&device);
        let mut pins = PinStore::new();
        pins.pin(&peer.directory.cluster_id, &peer.root.verifying_key());
        let state = ClientState { device, pins, directory: peer.directory.clone() };

        let mock = std::sync::Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = std::sync::Arc::new(TunIo::from_arc(mock.clone()));
        let tun_sup = tun.clone();

        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let sup = tokio::spawn(async move {
            supervise(
                &state,
                tun_sup.as_ref(),
                TunnelConfig::default(),
                Backoff::new(Duration::from_millis(80), Duration::from_millis(300)),
                |ev| {
                    let _ = ev_tx.send(
                        match ev {
                            ConnEvent::Dialing { endpoint, attempt } => {
                                format!("dial {endpoint} #{attempt}")
                            }
                            ConnEvent::Connected { endpoint, server } => {
                                format!("connected {endpoint} server-{:x?}", server.0.first())
                            }
                            ConnEvent::SessionEnded { endpoint, reason } => format!(
                                "ended {endpoint} reason={}",
                                reason.map(|r| r.to_string()).unwrap_or_else(|| "io".into())
                            ),
                        },
                    );
                },
            )
            .await;
        });

        // ① 首连 + 数据面回显。
        wait_event(&mut ev_rx, "connected").await;
        mock.inject(b"\x45\x00\x00\x14first");
        wait_written(&mock, 1).await;
        assert_eq!(mock.written()[0], b"\x45\x00\x00\x14first");

        // ② 对端拆全部会话 ⇒ SessionEnded ⇒ 退避 ⇒ 重连。
        peer.kill_sessions();
        wait_event(&mut ev_rx, "ended").await;
        wait_event(&mut ev_rx, "connected").await;

        // ③ 重连后数据面照常（tun 设备常驻复用）。
        let base = mock.written().len();
        mock.inject(b"\x45\x00\x00\x14again");
        wait_written(&mock, base + 1).await;
        assert_eq!(mock.written()[base], b"\x45\x00\x00\x14again");

        sup.abort();
        tun.shutdown();
    }

    async fn wait_event(rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>, needle: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(ev)) => {
                    if ev.contains(needle) {
                        return;
                    }
                }
                _ => panic!("15s 内未见事件 {needle:?}"),
            }
        }
    }

    async fn wait_written(mock: &std::sync::Arc<MockTunDevice>, n: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while mock.written().len() < n && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(mock.written().len() >= n, "写侧未达 {n}（现 {}）", mock.written().len());
    }

    #[test]
    fn backoff_sequence_and_jitter_bounds() {
        let mut b = Backoff::new(Duration::from_secs(5), Duration::from_secs(60));
        // 无抖动：5,10,20,40,60（封顶）,60…
        let seq: Vec<Duration> = (0..6).map(|_| b.next_jitter(0.0)).collect();
        assert_eq!(
            seq,
            vec![
                Duration::from_secs(5),
                Duration::from_secs(10),
                Duration::from_secs(20),
                Duration::from_secs(40),
                Duration::from_secs(60),
                Duration::from_secs(60),
            ],
            "5s 起步倍增封顶 60s（§2.3）"
        );
        // 抖动界：每一步 d ∈ [step, step·1.25]（step = 当步未抖动基数）。
        let mut b2 = Backoff::new(Duration::from_secs(5), Duration::from_secs(60));
        for k in 0..8u32 {
            let step = Duration::from_secs(5u64.saturating_mul(1 << k.min(4))).min(Duration::from_secs(60));
            let d = b2.next_jitter(0.999);
            assert!(
                d >= step && d <= step.mul_f64(1.25 + 1e-9),
                "attempt {k}: {d:?} 不在 [{step:?}, {:.2?}] 内",
                step.mul_f64(1.25)
            );
        }
        // 成功归零。
        let mut b3 = Backoff::default();
        let _ = b3.next_jitter(0.0);
        let _ = b3.next_jitter(0.0);
        b3.reset();
        assert_eq!(b3.next_jitter(0.0), Duration::from_secs(5), "reset 后回到 5s 起步");
    }

    #[test]
    fn endpoint_ring_rotates() {
        let mut r = EndpointRing::new(vec!["a:1".into(), "b:2".into(), "a:1".into(), "c:3".into()]);
        assert_eq!(r.len(), 4); // 轮询不在此去重（目录端点集在 endpoints() 已去重）
        let got: Vec<String> = (0..5).map(|_| r.next_endpoint().unwrap()).collect();
        assert_eq!(got, ["a:1", "b:2", "a:1", "c:3", "a:1"], "round-robin 轮询切换");
        let mut empty = EndpointRing::new(vec![]);
        assert!(empty.next_endpoint().is_none());
    }

    fn invite_fixture(root: &chml_protocol::ed25519_dalek::SigningKey, ttl: u64) -> chml_protocol::trust::InviteFile {
        use chml_protocol::session::{ClusterId, ServerEntry, ServerId};
        let identity = chml_protocol::ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let entry = ServerEntry {
            server_id: ServerId([9; 16]),
            relay_endpoint: "frps.test:27500".into(),
            identity_pub: identity.verifying_key(),
            static_hybrid_pub: chml_protocol::kem::HybridKeypair::generate(&mut rand::rngs::OsRng)
                .public(),
        };
        chml_protocol::trust::InviteFile::issue(
            root,
            ClusterId([7; 16]),
            1,
            vec![entry],
            chml_protocol::trust::now_unix() + ttl,
            [5; 16],
        )
    }

    #[test]
    fn ingest_invite_pins_root_and_persists_state() {
        let dir = tempfile::tempdir().unwrap();
        let root = chml_protocol::ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let inv = invite_fixture(&root, 3600);
        let state = ingest_invite(dir.path(), &inv).expect("落地");
        assert_eq!(state.endpoints(), vec!["frps.test:27500".to_string()]);
        // 重读（三件套落盘；gen-keys 先行生成的密钥保持同一把）。
        let re = ClientState::load(dir.path(), false).expect("reload");
        assert_eq!(
            re.device.to_bytes(),
            state.device.to_bytes(),
            "设备密钥跨 invite/load 稳定（永不出机）"
        );
        assert_eq!(re.directory.dir_version, 1);
        // pin_for 产出可拨号材料（根 = 钉扎值）。
        let pin = re.pin_for("frps.test:27500").expect("pin");
        assert_eq!(pin.cluster_root_pub, root.verifying_key());
        // 未知端点 ⇒ None（端点↔材料同签）。
        assert!(re.pin_for("evil:1").is_none());
    }

    #[test]
    fn ingest_invite_rejects_expired_and_root_change() {
        let dir = tempfile::tempdir().unwrap();
        let root = chml_protocol::ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        // 过期拒。
        let expired = chml_protocol::trust::InviteFile {
            expiry_unix: 1,
            ..invite_fixture(&root, 3600)
        };
        assert!(
            matches!(ingest_invite(dir.path(), &expired), Err(ClientError::Trust(_))),
            "过期邀请拒载"
        );
        // 根变更：先钉 A，再拿 B 签的邀请 ⇒ RootChanged（显式告警，不静默）。
        ingest_invite(dir.path(), &invite_fixture(&root, 3600)).expect("首钉");
        let other = chml_protocol::ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        match ingest_invite(dir.path(), &invite_fixture(&other, 3600)) {
            Err(ClientError::Trust(chml_protocol::trust::TrustError::RootChanged { .. })) => {}
            other_res => panic!("期望 RootChanged，得 {other_res:?}"),
        }
    }

    #[test]
    fn load_requires_directory_and_vip_resolution() {
        let dir = tempfile::tempdir().unwrap();
        // 只有密钥、无目录 ⇒ run 路径拒（提示 invite）。
        let _ = ClientState::load_keys(dir.path(), true).unwrap();
        assert!(matches!(
            ClientState::load(dir.path(), false),
            Err(ClientError::State(_))
        ));
        // VIP 解析：config 覆盖优先；缺省读 vip 文件。
        let state = {
            let root = chml_protocol::ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
            ingest_invite(dir.path(), &invite_fixture(&root, 3600)).unwrap()
        };
        assert_eq!(
            state
                .resolve_vip(dir.path(), Some("100.64.0.11".parse().unwrap()))
                .unwrap(),
            "100.64.0.11".parse::<std::net::Ipv4Addr>().unwrap()
        );
        std::fs::write(dir.path().join(VIP_FILE), "100.64.0.42\n").unwrap();
        assert_eq!(
            state.resolve_vip(dir.path(), None).unwrap(),
            "100.64.0.42".parse::<std::net::Ipv4Addr>().unwrap()
        );
    }
}
