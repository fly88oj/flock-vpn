//! 客户端控制流半边（M7，docs/design.md §7-M7.7 / §2.2 / §3.4）。
//!
//! 服务端控制面（登录/票据/key-bind/名册）此前只有 server 测试代偿的客户端角色；本模块
//! 补齐正式客户端半边，全部线类型复用 [`flock_protocol::roster`]（M7 上收——两端同类型）：
//!
//! - [`ControlPlane`]：当前会话控制流的**共享槽**——supervise 每会话 install/remove，
//!   业务任务（登录保持/名册拉取）经 [`ControlPlane::request`] 串行复用。请求超时 ⇒ 槽
//!   毒化 + 主动杀会话重连（yamux 流在超时后可能错位，宁可重连也不带错位继续——
//!   「不静默容错」纪律）。
//! - [`login_and_bind`]：Hello → OPAQUE 登录（anchor 验签：以钉扎目录条目身份为锚，
//!   §1.3.3f/§3.4）→ 票据（**只存内存**）→ key-bind（设备签名携带 hostname——re-register
//!   更新链路，§7-M7.1）。
//! - [`set_password_once`]：PwBegin/PwCommit（授权 = 会话设备 owner；`login` 子命令首次
//!   配置用——admin 面无开户口令操作，口令设置本就走控制流，§2.2）。
//! - 凭据文件（0600，一行口令）与 SR-SIG1 用户密钥的落位。
//!
//! 可测性：业务流经 [`CtrlTransport`] 抽象——生产 = 隧道内 yamux 控制流；单测 = mock
//! 传输 + `flock-protocol` pake **双端函数**内存走通（真 anchor 签名/验签、真 ke3 校验）。

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use flock_protocol::mux;
use flock_protocol::pake::{
    login_finish_anchored, login_start, reg_finish, reg_start, AnchorExpectation,
    Profile as PakeProfile,
};
use flock_protocol::roster::{
    keybind_canonical, normalize_hostname, recv_ctrl_msg, send_ctrl_msg, CtrlRequest, CtrlResponse,
    DevicePubs, TicketWire, CTRL_PROTO_VERSION,
};
use flock_protocol::session::{ClusterId, DeviceStaticKeys, ServerId};
use flock_protocol::sig::UserKey;
use flock_protocol::trust::ClusterDirectory;

/// 控制流单请求超时（登录含客户端侧 argon2 派生，放宽到 10s）。
pub const CTRL_REQ_TIMEOUT: Duration = Duration::from_secs(10);
/// 登录失败（拒绝类——口令错/无票据权）后的重试退避。
pub const LOGIN_RETRY_BACKOFF: Duration = Duration::from_secs(5);
/// state 目录内凭据文件名（`[auth] credentials_file` 可覆盖路径）。
pub const CREDENTIALS_FILE: &str = "credentials";
/// state 目录内 SR-SIG1 用户密钥种子文件名（key-bind 登记；0600）。
pub const SR_SIG_KEY_FILE: &str = "sr-sig.key";

// ============================================================================
// 控制流传输抽象（生产/测试同一业务流）
// ============================================================================

/// 控制流传输（一请求一响应，串行——与线协议「请求→响应」步进一致）。
pub trait CtrlTransport {
    fn request(
        &self,
        req: CtrlRequest,
    ) -> Pin<Box<dyn Future<Output = io::Result<CtrlResponse>> + Send + '_>>;
}

/// 共享 yamux 控制流（会话内在位）。
type SharedStream = std::sync::Arc<tokio::sync::Mutex<mux::Stream>>;

/// 当前会话控制流的共享槽（supervise ↔ 业务任务）。
///
/// 生命周期：supervise 每次会话建立即 [`install`](Self::install)，数据面结束/毒化即
/// [`remove`](Self::remove)；业务任务 [`request`](Self::request) 拿当前流串行收发。
/// 会话在位性经 watch 通道观察（登录保持任务等待「会话在位」再登录）。
#[derive(Clone)]
pub struct ControlPlane {
    inner: std::sync::Arc<PlaneInner>,
}

struct PlaneInner {
    stream: std::sync::Mutex<Option<SharedStream>>,
    up_tx: tokio::sync::watch::Sender<bool>,
    /// 常驻接收端（watch 的 send 在「零接收端」时关闭丢值——瞬时订阅的 is_up 会制造
    /// 该窗口；持有常驻接收端杜绝）。
    up_rx: tokio::sync::watch::Receiver<bool>,
    /// 会话毒化（请求超时）⇒ 主动杀会话（supervise select 该信号提前结束数据面）。
    kill: tokio::sync::Notify,
}

impl Default for ControlPlane {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlPlane {
    pub fn new() -> Self {
        let (up_tx, up_rx) = tokio::sync::watch::channel(false);
        ControlPlane {
            inner: std::sync::Arc::new(PlaneInner {
                stream: std::sync::Mutex::new(None),
                up_tx,
                up_rx,
                kill: tokio::sync::Notify::new(),
            }),
        }
    }

    /// 会话建立：装入控制流（supervise 调用）。
    pub fn install(&self, stream: mux::Stream) {
        self.install_arc(std::sync::Arc::new(tokio::sync::Mutex::new(stream)));
    }

    /// [`install`](Self::install) 的共享句柄形态（supervise 侧同持——会话结束先于 Drop）。
    pub fn install_arc(&self, shared: SharedStream) {
        *self.inner.stream.lock().expect("plane poisoned") = Some(shared);
        let _ = self.inner.up_tx.send(true);
    }

    /// 会话结束：取出并丢弃（supervise 调用；在途请求持克隆的将继续到 IO 失败为止）。
    pub fn remove(&self) {
        *self.inner.stream.lock().expect("plane poisoned") = None;
        let _ = self.inner.up_tx.send(false);
    }

    /// 会话是否在位（快照值）。
    pub fn is_up(&self) -> bool {
        *self.inner.up_rx.borrow()
    }

    /// 等待会话在位（已 true 立即返回；false→true 边缘经 watch 感知）。
    pub async fn wait_up(&self) {
        let mut rx = self.inner.up_rx.clone();
        loop {
            if *rx.borrow_and_update() {
                return;
            }
            if rx.changed().await.is_err() {
                // 发送端与 plane 同生命周期——不可达；防御性挂起而非自旋。
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    /// 等会话失位（登录保持任务在票据有效期内监听断链；已 false 立即返回）。
    pub async fn wait_down(&self) {
        let mut rx = self.inner.up_rx.clone();
        loop {
            if !*rx.borrow_and_update() {
                return;
            }
            if rx.changed().await.is_err() {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    /// 会话毒化信号（请求超时后由 [`Self::request`] 触发；supervise select 提前重连）。
    pub async fn killed(&self) {
        self.inner.kill.notified().await
    }

    /// 当前流（None = 无会话）。
    fn current(&self) -> Option<SharedStream> {
        self.inner.stream.lock().expect("plane poisoned").clone()
    }

    /// 毒化：清槽 + 杀会话（超时后流可能错位——不带错位继续，重连换新流）。
    fn poison(&self, why: &str) {
        eprintln!("flock-client: 控制流毒化（{why}）⇒ 主动重连");
        *self.inner.stream.lock().expect("plane poisoned") = None;
        let _ = self.inner.up_tx.send(false);
        self.inner.kill.notify_one();
    }

    /// 在当前会话控制流上发一请求收一响应（会话内在途互斥 ⇒ 串行）。
    pub async fn request(&self, req: CtrlRequest) -> io::Result<CtrlResponse> {
        self.request_timeout(req, CTRL_REQ_TIMEOUT).await
    }

    /// [`request`](Self::request) 的超时注入档（测试用短超时复现毒化路径）。
    pub async fn request_timeout(
        &self,
        req: CtrlRequest,
        timeout: Duration,
    ) -> io::Result<CtrlResponse> {
        let stream = self
            .current()
            .ok_or_else(|| io::Error::other("控制流未就绪（隧道未连接）"))?;
        let mut g = stream.lock().await;
        let r = tokio::time::timeout(timeout, async {
            send_ctrl_msg(&mut *g, &req).await?;
            recv_ctrl_msg(&mut *g).await
        })
        .await;
        match r {
            Ok(res) => res,
            Err(_) => {
                // 超时：响应可能迟到 ⇒ 流错位风险。毒化并杀会话，重连后重试。
                drop(g);
                self.poison("请求超时");
                Err(io::Error::new(io::ErrorKind::TimedOut, "控制流请求超时"))
            }
        }
    }
}

impl CtrlTransport for ControlPlane {
    fn request(
        &self,
        req: CtrlRequest,
    ) -> Pin<Box<dyn Future<Output = io::Result<CtrlResponse>> + Send + '_>> {
        Box::pin(Self::request(self, req))
    }
}

/// 独占控制流传输（`login` 一次性命令用——不经 daemon/共享槽；超时直接报错不毒化，
/// 命令进程随即退出、会话由 Drop 拆除）。
pub struct StreamTransport(pub std::sync::Arc<tokio::sync::Mutex<mux::Stream>>);

impl CtrlTransport for StreamTransport {
    fn request(
        &self,
        req: CtrlRequest,
    ) -> Pin<Box<dyn Future<Output = io::Result<CtrlResponse>> + Send + '_>> {
        let stream = self.0.clone();
        Box::pin(async move {
            let mut g = stream.lock().await;
            let r = tokio::time::timeout(CTRL_REQ_TIMEOUT, async {
                send_ctrl_msg(&mut *g, &req).await?;
                recv_ctrl_msg(&mut *g).await
            })
            .await;
            r.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "控制流请求超时"))?
        })
    }
}

// ============================================================================
// 登录参数与结果
// ============================================================================

/// 一次登录的全部入参（daemon 保持任务与 `login` 子命令共用）。
pub struct AuthParams {
    pub username: String,
    pub password: String,
    /// 上报 hostname（已经 [`normalize_hostname`] 对齐服务端语义）。
    pub hostname: String,
    pub device: DeviceStaticKeys,
    pub cluster_id: ClusterId,
    pub directory: ClusterDirectory,
    /// SR-SIG1 用户密钥（key-bind 登记；`login_and_bind` 只用公钥面）。
    pub sr_key: UserKey,
}

/// 登录成功产物（票据**只存内存**——进程退出即失效，§2.2）。
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    pub ticket: TicketWire,
    pub epoch: u64,
    pub device_id: [u8; 32],
    pub vip: [u8; 4],
    pub server_id: [u8; 16],
    /// 建议的下次重登等待（TTL 的 2/3——用 TTL 而非绝对 exp 排程，免疫两端时钟偏移）。
    pub refresh_after: Duration,
}

/// 登录失败（Io = 会话/传输层；Refused = 服务端拒绝或本地 OPAQUE 失败）。
#[derive(Debug)]
pub enum LoginError {
    Io(io::Error),
    Refused(String),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::Io(e) => write!(f, "控制流 IO: {e}"),
            LoginError::Refused(m) => write!(f, "登录被拒: {m}"),
        }
    }
}

fn refused<M: Into<String>>(m: M) -> LoginError {
    LoginError::Refused(m.into())
}

/// 从 [`CtrlResponse::Err`] 提取可读描述。
fn describe_err(resp: CtrlResponse) -> String {
    match resp {
        CtrlResponse::Err { code, msg } => format!("{code:?}: {msg}"),
        other => format!("意外响应: {other:?}"),
    }
}

// ============================================================================
// 登录 → key-bind（携带 hostname）
// ============================================================================

/// OPAQUE 登录（anchor 验签）+ key-bind（hostname 上报）。
///
/// 步骤（§2.2/§3.4/§7-M7.1）：
/// 1. Hello——校验 cluster_id 与钉扎目录一致（防串群）；
/// 2. LoginBegin/LoginFinish——anchor 签名以**钉扎目录内该 server 的身份公钥**验证
///    （`Hello.server_id` → 目录条目；未在册 ⇒ 拒）；
/// 3. LoginOk——票据入内存；
/// 4. KeyBind——设备签名覆盖 cluster‖user‖bind_token‖公钥‖hostname‖SR-SIG1 公钥
///    （同设备 re-register ⇒ 服务端更新 hostname，VIP 不变）。
pub async fn login_and_bind<T: CtrlTransport + ?Sized>(
    t: &T,
    p: &AuthParams,
) -> Result<LoginOutcome, LoginError> {
    // ① Hello + 集群一致性。
    let (cluster_id, server_id) = match t
        .request(CtrlRequest::Hello {
            ver: CTRL_PROTO_VERSION,
        })
        .await
    {
        Ok(CtrlResponse::Hello {
            cluster_id,
            server_id,
            ..
        }) => (cluster_id, server_id),
        Ok(other) => return Err(refused(describe_err(other))),
        Err(e) => return Err(LoginError::Io(e)),
    };
    if cluster_id != p.cluster_id.0 {
        return Err(refused(format!(
            "server cluster {cluster_id:02x?} ≠ 钉扎目录 {}",
            hex::encode(p.cluster_id.0)
        )));
    }
    // anchor 锚 = 钉扎目录内该服务器的身份公钥（端点轮询换服后仍取到正确锚）。
    let entry = p
        .directory
        .find(&ServerId(server_id))
        .ok_or_else(|| refused(format!("server {:02x?} 不在钉扎目录内", server_id)))?
        .clone();

    // ② OPAQUE 登录（ke1 → ke2[anchor 签名] → ke3）。
    let mut rng = flock_protocol::rand::rngs::OsRng;
    let (state, ke1) =
        login_start(&mut rng, &p.password, &p.username).map_err(|e| refused(e.to_string()))?;
    let (ke2_b64, bind_token, anchor_sig) = match t
        .request(CtrlRequest::LoginBegin {
            user: p.username.clone(),
            ke1_b64: ke1,
        })
        .await
    {
        Ok(CtrlResponse::LoginChallenge {
            ke2_b64,
            bind_token,
            anchor_sig,
        }) => (ke2_b64, bind_token, anchor_sig),
        Ok(other) => return Err(refused(describe_err(other))),
        Err(e) => return Err(LoginError::Io(e)),
    };
    let mut sig = [0u8; 64];
    if anchor_sig.len() != 64 {
        return Err(refused("anchor 签名长度非法"));
    }
    sig.copy_from_slice(&anchor_sig);
    // anchor 验签失败/口令错都在此 Err（口令错 = OPAQUE 本地 finish 失败，§3.4）。
    let ke3 = login_finish_anchored(
        state,
        &p.password,
        &p.username,
        &ke2_b64,
        PakeProfile::default(),
        &AnchorExpectation {
            server_id,
            identity_pub: entry.identity_pub,
            bind_token,
        },
        &sig,
    )
    .map_err(|e| refused(format!("anchor/OPAQUE finish: {e}")))?;
    let (ticket, epoch) = match t.request(CtrlRequest::LoginFinish { ke3_b64: ke3 }).await {
        Ok(CtrlResponse::LoginOk { ticket, epoch }) => (ticket, epoch),
        Ok(other) => return Err(refused(describe_err(other))),
        Err(e) => return Err(LoginError::Io(e)),
    };

    // ③ key-bind（设备签名携带 hostname + SR-SIG1 公钥）。
    let device = DevicePubs {
        x25519: p.device.x25519_public().to_bytes(),
        ed25519: *p.device.ed25519_public().as_bytes(),
        hostname: p.hostname.clone(),
    };
    let sr_pub = match flock_protocol::sig::UserKey::from_pub_string(&p.sr_key.pub_string()) {
        Ok(vk) => *vk.as_bytes(),
        Err(_) => unreachable!("自产公钥编码必回解"),
    };
    let canonical = keybind_canonical(&p.cluster_id.0, &p.username, &bind_token, &device, &sr_pub);
    let seed = p.device.to_bytes();
    let sk =
        flock_protocol::ed25519_dalek::SigningKey::from_bytes(seed[32..64].try_into().unwrap());
    use flock_protocol::ed25519_dalek::Signer as _;
    let device_sig = sk.sign(&canonical).to_bytes().to_vec();
    let (device_id, vip) = match t
        .request(CtrlRequest::KeyBind {
            ticket: ticket.clone(),
            bind_token,
            device,
            sr_sig_pub: sr_pub,
            device_sig,
        })
        .await
    {
        Ok(CtrlResponse::KeyBound { device_id, vip }) => (device_id, vip),
        Ok(other) => return Err(refused(describe_err(other))),
        Err(e) => return Err(LoginError::Io(e)),
    };

    // ④ 重登节奏：TTL 的 2/3（相对量——免疫两端时钟偏移；下限 2s、**上限 25s**——
    // 服务端控制流空闲超时 = 3×keepalive = 30s（§2.2 评审项 8），重登即保活；超 25s
    // 会让流先于票据过期被空闲关闭，届时本会话控制面不可再开（首流契约：一条会话
    // 恰一条控制流）⇒ 只能杀会话重连——封顶避免该形态成为常态）。
    let ttl = ticket.ttl_hint_secs().max(2);
    let refresh_after = Duration::from_secs((ttl * 2 / 3).clamp(2, 25));
    Ok(LoginOutcome {
        ticket,
        epoch,
        device_id,
        vip,
        server_id,
        refresh_after,
    })
}

// ============================================================================
// 首次配置：口令设置（PwBegin/PwCommit）+ 凭据/密钥落位
// ============================================================================

/// 服务端口令设置（一次性；授权 = 会话设备 owner == user）。
///
/// `PasswordExists` 视为已配置（返回 Ok(false)——沿用既有口令，登录验证兜底）。
pub async fn set_password_once<T: CtrlTransport + ?Sized>(
    t: &T,
    user: &str,
    pw: &str,
) -> Result<bool, String> {
    let mut rng = flock_protocol::rand::rngs::OsRng;
    let (state, m1) = reg_start(&mut rng, pw, user).map_err(|e| e.to_string())?;
    let m2 = match t
        .request(CtrlRequest::PwBegin {
            user: user.into(),
            m1_b64: m1,
        })
        .await
        .map_err(|e| e.to_string())?
    {
        CtrlResponse::PwChallenge { m2_b64 } => m2_b64,
        CtrlResponse::Err {
            code: flock_protocol::roster::CtrlError::PasswordExists,
            ..
        } => return Ok(false),
        other => return Err(describe_err(other)),
    };
    let record = reg_finish(&mut rng, state, pw, user, &m2).map_err(|e| e.to_string())?;
    match t
        .request(CtrlRequest::PwCommit {
            record_b64: record,
            profile: PakeProfile::default().id(),
        })
        .await
        .map_err(|e| e.to_string())?
    {
        CtrlResponse::Ok => Ok(true),
        other => Err(describe_err(other)),
    }
}

/// 凭据文件路径（`[auth] credentials_file` 覆盖；缺省 state 目录 `credentials`）。
pub fn credentials_path(state_dir: &Path, cfg_override: Option<&Path>) -> PathBuf {
    cfg_override
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| state_dir.join(CREDENTIALS_FILE))
}

/// 写凭据文件：单行口令；**0600**（unix）/ 管理员+SYSTEM 全权（Windows 显式 DACL）。
///
/// 静止风险如实声明（§7-M7.7）：OPAQUE 保证口令不上线；本地静止 = 本地信任域——
/// 文件属主外不可读（0600 / 受限 DACL），但属主侧（root/管理员/本用户）明文可读。
pub fn save_credentials(path: &Path, password: &str) -> io::Result<()> {
    write_secret_file(path, password.as_bytes())?;
    // 二次写（换口令）时权限不回退。
    Ok(())
}

/// 读凭据文件（剥单个行尾——保留口令内空白）。
pub fn load_credentials(path: &Path) -> io::Result<String> {
    let mut text = std::fs::read_to_string(path)
        .map_err(|e| io::Error::other(format!("读 {}: {e}", path.display())))?;
    if text.ends_with('\n') {
        text.pop();
    }
    if text.ends_with('\r') {
        text.pop();
    }
    if text.is_empty() {
        return Err(io::Error::other(format!(
            "{} 口令为空（重跑 `flock-client login` 配置）",
            path.display()
        )));
    }
    Ok(text)
}

/// SR-SIG1 用户密钥落位（缺失生成；存在复用——与设备密钥同一「永不出机」纪律）。
pub fn load_or_create_sr_key(state_dir: &Path) -> io::Result<UserKey> {
    let path = state_dir.join(SR_SIG_KEY_FILE);
    if let Ok(k) = UserKey::from_seed_file(&path) {
        return Ok(k);
    }
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let seed: [u8; 32] = bytes.as_slice().try_into().unwrap();
            return Ok(UserKey::from_seed(&seed));
        }
        return Err(io::Error::other(format!(
            "{} 期望 32B 种子",
            path.display()
        )));
    }
    let k = UserKey::generate();
    write_secret_file(&path, &k.to_seed())?;
    Ok(k)
}

/// 机密文件写盘：0600（unix）/ SYSTEM+Administrators 全权（Windows 显式 DACL，无 Users）。
fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        // Windows：写后立即显式收紧 DACL（SYSTEM+管理员；短暂窗口 = 创建到收紧之间，
        // 继承 ACL 默认——如实声明，非 0600 等价瞬时）。失败仅告警（继承 ACL 兜底可读）。
        if let Err(e) = crate::ipc_windows::set_file_acl_admins_only(path) {
            eprintln!(
                "flock-client: 告警：机密文件 ACL 收紧失败（{e}）: {}",
                path.display()
            );
        }
    }
    Ok(())
}

/// 上报 hostname：config 覆盖 → OS 主机名（hostname crate）→ 空串（服务端落 "(unknown)"）；
/// 统一 [`normalize_hostname`]（trim/64B 截断——与服务端落库语义对齐，§7-M7.1）。
pub fn resolve_hostname(cfg_override: Option<&str>) -> String {
    let raw = cfg_override
        .map(str::to_string)
        .or_else(|| hostname::get().ok().and_then(|s| s.into_string().ok()))
        .unwrap_or_default();
    normalize_hostname(&raw)
}

// ============================================================================
// 登录保持任务 + 名册缓存（daemon 装配面，§7-M7.7）
// ============================================================================

/// 登录阶段快照（IPC 错误文案/可观测面）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPhase {
    /// 未配置 `[auth]`（daemon 不登录——名册功能不可用）。
    Unconfigured,
    /// 隧道未连接，等待会话。
    WaitingSession,
    LoggingIn,
    LoggedIn {
        user: String,
    },
    Failed {
        reason: String,
    },
}

/// 登录态 + 当前票据（票据**只存内存**——daemon 生命周期内有效，§2.2）。
#[derive(Debug, Default)]
pub struct AuthShared {
    inner: std::sync::Mutex<AuthInner>,
}

#[derive(Debug, Default)]
struct AuthInner {
    phase: Option<AuthPhase>,
    ticket: Option<TicketWire>,
}

impl AuthShared {
    pub fn new() -> Self {
        Self::default()
    }

    /// 阶段快照（未上报过 ⇒ None——装配前态）。
    pub fn phase(&self) -> Option<AuthPhase> {
        self.inner
            .lock()
            .expect("auth shared poisoned")
            .phase
            .clone()
    }

    fn set_phase(&self, p: AuthPhase) {
        self.inner.lock().expect("auth shared poisoned").phase = Some(p);
    }

    fn set_ticket(&self, t: Option<TicketWire>) {
        self.inner.lock().expect("auth shared poisoned").ticket = t;
    }

    /// 当前票据克隆（IPC Peers 拉取用；无 ⇒ None）。
    pub fn ticket(&self) -> Option<TicketWire> {
        self.inner
            .lock()
            .expect("auth shared poisoned")
            .ticket
            .clone()
    }
}

/// 最近一次名册拉取的缓存（IPC `Peers` 的 ≤5s 新鲜窗数据源）。
#[derive(Debug, Default)]
pub struct RosterCache {
    inner: std::sync::Mutex<Option<RosterSnapshot>>,
}

/// 缓存条目：拉取时刻 + 名册。
#[derive(Debug, Clone)]
pub struct RosterSnapshot {
    pub at: std::time::Instant,
    pub peers: Vec<flock_protocol::roster::PeerInfo>,
}

/// 名册缓存新鲜窗（IPC Peers：≤5s 内直接用缓存，否则重拉）。
pub const ROSTER_FRESH_WINDOW: Duration = Duration::from_secs(5);

impl RosterCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// 新鲜窗内的缓存命中（None = 无缓存或已过期）。
    pub fn fresh(&self) -> Option<Vec<flock_protocol::roster::PeerInfo>> {
        let g = self.inner.lock().expect("roster cache poisoned");
        g.as_ref()
            .filter(|s| s.at.elapsed() <= ROSTER_FRESH_WINDOW)
            .map(|s| s.peers.clone())
    }

    /// 覆盖缓存（成功拉取后写）。
    pub fn store(&self, peers: Vec<flock_protocol::roster::PeerInfo>) {
        *self.inner.lock().expect("roster cache poisoned") = Some(RosterSnapshot {
            at: std::time::Instant::now(),
            peers,
        });
    }
}

/// 登录保持任务的静态入参（口令外全部——口令每次登录前**重读**凭据文件，
/// `flock-client login` 换口令后无需重启 daemon）。
pub struct AuthCtx {
    pub username: String,
    pub credentials_path: PathBuf,
    pub hostname: String,
    pub device: DeviceStaticKeys,
    pub cluster_id: ClusterId,
    pub directory: ClusterDirectory,
    pub sr_key: UserKey,
}

impl AuthCtx {
    /// 组装本次登录参数（口令现读）。
    fn params(&self) -> Result<AuthParams, String> {
        let password = load_credentials(&self.credentials_path)
            .map_err(|e| format!("凭据文件: {e}（重跑 `flock-client login` 配置）"))?;
        Ok(AuthParams {
            username: self.username.clone(),
            password,
            hostname: self.hostname.clone(),
            device: DeviceStaticKeys::from_bytes(&self.device.to_bytes()),
            cluster_id: self.cluster_id,
            directory: self.directory.clone(),
            sr_key: UserKey::from_seed(&self.sr_key.to_seed()),
        })
    }
}

/// 登录保持任务：会话在位 ⇒ 登录（+key-bind hostname）⇒ 票据入内存 ⇒ 按 TTL 的 2/3
/// 周期重登保持新鲜；会话失位 ⇒ 等新会话重登；拒绝类失败 ⇒ 退避重试。
///
/// 永不正常返回（daemon 生命周期任务；`stop` 触发即退出）。
pub async fn run_auth_keepalive(
    plane: ControlPlane,
    ctx: AuthCtx,
    shared: std::sync::Arc<AuthShared>,
    stop: std::sync::Arc<tokio::sync::Notify>,
) {
    loop {
        // —— 等会话在位（或停机）——
        shared.set_phase(AuthPhase::WaitingSession);
        tokio::select! {
            _ = plane.wait_up() => {}
            _ = stop.notified() => return
        }
        // —— 登录循环（成功后按 refresh_after 周期重登；失位/停机退出本层）——
        loop {
            let params = match ctx.params() {
                Ok(p) => p,
                Err(e) => {
                    shared.set_phase(AuthPhase::Failed { reason: e });
                    tokio::select! {
                        _ = tokio::time::sleep(LOGIN_RETRY_BACKOFF) => continue,
                        _ = plane.wait_down() => break,
                        _ = stop.notified() => return,
                    }
                }
            };
            shared.set_phase(AuthPhase::LoggingIn);
            match login_and_bind(&plane, &params).await {
                Ok(out) => {
                    eprintln!(
                        "flock-client: login ok user={} vip={} epoch={}（{} 后重登保持票据）",
                        params.username,
                        std::net::Ipv4Addr::from(out.vip),
                        out.epoch,
                        out.refresh_after.as_secs()
                    );
                    shared.set_phase(AuthPhase::LoggedIn {
                        user: params.username.clone(),
                    });
                    shared.set_ticket(Some(out.ticket));
                    tokio::select! {
                        _ = tokio::time::sleep(out.refresh_after) => {} // 周期重登
                        _ = plane.wait_down() => break,                  // 会话失位 ⇒ 等新会话
                        _ = stop.notified() => return,
                    }
                }
                Err(LoginError::Io(e)) => {
                    // 传输失败 = 控制流已不可用（EOF/坏帧；**首流契约**下本会话控制
                    // 面不可再开——服务端只把流 id=1 分派为控制流）。毒化 ⇒ 杀会话
                    // 重连换新流；不做「plane 仍在的短退避重试」——死流上重试只会
                    // 空转（评审补：原 500ms 重试循环在服务端 30s 空闲关流后死循环）。
                    eprintln!("flock-client: login io（控制流不可用，重连换流）: {e}");
                    shared.set_phase(AuthPhase::Failed {
                        reason: format!("控制流 IO: {e}"),
                    });
                    plane.poison("登录传输失败");
                    tokio::select! {
                        _ = plane.wait_down() => break,
                        _ = stop.notified() => return,
                    }
                }
                Err(e @ LoginError::Refused(_)) => {
                    // 服务端拒绝（口令错/票据权缺失等）——会话仍在：固定退避重试
                    //（换口令重跑 `flock-client login` 后自动恢复）。
                    eprintln!(
                        "flock-client: login 被拒，{}s 后重试: {e}",
                        LOGIN_RETRY_BACKOFF.as_secs()
                    );
                    shared.set_phase(AuthPhase::Failed {
                        reason: e.to_string(),
                    });
                    tokio::select! {
                        _ = tokio::time::sleep(LOGIN_RETRY_BACKOFF) => {}
                        _ = plane.wait_down() => break,
                        _ = stop.notified() => return,
                    }
                }
            }
        }
    }
}

// ============================================================================
// 名册拉取（PeerListPull 消费，§7-M7.4——票据保护；结果进 RosterCache）
// ============================================================================

/// 拉取成员名册（当前票据 + 控制流在位；成功由调用方 [`RosterCache::store` 缓存）。
pub async fn pull_roster(
    plane: &ControlPlane,
    ticket: &TicketWire,
) -> Result<Vec<flock_protocol::roster::PeerInfo>, String> {
    match plane
        .request(CtrlRequest::PeerListPull {
            ticket: Some(ticket.clone()),
        })
        .await
    {
        Ok(CtrlResponse::PeerList { peers }) => Ok(peers),
        Ok(CtrlResponse::Err { code, msg }) => Err(format!("{code:?}: {msg}")),
        Ok(other) => Err(format!("意外响应: {other:?}")),
        Err(e) => Err(format!("控制流: {e}")),
    }
}

// ============================================================================
// 单元测试：登录态机（mock 传输 + flock-protocol pake 双端函数内存走通——
// 真 anchor 签名/验签、真 ke1/ke2/ke3、真 keybind 设备签名验证）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use flock_protocol::ed25519_dalek::Verifier as _;
    use flock_protocol::opaque_ke;
    use flock_protocol::pake::{
        anchor_sign, server_login_finish, server_login_start, server_record_from_b64,
        server_reg_canonical, server_reg_start, server_setup_load, server_setup_new, Suite,
    };
    use flock_protocol::rand;
    use flock_protocol::roster::{CtrlError, SignedTicket};
    use flock_protocol::session::{DeviceId, ServerEntry};

    /// mock 服务端状态（真实 pake 服务端函数；票据签发用哑签名——客户端不验签，
    /// 只透传与读 TTL hint）。
    struct MockState {
        identity: flock_protocol::ed25519_dalek::SigningKey,
        attacker: flock_protocol::ed25519_dalek::SigningKey,
        server_id: [u8; 16],
        cluster_id: [u8; 16],
        setup: opaque_ke::ServerSetup<Suite>,
        record: Option<String>,
        pending: Option<Vec<u8>>,
        password_set: bool,
        hostname_seen: Option<String>,
        keybind_device_sig_ok: Option<bool>,
        /// 负路径开关：anchor 用攻击者密钥签（伪服务器替身）。
        forged_anchor: bool,
    }

    impl MockState {
        fn new() -> Self {
            let mut rng = rand::rngs::OsRng;
            MockState {
                identity: flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                attacker: flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[8; 32]),
                server_id: [7; 16],
                cluster_id: [7; 16],
                setup: server_setup_load(&server_setup_new(&mut rng)).unwrap(),
                record: None,
                pending: None,
                password_set: false,
                hostname_seen: None,
                keybind_device_sig_ok: None,
                forged_anchor: false,
            }
        }

        /// 钉扎目录（identity_pub = mock 服务端身份——anchor 验签锚）。
        fn directory(&self) -> ClusterDirectory {
            ClusterDirectory {
                cluster_id: ClusterId(self.cluster_id),
                dir_version: 1,
                servers: vec![ServerEntry {
                    server_id: flock_protocol::session::ServerId(self.server_id),
                    relay_endpoint: "mock:1".into(),
                    identity_pub: self.identity.verifying_key(),
                    static_hybrid_pub: flock_protocol::kem::HybridKeypair::generate(
                        &mut rand::rngs::OsRng,
                    )
                    .public(),
                }],
                root_sig: flock_protocol::ed25519_dalek::Signature::from_bytes(&[0; 64]),
            }
        }

        fn err(&self, code: CtrlError) -> CtrlResponse {
            CtrlResponse::Err {
                code,
                msg: code.msg().to_string(),
            }
        }

        fn dispatch(&mut self, req: CtrlRequest) -> CtrlResponse {
            let mut rng = rand::rngs::OsRng;
            match req {
                CtrlRequest::Hello { .. } => CtrlResponse::Hello {
                    ver: CTRL_PROTO_VERSION,
                    cluster_id: self.cluster_id,
                    server_id: self.server_id,
                },
                CtrlRequest::PwBegin { user, m1_b64 } => {
                    // 与真服务端同语义：已设口令 ⇒ PasswordExists（首设一次成功）。
                    if self.record.is_some() {
                        return self.err(CtrlError::PasswordExists);
                    }
                    match server_reg_start(&self.setup, &m1_b64, &user) {
                        Ok(m2) => CtrlResponse::PwChallenge { m2_b64: m2 },
                        Err(_) => self.err(CtrlError::Internal),
                    }
                }
                CtrlRequest::PwCommit { record_b64, .. } => {
                    match server_reg_canonical(&record_b64) {
                        Ok(c) => {
                            self.record = Some(c);
                            self.password_set = true;
                            CtrlResponse::Ok
                        }
                        Err(_) => self.err(CtrlError::Internal),
                    }
                }
                CtrlRequest::LoginBegin { user, ke1_b64 } => {
                    let record = self
                        .record
                        .as_ref()
                        .and_then(|r| server_record_from_b64(r).ok());
                    match server_login_start(
                        &mut rng,
                        &self.setup,
                        record.as_ref(),
                        &ke1_b64,
                        &user,
                    ) {
                        Ok((ke2, state)) => {
                            let bind_token: [u8; 16] = rand::random();
                            let signer = if self.forged_anchor {
                                &self.attacker
                            } else {
                                &self.identity
                            };
                            let sig =
                                anchor_sign(signer, &self.server_id, &user, &ke2, &bind_token);
                            self.pending = Some(state);
                            CtrlResponse::LoginChallenge {
                                ke2_b64: ke2,
                                bind_token,
                                anchor_sig: sig.to_bytes().to_vec(),
                            }
                        }
                        Err(_) => self.err(CtrlError::LoginFailed),
                    }
                }
                CtrlRequest::LoginFinish { ke3_b64 } => {
                    let Some(state) = self.pending.take() else {
                        return self.err(CtrlError::NotAuthorized);
                    };
                    if server_login_finish(&state, &ke3_b64).is_err() {
                        return self.err(CtrlError::LoginFailed);
                    }
                    let now = flock_protocol::trust::now_unix();
                    // 哑票据（客户端不验签；TTL hint 60 ⇒ refresh_after 40s）。
                    CtrlResponse::LoginOk {
                        ticket: TicketWire::Local(SignedTicket {
                            user: "alice".into(),
                            device: vec![0; 32],
                            epoch: 0,
                            iat: now,
                            exp: now + 60,
                            sig: vec![0; 64],
                        }),
                        epoch: 3,
                    }
                }
                CtrlRequest::KeyBind {
                    ticket,
                    bind_token,
                    device,
                    sr_sig_pub,
                    device_sig,
                } => {
                    // 票据必须在位（哑票据透传语义：Local 即视为已登录产物）。
                    let TicketWire::Local(t) = ticket else {
                        return self.err(CtrlError::TicketBad);
                    };
                    // 设备签名真验证（keybind_canonical 与服务端同源）。
                    let user = t.user.clone();
                    let canonical = keybind_canonical(
                        &self.cluster_id,
                        &user,
                        &bind_token,
                        &device,
                        &sr_sig_pub,
                    );
                    let (vk, sig) = (
                        flock_protocol::ed25519_dalek::VerifyingKey::from_bytes(&device.ed25519),
                        flock_protocol::ed25519_dalek::Signature::from_slice(&device_sig),
                    );
                    let ok = vk
                        .and_then(|vk| sig.map(|s| vk.verify(&canonical, &s).is_ok()))
                        .unwrap_or(false);
                    self.keybind_device_sig_ok = Some(ok);
                    if !ok {
                        return self.err(CtrlError::BindSigBad);
                    }
                    self.hostname_seen = Some(device.hostname.clone());
                    let vk =
                        flock_protocol::ed25519_dalek::VerifyingKey::from_bytes(&device.ed25519)
                            .unwrap();
                    CtrlResponse::KeyBound {
                        device_id: DeviceId::from_ed25519(&vk).0,
                        vip: [100, 64, 0, 11],
                    }
                }
                _ => self.err(CtrlError::NotAuthorized),
            }
        }
    }

    /// mock 传输：请求即刻同步调度（pake 服务端函数全同步——无需真网络/yamux）。
    struct MockTransport {
        st: std::sync::Arc<std::sync::Mutex<MockState>>,
        log: std::sync::Arc<std::sync::Mutex<Vec<CtrlRequest>>>,
    }

    impl MockTransport {
        fn new(st: std::sync::Arc<std::sync::Mutex<MockState>>) -> Self {
            MockTransport {
                st,
                log: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
    }

    impl CtrlTransport for MockTransport {
        fn request(
            &self,
            req: CtrlRequest,
        ) -> Pin<Box<dyn Future<Output = io::Result<CtrlResponse>> + Send + '_>> {
            let st = self.st.clone();
            let log = self.log.clone();
            Box::pin(async move {
                log.lock().unwrap().push(req.clone());
                let mut g = st.lock().unwrap();
                Ok(g.dispatch(req))
            })
        }
    }

    fn params(st: &MockState, pw: &str, hostname: &str) -> AuthParams {
        AuthParams {
            username: "alice".into(),
            password: pw.into(),
            hostname: hostname.into(),
            device: DeviceStaticKeys::generate(),
            cluster_id: ClusterId(st.cluster_id),
            directory: st.directory(),
            sr_key: UserKey::generate(),
        }
    }

    /// 正向全链：set_password → login_and_bind（anchor 验签过 + hostname 携带 +
    /// 设备签名被服务端侧验过 + TTL hint → refresh 40s）。
    #[tokio::test]
    async fn login_state_machine_happy_path() {
        let st = std::sync::Arc::new(std::sync::Mutex::new(MockState::new()));
        let t = MockTransport::new(st.clone());
        let p = params(&st.lock().unwrap(), "pw-123", "box-m7");

        // 首次配置：口令设置（真 reg 链路——服务端 mock 落 record）。
        assert!(set_password_once(&t, "alice", "pw-123").await.unwrap());
        assert!(st.lock().unwrap().password_set);

        let out = login_and_bind(&t, &p).await.expect("登录全链");
        assert_eq!(out.vip, [100, 64, 0, 11]);
        assert_eq!(out.epoch, 3);
        assert_eq!(
            out.device_id,
            DeviceId::from_ed25519(&p.device.ed25519_public()).0
        );
        assert_eq!(
            out.refresh_after,
            Duration::from_secs(25),
            "TTL 60 ⇒ 2/3=40 封顶 25（服务端控制流 30s 空闲窗内保活）"
        );
        let g = st.lock().unwrap();
        assert_eq!(
            g.hostname_seen.as_deref(),
            Some("box-m7"),
            "key-bind 携带 hostname"
        );
        assert_eq!(
            g.keybind_device_sig_ok,
            Some(true),
            "设备签名服务端侧验证通过"
        );
    }

    /// 负路径：伪造 anchor（伪服务器替身）⇒ 客户端拒绝（ke3 不产生，后续步骤不走）。
    #[tokio::test]
    async fn login_rejects_forged_anchor() {
        let st = std::sync::Arc::new(std::sync::Mutex::new(MockState::new()));
        let t = MockTransport::new(st.clone());
        {
            let mut g = st.lock().unwrap();
            g.forged_anchor = true;
        }
        let p = params(&st.lock().unwrap(), "pw-123", "box");
        set_password_once(&t, "alice", "pw-123").await.unwrap();

        let e = login_and_bind(&t, &p)
            .await
            .expect_err("伪 anchor 必须被拒");
        assert!(
            matches!(&e, LoginError::Refused(m) if m.contains("anchor")),
            "{e}"
        );
        // 未推进到 LoginFinish（anchor 失败即止——不产生 ke3）。
        let log = t.log.lock().unwrap();
        assert!(
            !log.iter()
                .any(|r| matches!(r, CtrlRequest::LoginFinish { .. })),
            "ke3 不产生"
        );
    }

    /// 负路径：口令错 ⇒ 客户端本地 finish 失败（不产生 ke3；线上无差异）。
    #[tokio::test]
    async fn login_wrong_password_fails_client_finish() {
        let st = std::sync::Arc::new(std::sync::Mutex::new(MockState::new()));
        let t = MockTransport::new(st.clone());
        set_password_once(&t, "alice", "pw-123").await.unwrap();
        let p = params(&st.lock().unwrap(), "wrong-pw", "box");

        let e = login_and_bind(&t, &p).await.expect_err("错口令必须被拒");
        assert!(matches!(e, LoginError::Refused(_)), "{e}");
        let log = t.log.lock().unwrap();
        assert!(
            !log.iter()
                .any(|r| matches!(r, CtrlRequest::LoginFinish { .. })),
            "本地失败即止——第三请求不发"
        );
    }

    /// set_password：已设口令 ⇒ Ok(false)（沿用语义——登录验证兜底）。
    #[tokio::test]
    async fn set_password_once_password_exists_is_ok_false() {
        let st = std::sync::Arc::new(std::sync::Mutex::new(MockState::new()));
        let t = MockTransport::new(st.clone());
        assert!(set_password_once(&t, "alice", "pw").await.unwrap());
        assert!(!set_password_once(&t, "alice", "other").await.unwrap());
    }

    /// 凭据文件往返：0600（unix）+ 读回一致 + 空口令拒。
    #[test]
    fn credentials_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nested").join(CREDENTIALS_FILE);
        save_credentials(&p, "s3cret pw ").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600,
                "凭据文件 0600"
            );
        }
        assert_eq!(
            load_credentials(&p).unwrap(),
            "s3cret pw ",
            "行尾剥除、内空白保留"
        );
        let empty = dir.path().join("empty-cred");
        std::fs::write(&empty, "\r\n").unwrap();
        assert!(load_credentials(&empty).is_err(), "空口令拒");
    }

    /// SR-SIG1 密钥落位：首建持久化、二次载入同种子。
    #[test]
    fn sr_key_load_or_create_persists() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_or_create_sr_key(dir.path()).unwrap();
        let b = load_or_create_sr_key(dir.path()).unwrap();
        assert_eq!(a.to_seed(), b.to_seed(), "跨调用稳定（永不出机）");
        assert!(dir.path().join(SR_SIG_KEY_FILE).exists());
    }

    /// hostname 覆盖语义：trim 后规范化；空串 ⇒ "(unknown)"。
    #[test]
    fn resolve_hostname_override_semantics() {
        assert_eq!(resolve_hostname(Some("  box-a ")), "box-a");
        assert_eq!(resolve_hostname(Some("")), "(unknown)");
        let long = "x".repeat(80);
        assert_eq!(
            resolve_hostname(Some(&long)).len(),
            64,
            "64B 截断与服务端对齐"
        );
    }
}
