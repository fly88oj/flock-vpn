//! 控制 IPC v1（docs/design.md §7-M6.2）：托盘/CLI ⇄ daemon 的本地控制面。
//!
//! **契约（消费方 = 下一阶段托盘工程）**：postcard over 本地传输，帧格式与
//! §3.11 admin 面同构——`[u32 LE len][postcard]`（len=0 或 > [`MAX_CTRL_FRAME`] 拒帧）；
//! **单连接单请求-响应**（一帧请求 → 一帧响应 → 连接关闭）。每请求都带 token
//! （[`CtrlReq`] 两变体同名字段），校验先于分发，错即 [`CtrlResp::Denied`]。
//!
//! 传输层选型：
//! - **Windows 命名管道**（`\\.\pipe\flock-client-control`）：`tokio::net::windows::
//!   named_pipe` 重叠 IO（tokio 官方封装， overlapped 句柄 + IOCP 完成端口，与既有
//!   tokio 运行时同调度域；不选同步线程泵——多连接并发 + 优雅关闭需自管线程池与
//!   CancelIoEx 生命周期，复杂度无收益）。管道实例以显式 DACL 创建（SDDL
//!   `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)`：SYSTEM + Administrators + 交互用户组），
//!   覆盖默认 DACL（默认对 Everyone 开读，见 CreateNamedPipeW 文档）。
//! - **Unix socket**（`/run/flock/client.sock`）：`tokio::net::UnixListener`，bind 后
//!   chmod 0660（bind 前路径不存在，umask 不可控 ⇒ 显式 chmod）。
//!
//! 认证 token：daemon 每次启动 [`generate_token`] 生成 32B，hex 文本落
//! [`ControlPaths::token_file`]（Windows 显式 ACL：SYSTEM/管理员全权 + Users 读；
//! Unix 0640 root，`control_group` 配置存在时尝试 chgrp）。token 比较走常量时间
//! （本地传输 + DACL 之下为纵深防御位，非主要边界）。

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 单帧上限（v1 原为 4KiB；M7 `Peers` 名册面扩到 256KiB——千行级名册 ~64B/行余量，
/// 仍远小于控制面 256KiB 上限的记录层语义；防御位不变：超限拒帧）。
pub const MAX_CTRL_FRAME: usize = 256 * 1024;
/// 客户端单次请求的整链超时（连接 + 往返；status/托盘轮询的默认档）。
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
/// `Peers` 请求的整链超时档（名册拉取 + 3 探针 × 2s 超时串行 ⇒ 上限 ~10s，留余量）。
pub const PEERS_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// 单连接服务整链超时（评审项 4：连接后不发帧/不读帧的对端不得永久占住管道
/// 实例——超时即断开释放）。10s 对 Peers 最重路径自洽：名册拉取内部
/// [`crate::ctrl::CTRL_REQ_TIMEOUT`] 10s 到点即错出（不叠加）、ping 并发 ≤6s，
/// 典型完成 <10s；拉取恰在 10s 到点错误的极窄竞态下客户端见断管（与超时同义）。
pub const SERVE_CONN_TIMEOUT: Duration = Duration::from_secs(10);
/// accept/connect 瞬态错误的退避（评审项 4：持续瞬态压力下不空转刷日志）。
pub const ACCEPT_RETRY_BACKOFF: Duration = Duration::from_millis(250);

// ============================================================================
// 契约类型（v1——托盘工程消费面，改字段=破契；M7 增 Peers 面）
// ============================================================================

/// 控制面认证 token（32B 随机，daemon 每次启动生成）。
pub type CtrlToken = [u8; 32];

/// v1 控制请求（每变体都带 token：认证先于分发，§7-M6.2）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtrlReq {
    /// 查询状态（幂等无副作用）。
    Status { token: CtrlToken },
    /// 优雅停服（断会话 → 停数据面 → 拆 tun → 进程退出；服务管理器不复活）。
    Shutdown { token: CtrlToken },
    /// 成员名册（M7 §7-M7.7）：daemon 组装增强名册（拉取/≤5s 缓存 + ping 探测）。
    Peers { token: CtrlToken },
}

/// 连接状态（`flock-client service` 的 supervise 投影）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnState {
    Connected,
    Connecting,
    Disconnected,
}

/// v1 控制响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtrlResp {
    /// 状态快照（Status 请求的响应）。
    Status {
        state: ConnState,
        /// 本端 VIP（启动即解析 ⇒ Some；Option 为文案容错位）。
        vip: Option<String>,
        /// 当前/最近一次拨号端点。
        endpoint: Option<String>,
        /// 当前会话密钥纪元（rekey 推进；无会话 ⇒ 0）。
        epoch: u64,
        /// daemon 启动至今秒数。
        uptime_secs: u64,
    },
    /// Shutdown 受理。
    Ok,
    /// 成员名册（M7 §7-M7.7；按 VIP 升序——服务端装配序）。
    Peers { rows: Vec<crate::peers::PeerRow> },
    /// 名册不可用（M7：未登录/隧道未连/未配置 [auth] 等——`reason` 供 CLI 指引文案）。
    PeersUnavailable { reason: String },
    /// token 错（任何请求）。
    Denied,
}

// ============================================================================
// 帧编解码（与 §3.11 admin 面同构）
// ============================================================================

async fn send_frame<S: AsyncWrite + Unpin, M: Serialize>(io: &mut S, msg: &M) -> io::Result<()> {
    let bytes = postcard::to_allocvec(msg).map_err(|e| io::Error::other(e.to_string()))?;
    if bytes.len() > MAX_CTRL_FRAME {
        return Err(io::Error::other("ctrl msg too large"));
    }
    io.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    io.write_all(&bytes).await?;
    io.flush().await
}

async fn recv_frame<S: AsyncRead + Unpin, M: for<'de> Deserialize<'de>>(
    io: &mut S,
) -> io::Result<M> {
    let mut hdr = [0u8; 4];
    io.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > MAX_CTRL_FRAME {
        return Err(io::Error::other("ctrl frame length"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    postcard::from_bytes(&buf).map_err(|e| io::Error::other(e.to_string()))
}

// ============================================================================
// daemon 侧
// ============================================================================

/// daemon 侧控制面依赖（service 装配注入；快照源 + 停机触发 + 名册装配）。
pub struct DaemonControl {
    /// 通行 token（请求侧比对基准）。
    pub token: CtrlToken,
    /// 状态快照（须返回 [`CtrlResp::Status`] 变体；IPC 任务并发调用 ⇒ Send+Sync）。
    pub status: std::sync::Arc<dyn Fn() -> CtrlResp + Send + Sync>,
    /// 停机触发（受理 Shutdown 后同步返回前调用；实际拆除由 service 主流程执行）。
    pub shutdown: std::sync::Arc<dyn Fn() + Send + Sync>,
    /// 名册装配（M7 §7-M7.7：拉取/缓存 + ping 探测；None = 未装配——
    /// 无 [auth] 配置/测试注入面 ⇒ PeersUnavailable）。
    pub peers: Option<std::sync::Arc<dyn Fn() -> BoxFuture<'static, CtrlResp> + Send + Sync>>,
}

/// 常量时间比对（长度不等直接假——token 定长 32B，无长度泄露面）。
fn token_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = a.len() ^ b.len();
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

/// accept/connect 循环错误分类（评审项 4）。
///
/// - **瞬态**（记日志 + [`ACCEPT_RETRY_BACKOFF`] 退避后 continue——不杀 IPC 任务）：
///   fd 耗尽（EMFILE/ENFILE——进程级资源压力）、WouldBlock/Interrupted、
///   ConnectionAborted/ConnectionReset（对端半途消失）、Windows 管道首连
///   NotConnected（ERROR_NO_DATA：客户端连后即断，实例可重用）与下实例创建
///   ERROR_PIPE_BUSY（231，AllPipeInstancesBusy——实例在途，既有连接完成后可建）；
/// - **致命**（其余：listener/管道损坏、权限、编程错误）⇒ 循环返回上浮，daemon
///   主流程经 IPC 任务收尾感知（service.rs select 臂）。
pub fn accept_error_is_transient(e: &io::Error) -> bool {
    use io::ErrorKind as K;
    if matches!(
        e.kind(),
        K::WouldBlock | K::Interrupted | K::ConnectionAborted | K::ConnectionReset | K::NotConnected
    ) {
        return true;
    }
    // Windows：ERROR_PIPE_BUSY（231）——管道实例在途耗尽（AllPipeInstancesBusy）。
    #[cfg(windows)]
    if e.raw_os_error() == Some(231) {
        return true;
    }
    // Unix：EMFILE(24)/ENFILE(23)——linux/macos 同值（无 libc 依赖面；fd 耗尽为
    // 进程级瞬态压力，退避后既有连接释放即恢复）。
    #[cfg(unix)]
    if matches!(e.raw_os_error(), Some(24) | Some(23)) {
        return true;
    }
    false
}

/// 单连接服务：读一帧请求 → 认证 → 分发 → 写一帧响应（整链受
/// [`SERVE_CONN_TIMEOUT`] 约束——评审项 4：不发帧/不读帧的连接不得永久占住
/// 管道实例，超时断开释放）。
///
/// 传输层泛型（mock duplex 单测面）；畸形帧 ⇒ io 错误关闭连接，无响应。
pub async fn serve_conn<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    ctrl: &DaemonControl,
) -> io::Result<()> {
    let served = async {
        let req: CtrlReq = recv_frame(io).await?;
        let resp = match &req {
            CtrlReq::Status { token } if token_eq(token, &ctrl.token) => (ctrl.status)(),
            CtrlReq::Shutdown { token } if token_eq(token, &ctrl.token) => {
                (ctrl.shutdown)();
                CtrlResp::Ok
            }
            CtrlReq::Peers { token } if token_eq(token, &ctrl.token) => match &ctrl.peers {
                Some(f) => f().await,
                None => CtrlResp::PeersUnavailable {
                    reason: "daemon 未装配名册面（client.toml 缺 [auth]？）".into(),
                },
            },
            _ => CtrlResp::Denied,
        };
        send_frame(io, &resp).await
    };
    match tokio::time::timeout(SERVE_CONN_TIMEOUT, served).await {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "控制连接整链超时（10s——连接不发帧/不收帧即断开释放实例）",
        )),
    }
}

/// 控制面端点（平台传输地址；测试注入临时路径）。
#[derive(Debug, Clone)]
pub struct IpcEndpoint {
    /// Windows：命名管道名（`\\.\pipe\...`）。
    #[cfg(windows)]
    pub pipe_name: String,
    /// Unix：socket 路径。
    #[cfg(unix)]
    pub socket_path: PathBuf,
}

/// 控制面落位路径（§7-M6.2 表；`platform_default` 取系统常量，测试注入）。
#[derive(Debug, Clone)]
pub struct ControlPaths {
    pub endpoint: IpcEndpoint,
    pub token_file: PathBuf,
}

/// Windows 命名管道名常量。
#[cfg(windows)]
pub const PIPE_NAME: &str = r"\\.\pipe\flock-client-control";
/// Unix socket 路径常量。
#[cfg(unix)]
pub const SOCKET_PATH: &str = "/run/flock/client.sock";
/// Unix token 文件路径常量。
#[cfg(unix)]
pub const TOKEN_FILE: &str = "/var/lib/flock/client/control-token";
/// Windows token 文件相对 %ProgramData% 路径。
#[cfg(windows)]
pub const TOKEN_FILE_REL: &str = r"flock\control-token";

impl ControlPaths {
    /// 平台缺省落位（§7-M6.2 表）。
    pub fn platform_default() -> Self {
        #[cfg(windows)]
        {
            let base = std::env::var("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"));
            ControlPaths {
                endpoint: IpcEndpoint {
                    pipe_name: PIPE_NAME.to_string(),
                },
                token_file: base.join(TOKEN_FILE_REL),
            }
        }
        #[cfg(unix)]
        {
            ControlPaths {
                endpoint: IpcEndpoint {
                    socket_path: PathBuf::from(SOCKET_PATH),
                },
                token_file: PathBuf::from(TOKEN_FILE),
            }
        }
    }
}

/// 起 IPC 服务端（accept 循环 + 每连接一任务；返回 JoinHandle 供 daemon 收尾 abort）。
///
/// Unix：bind 前 mkdir -p 父目录（0755）、bind 后 chmod 0660（`control_group` 存在则
/// 尝试 chgrp，失败仅告警——即装即用缺省 root:root）。Windows：DACL 见模块文档。
pub fn spawn_server(
    paths: &ControlPaths,
    group: Option<&str>,
    ctrl: std::sync::Arc<DaemonControl>,
) -> io::Result<tokio::task::JoinHandle<()>> {
    #[cfg(windows)]
    {
        let _ = group; // Windows 侧组语义由管道 DACL 的 IU 承担，token 文件 ACL 不分组。
        crate::ipc_windows::spawn_named_pipe_server(&paths.endpoint.pipe_name, ctrl)
    }
    #[cfg(unix)]
    {
        crate::ipc_unix::spawn_unix_server(&paths.endpoint.socket_path, group, ctrl)
    }
}

/// Unix 私有文件原子落盘（评审项 3：消除「先 `fs::write`（umask 默认权限）再补
/// chmod」的间窗——窗口内机密按默认权限可读）。
///
/// - 首次：`OpenOptions::create_new` + `mode`——文件**出生即目标权限**（open 原子
///   携带 mode，无 umask 参与窗口）；
/// - 已存在（换写）：同目录临时文件（同 mode `create_new`）写毕 `rename` 覆盖。
///   选型注释（vs「先收紧旧文件权限再 truncate 重写」）：rename 在同文件系统内
///   原子替换——既无新内容的默认权限窗口，也无截断窗口（崩溃时磁盘上要么完整
///   旧文件要么完整新文件；truncate 重写崩溃则丢凭据内容），对凭据/token 这类
///   「丢内容即失联、泄内容即失守」的文件取可恢复性优先。
#[cfg(unix)]
pub(crate) fn write_file_private(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let create_new = |p: &Path| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(p)
    };
    match create_new(path) {
        Ok(mut f) => f.write_all(bytes),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // 换写：tempfile（同 mode）→ rename 原子替换（选型见函数文档）。
            // 同目录 ⇒ 同文件系统；名字带进程内序号防并发写者碰撞。
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let tmp = path.with_file_name(format!(
                ".{}.tmp.{}",
                path.file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let mut f = create_new(&tmp)?;
            f.write_all(bytes)?;
            drop(f); // 关闭落盘后再替换（rename 不携未刷新缓冲）。
            std::fs::rename(&tmp, path)
        }
        Err(e) => Err(e),
    }
}

// ============================================================================
// token 生成与落盘
// ============================================================================

/// 生成 32B 随机 token（daemon 每次启动调用）。
pub fn generate_token() -> CtrlToken {
    flock_protocol::rand::random()
}

/// token 文件写盘：hex 文本（64 字符，可人工检视）。
///
/// 权限（§7-M6.2）：Windows 显式 ACL（SYSTEM/管理员全权 + Users 读）；Unix 0640
///（[`write_file_private`]——出生即 0640，无默认权限间窗；评审项 3），
/// `group` 给定则尝试 chgrp（解析失败/无权限仅告警——「尝试」语义）。
pub fn write_token_file(path: &Path, token: &CtrlToken, group: Option<&str>) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    write_file_private(path, hex::encode(token).as_bytes(), 0o640)?;
    #[cfg(windows)]
    std::fs::write(path, hex::encode(token))?;
    #[cfg(unix)]
    {
        if let Some(gname) = group {
            match resolve_gid(gname) {
                Some(gid) => {
                    if let Err(e) = std::os::unix::fs::chown(path, None, Some(gid)) {
                        eprintln!("flock-client: 告警：token 文件 chgrp {gname}({gid}) 失败: {e}");
                    }
                }
                None => eprintln!(
                    "flock-client: 告警：control_group {gname:?} 无法解析为 gid（仅查本地 /etc/group 与数字 gid）——token 保持 root:root"
                ),
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = group;
        if let Err(e) = crate::ipc_windows::set_file_acl_users_read(path) {
            eprintln!("flock-client: 告警：token 文件 ACL 设置失败（继承保留）: {e}");
        }
    }
    Ok(())
}

/// 读 token 文件（hex 文本 → 32B；status 子命令用）。
pub fn load_token_file(path: &Path) -> io::Result<CtrlToken> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| io::Error::other(format!("读 {}: {e}", path.display())))?;
    let bytes = hex::decode(text.trim())
        .map_err(|e| io::Error::other(format!("{} 内容非 hex: {e}", path.display())))?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| io::Error::other(format!("{} 期望 32B token", path.display())))
}

/// Unix：组名 → gid（仅本地 /etc/group 与数字 gid；NSS 目录不在此列，失败=告警不阻断）。
#[cfg(unix)]
pub(crate) fn resolve_gid(group: &str) -> Option<u32> {
    if let Ok(g) = group.parse::<u32>() {
        return Some(g);
    }
    let text = std::fs::read_to_string("/etc/group").ok()?;
    text.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&group) && fields.len() >= 3 {
            return fields[2].parse::<u32>().ok();
        }
        None
    })
}

// ============================================================================
// 客户端侧（托盘轮询 / status 子命令）
// ============================================================================

/// 在已建立连接上发一次请求收一次响应（传输层泛型；duplex mock 单测面）。
pub async fn request_over<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    req: &CtrlReq,
) -> io::Result<CtrlResp> {
    send_frame(io, req).await?;
    recv_frame(io).await
}

/// 单次请求（连接 + 往返，整链受 [`REQUEST_TIMEOUT`] 约束）。
///
/// Windows 管道 busy（服务端实例瞬时耗尽）时短重试；Unix 连接失败直接返回错误
/// （daemon 未运行 ⇒ socket 不存在，语义交调用方）。
pub async fn request_once(endpoint: &IpcEndpoint, req: CtrlReq) -> io::Result<CtrlResp> {
    request_once_timeout(endpoint, req, REQUEST_TIMEOUT).await
}

/// [`request_once`] 的超时注入档（`Peers` 用 [`PEERS_REQUEST_TIMEOUT`]——探测面远超
/// 默认 3s）。
pub async fn request_once_timeout(
    endpoint: &IpcEndpoint,
    req: CtrlReq,
    timeout: Duration,
) -> io::Result<CtrlResp> {
    tokio::time::timeout(timeout, async {
        #[cfg(windows)]
        {
            crate::ipc_windows::client_request(&endpoint.pipe_name, &req).await
        }
        #[cfg(unix)]
        {
            let path = endpoint.socket_path.clone();
            let mut stream = tokio::net::UnixStream::connect(path).await?;
            request_over(&mut stream, &req).await
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "控制请求超时"))?
}

// ============================================================================
// 单元测试（传输层 mock：tokio::io::duplex 回环——契约往返/token 拒绝/Denied 路径）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::duplex;

    fn daemon_control(
        token: CtrlToken,
    ) -> (Arc<DaemonControl>, Arc<std::sync::atomic::AtomicBool>) {
        let shutdown_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fired = shutdown_fired.clone();
        let ctrl = Arc::new(DaemonControl {
            token,
            status: Arc::new(|| CtrlResp::Status {
                state: ConnState::Connected,
                vip: Some("100.64.0.11".into()),
                endpoint: Some("ep.test:27500".into()),
                epoch: 3,
                uptime_secs: 42,
            }),
            shutdown: Arc::new(move || fired.store(true, std::sync::atomic::Ordering::SeqCst)),
            peers: None,
        });
        (ctrl, shutdown_fired)
    }

    /// 契约往返：Status 请求 → Status 快照（字段逐项）。
    #[tokio::test]
    async fn ctrl_roundtrip_status_over_duplex() {
        let token = generate_token();
        let (ctrl, _) = daemon_control(token);
        let (mut client, mut server) = duplex(4096);
        let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });

        let resp = request_over(&mut client, &CtrlReq::Status { token })
            .await
            .expect("往返");
        assert_eq!(
            resp,
            CtrlResp::Status {
                state: ConnState::Connected,
                vip: Some("100.64.0.11".into()),
                endpoint: Some("ep.test:27500".into()),
                epoch: 3,
                uptime_secs: 42,
            }
        );
        served.await.unwrap().unwrap();
    }

    /// token 拒绝：错 token 的 Status ⇒ Denied（不触发快照副作用面之外的行为）。
    #[tokio::test]
    async fn wrong_token_status_is_denied() {
        let (ctrl, _) = daemon_control(generate_token());
        let (mut client, mut server) = duplex(4096);
        let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });

        let resp = request_over(&mut client, &CtrlReq::Status { token: [0x41; 32] })
            .await
            .unwrap();
        assert_eq!(resp, CtrlResp::Denied);
        served.await.unwrap().unwrap();
    }

    /// Shutdown 路径：对 token ⇒ 触发停机钩子 + 回 Ok；错 token ⇒ Denied 且不触发。
    #[tokio::test]
    async fn shutdown_replies_ok_and_fires_hook_only_with_token() {
        let token = generate_token();
        // 错 token：Denied，钩子不触发。
        {
            let (ctrl, fired) = daemon_control(token);
            let (mut client, mut server) = duplex(4096);
            let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
            let resp = request_over(&mut client, &CtrlReq::Shutdown { token: [0x00; 32] })
                .await
                .unwrap();
            assert_eq!(resp, CtrlResp::Denied);
            assert!(
                !fired.load(std::sync::atomic::Ordering::SeqCst),
                "错 token 不得触发停机"
            );
            served.await.unwrap().unwrap();
        }
        // 对 token：Ok + 钩子触发。
        {
            let (ctrl, fired) = daemon_control(token);
            let (mut client, mut server) = duplex(4096);
            let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
            let resp = request_over(&mut client, &CtrlReq::Shutdown { token })
                .await
                .unwrap();
            assert_eq!(resp, CtrlResp::Ok);
            assert!(
                fired.load(std::sync::atomic::Ordering::SeqCst),
                "对 token 必须触发停机"
            );
            served.await.unwrap().unwrap();
        }
    }

    /// 畸形帧（非 postcard）：连接关闭、无响应字节（客户端见 EOF/断管）。
    #[tokio::test]
    async fn malformed_frame_closes_without_response() {
        let (ctrl, _) = daemon_control(generate_token());
        let (mut client, mut server) = duplex(4096);
        let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
        // 合法帧头 + 垃圾载荷（varint 变体序号溢出/截断 ⇒ postcard 解码错误）。
        client.write_all(&4u32.to_le_bytes()).await.unwrap();
        client.write_all(&[0xff, 0xff, 0xff, 0xff]).await.unwrap();
        let mut buf = [0u8; 8];
        match client.read(&mut buf).await {
            Ok(0) | Err(_) => {} // EOF（服务端 drop）或断管——均为「无响应」。
            Ok(n) => panic!("畸形帧不得收到响应，却读到 {n} 字节"),
        }
        served.await.unwrap().expect_err("服务端须报解码错误");
    }

    /// 超长帧头（len > MAX_CTRL_FRAME）拒帧。
    #[tokio::test]
    async fn oversized_frame_rejected() {
        let (ctrl, _) = daemon_control(generate_token());
        let (mut client, mut server) = duplex(4096);
        let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
        client
            .write_all(&((MAX_CTRL_FRAME + 1) as u32).to_le_bytes())
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        match client.read(&mut buf).await {
            Ok(0) | Err(_) => {}
            Ok(n) => panic!("超长帧不得收到响应，却读到 {n} 字节"),
        }
        served.await.unwrap().expect_err("超长帧须报错");
    }

    /// token 文件往返（写 → 权限 → 读回一致）。
    #[tokio::test]
    async fn token_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("control-token");
        let token = generate_token();
        write_token_file(&path, &token, None).expect("写 token 文件");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o640, "Unix token 文件 0640");
        }
        assert_eq!(load_token_file(&path).unwrap(), token);
        // 非法内容拒读（另起文件——Windows 显式 ACL 后原文件对 Users 只读）。
        let bad = dir.path().join("bad-token");
        std::fs::write(&bad, "zz-nothex").unwrap();
        assert!(load_token_file(&bad).is_err());
    }

    /// 评审项 3：token 换写路径——已存在松权限（0666）文件被替换后 0640 + 新 token
    /// 读回一致（tempfile 出生即 0640，rename 原子落位——无默认权限间窗）。
    #[cfg(unix)]
    #[tokio::test]
    async fn token_file_overwrite_replaces_loose_perm_file_with_0640() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control-token");
        std::fs::write(&path, "stale").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let token = generate_token();
        write_token_file(&path, &token, None).expect("换写 token 文件");
        assert_eq!(load_token_file(&path).unwrap(), token, "新 token 在位");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640,
            "换写后 0640"
        );
    }

    /// 常量时间比对：等长不同值 ⇒ false；等值 ⇒ true（行为面，时序面由实现保证）。
    #[test]
    fn token_eq_semantics() {
        let a = [1u8; 32];
        assert!(token_eq(&a, &a));
        let mut b = a;
        b[31] ^= 1;
        assert!(!token_eq(&a, &b));
        assert!(!token_eq(&[0u8; 32], &[1u8; 32]));
    }

    /// 评审项 4：错误分类——瞬态集（WouldBlock/Interrupted/ConnAborted/ConnReset/
    /// 管道首连 NotConnected/EMFILE/ENFILE（unix）/ERROR_PIPE_BUSY 231（windows））
    /// 记日志退避 continue；其余（PermissionDenied/EBADF 等）致命上浮。
    #[test]
    fn accept_error_classification() {
        // —— 瞬态（ErrorKind 面，全平台）——
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::NotConnected,
        ] {
            assert!(
                accept_error_is_transient(&io::Error::from(kind)),
                "{kind:?} 应为瞬态"
            );
        }
        // —— 致命（其余 kind / 原始码）——
        assert!(
            !accept_error_is_transient(&io::Error::from(io::ErrorKind::PermissionDenied)),
            "权限错误致命"
        );
        assert!(
            !accept_error_is_transient(&io::Error::from_raw_os_error(9)),
            "EBADF（监听面损坏）致命"
        );
        // —— 平台原始码面 ——
        #[cfg(unix)]
        {
            // EMFILE=24/ENFILE=23（linux/macos 同值）——fd 耗尽瞬态。
            assert!(accept_error_is_transient(&io::Error::from_raw_os_error(24)));
            assert!(accept_error_is_transient(&io::Error::from_raw_os_error(23)));
            // 其余原始码（如 EACCES=13）致命。
            assert!(!accept_error_is_transient(&io::Error::from_raw_os_error(13)));
        }
        #[cfg(windows)]
        {
            // ERROR_PIPE_BUSY=231（AllPipeInstancesBusy——实例在途）瞬态；
            // ERROR_ACCESS_DENIED=5 致命。
            assert!(accept_error_is_transient(&io::Error::from_raw_os_error(231)));
            assert!(!accept_error_is_transient(&io::Error::from_raw_os_error(5)));
        }
    }

    /// 评审项 4：连接后不发帧 ⇒ serve_conn 整链超时错出（TimedOut）——不占住
    /// 管道实例（paused 时钟下 10s 即时推进）。
    #[tokio::test(start_paused = true)]
    async fn serve_conn_times_out_when_client_never_frames() {
        let (ctrl, _) = daemon_control(generate_token());
        let (mut client, mut server) = duplex(4096);
        let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
        // 客户端连接在位但不发任何字节：服务端 10s 整链超时（paused 时钟自动推进）。
        let res = tokio::time::timeout(Duration::from_secs(15), served)
            .await
            .expect("超时须在 10s 整链档内触发")
            .unwrap();
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::TimedOut);
        drop(client);
    }

    /// M7：Peers 契约往返——对 token ⇒ 增强名册行（含 latency/self）；错 token ⇒
    /// Denied；未装配 peers 处理器 ⇒ PeersUnavailable。
    #[tokio::test]
    async fn ctrl_roundtrip_peers_over_duplex() {
        use crate::peers::PeerRow;
        use flock_protocol::roster::{PeerInfo, PeerKind};
        let token = generate_token();
        let rows = vec![
            PeerRow {
                info: PeerInfo {
                    vip: [100, 64, 0, 1],
                    hostname: "srv".into(),
                    owner: "1".into(),
                    kind: PeerKind::Server,
                    online: true,
                    last_seen_unix: 5,
                    tx_bps: 10,
                    rx_bps: 20,
                },
                latency_ms: Some(3),
                self_flag: false,
            },
            PeerRow {
                info: PeerInfo {
                    vip: [100, 64, 0, 11],
                    hostname: "me".into(),
                    owner: "alice".into(),
                    kind: PeerKind::Device,
                    online: true,
                    last_seen_unix: 5,
                    tx_bps: 1,
                    rx_bps: 2,
                },
                latency_ms: None,
                self_flag: true,
            },
        ];
        let expected = rows.clone();
        // ① 对 token ⇒ Peers{rows}（逐字段往返）。
        {
            let ctrl = Arc::new(DaemonControl {
                token,
                status: Arc::new(|| CtrlResp::Ok),
                shutdown: Arc::new(|| {}),
                peers: Some(Arc::new(move || {
                    Box::pin(std::future::ready(CtrlResp::Peers {
                        rows: expected.clone(),
                    }))
                })),
            });
            let (mut client, mut server) = duplex(MAX_CTRL_FRAME);
            let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
            let resp = request_over(&mut client, &CtrlReq::Peers { token })
                .await
                .unwrap();
            match resp {
                CtrlResp::Peers { rows } => {
                    assert_eq!(rows.len(), 2);
                    assert_eq!(rows[0].latency_ms, Some(3));
                    assert!(rows[1].self_flag);
                    assert_eq!(rows[1].info.hostname, "me");
                }
                other => panic!("Peers 变体，得 {other:?}"),
            }
            served.await.unwrap().unwrap();
        }
        // ② 错 token ⇒ Denied。
        {
            let (ctrl, _) = daemon_control(token);
            let (mut client, mut server) = duplex(4096);
            let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
            let resp = request_over(&mut client, &CtrlReq::Peers { token: [7; 32] })
                .await
                .unwrap();
            assert_eq!(resp, CtrlResp::Denied);
            served.await.unwrap().unwrap();
        }
        // ③ 未装配 peers 处理器 ⇒ PeersUnavailable（reason 非空）。
        {
            let (ctrl, _) = daemon_control(token);
            let (mut client, mut server) = duplex(4096);
            let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
            let resp = request_over(&mut client, &CtrlReq::Peers { token })
                .await
                .unwrap();
            match resp {
                CtrlResp::PeersUnavailable { reason } => assert!(!reason.is_empty()),
                other => panic!("PeersUnavailable，得 {other:?}"),
            }
            served.await.unwrap().unwrap();
        }
    }
}
