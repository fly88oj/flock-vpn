//! daemon 装配（docs/design.md §7-M6.1/M6.2）：`flock-client service` 的进程体。
//!
//! 复用 [`connector::supervise`] 全部逻辑（tun/路由/拨号/退避/数据面不动），叠加：
//! - **IPC 服务端**：`ControlPaths` 落位 + token 生成/写盘 + [`crate::ipc::spawn_server`]；
//! - **状态快照源**：`ConnEvent`（连接状态/端点）+ `epoch_watch`（纪元）→
//!   [`ServiceStatus`]（IPC `Status` 的数据源）；
//! - **优雅停服**：IPC `Shutdown` / SCM Stop / SIGTERM 任一触发 → 断会话（supervise
//!   任务 abort ⇒ 隧道与控制流 Drop、TCP 关闭，对端见会话终止）→ 停数据面 → 拆
//!   tun → 进程退出；服务管理器**不复活**（systemd `Restart=on-failure` 只对失败
//!   退出动作、launchd 无 KeepAlive、Windows 恢复策略只挂失败码，§7-M6.1）。
//!
//! 无头确认：本模块（及 `service` 子命令路径）不依赖任何 GUI crate；托盘在 `tray`
//! 子命令（第二阶段，feature 门控）。
//!
//! Windows SCM 集成：`service_dispatcher` 分派 + SCM 状态机（StartPending→Running→
//! Stopped）+ 事件日志上报（事件日志**源**注册在 install 侧 HKLM，未注册时事件仍落
//! Application 日志、消息以插入串呈现）。非 SCM 上下文启动（终端/容器调试）回落前台。

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::Notify;

use crate::config::ClientConfig;
use crate::connector::{self, ConnEvent};
use crate::ipc::{spawn_server, write_token_file, ControlPaths, CtrlResp, DaemonControl};
use crate::tun::{TunIo, TunSpec};

/// 服务名（Windows SCM / systemd unit / launchd label 统一标识）。
pub const SERVICE_NAME: &str = "flock-client";

/// 停机触发后的响应让步窗（评审项 8）：停机与在途 serve_conn 写响应帧之间存在
/// 竞态——主流程返回即拆 runtime，客户端可能见断管而非 `Ok`/最后快照。
const SHUTDOWN_RESP_GRACE: std::time::Duration = std::time::Duration::from_millis(100);

// ============================================================================
// 状态快照源（IPC Status 的数据面）
// ============================================================================

/// supervise 投影（ConnEvent 聚合）。
#[derive(Debug)]
struct StatusInner {
    state: crate::ipc::ConnState,
    endpoint: Option<String>,
}

/// daemon 状态快照源：`Arc` 共享给 IPC 快照闭包与 supervise 事件闭包。
pub struct ServiceStatus {
    start: Instant,
    vip: Option<String>,
    inner: Mutex<StatusInner>,
    /// 当前会话纪元（`supervise_with_epoch` 的 watch；snapshot 只 borrow 不消费标记）。
    epoch_rx: Mutex<tokio::sync::watch::Receiver<u64>>,
}

impl ServiceStatus {
    fn new(vip: Option<std::net::Ipv4Addr>, epoch_rx: tokio::sync::watch::Receiver<u64>) -> Self {
        ServiceStatus {
            start: Instant::now(),
            vip: vip.map(|v| v.to_string()),
            inner: Mutex::new(StatusInner {
                state: crate::ipc::ConnState::Disconnected,
                endpoint: None,
            }),
            epoch_rx: Mutex::new(epoch_rx),
        }
    }

    /// IPC `Status` 快照（字段语义见 §7-M6.2 契约）。
    pub fn snapshot(&self) -> CtrlResp {
        let inner = self.inner.lock().expect("status poisoned");
        let epoch = *self.epoch_rx.lock().expect("epoch poisoned").borrow();
        CtrlResp::Status {
            state: inner.state,
            vip: self.vip.clone(),
            endpoint: inner.endpoint.clone(),
            epoch,
            uptime_secs: self.start.elapsed().as_secs(),
        }
    }

    /// `ConnEvent` → 状态投影（supervise 事件闭调；Dialing=Connecting、
    /// Connected=Connected、SessionEnded=Disconnected，端点保留最近值）。
    fn project(&self, ev: &ConnEvent) {
        let mut inner = self.inner.lock().expect("status poisoned");
        match ev {
            ConnEvent::Dialing { endpoint, .. } => {
                inner.state = crate::ipc::ConnState::Connecting;
                inner.endpoint = Some(endpoint.clone());
            }
            ConnEvent::Connected { endpoint, .. } => {
                inner.state = crate::ipc::ConnState::Connected;
                inner.endpoint = Some(endpoint.clone());
            }
            ConnEvent::SessionEnded { endpoint, .. } => {
                inner.state = crate::ipc::ConnState::Disconnected;
                inner.endpoint = Some(endpoint.clone());
            }
        }
    }
}

// ============================================================================
// daemon 主流程
// ============================================================================

/// 前台 daemon（`service` 子命令直跑 / Unix 服务管理器 ExecStart）：
/// SIGTERM/SIGINT ⇒ 优雅停服。
pub async fn run_service(cfg: ClientConfig, paths: ControlPaths) -> Result<(), String> {
    let stop = Arc::new(Notify::new());
    #[cfg(unix)]
    {
        let sig_stop = stop.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).expect("SIGTERM 注册");
            let mut int = signal(SignalKind::interrupt()).expect("SIGINT 注册");
            tokio::select! {
                _ = term.recv() => eprintln!("flock-client: SIGTERM → 优雅停服"),
                _ = int.recv() => eprintln!("flock-client: SIGINT → 优雅停服"),
            }
            sig_stop.notify_one();
        });
    }
    run_service_inner(cfg, paths, stop).await
}

/// daemon 主体（停机信号注入位：Unix 信号 / Windows SCM Stop / IPC Shutdown 共用）。
async fn run_service_inner(
    cfg: ClientConfig,
    paths: ControlPaths,
    stop: Arc<Notify>,
) -> Result<(), String> {
    let started = Instant::now();
    log_service_event(
        EventLevel::Info,
        &format!("service 启动（state_dir={}）", cfg.state_dir.display()),
    );

    // —— 状态三件套 + VIP + 端点覆盖（与前台 run 同序）——
    let state = connector::ClientState::load(&cfg.state_dir, true).map_err(|e| e.to_string())?;
    let vip = state
        .resolve_vip(&cfg.state_dir, cfg.vip)
        .map_err(|e| e.to_string())?;
    let state = if cfg.endpoints.is_empty() {
        state
    } else {
        connector::override_endpoints(state, &cfg.endpoints)?
    };

    // —— tun + 路由（持久设备，跨会话复用；失败=致命——无数据面即无服务价值）——
    let spec = TunSpec {
        name: cfg.tun_name.clone(),
        mtu: cfg.mtu,
    };
    let tun = Arc::new(TunIo::open(&spec).map_err(|e| format!("tun: {e}"))?);
    eprintln!(
        "flock-client: service tun {} mtu={} vip={vip}",
        tun.name(),
        spec.mtu
    );
    crate::route::apply(&crate::route::RoutePlan::new(&spec.name, vip))
        .await
        .map_err(|e| {
            tun.shutdown();
            format!("route: {e}")
        })?;
    eprintln!(
        "flock-client: service route {}/{} → {}",
        crate::route::VIP_POOL.0,
        crate::route::VIP_POOL.1,
        spec.name
    );

    daemon_loop(cfg, state, tun, Some(vip), paths, stop, started).await
}

/// daemon 循环（快照源 + supervise + 控制流登录保持 + IPC + 停机等待 + 拆除）。
///
/// 独立于 tun/route 装配（`run_service_inner` 先行完成）——集成测试注入 mock tun
/// 直达此层（宿主无真设备）。
async fn daemon_loop(
    cfg: ClientConfig,
    state: connector::ClientState,
    tun: Arc<TunIo>,
    vip: Option<std::net::Ipv4Addr>,
    paths: ControlPaths,
    stop: Arc<Notify>,
    started: Instant,
) -> Result<(), String> {
    // —— 快照源 + supervise 任务（epoch 随连接建立发初值、rekey 发增量）——
    let (epoch_tx, epoch_rx) = tokio::sync::watch::channel(0u64);
    let status = Arc::new(ServiceStatus::new(vip, epoch_rx));
    let ev_status = status.clone();
    let tun_sup = tun.clone();

    // —— M7 控制流共享槽（supervise 装流；登录保持/名册拉取业务消费）——
    let plane = crate::ctrl::ControlPlane::new();
    let plane_for_peers = plane.clone();

    // —— M7 名册缓存 + 延迟探测器（raw 权限缺失 ⇒ 降级无延迟档，名册照常）——
    let roster_cache = Arc::new(crate::ctrl::RosterCache::new());
    let pinger: Option<Arc<dyn crate::ping::Pinger>> = match crate::ping::RawIcmpPinger::new() {
        Ok(p) => Some(Arc::new(p)),
        Err(e) => {
            eprintln!("flock-client: 告警：raw ICMP 探测器不可用（延迟列将显示 —）: {e}");
            None
        }
    };

    // —— M7 登录保持任务（[auth] 配置在位才装配；票据只存内存，§7-M7.7）——
    let auth_shared = Arc::new(crate::ctrl::AuthShared::new());
    let mut auth_task: Option<tokio::task::JoinHandle<()>> = None;
    if let Some(auth) = &cfg.auth {
        let ctx = crate::ctrl::AuthCtx {
            username: auth.username.clone(),
            credentials_path: crate::ctrl::credentials_path(
                &cfg.state_dir,
                auth.credentials_file.as_deref(),
            ),
            hostname: crate::ctrl::resolve_hostname(cfg.hostname.as_deref()),
            device: flock_protocol::session::DeviceStaticKeys::from_bytes(&state.device.to_bytes()),
            cluster_id: state.directory.cluster_id,
            directory: state.directory.clone(),
            sr_key: crate::ctrl::load_or_create_sr_key(&cfg.state_dir)
                .map_err(|e| format!("SR-SIG1 密钥: {e}"))?,
        };
        let stop_auth = stop.clone();
        auth_task = Some(tokio::spawn(crate::ctrl::run_auth_keepalive(
            plane.clone(),
            ctx,
            auth_shared.clone(),
            stop_auth,
        )));
    }

    // supervise 永不正常返回；任务 panic ⇒ 死亡信号通道关闭（recv 返回 None）⇒ 主
    // 流程按失败停机（服务管理器失败语义接管——Restart/恢复策略只在此路径生效）。
    let (sup_alive_tx, mut sup_alive_rx) = tokio::sync::mpsc::channel::<()>(1);
    let supervise_task = tokio::spawn(async move {
        let _alive = sup_alive_tx; // 持有到任务终止（Drop ⇒ 主流程 recv 得 None）
        connector::supervise_with_control(
            &state,
            tun_sup.as_ref(),
            flock_protocol::session::TunnelConfig::default(),
            connector::Backoff::default(),
            move |ev: ConnEvent| {
                ev_status.project(&ev);
                match &ev {
                    ConnEvent::Dialing { endpoint, attempt } => {
                        eprintln!("flock-client: 拨号 {endpoint}（attempt {attempt}）")
                    }
                    ConnEvent::Connected { endpoint, server } => eprintln!(
                        "flock-client: 已连接 {endpoint}（server={}）",
                        hex::encode(server.0)
                    ),
                    ConnEvent::SessionEnded { endpoint, reason } => eprintln!(
                        "flock-client: 会话结束 {endpoint} reason={} → 进入重连",
                        reason
                            .map(|r| r.to_string())
                            .unwrap_or_else(|| "none(io/fin)".into())
                    ),
                }
            },
            epoch_tx,
            plane,
        )
        .await;
    });

    // —— IPC 服务端（token 生成/写盘 → DaemonControl → accept 循环；失败回收 tun）——
    let token = crate::ipc::generate_token();
    if let Err(e) = write_token_file(&paths.token_file, &token, cfg.control_group.as_deref()) {
        supervise_task.abort();
        tun.shutdown();
        return Err(format!("token 文件: {e}"));
    }
    let ctrl = Arc::new(DaemonControl {
        token,
        status: {
            let status = status.clone();
            Arc::new(move || status.snapshot())
        },
        shutdown: {
            let stop = stop.clone();
            Arc::new(move || stop.notify_one())
        },
        // M7 名册装配（§7-M7.7）：≤5s 缓存 → 否则 PeerListPull（票据来自登录保持）；
        // 对 online 非自身行并发 ping 探测（raw 权限缺失 ⇒ 降级无延迟档）。
        peers: {
            let plane = plane_for_peers.clone();
            let auth_shared = auth_shared.clone();
            let roster = roster_cache.clone();
            let pinger = pinger.clone();
            let self_vip = vip;
            Some(Arc::new(move || {
                let plane = plane.clone();
                let auth_shared = auth_shared.clone();
                let roster = roster.clone();
                let pinger = pinger.clone();
                Box::pin(async move {
                    // 阶段检查前置：未配置/未登录/隧道断的指引文案（不发起拉取）。
                    // phase()==None = 登录保持任务未装配（无 [auth]）⇒ login 引导
                    // 文案（评审项 5——此前该形态落进「尚无登录票据（稍候重试）」）。
                    if let Some(r) = crate::ctrl::AuthPhase::peers_block_reason(auth_shared.phase())
                    {
                        return CtrlResp::PeersUnavailable { reason: r };
                    }
                    // 名册：缓存新鲜（≤5s）直接用；否则持当前票据拉取。
                    let peers = match roster.fresh() {
                        Some(p) => p,
                        None => {
                            let Some(ticket) = auth_shared.ticket() else {
                                return CtrlResp::PeersUnavailable {
                                    reason: "尚无登录票据（登录保持任务启动中——稍候重试）".into(),
                                };
                            };
                            match crate::ctrl::pull_roster(&plane, &ticket).await {
                                Ok(p) => {
                                    roster.store(p.clone());
                                    p
                                }
                                Err(e) => {
                                    return CtrlResp::PeersUnavailable {
                                        reason: format!("名册拉取失败: {e}"),
                                    }
                                }
                            }
                        }
                    };
                    let rows =
                        crate::peers::assemble_rows(peers, self_vip, pinger.as_deref()).await;
                    CtrlResp::Peers { rows }
                })
            }))
        },
    });
    let mut ipc_task = match spawn_server(&paths, cfg.control_group.as_deref(), ctrl) {
        Ok(t) => t,
        Err(e) => {
            supervise_task.abort();
            tun.shutdown();
            return Err(format!("控制面监听失败: {e}"));
        }
    };

    // —— 停机等待：IPC Shutdown / SCM Stop / 信号 任一触发；supervise/IPC 死亡同停 ——
    let outcome = tokio::select! {
        _ = stop.notified() => Ok(()),
        // supervise 任务终止（仅可能 panic）⇒ 存活通道关闭 ⇒ 按失败停服。
        sup_dead = sup_alive_rx.recv() => Err(format!(
            "守护循环异常退出（存活信号: {sup_dead:?}）"
        )),
        // IPC accept 循环致命退出（评审项 4：瞬态已在其内退避 continue，仅致命
        // 上浮返回）⇒ 控制面失能——按失败停服，主流程可见（非静默失联）。
        ipc_dead = &mut ipc_task => Err(format!(
            "控制 IPC 循环异常退出（致命 accept/创建错误，详见日志）: {ipc_dead:?}"
        )),
    };

    // —— Shutdown 响应让步（评审项 8，选最小实现）：停机触发后固定 100ms 定时隙
    // 让在途 serve_conn（每连接独立任务——abort IPC accept 循环不触及它们）把
    // Shutdown `Ok`/最后快照帧写完，再进拆除/退 runtime。vs「在途 serve_conn 注册
    // 表清点」：无需连接记账面，一条 sleep 覆盖全部触发路径（IPC/SCM/信号）。
    tokio::time::sleep(SHUTDOWN_RESP_GRACE).await;

    // —— 优雅拆除：IPC → 登录保持 → supervise（断会话/停数据面：隧道随任务 Drop）→ tun ——
    ipc_task.abort();
    #[cfg(unix)]
    let _ = std::fs::remove_file(&paths.endpoint.socket_path); // 停机即时收；残留兜底见 ipc_unix
    if let Some(t) = &auth_task {
        t.abort();
    }
    supervise_task.abort();
    tun.shutdown();
    log_service_event(
        EventLevel::Info,
        &format!(
            "service 停止（运行 {:?}，登录态 {:?}）",
            started.elapsed(),
            auth_shared
                .phase()
                .unwrap_or(crate::ctrl::AuthPhase::Unconfigured)
        ),
    );
    outcome
}

// ============================================================================
// Windows SCM 集成
// ============================================================================

#[cfg(windows)]
mod scm {
    use super::*;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::ServiceControlHandlerResult;
    use windows_service::{service_control_handler, service_dispatcher};

    /// 非 SCM 启动的分派失败码（StartServiceCtrlDispatcherW：进程非由 SCM 启动）。
    const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
    /// Stop 状态机 wait_hint（SCM 期待的最长停服时长）。
    const STOP_HINT: Duration = Duration::from_secs(30);

    /// SCM 上下文（dispatcher 的 extern 回调取不到闭包 ⇒ OnceLock 传递）。
    struct ServiceCtx {
        cfg_path: PathBuf,
        stop: Arc<Notify>,
    }
    static SERVICE_CTX: std::sync::OnceLock<ServiceCtx> = std::sync::OnceLock::new();

    windows_service::define_windows_service!(ffi_service_main, windows_service_main);

    /// `service` 子命令入口（Windows）：SCM 分派；终端/容器直跑回落前台 daemon。
    pub fn service_entry(cfg_path: PathBuf) -> Result<(), String> {
        let ctx = ServiceCtx {
            cfg_path,
            stop: Arc::new(Notify::new()),
        };
        if SERVICE_CTX.set(ctx).is_err() {
            return Err("service 上下文重复初始化".into());
        }
        match service_dispatcher::start(crate::service::SERVICE_NAME, ffi_service_main) {
            Ok(()) => Ok(()),
            // 非 SCM 上下文（终端/容器调试）：回落前台 daemon（与 Unix `service` 同义路径）。
            Err(windows_service::Error::Winapi(e))
                if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) =>
            {
                eprintln!("flock-client: 非 SCM 上下文，前台运行 daemon（调试形态）");
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let Some(ctx) = SERVICE_CTX.get() else {
                    return Err("service 上下文缺失".into());
                };
                let cfg = ClientConfig::load(&ctx.cfg_path)?;
                let paths = ControlPaths::platform_default();
                rt.block_on(run_service_inner(cfg, paths, ctx.stop.clone()))
            }
            Err(e) => Err(format!("SCM 分派失败: {e}")),
        }
    }

    fn windows_service_main(_args: Vec<OsString>) {
        let Some(ctx) = SERVICE_CTX.get() else {
            log_service_event(EventLevel::Error, "service 上下文缺失（内部错误）");
            return;
        };
        // SCM handler 注册**先行**（评审项 6）：持有状态句柄后，config 载入失败等
        // 后续路径才能把 Stopped(+非零退出码) 落进状态机；注册本身失败 ⇒ 无句柄
        // 可 set——事件日志 + 非零进程退出码兜底（SCM 按进程退出记录）。
        let stop = ctx.stop.clone();
        let registered = service_control_handler::register(
            crate::service::SERVICE_NAME,
            move |event| match event {
                ServiceControl::Stop => {
                    log_service_event(EventLevel::Info, "SCM Stop → 优雅停服");
                    stop.notify_one();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        );
        let handler = match registered {
            Ok(h) => h,
            Err(e) => {
                log_service_event(EventLevel::Error, &format!("SCM handler 注册失败: {e}"));
                std::process::exit(2);
            }
        };
        /// 失败路径的非零退出码（SCM/恢复策略据此识别失败退出；优雅停服 = 0）。
        const SVC_EXIT_FAILURE: u32 = 1;
        let set = |state: ServiceState, exit_code: u32, accept_stop: bool, wait_hint: Duration| {
            let _ = handler.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: if accept_stop {
                    ServiceControlAccept::STOP
                } else {
                    ServiceControlAccept::empty()
                },
                exit_code: ServiceExitCode::Win32(exit_code),
                checkpoint: 0,
                wait_hint,
                process_id: None,
            });
        };
        set(ServiceState::StartPending, 0, false, STOP_HINT);
        let cfg = match ClientConfig::load(&ctx.cfg_path) {
            Ok(c) => c,
            Err(e) => {
                log_service_event(EventLevel::Error, &format!("config 载入失败: {e}"));
                set(
                    ServiceState::Stopped,
                    SVC_EXIT_FAILURE,
                    false,
                    Duration::ZERO,
                );
                return;
            }
        };
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                log_service_event(EventLevel::Error, &format!("runtime 创建失败: {e}"));
                set(
                    ServiceState::Stopped,
                    SVC_EXIT_FAILURE,
                    false,
                    Duration::ZERO,
                );
                return;
            }
        };
        set(ServiceState::Running, 0, true, Duration::ZERO);
        let paths = ControlPaths::platform_default();
        // 评审项 6：run_service_inner 包 catch_unwind——panic 也落 Stopped(+非零) +
        // 事件日志（AssertUnwindSafe：panic 后装配态不复用，进程即退——无 unwind
        // 安全债）。子任务（supervise 等）panic 由 daemon_loop 存活通道另行接管。
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(run_service_inner(cfg, paths, ctx.stop.clone()))
        }));
        let res = match res {
            Ok(r) => r,
            Err(panic) => {
                let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<非字符串 panic 载荷>".to_string()
                };
                log_service_event(EventLevel::Error, &format!("service panic: {msg}"));
                Err(format!("service panic: {msg}"))
            }
        };
        if let Err(e) = &res {
            log_service_event(EventLevel::Error, &format!("service 异常退出: {e}"));
        }
        let exit = if res.is_ok() { 0 } else { SVC_EXIT_FAILURE };
        set(ServiceState::Stopped, exit, false, Duration::ZERO);
    }
}

#[cfg(windows)]
pub use scm::service_entry;

// ============================================================================
// 事件日志（Windows 事件日志源；Unix 侧 eprintln → journald）
// ============================================================================

/// 事件级别。
#[derive(Debug, Clone, Copy)]
pub enum EventLevel {
    Info,
    Error,
}

/// 服务生命周期事件上报：Windows 走事件日志源 [`SERVICE_NAME`]（install 侧注册；
/// 未注册时事件仍落 Application 日志、消息以插入串呈现），同时 eprintln 供前台
/// 形态直读；Unix 落 stderr（systemd 收进 journal）。
pub fn log_service_event(level: EventLevel, msg: &str) {
    match level {
        EventLevel::Info => eprintln!("flock-client: {msg}"),
        EventLevel::Error => eprintln!("flock-client: 错误：{msg}"),
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::EventLog::{
            DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
            EVENTLOG_INFORMATION_TYPE,
        };
        let mut source: Vec<u16> = SERVICE_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY：两串均 NUL 结尾；RegisterEventSourceW 失败返回 null ⇒ 跳过；
        // ReportEventW 拷贝语义，上报后 Deregister 释放句柄。
        unsafe {
            let h: HANDLE = RegisterEventSourceW(std::ptr::null(), source.as_mut_ptr());
            if !h.is_null() {
                let ty = match level {
                    EventLevel::Info => EVENTLOG_INFORMATION_TYPE,
                    EventLevel::Error => EVENTLOG_ERROR_TYPE,
                };
                let strings: [*const u16; 1] = [wide.as_ptr()];
                ReportEventW(
                    h,
                    ty,
                    0,
                    1, // 事件 ID（无消息 DLL 时占位）
                    std::ptr::null_mut(),
                    1,
                    0,
                    strings.as_ptr(),
                    std::ptr::null(),
                );
                DeregisterEventSource(h);
            }
        }
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{request_once, ConnState, CtrlReq, IpcEndpoint};
    use crate::tun::{MockTunDevice, TunSpec};

    /// 快照投影：初值 Disconnected → Dialing=Connecting → Connected（端点）→
    /// Ended=Disconnected（端点保留）；rekey 纪元即时反映。
    #[tokio::test]
    async fn status_projection_over_lifecycle() {
        let (tx, epoch_rx) = tokio::sync::watch::channel(0u64);
        let st = ServiceStatus::new(Some("100.64.0.7".parse().unwrap()), epoch_rx);

        // 初值：Disconnected、无端点、epoch 0、vip/uptime 齐备。
        match st.snapshot() {
            CtrlResp::Status {
                state,
                vip,
                endpoint,
                epoch,
                uptime_secs,
            } => {
                assert_eq!(state, ConnState::Disconnected);
                assert_eq!(vip.as_deref(), Some("100.64.0.7"));
                assert_eq!(endpoint, None);
                assert_eq!(epoch, 0);
                assert!(uptime_secs < 60);
            }
            other => panic!("Status 变体，得 {other:?}"),
        }

        st.project(&ConnEvent::Dialing {
            endpoint: "a:1".into(),
            attempt: 1,
        });
        match st.snapshot() {
            CtrlResp::Status {
                state, endpoint, ..
            } => {
                assert_eq!(state, ConnState::Connecting);
                assert_eq!(endpoint.as_deref(), Some("a:1"));
            }
            other => panic!("{other:?}"),
        }
        st.project(&ConnEvent::Connected {
            endpoint: "a:1".into(),
            server: flock_protocol::session::ServerId([9; 16]),
        });
        match st.snapshot() {
            CtrlResp::Status {
                state, endpoint, ..
            } => {
                assert_eq!(state, ConnState::Connected);
                assert_eq!(endpoint.as_deref(), Some("a:1"));
            }
            other => panic!("{other:?}"),
        }
        // 纪元推进（rekey）即时反映。
        tx.send(4).unwrap();
        match st.snapshot() {
            CtrlResp::Status { epoch, .. } => assert_eq!(epoch, 4),
            other => panic!("{other:?}"),
        }
        st.project(&ConnEvent::SessionEnded {
            endpoint: "a:1".into(),
            reason: None,
        });
        match st.snapshot() {
            CtrlResp::Status {
                state,
                endpoint,
                epoch,
                ..
            } => {
                assert_eq!(state, ConnState::Disconnected);
                assert_eq!(endpoint.as_deref(), Some("a:1"), "端点保留（最近一次）");
                assert_eq!(epoch, 4, "纪元保留（最近会话值）");
            }
            other => panic!("{other:?}"),
        }
    }

    /// daemon_loop 端到端（真 IPC 传输 + mock tun + 空端点目录的 supervise 空转）：
    /// Status 可查（Disconnected + vip + uptime）→ Shutdown（对 token）⇒ 回 Ok、
    /// 主流程返回 Ok、mock tun 进入关停位；错 token Shutdown ⇒ Denied 不停服。
    #[tokio::test]
    async fn daemon_loop_shutdown_via_ipc() {
        use crate::tun::TunDevice as _;

        let dir = tempfile::tempdir().unwrap();
        // 状态目录仅有设备密钥（无 directory.bin）：daemon_loop 不做 load（装配已在
        // run_service_inner），直接给空目录 ClientState ⇒ supervise「目录无端点 5s
        // 后重查」空转——聚焦 IPC→拆除链路，不依赖网络/对端。
        let cfg = ClientConfig {
            state_dir: dir.path().join("state"),
            vip: Some("100.64.0.5".parse().unwrap()),
            tun_name: "flocktest0".into(),
            mtu: 1280,
            endpoints: vec![],
            control_group: None,
            hostname: None,
            auth: None,
        };
        let state = connector::ClientState {
            device: flock_protocol::session::DeviceStaticKeys::generate(),
            pins: flock_protocol::trust::PinStore::new(),
            directory: empty_directory(),
        };

        let mock = Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = Arc::new(TunIo::from_arc(mock.clone()));

        // 注入式端点路径（真传输，临时落位）。
        #[cfg(windows)]
        let endpoint = {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            IpcEndpoint {
                pipe_name: format!(
                    r"\\.\pipe\flock-client-svc-test-{}-{}",
                    std::process::id(),
                    SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                ),
            }
        };
        #[cfg(unix)]
        let endpoint = IpcEndpoint {
            socket_path: dir.path().join("svc.sock"),
        };
        let token_file = dir.path().join("control-token");
        let paths = ControlPaths {
            endpoint: endpoint.clone(),
            token_file: token_file.clone(),
        };

        let stop = Arc::new(Notify::new());
        let daemon = tokio::spawn(async move {
            daemon_loop(
                cfg,
                state,
                tun,
                Some("100.64.0.5".parse().unwrap()),
                paths,
                stop,
                Instant::now(),
            )
            .await
        });

        // 就绪探针：token 文件落盘（IPC spawn 紧随其后）。
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !token_file.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "10s 内 token 未落盘（daemon 未就绪）"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let token = crate::ipc::load_token_file(&token_file).unwrap();

        // Status：Disconnected + vip（空目录 ⇒ supervise 未拨号）。
        let resp = request_once(&endpoint, CtrlReq::Status { token })
            .await
            .unwrap();
        match resp {
            CtrlResp::Status {
                state,
                vip,
                endpoint: ep,
                epoch,
                uptime_secs,
            } => {
                assert_eq!(state, ConnState::Disconnected);
                assert_eq!(vip.as_deref(), Some("100.64.0.5"));
                assert_eq!(ep, None, "空目录 ⇒ 未拨号");
                assert_eq!(epoch, 0);
                assert!(uptime_secs < 60);
            }
            other => panic!("Status 变体，得 {other:?}"),
        }

        // 错 token Shutdown ⇒ Denied，daemon 不退出。
        let resp = request_once(&endpoint, CtrlReq::Shutdown { token: [0x33; 32] })
            .await
            .unwrap();
        assert_eq!(resp, crate::ipc::CtrlResp::Denied);

        // 对 token Shutdown ⇒ Ok + 主流程返回 Ok + tun 关停。
        let resp = request_once(&endpoint, CtrlReq::Shutdown { token })
            .await
            .unwrap();
        assert_eq!(resp, crate::ipc::CtrlResp::Ok);
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), daemon)
            .await
            .unwrap();
        assert!(out.is_ok(), "优雅停服返回 Ok，得 {out:?}");
        let mut buf = [0u8; 4];
        assert!(
            mock.read(&mut buf).is_err(),
            "tun 已 close（MockTunDevice read ⇒ NotConnected）"
        );
    }

    /// 空根签目录（无端点 ⇒ supervise 空转；根签不校验——supervise 只取端点列表）。
    fn empty_directory() -> flock_protocol::trust::ClusterDirectory {
        use flock_protocol::session::ClusterId;
        flock_protocol::trust::ClusterDirectory {
            cluster_id: ClusterId([7; 16]),
            dir_version: 0,
            servers: vec![],
            root_sig: flock_protocol::ed25519_dalek::Signature::from_bytes(&[0; 64]),
        }
    }
}
