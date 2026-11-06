//! 托盘进程核心（docs/design.md §7-M6 第二阶段：`flock-client tray` 用户会话进程）。
//!
//! 职责切分（与 §7-M6.1 双进程模型一致：托盘不接触密钥/tun/数据面，仅经控制 IPC
//! 查询状态/触发退出）：
//! - **本模块（平台无关核心，无 GUI 依赖）**：菜单文案投影（[`menu_texts`]）、token
//!   源（[`TokenSource`]——Denied 后失效重载，daemon 重启换 token 的恢复路径）、
//!   2s 轮询（[`poll_once`]——daemon 未运行/IPC 失败 ⇒「服务未运行」并继续重试）、
//!   退出动作（[`request_exit`]——对 token `Shutdown` ⇒ daemon 优雅停服 + 托盘退出；
//!   daemon 不在 ⇒ 仅退托盘；`Denied` ⇒ 不退出并提示）、程序化图标（[`icon`]）、
//!   GUI 会话判定（[`gui_session_present`]）；
//! - **平台后端**（`backend_native`：Windows/macOS tray-icon；`backend_ksni`：Linux
//!   ksni over DBus SNI）：图标/菜单落位与事件泵，仅消费本模块的纯逻辑。
//!
//! 单元测试全在核心层（无 GUI 宿主可跑）：投影全分支/token 往返/轮询恢复/退出动作
//! 在 IPC mock（真传输：临时命名管道或 Unix socket）上的请求顺序。

#[cfg(target_os = "linux")]
mod backend_ksni;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod backend_native;
pub mod icon;

use std::path::PathBuf;
use std::time::Duration;

use crate::ipc::{self, ConnState, ControlPaths, CtrlReq, CtrlResp, CtrlToken};

/// 菜单刷新/状态轮询周期（2s——需求措辞「2s 轮询 Status 刷新文本」）。
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

// ============================================================================
// 菜单文案投影（Status 快照 → 三行文案：状态/VIP/tooltip）
// ============================================================================

/// `CtrlResp::Status` 的菜单投影（epoch/uptime 不进菜单——三项保持干净）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub state: ConnState,
    /// 本端 VIP（daemon 启动即解析 ⇒ 通常 Some；None 为文案容错位 ⇒ 显示「—」）。
    pub vip: Option<String>,
    /// 当前/最近拨号端点（已连接/连接中随行显示；未连接不带）。
    pub endpoint: Option<String>,
}

impl StatusSnapshot {
    /// 从响应取快照；`Ok`/`Denied`（及未来非 Status 变体）⇒ None（调用方按
    /// 「服务未运行」投影——v1 契约下 Status 请求只会回 Status/Denied）。
    pub fn of(resp: &CtrlResp) -> Option<Self> {
        match resp {
            CtrlResp::Status {
                state,
                vip,
                endpoint,
                ..
            } => Some(StatusSnapshot {
                state: *state,
                vip: vip.clone(),
                endpoint: endpoint.clone(),
            }),
            _ => None,
        }
    }
}

/// 菜单/tooltip 三行文案（「连接状态」「VPN IP」为动态只读项；tooltip 同步状态摘要）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuTexts {
    pub status: String,
    pub vip: String,
    pub tooltip: String,
}

/// Status 快照 → 菜单文案（纯函数，全分支单测）。
///
/// - 快照缺失（daemon 未运行/IPC 失败/Denied）⇒「连接状态：服务未运行」+「VPN IP：—」；
/// - 状态文案：Connected⇒已连接、Connecting⇒连接中、Disconnected⇒未连接；
///   已连接/连接中携带端点后缀（「 · frps-a:23000」），未连接不带（端点=最近一次，
///   菜单简洁优先）；
/// - `vip: None` ⇒「VPN IP：—」（任何状态下）。
pub fn menu_texts(view: Option<&StatusSnapshot>) -> MenuTexts {
    let Some(s) = view else {
        return MenuTexts {
            status: "连接状态：服务未运行".into(),
            vip: "VPN IP：—".into(),
            tooltip: "Flock VPN：服务未运行".into(),
        };
    };
    let state_label = match s.state {
        ConnState::Connected => "已连接",
        ConnState::Connecting => "连接中",
        ConnState::Disconnected => "未连接",
    };
    let ep_suffix = match s.state {
        ConnState::Connected | ConnState::Connecting => s
            .endpoint
            .as_deref()
            .map(|ep| format!(" · {ep}"))
            .unwrap_or_default(),
        ConnState::Disconnected => String::new(),
    };
    let vip = s.vip.as_deref().unwrap_or("—");
    MenuTexts {
        status: format!("连接状态：{state_label}{ep_suffix}"),
        vip: format!("VPN IP：{vip}"),
        tooltip: format!("Flock VPN：{state_label}{ep_suffix} · VPN IP {vip}"),
    }
}

// ============================================================================
// token 源（加载缓存 + Denied 失效重载）
// ============================================================================

/// 控制 token 源：daemon 每次启动重写 token 文件——托盘读一次即够，但 **`Denied`
/// （daemon 重启换 token）后须失效重载**，否则永久失配。
#[derive(Debug)]
pub struct TokenSource {
    path: PathBuf,
    cached: Option<CtrlToken>,
}

impl TokenSource {
    pub fn new(path: PathBuf) -> Self {
        TokenSource { path, cached: None }
    }

    /// 取 token：缓存优先，未缓存读文件（文件缺失/内容非法 ⇒ None——调用方按
    /// 「daemon 未运行」处理并继续重试）。
    pub fn load(&mut self) -> Option<CtrlToken> {
        if self.cached.is_none() {
            self.cached = ipc::load_token_file(&self.path).ok();
        }
        self.cached
    }

    /// 失效缓存（下一次 [`Self::load`] 重读文件）。
    pub fn invalidate(&mut self) {
        self.cached = None;
    }
}

// ============================================================================
// 轮询（2s 周期的一拍：查询 → 投影 → 日志；任何失败都不终止循环）
// ============================================================================

fn log_refresh(texts: &MenuTexts) {
    eprintln!(
        "flock-client tray: 菜单刷新｜{}｜{}",
        texts.status, texts.vip
    );
}

/// 单拍 Status 轮询 → 菜单文案。
///
/// - token 文件不可读 ⇒ 「服务未运行」（daemon 未启动/无权限）；
/// - Status 快照 ⇒ 投影文案 + 刷新日志；
/// - `Denied` ⇒ 「服务未运行」+ **token 失效**（下拍重载——daemon 已重启的恢复路径）；
/// - IPC 失败（连接拒绝/超时）⇒ 「服务未运行」——继续重试由调用方的周期循环承担。
pub async fn poll_once(paths: &ControlPaths, tokens: &mut TokenSource) -> MenuTexts {
    let Some(token) = tokens.load() else {
        let texts = menu_texts(None);
        eprintln!(
            "flock-client tray: token 文件不可读（{}）——daemon 未运行或无权限",
            paths.token_file.display()
        );
        return texts;
    };
    match ipc::request_once(&paths.endpoint, CtrlReq::Status { token }).await {
        Ok(resp) => match StatusSnapshot::of(&resp) {
            Some(snapshot) => {
                let texts = menu_texts(Some(&snapshot));
                log_refresh(&texts);
                texts
            }
            None => {
                if matches!(resp, CtrlResp::Denied) {
                    tokens.invalidate();
                    eprintln!(
                        "flock-client tray: Status 被拒（token 失配——daemon 已重启？）——\
                         token 已失效，下轮重载"
                    );
                } else {
                    eprintln!("flock-client tray: 意外响应 {resp:?}——按「服务未运行」显示");
                }
                menu_texts(None)
            }
        },
        Err(e) => {
            eprintln!("flock-client tray: 控制面不可达: {e}（daemon 未运行？）");
            menu_texts(None)
        }
    }
}

// ============================================================================
// 退出动作（§7-M6.1 语义：Shutdown=优雅停服不复活；服务保持已安装）
// ============================================================================

/// 退出动作裁决。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDecision {
    /// 托盘进程退出（Shutdown 受理，或 daemon 不在——「仅退托盘」）。
    ExitTray,
    /// 托盘保持运行（`Denied`：token 失配已重载，用户重试点「退出」即重试）。
    StayRunning,
}

/// 「退出」菜单动作：对 daemon 发 `Shutdown`（带 token）。
///
/// - token 文件不可读 ⇒ daemon 未运行 ⇒ **仅退托盘**（服务保持已安装，语义不变）；
/// - `Ok` ⇒ daemon 优雅停服（断会话→停数据面→拆 tun→退出）⇒ 托盘退出；
/// - `Denied` ⇒ 不退出 + 提示（token 失配已失效重载——daemon 重启后旧 token 作废）；
/// - IPC 失败 ⇒ daemon 不在/已退出 ⇒ 仅退托盘（托盘退出不被一个不存在的 daemon 扣押）；
/// - 意外响应（未来变体）⇒ daemon 状态未知但存活——保守不退出。
pub async fn request_exit(paths: &ControlPaths, tokens: &mut TokenSource) -> ExitDecision {
    let Some(token) = tokens.load() else {
        eprintln!("flock-client tray: 退出——daemon 不在（token 文件不可读），仅退出托盘");
        return ExitDecision::ExitTray;
    };
    match ipc::request_once(&paths.endpoint, CtrlReq::Shutdown { token }).await {
        Ok(CtrlResp::Ok) => {
            eprintln!(
                "flock-client tray: Shutdown 受理——daemon 优雅停服；托盘退出\
                 （服务保持已安装，下次开机自启）"
            );
            ExitDecision::ExitTray
        }
        Ok(CtrlResp::Denied) => {
            tokens.invalidate();
            eprintln!(
                "flock-client tray: 退出被拒（token 失配——daemon 已重启？）——\
                 token 已重载，托盘保持运行（请再点一次「退出」）"
            );
            ExitDecision::StayRunning
        }
        Ok(other) => {
            eprintln!("flock-client tray: 退出——daemon 回复意外响应 {other:?}，托盘保持运行");
            ExitDecision::StayRunning
        }
        Err(e) => {
            eprintln!("flock-client tray: 退出——控制面不可达: {e}（daemon 未运行），仅退出托盘");
            ExitDecision::ExitTray
        }
    }
}

// ============================================================================
// GUI 会话判定（无 GUI 主机：托盘进程优雅退出并留清晰日志）
// ============================================================================

/// GUI 会话判定（纯函数真值表；Linux 运行时以 env/文件系统探测注入，Windows/macOS
/// 不预判——创建失败路径兜底）。
///
/// 两个条件同时满足才算 GUI 会话：(1) X11/Wayland 至少一个在（`DISPLAY` /
/// `WAYLAND_DISPLAY`）；(2) 会话 DBus 可用（`DBUS_SESSION_BUS_ADDRESS` 或
/// `$XDG_RUNTIME_DIR/bus`——ksni 的 SNI 通道走会话 DBus，缺它托盘无处落位）。
pub fn gui_session_present(display: bool, wayland: bool, session_bus: bool) -> bool {
    (display || wayland) && session_bus
}

/// Linux 运行时探测（env + `$XDG_RUNTIME_DIR/bus` 存在性）。
#[cfg(target_os = "linux")]
pub(crate) fn linux_gui_session_present() -> bool {
    let display = std::env::var("DISPLAY")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let wayland = std::env::var("WAYLAND_DISPLAY")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let bus = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .map(|v| !v.is_empty())
        .unwrap_or_else(|_| {
            std::env::var("XDG_RUNTIME_DIR")
                .ok()
                .map(|d| PathBuf::from(d).join("bus"))
                .is_some_and(|p| p.exists())
        });
    gui_session_present(display, wayland, bus)
}

// ============================================================================
// 进程入口（`tray` 子命令体；平台后端分派）
// ============================================================================

/// 托盘进程入口（main 直调）：端点/token 取平台缺省（§7-M6.2），GUI 缺席与托盘
/// 创建失败均**优雅退出**（`Ok(())`——退出码 0，清晰日志落 stderr）；仅内部错误
/// （线程/运行时创建失败等）以 `Err` 上浮（退出码 2）。
pub fn run_tray() -> Result<(), String> {
    let paths = ControlPaths::platform_default();
    #[cfg(windows)]
    let endpoint_disp = paths.endpoint.pipe_name.as_str();
    #[cfg(unix)]
    let endpoint_disp = paths.endpoint.socket_path.display().to_string();
    eprintln!(
        "flock-client tray: 启动（控制端点 {endpoint_disp}，token 文件 {}）",
        paths.token_file.display()
    );
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        backend_native::run(&paths)
    }
    #[cfg(target_os = "linux")]
    {
        backend_ksni::run(&paths)
    }
}

// ============================================================================
// 单元测试（无 GUI 宿主可跑：投影纯函数 + token 往返 + 真传输 IPC mock）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // —— 投影全分支 ——

    /// 全分支：Connected/Connecting/Disconnected/服务未运行；端点随行规则；vip None⇒「—」。
    #[test]
    fn menu_texts_projection_all_branches() {
        // 服务未运行（None）：状态 + VIP 占位「—」。
        let t = menu_texts(None);
        assert_eq!(t.status, "连接状态：服务未运行");
        assert_eq!(t.vip, "VPN IP：—");
        assert_eq!(t.tooltip, "Flock VPN：服务未运行");

        // 已连接 + 端点 + VIP（需求措辞样例）。
        let t = menu_texts(Some(&StatusSnapshot {
            state: ConnState::Connected,
            vip: Some("100.64.0.11".into()),
            endpoint: Some("frps-a:23000".into()),
        }));
        assert_eq!(t.status, "连接状态：已连接 · frps-a:23000");
        assert_eq!(t.vip, "VPN IP：100.64.0.11");
        assert_eq!(
            t.tooltip,
            "Flock VPN：已连接 · frps-a:23000 · VPN IP 100.64.0.11"
        );

        // 已连接但 vip None（文案容错位）⇒「VPN IP：—」。
        let t = menu_texts(Some(&StatusSnapshot {
            state: ConnState::Connected,
            vip: None,
            endpoint: Some("a:1".into()),
        }));
        assert_eq!(t.vip, "VPN IP：—");

        // 连接中：端点随行；无端点 ⇒ 无后缀。
        let t = menu_texts(Some(&StatusSnapshot {
            state: ConnState::Connecting,
            vip: Some("100.64.0.2".into()),
            endpoint: Some("b:2".into()),
        }));
        assert_eq!(t.status, "连接状态：连接中 · b:2");
        let t = menu_texts(Some(&StatusSnapshot {
            state: ConnState::Connecting,
            vip: None,
            endpoint: None,
        }));
        assert_eq!(t.status, "连接状态：连接中");
        assert_eq!(t.vip, "VPN IP：—");

        // 未连接：端点（最近一次）不进文案；VIP 缺省时同占位。
        let t = menu_texts(Some(&StatusSnapshot {
            state: ConnState::Disconnected,
            vip: Some("100.64.0.3".into()),
            endpoint: Some("c:3".into()),
        }));
        assert_eq!(t.status, "连接状态：未连接");
        assert_eq!(t.vip, "VPN IP：100.64.0.3");
    }

    /// `StatusSnapshot::of`：Status 变体取字段；Ok/Denied ⇒ None（防御分支）。
    #[test]
    fn snapshot_of_extracts_status_variant_only() {
        let resp = CtrlResp::Status {
            state: ConnState::Connected,
            vip: Some("100.64.0.4".into()),
            endpoint: Some("d:4".into()),
            epoch: 9,
            uptime_secs: 100,
        };
        let snap = StatusSnapshot::of(&resp).expect("Status 变体");
        assert_eq!(
            snap,
            StatusSnapshot {
                state: ConnState::Connected,
                vip: Some("100.64.0.4".into()),
                endpoint: Some("d:4".into()),
            }
        );
        assert_eq!(StatusSnapshot::of(&CtrlResp::Ok), None);
        assert_eq!(StatusSnapshot::of(&CtrlResp::Denied), None);
    }

    /// GUI 会话真值表：X11/Wayland 至少一个 + 会话 DBus——缺任一即无 GUI。
    #[test]
    fn gui_session_truth_table() {
        assert!(gui_session_present(true, false, true));
        assert!(gui_session_present(false, true, true));
        assert!(gui_session_present(true, true, true));
        assert!(!gui_session_present(true, false, false), "无会话 DBus");
        assert!(!gui_session_present(false, false, true), "无显示服务");
        assert!(!gui_session_present(false, false, false));
    }

    // —— token 源 ——

    /// token 源往返：加载缓存 → 失效 → 重读新值；缺失/非法内容 ⇒ None。
    #[test]
    fn token_source_invalidate_reloads_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control-token");
        let mut src = TokenSource::new(path.clone());

        // 文件缺失 ⇒ None（不 panic、不留毒缓存）。
        assert!(src.load().is_none());

        // 写 token A ⇒ 加载缓存（期间改文件不受影响——缓存生效）。
        let a = ipc::generate_token();
        std::fs::write(&path, hex::encode(a)).unwrap();
        assert_eq!(src.load(), Some(a));
        let b = ipc::generate_token();
        std::fs::write(&path, hex::encode(b)).unwrap();
        assert_eq!(src.load(), Some(a), "缓存优先（失效前不重读）");

        // 失效 ⇒ 重读到 B（daemon 重启换 token 的恢复路径）。
        src.invalidate();
        assert_eq!(src.load(), Some(b));

        // 非法内容 ⇒ None。
        src.invalidate();
        std::fs::write(&path, "zz-nothex").unwrap();
        assert!(src.load().is_none());
    }

    // —— 轮询（真传输 IPC mock）——
    //
    // 注：token 文件一律 `std::fs::write(hex)` 直写而非 `ipc::write_token_file`——后者
    // 在 Windows 落显式保护 DACL（Users 只读），非提升测试进程无法随后改写文件模拟
    // 「daemon 重启换 token」；ACL 行为已由 ipc 模块测试覆盖，本组测试聚焦托盘逻辑。

    /// 测试注入端点（与 service.rs 集成测试同款：Windows 临时命名管道 / Unix 临时
    /// socket——非提升宿主可建）。多次调用各起独立端点（Windows 侧序号防重名）。
    fn temp_endpoint() -> crate::ipc::IpcEndpoint {
        #[cfg(windows)]
        {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            crate::ipc::IpcEndpoint {
                pipe_name: format!(
                    r"\\.\pipe\flock-client-tray-test-{}-{}",
                    std::process::id(),
                    SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                ),
            }
        }
        #[cfg(unix)]
        {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let dir = std::env::temp_dir();
            crate::ipc::IpcEndpoint {
                socket_path: dir.join(format!(
                    "flock-client-tray-test-{}-{}.sock",
                    std::process::id(),
                    SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                )),
            }
        }
    }

    /// 起 mock daemon（真传输 + 固定快照）：返回 (paths, 服务器任务)。
    fn mock_daemon(
        dir: &std::path::Path,
        token: CtrlToken,
    ) -> (ControlPaths, tokio::task::JoinHandle<()>) {
        let endpoint = temp_endpoint();
        let token_file = dir.join("control-token");
        std::fs::write(&token_file, hex::encode(token)).unwrap();
        let paths = ControlPaths {
            endpoint,
            token_file,
        };
        let ctrl = Arc::new(ipc::DaemonControl {
            token,
            status: Arc::new(|| CtrlResp::Status {
                state: ConnState::Connected,
                vip: Some("100.64.0.9".into()),
                endpoint: Some("mock:27500".into()),
                epoch: 1,
                uptime_secs: 2,
            }),
            shutdown: Arc::new(|| {}),
        });
        let server = ipc::spawn_server(&paths, None, ctrl).expect("mock daemon IPC 起");
        (paths, server)
    }

    /// 轮询恢复：daemon 不在 ⇒「服务未运行」不 panic；daemon 起后同 token 源恢复
    /// 真实文案；token 失配（Denied）⇒「服务未运行」+ 失效后重载恢复。
    #[tokio::test]
    async fn poll_recovers_from_missing_denied_and_back() {
        let dir = tempfile::tempdir().unwrap();

        // (1) daemon 不在（token 文件缺失）：服务未运行 + 继续（函数返回即「未终止」）。
        let mut src = TokenSource::new(dir.path().join("absent-token"));
        let paths = ControlPaths {
            endpoint: temp_endpoint(),
            token_file: dir.path().join("absent-token"),
        };
        let texts = poll_once(&paths, &mut src).await;
        assert_eq!(texts.status, "连接状态：服务未运行");

        // (2) mock daemon 在 + token 正确 ⇒ 真实快照文案。
        let token = ipc::generate_token();
        let (paths, server) = mock_daemon(dir.path(), token);
        let mut src = TokenSource::new(paths.token_file.clone());
        let texts = poll_once(&paths, &mut src).await;
        assert_eq!(texts.status, "连接状态：已连接 · mock:27500");
        assert_eq!(texts.vip, "VPN IP：100.64.0.9");

        // (3) 失配 token（模拟 daemon 重启换 token）：Denied ⇒ 服务未运行 + token 失效；
        // 换回正确 token 文件后下一拍恢复。
        let stale = ipc::generate_token();
        std::fs::write(&paths.token_file, hex::encode(stale)).unwrap();
        let mut src = TokenSource::new(paths.token_file.clone());
        let texts = poll_once(&paths, &mut src).await;
        assert_eq!(
            texts.status, "连接状态：服务未运行",
            "Denied 拍按服务未运行显示"
        );
        std::fs::write(&paths.token_file, hex::encode(token)).unwrap();
        let texts = poll_once(&paths, &mut src).await;
        assert_eq!(
            texts.status, "连接状态：已连接 · mock:27500",
            "token 失效重载后恢复"
        );

        // (4) daemon 停止（IPC 失败）⇒ 服务未运行（重试语义由周期循环承担）。
        server.abort();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let texts = poll_once(&paths, &mut src).await;
        assert_eq!(texts.status, "连接状态：服务未运行");
    }

    // —— 退出动作（真传输 IPC mock 上的请求顺序）——

    /// 退出顺序（IPC mock）：`Denied`（token 失配）⇒ 不退出（StayRunning）且 daemon
    /// 停机钩子不触发；换正确 token 再退 ⇒ `Shutdown` ⇒ 钩子触发 + `Ok` ⇒ ExitTray；
    /// daemon 不在（无 token 文件）⇒ 零请求直接仅退托盘。
    ///
    /// 顺序断言面：mock daemon 的 shutdown 钩子在响应写出**之前**执行（serve_conn
    /// 先调钩子后回帧）——`request_exit` 返回即可读记录，无需额外同步。
    #[tokio::test]
    async fn exit_action_order_on_ipc_mock() {
        let dir = tempfile::tempdir().unwrap();
        let token = ipc::generate_token();
        let endpoint = temp_endpoint();
        let token_file = dir.path().join("control-token");
        std::fs::write(&token_file, hex::encode(token)).unwrap();
        let paths = ControlPaths {
            endpoint,
            token_file,
        };
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let log_shutdown = log.clone();
        let ctrl = Arc::new(ipc::DaemonControl {
            token,
            status: Arc::new(|| CtrlResp::Status {
                state: ConnState::Connected,
                vip: Some("100.64.0.9".into()),
                endpoint: Some("mock:27500".into()),
                epoch: 1,
                uptime_secs: 2,
            }),
            shutdown: Arc::new(move || {
                log_shutdown.lock().unwrap().push("shutdown");
            }),
        });
        let server = ipc::spawn_server(&paths, None, ctrl).expect("mock daemon IPC 起");

        // (1) 失配 token 文件：Shutdown 请求被 daemon 认证层拒（Denied）⇒ StayRunning
        // （不退出并提示）——停机钩子**不得**触发（token 校验先于分发，§7-M6.2）。
        let stale = ipc::generate_token();
        std::fs::write(&paths.token_file, hex::encode(stale)).unwrap();
        let mut src = TokenSource::new(paths.token_file.clone());
        assert_eq!(
            request_exit(&paths, &mut src).await,
            ExitDecision::StayRunning
        );
        assert!(
            log.lock().unwrap().is_empty(),
            "Denied 不得触发 daemon 停机"
        );

        // (2) 修正 token 文件（失效重载）再退：Shutdown ⇒ 钩子触发 + Ok ⇒ ExitTray。
        std::fs::write(&paths.token_file, hex::encode(token)).unwrap();
        assert_eq!(request_exit(&paths, &mut src).await, ExitDecision::ExitTray);
        assert_eq!(
            *log.lock().unwrap(),
            vec!["shutdown"],
            "对 token 恰一次 Shutdown 且已受理（钩子触发后才可能回 Ok）"
        );

        // (3) daemon 不在（token 文件缺失 ⇒ 零请求发出）⇒ 仅退托盘。
        let absent = ControlPaths {
            endpoint: temp_endpoint(),
            token_file: dir.path().join("absent-token"),
        };
        let mut src = TokenSource::new(absent.token_file.clone());
        assert_eq!(
            request_exit(&absent, &mut src).await,
            ExitDecision::ExitTray
        );
        assert_eq!(
            log.lock().unwrap().len(),
            1,
            "daemon 不在时退出动作零 IPC 请求（记录不增）"
        );

        server.abort();
    }
}
