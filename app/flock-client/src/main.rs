//! flock-client 进程入口（docs/design.md §3.12/§7-M3/§7-M6.4）。
//!
//! 子命令：
//! - （缺省 `run`）：前台调试模式——tun（MTU 1280）+ 路由 + 接入器守护（退避重连）；
//!   **不起 IPC**（日志直连 stderr；daemon 形态用 `service`）；
//! - `service`：daemon 装配（§7-M6.1：supervise 复用 + 控制面 IPC + 优雅停服；
//!   Windows 走 SCM 分派，终端直跑自动回落前台）；
//! - `status`：向 daemon 发一次 `Status` 请求并打印（无托盘环境/测试探针）；
//! - `invite <path>`：载入邀请文件（b64 文本或原始字节）→ 钉扎集群根公钥 + 存根签
//!   目录（一次性引导，§1.3.3f 强路径）；
//! - `gen-keys`：生成/复用设备静态密钥并打印公钥（部署编排把公钥交给
//!   `flock-server device-add`/`redeem` 预注册）；
//! - `--smoke`：wintun/真机冒烟（§7-M3 Windows 手工清单）——建 tun + 配路由 +
//!   打印接口状态即退。
//!
//! Windows 路由注入与 wintun 运行路径留待 M5 真机手工验证（§7-M3 清单；route 模块
//! 返回显式 `Unsupported` 并附手工指令）。macOS 无设备 ⇒ 未验证（utun 按 tun-rs
//! 平台矩阵设计）。

use std::io::Write as _;
use std::path::PathBuf;

use flock_client::config::ClientConfig;
use flock_client::connector::{self, Backoff, ClientError, ClientState, ConnEvent};
use flock_client::route::{self, RoutePlan};
use flock_client::tun::{TunIo, TunSpec};
use flock_protocol::trust::InviteFile;

const USAGE: &str = "\
flock-client [--config <client.toml>] [<subcommand>]

子命令：
  (run)                  前台调试模式（缺省）：tun + 路由 + 接入器守护（不起 IPC）
  service                daemon：supervise + 控制面 IPC + 优雅停服（§7-M6）
  status                 向 daemon 发一次 Status 请求并打印（无托盘环境探针）
  install [--user|--service]  安装服务+托盘自启（缺省两者；安装时 --config 记入服务定义）
  uninstall [--user|--service] 反向卸载
  tray                   托盘进程（M6 第二阶段；本阶段为占位入口，tray feature 门控）
  invite <path>          载入邀请（b64 文本/原始字节）→ 钉扎根公钥 + 存根签目录
  gen-keys               生成/复用设备密钥并打印公钥（device-x=/device-ed= b64）
  --smoke                真机冒烟：建 tun + 配路由 + 打印状态即退（§7-M3 手工清单）
";

fn main() {
    let code = match run_cli() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("flock-client: {e}");
            2
        }
    };
    std::process::exit(code);
}

struct Cli {
    config: PathBuf,
    cmd: Cmd,
}

enum Cmd {
    Run,
    Service,
    Status,
    Install {
        scope: flock_client::install::Scope,
    },
    Uninstall {
        scope: flock_client::install::Scope,
    },
    #[cfg(feature = "tray")]
    Tray,
    Invite {
        path: PathBuf,
    },
    GenKeys,
    Smoke,
}

fn parse_args() -> Result<Cli, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut config = PathBuf::from("client.toml");
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--config" => {
                i += 1;
                config = PathBuf::from(raw.get(i).ok_or("--config 值")?.clone());
            }
            "--smoke" => rest.push("--smoke".into()),
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    let mut it = rest.into_iter().peekable();
    let first = it.next();
    // 范围旗标（install/uninstall）：--user 只托盘自启、--service 只服务、缺省两者
    //（旗标跟在子命令之后：`install --user`）。
    let mut scope_user = false;
    let mut scope_service = false;
    if matches!(first.as_deref(), Some("install") | Some("uninstall")) {
        while let Some(flag) = it.peek() {
            match flag.as_str() {
                "--user" => {
                    scope_user = true;
                    it.next();
                }
                "--service" => {
                    scope_service = true;
                    it.next();
                }
                _ => break,
            }
        }
    }
    let scope = match (scope_user, scope_service) {
        (true, false) => flock_client::install::Scope::TrayOnly,
        (false, true) => flock_client::install::Scope::ServiceOnly,
        (false, false) => flock_client::install::Scope::Both,
        (true, true) => {
            return Err("--user 与 --service 互斥（缺省 = 两者都装）".into());
        }
    };
    let cmd = match first.as_deref() {
        None | Some("run") => Cmd::Run,
        Some("service") => Cmd::Service,
        Some("status") => Cmd::Status,
        Some("install") => Cmd::Install { scope },
        Some("uninstall") => Cmd::Uninstall { scope },
        #[cfg(feature = "tray")]
        Some("tray") => Cmd::Tray,
        #[cfg(not(feature = "tray"))]
        Some("tray") => return Err(
            "tray 子命令未编入本构建（--no-default-features 无头档；重编译请启用 tray feature）"
                .into(),
        ),
        Some("invite") => Cmd::Invite {
            path: PathBuf::from(it.next().ok_or("invite 需要 <文件路径>")?),
        },
        Some("gen-keys") => Cmd::GenKeys,
        Some("--smoke") => Cmd::Smoke,
        Some(other) => return Err(format!("未知子命令 {other:?}\n\n{USAGE}")),
    };
    Ok(Cli { config, cmd })
}

fn b64_decode_flex(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let t = text.trim();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(t))
        .map_err(|e| format!("b64: {e}"))
}

fn run_cli() -> Result<(), String> {
    let cli = parse_args()?;
    match cli.cmd {
        // status 不依赖 config（端点/token 全取平台缺省）；Windows service 在 SCM
        // 上下文内自载 config（工作目录 = system32，配置路径须安装时写绝对路径）。
        Cmd::Status => cmd_status(),
        Cmd::Service => cmd_service(&cli.config),
        Cmd::Install { scope } => flock_client::install::install(&cli.config, scope)
            .map_err(|e| format!("{e}\n（提权要求与平台矩阵见 docs/manual/service-install.md）")),
        Cmd::Uninstall { scope } => flock_client::install::uninstall(scope)
            .map_err(|e| format!("{e}\n（提权要求与平台矩阵见 docs/manual/service-install.md）")),
        #[cfg(feature = "tray")]
        Cmd::Tray => Err(
            "tray 子命令为 M6 第二阶段占位（IPC 契约已就绪：flock_client::ipc 的 \
             CtrlReq/CtrlResp + ControlPaths::platform_default）"
                .into(),
        ),
        Cmd::Run | Cmd::GenKeys | Cmd::Invite { .. } | Cmd::Smoke => {
            let cfg = ClientConfig::load(&cli.config)?;
            match cli.cmd {
                Cmd::GenKeys => {
                    let device =
                        ClientState::load_keys(&cfg.state_dir, true).map_err(|e| e.to_string())?;
                    use base64::Engine as _;
                    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
                    let mut out = std::io::stdout();
                    let _ = writeln!(
                        out,
                        "device-id={}",
                        hex::encode(
                            flock_protocol::session::DeviceId::from_ed25519(
                                &device.ed25519_public()
                            )
                            .0
                        )
                    );
                    let _ = writeln!(
                        out,
                        "device-x={}",
                        b64.encode(device.x25519_public().to_bytes())
                    );
                    let _ = writeln!(
                        out,
                        "device-ed={}",
                        b64.encode(device.ed25519_public().as_bytes())
                    );
                    Ok(())
                }
                Cmd::Invite { path } => {
                    // state_dir 无 directory 时 bootstrap 会拒——invite 路径先读密钥生成（容缺目录）。
                    let text = std::fs::read_to_string(&path)
                        .map_err(|e| format!("读 {}: {e}", path.display()))?;
                    let bytes = b64_decode_flex(&text)
                        .or_else(|_| std::fs::read(&path).map_err(|e| e.to_string()))?;
                    let invite =
                        InviteFile::from_bytes(&bytes).map_err(|e| format!("邀请文件: {e}"))?;
                    connector::ingest_invite(&cfg.state_dir, &invite)
                        .map(|_| ())
                        .map_err(|e| e.to_string())?;
                    println!(
                        "invite ok: cluster={} endpoints={}（已钉扎根公钥 + 存目录）",
                        hex::encode(invite.directory.cluster_id.0),
                        invite.directory.servers.len()
                    );
                    Ok(())
                }
                Cmd::Smoke => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| e.to_string())?;
                    rt.block_on(async move {
                        let state =
                            ClientState::load(&cfg.state_dir, true).map_err(|e| e.to_string())?;
                        let vip = state
                            .resolve_vip(&cfg.state_dir, cfg.vip)
                            .map_err(|e| e.to_string())?;
                        let spec = TunSpec {
                            name: cfg.tun_name.clone(),
                            mtu: cfg.mtu,
                        };
                        let tun = TunIo::open(&spec).map_err(|e| format!("tun: {e}"))?;
                        println!("tun: {} mtu={} vip={vip}", tun.name(), spec.mtu);
                        match route::apply(&RoutePlan::new(&cfg.tun_name, vip)).await {
                            Ok(()) => println!(
                                "route: {}/{} → {}（rp_filter=1）",
                                route::VIP_POOL.0,
                                route::VIP_POOL.1,
                                cfg.tun_name
                            ),
                            Err(e) => eprintln!("route: {e}"),
                        }
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        tun.shutdown();
                        println!("smoke done");
                        Ok(())
                    })
                }
                Cmd::Run => {
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| e.to_string())?;
                    rt.block_on(async move {
                        let state = ClientState::load(&cfg.state_dir, true).map_err(cli_err)?;
                        let vip = state
                            .resolve_vip(&cfg.state_dir, cfg.vip)
                            .map_err(cli_err)?;
                        let spec = TunSpec {
                            name: cfg.tun_name.clone(),
                            mtu: cfg.mtu,
                        };
                        let tun = TunIo::open(&spec).map_err(|e| cli_err(ClientError::from(e)))?;
                        eprintln!(
                            "flock-client: tun {} mtu={} vip={vip}",
                            tun.name(),
                            spec.mtu
                        );
                        route::apply(&RoutePlan::new(&spec.name, vip))
                            .await
                            .map_err(|e| cli_err(ClientError::State(e.to_string())))?;
                        eprintln!(
                            "flock-client: route {}/{} → {} + rp_filter=1",
                            route::VIP_POOL.0,
                            route::VIP_POOL.1,
                            spec.name
                        );
                        // 端点覆盖（断言钉死）优先；缺省 = 目录轮询。
                        let state = if cfg.endpoints.is_empty() {
                            state
                        } else {
                            connector::override_endpoints(state, &cfg.endpoints)?
                        };
                        eprintln!(
                            "flock-client: 守护启动（端点: {}）",
                            state.endpoints().join(", ")
                        );
                        connector::supervise(
                            &state,
                            &tun,
                            flock_protocol::session::TunnelConfig::default(),
                            Backoff::default(),
                            |ev| match ev {
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
                            },
                        )
                        .await;
                        Ok(())
                    })
                }
                // 不可达（外层 match 已分流；保穷尽性）。
                Cmd::Service | Cmd::Status | Cmd::Install { .. } | Cmd::Uninstall { .. } => {
                    unreachable!("已在 run_cli 分流")
                }
                #[cfg(feature = "tray")]
                Cmd::Tray => unreachable!("已在 run_cli 分流"),
            }
        }
    }
}

fn cli_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// `service` 子命令：Windows 走 SCM 分派（终端直跑自动回落前台 daemon）；Unix
/// 前台运行 daemon（systemd/launchd 的 ExecStart/Program 直接拉起本子命令）。
fn cmd_service(config: &std::path::Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        flock_client::service::service_entry(config.to_path_buf())
    }
    #[cfg(not(windows))]
    {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let cfg = ClientConfig::load(config)?;
        let paths = flock_client::ipc::ControlPaths::platform_default();
        rt.block_on(flock_client::service::run_service(cfg, paths))
    }
}

/// `status` 子命令：读 token 文件 → 发一次 `Status` 请求 → 打印快照。
fn cmd_status() -> Result<(), String> {
    use flock_client::ipc::{ConnState, CtrlReq, CtrlResp};
    let paths = flock_client::ipc::ControlPaths::platform_default();
    let token = flock_client::ipc::load_token_file(&paths.token_file)
        .map_err(|e| format!("{e}（daemon 未运行，或本用户无权读取控制 token）"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        match flock_client::ipc::request_once(&paths.endpoint, CtrlReq::Status { token }).await {
            Ok(CtrlResp::Status {
                state,
                vip,
                endpoint,
                epoch,
                uptime_secs,
            }) => {
                let state = match state {
                    ConnState::Connected => "connected",
                    ConnState::Connecting => "connecting",
                    ConnState::Disconnected => "disconnected",
                };
                println!("state={state}");
                println!("vip={}", vip.as_deref().unwrap_or("-"));
                println!("endpoint={}", endpoint.as_deref().unwrap_or("-"));
                println!("epoch={epoch} uptime={uptime_secs}s");
                Ok(())
            }
            Ok(CtrlResp::Denied) => {
                Err("请求被拒（token 失配——daemon 重启后旧 token 失效，重试）".into())
            }
            Ok(other) => Err(format!("意外响应: {other:?}")),
            Err(e) => Err(format!(
                "控制面不可达: {e}（daemon 未运行？`flock-client service` 或服务管理器启动）"
            )),
        }
    })
}
