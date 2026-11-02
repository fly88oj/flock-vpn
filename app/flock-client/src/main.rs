//! flock-client 进程入口（docs/design.md §3.12/§7-M3）。
//!
//! 子命令：
//! - （缺省 `run`）：起客户端——tun（MTU 1280）+ 路由 + 接入器守护（退避重连）；
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

use flock_protocol::trust::InviteFile;
use flock_client::config::ClientConfig;
use flock_client::connector::{self, Backoff, ClientError, ClientState, ConnEvent};
use flock_client::route::{self, RoutePlan};
use flock_client::tun::{TunIo, TunSpec};

const USAGE: &str = "\
flock-client [--config <client.toml>] [<subcommand>]

子命令：
  (run)                  起客户端（缺省）：tun + 路由 + 接入器守护（退避重连）
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
    Invite { path: PathBuf },
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
    let mut it = rest.into_iter();
    let cmd = match it.next().as_deref() {
        None | Some("run") => Cmd::Run,
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
    let cfg = ClientConfig::load(&cli.config)?;
    match cli.cmd {
        Cmd::GenKeys => {
            let device = ClientState::load_keys(&cfg.state_dir, true).map_err(|e| e.to_string())?;
            use base64::Engine as _;
            let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
            let mut out = std::io::stdout();
            let _ = writeln!(
                out,
                "device-id={}",
                hex::encode(
                    flock_protocol::session::DeviceId::from_ed25519(&device.ed25519_public()).0
                )
            );
            let _ = writeln!(out, "device-x={}", b64.encode(device.x25519_public().to_bytes()));
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
            let bytes =
                b64_decode_flex(&text).or_else(|_| std::fs::read(&path).map_err(|e| e.to_string()))?;
            let invite = InviteFile::from_bytes(&bytes).map_err(|e| format!("邀请文件: {e}"))?;
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
                let state = ClientState::load(&cfg.state_dir, true).map_err(|e| e.to_string())?;
                let vip = state.resolve_vip(&cfg.state_dir, cfg.vip).map_err(|e| e.to_string())?;
                let spec = TunSpec { name: cfg.tun_name.clone(), mtu: cfg.mtu };
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
                let vip = state.resolve_vip(&cfg.state_dir, cfg.vip).map_err(cli_err)?;
                let spec = TunSpec { name: cfg.tun_name.clone(), mtu: cfg.mtu };
                let tun = TunIo::open(&spec).map_err(|e| cli_err(ClientError::from(e)))?;
                eprintln!("flock-client: tun {} mtu={} vip={vip}", tun.name(), spec.mtu);
                route::apply(&RoutePlan::new(&spec.name, vip)).await.map_err(|e| cli_err(ClientError::State(e.to_string())))?;
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
                    override_endpoints(state, &cfg.endpoints)?
                };
                eprintln!(
                    "flock-client: 守护启动（端点: {}）",
                    state.endpoints().join(", ")
                );
                connector::supervise(&state, &tun, flock_protocol::session::TunnelConfig::default(), Backoff::default(), |ev| {
                    match ev {
                        ConnEvent::Dialing { endpoint, attempt } => eprintln!(
                            "flock-client: 拨号 {endpoint}（attempt {attempt}）"
                        ),
                        ConnEvent::Connected { endpoint, server } => eprintln!(
                            "flock-client: 已连接 {endpoint}（server={}）",
                            hex::encode(server.0)
                        ),
                        ConnEvent::SessionEnded { endpoint, reason } => eprintln!(
                            "flock-client: 会话结束 {endpoint} reason={} → 进入重连",
                            reason.map(|r| r.to_string()).unwrap_or_else(|| "none(io/fin)".into())
                        ),
                    }
                })
                .await;
                Ok(())
            })
        }
    }
}

fn cli_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// 端点覆盖：仅接受目录内端点（材料必须匹配，§1.3.3f 端点↔材料同签）；重复项
/// 告警并去重（保首次出现序——不去重会让 EndpointRing 轮询重复拨同一端点）。
fn override_endpoints(mut state: ClientState, eps: &[String]) -> Result<ClientState, String> {
    let known = state.endpoints();
    let mut seen: Vec<String> = Vec::new();
    for ep in eps {
        if !known.contains(ep) {
            return Err(format!("覆盖端点 {ep} 不在根签目录内（端点↔材料同签，拒绝未签名端点）"));
        }
        if seen.contains(ep) {
            eprintln!("flock-client: 配置告警：覆盖端点列表重复项 {ep}（已去重，保留首次出现序）");
        } else {
            seen.push(ep.clone());
        }
    }
    let mut servers = Vec::new();
    for ep in &seen {
        if let Some(e) = state.directory.servers.iter().find(|s| &s.relay_endpoint == ep) {
            servers.push(e.clone());
        }
    }
    state.directory.servers = servers;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flock_client::connector::ClientState;
    use flock_protocol::session::{ClusterId, ServerEntry, ServerId};
    use flock_protocol::trust::{ClusterDirectory, PinStore};

    fn state_with(endpoints: &[&str]) -> ClientState {
        let mut servers = Vec::new();
        for (i, ep) in endpoints.iter().enumerate() {
            let identity =
                flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[i as u8 + 1; 32]);
            servers.push(ServerEntry {
                server_id: ServerId([i as u8 + 1; 16]),
                relay_endpoint: (*ep).to_string(),
                identity_pub: identity.verifying_key(),
                static_hybrid_pub: flock_protocol::kem::HybridKeypair::generate(
                    &mut flock_protocol::rand::rngs::OsRng,
                )
                .public(),
            });
        }
        let directory = ClusterDirectory {
            cluster_id: ClusterId([7; 16]),
            dir_version: 1,
            servers,
            root_sig: flock_protocol::ed25519_dalek::Signature::from_bytes(&[0; 64]),
        };
        ClientState {
            device: flock_protocol::session::DeviceStaticKeys::generate(),
            pins: PinStore::new(),
            directory,
        }
    }

    /// 覆盖端点去重（保序）+ 未签名端点拒绝（§1.3.3f 原语义不回归）。
    #[test]
    fn override_endpoints_dedups_repeats_and_keeps_gate() {
        let state = state_with(&["a:1", "b:2", "c:3"]);
        // 重复项：去重保首现序。
        let eps = vec!["b:2".to_string(), "a:1".to_string(), "b:2".to_string()];
        let out = override_endpoints(state, &eps).expect("合法覆盖");
        assert_eq!(out.endpoints(), vec!["b:2".to_string(), "a:1".to_string()]);
        // 未签名端点仍拒。
        let state2 = state_with(&["a:1"]);
        let bad = vec!["evil:9".to_string()];
        assert!(override_endpoints(state2, &bad).is_err(), "未签名端点必须拒绝");
    }
}
