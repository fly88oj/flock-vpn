//! flock-client process entry point (docs/design.md §3.12/§7-M3/§7-M6.4).
//!
//! Subcommands:
//! - (default `run`): foreground debug mode — tun (MTU 1280) + routes +
//!   connector supervise (backoff reconnect); **no IPC** (logs straight to
//!   stderr; for the daemon form use `service`);
//! - `service`: daemon assembly (§7-M6.1: supervise reuse + control-plane
//!   IPC + graceful shutdown; Windows goes through the SCM dispatcher, a
//!   direct terminal run falls back to foreground);
//! - `status`: send one `Status` request to the daemon and print it (for
//!   tray-less environments / test probes);
//! - `tray`: tray process (§7-M6 phase two): right-click menu
//!   "connection status / VPN IP / quit", refreshed on a 2s poll, queries and
//!   shuts down via control IPC; exits gracefully on GUI-less hosts (tray
//!   feature-gated);
//! - `invite <path>`: load an invite file (b64 text or raw bytes) → pin the
//!   cluster root public key + store the root-signed directory (one-time
//!   bootstrap, §1.3.3f strong path);
//! - `gen-keys`: generate/reuse the device static keys and print the public
//!   keys (deployment orchestration hands them to `flock-server
//!   device-add`/`redeem` for pre-registration);
//! - `--smoke`: wintun/on-machine smoke test (§7-M3 Windows manual checklist)
//!   — create tun + apply routes + print interface status, then exit.
//!
//! Interactive copy (usage, guidance, error prompts) is rendered through the
//! [`flock_client::lang`] pack (`[general] language`, default auto-detect);
//! operational diagnostic logs on stderr are English-only. Windows route
//! injection and the wintun runtime path are pending M5 real-machine manual
//! verification (§7-M3 checklist; the route module returns an explicit
//! `Unsupported` with manual instructions). No macOS device ⇒ unverified
//! (utun designed against the tun-rs platform matrix).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use flock_client::config::ClientConfig;
use flock_client::connector::{self, Backoff, ClientError, ClientState, ConnEvent};
use flock_client::lang::{Lang, LanguageSetting};
use flock_client::route::{self, RoutePlan};
use flock_client::tun::{TunIo, TunSpec};
use flock_protocol::trust::InviteFile;

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
    Login,
    Peers {
        json: bool,
    },
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

/// Locate the `--config` path in raw args (pre-parse, only to resolve the UI
/// language from client.toml — argument validation itself happens in
/// [`parse_args`]).
fn config_path_from_args() -> PathBuf {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--config" {
            if let Some(v) = it.next() {
                return PathBuf::from(v);
            }
        }
    }
    PathBuf::from("client.toml")
}

/// Best-effort UI language for interactive copy: client.toml
/// `[general] language` when the file parses, otherwise runtime detection
/// (`auto` semantics); never fails — interactive copy must not brick on a
/// broken config (the later strict `ClientConfig::load` surfaces the error).
fn best_effort_lang(config: &Path) -> Lang {
    ClientConfig::load(config)
        .map(|c| c.general.language.resolve())
        .unwrap_or_else(|_| LanguageSetting::Auto.resolve())
}

fn parse_args(lang: Lang) -> Result<Cli, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut config = PathBuf::from("client.toml");
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--config" => {
                i += 1;
                config = PathBuf::from(
                    raw.get(i)
                        .ok_or_else(|| {
                            lang.tr(flock_client::lang::Key::CliErrConfigValue)
                                .to_string()
                        })?
                        .clone(),
                );
            }
            "--smoke" => rest.push("--smoke".into()),
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    let mut it = rest.into_iter().peekable();
    let first = it.next();
    // Scope flags (install/uninstall): --user = tray autostart only,
    // --service = service only, default both (flags follow the subcommand:
    // `install --user`).
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
            return Err(lang
                .tr(flock_client::lang::Key::CliErrScopeMutex)
                .to_string());
        }
    };
    let cmd = match first.as_deref() {
        None | Some("run") => Cmd::Run,
        Some("service") => Cmd::Service,
        Some("status") => Cmd::Status,
        Some("login") => Cmd::Login,
        Some("peers") => {
            // `peers [--json]`: the machine-readable flag follows the subcommand.
            let mut json = false;
            while let Some(flag) = it.peek() {
                match flag.as_str() {
                    "--json" => {
                        json = true;
                        it.next();
                    }
                    _ => break,
                }
            }
            Cmd::Peers { json }
        }
        Some("install") => Cmd::Install { scope },
        Some("uninstall") => Cmd::Uninstall { scope },
        #[cfg(feature = "tray")]
        Some("tray") => Cmd::Tray,
        #[cfg(not(feature = "tray"))]
        Some("tray") => {
            return Err(lang
                .tr(flock_client::lang::Key::CliErrTrayNotBuilt)
                .to_string());
        }
        Some("invite") => Cmd::Invite {
            path: PathBuf::from(it.next().ok_or_else(|| {
                lang.tr(flock_client::lang::Key::CliErrInvitePath)
                    .to_string()
            })?),
        },
        Some("gen-keys") => Cmd::GenKeys,
        Some("--smoke") => Cmd::Smoke,
        Some(other) => {
            return Err(lang.trf(
                flock_client::lang::Key::CliErrUnknownSub,
                &[&other, &lang.tr(flock_client::lang::Key::CliUsage)],
            ))
        }
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
    // Interactive-copy language: resolved once from client.toml (best-effort
    // pre-scan of --config; falls back to detection), then threaded to every
    // command that renders user-facing copy. Operational logs stay English.
    let lang = best_effort_lang(&config_path_from_args());
    let cli = parse_args(lang)?;
    match cli.cmd {
        // status does not depend on config (endpoint/token take platform
        // defaults); the Windows service loads config itself inside the SCM
        // context (working dir = system32, so installation must record an
        // absolute config path).
        Cmd::Status => cmd_status(lang),
        Cmd::Peers { json } => cmd_peers(json, lang),
        Cmd::Service => cmd_service(&cli.config),
        Cmd::Install { scope } => flock_client::install::install(&cli.config, scope)
            .map_err(|e| format!("{e}{}", lang.tr(flock_client::lang::Key::CliInstallDocHint))),
        Cmd::Uninstall { scope } => flock_client::install::uninstall(scope)
            .map_err(|e| format!("{e}{}", lang.tr(flock_client::lang::Key::CliInstallDocHint))),
        #[cfg(feature = "tray")]
        Cmd::Tray => flock_client::tray::run_tray(lang),
        Cmd::Run | Cmd::GenKeys | Cmd::Invite { .. } | Cmd::Smoke | Cmd::Login => {
            let cfg = ClientConfig::load(&cli.config)?;
            let lang = cfg.general.language.resolve();
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
                    // bootstrap rejects a state_dir without directory — the
                    // invite path reads/generates keys first (tolerates a
                    // missing directory).
                    let text = std::fs::read_to_string(&path)
                        .map_err(|e| format!("read {}: {e}", path.display()))?;
                    let bytes = b64_decode_flex(&text)
                        .or_else(|_| std::fs::read(&path).map_err(|e| e.to_string()))?;
                    let invite =
                        InviteFile::from_bytes(&bytes).map_err(|e| format!("invite file: {e}"))?;
                    connector::ingest_invite(&cfg.state_dir, &invite)
                        .map(|_| ())
                        .map_err(|e| e.to_string())?;
                    println!(
                        "invite ok: cluster={} endpoints={} (root key pinned + directory stored)",
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
                                "route: {}/{} -> {} (rp_filter=1)",
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
                            "flock-client: route {}/{} -> {} + rp_filter=1",
                            route::VIP_POOL.0,
                            route::VIP_POOL.1,
                            spec.name
                        );
                        // Endpoint override (assertion pinning) wins; default
                        // = directory rotation.
                        let state = if cfg.endpoints.is_empty() {
                            state
                        } else {
                            connector::override_endpoints(state, &cfg.endpoints)?
                        };
                        eprintln!(
                            "flock-client: supervise started (endpoints: {})",
                            state.endpoints().join(", ")
                        );
                        connector::supervise(
                            &state,
                            &tun,
                            flock_protocol::session::TunnelConfig::default(),
                            Backoff::default(),
                            |ev| match ev {
                                ConnEvent::Dialing { endpoint, attempt } => {
                                    eprintln!("flock-client: dialing {endpoint} (attempt {attempt})")
                                }
                                ConnEvent::Connected { endpoint, server } => eprintln!(
                                    "flock-client: connected {endpoint} (server={})",
                                    hex::encode(server.0)
                                ),
                                ConnEvent::SessionEnded { endpoint, reason } => eprintln!(
                                    "flock-client: session ended {endpoint} reason={} -> reconnecting",
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
                Cmd::Login => {
                    cmd_login(&cfg, lang)?;
                    Ok(())
                }
                // Unreachable (the outer match already dispatched; keeps
                // exhaustiveness).
                Cmd::Service
                | Cmd::Status
                | Cmd::Peers { .. }
                | Cmd::Install { .. }
                | Cmd::Uninstall { .. } => {
                    unreachable!("already dispatched in run_cli")
                }
                #[cfg(feature = "tray")]
                Cmd::Tray => unreachable!("already dispatched in run_cli"),
            }
        }
    }
}

fn cli_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// `login` subcommand (M7 §7-M7.7 first-time setup): read the password (one
/// stdin line) → 0600 credentials file → direct-over-tunnel control stream:
/// set the service password (PwBegin/PwCommit — authorization = device owner
/// == [auth] username) → login verification (anchor + key-bind hostname
/// registration).
///
/// Password echo: line-reading stdin under a tty echoes — an accepted
/// trade-off inside the local trust domain (OPAQUE keeps the password off the
/// wire; at rest locally = local trust domain, §7-M7.7); pipes/containers
/// (`echo pw | login`) have no echo and no issue.
fn cmd_login(cfg: &ClientConfig, lang: Lang) -> Result<(), String> {
    use flock_client::lang::Key as K;
    let auth = cfg
        .auth
        .as_ref()
        .ok_or_else(|| lang.tr(K::CliLoginErrNoAuth).to_string())?;
    let cred_path =
        flock_client::ctrl::credentials_path(&cfg.state_dir, auth.credentials_file.as_deref());
    eprint!(
        "{}",
        lang.trf(K::CliLoginPrompt, &[&auth.username, &cred_path.display()])
    );
    let _ = std::io::stderr().flush();
    let mut pw = String::new();
    std::io::stdin()
        .read_line(&mut pw)
        .map_err(|e| lang.trf(K::CliLoginErrReadPassword, &[&e]))?;
    let pw = pw.trim_end_matches(['\n', '\r']).to_string();
    if pw.is_empty() {
        return Err(lang.tr(K::CliLoginErrEmptyPassword).to_string());
    }
    flock_client::ctrl::save_credentials(&cred_path, &pw)
        .map_err(|e| lang.trf(K::CliLoginErrWriteCredentials, &[&e]))?;
    eprintln!(
        "{}",
        lang.trf(K::CliLoginCredentialsSaved, &[&cred_path.display()])
    );

    // State trio (invite first) + SR-SIG1 key + hostname.
    let state = ClientState::load(&cfg.state_dir, false).map_err(cli_err)?;
    let sr_key =
        flock_client::ctrl::load_or_create_sr_key(&cfg.state_dir).map_err(|e| e.to_string())?;
    let hostname = flock_client::ctrl::resolve_hostname(cfg.hostname.as_deref());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let mut last_err = lang.tr(K::CliLoginNoEndpoints).to_string();
        for ep in state.endpoints() {
            let Some(pin) = state.pin_for(&ep) else {
                continue;
            };
            let tunnel = match connector::dial(
                &pin,
                &state.device,
                flock_protocol::session::TunnelConfig::default(),
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    last_err = format!("dial {ep}: {e}");
                    continue;
                }
            };
            let stream = match tunnel.open_stream(flock_protocol::mux::Prio::Control).await {
                Ok(s) => std::sync::Arc::new(tokio::sync::Mutex::new(s)),
                Err(e) => {
                    last_err = format!("control stream {ep}: {e}");
                    tunnel.shutdown().await;
                    continue;
                }
            };
            let t = flock_client::ctrl::StreamTransport(stream);
            // (1) Set the password (PasswordExists = already set — keep it;
            // login verification is the fallback check).
            match flock_client::ctrl::set_password_once(&t, &auth.username, &pw).await {
                Ok(true) => eprintln!("{}", lang.tr(K::CliLoginPwSet)),
                Ok(false) => eprintln!("{}", lang.tr(K::CliLoginPwExists)),
                Err(e) => {
                    tunnel.shutdown().await;
                    last_err = format!("set password: {e}");
                    continue;
                }
            }
            // (2) Login verification + hostname registration (no ticket
            // retention — one-shot command; the daemon logs in on its own).
            let params = flock_client::ctrl::AuthParams {
                username: auth.username.clone(),
                password: pw.clone(),
                hostname: hostname.clone(),
                device: flock_protocol::session::DeviceStaticKeys::from_bytes(
                    &state.device.to_bytes(),
                ),
                cluster_id: state.directory.cluster_id,
                directory: state.directory.clone(),
                sr_key: flock_protocol::sig::UserKey::from_seed(&sr_key.to_seed()),
            };
            let out = match flock_client::ctrl::login_and_bind(&t, &params).await {
                Ok(o) => o,
                Err(e) => {
                    tunnel.shutdown().await;
                    last_err = format!("login verification: {e}");
                    continue;
                }
            };
            tunnel.shutdown().await;
            // Stable English output line: m7_assert.sh greps '^login ok:'.
            println!(
                "login ok: user={} vip={} hostname={} (hostname registered; the daemon will \
                 log in automatically to keep the ticket fresh)",
                auth.username,
                std::net::Ipv4Addr::from(out.vip),
                hostname
            );
            return Ok(());
        }
        Err(lang.trf(
            K::CliLoginAllFailed,
            &[&last_err, &cred_path.display(), &auth.username],
        ))
    })
}

/// `service` subcommand: Windows goes through the SCM dispatcher (a direct
/// terminal run automatically falls back to the foreground daemon); Unix runs
/// the daemon in the foreground (ExecStart/Program of systemd/launchd invoke
/// this subcommand directly).
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

/// `status` subcommand: read the token file → send one `Status` request →
/// print the snapshot.
fn cmd_status(lang: Lang) -> Result<(), String> {
    use flock_client::ipc::{ConnState, CtrlReq, CtrlResp};
    use flock_client::lang::Key as K;
    let paths = flock_client::ipc::ControlPaths::platform_default();
    let token = flock_client::ipc::load_token_file(&paths.token_file)
        .map_err(|e| lang.trf(K::CliStatusErrToken, &[&e]))?;
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
            Ok(CtrlResp::Denied) => Err(lang.tr(K::CliErrDenied).to_string()),
            Ok(other) => Err(lang.trf(K::CliErrUnexpectedResp, &[&format!("{other:?}")])),
            Err(e) => Err(lang.trf(K::CliStatusErrUnreachable, &[&e])),
        }
    })
}

/// `peers` subcommand (M7 §7-M7.7): IPC `Peers` → table (default) / `--json`
/// machine-readable. Daemon absent/not logged in ⇒ explicit error with
/// guidance (exit code 2).
fn cmd_peers(json: bool, lang: Lang) -> Result<(), String> {
    use flock_client::ipc::{CtrlReq, CtrlResp, PEERS_REQUEST_TIMEOUT};
    use flock_client::lang::Key as K;
    let paths = flock_client::ipc::ControlPaths::platform_default();
    let token = flock_client::ipc::load_token_file(&paths.token_file)
        .map_err(|e| lang.trf(K::CliPeersErrToken, &[&e]))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        match flock_client::ipc::request_once_timeout(
            &paths.endpoint,
            CtrlReq::Peers { token },
            PEERS_REQUEST_TIMEOUT,
        )
        .await
        {
            Ok(CtrlResp::Peers { rows }) => {
                if json {
                    println!("{}", flock_client::peers::render_json(&rows)?);
                } else {
                    print!("{}", flock_client::peers::render_table(&rows, lang));
                }
                Ok(())
            }
            Ok(CtrlResp::PeersUnavailable { reason }) => {
                Err(lang.trf(K::CliPeersErrUnavailable, &[&reason]))
            }
            Ok(CtrlResp::Denied) => Err(lang.tr(K::CliErrDenied).to_string()),
            Ok(other) => Err(lang.trf(K::CliErrUnexpectedResp, &[&format!("{other:?}")])),
            Err(e) => Err(lang.trf(K::CliPeersErrUnreachable, &[&e])),
        }
    })
}
