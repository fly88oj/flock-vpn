//! Daemon assembly (docs/design.md §7-M6.1/M6.2): the process body of
//! `flock-client service`.
//!
//! Reuses all of [`connector::supervise`] (tun/routes/dialing/backoff/data
//! plane untouched), adding:
//! - **IPC server**: `ControlPaths` placement + token generation/file write
//!   + [`crate::ipc::spawn_server`];
//! - **Status snapshot source**: `ConnEvent` (connection state/endpoint) +
//!   `epoch_watch` (epoch) → [`ServiceStatus`] (the data source of the IPC
//!   `Status`);
//! - **Graceful shutdown**: any of IPC `Shutdown` / SCM Stop / SIGTERM fires
//!   → tear down the session (the supervise task aborts ⇒ tunnel and control
//!   stream Drop, TCP closes, the peer sees session termination) → stop the
//!   data plane → tear down tun → process exit; the service manager **does
//!   not revive it** (systemd `Restart=on-failure` acts only on failure
//!   exits, launchd has no KeepAlive, the Windows recovery policy hooks only
//!   failure codes, §7-M6.1).
//!
//! Headless confirmation: this module (and the `service` subcommand path)
//! depends on no GUI crate; the tray lives in the `tray` subcommand (phase
//! two, feature-gated).
//!
//! Windows SCM integration: `service_dispatcher` dispatch + the SCM state
//! machine (StartPending→Running→Stopped) + event-log reporting (the event
//! log **source** is registered on the install side under HKLM; when not
//! registered, events still land in the Application log with the message
//! rendered as insertion strings). A non-SCM-context start
//! (terminal/container debugging) falls back to the foreground.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::Notify;

use crate::config::ClientConfig;
use crate::connector::{self, ConnEvent};
use crate::ipc::{spawn_server, write_token_file, ControlPaths, CtrlResp, DaemonControl};
use crate::tun::{TunIo, TunSpec};

/// Service name (unified identity across the Windows SCM / systemd unit /
/// launchd label).
pub const SERVICE_NAME: &str = "flock-client";

/// Response grace window after a shutdown trigger (review item 8): there is
/// a race between shutdown and an in-flight serve_conn writing its response
/// frame — the main flow returning immediately tears down the runtime and
/// the client might see a broken pipe instead of `Ok`/the last snapshot.
const SHUTDOWN_RESP_GRACE: std::time::Duration = std::time::Duration::from_millis(100);

// ============================================================================
// Status snapshot source (the data plane of IPC Status)
// ============================================================================

/// supervise projection (ConnEvent aggregation).
#[derive(Debug)]
struct StatusInner {
    state: crate::ipc::ConnState,
    endpoint: Option<String>,
}

/// Daemon status snapshot source: shared as `Arc` with the IPC snapshot
/// closure and the supervise event closure.
pub struct ServiceStatus {
    start: Instant,
    vip: Option<String>,
    inner: Mutex<StatusInner>,
    /// Current session epoch (the watch of `supervise_with_epoch`; snapshot
    /// only borrows without consuming the mark).
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

    /// The IPC `Status` snapshot (field semantics per the §7-M6.2 contract).
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

    /// `ConnEvent` → state projection (called by the supervise event
    /// closure; Dialing=Connecting, Connected=Connected,
    /// SessionEnded=Disconnected, the endpoint keeps the most recent value).
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
// Daemon main flow
// ============================================================================

/// Foreground daemon (`service` subcommand run directly / Unix service
/// manager ExecStart): SIGTERM/SIGINT ⇒ graceful shutdown.
pub async fn run_service(cfg: ClientConfig, paths: ControlPaths) -> Result<(), String> {
    let stop = Arc::new(Notify::new());
    #[cfg(unix)]
    {
        let sig_stop = stop.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).expect("SIGTERM registration");
            let mut int = signal(SignalKind::interrupt()).expect("SIGINT registration");
            tokio::select! {
                _ = term.recv() => eprintln!("flock-client: SIGTERM -> graceful shutdown"),
                _ = int.recv() => eprintln!("flock-client: SIGINT -> graceful shutdown"),
            }
            sig_stop.notify_one();
        });
    }
    run_service_inner(cfg, paths, stop).await
}

/// Daemon body (shutdown-signal injection point: shared by Unix signals /
/// Windows SCM Stop / IPC Shutdown).
async fn run_service_inner(
    cfg: ClientConfig,
    paths: ControlPaths,
    stop: Arc<Notify>,
) -> Result<(), String> {
    let started = Instant::now();
    log_service_event(
        EventLevel::Info,
        &format!("service started (state_dir={})", cfg.state_dir.display()),
    );

    // —— Status trio + VIP + endpoint override (same order as the
    //    foreground run). ——
    let state = connector::ClientState::load(&cfg.state_dir, true).map_err(|e| e.to_string())?;
    let vip = state
        .resolve_vip(&cfg.state_dir, cfg.vip)
        .map_err(|e| e.to_string())?;
    let state = if cfg.endpoints.is_empty() {
        state
    } else {
        connector::override_endpoints(state, &cfg.endpoints)?
    };

    // —— tun + routes (persistent device, reused across sessions; failure =
    //    fatal — no data plane means no service value). ——
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
        "flock-client: service route {}/{} -> {}",
        crate::route::VIP_POOL.0,
        crate::route::VIP_POOL.1,
        spec.name
    );

    daemon_loop(cfg, state, tun, Some(vip), paths, stop, started).await
}

/// Daemon loop (snapshot source + supervise + control-stream login keepalive
/// + IPC + shutdown wait + teardown).
///
/// Independent of the tun/route assembly (`run_service_inner` completes it
/// first) — integration tests inject a mock tun and enter this layer
/// directly (the host has no real device).
async fn daemon_loop(
    cfg: ClientConfig,
    state: connector::ClientState,
    tun: Arc<TunIo>,
    vip: Option<std::net::Ipv4Addr>,
    paths: ControlPaths,
    stop: Arc<Notify>,
    started: Instant,
) -> Result<(), String> {
    // —— Snapshot source + supervise task (epoch sends its initial value on
    //    connection establishment, increments on rekey). ——
    let (epoch_tx, epoch_rx) = tokio::sync::watch::channel(0u64);
    let status = Arc::new(ServiceStatus::new(vip, epoch_rx));
    let ev_status = status.clone();
    let tun_sup = tun.clone();

    // —— M7 control-stream shared slot (supervise installs the stream;
    //    login keepalive/roster pulls are the business consumers). ——
    let plane = crate::ctrl::ControlPlane::new();
    let plane_for_peers = plane.clone();

    // —— M7 roster cache + latency prober (missing raw capability ⇒ degrade
    //    to the no-latency mode, roster as usual). ——
    let roster_cache = Arc::new(crate::ctrl::RosterCache::new());
    let pinger: Option<Arc<dyn crate::ping::Pinger>> = match crate::ping::RawIcmpPinger::new() {
        Ok(p) => Some(Arc::new(p)),
        Err(e) => {
            eprintln!(
                "flock-client: warning: raw ICMP prober unavailable (the latency column will \
                 show —): {e}"
            );
            None
        }
    };

    // —— M7 login keepalive task (assembled only when [auth] is configured;
    //    ticket memory-only, §7-M7.7). ——
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
                .map_err(|e| format!("SR-SIG1 key: {e}"))?,
        };
        let stop_auth = stop.clone();
        auth_task = Some(tokio::spawn(crate::ctrl::run_auth_keepalive(
            plane.clone(),
            ctx,
            auth_shared.clone(),
            stop_auth,
        )));
    }

    // supervise never returns normally; a task panic ⇒ the alive-signal
    // channel closes (recv returns None) ⇒ the main flow shuts down as a
    // failure (the service manager's failure semantics take over —
    // Restart/recovery policy acts only on this path).
    let (sup_alive_tx, mut sup_alive_rx) = tokio::sync::mpsc::channel::<()>(1);
    let supervise_task = tokio::spawn(async move {
        let _alive = sup_alive_tx; // held until the task ends (Drop ⇒ the main flow's recv sees None)
        connector::supervise_with_control(
            &state,
            tun_sup.as_ref(),
            flock_protocol::session::TunnelConfig::default(),
            connector::Backoff::default(),
            move |ev: ConnEvent| {
                ev_status.project(&ev);
                match &ev {
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
                }
            },
            epoch_tx,
            plane,
        )
        .await;
    });

    // —— IPC server (token generation/file write → DaemonControl → accept
    //    loop; on failure reclaim tun). ——
    let token = crate::ipc::generate_token();
    if let Err(e) = write_token_file(&paths.token_file, &token, cfg.control_group.as_deref()) {
        supervise_task.abort();
        tun.shutdown();
        return Err(format!("token file: {e}"));
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
        // M7 roster assembly (§7-M7.7): ≤5s cache → otherwise PeerListPull
        // (ticket from the login keepalive); concurrent ping probing of
        // online non-self rows (missing raw capability ⇒ degrade to the
        // no-latency mode).
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
                    // Phase pre-check: guidance text for
                    // unconfigured/not-logged-in/tunnel-down (no pull
                    // initiated). phase()==None = login keepalive task not
                    // assembled (no [auth]) ⇒ login bootstrap guidance
                    // (review item 5 — this shape previously fell into "no
                    // login ticket yet (retry shortly)").
                    if let Some(r) = crate::ctrl::AuthPhase::peers_block_reason(auth_shared.phase())
                    {
                        return CtrlResp::PeersUnavailable { reason: r };
                    }
                    // Roster: use the cache while fresh (≤5s); otherwise pull
                    // with the current ticket.
                    let peers = match roster.fresh() {
                        Some(p) => p,
                        None => {
                            let Some(ticket) = auth_shared.ticket() else {
                                return CtrlResp::PeersUnavailable {
                                    reason: "no login ticket yet (login keepalive task is \
                                             starting — retry shortly)"
                                        .into(),
                                };
                            };
                            match crate::ctrl::pull_roster(&plane, &ticket).await {
                                Ok(p) => {
                                    roster.store(p.clone());
                                    p
                                }
                                Err(e) => {
                                    return CtrlResp::PeersUnavailable {
                                        reason: format!("roster fetch failed: {e}"),
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
            return Err(format!("control-plane listen failed: {e}"));
        }
    };

    // —— Shutdown wait: any of IPC Shutdown / SCM Stop / signals fires;
    //    supervise/IPC death stops it too. ——
    let outcome = tokio::select! {
        _ = stop.notified() => Ok(()),
        // supervise task termination (only possible via panic) ⇒ alive
        // channel closed ⇒ shut down as a failure.
        sup_dead = sup_alive_rx.recv() => Err(format!(
            "supervise loop exited abnormally (alive signal: {sup_dead:?})"
        )),
        // Fatal exit of the IPC accept loop (review item 4: transient cases
        // already back off and continue inside it; only fatal ones return
        // here) ⇒ control plane disabled — shut down as a failure, visible
        // to the main flow (no silent loss of control).
        ipc_dead = &mut ipc_task => Err(format!(
            "control IPC loop exited abnormally (fatal accept/creation error, see logs): \
             {ipc_dead:?}"
        )),
    };

    // —— Shutdown response grace (review item 8, minimal implementation
    //    chosen): after the shutdown trigger, a fixed 100ms timer slot lets
    //    in-flight serve_conn tasks (one task per connection — aborting the
    //    IPC accept loop does not touch them) finish writing their Shutdown
    //    `Ok`/last-snapshot frames before teardown/runtime exit. vs "an
    //    in-flight serve_conn registry to count down": no connection
    //    bookkeeping surface; one sleep covers all trigger paths
    //    (IPC/SCM/signals).
    tokio::time::sleep(SHUTDOWN_RESP_GRACE).await;

    // —— Graceful teardown: IPC → login keepalive → supervise (session
    //    teardown/data-plane stop: the tunnel Drops with the task) → tun. ——
    ipc_task.abort();
    #[cfg(unix)]
    let _ = std::fs::remove_file(&paths.endpoint.socket_path); // collected immediately at shutdown; leftover backstop in ipc_unix
    if let Some(t) = &auth_task {
        t.abort();
    }
    supervise_task.abort();
    tun.shutdown();
    log_service_event(
        EventLevel::Info,
        &format!(
            "service stopped (ran {:?}, auth phase {:?})",
            started.elapsed(),
            auth_shared
                .phase()
                .unwrap_or(crate::ctrl::AuthPhase::Unconfigured)
        ),
    );
    outcome
}

// ============================================================================
// Windows SCM integration
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

    /// Dispatch failure code for a non-SCM start
    /// (StartServiceCtrlDispatcherW: process not started by the SCM).
    const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
    /// Stop state-machine wait_hint (the longest shutdown duration the SCM
    /// expects).
    const STOP_HINT: Duration = Duration::from_secs(30);

    /// SCM context (the dispatcher's extern callback cannot take closures ⇒
    /// passed through a OnceLock).
    struct ServiceCtx {
        cfg_path: PathBuf,
        stop: Arc<Notify>,
    }
    static SERVICE_CTX: std::sync::OnceLock<ServiceCtx> = std::sync::OnceLock::new();

    windows_service::define_windows_service!(ffi_service_main, windows_service_main);

    /// `service` subcommand entry point (Windows): SCM dispatch; a direct
    /// terminal/container run falls back to the foreground daemon.
    pub fn service_entry(cfg_path: PathBuf) -> Result<(), String> {
        let ctx = ServiceCtx {
            cfg_path,
            stop: Arc::new(Notify::new()),
        };
        if SERVICE_CTX.set(ctx).is_err() {
            return Err("service context initialized twice".into());
        }
        match service_dispatcher::start(crate::service::SERVICE_NAME, ffi_service_main) {
            Ok(()) => Ok(()),
            // Non-SCM context (terminal/container debugging): fall back to
            // the foreground daemon (same-meaning path as Unix `service`).
            Err(windows_service::Error::Winapi(e))
                if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) =>
            {
                eprintln!("flock-client: non-SCM context, running the daemon in the foreground (debug form)");
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let Some(ctx) = SERVICE_CTX.get() else {
                    return Err("service context missing".into());
                };
                let cfg = ClientConfig::load(&ctx.cfg_path)?;
                let paths = ControlPaths::platform_default();
                rt.block_on(run_service_inner(cfg, paths, ctx.stop.clone()))
            }
            Err(e) => Err(format!("SCM dispatch failed: {e}")),
        }
    }

    fn windows_service_main(_args: Vec<OsString>) {
        let Some(ctx) = SERVICE_CTX.get() else {
            log_service_event(
                EventLevel::Error,
                "service context missing (internal error)",
            );
            return;
        };
        // SCM handler registration comes **first** (review item 6): only
        // while holding the status handle can later paths such as a config
        // load failure land Stopped(+non-zero exit code) in the state
        // machine; if registration itself fails ⇒ no handle to set — the
        // event log + a non-zero process exit code are the backstop (the SCM
        // records by process exit).
        let stop = ctx.stop.clone();
        let registered = service_control_handler::register(
            crate::service::SERVICE_NAME,
            move |event| match event {
                ServiceControl::Stop => {
                    log_service_event(EventLevel::Info, "SCM Stop -> graceful shutdown");
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
                log_service_event(
                    EventLevel::Error,
                    &format!("SCM handler registration failed: {e}"),
                );
                std::process::exit(2);
            }
        };
        /// Non-zero exit code for failure paths (the SCM/recovery policy
        /// recognizes failure exits by it; graceful shutdown = 0).
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
                log_service_event(EventLevel::Error, &format!("config load failed: {e}"));
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
                log_service_event(EventLevel::Error, &format!("runtime creation failed: {e}"));
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
        // Review item 6: wrap run_service_inner in catch_unwind — a panic
        // also lands Stopped(+non-zero) + the event log (AssertUnwindSafe:
        // the post-panic assembly state is not reused, the process exits
        // right away — no unwind-safety debt). Sub-task panics (supervise
        // etc.) are handled separately by daemon_loop's alive channel.
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
                    "<non-string panic payload>".to_string()
                };
                log_service_event(EventLevel::Error, &format!("service panic: {msg}"));
                Err(format!("service panic: {msg}"))
            }
        };
        if let Err(e) = &res {
            log_service_event(
                EventLevel::Error,
                &format!("service exited abnormally: {e}"),
            );
        }
        let exit = if res.is_ok() { 0 } else { SVC_EXIT_FAILURE };
        set(ServiceState::Stopped, exit, false, Duration::ZERO);
    }
}

#[cfg(windows)]
pub use scm::service_entry;

// ============================================================================
// Event log (Windows event-log source; on Unix, eprintln → journald)
// ============================================================================

/// Event level.
#[derive(Debug, Clone, Copy)]
pub enum EventLevel {
    Info,
    Error,
}

/// Service-lifecycle event reporting: Windows goes through the event-log
/// source [`SERVICE_NAME`] (registered on the install side; when not
/// registered, events still land in the Application log with the message
/// rendered as insertion strings), plus an eprintln for the foreground form;
/// Unix lands on stderr (systemd collects it into the journal).
pub fn log_service_event(level: EventLevel, msg: &str) {
    match level {
        EventLevel::Info => eprintln!("flock-client: {msg}"),
        EventLevel::Error => eprintln!("flock-client: error: {msg}"),
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
        // SAFETY: both strings are NUL-terminated; RegisterEventSourceW
        // returns null on failure ⇒ skip; ReportEventW copies by value,
        // Deregister releases the handle after reporting.
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
                    1, // event ID (placeholder without a message DLL)
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
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{request_once, ConnState, CtrlReq, IpcEndpoint};
    use crate::tun::{MockTunDevice, TunSpec};

    /// Snapshot projection: initial Disconnected → Dialing=Connecting →
    /// Connected (endpoint) → Ended=Disconnected (endpoint kept); rekey
    /// epoch reflected immediately.
    #[tokio::test]
    async fn status_projection_over_lifecycle() {
        let (tx, epoch_rx) = tokio::sync::watch::channel(0u64);
        let st = ServiceStatus::new(Some("100.64.0.7".parse().unwrap()), epoch_rx);

        // Initial: Disconnected, no endpoint, epoch 0, vip/uptime present.
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
            other => panic!("expected the Status variant, got {other:?}"),
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
        // Epoch advance (rekey) reflected immediately.
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
                assert_eq!(
                    endpoint.as_deref(),
                    Some("a:1"),
                    "endpoint kept (most recent)"
                );
                assert_eq!(epoch, 4, "epoch kept (most recent session value)");
            }
            other => panic!("{other:?}"),
        }
    }

    /// daemon_loop end to end (real IPC transport + mock tun + supervise
    /// idling over an empty-endpoint directory): Status queryable
    /// (Disconnected + vip + uptime) → Shutdown (with the token) ⇒ replies
    /// Ok, the main flow returns Ok, the mock tun enters the closed state;
    /// a wrong-token Shutdown ⇒ Denied, no shutdown.
    #[tokio::test]
    async fn daemon_loop_shutdown_via_ipc() {
        use crate::tun::TunDevice as _;

        let dir = tempfile::tempdir().unwrap();
        // The state directory has only the device keys (no directory.bin):
        // daemon_loop does no load (assembly already happened in
        // run_service_inner); handing over a ClientState with an empty
        // directory directly ⇒ supervise idles in "directory has no
        // endpoints, recheck in 5s" — focus on the IPC→teardown chain, no
        // network/peer dependency.
        let cfg = ClientConfig {
            state_dir: dir.path().join("state"),
            vip: Some("100.64.0.5".parse().unwrap()),
            tun_name: "flocktest0".into(),
            mtu: 1280,
            endpoints: vec![],
            control_group: None,
            hostname: None,
            auth: None,
            general: Default::default(),
        };
        let state = connector::ClientState {
            device: flock_protocol::session::DeviceStaticKeys::generate(),
            pins: flock_protocol::trust::PinStore::new(),
            directory: empty_directory(),
        };

        let mock = Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = Arc::new(TunIo::from_arc(mock.clone()));

        // Injected endpoint paths (real transport, temporary placement).
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

        // Readiness probe: the token file lands on disk (IPC spawn follows
        // right after).
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !token_file.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "token not on disk within 10s (daemon not ready)"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let token = crate::ipc::load_token_file(&token_file).unwrap();

        // Status: Disconnected + vip (empty directory ⇒ supervise never
        // dialed).
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
                assert_eq!(ep, None, "empty directory ⇒ never dialed");
                assert_eq!(epoch, 0);
                assert!(uptime_secs < 60);
            }
            other => panic!("expected the Status variant, got {other:?}"),
        }

        // Wrong-token Shutdown ⇒ Denied, the daemon does not exit.
        let resp = request_once(&endpoint, CtrlReq::Shutdown { token: [0x33; 32] })
            .await
            .unwrap();
        assert_eq!(resp, crate::ipc::CtrlResp::Denied);

        // Right-token Shutdown ⇒ Ok + the main flow returns Ok + tun closed.
        let resp = request_once(&endpoint, CtrlReq::Shutdown { token })
            .await
            .unwrap();
        assert_eq!(resp, crate::ipc::CtrlResp::Ok);
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), daemon)
            .await
            .unwrap();
        assert!(out.is_ok(), "graceful shutdown returns Ok, got {out:?}");
        let mut buf = [0u8; 4];
        assert!(
            mock.read(&mut buf).is_err(),
            "tun closed (MockTunDevice read ⇒ NotConnected)"
        );
    }

    /// Empty root-signed directory (no endpoints ⇒ supervise idles; the root
    /// signature is not verified — supervise only takes the endpoint list).
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
