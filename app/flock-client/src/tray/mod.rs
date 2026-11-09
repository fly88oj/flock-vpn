//! Tray process core (docs/design.md §7-M6 phase two: the `flock-client
//! tray` user-session process).
//!
//! Responsibility split (consistent with the §7-M6.1 dual-process model: the
//! tray touches no keys/tun/data plane; it only queries status and triggers
//! exit over control IPC):
//! - **This module (platform-independent core, no GUI dependencies)**: menu
//!   text projection ([`menu_texts`] — localized via [`crate::lang`]), the
//!   token source ([`TokenSource`] — invalidated and reloaded after Denied,
//!   the recovery path for a daemon restart rotating the token), the 2s poll
//!   ([`poll_once`] — daemon absent/IPC failure ⇒ "service not running" and
//!   keep retrying), the exit action ([`request_exit`] — `Shutdown` with the
//!   token ⇒ the daemon shuts down gracefully + the tray exits; daemon
//!   absent ⇒ exit the tray only; `Denied` ⇒ stay running with a hint), the
//!   programmatic icon ([`icon`]), GUI-session detection
//!   ([`gui_session_present`]);
//! - **Platform backends** (`backend_native`: Windows/macOS tray-icon;
//!   `backend_ksni`: Linux ksni over DBus SNI): icon/menu placement and the
//!   event pump, consuming only this module's pure logic.
//!
//! Unit tests all live in the core layer (runnable on GUI-less hosts): every
//! projection branch/token roundtrip/poll recovery/exit action against an
//! IPC mock (real transport: a temporary named pipe or Unix socket).

#[cfg(target_os = "linux")]
mod backend_ksni;
#[cfg(any(target_os = "windows", target_os = "macos"))]
mod backend_native;
pub mod icon;

use std::path::PathBuf;
use std::time::Duration;

use crate::ipc::{self, ConnState, ControlPaths, CtrlReq, CtrlResp, CtrlToken};
use crate::lang::{Key, Lang};

/// Menu-refresh/status-poll period (2s — the requirement wording "poll
/// Status every 2s to refresh the texts").
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

// ============================================================================
// Menu text projection (Status snapshot → three text lines:
// status/VIP/tooltip; localized interactive copy)
// ============================================================================

/// Menu projection of `CtrlResp::Status` (epoch/uptime stay out of the menu
/// — the three items stay clean).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub state: ConnState,
    /// Local VIP (resolved at daemon startup ⇒ usually Some; None is the
    /// display-tolerance slot ⇒ show "—").
    pub vip: Option<String>,
    /// Current/most recent dialed endpoint (shown alongside when
    /// connected/connecting; not shown when disconnected).
    pub endpoint: Option<String>,
}

impl StatusSnapshot {
    /// Take the snapshot from a response; `Ok`/`Denied` (and future non-
    /// Status variants) ⇒ None (the caller projects "service not running" —
    /// under the v1 contract a Status request only ever gets
    /// Status/Denied).
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

/// The three menu/tooltip text lines ("connection status" and "VPN IP" are
/// dynamic read-only items; the tooltip mirrors the status summary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuTexts {
    pub status: String,
    pub vip: String,
    pub tooltip: String,
}

/// Status snapshot → menu texts (pure function; localized via the language
/// pack, all branches unit-tested).
///
/// - Snapshot missing (daemon absent/IPC failure/Denied) ⇒
///   "Connection: service not running" + "VPN IP: —";
/// - State labels: Connected⇒Connected, Connecting⇒Connecting,
///   Disconnected⇒Disconnected; connected/connecting carry an endpoint
///   suffix (" · frps-a:23000"), disconnected does not (endpoint = the most
///   recent one; menu brevity wins);
/// - `vip: None` ⇒ "VPN IP: —" (in any state).
pub fn menu_texts(view: Option<&StatusSnapshot>, lang: Lang) -> MenuTexts {
    let placeholder = "—";
    let Some(s) = view else {
        let down = lang.tr(Key::TrayServiceDown);
        return MenuTexts {
            status: lang.trf(Key::TrayStatusLine, &[&down]),
            vip: lang.trf(Key::TrayVipLine, &[&placeholder]),
            tooltip: lang.trf(Key::TrayTooltip, &[&down, &placeholder]),
        };
    };
    let state_label = match s.state {
        ConnState::Connected => lang.tr(Key::TrayStateConnected),
        ConnState::Connecting => lang.tr(Key::TrayStateConnecting),
        ConnState::Disconnected => lang.tr(Key::TrayStateDisconnected),
    };
    let ep_suffix = match s.state {
        ConnState::Connected | ConnState::Connecting => s
            .endpoint
            .as_deref()
            .map(|ep| format!(" · {ep}"))
            .unwrap_or_default(),
        ConnState::Disconnected => String::new(),
    };
    let state_with_ep = format!("{state_label}{ep_suffix}");
    let vip = s.vip.as_deref().unwrap_or(placeholder);
    MenuTexts {
        status: lang.trf(Key::TrayStatusLine, &[&state_with_ep]),
        vip: lang.trf(Key::TrayVipLine, &[&vip]),
        tooltip: lang.trf(Key::TrayTooltip, &[&state_with_ep, &vip]),
    }
}

// ============================================================================
// Token source (load-and-cache + invalidation reload after Denied)
// ============================================================================

/// Control-token source: the daemon rewrites the token file at every start —
/// reading it once would suffice, but after a **`Denied`** (daemon restart
/// rotated the token) it must be **invalidated and reloaded**, otherwise it
/// mismatches forever.
#[derive(Debug)]
pub struct TokenSource {
    path: PathBuf,
    cached: Option<CtrlToken>,
}

impl TokenSource {
    pub fn new(path: PathBuf) -> Self {
        TokenSource { path, cached: None }
    }

    /// Get the token: cache first, read the file when uncached (file
    /// missing/invalid content ⇒ None — the caller treats it as "daemon not
    /// running" and keeps retrying).
    pub fn load(&mut self) -> Option<CtrlToken> {
        if self.cached.is_none() {
            self.cached = ipc::load_token_file(&self.path).ok();
        }
        self.cached
    }

    /// Invalidate the cache (the next [`Self::load`] rereads the file).
    pub fn invalidate(&mut self) {
        self.cached = None;
    }
}

// ============================================================================
// Polling (one beat of the 2s cycle: query → project → log; no failure ever
// ends the loop)
// ============================================================================

/// Refresh diagnostic (English-only operational log line, independent of the
/// display language — derived from the snapshot, not from the localized
/// menu texts).
fn log_refresh(snapshot: Option<&StatusSnapshot>) {
    let state = match snapshot.map(|s| s.state) {
        Some(ConnState::Connected) => "connected",
        Some(ConnState::Connecting) => "connecting",
        Some(ConnState::Disconnected) => "disconnected",
        None => "down",
    };
    let vip = snapshot
        .and_then(|s| s.vip.clone())
        .unwrap_or_else(|| "-".into());
    eprintln!("flock-client tray: menu refresh | state={state} | vip={vip}");
}

/// One Status poll beat → menu texts.
///
/// - Token file unreadable ⇒ "service not running" (daemon not started / no
///   permission);
/// - Status snapshot ⇒ projected texts + refresh log;
/// - `Denied` ⇒ "service not running" + **token invalidated** (next beat
///   reloads — the recovery path after a daemon restart);
/// - IPC failure (connection refused/timeout) ⇒ "service not running" —
///   continuing to retry is the caller's periodic loop's job.
pub async fn poll_once(paths: &ControlPaths, tokens: &mut TokenSource, lang: Lang) -> MenuTexts {
    let Some(token) = tokens.load() else {
        let texts = menu_texts(None, lang);
        eprintln!(
            "flock-client tray: token file unreadable ({}) — daemon not running or no permission",
            paths.token_file.display()
        );
        return texts;
    };
    match ipc::request_once(&paths.endpoint, CtrlReq::Status { token }).await {
        Ok(resp) => match StatusSnapshot::of(&resp) {
            Some(snapshot) => {
                let texts = menu_texts(Some(&snapshot), lang);
                log_refresh(Some(&snapshot));
                texts
            }
            None => {
                if matches!(resp, CtrlResp::Denied) {
                    tokens.invalidate();
                    eprintln!(
                        "flock-client tray: Status denied (token mismatch — daemon restarted?) — \
                         token invalidated, reload next cycle"
                    );
                } else {
                    eprintln!(
                        "flock-client tray: unexpected response {resp:?} — showing \"service not \
                         running\""
                    );
                }
                menu_texts(None, lang)
            }
        },
        Err(e) => {
            eprintln!("flock-client tray: control plane unreachable: {e} (daemon not running?)");
            menu_texts(None, lang)
        }
    }
}

// ============================================================================
// Exit action (§7-M6.1 semantics: Shutdown = graceful stop without revival;
// the installation itself stays)
// ============================================================================

/// Exit-action verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDecision {
    /// The tray process exits (Shutdown accepted, or the daemon absent —
    /// "exit the tray only").
    ExitTray,
    /// The tray keeps running (`Denied`: the token mismatch was already
    /// reloaded; the user clicking "Quit" again retries).
    StayRunning,
}

/// The "Quit" menu action: send `Shutdown` to the daemon (with the token).
///
/// - Token file unreadable ⇒ daemon absent ⇒ **exit the tray only** (the
///   installation stays, semantics unchanged);
/// - `Ok` ⇒ the daemon shuts down gracefully (session down → data plane
///   stopped → tun torn down → exit) ⇒ the tray exits;
/// - `Denied` ⇒ do not exit + hint (token mismatch already invalidated and
///   reloaded — an old token is void after a daemon restart);
/// - IPC failure ⇒ daemon absent/already gone ⇒ exit the tray only (a tray
///   exit must not be held hostage by a nonexistent daemon);
/// - Unexpected response (future variants) ⇒ daemon state unknown but alive
///   — conservatively do not exit.
pub async fn request_exit(paths: &ControlPaths, tokens: &mut TokenSource) -> ExitDecision {
    let Some(token) = tokens.load() else {
        eprintln!(
            "flock-client tray: quit — daemon absent (token file unreadable), exiting the tray \
             only"
        );
        return ExitDecision::ExitTray;
    };
    match ipc::request_once(&paths.endpoint, CtrlReq::Shutdown { token }).await {
        Ok(CtrlResp::Ok) => {
            eprintln!(
                "flock-client tray: Shutdown accepted — daemon stopping gracefully; tray exiting \
                 (installation stays, autostart on next boot)"
            );
            ExitDecision::ExitTray
        }
        Ok(CtrlResp::Denied) => {
            tokens.invalidate();
            eprintln!(
                "flock-client tray: quit denied (token mismatch — daemon restarted?) — token \
                 reloaded, tray stays running (click \"Quit\" once more)"
            );
            ExitDecision::StayRunning
        }
        Ok(other) => {
            eprintln!(
                "flock-client tray: quit — daemon replied with an unexpected response {other:?}, \
                 tray stays running"
            );
            ExitDecision::StayRunning
        }
        Err(e) => {
            eprintln!(
                "flock-client tray: quit — control plane unreachable: {e} (daemon not running), \
                 exiting the tray only"
            );
            ExitDecision::ExitTray
        }
    }
}

// ============================================================================
// GUI-session detection (GUI-less host: the tray process exits gracefully
// with a clear log)
// ============================================================================

/// GUI-session verdict (pure truth table; the Linux runtime injects env/
/// filesystem probes; Windows/macOS make no up-front call — the
/// tray-creation-failure path backstops).
///
/// A GUI session requires both: (1) at least one of X11/Wayland present
/// (`DISPLAY` / `WAYLAND_DISPLAY`); (2) the session DBus available
/// (`DBUS_SESSION_BUS_ADDRESS` or `$XDG_RUNTIME_DIR/bus` — the ksni SNI
/// channel rides the session DBus; without it the tray has nowhere to sit).
pub fn gui_session_present(display: bool, wayland: bool, session_bus: bool) -> bool {
    (display || wayland) && session_bus
}

/// Linux runtime probe (env + existence of `$XDG_RUNTIME_DIR/bus`).
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
// Process entry point (the `tray` subcommand body; platform-backend
// dispatch)
// ============================================================================

/// Tray process entry point (called directly from main): endpoint/token take
/// the platform defaults (§7-M6.2); GUI absence and tray-creation failure
/// both **exit gracefully** (`Ok(())` — exit code 0, clear log on stderr);
/// only internal errors (thread/runtime creation failures, etc.) surface as
/// `Err` (exit code 2). Interactive menu copy renders through the language
/// pack ([`crate::lang`]).
pub fn run_tray(lang: Lang) -> Result<(), String> {
    let paths = ControlPaths::platform_default();
    #[cfg(windows)]
    let endpoint_disp = paths.endpoint.pipe_name.as_str();
    #[cfg(unix)]
    let endpoint_disp = paths.endpoint.socket_path.display().to_string();
    eprintln!(
        "flock-client tray: starting (control endpoint {endpoint_disp}, token file {})",
        paths.token_file.display()
    );
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        backend_native::run(&paths, lang)
    }
    #[cfg(target_os = "linux")]
    {
        backend_ksni::run(&paths, lang)
    }
}

// ============================================================================
// Unit tests (runnable on GUI-less hosts: projection pure functions +
// token roundtrip + real-transport IPC mock)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // —— Projection, all branches (default en + zh pack spot checks). ——

    /// All branches: Connected/Connecting/Disconnected/service-not-running;
    /// endpoint-suffix rules; vip None ⇒ "—".
    #[test]
    fn menu_texts_projection_all_branches() {
        // Service not running (None): status + VIP placeholder "—".
        let t = menu_texts(None, Lang::En);
        assert_eq!(t.status, "Connection: service not running");
        assert_eq!(t.vip, "VPN IP: —");
        assert_eq!(t.tooltip, "Flock VPN: service not running · VPN IP —");

        // Connected + endpoint + VIP (requirement-wording sample).
        let t = menu_texts(
            Some(&StatusSnapshot {
                state: ConnState::Connected,
                vip: Some("100.64.0.11".into()),
                endpoint: Some("frps-a:23000".into()),
            }),
            Lang::En,
        );
        assert_eq!(t.status, "Connection: Connected · frps-a:23000");
        assert_eq!(t.vip, "VPN IP: 100.64.0.11");
        assert_eq!(
            t.tooltip,
            "Flock VPN: Connected · frps-a:23000 · VPN IP 100.64.0.11"
        );

        // Connected but vip None (display-tolerance slot) ⇒ "VPN IP: —".
        let t = menu_texts(
            Some(&StatusSnapshot {
                state: ConnState::Connected,
                vip: None,
                endpoint: Some("a:1".into()),
            }),
            Lang::En,
        );
        assert_eq!(t.vip, "VPN IP: —");

        // Connecting: endpoint rides along; no endpoint ⇒ no suffix.
        let t = menu_texts(
            Some(&StatusSnapshot {
                state: ConnState::Connecting,
                vip: Some("100.64.0.2".into()),
                endpoint: Some("b:2".into()),
            }),
            Lang::En,
        );
        assert_eq!(t.status, "Connection: Connecting · b:2");
        let t = menu_texts(
            Some(&StatusSnapshot {
                state: ConnState::Connecting,
                vip: None,
                endpoint: None,
            }),
            Lang::En,
        );
        assert_eq!(t.status, "Connection: Connecting");
        assert_eq!(t.vip, "VPN IP: —");

        // Disconnected: the endpoint (most recent) stays out of the text;
        // VIP placeholder when absent.
        let t = menu_texts(
            Some(&StatusSnapshot {
                state: ConnState::Disconnected,
                vip: Some("100.64.0.3".into()),
                endpoint: Some("c:3".into()),
            }),
            Lang::En,
        );
        assert_eq!(t.status, "Connection: Disconnected");
        assert_eq!(t.vip, "VPN IP: 100.64.0.3");
    }

    /// zh pack: same projection shape with Chinese state labels (interactive
    /// copy follows `[general] language`). Asserted against the pack entries
    /// themselves — the pack's own content lives (and is literal-checked) in
    /// `lang::tests`; no Chinese literals here.
    #[test]
    fn menu_texts_projection_zh_pack() {
        let zh = Lang::Zh;
        let t = menu_texts(None, zh);
        // Composition: the status line is the pack template applied to the
        // pack's service-down label.
        assert_eq!(
            t.status,
            zh.trf(Key::TrayStatusLine, &[&zh.tr(Key::TrayServiceDown)])
        );
        assert!(t.vip.contains("—"));
        assert!(t.tooltip.contains(zh.tr(Key::TrayServiceDown)));
        // Localization actually switched (zh differs from the en default).
        assert_ne!(t.status, menu_texts(None, Lang::En).status);

        let t = menu_texts(
            Some(&StatusSnapshot {
                state: ConnState::Connected,
                vip: Some("100.64.0.11".into()),
                endpoint: Some("frps-a:23000".into()),
            }),
            zh,
        );
        assert!(t.status.contains(zh.tr(Key::TrayStateConnected)));
        assert!(t.status.contains("frps-a:23000"));
        assert!(t.vip.contains("100.64.0.11"));
        assert!(t.tooltip.contains(zh.tr(Key::TrayStateConnected)));
        assert_ne!(t.status, menu_texts(None, zh).status);
    }

    /// `StatusSnapshot::of`: takes fields from the Status variant;
    /// Ok/Denied ⇒ None (defensive branches).
    #[test]
    fn snapshot_of_extracts_status_variant_only() {
        let resp = CtrlResp::Status {
            state: ConnState::Connected,
            vip: Some("100.64.0.4".into()),
            endpoint: Some("d:4".into()),
            epoch: 9,
            uptime_secs: 100,
        };
        let snap = StatusSnapshot::of(&resp).expect("Status variant");
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

    /// GUI-session truth table: at least one of X11/Wayland + the session
    /// DBus — missing either means no GUI.
    #[test]
    fn gui_session_truth_table() {
        assert!(gui_session_present(true, false, true));
        assert!(gui_session_present(false, true, true));
        assert!(gui_session_present(true, true, true));
        assert!(!gui_session_present(true, false, false), "no session DBus");
        assert!(
            !gui_session_present(false, false, true),
            "no display server"
        );
        assert!(!gui_session_present(false, false, false));
    }

    // —— Token source. ——

    /// Token-source roundtrip: load-and-cache → invalidate → reread the new
    /// value; missing/invalid content ⇒ None.
    #[test]
    fn token_source_invalidate_reloads_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control-token");
        let mut src = TokenSource::new(path.clone());

        // File missing ⇒ None (no panic, no poisoned cache).
        assert!(src.load().is_none());

        // Write token A ⇒ loads and caches (a concurrent file change is not
        // seen — the cache is in effect).
        let a = ipc::generate_token();
        std::fs::write(&path, hex::encode(a)).unwrap();
        assert_eq!(src.load(), Some(a));
        let b = ipc::generate_token();
        std::fs::write(&path, hex::encode(b)).unwrap();
        assert_eq!(
            src.load(),
            Some(a),
            "cache wins (no reread before invalidation)"
        );

        // Invalidate ⇒ rereads B (the recovery path after a daemon restart
        // rotated the token).
        src.invalidate();
        assert_eq!(src.load(), Some(b));

        // Invalid content ⇒ None.
        src.invalidate();
        std::fs::write(&path, "zz-nothex").unwrap();
        assert!(src.load().is_none());
    }

    // —— Polling (real-transport IPC mock). ——
    //
    // Note: token files are always written directly via `std::fs::write(hex)`
    // rather than `ipc::write_token_file` — the latter lands an explicit
    // protective DACL on Windows (Users read-only), so a non-elevated test
    // process could not rewrite the file afterwards to simulate "daemon
    // restart rotated the token"; the ACL behavior is already covered by the
    // ipc module's tests, this group focuses on tray logic.

    /// Injected test endpoint (same shape as the service.rs integration
    /// tests: a Windows temporary named pipe / Unix temporary socket —
    /// creatable by a non-elevated host). Repeated calls each start an
    /// independent endpoint (a Windows-side sequence number avoids name
    /// collisions).
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

    /// Start a mock daemon (real transport + a fixed snapshot): returns
    /// (paths, server task).
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
            peers: None,
        });
        let server = ipc::spawn_server(&paths, None, ctrl).expect("start mock daemon IPC");
        (paths, server)
    }

    /// Poll recovery: daemon absent ⇒ "service not running", no panic; once
    /// the daemon is up, the same token source recovers the real texts; a
    /// token mismatch (Denied) ⇒ "service not running" + recovery via
    /// invalidation-reload.
    #[tokio::test]
    async fn poll_recovers_from_missing_denied_and_back() {
        let lang = Lang::En;
        let dir = tempfile::tempdir().unwrap();

        // (1) Daemon absent (token file missing): service not running + keep
        //     going (the function returning means "not terminated").
        let mut src = TokenSource::new(dir.path().join("absent-token"));
        let paths = ControlPaths {
            endpoint: temp_endpoint(),
            token_file: dir.path().join("absent-token"),
        };
        let texts = poll_once(&paths, &mut src, lang).await;
        assert_eq!(texts.status, "Connection: service not running");

        // (2) Mock daemon up + correct token ⇒ real snapshot texts.
        let token = ipc::generate_token();
        let (paths, server) = mock_daemon(dir.path(), token);
        let mut src = TokenSource::new(paths.token_file.clone());
        let texts = poll_once(&paths, &mut src, lang).await;
        assert_eq!(texts.status, "Connection: Connected · mock:27500");
        assert_eq!(texts.vip, "VPN IP: 100.64.0.9");

        // (3) Mismatched token (simulating a daemon restart rotating the
        //     token): Denied ⇒ service not running + token invalidated;
        //     after restoring the correct token file, the next beat
        //     recovers.
        let stale = ipc::generate_token();
        std::fs::write(&paths.token_file, hex::encode(stale)).unwrap();
        let mut src = TokenSource::new(paths.token_file.clone());
        let texts = poll_once(&paths, &mut src, lang).await;
        assert_eq!(
            texts.status, "Connection: service not running",
            "the Denied beat shows service-not-running"
        );
        std::fs::write(&paths.token_file, hex::encode(token)).unwrap();
        let texts = poll_once(&paths, &mut src, lang).await;
        assert_eq!(
            texts.status, "Connection: Connected · mock:27500",
            "recovers after token invalidation-reload"
        );

        // (4) Daemon stopped (IPC failure) ⇒ service not running (retry
        //     semantics carried by the periodic loop).
        server.abort();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let texts = poll_once(&paths, &mut src, lang).await;
        assert_eq!(texts.status, "Connection: service not running");
    }

    // —— Exit action (request ordering against the real-transport IPC
    //     mock). ——

    /// Exit ordering (IPC mock): `Denied` (token mismatch) ⇒ does not exit
    /// (StayRunning) and the daemon's shutdown hook does not fire; quit
    /// again with the correct token ⇒ `Shutdown` ⇒ hook fires + `Ok` ⇒
    /// ExitTray; daemon absent (no token file) ⇒ zero requests, tray exits
    /// directly.
    ///
    /// Ordering assertion surface: the mock daemon's shutdown hook runs
    /// **before** the response is written (serve_conn calls the hook before
    /// replying) — once `request_exit` returns, the record is readable with
    /// no extra synchronization.
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
            peers: None,
        });
        let server = ipc::spawn_server(&paths, None, ctrl).expect("start mock daemon IPC");

        // (1) Mismatched token file: the Shutdown request is rejected by the
        //     daemon's auth layer (Denied) ⇒ StayRunning (no exit, with the
        //     hint) — the shutdown hook must **not** fire (token
        //     verification precedes dispatch, §7-M6.2).
        let stale = ipc::generate_token();
        std::fs::write(&paths.token_file, hex::encode(stale)).unwrap();
        let mut src = TokenSource::new(paths.token_file.clone());
        assert_eq!(
            request_exit(&paths, &mut src).await,
            ExitDecision::StayRunning
        );
        assert!(
            log.lock().unwrap().is_empty(),
            "Denied must not trigger the daemon shutdown"
        );

        // (2) Fix the token file (invalidated reload) and quit again:
        //     Shutdown ⇒ hook fires + Ok ⇒ ExitTray.
        std::fs::write(&paths.token_file, hex::encode(token)).unwrap();
        assert_eq!(request_exit(&paths, &mut src).await, ExitDecision::ExitTray);
        assert_eq!(
            *log.lock().unwrap(),
            vec!["shutdown"],
            "exactly one Shutdown with the token, accepted (the hook fires before Ok is possible)"
        );

        // (3) Daemon absent (token file missing ⇒ zero requests sent) ⇒
        //     exit the tray only.
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
            "the exit action issues zero IPC requests when the daemon is absent (record unchanged)"
        );

        server.abort();
    }
}
