//! Control IPC v1 (docs/design.md §7-M6.2): the local control plane between
//! tray/CLI and the daemon.
//!
//! **Contract (consumer = the tray project of the next phase)**: postcard
//! over a local transport, frame format isomorphic to the §3.11 admin plane
//! — `[u32 LE len][postcard]` (len=0 or > [`MAX_CTRL_FRAME`] rejects the
//! frame); **one connection, one request-response** (one request frame → one
//! response frame → connection closed). Every request carries a token (the
//! same-named field on both [`CtrlReq`] variants), verification precedes
//! dispatch, and a mismatch yields [`CtrlResp::Denied`].
//!
//! Transport selection:
//! - **Windows named pipe** (`\\.\pipe\flock-client-control`):
//!   `tokio::net::windows::named_pipe` overlapped IO (tokio's official
//!   wrapper, overlapped handle + IOCP completion port, in the same
//!   scheduling domain as the existing tokio runtime; a synchronous thread
//!   pump is not chosen — multi-connection concurrency + graceful shutdown
//!   would require hand-managed thread pools and CancelIoEx lifetimes,
//!   complexity without benefit). Pipe instances are created with an
//!   explicit DACL (SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)`: SYSTEM +
//!   Administrators + interactive-user group), overriding the default DACL
//!   (which opens read to Everyone by default, see the CreateNamedPipeW
//!   docs).
//! - **Unix socket** (`/run/flock/client.sock`): `tokio::net::UnixListener`,
//!   chmod 0660 after bind (the path does not exist before bind and umask is
//!   uncontrollable ⇒ explicit chmod).
//!
//! Auth token: at every daemon start [`generate_token`] produces 32B, hex
//! text landed in [`ControlPaths::token_file`] (Windows explicit ACL:
//! SYSTEM/administrators full + Users read; Unix 0640 root, with a chgrp
//! attempt when a `control_group` is configured). Token comparison runs in
//! constant time (under local transport + DACL this is a defense-in-depth
//! position, not the primary boundary).

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Single-frame cap (v1 was 4KiB; the M7 `Peers` roster surface raised it to
/// 256KiB — headroom for a thousand-row roster at ~64B/row, still far below
/// the control plane's 256KiB record-layer cap; the defensive stance is
/// unchanged: over-limit frames are rejected).
pub const MAX_CTRL_FRAME: usize = 256 * 1024;
/// Whole-chain timeout for a client one-shot request (connect + round trip;
/// the default for status/tray polling).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
/// Whole-chain timeout for `Peers` requests (roster pull + 3 probes × 2s
/// timeout serial ⇒ ceiling ~10s, plus margin).
pub const PEERS_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Whole-chain timeout for serving one connection (review item 4: a peer
/// that connects but never sends/receives frames must not hold a pipe
/// instance forever — disconnect and release on timeout). 10s is
/// self-consistent for the heaviest Peers path: the internal roster pull's
/// [`crate::ctrl::CTRL_REQ_TIMEOUT`] of 10s errors out at the deadline (no
/// stacking), pings run concurrently ≤6s, typical completion <10s; in the
/// razor-thin race where the pull errors exactly at the 10s mark, the client
/// sees a broken pipe (synonymous with the timeout).
pub const SERVE_CONN_TIMEOUT: Duration = Duration::from_secs(10);
/// Backoff for transient accept/connect errors (review item 4: no log
/// flooding spin under sustained transient pressure).
pub const ACCEPT_RETRY_BACKOFF: Duration = Duration::from_millis(250);

// ============================================================================
// Contract types (v1 — the tray project's consumption surface; changing
// fields breaks the contract; M7 adds the Peers surface)
// ============================================================================

/// Control-plane auth token (32B random, generated at every daemon start).
pub type CtrlToken = [u8; 32];

/// v1 control request (every variant carries a token: authentication
/// precedes dispatch, §7-M6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtrlReq {
    /// Query status (idempotent, no side effects).
    Status { token: CtrlToken },
    /// Graceful shutdown (teardown: session → data plane → tun → process
    /// exit; the service manager does not revive it).
    Shutdown { token: CtrlToken },
    /// Member roster (M7 §7-M7.7): the daemon assembles the enhanced roster
    /// (pull/≤5s cache + ping probing).
    Peers { token: CtrlToken },
}

/// Connection state (the supervise projection of `flock-client service`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnState {
    Connected,
    Connecting,
    Disconnected,
}

/// v1 control response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtrlResp {
    /// Status snapshot (the response to a Status request).
    Status {
        state: ConnState,
        /// Local VIP (resolved at startup ⇒ Some; Option is the
        /// display-tolerance slot).
        vip: Option<String>,
        /// Current/most recent dialed endpoint.
        endpoint: Option<String>,
        /// Current session key epoch (advanced by rekey; no session ⇒ 0).
        epoch: u64,
        /// Seconds since the daemon started.
        uptime_secs: u64,
    },
    /// Shutdown accepted.
    Ok,
    /// Member roster (M7 §7-M7.7; VIP-ascending — the server-side assembly
    /// order).
    Peers { rows: Vec<crate::peers::PeerRow> },
    /// Roster unavailable (M7: not logged in / tunnel down / no [auth]
    /// configured, etc. — `reason` feeds the CLI guidance text).
    PeersUnavailable { reason: String },
    /// Wrong token (any request).
    Denied,
}

// ============================================================================
// Frame codec (isomorphic with the §3.11 admin plane)
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
// Daemon side
// ============================================================================

/// Daemon-side control-plane dependencies (injected by the service
/// assembly; snapshot source + shutdown trigger + roster assembly).
pub struct DaemonControl {
    /// The pass token (comparison baseline on the request side).
    pub token: CtrlToken,
    /// Status snapshot (must return the [`CtrlResp::Status`] variant; the
    /// IPC task calls it concurrently ⇒ Send+Sync).
    pub status: std::sync::Arc<dyn Fn() -> CtrlResp + Send + Sync>,
    /// Shutdown trigger (invoked synchronously before the accepted Shutdown
    /// returns; the actual teardown is done by the service main flow).
    pub shutdown: std::sync::Arc<dyn Fn() + Send + Sync>,
    /// Roster assembly (M7 §7-M7.7: pull/cache + ping probing; None = not
    /// assembled — no [auth] config/test injection surface ⇒
    /// PeersUnavailable).
    pub peers: Option<std::sync::Arc<dyn Fn() -> BoxFuture<'static, CtrlResp> + Send + Sync>>,
}

/// Constant-time comparison (unequal lengths fail immediately — the token is
/// a fixed 32B, no length-leak surface).
fn token_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = a.len() ^ b.len();
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

/// accept/connect loop error classification (review item 4).
///
/// - **Transient** (log + back off via [`ACCEPT_RETRY_BACKOFF`] then
///   continue — do not kill the IPC task): fd exhaustion (EMFILE/ENFILE —
///   process-level resource pressure), WouldBlock/Interrupted,
///   ConnectionAborted/ConnectionReset (peer vanished mid-flight), the
///   Windows pipe's first-connect NotConnected (ERROR_NO_DATA: the client
///   connected then dropped immediately, instance reusable) and the next
///   instance creation ERROR_PIPE_BUSY (231, AllPipeInstancesBusy —
///   instances in flight, creatable once existing connections complete);
/// - **Fatal** (the rest: listener/pipe broken, permissions, programming
///   errors) ⇒ the loop returns and bubbles up, noticed by the daemon main
///   flow via the IPC task's conclusion (the select arms in service.rs).
pub fn accept_error_is_transient(e: &io::Error) -> bool {
    use io::ErrorKind as K;
    if matches!(
        e.kind(),
        K::WouldBlock
            | K::Interrupted
            | K::ConnectionAborted
            | K::ConnectionReset
            | K::NotConnected
    ) {
        return true;
    }
    // Windows: ERROR_PIPE_BUSY (231) — pipe instances exhausted in flight
    // (AllPipeInstancesBusy).
    #[cfg(windows)]
    if e.raw_os_error() == Some(231) {
        return true;
    }
    // Unix: EMFILE(24)/ENFILE(23) — same values on linux/macos (no libc
    // dependency surface; fd exhaustion is process-level transient pressure,
    // recovers after backoff once existing connections release).
    #[cfg(unix)]
    if matches!(e.raw_os_error(), Some(24) | Some(23)) {
        return true;
    }
    false
}

/// Serve one connection: read one request frame → authenticate → dispatch →
/// write one response frame (the whole chain bounded by
/// [`SERVE_CONN_TIMEOUT`] — review item 4: a connection that sends no frame
/// or reads none must not hold a pipe instance forever; disconnect and
/// release on timeout).
///
/// Transport-layer generic (mock duplex for the unit-test surface); a
/// malformed frame ⇒ io error closing the connection, no response.
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
                    reason: "daemon has no peers handler assembled (client.toml missing \
                             [auth]?)"
                        .into(),
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
            "control connection whole-chain timeout (10s — a connection that neither sends nor \
             receives frames is disconnected and its instance released)",
        )),
    }
}

/// Control-plane endpoint (platform transport address; tests inject
/// temporary paths).
#[derive(Debug, Clone)]
pub struct IpcEndpoint {
    /// Windows: named pipe name (`\\.\pipe\...`).
    #[cfg(windows)]
    pub pipe_name: String,
    /// Unix: socket path.
    #[cfg(unix)]
    pub socket_path: PathBuf,
}

/// Control-plane placement paths (§7-M6.2 table; `platform_default` takes
/// the system constants, tests inject).
#[derive(Debug, Clone)]
pub struct ControlPaths {
    pub endpoint: IpcEndpoint,
    pub token_file: PathBuf,
}

/// Windows named-pipe name constant.
#[cfg(windows)]
pub const PIPE_NAME: &str = r"\\.\pipe\flock-client-control";
/// Unix socket path constant.
#[cfg(unix)]
pub const SOCKET_PATH: &str = "/run/flock/client.sock";
/// Unix token file path constant.
#[cfg(unix)]
pub const TOKEN_FILE: &str = "/var/lib/flock/client/control-token";
/// Windows token file path relative to %ProgramData%.
#[cfg(windows)]
pub const TOKEN_FILE_REL: &str = r"flock\control-token";

impl ControlPaths {
    /// Platform-default placement (§7-M6.2 table).
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

/// Start the IPC server (accept loop + one task per connection; returns the
/// JoinHandle for the daemon to abort at teardown).
///
/// Unix: mkdir -p the parent before bind (0755), chmod 0660 after bind (with
/// a chgrp attempt when `control_group` is set — failure is a warning only;
/// the out-of-the-box default is root:root). Windows: DACL in the module
/// docs.
pub fn spawn_server(
    paths: &ControlPaths,
    group: Option<&str>,
    ctrl: std::sync::Arc<DaemonControl>,
) -> io::Result<tokio::task::JoinHandle<()>> {
    #[cfg(windows)]
    {
        let _ = group; // On the Windows side, group semantics are carried by the pipe DACL's IU; the token file ACL does no grouping.
        crate::ipc_windows::spawn_named_pipe_server(&paths.endpoint.pipe_name, ctrl)
    }
    #[cfg(unix)]
    {
        crate::ipc_unix::spawn_unix_server(&paths.endpoint.socket_path, group, ctrl)
    }
}

/// Atomic private-file placement on Unix (review item 3: eliminates the
/// "first `fs::write` (umask default permissions), then chmod" window —
/// within that window the secret is readable at default permissions).
///
/// - First write: `OpenOptions::create_new` + `mode` — the file is **born
///   with the target permissions** (open carries the mode atomically, no
///   umask window);
/// - Already exists (rewrite): a temp file in the same directory (same-mode
///   `create_new`), then `rename` over it once written. Selection note (vs
///   "tighten the old file's permissions first, then truncate-rewrite"):
///   rename is an atomic replacement within the same filesystem — neither a
///   default-permissions window for the new content nor a truncation window
///   (on a crash, the disk holds either the complete old file or the
///   complete new one; a truncate-rewrite crash loses the credentials'
///   content). For files where "lost content = lockout, leaked content =
///   compromise" (credentials/tokens), recoverability wins.
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
            // Rewrite: tempfile (same mode) → rename atomic replacement
            // (selection notes in the function docs). Same directory ⇒ same
            // filesystem; the name carries an in-process sequence number to
            // avoid colliding concurrent writers.
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
            drop(f); // Close/flush to disk before replacing (rename does not carry unflushed buffers).
            std::fs::rename(&tmp, path)
        }
        Err(e) => Err(e),
    }
}

// ============================================================================
// Token generation and placement
// ============================================================================

/// Generate a 32B random token (called at every daemon start).
pub fn generate_token() -> CtrlToken {
    flock_protocol::rand::random()
}

/// Write the token file: hex text (64 chars, human-inspectable).
///
/// Permissions (§7-M6.2): Windows explicit ACL (SYSTEM/administrators full +
/// Users read); Unix 0640 ([`write_file_private`] — born 0640, no
/// default-permissions window; review item 3); when `group` is given, a
/// chgrp is attempted (resolution failure / no permission is a warning only
/// — "best-effort" semantics).
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
                        eprintln!(
                            "flock-client: warning: token file chgrp {gname}({gid}) failed: {e}"
                        );
                    }
                }
                None => eprintln!(
                    "flock-client: warning: control_group {gname:?} could not be resolved to a \
                     gid (only the local /etc/group and numeric gids are consulted) — token \
                     stays root:root"
                ),
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = group;
        if let Err(e) = crate::ipc_windows::set_file_acl_users_read(path) {
            eprintln!(
                "flock-client: warning: token file ACL setup failed (inherited ACL kept): {e}"
            );
        }
    }
    Ok(())
}

/// Read the token file (hex text → 32B; used by the status subcommand).
pub fn load_token_file(path: &Path) -> io::Result<CtrlToken> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| io::Error::other(format!("read {}: {e}", path.display())))?;
    let bytes = hex::decode(text.trim())
        .map_err(|e| io::Error::other(format!("{}: content is not hex: {e}", path.display())))?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| io::Error::other(format!("{}: expected a 32B token", path.display())))
}

/// Unix: group name → gid (only the local /etc/group and numeric gids; NSS
/// directories are out of scope — failure = warning, not blocking).
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
// Client side (tray polling / status subcommand)
// ============================================================================

/// Send one request and receive one response over an established connection
/// (transport-generic; duplex mock for the unit-test surface).
pub async fn request_over<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    req: &CtrlReq,
) -> io::Result<CtrlResp> {
    send_frame(io, req).await?;
    recv_frame(io).await
}

/// One-shot request (connect + round trip, the whole chain bounded by
/// [`REQUEST_TIMEOUT`]).
///
/// Short retry when the Windows pipe is busy (server instances momentarily
/// exhausted); Unix returns connect failures directly (daemon not running ⇒
/// socket absent, semantics left to the caller).
pub async fn request_once(endpoint: &IpcEndpoint, req: CtrlReq) -> io::Result<CtrlResp> {
    request_once_timeout(endpoint, req, REQUEST_TIMEOUT).await
}

/// Timeout-injectable form of [`request_once`] (`Peers` uses
/// [`PEERS_REQUEST_TIMEOUT`] — the probing surface far exceeds the default
/// 3s).
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
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control request timed out"))?
}

// ============================================================================
// Unit tests (transport-layer mock: tokio::io::duplex loopback — contract
// roundtrip/token rejection/Denied paths)
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

    /// Contract roundtrip: Status request → Status snapshot (field by
    /// field).
    #[tokio::test]
    async fn ctrl_roundtrip_status_over_duplex() {
        let token = generate_token();
        let (ctrl, _) = daemon_control(token);
        let (mut client, mut server) = duplex(4096);
        let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });

        let resp = request_over(&mut client, &CtrlReq::Status { token })
            .await
            .expect("roundtrip");
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

    /// Token rejection: a wrong-token Status ⇒ Denied (no behavior beyond
    /// the snapshot's side-effect-free surface).
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

    /// Shutdown path: right token ⇒ fires the shutdown hook + replies Ok;
    /// wrong token ⇒ Denied and does not fire.
    #[tokio::test]
    async fn shutdown_replies_ok_and_fires_hook_only_with_token() {
        let token = generate_token();
        // Wrong token: Denied, hook not fired.
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
                "a wrong token must not trigger shutdown"
            );
            served.await.unwrap().unwrap();
        }
        // Right token: Ok + hook fired.
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
                "the right token must trigger shutdown"
            );
            served.await.unwrap().unwrap();
        }
    }

    /// Malformed frame (not postcard): connection closed, no response bytes
    /// (the client sees EOF/broken pipe).
    #[tokio::test]
    async fn malformed_frame_closes_without_response() {
        let (ctrl, _) = daemon_control(generate_token());
        let (mut client, mut server) = duplex(4096);
        let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
        // A legal frame header + garbage payload (varint variant overflow/
        // truncation ⇒ postcard decode error).
        client.write_all(&4u32.to_le_bytes()).await.unwrap();
        client.write_all(&[0xff, 0xff, 0xff, 0xff]).await.unwrap();
        let mut buf = [0u8; 8];
        match client.read(&mut buf).await {
            Ok(0) | Err(_) => {} // EOF (server dropped) or broken pipe — both mean "no response".
            Ok(n) => panic!("a malformed frame must not get a response, yet read {n} bytes"),
        }
        served
            .await
            .unwrap()
            .expect_err("the server must report a decode error");
    }

    /// Oversized frame header (len > MAX_CTRL_FRAME) is rejected.
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
            Ok(n) => panic!("an oversized frame must not get a response, yet read {n} bytes"),
        }
        served
            .await
            .unwrap()
            .expect_err("an oversized frame must error");
    }

    /// Token file roundtrip (write → permissions → read back identical).
    #[tokio::test]
    async fn token_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("control-token");
        let token = generate_token();
        write_token_file(&path, &token, None).expect("write token file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o640, "Unix token file is 0640");
        }
        assert_eq!(load_token_file(&path).unwrap(), token);
        // Invalid content rejected on read (separate file — after the Windows
        // explicit ACL, the original is read-only for Users).
        let bad = dir.path().join("bad-token");
        std::fs::write(&bad, "zz-nothex").unwrap();
        assert!(load_token_file(&bad).is_err());
    }

    /// Review item 3: token rewrite path — an existing loose-permission
    /// (0666) file gets replaced with 0640 + the new token reads back
    /// identical (tempfile born 0640, rename lands atomically — no
    /// default-permissions window).
    #[cfg(unix)]
    #[tokio::test]
    async fn token_file_overwrite_replaces_loose_perm_file_with_0640() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control-token");
        std::fs::write(&path, "stale").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let token = generate_token();
        write_token_file(&path, &token, None).expect("rewrite token file");
        assert_eq!(load_token_file(&path).unwrap(), token, "new token in place");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640,
            "0640 after the rewrite"
        );
    }

    /// Constant-time comparison: equal-length different values ⇒ false;
    /// equal values ⇒ true (behavioral surface; the timing surface is
    /// guaranteed by the implementation).
    #[test]
    fn token_eq_semantics() {
        let a = [1u8; 32];
        assert!(token_eq(&a, &a));
        let mut b = a;
        b[31] ^= 1;
        assert!(!token_eq(&a, &b));
        assert!(!token_eq(&[0u8; 32], &[1u8; 32]));
    }

    /// Review item 4: error classification — the transient set
    /// (WouldBlock/Interrupted/ConnAborted/ConnReset/pipe first-connect
    /// NotConnected/EMFILE/ENFILE (unix)/ERROR_PIPE_BUSY 231 (windows)) logs,
    /// backs off, continues; the rest (PermissionDenied/EBADF, etc.) is
    /// fatal and bubbles up.
    #[test]
    fn accept_error_classification() {
        // —— Transient (ErrorKind surface, all platforms). ——
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::NotConnected,
        ] {
            assert!(
                accept_error_is_transient(&io::Error::from(kind)),
                "{kind:?} should be transient"
            );
        }
        // —— Fatal (other kinds / raw codes). ——
        assert!(
            !accept_error_is_transient(&io::Error::from(io::ErrorKind::PermissionDenied)),
            "permission errors are fatal"
        );
        assert!(
            !accept_error_is_transient(&io::Error::from_raw_os_error(9)),
            "EBADF (broken listener surface) is fatal"
        );
        // —— Platform raw-code surfaces. ——
        #[cfg(unix)]
        {
            // EMFILE=24/ENFILE=23 (same values on linux/macos) — fd
            // exhaustion is transient.
            assert!(accept_error_is_transient(&io::Error::from_raw_os_error(24)));
            assert!(accept_error_is_transient(&io::Error::from_raw_os_error(23)));
            // Other raw codes (e.g. EACCES=13) are fatal.
            assert!(!accept_error_is_transient(&io::Error::from_raw_os_error(
                13
            )));
        }
        #[cfg(windows)]
        {
            // ERROR_PIPE_BUSY=231 (AllPipeInstancesBusy — instances in
            // flight) is transient; ERROR_ACCESS_DENIED=5 is fatal.
            assert!(accept_error_is_transient(&io::Error::from_raw_os_error(
                231
            )));
            assert!(!accept_error_is_transient(&io::Error::from_raw_os_error(5)));
        }
    }

    /// Review item 4: a client that never frames ⇒ serve_conn errors out on
    /// the whole-chain timeout (TimedOut) — the pipe instance is not held
    /// (10s advance instantly under the paused clock).
    #[tokio::test(start_paused = true)]
    async fn serve_conn_times_out_when_client_never_frames() {
        let (ctrl, _) = daemon_control(generate_token());
        let (client, mut server) = duplex(4096);
        let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
        // The client's connection is in place but sends no bytes: the
        // server's 10s whole-chain timeout (auto-advanced paused clock).
        let res = tokio::time::timeout(Duration::from_secs(15), served)
            .await
            .expect("the timeout must fire within the 10s whole-chain budget")
            .unwrap();
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::TimedOut);
        drop(client);
    }

    /// M7: Peers contract roundtrip — right token ⇒ enhanced roster rows
    /// (with latency/self); wrong token ⇒ Denied; no peers handler assembled
    /// ⇒ PeersUnavailable.
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
        // (1) Right token ⇒ Peers{rows} (field-by-field roundtrip).
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
                other => panic!("expected the Peers variant, got {other:?}"),
            }
            served.await.unwrap().unwrap();
        }
        // (2) Wrong token ⇒ Denied.
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
        // (3) No peers handler assembled ⇒ PeersUnavailable (reason
        //     non-empty).
        {
            let (ctrl, _) = daemon_control(token);
            let (mut client, mut server) = duplex(4096);
            let served = tokio::spawn(async move { serve_conn(&mut server, &ctrl).await });
            let resp = request_over(&mut client, &CtrlReq::Peers { token })
                .await
                .unwrap();
            match resp {
                CtrlResp::PeersUnavailable { reason } => assert!(!reason.is_empty()),
                other => panic!("expected PeersUnavailable, got {other:?}"),
            }
            served.await.unwrap().unwrap();
        }
    }
}
