//! Client half of the control stream (M7, docs/design.md §7-M7.7 / §2.2 / §3.4).
//!
//! The server control plane (login/tickets/key-bind/roster) previously had
//! only the client role compensated by server tests; this module adds the
//! production client half, reusing the [`flock_protocol::roster`] wire types
//! throughout (M7 uplift — same types on both ends):
//!
//! - [`ControlPlane`]: the **shared slot** for the current session's control
//!   stream — supervise installs/removes it per session; business tasks
//!   (login keepalive/roster pull) reuse it serially via
//!   [`ControlPlane::request`]. A request timeout ⇒ the slot is poisoned +
//!   the session is killed proactively to reconnect (a yamux stream may be
//!   misaligned after a timeout — reconnect rather than continue misaligned:
//!   the "no silent fault tolerance" discipline).
//! - [`login_and_bind`]: Hello → OPAQUE login (anchor verification: anchored
//!   on the pinned-directory entry identity, §1.3.3f/§3.4) → ticket (**memory
//!   only**) → key-bind (device signature carries the hostname — the
//!   re-register update path, §7-M7.1).
//! - [`set_password_once`]: PwBegin/PwCommit (authorization = session device
//!   owner; used by the `login` subcommand for first-time setup — the admin
//!   plane has no account-password operation, password setting goes over the
//!   control stream by design, §2.2).
//! - The credentials file (0600, one password line) and the SR-SIG1 user
//!   key placement.
//!
//! Testability: business flows go through the [`CtrlTransport`] abstraction —
//! production = the yamux control stream inside the tunnel; unit tests = a
//! mock transport + the `flock-protocol` pake **both-sides** functions run
//! in memory (real anchor signing/verification, real ke3 checks).

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

/// Control-stream single-request timeout (login includes the client-side
/// argon2 derivation, relaxed to 10s).
pub const CTRL_REQ_TIMEOUT: Duration = Duration::from_secs(10);
/// Retry backoff after a login failure (rejection class — wrong password / no
/// ticket privilege).
pub const LOGIN_RETRY_BACKOFF: Duration = Duration::from_secs(5);
/// Credentials file name inside the state directory (path overridable via
/// `[auth] credentials_file`).
pub const CREDENTIALS_FILE: &str = "credentials";
/// SR-SIG1 user key seed file name inside the state directory (key-bind
/// registration; 0600).
pub const SR_SIG_KEY_FILE: &str = "sr-sig.key";

// ============================================================================
// Control-stream transport abstraction (same business flow in prod and tests)
// ============================================================================

/// Control-stream transport (one request, one response, serial — aligned with
/// the "request → response" stepping of the wire protocol).
pub trait CtrlTransport {
    fn request(
        &self,
        req: CtrlRequest,
    ) -> Pin<Box<dyn Future<Output = io::Result<CtrlResponse>> + Send + '_>>;
}

/// Shared yamux control stream (in place for the session's lifetime).
type SharedStream = std::sync::Arc<tokio::sync::Mutex<mux::Stream>>;

/// Shared slot for the current session's control stream (supervise ↔
/// business tasks).
///
/// Lifecycle: supervise [`install`](Self::install)s on every session
/// establishment, [`remove`](Self::remove)s on data-plane end/poisoning;
/// business tasks [`request`](Self::request) against the current stream,
/// serially. Session presence is observed via a watch channel (the login
/// keepalive task waits for "session up" before logging in).
#[derive(Clone)]
pub struct ControlPlane {
    inner: std::sync::Arc<PlaneInner>,
}

struct PlaneInner {
    stream: std::sync::Mutex<Option<SharedStream>>,
    up_tx: tokio::sync::watch::Sender<bool>,
    /// Resident receiver (a watch `send` drops the value when there are "zero
    /// receivers" — a transient subscriber's is_up would open that window;
    /// holding a resident receiver eliminates it).
    up_rx: tokio::sync::watch::Receiver<bool>,
    /// Session poisoned (request timeout) ⇒ kill the session proactively
    /// (supervise selects on this signal to end the data plane early).
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

    /// Session established: install the control stream (called by supervise).
    pub fn install(&self, stream: mux::Stream) {
        self.install_arc(std::sync::Arc::new(tokio::sync::Mutex::new(stream)));
    }

    /// Shared-handle form of [`install`](Self::install) (supervise holds the
    /// same handle — session end can precede Drop).
    pub fn install_arc(&self, shared: SharedStream) {
        *self.inner.stream.lock().expect("plane poisoned") = Some(shared);
        let _ = self.inner.up_tx.send(true);
    }

    /// Session ended: take out and drop (called by supervise; in-flight
    /// requests hold clones and continue until IO failure).
    pub fn remove(&self) {
        *self.inner.stream.lock().expect("plane poisoned") = None;
        let _ = self.inner.up_tx.send(false);
    }

    /// Whether a session is in place (snapshot value).
    pub fn is_up(&self) -> bool {
        *self.inner.up_rx.borrow()
    }

    /// Wait for a session to be in place (returns immediately when already
    /// true; false→true edges observed via the watch).
    pub async fn wait_up(&self) {
        let mut rx = self.inner.up_rx.clone();
        loop {
            if *rx.borrow_and_update() {
                return;
            }
            if rx.changed().await.is_err() {
                // The sender lives as long as the plane — unreachable;
                // defensive suspend instead of spinning.
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    /// Wait for the session to be gone (the login keepalive task watches for
    /// disconnection while the ticket is valid; returns immediately when
    /// already false).
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

    /// Session-poisoned signal (raised by [`Self::request`] after a request
    /// timeout; supervise selects on it to reconnect early).
    pub async fn killed(&self) {
        self.inner.kill.notified().await
    }

    /// The current stream (None = no session).
    fn current(&self) -> Option<SharedStream> {
        self.inner.stream.lock().expect("plane poisoned").clone()
    }

    /// Poison: clear the slot + kill the session (the stream may be
    /// misaligned after a timeout — do not continue misaligned; reconnect
    /// for a fresh stream).
    fn poison(&self, why: &str) {
        eprintln!("flock-client: control stream poisoned ({why}) => proactive reconnect");
        *self.inner.stream.lock().expect("plane poisoned") = None;
        let _ = self.inner.up_tx.send(false);
        self.inner.kill.notify_one();
    }

    /// Send one request and receive one response on the current session's
    /// control stream (in-flight mutex within the session ⇒ serial).
    pub async fn request(&self, req: CtrlRequest) -> io::Result<CtrlResponse> {
        self.request_timeout(req, CTRL_REQ_TIMEOUT).await
    }

    /// Timeout-injectable form of [`request`](Self::request) (tests use a
    /// short timeout to reproduce the poisoning path).
    pub async fn request_timeout(
        &self,
        req: CtrlRequest,
        timeout: Duration,
    ) -> io::Result<CtrlResponse> {
        let stream = self
            .current()
            .ok_or_else(|| io::Error::other("control stream not ready (tunnel not connected)"))?;
        let mut g = stream.lock().await;
        let r = tokio::time::timeout(timeout, async {
            send_ctrl_msg(&mut *g, &req).await?;
            recv_ctrl_msg(&mut *g).await
        })
        .await;
        match r {
            Ok(res) => res,
            Err(_) => {
                // Timeout: the response may arrive late ⇒ misalignment risk.
                // Poison and kill the session; retry after reconnecting.
                drop(g);
                self.poison("request timeout");
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "control stream request timed out",
                ))
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

/// Exclusive control-stream transport (for the one-shot `login` command — no
/// daemon/shared slot; a timeout is a plain error, no poisoning: the command
/// process exits right after and Drop tears the session down).
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
            r.map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "control stream request timed out")
            })?
        })
    }
}

// ============================================================================
// Login parameters and outcome
// ============================================================================

/// Full inputs for one login (shared by the daemon keepalive task and the
/// `login` subcommand).
pub struct AuthParams {
    pub username: String,
    pub password: String,
    /// Reported hostname (already aligned with server semantics via
    /// [`normalize_hostname`]).
    pub hostname: String,
    pub device: DeviceStaticKeys,
    pub cluster_id: ClusterId,
    pub directory: ClusterDirectory,
    /// SR-SIG1 user key (key-bind registration; `login_and_bind` uses only
    /// its public side).
    pub sr_key: UserKey,
}

/// Login success artifact (ticket **memory only** — invalid once the process
/// exits, §2.2).
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    pub ticket: TicketWire,
    pub epoch: u64,
    pub device_id: [u8; 32],
    pub vip: [u8; 4],
    pub server_id: [u8; 16],
    /// Suggested wait until the next re-login (2/3 of the TTL — scheduling on
    /// the TTL rather than the absolute exp is immune to clock skew on either
    /// end).
    pub refresh_after: Duration,
}

/// Login failure (Io = session/transport layer; Refused = server rejection or
/// local OPAQUE failure).
#[derive(Debug)]
pub enum LoginError {
    Io(io::Error),
    Refused(String),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::Io(e) => write!(f, "control stream IO: {e}"),
            LoginError::Refused(m) => write!(f, "login refused: {m}"),
        }
    }
}

fn refused<M: Into<String>>(m: M) -> LoginError {
    LoginError::Refused(m.into())
}

/// Extract a readable description from [`CtrlResponse::Err`].
///
/// The unexpected-response branch prints only the **variant name** (review
/// item 8): `{other:?}` would drag the whole payload into error strings/logs
/// — the ticket (TicketWire) carried by `LoginOk`/`TicketRenewed`, the ke2 of
/// `LoginChallenge`, the directory bytes of `Directory` and other sensitive
/// payloads must not appear in log output.
fn describe_err(resp: CtrlResponse) -> String {
    match resp {
        CtrlResponse::Err { code, msg } => format!("{code:?}: {msg}"),
        other => format!("unexpected response: {}", ctrl_response_variant(&other)),
    }
}

/// Variant name of an unexpected response (zero payload in logs).
fn ctrl_response_variant(r: &CtrlResponse) -> &'static str {
    match r {
        CtrlResponse::Hello { .. } => "Hello",
        CtrlResponse::PwChallenge { .. } => "PwChallenge",
        CtrlResponse::Ok => "Ok",
        CtrlResponse::LoginChallenge { .. } => "LoginChallenge",
        CtrlResponse::LoginOk { .. } => "LoginOk",
        CtrlResponse::KeyBound { .. } => "KeyBound",
        CtrlResponse::TicketRenewed { .. } => "TicketRenewed",
        CtrlResponse::Redeemed { .. } => "Redeemed",
        CtrlResponse::DeviceList { .. } => "DeviceList",
        CtrlResponse::Directory { .. } => "Directory",
        CtrlResponse::PeerList { .. } => "PeerList",
        CtrlResponse::Err { .. } => "Err",
    }
}

// ============================================================================
// Login → key-bind (carrying the hostname)
// ============================================================================

/// OPAQUE login (anchor verification) + key-bind (hostname reporting).
///
/// Steps (§2.2/§3.4/§7-M7.1):
/// 1. Hello — verify cluster_id matches the pinned directory (anti
///    cross-cluster);
/// 2. LoginBegin/LoginFinish — the anchor signature is verified against the
///    **identity public key of that server inside the pinned directory**
///    (`Hello.server_id` → directory entry; not registered ⇒ reject);
/// 3. LoginOk — ticket into memory;
/// 4. KeyBind — device signature covers cluster‖user‖bind_token‖pubkeys‖
///    hostname‖SR-SIG1 public key (same-device re-register ⇒ the server
///    updates the hostname, VIP unchanged).
pub async fn login_and_bind<T: CtrlTransport + ?Sized>(
    t: &T,
    p: &AuthParams,
) -> Result<LoginOutcome, LoginError> {
    // (1) Hello + cluster consistency.
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
            "server cluster {cluster_id:02x?} != pinned directory {}",
            hex::encode(p.cluster_id.0)
        )));
    }
    // Anchor = the identity public key of this server inside the pinned
    // directory (after endpoint rotation switches servers, the right anchor is
    // still resolved).
    let entry = p
        .directory
        .find(&ServerId(server_id))
        .ok_or_else(|| {
            refused(format!(
                "server {:02x?} not in the pinned directory",
                server_id
            ))
        })?
        .clone();

    // (2) OPAQUE login (ke1 → ke2[anchor signature] → ke3).
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
        return Err(refused("invalid anchor signature length"));
    }
    sig.copy_from_slice(&anchor_sig);
    // Anchor verification failure and wrong password both surface as this
    // Err (wrong password = local OPAQUE finish failure, §3.4).
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

    // (3) key-bind (device signature carries the hostname + SR-SIG1 public
    //     key).
    let device = DevicePubs {
        x25519: p.device.x25519_public().to_bytes(),
        ed25519: *p.device.ed25519_public().as_bytes(),
        hostname: p.hostname.clone(),
    };
    let sr_pub = match flock_protocol::sig::UserKey::from_pub_string(&p.sr_key.pub_string()) {
        Ok(vk) => *vk.as_bytes(),
        Err(_) => unreachable!("self-produced public key encoding always round-trips"),
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

    // (4) Re-login cadence: 2/3 of the TTL (a relative amount — immune to
    //     clock skew; floor 2s, **ceiling 25s** — the server-side control
    //     stream idle timeout = 3×keepalive = 30s (§2.2 review item 8), so a
    //     re-login doubles as keepalive; beyond 25s the stream would be
    //     idle-closed before the ticket expires, and under the first-stream
    //     contract (exactly one control stream per session) the control plane
    //     could not be reopened — the cap keeps that from becoming routine).
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
// First-time setup: password setting (PwBegin/PwCommit) + credentials/key
// placement
// ============================================================================

/// Service password setting (one-time; authorization = session device owner
/// == user).
///
/// `PasswordExists` counts as already configured (returns Ok(false) — keep
/// the existing password, login verification is the fallback check).
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

/// Credentials file path (`[auth] credentials_file` override; default
/// `credentials` in the state directory).
pub fn credentials_path(state_dir: &Path, cfg_override: Option<&Path>) -> PathBuf {
    cfg_override
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| state_dir.join(CREDENTIALS_FILE))
}

/// Write the credentials file: single password line; **0600** (unix) /
/// Administrators+SYSTEM full access (explicit DACL on Windows).
///
/// At-rest risk, stated honestly (§7-M7.7): OPAQUE keeps the password off
/// the wire; at rest locally = local trust domain — unreadable outside the
/// file owner (0600 / restricted DACL), but plaintext-readable on the owner
/// side (root/administrator/the user).
pub fn save_credentials(path: &Path, password: &str) -> io::Result<()> {
    write_secret_file(path, password.as_bytes())?;
    // No permission regression on a second write (password change).
    Ok(())
}

/// Read the credentials file (strips a single trailing newline — whitespace
/// inside the password is preserved).
pub fn load_credentials(path: &Path) -> io::Result<String> {
    let mut text = std::fs::read_to_string(path)
        .map_err(|e| io::Error::other(format!("read {}: {e}", path.display())))?;
    if text.ends_with('\n') {
        text.pop();
    }
    if text.ends_with('\r') {
        text.pop();
    }
    if text.is_empty() {
        return Err(io::Error::other(format!(
            "{}: password is empty (re-run `flock-client login` to configure)",
            path.display()
        )));
    }
    Ok(text)
}

/// SR-SIG1 user key placement (generate when missing; reuse when present —
/// the same "never leaves the machine" discipline as the device keys).
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
            "{}: expected a 32-byte seed",
            path.display()
        )));
    }
    let k = UserKey::generate();
    write_secret_file(&path, &k.to_seed())?;
    Ok(k)
}

/// Secret file write: 0600 (unix) / SYSTEM+Administrators full access
/// (explicit Windows DACL, no Users).
///
/// Unix goes through [`crate::ipc::write_file_private`] (review item 3:
/// `create_new(0o600)` is born with the target permissions, and rewrites use
/// tempfile+rename atomic replacement — eliminating the "fs::write default
/// permissions → chmod 0600 afterwards" window; selection notes in that
/// function's docs).
fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    crate::ipc::write_file_private(path, bytes, 0o600)?;
    #[cfg(windows)]
    {
        std::fs::write(path, bytes)?;
        // Windows: tighten the DACL explicitly right after the write
        // (SYSTEM+administrators; the brief window is creation-to-tightening
        // with the inherited default ACL — stated honestly, not an
        // instantaneous 0600 equivalent). Failure is a warning only (the
        // inherited ACL still limits reads).
        if let Err(e) = crate::ipc_windows::set_file_acl_admins_only(path) {
            eprintln!(
                "flock-client: warning: failed to tighten secret-file ACL ({e}): {}",
                path.display()
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Reported hostname: config override → OS hostname (hostname crate) → empty
/// string (the server stores "(unknown)"); normalized uniformly via
/// [`normalize_hostname`] (trim/64B truncation — aligned with the server's
/// storage semantics, §7-M7.1).
pub fn resolve_hostname(cfg_override: Option<&str>) -> String {
    let raw = cfg_override
        .map(str::to_string)
        .or_else(|| hostname::get().ok().and_then(|s| s.into_string().ok()))
        .unwrap_or_default();
    normalize_hostname(&raw)
}

// ============================================================================
// Login keepalive task + roster cache (daemon assembly side, §7-M7.7)
// ============================================================================

/// Login-phase snapshot (IPC error text / observability surface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPhase {
    /// No `[auth]` configured (the daemon does not log in — roster features
    /// unavailable).
    Unconfigured,
    /// Tunnel not connected, waiting for a session.
    WaitingSession,
    LoggingIn,
    LoggedIn {
        user: String,
    },
    Failed {
        reason: String,
    },
}

impl AuthPhase {
    /// Pre-check text for the roster (IPC `Peers`): `None` = phase ready,
    /// proceed with the pull.
    ///
    /// Review item 5: `phase()==None` = login keepalive task not assembled
    /// (client.toml without `[auth]`) — return the **login bootstrap**
    /// message, not "retry later" (unconfigured never self-heals with time;
    /// previously this shape fell into the misleading "no login ticket yet
    /// (retry shortly)" message and the `Unconfigured` branch was dead code).
    pub fn peers_block_reason(phase: Option<AuthPhase>) -> Option<String> {
        match phase.unwrap_or(AuthPhase::Unconfigured) {
            AuthPhase::Unconfigured => Some(
                "client.toml has no [auth] configured (bootstrap via `flock-client login`)".into(),
            ),
            AuthPhase::WaitingSession => {
                Some("tunnel not connected (logs in automatically once the session is up)".into())
            }
            AuthPhase::LoggingIn => Some("login in progress (retry shortly)".into()),
            AuthPhase::Failed { reason } => Some(reason),
            AuthPhase::LoggedIn { .. } => None,
        }
    }
}

/// Login state + current ticket (ticket **memory only** — valid for the
/// daemon's lifetime, §2.2).
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

    /// Phase snapshot (None = never reported — pre-assembly state).
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

    /// Clone of the current ticket (for IPC Peers pulls; None when absent).
    pub fn ticket(&self) -> Option<TicketWire> {
        self.inner
            .lock()
            .expect("auth shared poisoned")
            .ticket
            .clone()
    }
}

/// Cache of the most recent roster pull (data source for the ≤5s freshness
/// window of IPC `Peers`).
#[derive(Debug, Default)]
pub struct RosterCache {
    inner: std::sync::Mutex<Option<RosterSnapshot>>,
}

/// Cache entry: pull instant + roster.
#[derive(Debug, Clone)]
pub struct RosterSnapshot {
    pub at: std::time::Instant,
    pub peers: Vec<flock_protocol::roster::PeerInfo>,
}

/// Roster cache freshness window (IPC Peers: within ≤5s use the cache,
/// otherwise re-pull).
pub const ROSTER_FRESH_WINDOW: Duration = Duration::from_secs(5);

impl RosterCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fresh cache hit (None = no cache or expired).
    pub fn fresh(&self) -> Option<Vec<flock_protocol::roster::PeerInfo>> {
        let g = self.inner.lock().expect("roster cache poisoned");
        g.as_ref()
            .filter(|s| s.at.elapsed() <= ROSTER_FRESH_WINDOW)
            .map(|s| s.peers.clone())
    }

    /// Overwrite the cache (written after a successful pull).
    pub fn store(&self, peers: Vec<flock_protocol::roster::PeerInfo>) {
        *self.inner.lock().expect("roster cache poisoned") = Some(RosterSnapshot {
            at: std::time::Instant::now(),
            peers,
        });
    }
}

/// Static inputs of the login keepalive task (everything but the password —
/// the credentials file is **re-read** before every login, so `flock-client
/// login` can change the password without a daemon restart).
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
    /// Assemble the login parameters for this attempt (password read fresh).
    fn params(&self) -> Result<AuthParams, String> {
        let password = load_credentials(&self.credentials_path).map_err(|e| {
            format!("credentials file: {e} (re-run `flock-client login` to configure)")
        })?;
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

/// Login keepalive task: session up ⇒ login (+key-bind hostname) ⇒ ticket
/// into memory ⇒ periodic re-login at 2/3 of the TTL to keep it fresh;
/// session down ⇒ wait for a new session and re-login; rejection-class
/// failures ⇒ retry with backoff.
///
/// Never returns normally (a daemon-lifetime task; exits when `stop` fires).
pub async fn run_auth_keepalive(
    plane: ControlPlane,
    ctx: AuthCtx,
    shared: std::sync::Arc<AuthShared>,
    stop: std::sync::Arc<tokio::sync::Notify>,
) {
    loop {
        // —— Wait for the session to be up (or shutdown). ——
        shared.set_phase(AuthPhase::WaitingSession);
        tokio::select! {
            _ = plane.wait_up() => {}
            _ = stop.notified() => return
        }
        // —— Login loop (after success, re-login on the refresh_after
        //     cadence; session-down/shutdown exits this level). ——
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
                        "flock-client: login ok user={} vip={} epoch={} (re-login in {}s to keep \
                         the ticket fresh)",
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
                        _ = tokio::time::sleep(out.refresh_after) => {} // periodic re-login
                        _ = plane.wait_down() => break,                  // session down ⇒ wait for a new one
                        _ = stop.notified() => return,
                    }
                }
                Err(LoginError::Io(e)) => {
                    // Transport failure = the control stream is unusable
                    // (EOF/bad frame; under the **first-stream contract** the
                    // control plane cannot reopen in this session — the
                    // server dispatches only stream id=1 as the control
                    // stream). Poison ⇒ kill the session and reconnect for a
                    // fresh stream; no "short-backoff retry while the plane
                    // is still up" — retrying on a dead stream only spins
                    // (review follow-up: the original 500ms retry loop
                    // dead-looped after the server's 30s idle stream close).
                    eprintln!("flock-client: login io (control stream unusable, reconnecting for a fresh stream): {e}");
                    shared.set_phase(AuthPhase::Failed {
                        reason: format!("control stream IO: {e}"),
                    });
                    plane.poison("login transport failure");
                    tokio::select! {
                        _ = plane.wait_down() => break,
                        _ = stop.notified() => return,
                    }
                }
                Err(e @ LoginError::Refused(_)) => {
                    // Server refusal (wrong password / missing ticket
                    // privilege, etc.) — the session is still alive: fixed
                    // backoff retry (recovers automatically after changing
                    // the password via `flock-client login`).
                    eprintln!(
                        "flock-client: login refused, retrying in {}s: {e}",
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
// Roster pull (PeerListPull consumption, §7-M7.4 — ticket-protected; result
// goes into RosterCache)
// ============================================================================

/// Pull the member roster (current ticket + control stream in place; the
/// caller caches the result via [`RosterCache::store`]).
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
        Ok(other) => Err(format!(
            "unexpected response: {}",
            ctrl_response_variant(&other)
        )),
        Err(e) => Err(format!("control stream: {e}")),
    }
}

// ============================================================================
// Unit tests: login state machine (mock transport + flock-protocol pake
// both-sides functions in memory — real anchor signing/verification, real
// ke1/ke2/ke3, real keybind device-signature verification)
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

    /// Mock server state (real pake server functions; tickets issued with a
    /// dummy signature — the client does not verify, it only passes through
    /// and reads the TTL hint).
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
        /// Negative-path switch: anchor signed with the attacker key (fake
        /// server stand-in).
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

        /// Pinned directory (identity_pub = mock server identity — the anchor
        /// verification anchor).
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
                    // Same semantics as the real server: password already set
                    // ⇒ PasswordExists (first set succeeds once).
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
                    // Dummy ticket (the client does not verify; TTL hint 60 ⇒
                    // refresh_after 40s).
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
                    // The ticket must be in place (dummy-ticket passthrough
                    // semantics: Local counts as a login artifact).
                    let TicketWire::Local(t) = ticket else {
                        return self.err(CtrlError::TicketBad);
                    };
                    // Real device-signature verification (keybind_canonical
                    // shared with the server).
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

    /// Mock transport: requests dispatch synchronously on the spot (the pake
    /// server functions are fully synchronous — no real network/yamux
    /// needed).
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

    /// Happy path, full chain: set_password → login_and_bind (anchor
    /// verification passes + hostname carried + device signature verified on
    /// the server side + TTL hint → refresh 40s).
    #[tokio::test]
    async fn login_state_machine_happy_path() {
        let st = std::sync::Arc::new(std::sync::Mutex::new(MockState::new()));
        let t = MockTransport::new(st.clone());
        let p = params(&st.lock().unwrap(), "pw-123", "box-m7");

        // First-time setup: password setting (real reg chain — the server
        // mock stores the record).
        assert!(set_password_once(&t, "alice", "pw-123").await.unwrap());
        assert!(st.lock().unwrap().password_set);

        let out = login_and_bind(&t, &p).await.expect("full login chain");
        assert_eq!(out.vip, [100, 64, 0, 11]);
        assert_eq!(out.epoch, 3);
        assert_eq!(
            out.device_id,
            DeviceId::from_ed25519(&p.device.ed25519_public()).0
        );
        assert_eq!(
            out.refresh_after,
            Duration::from_secs(25),
            "TTL 60 ⇒ 2/3=40 capped at 25 (keepalive within the server control stream's 30s idle window)"
        );
        let g = st.lock().unwrap();
        assert_eq!(
            g.hostname_seen.as_deref(),
            Some("box-m7"),
            "key-bind carries the hostname"
        );
        assert_eq!(
            g.keybind_device_sig_ok,
            Some(true),
            "device signature verified server-side"
        );
    }

    /// Negative path: forged anchor (fake server stand-in) ⇒ client rejects
    /// (no ke3 produced, subsequent steps skipped).
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
            .expect_err("a forged anchor must be rejected");
        assert!(
            matches!(&e, LoginError::Refused(m) if m.contains("anchor")),
            "{e}"
        );
        // Not advanced to LoginFinish (stop at anchor failure — no ke3).
        let log = t.log.lock().unwrap();
        assert!(
            !log.iter()
                .any(|r| matches!(r, CtrlRequest::LoginFinish { .. })),
            "no ke3 produced"
        );
    }

    /// Negative path: wrong password ⇒ client-side finish failure (no ke3
    /// produced; no difference on the wire).
    #[tokio::test]
    async fn login_wrong_password_fails_client_finish() {
        let st = std::sync::Arc::new(std::sync::Mutex::new(MockState::new()));
        let t = MockTransport::new(st.clone());
        set_password_once(&t, "alice", "pw-123").await.unwrap();
        let p = params(&st.lock().unwrap(), "wrong-pw", "box");

        let e = login_and_bind(&t, &p)
            .await
            .expect_err("a wrong password must be rejected");
        assert!(matches!(e, LoginError::Refused(_)), "{e}");
        let log = t.log.lock().unwrap();
        assert!(
            !log.iter()
                .any(|r| matches!(r, CtrlRequest::LoginFinish { .. })),
            "stops at the local failure — the third request is never sent"
        );
    }

    /// set_password: password already set ⇒ Ok(false) (keep semantics —
    /// login verification is the fallback).
    #[tokio::test]
    async fn set_password_once_password_exists_is_ok_false() {
        let st = std::sync::Arc::new(std::sync::Mutex::new(MockState::new()));
        let t = MockTransport::new(st.clone());
        assert!(set_password_once(&t, "alice", "pw").await.unwrap());
        assert!(!set_password_once(&t, "alice", "other").await.unwrap());
    }

    /// Credentials file roundtrip: 0600 (unix) + read-back identical +
    /// empty password rejected.
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
                "credentials file is 0600"
            );
        }
        assert_eq!(
            load_credentials(&p).unwrap(),
            "s3cret pw ",
            "trailing newline stripped, inner whitespace preserved"
        );
        let empty = dir.path().join("empty-cred");
        std::fs::write(&empty, "\r\n").unwrap();
        assert!(load_credentials(&empty).is_err(), "empty password rejected");
    }

    /// Review item 3: rewrite path — a credentials file that **already exists
    /// with loose permissions (0666)** gets replaced and then: (a) the new
    /// content is in place; (b) permissions are 0600 (rename carries the new
    /// inode's permissions, the old loose ones do not survive); (c) no
    /// `.tmp.` leftovers (rename consumes the temp file).
    #[cfg(unix)]
    #[test]
    fn credentials_overwrite_replaces_loose_perm_file_with_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(CREDENTIALS_FILE);
        std::fs::write(&p, "old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        save_credentials(&p, "new-pw").unwrap();
        assert_eq!(load_credentials(&p).unwrap(), "new-pw");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600,
            "0600 after the rewrite (tempfile birth permissions land via rename)"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp-file leftovers: {leftovers:?}"
        );
    }

    /// SR-SIG1 key placement: first creation persists, second load yields
    /// the same seed.
    #[test]
    fn sr_key_load_or_create_persists() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_or_create_sr_key(dir.path()).unwrap();
        let b = load_or_create_sr_key(dir.path()).unwrap();
        assert_eq!(
            a.to_seed(),
            b.to_seed(),
            "stable across calls (never leaves the machine)"
        );
        assert!(dir.path().join(SR_SIG_KEY_FILE).exists());
    }

    /// Hostname override semantics: normalized after trim; empty ⇒
    /// "(unknown)".
    #[test]
    fn resolve_hostname_override_semantics() {
        assert_eq!(resolve_hostname(Some("  box-a ")), "box-a");
        assert_eq!(resolve_hostname(Some("")), "(unknown)");
        let long = "x".repeat(80);
        assert_eq!(
            resolve_hostname(Some(&long)).len(),
            64,
            "64B truncation aligned with the server"
        );
    }

    /// Review item 5, message one: `phase()==None` (login keepalive task not
    /// assembled = client.toml without `[auth]`) ⇒ **login bootstrap**
    /// guidance — must not be "retry later" (unconfigured never self-heals).
    #[test]
    fn peers_block_reason_none_is_unconfigured_guidance() {
        let r = AuthPhase::peers_block_reason(None).expect("not assembled ⇒ blocking reason");
        assert!(r.contains("no [auth]"), "{r}");
        assert!(r.contains("flock-client login"), "{r}");
        assert!(
            !r.contains("retry shortly"),
            "the unconfigured shape must not fall into 'retry shortly': {r}"
        );
        // Explicit Unconfigured yields the same message (branch activated —
        // equivalent to None).
        assert_eq!(
            AuthPhase::peers_block_reason(Some(AuthPhase::Unconfigured)),
            AuthPhase::peers_block_reason(None)
        );
    }

    /// Review item 5, message two: phase mapping once assembled
    /// (waiting/logging-in get self-healing "retry shortly"-style messages;
    /// LoggedIn passes with None; Failed passes the reason through).
    #[test]
    fn peers_block_reason_maps_assembled_phases() {
        let r = AuthPhase::peers_block_reason(Some(AuthPhase::WaitingSession)).unwrap();
        assert!(r.contains("tunnel not connected"), "{r}");
        let r = AuthPhase::peers_block_reason(Some(AuthPhase::LoggingIn)).unwrap();
        assert!(r.contains("retry shortly"), "{r}");
        assert_eq!(
            AuthPhase::peers_block_reason(Some(AuthPhase::Failed {
                reason: "credentials file: boom".into()
            }))
            .as_deref(),
            Some("credentials file: boom")
        );
        assert!(
            AuthPhase::peers_block_reason(Some(AuthPhase::LoggedIn { user: "a".into() })).is_none(),
            "LoggedIn lets the pull proceed"
        );
    }

    /// Review item 8: describe_err's unexpected-response branch prints only
    /// the variant name — tickets and other payloads stay out of error
    /// strings.
    #[test]
    fn describe_err_unexpected_response_hides_payload() {
        let now = flock_protocol::trust::now_unix();
        let resp = CtrlResponse::LoginOk {
            ticket: TicketWire::Local(SignedTicket {
                user: "secret-user".into(),
                device: vec![1; 32],
                epoch: 0,
                iat: now,
                exp: now + 60,
                sig: vec![7; 64],
            }),
            epoch: 1,
        };
        let msg = describe_err(resp);
        assert!(msg.contains("LoginOk"), "variant name present: {msg}");
        assert!(
            !msg.contains("secret-user"),
            "ticket user stays out of logs: {msg}"
        );
        assert!(
            !msg.contains("TicketWire"),
            "payload Debug stays out of logs: {msg}"
        );
        // The Err variant keeps its original semantics (code + msg).
        assert_eq!(
            describe_err(CtrlResponse::Err {
                code: CtrlError::LoginFailed,
                msg: "nope".into(),
            }),
            "LoginFailed: nope"
        );
    }
}
