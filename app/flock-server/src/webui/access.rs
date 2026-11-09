//! M8 webui access control (docs/design.md §7-M8.2/M8.3/M8.4/M8.7):
//!
//! - **Origin matrix** (W-A1–W-A4): `127.0.0.0/8` (including ::1) and
//!   `100.64.0.0/10` allowed; everything else 403 `forbidden_origin` (defense
//!   in depth —— the fundamental mechanism is not binding to LAN/public
//!   interfaces). `X-Forwarded-For` is **always ignored** (client-forgeable;
//!   reverse-proxy deployments unsupported);
//! - **CSRF double gate** (mutating class = all POSTs): `X-Flock-Web: 1`
//!   **and** `Content-Type: application/json` —— a missing header ⇒ 400 (does
//!   not leak that it was a CSRF block);
//! - **Role matrix** (routing static surface: public/logged-in/admin tiers;
//!   the "session before role" ordering is carried by the api.rs dispatch
//!   order);
//! - **Login backoff** (per username, 15min sliding window: from the 5th
//!   failure lock 30s, doubling per further failure, capped at 900s; zeroed
//!   on success or when the window drains —— injectable clock, testable);
//! - **Per-IP token bucket** (login-begin/pw-begin: 10/min, burst 10);
//! - **Audit ring** (most recent 200 entries in memory + synchronous stderr
//!   trail; an 11-entry action vocabulary + three result states; no
//!   passwords/tokens/ticket bytes recorded).
//!
//! All components are in-process memory with injected clock parameters —— no
//! Raft / no persistence (fixed by design).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

use super::session::Origin;

// ============================================================================
// Origin matrix (W-A1–W-A4)
// ============================================================================

/// `100.64.0.0/10` (the RFC 6598 CGNAT segment = this VPN's VIP pool, §2.1).
fn in_vpn_segment(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (o[1] & 0xC0) == 0x40 // 64..=127
        }
        IpAddr::V6(_) => false,
    }
}

/// Origin classification (`X-Forwarded-For` does not participate —— decided
/// solely by the connection's RemoteAddr, W-A4). None = out-of-bounds origin
/// (the 403 `forbidden_origin` face).
pub fn classify_origin(remote: &SocketAddr) -> Option<Origin> {
    match remote.ip() {
        IpAddr::V4(v4) if v4.is_loopback() => Some(Origin::Loopback), // 127.0.0.0/8
        IpAddr::V6(v6) if v6.is_loopback() => Some(Origin::Loopback), // ::1
        ip if in_vpn_segment(ip) => Some(Origin::Vpn),
        _ => None,
    }

    // Note: 127.0.0.0/8 and 100.64.0.0/10 do not intersect (is_loopback is
    // checked first); the two tiers are recorded separately.
}

// ============================================================================
// CSRF double gate (§M8.4 —— mutating class = all POSTs)
// ============================================================================

/// POST CSRF double gate: `X-Flock-Web: 1` and `Content-Type:
/// application/json` (prefix match on `application/json` —— a charset
/// parameter is legal). true = allowed through.
pub fn csrf_gate_ok(method: &str, x_flock_web: Option<&str>, content_type: Option<&str>) -> bool {
    if method != "POST" {
        return true;
    }
    let has_gate = x_flock_web.map(|v| v.trim() == "1").unwrap_or(false);
    let is_json = content_type
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
        .unwrap_or(false);
    has_gate && is_json
}

// ============================================================================
// Role matrix (routing static surface —— the decision source of the
// three-state enum)
// ============================================================================

/// Endpoint role slot (§M8.4 per endpoint; "session before role" lives in the
/// api.rs dispatch order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Public (login-begin/finish, pw-begin/commit, bootstrap, static assets
    /// —— static assets do not pass through this enum, routed directly by
    /// api.rs).
    Public,
    /// Logged-in suffices (read-only surface + logout + me).
    LoggedIn,
    /// admin.
    Admin,
    /// Unknown `/api/*` path (404).
    Unknown,
}

/// Role slot by method+path (admin write paths dispatched by prefix: the four
/// action endpoints of `/api/users/{u}/*` and `/api/peers/{id}/*` are all
/// Admin).
pub fn required_role(method: &str, path: &str) -> Role {
    let m_get = method == "GET";
    let m_post = method == "POST";
    match path {
        "/api/bootstrap" if m_get => Role::Public,
        "/api/login-begin" | "/api/login-finish" | "/api/pw-begin" | "/api/pw-commit" if m_post => {
            Role::Public
        }
        "/api/logout" if m_post => Role::LoggedIn,
        "/api/me" | "/api/peers" | "/api/dashboard/summary" | "/api/config" if m_get => {
            Role::LoggedIn
        }
        "/api/dashboard/series" if m_get => Role::LoggedIn,
        "/api/users" if m_get => Role::Admin,
        "/api/users" if m_post => Role::Admin,
        "/api/audit" if m_get => Role::Admin,
        _ => {
            // /api/users/{u}/disable|enable|reset-password|admin (POST, Admin)
            // /api/peers/{device_id}/revoke|disable|enable|kick (POST, Admin)
            if m_post {
                if let Some(rest) = path.strip_prefix("/api/users/") {
                    if user_action_known(rest) {
                        return Role::Admin;
                    }
                }
                if let Some(rest) = path.strip_prefix("/api/peers/") {
                    if peer_action_known(rest) {
                        return Role::Admin;
                    }
                }
            }
            Role::Unknown
        }
    }
}

/// Action slot of `/api/users/{u}/<action>` (path-shape determination
/// independent of method).
fn user_action_known(rest: &str) -> bool {
    rest.contains('/')
        && matches!(
            rest.rsplit('/').next().unwrap_or(""),
            "disable" | "enable" | "reset-password" | "admin"
        )
}

/// Action slot of `/api/peers/{id}/<action>` (path-shape determination
/// independent of method).
fn peer_action_known(rest: &str) -> bool {
    rest.contains('/')
        && matches!(
            rest.rsplit('/').next().unwrap_or(""),
            "revoke" | "disable" | "enable" | "kick"
        )
}

/// Path known (path shape independent of method): known path + wrong method
/// slot ⇒ dispatch layer 405 `method_not_allowed` (the §M8.4 error-code
/// table); only unknown paths 404 (green review item 7 —— the old
/// implementation folded wrong-method into Unknown ⇒ 404, inconsistent with
/// the error-code table's 405 tier).
pub fn path_known(path: &str) -> bool {
    match path {
        "/api/bootstrap"
        | "/api/login-begin"
        | "/api/login-finish"
        | "/api/logout"
        | "/api/me"
        | "/api/pw-begin"
        | "/api/pw-commit"
        | "/api/users"
        | "/api/audit"
        | "/api/peers"
        | "/api/dashboard/summary"
        | "/api/dashboard/series"
        | "/api/config" => true,
        _ => {
            path.strip_prefix("/api/users/")
                .is_some_and(user_action_known)
                || path
                    .strip_prefix("/api/peers/")
                    .is_some_and(peer_action_known)
        }
    }
}

// ============================================================================
// Login backoff (per username; injected clock)
// ============================================================================

/// Sliding window (15min).
const FAIL_WINDOW_SECS: u64 = 15 * 60;
/// Lockout threshold (locked from the 5th failure).
const LOCK_THRESHOLD: usize = 5;
/// Initial lockout duration (30s; doubles per further failure).
const LOCK_BASE_SECS: u64 = 30;
/// Cap (900s).
const LOCK_MAX_SECS: u64 = 900;
/// Table capacity cap (review item 5: the unauthenticated surface can inject
/// arbitrary user names —— over the cap, first clear lazily-expired rows,
/// evict the oldest if still full; a 60s periodic sweep backstops).
pub const LOGIN_BACKOFF_CAP: usize = 4096;

/// Per-username failure accounting.
#[derive(Default)]
struct FailState {
    /// Failure timestamps inside the window (unix seconds; pushed ascending).
    fails: Vec<u64>,
    /// Current lockout duration (doubling base; 0 = not locked).
    lock_secs: u64,
}

/// Login backoff (in-process memory; `Mutex<HashMap<user, FailState>>`).
#[derive(Default)]
pub struct LoginBackoff {
    inner: std::sync::Mutex<HashMap<String, FailState>>,
}

impl LoginBackoff {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lockout check: Some(retry_after_secs) = currently locked (does not
    /// consume a failure).
    pub fn check(&self, user: &str, now_unix: u64) -> Option<u64> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let st = g.get(user)?;
        // Lockout window = lock_secs from the most recent failure.
        let last = *st.fails.last()?;
        let until = last.saturating_add(st.lock_secs);
        (now_unix < until).then(|| until - now_unix)
    }

    /// Record one failure (restarts counting once the window drains; from the
    /// 5th failure lock 30s, doubling per further failure, capped at 900).
    pub fn on_failure(&self, user: &str, now_unix: u64) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Capacity cap: first clear lazily-expired rows (see
        // sweep_backoff_locked —— lock_secs ≤ LOCK_MAX_SECS =
        // FAIL_WINDOW_SECS, so once the window drains the lockout has also
        // expired and the row is fully lazy); evict the oldest by most-recent
        // failure time if still full.
        if g.len() >= LOGIN_BACKOFF_CAP {
            sweep_backoff_locked(&mut g, now_unix);
        }
        while g.len() >= LOGIN_BACKOFF_CAP {
            let Some(oldest) = g
                .iter()
                .min_by_key(|(_, st)| st.fails.last().copied().unwrap_or(0))
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            g.remove(&oldest);
        }
        let st = g.entry(user.to_string()).or_default();
        // 15min sliding-window drain (including leftover failures after a
        // lockout).
        st.fails
            .retain(|t| now_unix.saturating_sub(*t) < FAIL_WINDOW_SECS);
        st.fails.push(now_unix);
        if st.fails.len() >= LOCK_THRESHOLD {
            // 5th failure: 30s; each further failure doubles (len=5→30,
            // 6→60, 7→120 … capped at 900).
            let excess = st.fails.len() - LOCK_THRESHOLD;
            st.lock_secs = LOCK_BASE_SECS
                .saturating_mul(1u64 << excess.min(6))
                .min(LOCK_MAX_SECS);
        }
    }

    /// Success zeroes everything (window and lockout fully cleared).
    pub fn on_success(&self, user: &str) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(user);
    }

    /// Periodic sweep (60s task —— same tier as the session sweep in mod.rs):
    /// clears lazy rows whose window has drained and whose lockout has
    /// expired (returns the number cleared —— test surface).
    pub fn sweep(&self, now_unix: u64) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        sweep_backoff_locked(&mut g, now_unix)
    }

    /// Rows on record (test/diagnostics surface).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Lazy-row predicate + sweep: most recent failure ≥ FAIL_WINDOW_SECS ago ⇒
/// the sliding window has drained and the lockout has necessarily expired
/// (lock_secs ≤ LOCK_MAX_SECS = FAIL_WINDOW_SECS) —— deleting the row makes no
/// behavioral difference.
fn sweep_backoff_locked(g: &mut HashMap<String, FailState>, now_unix: u64) -> usize {
    let before = g.len();
    g.retain(|_, st| {
        st.fails
            .last()
            .is_some_and(|t| now_unix.saturating_sub(*t) < FAIL_WINDOW_SECS)
    });
    before - g.len()
}

// ============================================================================
// Per-IP token bucket (login-begin/pw-begin; 10/min burst 10)
// ============================================================================

/// Bucket capacity (burst 10).
const BUCKET_BURST: f64 = 10.0;
/// Refill rate (10/min).
const BUCKET_RATE_PER_SEC: f64 = 10.0 / 60.0;
/// Time to refill full (burst 10 / 10 per min ⇒ an equivalent fresh bucket
/// after 60s —— rows idle ≥ this value can be safely rebuilt).
const BUCKET_REFILL_SECS: u64 = 60;
/// Table capacity cap (review item 5: many source IPs inside the VPN segment
/// can grow rows without bound —— over the cap, first clear idle rows, evict
/// the oldest if still full; a 60s periodic sweep backstops).
pub const IP_BUCKETS_CAP: usize = 4096;

/// Token bucket (in-process memory; `Mutex<HashMap<IpAddr, (tokens, last)>>`).
#[derive(Default)]
pub struct IpBuckets {
    inner: std::sync::Mutex<HashMap<IpAddr, (f64, u64)>>,
}

impl IpBuckets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one token: true = allowed; false = over rate (429; retry_after per
    /// the full-token refill time).
    pub fn allow(&self, ip: IpAddr, now_unix: u64) -> Result<(), u64> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Capacity cap: first clear rows idle ≥ the full-refill time
        // (rebuilding = a brand-new full bucket, no behavioral difference);
        // evict the oldest by last if still full (an evicted IP is treated as
        // a fresh bucket on its next request —— a momentary loosening of the
        // rate-limit surface beats unbounded memory growth).
        if g.len() >= IP_BUCKETS_CAP {
            sweep_buckets_locked(&mut g, now_unix);
        }
        while g.len() >= IP_BUCKETS_CAP {
            let Some(oldest) = g.iter().min_by_key(|(_, (_, last))| *last).map(|(k, _)| *k) else {
                break;
            };
            g.remove(&oldest);
        }
        let (tokens, last) = g.get(&ip).copied().unwrap_or((BUCKET_BURST, now_unix));
        let elapsed = now_unix.saturating_sub(last) as f64;
        let filled = (tokens + elapsed * BUCKET_RATE_PER_SEC).min(BUCKET_BURST);
        if filled >= 1.0 {
            g.insert(ip, (filled - 1.0, now_unix));
            Ok(())
        } else {
            let need = 1.0 - filled;
            let retry = (need / BUCKET_RATE_PER_SEC).ceil() as u64;
            g.insert(ip, (filled, now_unix));
            Err(retry.max(1))
        }
    }

    /// Periodic sweep (60s task): clears rows idle ≥ the full-refill time
    /// (returns the number cleared —— test surface).
    pub fn sweep(&self, now_unix: u64) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        sweep_buckets_locked(&mut g, now_unix)
    }

    /// Rows on record (test/diagnostics surface).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Idle-row sweep: last ≥ BUCKET_REFILL_SECS ago ⇒ the bucket has refilled
/// full; deleting and rebuilding is equivalent.
fn sweep_buckets_locked(g: &mut HashMap<IpAddr, (f64, u64)>, now_unix: u64) -> usize {
    let before = g.len();
    g.retain(|_, (_, last)| now_unix.saturating_sub(*last) < BUCKET_REFILL_SECS);
    before - g.len()
}

// ============================================================================
// Audit ring (§M8.7-4: 200 entries in memory + stderr; action vocabulary
// fixed)
// ============================================================================

/// Audit ring capacity.
pub const AUDIT_CAP: usize = 200;

/// Action vocabulary (11 entries, fixed by §M8.4).
pub const AUDIT_ACTIONS: [&str; 11] = [
    "session.login",
    "session.logout",
    "user.create",
    "user.disable",
    "user.enable",
    "user.reset_password",
    "user.set_admin",
    "peer.revoke",
    "peer.disable",
    "peer.enable",
    "peer.kick",
];

/// Audit entry (no passwords/tokens/ticket bytes recorded —— the §M8.7-4 red
/// line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub ts: u64,
    pub user: String,
    pub action: String,
    pub target: String,
    pub origin: Origin,
    pub result: &'static str, // "ok" | "denied" | "error"
}

/// Audit ring (`Mutex<VecDeque>` + synchronous stderr lines —— journald takes
/// them over, same channel as the existing flock-server: logs).
#[derive(Default)]
pub struct AuditLog {
    inner: std::sync::Mutex<VecDeque<AuditEntry>>,
}

/// Audit field sanitization (review item 4): when user/target contain
/// line feeds/carriage returns (or other control characters), the
/// single-line stderr format could be forged into "new audit lines" (line
/// injection). Before output, control characters are replaced with a visible
/// placeholder (stderr and the in-memory ring sanitized identically —— the
/// API-surface echo and the trail stay consistent).
fn audit_sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '␀' } else { c })
        .collect()
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one line (synchronous stderr trail + memory ring; the ring
    /// evicts the oldest when full; user/target sanitized before output ——
    /// prevents stderr line injection forging audit lines).
    pub fn record(
        &self,
        ts: u64,
        user: &str,
        action: &str,
        target: &str,
        origin: Origin,
        result: &'static str,
    ) {
        debug_assert!(
            AUDIT_ACTIONS.contains(&action),
            "action outside vocabulary: {action}"
        );
        let user = audit_sanitize(user);
        let target = audit_sanitize(target);
        let entry = AuditEntry {
            ts,
            user,
            action: action.to_string(),
            target,
            origin,
            result,
        };
        // stderr (journald): fixed single-line format, greppable for
        // diagnostics; no credential bytes printed.
        eprintln!(
            "flock-server: webui audit ts={} user={} action={} target={} origin={} result={}",
            entry.ts,
            entry.user,
            entry.action,
            entry.target,
            entry.origin.as_str(),
            entry.result
        );
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= AUDIT_CAP {
            g.pop_front();
        }
        g.push_back(entry);
    }

    /// Snapshot (new→old, §M8.4 `/api/audit`).
    pub fn entries_newest_first(&self) -> Vec<AuditEntry> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.iter().rev().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// Unit tests (§M8.9: origin matrix / CSRF / role three-states / backoff
// curve / token bucket / audit ring)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// W-A1–W-A3 origin matrix: 127.0.0.0/8 (including 127.3.2.1) and ::1 go
    /// Loopback; 100.64.0.0/10 (including segment head/tail/middle) goes Vpn;
    /// the rest (RFC1918/public internet/other non-loopback IPv6/link-local)
    /// rejected.
    #[test]
    fn origin_matrix() {
        for ok_lb in ["127.0.0.1:1", "127.3.2.1:2", "127.255.255.254:3", "[::1]:4"] {
            assert_eq!(
                classify_origin(&addr(ok_lb)),
                Some(Origin::Loopback),
                "{ok_lb} ⇒ loopback"
            );
        }
        for ok_vpn in [
            "100.64.0.1:9",
            "100.64.0.11:9",
            "100.100.1.2:9",
            "100.127.255.254:9",
        ] {
            assert_eq!(
                classify_origin(&addr(ok_vpn)),
                Some(Origin::Vpn),
                "{ok_vpn} ⇒ vpn"
            );
        }
        // Neighbors just outside the /10 segment (100.63.x / 100.128.x)
        // rejected.
        for bad in [
            "192.168.1.5:1",
            "10.0.0.1:1",
            "8.8.8.8:53",
            "100.63.255.254:1",
            "100.128.0.1:1",
            "[fe80::1]:1",
            "[2001:db8::1]:1",
            "169.254.1.1:1",
        ] {
            assert_eq!(
                classify_origin(&addr(bad)),
                None,
                "{bad} ⇒ rejected (403 face)"
            );
        }
    }

    /// CSRF double gate: POST missing the custom header 400; header present
    /// but missing the JSON content-type 400; both present passes; GET sets
    /// no gate; `application/json; charset=utf-8` prefix is legal.
    #[test]
    fn csrf_double_gate() {
        let ct_json = Some("application/json");
        let gate = Some("1");
        assert!(csrf_gate_ok("POST", gate, ct_json), "both present passes");
        assert!(csrf_gate_ok(
            "POST",
            gate,
            Some("application/json; charset=utf-8")
        ));
        assert!(!csrf_gate_ok("POST", None, ct_json), "missing X-Flock-Web");
        assert!(!csrf_gate_ok("POST", Some("0"), ct_json), "value not 1");
        assert!(
            !csrf_gate_ok("POST", gate, Some("text/plain")),
            "missing JSON"
        );
        assert!(!csrf_gate_ok("POST", gate, None), "missing content-type");
        assert!(!csrf_gate_ok("POST", gate, Some("application/json+xml")),);
        assert!(csrf_gate_ok("GET", None, None), "GET sets no gate");
    }

    /// Role matrix enumerated per endpoint (§M8.4, all 22 endpoints + wrong
    /// methods + unknown paths).
    #[test]
    fn role_matrix_all_endpoints() {
        // 5 public.
        for (m, p) in [
            ("GET", "/api/bootstrap"),
            ("POST", "/api/login-begin"),
            ("POST", "/api/login-finish"),
            ("POST", "/api/pw-begin"),
            ("POST", "/api/pw-commit"),
        ] {
            assert_eq!(required_role(m, p), Role::Public, "{m} {p}");
        }
        // 6 logged-in.
        for (m, p) in [
            ("GET", "/api/me"),
            ("POST", "/api/logout"),
            ("GET", "/api/peers"),
            ("GET", "/api/dashboard/summary"),
            ("GET", "/api/dashboard/series"),
            ("GET", "/api/config"),
        ] {
            assert_eq!(required_role(m, p), Role::LoggedIn, "{m} {p}");
        }
        // 11 admin (including path-parameter shapes).
        for (m, p) in [
            ("GET", "/api/users"),
            ("POST", "/api/users"),
            ("GET", "/api/audit"),
            ("POST", "/api/users/bob/disable"),
            ("POST", "/api/users/bob/enable"),
            ("POST", "/api/users/bob/reset-password"),
            ("POST", "/api/users/bob/admin"),
            ("POST", "/api/peers/abcd/revoke"),
            ("POST", "/api/peers/abcd/disable"),
            ("POST", "/api/peers/abcd/enable"),
            ("POST", "/api/peers/abcd/kick"),
        ] {
            assert_eq!(required_role(m, p), Role::Admin, "{m} {p}");
        }
        // Wrong-method slots (same path, foreign method = unknown —— the
        // dispatch layer 405s) and unknown paths.
        for (m, p) in [
            ("GET", "/api/login-begin"),
            ("POST", "/api/bootstrap"),
            ("PUT", "/api/users"),
            ("GET", "/api/users/bob/disable"),
            ("POST", "/api/peers/abcd/rename"),
            ("GET", "/api/nope"),
        ] {
            assert_eq!(required_role(m, p), Role::Unknown, "{m} {p}");
        }
    }

    /// Backoff curve (injected clock): 4 failures do not lock; the 5th locks
    /// 30s; further failures double 60/120/240/480/960 → capped at 900;
    /// success zeroes; window drain (15min without failure) resets.
    #[test]
    fn login_backoff_curve() {
        let b = LoginBackoff::new();
        let mut t = 1_000u64;
        // ① Failures 1–4: no lockout.
        for i in 1..5 {
            b.on_failure("alice", t);
            assert!(
                b.check("alice", t + 1).is_none(),
                "failure {i} does not lock (threshold 5)"
            );
            t += 10;
        }
        // ② 5th failure: 30s lockout.
        b.on_failure("alice", t);
        assert_eq!(b.check("alice", t), Some(30));
        assert_eq!(b.check("alice", t + 29), Some(1));
        assert!(
            b.check("alice", t + 30).is_none(),
            "lockout expires and releases"
        );
        // ③ Further failures double: 60/120/240/480; the 10th (excess=5) is
        // 960 → capped at 900.
        for expect in [60u64, 120, 240, 480] {
            t += 60;
            b.on_failure("alice", t);
            assert_eq!(b.check("alice", t), Some(expect), "doubled to {expect}");
        }
        t += 60;
        b.on_failure("alice", t);
        assert_eq!(b.check("alice", t), Some(900), "capped at 900");
        // ④ Success zeroes (even mid-lockout —— success proves the legitimate
        // user recovered the account).
        b.on_success("alice");
        assert!(b.check("alice", t).is_none());
        // ⑤ Window drain resets: 4 failures + across the window (>15min) then
        // another failure = the new window's 1st (no lockout).
        let b2 = LoginBackoff::new();
        let t0 = 10_000u64;
        for i in 0..4 {
            b2.on_failure("bob", t0 + i);
        }
        b2.on_failure("bob", t0 + FAIL_WINDOW_SECS + 1);
        assert!(
            b2.check("bob", t0 + FAIL_WINDOW_SECS + 2).is_none(),
            "restarts counting after the window drains"
        );
        // ⑥ Different users do not affect each other.
        assert!(b2.check("carol", t0).is_none());
    }

    /// Token bucket (injected clock): 10 burst tokens allowed immediately;
    /// the 11th rejected (429 face); refills at 10/min (1 token per 6s);
    /// independent buckets per IP.
    #[test]
    fn ip_token_bucket() {
        let b = IpBuckets::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let t0 = 100u64;
        // 10-token burst: taken at the same instant (under a discrete clock no
        // refill mixes in —— the refill curve is verified in its own case).
        for i in 0..10 {
            assert!(
                b.allow(ip, t0).is_ok(),
                "token {} allowed within burst 10",
                i + 1
            );
        }
        assert!(b.allow(ip, t0).is_err(), "the 11th rejected");
        // Same-instant retry still rejected (no refill).
        assert!(b.allow(ip, t0).is_err());
        // 6s refills ≈1 token (10/min ⇒ 6s/token; float rounding is
        // conservative —— after 7s a full token is guaranteed).
        assert!(b.allow(ip, t0 + 7).is_ok(), "one token refilled");
        assert!(b.allow(ip, t0 + 7).is_err(), "the next take still waits");
        // Independent buckets per IP.
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(b.allow(ip2, t0).is_ok());
    }

    /// Capacity caps + sweep (review item 5):
    /// - Backoff table saturated (4096): lazily-expired rows cleared first;
    ///   if still full, the row with the oldest most-recent failure is
    ///   evicted —— the on-record count never exceeds the cap, and a new
    ///   failure's state is retained (can keep accumulating toward lockout).
    /// - Backoff table sweep: window drained (≥15min without failure) rows
    ///   cleared; locked rows are not.
    #[test]
    fn login_backoff_cap_and_sweep() {
        let b = LoginBackoff::new();
        let t0 = 1_000u64;
        // Fill: 4095 users, one failure each (timestamps increasing —— u0
        // earliest; total span 512s < 900s window ⇒ when the cap triggers the
        // sweep finds no lazy rows to clear and must take the "evict oldest"
        // path).
        for i in 0..LOGIN_BACKOFF_CAP - 1 {
            b.on_failure(&format!("u{i:04}"), t0 + i as u64 / 8);
        }
        assert_eq!(b.len(), LOGIN_BACKOFF_CAP - 1);
        // u-last pre-seeded with 4 failures (no lockout —— threshold 5); if
        // eviction hit it, the 5th failure below would not start a lockout;
        // here it has the newest timestamp and must not be evicted.
        let t_last = t0 + (LOGIN_BACKOFF_CAP - 1) as u64 / 8;
        for _ in 0..4 {
            b.on_failure("u-last", t_last);
        }
        // Full +1: cap triggers (timestamps close ⇒ sweep clears nothing ⇒
        // evict the oldest by most-recent failure = u0000).
        b.on_failure("u-new", t_last + 1);
        assert_eq!(
            b.len(),
            LOGIN_BACKOFF_CAP,
            "cap maintained (never exceeds 4096)"
        );
        // u-last retained: the 5th failure starts a 30s lockout.
        b.on_failure("u-last", t_last + 2);
        assert_eq!(
            b.check("u-last", t_last + 2),
            Some(30),
            "newest user state retained"
        );
        // sweep: window drained (u-last's most recent failure ≥ 15min ago) ⇒
        // all cleared; inside the window / mid-lockout (<15min) not cleared.
        assert_eq!(
            b.sweep(t_last + 3),
            0,
            "rows inside window/lockout not cleared"
        );
        let swept = b.sweep(t_last + 2 + FAIL_WINDOW_SECS);
        assert!(swept >= 2, "drained rows all cleared (actually {swept})");
        assert!(b.is_empty());
        // Boundary: exactly FAIL_WINDOW_SECS distance = window drained (the
        // retain condition is <).
        let b2 = LoginBackoff::new();
        b2.on_failure("solo", 100);
        assert_eq!(
            b2.sweep(100 + FAIL_WINDOW_SECS - 1),
            0,
            "1s short is still in-window"
        );
        assert_eq!(
            b2.sweep(100 + FAIL_WINDOW_SECS),
            1,
            "drained right at the mark"
        );
    }

    /// Token bucket capacity cap + sweep (review item 5): when saturated,
    /// first clear rows idle ≥60s (rebuild = full bucket, no behavioral
    /// difference); when all fresh, evict the oldest by last; sweep clears
    /// idle rows and keeps recent ones.
    #[test]
    fn ip_buckets_cap_and_sweep() {
        let b = IpBuckets::new();
        let t0 = 100u64;
        // Fill: 4096 IPs, one token each (timestamps increasing —— the first
        // is the oldest).
        for i in 0..IP_BUCKETS_CAP {
            let ip: IpAddr = format!("10.1.{}.{}", i / 250, i % 250 + 1).parse().unwrap();
            assert!(b.allow(ip, t0 + i as u64 / 64).is_ok());
        }
        assert_eq!(b.len(), IP_BUCKETS_CAP);
        // Idle-sweep path: ≥60s from all rows ⇒ a new IP triggers a full
        // clear then inserts (1 on record).
        let ip_new: IpAddr = "10.9.9.9".parse().unwrap();
        assert!(b.allow(ip_new, t0 + 5000).is_ok());
        assert_eq!(b.len(), 1, "idle rows fully cleared + new row inserted");
        // Fresh-eviction path: saturated at the same instant, a new IP ⇒ evict
        // the oldest by last rather than reject; the new row is usable
        // (same-instant takes allowed within burst 10).
        let b2 = IpBuckets::new();
        let t1 = 9_000u64;
        for i in 0..IP_BUCKETS_CAP {
            let ip: IpAddr = format!("10.2.{}.{}", i / 250, i % 250 + 1).parse().unwrap();
            assert!(b2.allow(ip, t1).is_ok(), "fresh fill: {ip}");
        }
        assert!(
            b2.allow(ip_new, t1).is_ok(),
            "new IP allowed after oldest evicted at saturation"
        );
        assert_eq!(b2.len(), IP_BUCKETS_CAP);
        // New row retained: ip_new takes 9 more (the first take used 1) ——
        // the 11th rejected.
        for _ in 0..9 {
            assert!(b2.allow(ip_new, t1).is_ok());
        }
        assert!(
            b2.allow(ip_new, t1).is_err(),
            "eviction-victim semantics self-check"
        );
        // sweep: idle ≥60s rows cleared, fresh rows kept (ip_new takes one
        // more token at t1+60 ⇒ last refreshed).
        assert!(
            b2.allow(ip_new, t1 + BUCKET_REFILL_SECS).is_ok(),
            "take again after full refill"
        );
        let before = b2.len();
        assert!(before <= IP_BUCKETS_CAP, "cap invariant (≤4096)");
        assert_eq!(
            b2.sweep(t1 + BUCKET_REFILL_SECS),
            before - 1,
            "all other idle rows cleared"
        );
        assert_eq!(b2.len(), 1, "only ip_new (fresh) kept");
    }

    /// Audit ring: synchronous stderr + memory ≤200 + new→old order + denied
    /// lines also recorded.
    #[test]
    fn audit_ring_cap_and_order() {
        let a = AuditLog::new();
        let t0 = 7u64;
        a.record(t0, "alice", "session.login", "alice", Origin::Vpn, "ok");
        a.record(
            t0 + 1,
            "bob",
            "user.create",
            "carol",
            Origin::Loopback,
            "denied",
        );
        let es = a.entries_newest_first();
        assert_eq!(es.len(), 2);
        assert_eq!(es[0].action, "user.create", "new→old");
        assert_eq!(es[0].result, "denied", "denied also recorded");
        assert_eq!(es[1].origin, Origin::Vpn);
        // Ring cap 200 (evicts the oldest).
        for i in 0..AUDIT_CAP + 37 {
            a.record(
                t0 + i as u64 + 2,
                "u",
                "peer.kick",
                "dev",
                Origin::Loopback,
                "ok",
            );
        }
        assert_eq!(a.len(), AUDIT_CAP, "ring cap 200");
        assert_eq!(a.entries_newest_first()[0].ts, t0 + AUDIT_CAP as u64 + 38);
    }

    /// Audit output sanitization (review item 4): user/target containing
    /// \n/\r/other control characters ⇒ replaced with a visible placeholder
    /// before output —— the single-line stderr format cannot be forged into
    /// new audit lines (line injection).
    #[test]
    fn audit_sanitizes_control_chars_in_user_and_target() {
        let a = AuditLog::new();
        a.record(
            7,
            "evil\n2026-01-01 user=root action=peer.revoke target=all result=ok",
            "user.create",
            "bob\r\ninjected",
            Origin::Vpn,
            "ok",
        );
        let e = &a.entries_newest_first()[0];
        assert!(
            !e.user.contains('\n') && !e.user.contains('\r'),
            "user has no bare line feeds"
        );
        assert!(
            !e.target.contains('\n') && !e.target.contains('\r'),
            "target has no bare line feeds"
        );
        assert!(e.user.contains("evil"), "content retained (traceable)");
        assert!(
            e.user.contains('␀'),
            "control characters visualized as placeholders"
        );
        // NUL/Tab sanitized the same way.
        a.record(8, "u\u{0}x\t", "session.login", "t\u{1}", Origin::Vpn, "ok");
        let e2 = &a.entries_newest_first()[0];
        assert!(!e2.user.bytes().any(|b| b.is_ascii_control()));
        assert!(!e2.target.bytes().any(|b| b.is_ascii_control()));
    }
}
