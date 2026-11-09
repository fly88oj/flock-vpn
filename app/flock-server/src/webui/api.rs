//! M8 webui API dispatch and all handlers (docs/design.md §7-M8.4, contract
//! verbatim).
//!
//! Dispatch order (fixed; tests assert "session before role"):
//! **origin matrix (403 forbidden_origin) → routing (404) → method (405) →
//! CSRF double gate (400) → session (401 not_logged_in) → role (403
//! forbidden) → handler**. The session slot **reads back the UserRow** after
//! lookup (the locally-applied view): demotion/disable take effect on old
//! sessions immediately (403/401 user_disabled) —— no lingering until the TTL
//! (review item 6).
//!
//! Dual write arms (§M8.3 decision 2): ordinary Raft writes (multi-primary) /
//! direct single-server writes —— all through [`crate::backend::NetBackend`]
//! (same shape as the control-plane DeviceOp); authorization happens at the
//! handler layer (the session user must be admin), neither going through nor
//! loosening the `admin_op` root-signature operations.
//!
//! Login chain (§M8.3): `login-begin/finish` call the same `pake::server_*`
//! group (dummy same-shape prevents enumeration); anchor = the server
//! identity signature (`anchor_sign`) —— /api/bootstrap provides the
//! `identity_pub` verification material. Pending login state is one slot per
//! user (the last begin overwrites) + 5min expiry + a 256 cap (when full, the
//! oldest is evicted by exp/insertion order; put/take lazily clear expired
//! rows —— review item 3: lexicographically smallest ≠ oldest).

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use serde_json::json;

use flock_protocol::pake::{
    anchor_sign, server_login_finish, server_login_start, server_reg_canonical, server_reg_start,
};
use flock_protocol::rand;
use flock_protocol::session::DeviceId;

use crate::backend::NetBackend;
use crate::netstate::{DeviceStatus, NetError, UserOpError};
use crate::server::ServerCore;

use super::access::AuditLog;
use super::access::{
    classify_origin, csrf_gate_ok, path_known, required_role, IpBuckets, LoginBackoff, Role,
};
use super::assets;
use super::http::{Request, Response};
use super::series::Series;
use super::session::{clear_cookie_value, set_cookie_value, Origin, Session, Sessions};

/// webui concurrency cap (independent semaphore; §M8.1 default 64).
pub const MAX_CONCURRENCY: usize = 64;
/// Pending login state expiry (the login-begin → login-finish window).
const PENDING_LOGIN_TTL: u64 = 300;
/// Pending login state table cap (unauthenticated attack surface —— evict the
/// oldest beyond the cap).
const PENDING_LOGIN_CAP: usize = 256;
/// Username character set (§M8.4: 1..=32B, [A-Za-z0-9_.-]).
fn valid_username(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 32
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// Validation of the `user` parameter on the public auth endpoints
/// (login-begin/finish, pw-begin/commit) (review item 4 + green item 7
/// alignment): 1..=64B and ASCII control characters rejected (including
/// `\n`/`\r` —— an audit stderr line-injection surface; login-begin's ≤64 cap
/// aligned with the other three endpoints). Does not reuse the full
/// [`valid_username`] 32B/[A-Za-z0-9_.-] set: control-plane device owner names
/// are not bound by that charset (such users also use the web login chain
/// after reset-password) —— "length cap + reject control characters" is the
/// common lower bound of the four endpoints (the second defense layer is the
/// output sanitization in `AuditLog::record`).
fn sane_user_param(u: &str) -> bool {
    !u.is_empty() && u.len() <= 64 && !u.bytes().any(|b| b.is_ascii_control())
}

// ============================================================================
// Error envelope (§M8.4 verbatim)
// ============================================================================

/// Error code → HTTP mapping (fixed).
fn status_of(code: &str) -> u16 {
    match code {
        "bad_request" => 400,
        "not_logged_in" | "login_failed" | "user_disabled" | "bad_token" => 401,
        "forbidden" | "forbidden_origin" => 403,
        "not_found" => 404,
        "method_not_allowed" => 405,
        "user_exists" | "password_exists" | "invalid_state" | "cannot_demote_self" => 409,
        "payload_too_large" => 413,
        "rate_limited" => 429,
        _ => 500,
    }
}

/// Whitelisted messages (no paths / internal error strings —— §M8.7-5).
fn message_of(code: &str) -> &'static str {
    match code {
        "bad_request" => "malformed request",
        "not_logged_in" => "not logged in",
        "login_failed" => "login failed",
        "user_disabled" => "user disabled",
        "bad_token" => "bad or consumed token",
        "forbidden" => "admin role required",
        "forbidden_origin" => "origin not allowed",
        "not_found" => "not found",
        "method_not_allowed" => "method not allowed",
        "user_exists" => "username already exists",
        "password_exists" => "password already set",
        "invalid_state" => "invalid state transition",
        "cannot_demote_self" => "cannot demote self",
        "payload_too_large" => "payload too large",
        "rate_limited" => "rate limited",
        _ => "internal error",
    }
}

fn err(code: &str) -> Response {
    err_with(code, None)
}

/// With extra fields (rate_limited's retry_after_secs).
fn err_with(code: &str, retry_after: Option<u64>) -> Response {
    let mut error = json!({"code": code, "message": message_of(code)});
    if let Some(secs) = retry_after {
        error["retry_after_secs"] = json!(secs);
    }
    Response::json(status_of(code), &json!({"error": error}))
}

fn ok_json(value: serde_json::Value) -> Response {
    Response::json(200, &value)
}

// ============================================================================
// WebState
// ============================================================================

/// Pending login state (one slot per user —— the last begin overwrites).
struct PendingLogin {
    state: Vec<u8>,
    exp_unix: u64,
    /// Insertion order (a deterministic tie-break for "evict the oldest" when
    /// exps tie in the same second —— a monotonically increasing counter).
    seq: u64,
}

/// Pending table internal state (seq shares the map lock —— no atomics needed
/// for insertion order).
#[derive(Default)]
struct PendingTable {
    seq: u64,
    map: std::collections::HashMap<String, PendingLogin>,
}

/// webui assembly state (built by serve/mod.rs; tests construct it directly to
/// inject source addresses).
pub struct WebState {
    pub core: Arc<ServerCore>,
    pub sessions: Arc<Sessions>,
    pub backoff: Arc<LoginBackoff>,
    pub buckets: Arc<IpBuckets>,
    pub audit: Arc<AuditLog>,
    pub series: Arc<Series>,
    pub ttl_secs: u64,
    pub started: std::time::Instant,
    pending: std::sync::Mutex<PendingTable>,
}

impl WebState {
    pub fn new(core: Arc<ServerCore>) -> Self {
        let (points, interval, ttl) = {
            let w = &core.cfg.webui;
            (w.series_points, w.series_interval_secs, w.session_ttl_secs)
        };
        WebState {
            core,
            sessions: Arc::new(Sessions::new()),
            backoff: Arc::new(LoginBackoff::new()),
            buckets: Arc::new(IpBuckets::new()),
            audit: Arc::new(AuditLog::new()),
            series: Arc::new(Series::new(points, interval)),
            ttl_secs: ttl,
            started: std::time::Instant::now(),
            pending: std::sync::Mutex::new(PendingTable::default()),
        }
    }

    fn now(&self) -> u64 {
        flock_protocol::trust::now_unix()
    }

    /// Evict the oldest when saturated (by `(exp_unix, seq)` —— exp = begin
    /// time + TTL, i.e. the in-flight slot that began earliest; a
    /// lexicographic keys().min() would wrongly evict "a recent begin with a
    /// lexicographically early name", review item 3). The entry point first
    /// lazily clears expired rows (expired slots are reclaimed first).
    fn put_pending(&self, user: &str, state: Vec<u8>) {
        let now = self.now();
        let mut g = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let tab = &mut *g;
        tab.map.retain(|_, p| p.exp_unix > now);
        while tab.map.len() >= PENDING_LOGIN_CAP {
            let Some(oldest) = tab
                .map
                .iter()
                .min_by_key(|(_, p)| (p.exp_unix, p.seq))
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            tab.map.remove(&oldest);
        }
        tab.seq += 1;
        let seq = tab.seq;
        tab.map.insert(
            user.to_string(),
            PendingLogin {
                state,
                exp_unix: now + PENDING_LOGIN_TTL,
                seq,
            },
        );
    }

    /// Take the in-flight state (from the last begin); lazily clears all
    /// expired rows along the way (review item 3).
    fn take_pending(&self, user: &str) -> Option<Vec<u8>> {
        let now = self.now();
        let mut g = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let tab = &mut *g;
        tab.map.retain(|_, p| p.exp_unix > now);
        tab.map.remove(user).map(|p| p.state)
    }

    /// Rows on record (test/diagnostics surface —— referenced by tests only).
    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len()
    }

    // ========================================================================
    // Dispatch (contract order: origin → routing → method → CSRF → session →
    // role → handler)
    // ========================================================================

    pub async fn dispatch(&self, req: Request, remote: SocketAddr) -> Response {
        // ① Origin matrix (W-A3 defense in depth; XFF never read —— W-A4).
        let Some(origin) = classify_origin(&remote) else {
            return err("forbidden_origin");
        };
        // ② Static assets and SPA fallback (non /api/*).
        if !req.path.starts_with("/api/") {
            return self.static_route(&req);
        }
        // ③ Routing slot (unknown /api/* → 404) + ④ method (wrong method on a
        //    known path → 405 —— required_role folds the method into slot
        //    determination; Unknown needs re-splitting: path shape known ⇒
        //    wrong-method 405 method_not_allowed (aligned with the §M8.4
        //    error-code table, green review item 7), otherwise 404 not_found).
        let role = required_role(&req.method, &req.path);
        if role == Role::Unknown {
            return err(if path_known(&req.path) {
                "method_not_allowed"
            } else {
                "not_found"
            });
        }
        // ⑤ CSRF double gate (mutating class = all POSTs).
        if !csrf_gate_ok(
            &req.method,
            req.header("x-flock-web"),
            req.header("content-type"),
        ) {
            return err("bad_request");
        }
        // ⑥ Session (401) before ⑦ role (403).
        let sess = match role {
            Role::Public => None,
            _ => {
                let Some(sid) = req.session_cookie() else {
                    return err("not_logged_in");
                };
                let Some(mut s) = self.sessions.lookup(sid, self.now()) else {
                    return err("not_logged_in");
                };
                // Demotion/disable take effect immediately (review item 6 ——
                // session permissions do not linger until the 8h TTL): the
                // authorization check reads back the UserRow. In Raft form the
                // locally-applied view suffices, **no need for
                // linearizability** —— trade-off: a demote/disable committed on
                // this machine is visible on read-back immediately; changes
                // committed on another machine take effect once applied locally
                // (sub-second to seconds, same view tier as the roster/peers).
                // Compared to the old behavior (the admin snapshot lingering
                // inside the 8h session row) this is an order-of-magnitude
                // convergence. A disabled user is rejected on the same path at
                // any login-tier endpoint (401 user_disabled).
                match self.core.net.user_row(&s.user).await {
                    Some(row) if !row.disabled => {
                        // The admin snapshot inside the session row is not
                        // authoritative —— the registry's current value wins.
                        s.admin = row.admin;
                        Some(s)
                    }
                    Some(_) => return err("user_disabled"),
                    None => return err("not_logged_in"),
                }
            }
        };
        if role == Role::Admin && !sess.as_ref().is_some_and(|s| s.admin) {
            return err("forbidden");
        }
        // ⑧ Handler.
        self.handle(&req, remote, origin, sess).await
    }

    fn static_route(&self, req: &Request) -> Response {
        if req.method != "GET" {
            return err("method_not_allowed");
        }
        // SPA fallback (the direct-hit/refresh surface of §M8.6 hash routing):
        // any unknown non-/api path returns index.html (200) —— the browser's
        // hash routing takes over; /api/* never reaches this function (no
        // fallback on the 404-JSON face —— API clients never swallow HTML).
        let (body, ctype) = match req.path.as_str() {
            "/" | "/index.html" => (assets::index(), "text/html; charset=utf-8"),
            p if p.starts_with("/static/") => match assets::static_file(&p["/static/".len()..]) {
                Some(b) => (b, assets::content_type(p)),
                None => (assets::index(), "text/html; charset=utf-8"),
            },
            _ => (assets::index(), "text/html; charset=utf-8"),
        };
        Response::new(200)
            .with_header("Content-Type", ctype)
            .with_header("Cache-Control", "no-cache")
            .body(body.to_vec())
    }

    async fn handle(
        &self,
        req: &Request,
        remote: SocketAddr,
        origin: Origin,
        sess: Option<Session>,
    ) -> Response {
        let path = req.path.as_str();
        let body =
            || -> serde_json::Value { serde_json::from_slice(&req.body).unwrap_or(json!(null)) };
        match path {
            "/api/bootstrap" => self.h_bootstrap(),
            "/api/login-begin" => self.h_login_begin(&body(), remote).await,
            "/api/login-finish" => self.h_login_finish(&body(), origin).await,
            "/api/logout" => self.h_logout(req, sess.expect("role checked")),
            "/api/me" => self.h_me(sess.expect("role checked")),
            "/api/users" if req.method == "GET" => self.h_users_list().await,
            "/api/users" => {
                self.h_users_create(&body(), sess.expect("role checked"), origin)
                    .await
            }
            "/api/audit" => self.h_audit(),
            "/api/peers" => self.h_peers().await,
            "/api/dashboard/summary" => self.h_summary().await,
            "/api/dashboard/series" => self.h_series(&req.query).await,
            "/api/config" => self.h_config(),
            _ => {
                // Path-parameter shapes (required_role already confirmed the
                // slot).
                if let Some(rest) = path.strip_prefix("/api/users/") {
                    let (user, action) = rest.rsplit_once('/').unwrap_or((rest, ""));
                    return self
                        .h_user_action(user, action, &body(), sess.expect("role checked"), origin)
                        .await;
                }
                if let Some(rest) = path.strip_prefix("/api/peers/") {
                    let (dev, action) = rest.rsplit_once('/').unwrap_or((rest, ""));
                    return self
                        .h_peer_action(dev, action, sess.expect("role checked"), origin)
                        .await;
                }
                if path == "/api/pw-begin" {
                    return self.h_pw_begin(&body(), remote).await;
                }
                if path == "/api/pw-commit" {
                    return self.h_pw_commit(&body()).await;
                }
                err("not_found")
            }
        }
    }

    // ========================================================================
    // Public endpoints
    // ========================================================================

    /// `GET /api/bootstrap`: this server's identity (wasm-side anchor
    /// verification material). The `lang` field is the server's initial UI
    /// language hint (consumed by i18n.js on first visit, before any explicit
    /// user choice).
    fn h_bootstrap(&self) -> Response {
        ok_json(json!({
            "cluster_id": hex::encode(self.core.identity.cluster_id.0),
            "server_id": hex::encode(self.core.identity.server_id.0),
            "identity_pub": b64_std(self.core.identity.identity.verifying_key().as_bytes()),
            "lang": "en",
        }))
    }

    /// `POST /api/login-begin`: OPAQUE ke1 → ke2 + anchor (dummy same-shape
    /// prevents enumeration; per-IP token bucket + username backoff).
    async fn h_login_begin(&self, body: &serde_json::Value, remote: SocketAddr) -> Response {
        let (Some(user), Some(ke1_b64)) = (body["user"].as_str(), body["ke1_b64"].as_str()) else {
            return err("bad_request");
        };
        if !sane_user_param(user) || ke1_b64.len() > 64 * 1024 {
            return err("bad_request");
        }
        // Per-IP token bucket (shared tier by login-begin/pw-begin).
        if let Err(retry) = self.buckets.allow(remote.ip(), self.now()) {
            return err_with("rate_limited", Some(retry));
        }
        // Username backoff (locked ⇒ 429).
        if let Some(retry) = self.backoff.check(user, self.now()) {
            return err_with("rate_limited", Some(retry));
        }
        // Record side: unknown user / no password set ⇒ dummy (ke2
        // same-shape prevents enumeration); **disabled users still use the
        // real record** —— the same-shape ke2 leaks no disabled state, and an
        // honest client gets to complete ke3 and receive 401 user_disabled at
        // login-finish (§M8.3's "login-begin still dummy same-shape, leaking
        // nothing" refers to the unknown-user face; the disabled decision
        // happens after the password proof holds —— no extra information
        // leaked).
        let record = self
            .core
            .net
            .user_row(user)
            .await
            .and_then(|row| row.opaque_record)
            .and_then(|r| flock_protocol::pake::server_record_from_b64(&r).ok());
        let (ke2_b64, state) = match server_login_start(
            &mut rand::rngs::OsRng,
            &self.core.oprf,
            record.as_ref(),
            ke1_b64,
            user,
        ) {
            Ok(v) => v,
            Err(_) => return err("bad_request"), // bad ke1 (b64/structure)
        };
        let bind_token: [u8; 16] = rand::random();
        let sig = anchor_sign(
            &self.core.identity.identity,
            &self.core.identity.server_id.0,
            user,
            &ke2_b64,
            &bind_token,
        );
        self.put_pending(user, state);
        ok_json(json!({
            "ke2_b64": ke2_b64,
            "bind_token": hex::encode(bind_token),
            "anchor_sig": hex::encode(sig.to_bytes()),
            "server_id": hex::encode(self.core.identity.server_id.0),
        }))
    }

    /// `POST /api/login-finish`: ke3 verification → session issuance (uniform
    /// 401; backoff/audit interplay).
    async fn h_login_finish(&self, body: &serde_json::Value, origin: Origin) -> Response {
        let (Some(user), Some(ke3_b64)) = (body["user"].as_str(), body["ke3_b64"].as_str()) else {
            return err("bad_request");
        };
        if !sane_user_param(user) {
            return err("bad_request");
        }
        if let Some(retry) = self.backoff.check(user, self.now()) {
            return err_with("rate_limited", Some(retry));
        }
        let Some(state) = self.take_pending(user) else {
            return err("login_failed"); // no in-flight begin (never began / consumed / expired)
        };
        let finish_ts = self.now();
        if server_login_finish(&state, ke3_b64).is_err() {
            // Failure accounting (lockout from the 5th attempt) + an audit
            // error line.
            self.backoff.on_failure(user, finish_ts);
            self.audit
                .record(finish_ts, user, "session.login", user, origin, "error");
            return err("login_failed");
        }
        // Password proof holds —— backoff reset; account state decided next
        // (disabled does not count as a failure).
        self.backoff.on_success(user);
        let Some(row) = self.core.net.user_row(user).await else {
            return err("login_failed");
        };
        if row.disabled {
            self.audit
                .record(finish_ts, user, "session.login", user, origin, "denied");
            return err("user_disabled");
        }
        let sid = self
            .sessions
            .issue(user, row.admin, origin, finish_ts, self.ttl_secs);
        self.audit
            .record(finish_ts, user, "session.login", user, origin, "ok");
        Response::json(200, &json!({"user": user, "admin": row.admin}))
            .with_header("Set-Cookie", &set_cookie_value(&sid, self.ttl_secs))
    }

    /// `POST /api/pw-begin`: bootstrap-token pre-check (read-only, does not
    /// consume) → m2.
    async fn h_pw_begin(&self, body: &serde_json::Value, remote: SocketAddr) -> Response {
        let (Some(user), Some(token_hex), Some(m1_b64)) = (
            body["user"].as_str(),
            body["token"].as_str(),
            body["m1_b64"].as_str(),
        ) else {
            return err("bad_request");
        };
        if !sane_user_param(user) {
            return err("bad_request");
        }
        let Ok(token) = hex::decode(token_hex) else {
            return err("bad_token");
        };
        let Ok(token): Result<[u8; 16], _> = token.try_into() else {
            return err("bad_token");
        };
        if let Err(retry) = self.buckets.allow(remote.ip(), self.now()) {
            return err_with("rate_limited", Some(retry));
        }
        // Read-only pre-check: token matches (unknown user same error —— no
        // enumeration); record already present ⇒ password_exists.
        let row_ok = self
            .core
            .net
            .user_row(user)
            .await
            .is_some_and(|r| r.pw_bootstrap == Some(token));
        if !row_ok {
            return err("bad_token");
        }
        if self
            .core
            .net
            .user_row(user)
            .await
            .is_some_and(|r| r.opaque_record.is_some())
        {
            return err("password_exists");
        }
        match server_reg_start(&self.core.oprf, m1_b64, user) {
            Ok(m2_b64) => ok_json(json!({"m2_b64": m2_b64})),
            Err(_) => err("bad_request"),
        }
    }

    /// `POST /api/pw-commit`: atomically consume the token + persist the
    /// record (single commit point for Raft/direct-write).
    async fn h_pw_commit(&self, body: &serde_json::Value) -> Response {
        let (Some(user), Some(token_hex), Some(record_b64)) = (
            body["user"].as_str(),
            body["token"].as_str(),
            body["record_b64"].as_str(),
        ) else {
            return err("bad_request");
        };
        if !sane_user_param(user) {
            return err("bad_request");
        }
        let profile = body["profile"].as_u64().unwrap_or(0) as u16;
        let Ok(token) = hex::decode(token_hex) else {
            return err("bad_token");
        };
        let Ok(token): Result<[u8; 16], _> = token.try_into() else {
            return err("bad_token");
        };
        // Record canonicalization (decode validation —— bad b64 ⇒ 400, never
        // enters the write path).
        let canonical = match server_reg_canonical(record_b64) {
            Ok(c) => c,
            Err(_) => return err("bad_request"),
        };
        match self
            .core
            .net
            .set_password_bootstrap(user, token, &canonical, profile)
            .await
        {
            Ok(()) => ok_json(json!({"ok": true})),
            Err(UserOpError::BadBootstrapToken) => err("bad_token"),
            Err(UserOpError::PasswordExists) => err("password_exists"),
            Err(UserOpError::NoSuchUser) => err("bad_token"), // no enumeration
            Err(_) => err("internal"),
        }
    }

    // ========================================================================
    // Login endpoints
    // ========================================================================

    /// `POST /api/logout`: delete session + clear cookie.
    fn h_logout(&self, req: &Request, sess: Session) -> Response {
        if let Some(sid) = req.session_cookie() {
            self.sessions.logout(sid);
        }
        self.audit.record(
            self.now(),
            &sess.user,
            "session.logout",
            &sess.user,
            sess.origin,
            "ok",
        );
        Response::json(200, &json!({"ok": true})).with_header("Set-Cookie", &clear_cookie_value())
    }

    /// `GET /api/me`.
    fn h_me(&self, sess: Session) -> Response {
        ok_json(json!({
            "user": sess.user,
            "admin": sess.admin,
            "origin": sess.origin.as_str(),
            "expires_unix": sess.exp_unix,
        }))
    }

    // ========================================================================
    // Admin endpoints (users)
    // ========================================================================

    /// `GET /api/users` (username ascending).
    async fn h_users_list(&self) -> Response {
        let users = self.core.net.users_all().await;
        let devices = self.all_devices().await;
        let mut items: Vec<serde_json::Value> = users
            .into_iter()
            .map(|(name, row)| {
                let devices = devices.iter().filter(|(_, d)| d.owner == name).count();
                json!({
                    "username": name,
                    "admin": row.admin,
                    "disabled": row.disabled,
                    "has_password": row.opaque_record.is_some(),
                    "devices": devices,
                })
            })
            .collect();
        items.sort_by(|a, b| a["username"].as_str().cmp(&b["username"].as_str()));
        ok_json(json!({"users": items}))
    }

    /// `POST /api/users`: create (the response returns the bootstrap token
    /// once —— only this once, delivered to the user out of band).
    async fn h_users_create(
        &self,
        body: &serde_json::Value,
        sess: Session,
        origin: Origin,
    ) -> Response {
        let Some(username) = body["username"].as_str() else {
            return err("bad_request");
        };
        if !valid_username(username) {
            return err("bad_request");
        }
        let now = self.now();
        let token: [u8; 16] = rand::random();
        match self.core.net.create_user(username, token).await {
            Ok(()) => {
                self.audit
                    .record(now, &sess.user, "user.create", username, origin, "ok");
                ok_json(json!({
                    "username": username,
                    "pw_bootstrap_token": hex::encode(token),
                }))
            }
            Err(UserOpError::UserExists) => {
                self.audit
                    .record(now, &sess.user, "user.create", username, origin, "denied");
                err("user_exists")
            }
            Err(_) => err("internal"),
        }
    }

    /// `/api/users/{u}/disable|enable|reset-password|admin`.
    async fn h_user_action(
        &self,
        user: &str,
        action: &str,
        body: &serde_json::Value,
        sess: Session,
        origin: Origin,
    ) -> Response {
        if self.core.net.user_row(user).await.is_none() {
            return err("not_found");
        }
        let now = self.now();
        match action {
            "disable" => match self.core.net.set_user_disabled(user, true).await {
                Ok(()) => {
                    self.audit
                        .record(now, &sess.user, "user.disable", user, origin, "ok");
                    ok_json(json!({"ok": true}))
                }
                Err(_) => err("internal"),
            },
            "enable" => match self.core.net.set_user_disabled(user, false).await {
                Ok(()) => {
                    self.audit
                        .record(now, &sess.user, "user.enable", user, origin, "ok");
                    ok_json(json!({"ok": true}))
                }
                Err(_) => err("internal"),
            },
            "reset-password" => {
                let token: [u8; 16] = rand::random();
                match self.core.net.reset_password(user, token).await {
                    Ok(()) => {
                        self.audit.record(
                            now,
                            &sess.user,
                            "user.reset_password",
                            user,
                            origin,
                            "ok",
                        );
                        ok_json(json!({"pw_bootstrap_token": hex::encode(token)}))
                    }
                    Err(_) => err("internal"),
                }
            }
            "admin" => {
                let Some(admin) = body["admin"].as_bool() else {
                    return err("bad_request");
                };
                // cannot_demote_self: target == session user and admin=false
                // (adjudicated at the handler layer —— the state machine knows
                // nothing of the session principal, §M8.3).
                if user == sess.user && !admin {
                    self.audit
                        .record(now, &sess.user, "user.set_admin", user, origin, "denied");
                    return err("cannot_demote_self");
                }
                match self.core.net.set_user_admin(user, admin).await {
                    Ok(()) => {
                        self.audit
                            .record(now, &sess.user, "user.set_admin", user, origin, "ok");
                        ok_json(json!({"ok": true}))
                    }
                    Err(_) => err("internal"),
                }
            }
            _ => err("not_found"),
        }
    }

    // ========================================================================
    // peers (full registry rows ⋈ local lease view —— same assembly source as
    // the roster, different projection: includes device_id/status across all
    // states + VIP ascending, §M8.4)
    // ========================================================================

    /// Device-row snapshot (all states; single-server redb / multi-primary
    /// locally-applied view).
    async fn all_devices(&self) -> Vec<(DeviceId, crate::netstate::DeviceRow)> {
        match &self.core.net {
            NetBackend::Single(s) => s.devices_all(),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => s
                .node
                .devices_snapshot()
                .into_iter()
                .map(|(id, r)| (DeviceId(id), r))
                .collect(),
        }
    }

    async fn h_peers(&self) -> Response {
        ok_json(json!({"peers": self.assemble_peers().await}))
    }

    async fn assemble_peers(&self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let vip_str = |v: &[u8; 4]| format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]);
        let status_str = |s: DeviceStatus| match s {
            DeviceStatus::Active => "active",
            DeviceStatus::Disabled => "disabled",
            DeviceStatus::Revoked => "revoked",
            DeviceStatus::Expired => "expired",
        };
        match &self.core.net {
            NetBackend::Single(store) => {
                for (id, row) in store.devices_all() {
                    let (tx, rx, last_seen) =
                        self.core.traffic.stats(&row.vip).unwrap_or((0, 0, 0));
                    out.push(json!({
                        "device_id": hex::encode(id.0),
                        "vip": vip_str(&row.vip),
                        "hostname": row.hostname,
                        "owner": row.owner,
                        "kind": "device",
                        "online": self.core.sessions.online(&id.0) > 0,
                        "status": status_str(row.status),
                        "last_seen_unix": last_seen,
                        "tx_bps": tx,
                        "rx_bps": rx,
                    }));
                }
                let (stx, srx, sls) = self
                    .core
                    .traffic
                    .stats(crate::dataplane::SERVER_TRAFFIC_KEY)
                    .unwrap_or((0, 0, 0));
                out.push(json!({
                    "device_id": hex::encode(server_self_device_id_single(&self.core)),
                    "vip": vip_str(&self.core.cfg.vip.octets()),
                    "hostname": self.core.cfg.advertise_endpoint,
                    // owner = the decimal string of node_id (u64 >2^53) ——
                    // lossless as a String; the frontend detects "pure digit
                    // string" and renders it grouped/truncated.
                    "owner": flock_sync::node::node_id_of(&self.core.identity.server_id).to_string(),
                    "kind": "server",
                    "online": true,
                    "status": "active",
                    "last_seen_unix": sls,
                    "tx_bps": stx,
                    "rx_bps": srx,
                }));
            }
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                let node = &s.node;
                let leases = node.lease();
                for (dev, row) in node.devices_snapshot() {
                    let st = leases.peer_stats(&dev);
                    out.push(json!({
                        "device_id": hex::encode(dev),
                        "vip": vip_str(&row.vip),
                        "hostname": row.hostname,
                        "owner": row.owner,
                        "kind": "device",
                        "online": st.is_some_and(|x| x.online),
                        "status": status_str(row.status),
                        "last_seen_unix": st.map_or(0, |x| x.last_seen_unix),
                        "tx_bps": st.map_or(0, |x| x.tx_ewma),
                        "rx_bps": st.map_or(0, |x| x.rx_ewma),
                    }));
                }
                let dir_hosts: std::collections::BTreeMap<u64, String> = node
                    .directory()
                    .current()
                    .map(|d| {
                        d.servers
                            .iter()
                            .map(|e| {
                                (
                                    flock_sync::node::node_id_of(&e.server_id),
                                    e.relay_endpoint.clone(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                for (node_id, entry) in node.server_keys_snapshot() {
                    let st = leases.peer_stats(&flock_sync::lease::server_self_device_id(node_id));
                    out.push(json!({
                        "device_id": hex::encode(flock_sync::lease::server_self_device_id(node_id)),
                        "vip": vip_str(&entry.vip),
                        "hostname": dir_hosts.get(&node_id).cloned()
                            .unwrap_or_else(|| flock_sync::HOSTNAME_UNKNOWN.to_string()),
                        // owner = node_id decimal string (>2^53 lossless, frontend renders grouped).
                        "owner": node_id.to_string(),
                        "kind": "server",
                        "online": st.is_some_and(|x| x.online),
                        "status": "active",
                        "last_seen_unix": st.map_or(0, |x| x.last_seen_unix),
                        "tx_bps": st.map_or(0, |x| x.tx_ewma),
                        "rx_bps": st.map_or(0, |x| x.rx_ewma),
                    }));
                }
            }
        }
        out.sort_by_key(|p| p["vip"].as_str().unwrap_or("").to_string());
        out
    }

    /// `/api/peers/{device_id}/revoke|disable|enable|kick`.
    async fn h_peer_action(
        &self,
        dev_hex: &str,
        action: &str,
        sess: Session,
        origin: Origin,
    ) -> Response {
        let Ok(dev) = hex::decode(dev_hex) else {
            return err("not_found");
        };
        let Ok(dev): Result<[u8; 32], _> = dev.try_into() else {
            return err("not_found");
        };
        if self.core.net.device_row(&DeviceId(dev)).await.is_none() {
            return err("not_found");
        }
        let now = self.now();
        let audit = |result: &'static str, epoch: Option<u64>, action: &str| -> Response {
            self.audit
                .record(now, &sess.user, action, dev_hex, origin, result);
            match epoch {
                Some(e) => ok_json(json!({"ok": true, "epoch": e})),
                None if result == "ok" => ok_json(json!({"ok": true})),
                None => err("internal"),
            }
        };
        match action {
            "revoke" => match self.core.net.revoke(&DeviceId(dev)).await {
                Ok(epoch) => {
                    self.core.sessions.kill(&dev);
                    audit("ok", Some(epoch), "peer.revoke")
                }
                Err(_) => audit("error", None, "peer.revoke"),
            },
            "disable" => match self.core.net.disable(&DeviceId(dev)).await {
                Ok(epoch) => {
                    self.core.sessions.kill(&dev);
                    audit("ok", Some(epoch), "peer.disable")
                }
                Err(_) => audit("error", None, "peer.disable"),
            },
            "enable" => match self.core.net.enable(&DeviceId(dev)).await {
                Ok(()) => {
                    let e = self.core.net.epoch().await;
                    audit("ok", Some(e), "peer.enable")
                }
                Err(NetError::InvalidState(_)) => {
                    self.audit
                        .record(now, &sess.user, "peer.enable", dev_hex, origin, "denied");
                    err("invalid_state")
                }
                Err(_) => audit("error", None, "peer.enable"),
            },
            "kick" => {
                // Best-effort local: kill local sessions + detach the local
                // lease (multi-primary other machines not traced —— the device
                // comes back online on automatic reconnection; kick ≠ ban, use
                // disable/revoke for a definitive cutoff, §M8.4).
                self.core.sessions.kill(&dev);
                #[cfg(feature = "multi-primary")]
                if let Some(node) = &self.core.sync {
                    node.detach_session(&dev);
                }
                audit("ok", None, "peer.kick")
            }
            _ => err("not_found"),
        }
    }

    // ========================================================================
    // dashboard
    // ========================================================================

    async fn h_summary(&self) -> Response {
        let peers = self.assemble_peers().await;
        let devices = self.all_devices().await;
        let users = self.core.net.users_all().await.len();
        let (devices_active, devices_online) = (
            devices
                .iter()
                .filter(|(_, r)| r.status == DeviceStatus::Active)
                .count(),
            peers
                .iter()
                .filter(|p| p["kind"] == "device" && p["online"] == true)
                .count(),
        );
        let (tx_sum, rx_sum): (u64, u64) = peers.iter().fold((0, 0), |(t, r), p| {
            (
                t + p["tx_bps"].as_u64().unwrap_or(0),
                r + p["rx_bps"].as_u64().unwrap_or(0),
            )
        });
        let epoch = self.core.net.epoch().await;
        let sync_mode = sync_mode_of(&self.core);
        let servers = match &self.core.net {
            NetBackend::Single(_) => vec![json!({
                // node_id is a u64 derived from the first 8B of ServerId
                // (>2^53 to dodge JS precision loss —— JSON numbers parse as
                // double on the JS side, must be delivered as strings).
                "node_id": flock_sync::node::node_id_of(&self.core.identity.server_id).to_string(),
                "vip": format!("{}", self.core.cfg.vip),
                "endpoint": self.core.cfg.advertise_endpoint,
                "leader": true,
                "epoch": epoch,
                "online": true,
            })],
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                let node = &s.node;
                let leader = node.current_leader().await;
                let dir_eps: std::collections::BTreeMap<u64, String> = node
                    .directory()
                    .current()
                    .map(|d| {
                        d.servers
                            .iter()
                            .map(|e| {
                                (
                                    flock_sync::node::node_id_of(&e.server_id),
                                    e.relay_endpoint.clone(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                node.server_keys_snapshot()
                    .into_iter()
                    .map(|(node_id, entry)| {
                        let online = node
                            .lease()
                            .peer_stats(&flock_sync::lease::server_self_device_id(node_id))
                            .is_some_and(|x| x.online);
                        json!({
                            // node_id is a u64 (>2^53 to dodge JS precision loss —— delivered as string).
                            "node_id": node_id.to_string(),
                            "vip": format!("{}.{}.{}.{}", entry.vip[0], entry.vip[1], entry.vip[2], entry.vip[3]),
                            "endpoint": dir_eps.get(&node_id).cloned().unwrap_or_default(),
                            "leader": leader == Some(node_id),
                            "epoch": epoch, // locally-applied view (display tier)
                            "online": online,
                        })
                    })
                    .collect()
            }
        };
        ok_json(json!({
            "cluster": {
                "cluster_id": hex::encode(self.core.identity.cluster_id.0),
                "epoch": epoch,
                "sync_mode": sync_mode,
            },
            "servers": servers,
            "totals": {
                "devices": devices.len(),
                "devices_active": devices_active,
                "devices_online": devices_online,
                "users": users,
                "tx_bps_sum": tx_sum,
                "rx_bps_sum": rx_sum,
            },
            "self": {
                "server_id": hex::encode(self.core.identity.server_id.0),
                "uptime_secs": self.started.elapsed().as_secs(),
            },
        }))
    }

    async fn h_series(&self, query: &str) -> Response {
        // query is shaped like vip=100.64.0.11.
        let vip_str = query.split('&').find_map(|kv| kv.strip_prefix("vip="));
        let Some(vip_str) = vip_str else {
            return err("bad_request");
        };
        let Ok(vip) = vip_str.parse::<std::net::Ipv4Addr>() else {
            return err("bad_request");
        };
        let vip = vip.octets();
        // 404 decision: neither a series nor in the registry (devices across
        // all states + server VIPs).
        let in_registry = self.vip_in_registry(&vip).await;
        if !in_registry && !self.series.knows(&vip).await {
            return err("not_found");
        }
        let points: Vec<serde_json::Value> = self
            .series
            .snapshot(&vip)
            .await
            .into_iter()
            .map(|p| json!({"t": p.t, "tx_bps": p.tx_bps, "rx_bps": p.rx_bps}))
            .collect();
        ok_json(json!({
            "vip": vip_str,
            "interval_secs": self.series.interval_secs(),
            "points": points,
        }))
    }

    /// Registry arm of the 404 decision: local VIP + devices across all
    /// states + (multi-primary) remote server VIPs (server_keys local view ——
    /// green review item 7: Series resets on restart ⇒ before the first
    /// sample after a restart knows()=false, so remote-server VIP queries
    /// must hit this arm and return empty points rather than 404).
    async fn vip_in_registry(&self, vip: &[u8; 4]) -> bool {
        if *vip == self.core.cfg.vip.octets() {
            return true;
        }
        if self.all_devices().await.iter().any(|(_, r)| r.vip == *vip) {
            return true;
        }
        #[cfg(feature = "multi-primary")]
        if let NetBackend::Sync(s) = &self.core.net {
            if s.node
                .server_keys_snapshot()
                .iter()
                .any(|(_, e)| e.vip == *vip)
            {
                return true;
            }
        }
        false
    }

    fn h_config(&self) -> Response {
        // Field whitelist (§M8.7-5: no keys / no srvmesh peer table / no root
        // material).
        ok_json(json!({
            "listen_mode": self.core.cfg.mode,
            "advertise_endpoint": self.core.cfg.advertise_endpoint,
            "sync_mode": sync_mode_of(&self.core),
            "ticket_ttl_secs": self.core.cfg.ticket_ttl_secs,
            "peer_retention_days": self.core.cfg.peer_retention_days,
            "max_sessions": self.core.cfg.max_sessions,
            "webui": {
                "port": self.core.cfg.webui.port,
                "session_ttl_secs": self.core.cfg.webui.session_ttl_secs,
            },
        }))
    }

    fn h_audit(&self) -> Response {
        let entries: Vec<serde_json::Value> = self
            .audit
            .entries_newest_first()
            .into_iter()
            .map(|e| {
                json!({
                    "ts": e.ts,
                    "user": e.user,
                    "action": e.action,
                    "target": e.target,
                    "origin": e.origin.as_str(),
                    "result": e.result,
                })
            })
            .collect();
        ok_json(json!({"entries": entries}))
    }
}

/// sync_mode (converged field access gated by feature).
#[cfg(feature = "multi-primary")]
fn sync_mode_of(core: &ServerCore) -> &'static str {
    if core.sync.is_some() {
        "raft"
    } else {
        "single"
    }
}
#[cfg(not(feature = "multi-primary"))]
fn sync_mode_of(_core: &ServerCore) -> &'static str {
    "single"
}

fn b64_std(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)
}

/// The server-self device_id surface in single-server form (the device_id of
/// the peers' Server entry —— for diagnostic addressing).
fn server_self_device_id_single(core: &ServerCore) -> [u8; 32] {
    let node_id = flock_sync::node::node_id_of(&core.identity.server_id);
    // server_self_device_id is a deterministic derivation of node_id
    // (flock-sync lease); reuse it.
    flock_sync::lease::server_self_device_id(node_id)
}

// ============================================================================
// Unit tests (the pending-table surface of review item 3 —— evict the oldest
// when saturated / lazy expiry clearing)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    async fn state() -> Arc<WebState> {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_path_buf();
        std::mem::forget(dir);
        let cfg = crate::config::ServerConfig {
            state_dir,
            bind: "127.0.0.1:0".parse().unwrap(),
            mode: "direct".into(),
            advertise_endpoint: "127.0.0.1:9443".into(),
            extra_endpoints: vec![],
            dir_version: 1,
            ticket_ttl_secs: 60,
            peer_retention_days: 30,
            admin_bind: "127.0.0.1:0".parse().unwrap(),
            max_sessions: 1024,
            tun_name: "tun0".into(),
            vip: "100.64.0.1".parse().unwrap(),
            frp: None,
            sync: None,
            webui: Default::default(),
        };
        let (core, _) = crate::server::ServerCore::open_or_init(cfg).unwrap();
        Arc::new(WebState::new(core))
    }

    /// Saturated eviction picks the "oldest", not the lexicographic minimum
    /// (review item 3): after pre-filling large-lexicographic names to
    /// saturation, admin (lexicographically smallest) logging in is not
    /// evicted —— the old keys().min() implementation would evict admin's
    /// in-flight state (whose login-finish fails with login_failed for no
    /// reason).
    #[tokio::test]
    async fn pending_evicts_oldest_not_lexicographic_min() {
        let st = state().await;
        // Pre-fill PENDING_LOGIN_CAP-1 large-lexicographic names (z-user-NNNN).
        for i in 0..PENDING_LOGIN_CAP - 1 {
            st.put_pending(&format!("z-user-{i:04}"), vec![i as u8]);
        }
        assert_eq!(st.pending_len(), PENDING_LOGIN_CAP - 1);
        // admin begins last (lexicographically smallest —— what the old
        // implementation would evict on the next round).
        st.put_pending("admin", vec![0xAA]);
        assert_eq!(st.pending_len(), PENDING_LOGIN_CAP);
        // Trigger one more saturated eviction: should evict the oldest
        // (z-user-0000), not admin.
        st.put_pending("z-zzz", vec![0xBB]);
        assert_eq!(
            st.pending_len(),
            PENDING_LOGIN_CAP,
            "one in, one out keeps the cap"
        );
        assert_eq!(
            st.take_pending("admin"),
            Some(vec![0xAA]),
            "admin not evicted for lexicographic reasons (the evicted one is the oldest z-user-0000)"
        );
    }

    /// take_pending lazily expires stale rows: expired rows (including the
    /// requester's own) are neither returned nor left behind.
    #[tokio::test]
    async fn pending_take_lazy_expires_stale_rows() {
        let st = state().await;
        st.put_pending("fresh", vec![1]);
        st.put_pending("stale", vec![2]);
        // Force expiry directly (same-module test surface —— no clock-injection
        // seam introduced).
        st.pending
            .lock()
            .unwrap()
            .map
            .get_mut("stale")
            .unwrap()
            .exp_unix = 1;
        assert_eq!(st.take_pending("stale"), None, "expired rows not returned");
        // Any take lazily clears all expired rows (fresh kept).
        assert_eq!(st.take_pending("nobody"), None);
        assert_eq!(st.pending_len(), 1);
        assert_eq!(st.take_pending("fresh"), Some(vec![1]));
        assert_eq!(st.pending_len(), 0);
    }

    /// Wrong method on a known path ⇒ 405 (green review item 7): known path
    /// with a foreign method ⇒ 405 method_not_allowed (aligned with the
    /// §M8.4 error-code table; ahead of CSRF/session —— 405 even when not
    /// logged in); unknown path / unknown action ⇒ 404 (no mistaken
    /// swallowing).
    #[tokio::test]
    async fn method_mismatch_returns_405_not_404() {
        let st = state().await;
        for (method, path) in [
            ("GET", "/api/login-begin"),
            ("GET", "/api/login-finish"),
            ("GET", "/api/pw-begin"),
            ("GET", "/api/pw-commit"),
            ("POST", "/api/bootstrap"),
            ("POST", "/api/me"),
            ("POST", "/api/peers"),
            ("PUT", "/api/users"),
            ("DELETE", "/api/audit"),
            ("GET", "/api/logout"),
            ("GET", "/api/users/bob/disable"),
            ("GET", "/api/peers/abcd/revoke"),
        ] {
            let r = Request {
                method: method.into(),
                path: path.into(),
                query: String::new(),
                headers: vec![],
                body: vec![],
            };
            let resp = st.dispatch(r, remote()).await;
            assert_eq!(resp.status, 405, "{method} {path}");
            assert_eq!(code_of(&resp), "method_not_allowed", "{method} {path}");
        }
        // Unknown path / unknown action suffix ⇒ 404 not_found.
        for (method, path) in [
            ("GET", "/api/nope"),
            ("POST", "/api/peers/abcd/rename"),
            ("PUT", "/api/users/bob/rename"),
            ("GET", "/api/users/bob"),
        ] {
            let r = Request {
                method: method.into(),
                path: path.into(),
                query: String::new(),
                headers: vec![],
                body: vec![],
            };
            let resp = st.dispatch(r, remote()).await;
            assert_eq!(resp.status, 404, "{method} {path}");
            assert_eq!(code_of(&resp), "not_found", "{method} {path}");
        }
    }

    fn remote() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    /// Merge a user field into an extra object (the serde_json macro has no
    /// struct-update syntax).
    fn user_body(extra: &serde_json::Value, user: &str) -> serde_json::Value {
        let mut v = extra.clone();
        v["user"] = json!(user);
        v
    }

    /// POST carrier with both CSRF double-gate headers for the public auth
    /// endpoints.
    fn post_req(path: &str, body: &serde_json::Value) -> Request {
        Request {
            method: "POST".into(),
            path: path.into(),
            query: String::new(),
            headers: vec![
                ("X-Flock-Web".into(), "1".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: serde_json::to_vec(body).unwrap(),
        }
    }

    fn code_of(resp: &Response) -> String {
        serde_json::from_slice::<serde_json::Value>(&resp.body)
            .unwrap_or_default()
            .pointer("/error/code")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    }

    /// Demotion/disable take effect on old sessions immediately (review item
    /// 6): the admin snapshot inside the session row is not authoritative and
    /// disabled does not wait for the TTL —— the dispatch session slot reads
    /// back the UserRow (locally-applied view).
    #[tokio::test]
    async fn demote_and_disable_take_effect_on_next_request() {
        let st = state().await;
        st.core.net.create_user("boss", [1; 16]).await.unwrap();
        st.core.net.set_user_admin("boss", true).await.unwrap();
        let now = flock_protocol::trust::now_unix();
        let sid = st
            .sessions
            .issue("boss", true, Origin::Loopback, now, 28_800);
        let cookie = format!("flock_session={sid}");
        let get = |path: &str| Request {
            method: "GET".into(),
            path: path.into(),
            query: String::new(),
            headers: vec![("Cookie".into(), cookie.clone())],
            body: vec![],
        };

        // Baseline: the admin session works.
        let resp = st.dispatch(get("/api/users"), remote()).await;
        assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));

        // Demotion (set_admin=false): the old session gets 403 on its next
        // request (no waiting for the 8h TTL).
        st.core.net.set_user_admin("boss", false).await.unwrap();
        let resp = st.dispatch(get("/api/users"), remote()).await;
        assert_eq!(
            resp.status, 403,
            "old session 403 immediately after demotion"
        );
        assert_eq!(code_of(&resp), "forbidden");
        // /api/me still reachable (login tier), and the admin echo follows the
        // registry (false).
        let resp = st.dispatch(get("/api/me"), remote()).await;
        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(
            body["admin"], false,
            "me.admin follows the read-back UserRow"
        );
        // Restore admin.
        st.core.net.set_user_admin("boss", true).await.unwrap();
        assert_eq!(st.dispatch(get("/api/users"), remote()).await.status, 200);

        // Disable: any login-tier endpoint returns 401 user_disabled (ahead of
        // the role check —— same code on admin endpoints).
        st.core.net.set_user_disabled("boss", true).await.unwrap();
        let resp = st.dispatch(get("/api/me"), remote()).await;
        assert_eq!(
            resp.status, 401,
            "old session 401 immediately after disable"
        );
        assert_eq!(code_of(&resp), "user_disabled");
        let resp = st.dispatch(get("/api/users"), remote()).await;
        assert_eq!(
            resp.status, 401,
            "disable rejects admin endpoints on the same path"
        );
        assert_eq!(code_of(&resp), "user_disabled");
        // enable restores.
        st.core.net.set_user_disabled("boss", false).await.unwrap();
        assert_eq!(st.dispatch(get("/api/users"), remote()).await.status, 200);
    }

    /// String round-trip serialization of u64 identifiers (UI review item 1:
    /// ID precision loss): `servers[].node_id` (derived from the first 8B of
    /// ServerId, necessarily >2^53 —— a JSON number parsed as a JS double
    /// would lose the low bits) must be delivered as a **string** whose value
    /// matches `node_id_of`'s full decimal form; the peers server row's
    /// `owner` (a same-source pure-digit String) round-trips losslessly too.
    /// Small-magnitude u64 counters like epoch/timestamps are not on this
    /// surface (<2^53, stay numbers).
    #[tokio::test]
    async fn u64_ids_serialize_as_json_strings() {
        let st = state().await;
        st.core.net.create_user("boss", [1; 16]).await.unwrap();
        st.core.net.set_user_admin("boss", true).await.unwrap();
        let now = flock_protocol::trust::now_unix();
        let sid = st
            .sessions
            .issue("boss", true, Origin::Loopback, now, 28_800);
        let cookie = format!("flock_session={sid}");
        let get = |path: &str| Request {
            method: "GET".into(),
            path: path.into(),
            query: String::new(),
            headers: vec![("Cookie".into(), cookie.clone())],
            body: vec![],
        };

        // dashboard/summary: node_id is a JSON string, lossless in full
        // decimal.
        let resp = st.dispatch(get("/api/dashboard/summary"), remote()).await;
        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        let want = flock_sync::node::node_id_of(&st.core.identity.server_id).to_string();
        let node_id = &body["servers"][0]["node_id"];
        assert!(
            node_id.is_string(),
            "node_id must be a string (got {node_id})"
        );
        assert_eq!(
            node_id.as_str().unwrap(),
            want,
            "node_id full decimal lossless"
        );
        // Small-magnitude counters (epoch) stay numbers —— the precision
        // surface is bounded by "identifier vs counter".
        assert!(body["cluster"]["epoch"].is_u64());

        // peers: the server row's owner is a pure-digit String (the frontend
        // renders digit strings grouped/truncated).
        let resp = st.dispatch(get("/api/peers"), remote()).await;
        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        let server_row = body["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["kind"] == "server")
            .expect("single-server form always has a server self-row");
        let owner = server_row["owner"].as_str().unwrap();
        assert!(
            owner.chars().all(|c| c.is_ascii_digit()),
            "server row owner is the node_id decimal string (got {owner})"
        );
        assert_eq!(owner, &want, "owner matches summary.node_id at full value");
    }

    /// Audit stderr line-injection vectors rejected (review item 4): a user
    /// containing \n/\r/NUL / overlong (>64B) ⇒ the four public auth endpoints
    /// return 400 bad_request (the second sanitization layer is in the
    /// access.rs unit tests); an exactly-64B valid user passes the shape gate
    /// —— login-begin (real ke1) ⇒ 200, the others ⇒ 401 (not 400, proving
    /// the rejection is truly due to the user's shape rather than a later
    /// business tier).
    #[tokio::test]
    async fn auth_endpoints_reject_control_char_and_overlong_user() {
        let st = state().await;
        let inject = "evil\n2026-01-01 user=root action=peer.revoke";
        // Real ke1 (a 64B user takes the dummy same-shape path ⇒ 200 ——
        // evidence the shape gate passed).
        let user64 = "u".repeat(64);
        let (_, ke1) = flock_protocol::pake::login_start(
            &mut flock_protocol::rand::rngs::OsRng,
            "pw",
            &user64,
        )
        .unwrap();
        for (path, extra, pass_status) in [
            ("/api/login-begin", json!({"ke1_b64": ke1}), 200u16),
            (
                "/api/login-finish",
                json!({"ke3_b64": "AAAA"}),
                401, // no in-flight begin ⇒ login_failed
            ),
            (
                "/api/pw-begin",
                json!({"token": "00".repeat(16), "m1_b64": "AAAA"}),
                401, // unknown user same bad_token (no enumeration)
            ),
            (
                "/api/pw-commit",
                json!({"token": "00".repeat(16), "record_b64": "AAAA"}),
                401, // NoSuchUser ⇒ bad_token
            ),
        ] {
            // \n / \r / NUL injection vectors ⇒ 400.
            for bad in [inject, "evil\rx", "u\u{0}x"] {
                let resp = st
                    .dispatch(post_req(path, &user_body(&extra, bad)), remote())
                    .await;
                assert_eq!(resp.status, 400, "{path} rejects {bad:?}");
                assert_eq!(code_of(&resp), "bad_request");
            }
            // > 64B ⇒ 400 (all four endpoints aligned to login-begin's length
            // cap).
            let resp = st
                .dispatch(
                    post_req(path, &user_body(&extra, &"u".repeat(65))),
                    remote(),
                )
                .await;
            assert_eq!(resp.status, 400, "{path} rejects 65B user");
            // Exactly 64B ⇒ passes the shape gate (the business tier takes
            // over —— not 400).
            let resp = st
                .dispatch(post_req(path, &user_body(&extra, &user64)), remote())
                .await;
            assert_eq!(
                resp.status,
                pass_status,
                "{path} 64B user passes the shape gate: {}",
                String::from_utf8_lossy(&resp.body)
            );
        }
    }
}
