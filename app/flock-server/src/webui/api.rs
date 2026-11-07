//! M8 webui API 分发与全部 handler（docs/design.md §7-M8.4 契约逐字）。
//!
//! 分发序（定死，测试断言「先会话后角色」）：
//! **来源矩阵（403 forbidden_origin）→ 路由（404）→ 方法（405）→ CSRF 双门槛
//!（400）→ 会话（401 not_logged_in）→ 角色（403 forbidden）→ handler**。
//!
//! 写操作双臂（§M8.3 裁决 2）：Raft 普通写（多主）/ 单服直写——全部经
//! [`crate::backend::NetBackend`]（与控制流 DeviceOp 同型）；授权在 handler 层
//!（会话 user 须 admin），不经也不放宽 `admin_op` 根签操作。
//!
//! 登录链（§M8.3）：`login-begin/finish` 调同一组 `pake::server_*`（dummy 同形防
//! 枚举）；anchor = 服务端身份签名（`anchor_sign`）——/api/bootstrap 提供
//! `identity_pub` 验签材料。pending 登录态按 user 单槽（末次 begin 覆盖）+ 5min
//! 过期 + 256 上限。

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
use super::access::{classify_origin, csrf_gate_ok, required_role, IpBuckets, LoginBackoff, Role};
use super::assets;
use super::http::{Request, Response};
use super::series::Series;
use super::session::{clear_cookie_value, set_cookie_value, Origin, Session, Sessions};

/// webui 并发上限（独立信号量；§M8.1 缺省 64）。
pub const MAX_CONCURRENCY: usize = 64;
/// pending 登录态过期（login-begin → login-finish 的窗口）。
const PENDING_LOGIN_TTL: u64 = 300;
/// pending 登录态表上限（未认证攻击面——超限逐出最旧）。
const PENDING_LOGIN_CAP: usize = 256;
/// 用户名字符集（§M8.4：1..=32B、[A-Za-z0-9_.-]）。
fn valid_username(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 32
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

// ============================================================================
// 错误信封（§M8.4 逐字）
// ============================================================================

/// 错误码 → HTTP 映射（定死）。
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

/// 白名单文案（不含路径/内部错误串——§M8.7-5）。
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

/// 带附加字段（rate_limited 的 retry_after_secs）。
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

/// pending 登录态（user 单槽——末次 begin 覆盖）。
struct PendingLogin {
    state: Vec<u8>,
    exp_unix: u64,
}

/// webui 装配态（serve/mod.rs 构建；测试直接构造以注入源地址）。
pub struct WebState {
    pub core: Arc<ServerCore>,
    pub sessions: Arc<Sessions>,
    pub backoff: Arc<LoginBackoff>,
    pub buckets: Arc<IpBuckets>,
    pub audit: Arc<AuditLog>,
    pub series: Arc<Series>,
    pub ttl_secs: u64,
    pub started: std::time::Instant,
    pending: std::sync::Mutex<std::collections::HashMap<String, PendingLogin>>,
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
            pending: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn now(&self) -> u64 {
        flock_protocol::trust::now_unix()
    }

    fn put_pending(&self, user: &str, state: Vec<u8>) {
        let mut g = self.pending.lock().expect("pending poisoned");
        if g.len() >= PENDING_LOGIN_CAP {
            if let Some(k) = g.keys().min().cloned() {
                g.remove(&k);
            }
        }
        g.insert(
            user.to_string(),
            PendingLogin {
                state,
                exp_unix: self.now() + PENDING_LOGIN_TTL,
            },
        );
    }

    fn take_pending(&self, user: &str) -> Option<Vec<u8>> {
        let mut g = self.pending.lock().expect("pending poisoned");
        let now = self.now();
        g.remove(user).filter(|p| p.exp_unix > now).map(|p| p.state)
    }

    // ========================================================================
    // 分发（契约序：来源 → 路由 → 方法 → CSRF → 会话 → 角色 → handler）
    // ========================================================================

    pub async fn dispatch(&self, req: Request, remote: SocketAddr) -> Response {
        // ① 来源矩阵（W-A3 纵深防御；XFF 一律不读——W-A4）。
        let Some(origin) = classify_origin(&remote) else {
            return err("forbidden_origin");
        };
        // ② 静态资产与 SPA fallback（非 /api/*）。
        if !req.path.starts_with("/api/") {
            return self.static_route(&req);
        }
        // ③ 路由档（未知 /api/* → 404）。
        let role = required_role(&req.method, &req.path);
        if role == Role::Unknown {
            return err("not_found");
        }
        // ④ 方法（required_role 已含方法匹配——不匹配即 Unknown；此处不再 405）。
        // ⑤ CSRF 双门槛（变更类 = 全部 POST）。
        if !csrf_gate_ok(
            &req.method,
            req.header("x-flock-web"),
            req.header("content-type"),
        ) {
            return err("bad_request");
        }
        // ⑥ 会话（401）先于 ⑦ 角色（403）。
        let sess = match role {
            Role::Public => None,
            _ => {
                let Some(sid) = req.session_cookie() else {
                    return err("not_logged_in");
                };
                match self.sessions.lookup(sid, self.now()) {
                    Some(s) => Some(s),
                    None => return err("not_logged_in"),
                }
            }
        };
        if role == Role::Admin && !sess.as_ref().is_some_and(|s| s.admin) {
            return err("forbidden");
        }
        // ⑧ handler。
        self.handle(&req, remote, origin, sess).await
    }

    fn static_route(&self, req: &Request) -> Response {
        if req.method != "GET" {
            return err("method_not_allowed");
        }
        // SPA fallback（§M8.6 hash 路由的直击/刷新面）：未知非 /api 路径一律回
        // index.html（200）——浏览器端 hash 路由接管；/api/* 不经本函数（404 JSON
        // 面不fallback——API 客户端不吞 HTML）。
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
                // 路径参数形（required_role 已确认档位）。
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
    // 公共端点
    // ========================================================================

    /// `GET /api/bootstrap`：本服务器身份（wasm 侧 anchor 验签材料）。
    fn h_bootstrap(&self) -> Response {
        ok_json(json!({
            "cluster_id": hex::encode(self.core.identity.cluster_id.0),
            "server_id": hex::encode(self.core.identity.server_id.0),
            "identity_pub": b64_std(self.core.identity.identity.verifying_key().as_bytes()),
            "lang": "zh-CN",
        }))
    }

    /// `POST /api/login-begin`：OPAQUE ke1 → ke2 + anchor（dummy 同形防枚举；
    /// per-IP 令牌桶 + 用户名退避）。
    async fn h_login_begin(&self, body: &serde_json::Value, remote: SocketAddr) -> Response {
        let (Some(user), Some(ke1_b64)) = (body["user"].as_str(), body["ke1_b64"].as_str()) else {
            return err("bad_request");
        };
        if user.is_empty() || user.len() > 64 || ke1_b64.len() > 64 * 1024 {
            return err("bad_request");
        }
        // per-IP 令牌桶（login-begin/pw-begin 共用档）。
        if let Err(retry) = self.buckets.allow(remote.ip(), self.now()) {
            return err_with("rate_limited", Some(retry));
        }
        // 用户名退避（锁定中 ⇒ 429）。
        if let Some(retry) = self.backoff.check(user, self.now()) {
            return err_with("rate_limited", Some(retry));
        }
        // 记录侧：未知用户/未设密码 ⇒ dummy（ke2 同形防枚举）；**disabled 用户仍用
        // 真记录**——ke2 同形不泄漏禁用态，且诚实客户端得以完成 ke3、在 login-finish
        // 收到 401 user_disabled（§M8.3「login-begin 仍 dummy 同形不泄漏」指未知
        // 用户面；禁用判定发生在口令证明成立之后——不泄漏任何额外信息）。
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
            Err(_) => return err("bad_request"), // 坏 ke1（b64/结构）
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

    /// `POST /api/login-finish`：ke3 验证 → 会话签发（统一 401；退避/审计联动）。
    async fn h_login_finish(&self, body: &serde_json::Value, origin: Origin) -> Response {
        let (Some(user), Some(ke3_b64)) = (body["user"].as_str(), body["ke3_b64"].as_str()) else {
            return err("bad_request");
        };
        if let Some(retry) = self.backoff.check(user, self.now()) {
            return err_with("rate_limited", Some(retry));
        }
        let Some(state) = self.take_pending(user) else {
            return err("login_failed"); // 无在途 begin（未 begin/已消费/过期）
        };
        let finish_ts = self.now();
        if server_login_finish(&state, ke3_b64).is_err() {
            // 失败记账（第 5 次起锁定）+ 审计 error 行。
            self.backoff.on_failure(user, finish_ts);
            self.audit
                .record(finish_ts, user, "session.login", user, origin, "error");
            return err("login_failed");
        }
        // 口令证明成立——退避清零；随后账号态判定（disabled 不计失败）。
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

    /// `POST /api/pw-begin`：引导令牌预检（只读、不消费）→ m2。
    async fn h_pw_begin(&self, body: &serde_json::Value, remote: SocketAddr) -> Response {
        let (Some(user), Some(token_hex), Some(m1_b64)) = (
            body["user"].as_str(),
            body["token"].as_str(),
            body["m1_b64"].as_str(),
        ) else {
            return err("bad_request");
        };
        let Ok(token) = hex::decode(token_hex) else {
            return err("bad_token");
        };
        let Ok(token): Result<[u8; 16], _> = token.try_into() else {
            return err("bad_token");
        };
        if let Err(retry) = self.buckets.allow(remote.ip(), self.now()) {
            return err_with("rate_limited", Some(retry));
        }
        // 只读预检：令牌匹配（未知用户同错——不枚举）；记录已有 ⇒ password_exists。
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

    /// `POST /api/pw-commit`：原子消费令牌 + 落记录（Raft/直写单点提交）。
    async fn h_pw_commit(&self, body: &serde_json::Value) -> Response {
        let (Some(user), Some(token_hex), Some(record_b64)) = (
            body["user"].as_str(),
            body["token"].as_str(),
            body["record_b64"].as_str(),
        ) else {
            return err("bad_request");
        };
        let profile = body["profile"].as_u64().unwrap_or(0) as u16;
        let Ok(token) = hex::decode(token_hex) else {
            return err("bad_token");
        };
        let Ok(token): Result<[u8; 16], _> = token.try_into() else {
            return err("bad_token");
        };
        // 记录规范化（解码验证——坏 b64 ⇒ 400，不进写路径）。
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
            Err(UserOpError::NoSuchUser) => err("bad_token"), // 不枚举
            Err(_) => err("internal"),
        }
    }

    // ========================================================================
    // 登录端点
    // ========================================================================

    /// `POST /api/logout`：删会话 + 清 cookie。
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

    /// `GET /api/me`。
    fn h_me(&self, sess: Session) -> Response {
        ok_json(json!({
            "user": sess.user,
            "admin": sess.admin,
            "origin": sess.origin.as_str(),
            "expires_unix": sess.exp_unix,
        }))
    }

    // ========================================================================
    // 管理端点（users）
    // ========================================================================

    /// `GET /api/users`（username 升序）。
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

    /// `POST /api/users`：创建（响应一次性返回引导令牌——仅此一次，线下交付用户）。
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

    /// `/api/users/{u}/disable|enable|reset-password|admin`。
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
                // cannot_demote_self：目标 == 会话用户且 admin=false（handler 层裁决
                //——状态机不知会话主体，§M8.3）。
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
    // peers（注册表全行 ⋈ 本地租约视图——名册同装配源、不同投影：含 device_id/
    // status 全状态 + VIP 升序，§M8.4）
    // ========================================================================

    /// 设备行快照（全状态；单服 redb / 多主本地已 apply 视图）。
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

    /// `/api/peers/{device_id}/revoke|disable|enable|kick`。
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
                // 尽力本地：杀本机会话 + detach 本机租约（多主他机不追溯——设备自动
                // 重连会重新上线；kick ≠ 封禁，确定断离用 disable/revoke，§M8.4）。
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
                "node_id": flock_sync::node::node_id_of(&self.core.identity.server_id),
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
                            "node_id": node_id,
                            "vip": format!("{}.{}.{}.{}", entry.vip[0], entry.vip[1], entry.vip[2], entry.vip[3]),
                            "endpoint": dir_eps.get(&node_id).cloned().unwrap_or_default(),
                            "leader": leader == Some(node_id),
                            "epoch": epoch, // 本机已 apply 视图（展示面档位）
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
        // query 形如 vip=100.64.0.11。
        let vip_str = query.split('&').find_map(|kv| kv.strip_prefix("vip="));
        let Some(vip_str) = vip_str else {
            return err("bad_request");
        };
        let Ok(vip) = vip_str.parse::<std::net::Ipv4Addr>() else {
            return err("bad_request");
        };
        let vip = vip.octets();
        // 404 判定：既无序列也不在注册表（设备全状态 + 服务器 VIP）。
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

    async fn vip_in_registry(&self, vip: &[u8; 4]) -> bool {
        if *vip == self.core.cfg.vip.octets() {
            return true;
        }
        self.all_devices().await.iter().any(|(_, r)| r.vip == *vip)
    }

    fn h_config(&self) -> Response {
        // 字段白名单（§M8.7-5：无密钥/无 srvmesh 对端表/无根材料）。
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

/// sync_mode（feature 门控的字段访问收敛）。
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

/// 单服形态服务器自身的 device_id 面（peers 的 Server 条目 device_id——诊断寻址用）。
fn server_self_device_id_single(core: &ServerCore) -> [u8; 32] {
    let node_id = flock_sync::node::node_id_of(&core.identity.server_id);
    // server_self_device_id 是 node_id 的确定性推导（flock-sync lease）；复用之。
    flock_sync::lease::server_self_device_id(node_id)
}
