//! M8 webui HTTP e2e（docs/design.md §7-M8.9——进程内真 HTTP + 原生 pake 客户端，
//! 协议同构、绕过 wasm）。
//!
//! 覆盖（集成清单逐字）：
//! 1. 未登录除公共端点外全 401（枚举全部端点）+ 壳页/bootstrap 公共面；
//! 2. 首 admin 引导（`web-admin-add` 的直写路径函数）→ bootstrap → login（anchor
//!    验签过）→ cookie 会话 → me/users CRUD（admin/非 admin 403/cannot_demote_self）
//!    → pw-begin/commit 令牌原子（重放拒）→ peers/summary/series/audit → logout
//!    后原 sid 401；
//! 3. dummy 同形（未知用户 ke2 有形）/错口令 401/禁用 401 user_disabled/限速 429；
//! 4. 访问矩阵（loopback/VPN 段/伪造 XFF）经注入连接源地址（mod.rs 单测面，此处
//!    以真 HTTP 的 loopback 面收口）。

use std::io::BufRead as _;
use std::sync::Arc;

use base64::Engine as _;
use serde_json::{json, Value};

use flock_protocol::ed25519_dalek::VerifyingKey;
use flock_protocol::pake::{login_start, reg_start};
use flock_protocol::rand;
use flock_server::admin::web_pw_commit;
use flock_server::config::ServerConfig;
use flock_server::control::client_login_finish_anchored;
use flock_server::server::ServerCore;
use flock_server::webui::{self, api::WebState};

// ============================================================================
// 载具：真 HTTP 客户端（tokio TcpStream + 手写请求——不引 reqwest）
// ============================================================================

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or("")
    }
    fn cookie_sid(&self) -> Option<String> {
        let sc = self.header("set-cookie")?;
        let kv = sc.split(';').next()?;
        kv.strip_prefix("flock_session=").map(|s| s.to_string())
    }
}

/// 一条 HTTP 请求（keep-alive 语义不需要——每请求新连接，`Connection: close`）。
async fn http(
    base: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Resp {
    let mut io = tokio::net::TcpStream::connect(base).await.expect("connect");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: webui-test\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("Connection: close\r\n\r\n");
    req.push_str(body);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    io.write_all(req.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    io.read_to_end(&mut raw).await.expect("read");
    parse_resp(&raw)
}

fn parse_resp(raw: &[u8]) -> Resp {
    let text = String::from_utf8_lossy(raw);
    let mut parts = text.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body_raw = parts.next().unwrap_or("");
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let body: Value = if body_raw.trim().starts_with('{') {
        serde_json::from_str(body_raw).unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    Resp {
        status,
        headers,
        body,
    }
}

fn gates() -> Vec<(&'static str, &'static str)> {
    vec![("X-Flock-Web", "1")]
}

async fn get(base: std::net::SocketAddr, path: &str, cookie: Option<&str>) -> Resp {
    let mut h = gates();
    if let Some(c) = cookie {
        h.push((
            "Cookie",
            Box::leak(format!("flock_session={c}").into_boxed_str()),
        ));
    }
    http(base, "GET", path, &h, "").await
}

async fn post(base: std::net::SocketAddr, path: &str, cookie: Option<&str>, body: &Value) -> Resp {
    let mut h = gates();
    if let Some(c) = cookie {
        h.push((
            "Cookie",
            Box::leak(format!("flock_session={c}").into_boxed_str()),
        ));
    }
    http(base, "POST", path, &h, &body.to_string()).await
}

// ============================================================================
// 载具：服务器（WebState 注入 + web-admin-add 直写路径函数）
// ============================================================================

struct TestWeb {
    base: std::net::SocketAddr,
    core: Arc<ServerCore>,
    state: Arc<WebState>,
    _task: tokio::task::JoinHandle<()>,
}

fn test_cfg(state_dir: std::path::PathBuf) -> ServerConfig {
    ServerConfig {
        state_dir,
        bind: "127.0.0.1:0".parse().unwrap(),
        mode: "direct".into(),
        advertise_endpoint: "127.0.0.1:19443".into(),
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
        webui: crate_webui_cfg(),
    }
}

fn crate_webui_cfg() -> flock_server::config::WebUiSection {
    flock_server::config::WebUiSection {
        enabled: true,
        port: 0, // ephemeral——serve 返回实际地址
        session_ttl_secs: 28_800,
        series_points: 120,
        series_interval_secs: 60,
    }
}

async fn start_web() -> TestWeb {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().to_path_buf();
    std::mem::forget(dir);
    let (core, _) = ServerCore::open_or_init(test_cfg(state_dir)).expect("core");
    let state = Arc::new(WebState::new(core.clone()));
    let (task, base) = webui::serve_state(core.clone(), state.clone())
        .await
        .expect("webui serve");
    TestWeb {
        base,
        core,
        state,
        _task: task,
    }
}

/// `web-admin-add` 的直写路径函数（CLI fallback 的同一实现面：reg_start →
/// 本机 OPRF m2 → reg_finish → [`web_pw_commit`]；admin=true）。
async fn web_admin_add_direct(core: &ServerCore, user: &str, pw: &str) {
    // 已有口令 ⇒ panic（测试面与 CLI 同语义拒）。
    assert!(
        !core
            .net
            .user_row(user)
            .await
            .is_some_and(|r| r.opaque_record.is_some()),
        "web_admin_add_direct: {user} 已有口令"
    );
    let mut rng = rand::rngs::OsRng;
    let (cstate, m1) = reg_start(&mut rng, pw, user).unwrap();
    let m2 = flock_protocol::pake::server_reg_start(&core.oprf, &m1, user).unwrap();
    let record = flock_protocol::pake::reg_finish(&mut rng, cstate, pw, user, &m2).unwrap();
    let token: [u8; 16] = rand::random();
    web_pw_commit(core, user, token, &record, 0, true)
        .await
        .expect("web_pw_commit");
}

/// 原生 OPAQUE 登录（anchor 验签——/api/bootstrap 取 identity_pub）。
/// Ok(cookie)：登录成功；Err(ke1_state 无用) 由调用方按需驱动失败面。
async fn pake_login(
    base: std::net::SocketAddr,
    core: &ServerCore,
    user: &str,
    pw: &str,
) -> Result<(String, Value), String> {
    let boot = get(base, "/api/bootstrap", None).await;
    assert_eq!(boot.status, 200, "bootstrap");
    let pub_bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(boot.body["identity_pub"].as_str().unwrap())
        .unwrap();
    let identity_pub = VerifyingKey::from_bytes(pub_bytes.as_slice().try_into().unwrap()).unwrap();

    let (lstate, ke1) = login_start(&mut rand::rngs::OsRng, pw, user).unwrap();
    let r = post(
        base,
        "/api/login-begin",
        None,
        &json!({"user": user, "ke1_b64": ke1}),
    )
    .await;
    assert_eq!(r.status, 200, "login-begin: {}", r.body);
    let ke2 = r.body["ke2_b64"].as_str().unwrap().to_string();
    let bind_token = hex::decode(r.body["bind_token"].as_str().unwrap()).unwrap();
    let bind_token: [u8; 16] = bind_token.try_into().unwrap();
    let anchor_sig = hex::decode(r.body["anchor_sig"].as_str().unwrap()).unwrap();
    let server_id = core.identity.server_id.0;
    // anchor 验签（错集群/错服务器响应混装在此拦截）。
    let ke3 = client_login_finish_anchored(
        lstate,
        pw,
        user,
        &ke2,
        flock_server::control::AnchorLoginExpectation {
            server_id,
            identity_pub,
            bind_token,
            anchor_sig,
        },
    )
    .map_err(|e| format!("client finish: {e}"))?;
    let r = post(
        base,
        "/api/login-finish",
        None,
        &json!({"user": user, "ke3_b64": ke3}),
    )
    .await;
    if r.status != 200 {
        return Err(format!("login-finish {} {}", r.status, r.code()));
    }
    Ok((r.cookie_sid().expect("Set-Cookie"), r.body))
}

// ============================================================================
// ① 未登录 401 矩阵 + 公共面
// ============================================================================

#[tokio::test]
async fn unauthenticated_matrix_and_public_surface() {
    let w = start_web().await;
    // 公共面：壳页 + bootstrap（无需会话）。
    let idx = http(w.base, "GET", "/", &[], "").await;
    assert_eq!(idx.status, 200);
    let boot = get(w.base, "/api/bootstrap", None).await;
    assert_eq!(boot.status, 200);
    for k in ["cluster_id", "server_id", "identity_pub", "lang"] {
        assert!(boot.body[k].is_string(), "bootstrap.{k}");
    }
    assert_eq!(boot.body["lang"], "zh-CN");
    // login-begin 公共（坏 ke1 ⇒ 400——不需会话即达 handler）。
    let r = post(
        w.base,
        "/api/login-begin",
        None,
        &json!({"user": "x", "ke1_b64": "!!!"}),
    )
    .await;
    assert_eq!(r.status, 400, "公共端点可达（坏 ke1 ⇒ 400）");
    // 全部受保护端点 ⇒ 401 not_logged_in（先于角色——403 面在登录后）。
    for path in [
        "/api/me",
        "/api/peers",
        "/api/dashboard/summary",
        "/api/dashboard/series?vip=100.64.0.1",
        "/api/config",
        "/api/users",
        "/api/audit",
    ] {
        let r = get(w.base, path, None).await;
        assert_eq!(r.status, 401, "{path}");
        assert_eq!(r.code(), "not_logged_in", "{path}");
    }
    for (path, body) in [
        ("/api/logout", json!({})),
        ("/api/users", json!({"username": "bob"})),
        ("/api/users/bob/disable", json!({})),
        ("/api/users/bob/enable", json!({})),
        ("/api/users/bob/reset-password", json!({})),
        ("/api/users/bob/admin", json!({"admin": true})),
        ("/api/peers/abcd/revoke", json!({})),
        ("/api/peers/abcd/kick", json!({})),
    ] {
        let r = post(w.base, path, None, &body).await;
        assert_eq!(r.status, 401, "{path}");
        assert_eq!(r.code(), "not_logged_in", "{path}");
    }
    // CSRF：POST 缺 X-Flock-Web ⇒ 400（对公共端点同样生效）。
    let r = http(
        w.base,
        "POST",
        "/api/login-begin",
        &[("Content-Type", "application/json")],
        "{\"user\":\"x\",\"ke1_b64\":\"y\"}",
    )
    .await;
    assert_eq!(r.status, 400);
    assert_eq!(r.code(), "bad_request");
}

// ============================================================================
// ② 全链：首 admin 引导 → 登录 → CRUD → 令牌原子 → peers/summary/series/audit →
//    logout；失败面（dummy/错口令/禁用/限速）收口
// ============================================================================

#[tokio::test]
async fn full_chain_admin_login_crud_token_atomic_and_logout() {
    let w = start_web().await;
    // 首 admin 引导（web-admin-add 直写路径）。
    web_admin_add_direct(&w.core, "boss", "S3cret-1").await;

    // dummy 同形：未知用户 login-begin 仍 200 + ke2 有形。
    let (lstate_ghost, ke1) = login_start(&mut rand::rngs::OsRng, "whatever", "ghost").unwrap();
    let r = post(
        w.base,
        "/api/login-begin",
        None,
        &json!({"user": "ghost", "ke1_b64": ke1}),
    )
    .await;
    assert_eq!(r.status, 200, "未知用户 ke2 同形");
    assert!(r.body["ke2_b64"].as_str().is_some_and(|s| !s.is_empty()));
    // 客户端 finish 必失败（本地——dummy 记录路径）。
    assert!(flock_protocol::pake::login_finish(
        lstate_ghost,
        "whatever",
        "ghost",
        r.body["ke2_b64"].as_str().unwrap()
    )
    .is_err());

    // admin 登录（anchor 验签过）→ cookie 会话。
    let (cookie, me) = pake_login(w.base, &w.core, "boss", "S3cret-1")
        .await
        .expect("login");
    assert_eq!(me["user"], "boss");
    assert_eq!(me["admin"], true);
    // /api/me：origin 回显 loopback。
    let r = get(w.base, "/api/me", Some(&cookie)).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body["user"], "boss");
    assert_eq!(r.body["origin"], "loopback");
    assert!(r.body["expires_unix"].as_u64().is_some_and(|e| e > 0));

    // 伪造 ke3 直发 ⇒ 401 login_failed（错口令的服务端可观测面：诚实客户端在
    // 本地 finish 即失败、不发第三请求——OPAQUE 语义；无在途 begin 同码）。
    let r = post(
        w.base,
        "/api/login-finish",
        None,
        &json!({"user": "boss", "ke3_b64": "AAAA"}),
    )
    .await;
    assert_eq!(r.status, 401);
    assert_eq!(r.code(), "login_failed");

    // users：创建 bob（令牌仅此一次）。
    let r = post(
        w.base,
        "/api/users",
        Some(&cookie),
        &json!({"username": "bob"}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let token = r.body["pw_bootstrap_token"].as_str().unwrap().to_string();
    assert_eq!(token.len(), 32, "16B hex32");
    // 重名 ⇒ 409 user_exists；坏用户名 ⇒ 400。
    let r = post(
        w.base,
        "/api/users",
        Some(&cookie),
        &json!({"username": "bob"}),
    )
    .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "user_exists");
    for bad in ["", "x!", &"u".repeat(33)] {
        let r = post(
            w.base,
            "/api/users",
            Some(&cookie),
            &json!({"username": bad}),
        )
        .await;
        assert_eq!(r.status, 400, "坏用户名 {bad:?}");
    }

    // pw-begin 令牌错 ⇒ 401 bad_token；正确 ⇒ m2；未知用户同错（不枚举）。
    let (cstate, m1) = reg_start(&mut rand::rngs::OsRng, "Bob-Pw-2", "bob").unwrap();
    let r = post(
        w.base,
        "/api/pw-begin",
        None,
        &json!({"user": "bob", "token": "00".repeat(16), "m1_b64": m1}),
    )
    .await;
    assert_eq!(r.status, 401);
    assert_eq!(r.code(), "bad_token");
    let r = post(
        w.base,
        "/api/pw-begin",
        None,
        &json!({"user": "ghost", "token": &token, "m1_b64": m1}),
    )
    .await;
    assert_eq!(r.status, 401, "未知用户同 bad_token（不枚举）");
    let r = post(
        w.base,
        "/api/pw-begin",
        None,
        &json!({"user": "bob", "token": &token, "m1_b64": m1}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let m2 = r.body["m2_b64"].as_str().unwrap().to_string();
    let record =
        flock_protocol::pake::reg_finish(&mut rand::rngs::OsRng, cstate, "Bob-Pw-2", "bob", &m2)
            .unwrap();

    // pw-commit：原子落记录 + 消费令牌；重放 ⇒ 401 bad_token；再 begin ⇒
    // bad_token（令牌已消费）。
    let r = post(
        w.base,
        "/api/pw-commit",
        None,
        &json!({"user": "bob", "token": &token, "record_b64": record, "profile": 0}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = post(
        w.base,
        "/api/pw-commit",
        None,
        &json!({"user": "bob", "token": &token, "record_b64": record, "profile": 0}),
    )
    .await;
    assert_eq!(r.status, 401, "令牌重放拒");
    assert_eq!(r.code(), "bad_token");
    let r = post(
        w.base,
        "/api/pw-begin",
        None,
        &json!({"user": "bob", "token": &token, "m1_b64": "AAAA"}),
    )
    .await;
    assert_eq!(r.status, 401, "消费后 begin 同 bad_token");

    // users 列表：username 升序 + has_password/devices 计数。
    let r = get(w.base, "/api/users", Some(&cookie)).await;
    assert_eq!(r.status, 200);
    let names: Vec<&str> = r.body["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["bob", "boss"], "username 升序");
    let bob = &r.body["users"][0];
    assert_eq!(bob["has_password"], true);
    assert_eq!(bob["admin"], false);

    // 禁用 ⇒ bob 登录 finish 401 user_disabled（口令证明成立后判定）；enable 恢复。
    let r = post(w.base, "/api/users/bob/disable", Some(&cookie), &json!({})).await;
    assert_eq!(r.status, 200);
    let r = post(w.base, "/api/users/bob/enable", Some(&cookie), &json!({})).await;
    assert_eq!(r.status, 200);
    let r = post(w.base, "/api/users/bob/disable", Some(&cookie), &json!({})).await;
    assert_eq!(r.status, 200);
    let err = pake_login(w.base, &w.core, "bob", "Bob-Pw-2")
        .await
        .expect_err("disabled");
    assert!(err.contains("user_disabled"), "{err}");
    let r = post(w.base, "/api/users/bob/enable", Some(&cookie), &json!({})).await;
    assert_eq!(r.status, 200);
    let (bob_cookie, _) = pake_login(w.base, &w.core, "bob", "Bob-Pw-2")
        .await
        .expect("enable 后登录");

    // 非 admin 403 矩阵（bob）。
    for path in ["/api/users", "/api/audit"] {
        let r = get(w.base, path, Some(&bob_cookie)).await;
        assert_eq!(r.status, 403, "{path}");
        assert_eq!(r.code(), "forbidden");
    }
    let r = post(
        w.base,
        "/api/users",
        Some(&bob_cookie),
        &json!({"username": "eve"}),
    )
    .await;
    assert_eq!(r.status, 403);
    let r = post(
        w.base,
        "/api/users/bob/admin",
        Some(&bob_cookie),
        &json!({"admin": true}),
    )
    .await;
    assert_eq!(r.status, 403, "非 admin 连自封 admin 也 403");

    // cannot_demote_self：boss 自降 ⇒ 409（handler 层裁决）。
    let r = post(
        w.base,
        "/api/users/boss/admin",
        Some(&cookie),
        &json!({"admin": false}),
    )
    .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "cannot_demote_self");
    // 对他人（bob 降/升）⇒ ok。
    let r = post(
        w.base,
        "/api/users/bob/admin",
        Some(&cookie),
        &json!({"admin": false}),
    )
    .await;
    assert_eq!(r.status, 200);
    // reset-password：旧口令即刻失效 + 新令牌可落。
    let r = post(
        w.base,
        "/api/users/bob/reset-password",
        Some(&cookie),
        &json!({}),
    )
    .await;
    assert_eq!(r.status, 200);
    let new_token = r.body["pw_bootstrap_token"].as_str().unwrap().to_string();
    // 旧口令失效形态：记录已清 ⇒ login-begin 走 dummy ⇒ 客户端本地 finish 失败
    //（OPAQUE 语义：错口令/无记录对客户端不可区分——同 error 面）。
    let err = pake_login(w.base, &w.core, "bob", "Bob-Pw-2")
        .await
        .expect_err("旧口令失效（dummy ⇒ 客户端 finish 失败）");
    assert!(err.contains("client finish"), "{err}");
    let (cstate2, m1b) = reg_start(&mut rand::rngs::OsRng, "Bob-Pw-3", "bob").unwrap();
    let r = post(
        w.base,
        "/api/pw-begin",
        None,
        &json!({"user": "bob", "token": &new_token, "m1_b64": m1b}),
    )
    .await;
    assert_eq!(r.status, 200);
    let record2 = flock_protocol::pake::reg_finish(
        &mut rand::rngs::OsRng,
        cstate2,
        "Bob-Pw-3",
        "bob",
        r.body["m2_b64"].as_str().unwrap(),
    )
    .unwrap();
    let r = post(
        w.base,
        "/api/pw-commit",
        None,
        &json!({"user": "bob", "token": &new_token, "record_b64": record2, "profile": 0}),
    )
    .await;
    assert_eq!(r.status, 200);
    // 未知用户操作 ⇒ 404。
    let r = post(
        w.base,
        "/api/users/ghost/disable",
        Some(&cookie),
        &json!({}),
    )
    .await;
    assert_eq!(r.status, 404);
    assert_eq!(r.code(), "not_found");

    // logout：Max-Age=0 + 原 sid 立即 401。
    let r = post(w.base, "/api/logout", Some(&bob_cookie), &json!({})).await;
    assert_eq!(r.status, 200);
    assert!(r
        .header("set-cookie")
        .is_some_and(|c| c.contains("Max-Age=0")));
    let r = get(w.base, "/api/me", Some(&bob_cookie)).await;
    assert_eq!(r.status, 401, "logout 后原 sid 401");

    // 审计面：含 session.login ok/error、user.create ok/denied、reset_password 行。
    let r = get(w.base, "/api/audit", Some(&cookie)).await;
    assert_eq!(r.status, 200);
    let entries = r.body["entries"].as_array().unwrap();
    assert!(!entries.is_empty());
    let actions: Vec<&str> = entries
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for want in [
        "session.login",
        "user.create",
        "user.reset_password",
        "user.disable",
        "user.enable",
        "session.logout",
    ] {
        assert!(actions.contains(&want), "audit 含 {want}: {actions:?}");
    }
    // 新→旧。
    let ts: Vec<u64> = entries.iter().map(|e| e["ts"].as_u64().unwrap()).collect();
    let mut sorted = ts.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(ts, sorted, "audit 新→旧");

    // 限速收口（最后驱动——同 IP（127.0.0.1）桶耗尽 ⇒ 429 + retry_after_secs）。
    let mut got_429 = None;
    for i in 0..24 {
        let r = post(
            w.base,
            "/api/login-begin",
            None,
            &json!({"user": "rate-probe", "ke1_b64": "AAAA"}),
        )
        .await;
        if r.status == 429 {
            got_429 = Some((i, r));
            break;
        }
    }
    let (_i, r) = got_429.expect("桶耗尽必达 429");
    // 突发 10 的下界断言在 access.rs 单测（本流程已消耗部分桶额度——只断 429 形）。
    assert_eq!(r.code(), "rate_limited");
    assert!(r.body["error"]["retry_after_secs"].as_u64().is_some());
}

// ============================================================================
// ③ peers/summary/series 数据面
// ============================================================================

#[tokio::test]
async fn peers_summary_series_data_plane() {
    let w = start_web().await;
    web_admin_add_direct(&w.core, "boss", "S3cret-9").await;
    let (cookie, _) = pake_login(w.base, &w.core, "boss", "S3cret-9")
        .await
        .expect("login");

    // 注册两台设备（一台喂流量 + 会话在册 ⇒ online）。
    let store = match &w.core.net {
        flock_server::backend::NetBackend::Single(s) => s.clone(),
        #[cfg(feature = "multi-primary")]
        _ => panic!("single"),
    };
    use sha2::Digest as _;
    let row_on = store
        .register_device("alice", [1; 32], [1; 32], "box-on")
        .unwrap();
    let row_off = store
        .register_device("alice", [2; 32], [2; 32], "")
        .unwrap();
    let id_on: [u8; 32] = sha2::Sha256::digest([1u8; 32]).into();
    let _kill = w.core.sessions.register(id_on);
    let _ = &_kill;
    let mut ms = 1_000_000u64;
    for _ in 0..3 {
        w.core.traffic.note_tx(&row_on.vip, 8192);
        ms += 1000;
        w.core.traffic.tick(ms);
    }
    // 定点采样两桶（此时 row_on 仍 Active；下方 revoke 后序列保留——「行消失后
    // 保留至自然环出」的实证）。
    w.state.series.sample_once(&w.core, 60).await;
    w.state.series.sample_once(&w.core, 120).await;

    // peers：全状态 + device_id + VIP 升序（server 条目 .1 在前）。
    let r = get(w.base, "/api/peers", Some(&cookie)).await;
    assert_eq!(r.status, 200);
    let peers = r.body["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 3, "2 设备 + 1 服务器: {peers:?}");
    let vips: Vec<&str> = peers.iter().map(|p| p["vip"].as_str().unwrap()).collect();
    let mut sorted = vips.clone();
    sorted.sort();
    assert_eq!(vips, sorted, "VIP 升序");
    let p_on = peers
        .iter()
        .find(|p| p["vip"].as_str().unwrap() == "100.64.0.2")
        .unwrap();
    assert_eq!(p_on["kind"], "device");
    assert_eq!(p_on["owner"], "alice");
    assert_eq!(p_on["hostname"], "box-on");
    assert_eq!(p_on["status"], "active");
    assert_eq!(p_on["online"], true);
    assert_eq!(p_on["device_id"].as_str().unwrap(), hex::encode(id_on));
    assert!(p_on["tx_bps"].as_u64().unwrap() > 0);
    let srv = peers.iter().find(|p| p["kind"] == "server").unwrap();
    assert_eq!(srv["vip"], "100.64.0.1");

    // revoke（admin）⇒ epoch + 状态 revoked；enable revoked ⇒ 409 invalid_state；
    // kick ⇒ ok（尽力本地）。
    let dev_hex = hex::encode(id_on);
    let r = post(
        w.base,
        &format!("/api/peers/{dev_hex}/revoke"),
        Some(&cookie),
        &json!({}),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["ok"], true);
    assert!(r.body["epoch"].as_u64().unwrap() >= 1);
    let r = get(w.base, "/api/peers", Some(&cookie)).await;
    let p = r.body["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["device_id"].as_str().unwrap() == dev_hex)
        .unwrap();
    assert_eq!(p["status"], "revoked", "全状态审计面（revoked 仍在列表）");
    let r = post(
        w.base,
        &format!("/api/peers/{dev_hex}/enable"),
        Some(&cookie),
        &json!({}),
    )
    .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "invalid_state");
    let r = post(
        w.base,
        &format!("/api/peers/{dev_hex}/kick"),
        Some(&cookie),
        &json!({}),
    )
    .await;
    assert_eq!(r.status, 200);
    // 未知设备 ⇒ 404；畸形 id ⇒ 404。
    let r = post(w.base, "/api/peers/abcd/revoke", Some(&cookie), &json!({})).await;
    assert_eq!(r.status, 404);
    let r = post(w.base, "/api/peers/zz/revoke", Some(&cookie), &json!({})).await;
    assert_eq!(r.status, 404);

    // series：真 HTTP 面读回（采样已在 revoke 前注入时钟完成）。
    let vip_on = format!(
        "vip={}.{}.{}.{}",
        row_on.vip[0], row_on.vip[1], row_on.vip[2], row_on.vip[3]
    );
    let r = get(
        w.base,
        &format!("/api/dashboard/series?{vip_on}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["interval_secs"], 60);
    let pts = r.body["points"].as_array().unwrap();
    assert_eq!(pts.len(), 2, "旧→新两桶");
    assert_eq!(pts[0]["t"], 60);
    assert!(pts[0]["tx_bps"].as_u64().unwrap() > 0);
    // 在册但无样本（row_off）⇒ 200 空 points；既无序列也不在册 ⇒ 404；坏参数 ⇒ 400。
    let vip_off = format!(
        "vip={}.{}.{}.{}",
        row_off.vip[0], row_off.vip[1], row_off.vip[2], row_off.vip[3]
    );
    let r = get(
        w.base,
        &format!("/api/dashboard/series?{vip_off}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body["points"].as_array().unwrap().len(), 0);
    let r = get(
        w.base,
        "/api/dashboard/series?vip=100.64.0.99",
        Some(&cookie),
    )
    .await;
    assert_eq!(r.status, 404);
    let r = get(w.base, "/api/dashboard/series", Some(&cookie)).await;
    assert_eq!(r.status, 400);
    let r = get(w.base, "/api/dashboard/series?vip=not-an-ip", Some(&cookie)).await;
    assert_eq!(r.status, 400);

    // summary：cluster/servers/totals/self。
    let r = get(w.base, "/api/dashboard/summary", Some(&cookie)).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body["cluster"]["sync_mode"], "single");
    assert_eq!(
        r.body["cluster"]["cluster_id"],
        hex::encode(w.core.identity.cluster_id.0)
    );
    let servers = r.body["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 1, "单服 = 本机一条");
    assert_eq!(servers[0]["leader"], true);
    assert_eq!(servers[0]["vip"], "100.64.0.1");
    let totals = &r.body["totals"];
    assert_eq!(totals["devices"], 2);
    assert_eq!(totals["devices_active"], 1, "一台 revoked");
    assert_eq!(totals["users"], 2, "alice（自动建户）+ boss");
    assert_eq!(
        r.body["self"]["server_id"],
        hex::encode(w.core.identity.server_id.0)
    );
    assert!(r.body["self"]["uptime_secs"].as_u64().is_some());

    // config：字段白名单。
    let r = get(w.base, "/api/config", Some(&cookie)).await;
    assert_eq!(r.status, 200);
    for k in [
        "listen_mode",
        "advertise_endpoint",
        "sync_mode",
        "ticket_ttl_secs",
        "peer_retention_days",
        "max_sessions",
        "webui",
    ] {
        assert!(r.body.get(k).is_some(), "config.{k}");
    }
    assert_eq!(r.body["sync_mode"], "single");
    let text = r.body.to_string();
    assert!(
        !text.contains("root") && !text.to_lowercase().contains("seed"),
        "白名单外不泄密"
    );

    // 审计含 peer.revoke/peer.kick 行。
    let r = get(w.base, "/api/audit", Some(&cookie)).await;
    let actions: Vec<&str> = r.body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"peer.revoke"));
    assert!(actions.contains(&"peer.kick"));
}

// ============================================================================
// ④ 访问矩阵（注入连接源地址——真 HTTP 面 loopback 收口 + 越界/VPN 段注入）
// ============================================================================

#[tokio::test]
async fn access_matrix_injected_remote_over_http_state() {
    let w = start_web().await;
    // 真 HTTP：loopback 面可达（未登录 401——非 403）。
    let r = http(
        w.base,
        "GET",
        "/api/me",
        &[("X-Forwarded-For", "8.8.8.8")],
        "",
    )
    .await;
    assert_eq!(r.status, 401, "loopback 可达；XFF 不参与判定");
    // 注入源地址（dispatch 面）：VPN 段放行 / 越界 403。
    let mk = |_ip: &str| -> flock_server::webui::http::Request {
        flock_server::webui::http::Request {
            method: "GET".into(),
            path: "/api/me".into(),
            query: String::new(),
            headers: vec![("X-Forwarded-For".into(), "127.0.0.1".into())],
            body: vec![],
        }
    };
    for ip in ["100.64.0.11", "100.127.255.254", "127.0.0.1"] {
        let resp = w
            .state
            .dispatch(mk(ip), format!("{ip}:40000").parse().unwrap())
            .await;
        assert_eq!(resp.status, 401, "{ip} 放行（会话层 401）");
    }
    for ip in ["192.168.1.5", "8.8.8.8", "100.128.0.1"] {
        let resp = w
            .state
            .dispatch(mk(ip), format!("{ip}:40000").parse().unwrap())
            .await;
        assert_eq!(resp.status, 403, "{ip} ⇒ forbidden_origin");
    }
}

// 载具占位（BufRead 引入于 stdin 语义说明处不需要——保留给未来驱动器扩展）。
#[allow(dead_code)]
fn _stdin_linesunused() {
    let _ = std::io::stdin().lock().lines();
}
