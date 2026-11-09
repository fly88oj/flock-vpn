//! M8 webui HTTP e2e (docs/design.md §7-M8.9 —— in-process real HTTP + a
//! native pake client, protocol-isomorphic, bypassing wasm).
//!
//! Coverage (the integration checklist verbatim):
//! 1. Everything but the public endpoints 401 when not logged in (all
//!    endpoints enumerated) + the shell page/bootstrap public surface;
//! 2. First-admin bootstrap (the `web-admin-add` direct-write path
//!    function) → bootstrap → login (anchor verification passes) → cookie
//!    session → me/users CRUD (admin/non-admin 403/cannot_demote_self) →
//!    pw-begin/commit token atomicity (replay rejected) →
//!    peers/summary/series/audit → after logout the original sid 401s;
//! 3. dummy same-shape (an unknown user gets a well-formed ke2)/wrong
//!    password 401/disabled 401 user_disabled/rate limit 429;
//! 4. access matrix (loopback/VPN segment/forged XFF) via injected
//!    connection source addresses (the mod.rs unit-test surface; closed
//!    here on the loopback face with real HTTP).

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
// Vehicle: a real HTTP client (tokio TcpStream + hand-written requests ——
// no reqwest pulled in)
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

/// One HTTP request (keep-alive semantics unneeded —— a new connection per
/// request, `Connection: close`).
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
// Vehicle: the server (WebState injection + the web-admin-add direct-write
// path function)
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
        port: 0, // ephemeral —— serve returns the actual address
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

/// The direct-write path function of `web-admin-add` (the same
/// implementation surface as the CLI fallback: reg_start → local OPRF m2 →
/// reg_finish → [`web_pw_commit`]; admin=true).
async fn web_admin_add_direct(core: &ServerCore, user: &str, pw: &str) {
    // A password already set ⇒ panic (the test surface rejects with the
    // same semantics as the CLI).
    assert!(
        !core
            .net
            .user_row(user)
            .await
            .is_some_and(|r| r.opaque_record.is_some()),
        "web_admin_add_direct: {user} already has a password"
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

/// Native OPAQUE login (anchor verification —— /api/bootstrap provides the
/// identity_pub). Ok(cookie): login succeeded; Err (the ke1_state goes
/// unused) is driven by the caller as needed for failure surfaces.
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
    // Anchor verification (wrong-cluster/wrong-server response splicing is
    // intercepted here).
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
// ① The unauthenticated 401 matrix + public surface
// ============================================================================

#[tokio::test]
async fn unauthenticated_matrix_and_public_surface() {
    let w = start_web().await;
    // Public surface: shell page + bootstrap (no session needed).
    let idx = http(w.base, "GET", "/", &[], "").await;
    assert_eq!(idx.status, 200);
    let boot = get(w.base, "/api/bootstrap", None).await;
    assert_eq!(boot.status, 200);
    for k in ["cluster_id", "server_id", "identity_pub", "lang"] {
        assert!(boot.body[k].is_string(), "bootstrap.{k}");
    }
    // The lang field is the server's initial UI language hint (en default;
    // the single-language-era zh-CN tag is superseded by the bilingual
    // packs).
    assert_eq!(boot.body["lang"], "en");
    // login-begin public (bad ke1 ⇒ 400 —— reaches the handler without a
    // session).
    let r = post(
        w.base,
        "/api/login-begin",
        None,
        &json!({"user": "x", "ke1_b64": "!!!"}),
    )
    .await;
    assert_eq!(r.status, 400, "public endpoint reachable (bad ke1 ⇒ 400)");
    // All protected endpoints ⇒ 401 not_logged_in (ahead of role —— the 403
    // surface comes after login).
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
    // CSRF: a POST missing X-Flock-Web ⇒ 400 (effective on the public
    // endpoints too).
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
// ② The full chain: first-admin bootstrap → login → CRUD → token
//    atomicity → peers/summary/series/audit → logout; the failure surfaces
//    (dummy/wrong password/disabled/rate limit) closed out
// ============================================================================

#[tokio::test]
async fn full_chain_admin_login_crud_token_atomic_and_logout() {
    let w = start_web().await;
    // First-admin bootstrap (the web-admin-add direct-write path).
    web_admin_add_direct(&w.core, "boss", "S3cret-1").await;

    // dummy same-shape: an unknown user's login-begin still gets 200 + a
    // well-formed ke2.
    let (lstate_ghost, ke1) = login_start(&mut rand::rngs::OsRng, "whatever", "ghost").unwrap();
    let r = post(
        w.base,
        "/api/login-begin",
        None,
        &json!({"user": "ghost", "ke1_b64": ke1}),
    )
    .await;
    assert_eq!(r.status, 200, "unknown user gets a same-shaped ke2");
    assert!(r.body["ke2_b64"].as_str().is_some_and(|s| !s.is_empty()));
    // The client finish must fail (locally —— the dummy-record path).
    assert!(flock_protocol::pake::login_finish(
        lstate_ghost,
        "whatever",
        "ghost",
        r.body["ke2_b64"].as_str().unwrap()
    )
    .is_err());

    // Admin login (anchor verification passes) → cookie session.
    let (cookie, me) = pake_login(w.base, &w.core, "boss", "S3cret-1")
        .await
        .expect("login");
    assert_eq!(me["user"], "boss");
    assert_eq!(me["admin"], true);
    // /api/me: origin echoes loopback.
    let r = get(w.base, "/api/me", Some(&cookie)).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body["user"], "boss");
    assert_eq!(r.body["origin"], "loopback");
    assert!(r.body["expires_unix"].as_u64().is_some_and(|e| e > 0));

    // A forged ke3 sent directly ⇒ 401 login_failed (the server-observable
    // surface of a wrong password: an honest client fails finish locally
    // and never sends the third request —— OPAQUE semantics; no in-flight
    // begin gets the same code).
    let r = post(
        w.base,
        "/api/login-finish",
        None,
        &json!({"user": "boss", "ke3_b64": "AAAA"}),
    )
    .await;
    assert_eq!(r.status, 401);
    assert_eq!(r.code(), "login_failed");

    // users: create bob (the token shown only this once).
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
    // Duplicate name ⇒ 409 user_exists; bad username ⇒ 400.
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
        assert_eq!(r.status, 400, "bad username {bad:?}");
    }

    // pw-begin with a wrong token ⇒ 401 bad_token; correct ⇒ m2; unknown
    // user same error (no enumeration).
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
    assert_eq!(
        r.status, 401,
        "unknown user same bad_token (no enumeration)"
    );
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

    // pw-commit: atomically persists the record + consumes the token;
    // replay ⇒ 401 bad_token; another begin ⇒ bad_token (token already
    // consumed).
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
    assert_eq!(r.status, 401, "token replay rejected");
    assert_eq!(r.code(), "bad_token");
    let r = post(
        w.base,
        "/api/pw-begin",
        None,
        &json!({"user": "bob", "token": &token, "m1_b64": "AAAA"}),
    )
    .await;
    assert_eq!(r.status, 401, "begin after consumption also bad_token");

    // users list: username ascending + has_password/devices counts.
    let r = get(w.base, "/api/users", Some(&cookie)).await;
    assert_eq!(r.status, 200);
    let names: Vec<&str> = r.body["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["bob", "boss"], "username ascending");
    let bob = &r.body["users"][0];
    assert_eq!(bob["has_password"], true);
    assert_eq!(bob["admin"], false);

    // Disable ⇒ bob's login finish 401 user_disabled (decided after the
    // password proof holds); enable restores.
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
        .expect("login after enable");

    // Non-admin 403 matrix (bob).
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
    assert_eq!(r.status, 403, "non-admin self-promotion also 403");

    // cannot_demote_self: boss self-demotion ⇒ 409 (adjudicated at the
    // handler layer).
    let r = post(
        w.base,
        "/api/users/boss/admin",
        Some(&cookie),
        &json!({"admin": false}),
    )
    .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "cannot_demote_self");
    // Toward others (bob demote/promote) ⇒ ok.
    let r = post(
        w.base,
        "/api/users/bob/admin",
        Some(&cookie),
        &json!({"admin": false}),
    )
    .await;
    assert_eq!(r.status, 200);
    // reset-password: the old password stops working immediately + the new
    // token can land.
    let r = post(
        w.base,
        "/api/users/bob/reset-password",
        Some(&cookie),
        &json!({}),
    )
    .await;
    assert_eq!(r.status, 200);
    let new_token = r.body["pw_bootstrap_token"].as_str().unwrap().to_string();
    // Old-password failure shape: the record is cleared ⇒ login-begin takes
    // the dummy path ⇒ the client finish fails locally (OPAQUE semantics:
    // wrong password/no record are indistinguishable to the client —— the
    // same error surface).
    let err = pake_login(w.base, &w.core, "bob", "Bob-Pw-2")
        .await
        .expect_err("old password invalidated (dummy ⇒ client finish fails)");
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
    // Operating on an unknown user ⇒ 404.
    let r = post(
        w.base,
        "/api/users/ghost/disable",
        Some(&cookie),
        &json!({}),
    )
    .await;
    assert_eq!(r.status, 404);
    assert_eq!(r.code(), "not_found");

    // logout: Max-Age=0 + the original sid immediately 401.
    let r = post(w.base, "/api/logout", Some(&bob_cookie), &json!({})).await;
    assert_eq!(r.status, 200);
    assert!(r
        .header("set-cookie")
        .is_some_and(|c| c.contains("Max-Age=0")));
    let r = get(w.base, "/api/me", Some(&bob_cookie)).await;
    assert_eq!(r.status, 401, "the original sid 401s after logout");

    // Audit surface: contains session.login ok/error, user.create
    // ok/denied, reset_password rows.
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
        assert!(
            actions.contains(&want),
            "audit contains {want}: {actions:?}"
        );
    }
    // new→old.
    let ts: Vec<u64> = entries.iter().map(|e| e["ts"].as_u64().unwrap()).collect();
    let mut sorted = ts.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(ts, sorted, "audit new→old");

    // Rate-limit close-out (driven last —— the same-IP (127.0.0.1) bucket
    // exhausting ⇒ 429 + retry_after_secs).
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
    let (_i, r) = got_429.expect("bucket exhaustion must reach 429");
    // The burst-10 lower-bound assertion is in the access.rs unit tests
    // (this flow has already consumed part of the bucket quota —— only the
    // 429 shape is asserted).
    assert_eq!(r.code(), "rate_limited");
    assert!(r.body["error"]["retry_after_secs"].as_u64().is_some());
}

// ============================================================================
// ③ The peers/summary/series data plane
// ============================================================================

#[tokio::test]
async fn peers_summary_series_data_plane() {
    let w = start_web().await;
    web_admin_add_direct(&w.core, "boss", "S3cret-9").await;
    let (cookie, _) = pake_login(w.base, &w.core, "boss", "S3cret-9")
        .await
        .expect("login");

    // Register two devices (one fed traffic + a session on record ⇒
    // online).
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
    // Sample two fixed-point buckets (row_on still Active here; the series
    // survives the revoke below —— the empirical proof of "retained after
    // the row disappears until natural ring-out").
    w.state.series.sample_once(&w.core, 60).await;
    w.state.series.sample_once(&w.core, 120).await;

    // peers: all states + device_id + VIP ascending (the server entry .1
    // first).
    let r = get(w.base, "/api/peers", Some(&cookie)).await;
    assert_eq!(r.status, 200);
    let peers = r.body["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 3, "2 devices + 1 server: {peers:?}");
    let vips: Vec<&str> = peers.iter().map(|p| p["vip"].as_str().unwrap()).collect();
    let mut sorted = vips.clone();
    sorted.sort();
    assert_eq!(vips, sorted, "VIP ascending");
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

    // revoke (admin) ⇒ epoch + status revoked; enable revoked ⇒ 409
    // invalid_state; kick ⇒ ok (best-effort local).
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
    assert_eq!(
        p["status"], "revoked",
        "full-state audit surface (revoked still listed)"
    );
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
    // Unknown device ⇒ 404; malformed id ⇒ 404.
    let r = post(w.base, "/api/peers/abcd/revoke", Some(&cookie), &json!({})).await;
    assert_eq!(r.status, 404);
    let r = post(w.base, "/api/peers/zz/revoke", Some(&cookie), &json!({})).await;
    assert_eq!(r.status, 404);

    // series: read back over the real HTTP face (sampling was injected at
    // fixed clocks before the revoke).
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
    assert_eq!(pts.len(), 2, "two buckets old→new");
    assert_eq!(pts[0]["t"], 60);
    assert!(pts[0]["tx_bps"].as_u64().unwrap() > 0);
    // Registered but no samples (row_off) ⇒ 200 empty points; neither a
    // series nor registered ⇒ 404; bad parameter ⇒ 400.
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

    // summary: cluster/servers/totals/self.
    let r = get(w.base, "/api/dashboard/summary", Some(&cookie)).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body["cluster"]["sync_mode"], "single");
    assert_eq!(
        r.body["cluster"]["cluster_id"],
        hex::encode(w.core.identity.cluster_id.0)
    );
    let servers = r.body["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 1, "single server = one local entry");
    assert_eq!(servers[0]["leader"], true);
    assert_eq!(servers[0]["vip"], "100.64.0.1");
    let totals = &r.body["totals"];
    assert_eq!(totals["devices"], 2);
    assert_eq!(totals["devices_active"], 1, "one revoked");
    assert_eq!(totals["users"], 2, "alice (auto-created account) + boss");
    assert_eq!(
        r.body["self"]["server_id"],
        hex::encode(w.core.identity.server_id.0)
    );
    assert!(r.body["self"]["uptime_secs"].as_u64().is_some());

    // config: the field whitelist.
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
        "nothing outside the whitelist leaks"
    );

    // Audit contains peer.revoke/peer.kick rows.
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
// ④ Access matrix (injected connection source addresses —— the real-HTTP
// loopback face closed out + out-of-bounds/VPN-segment injection)
// ============================================================================

#[tokio::test]
async fn access_matrix_injected_remote_over_http_state() {
    let w = start_web().await;
    // Real HTTP: the loopback face is reachable (not logged in 401 —— not
    // 403).
    let r = http(
        w.base,
        "GET",
        "/api/me",
        &[("X-Forwarded-For", "8.8.8.8")],
        "",
    )
    .await;
    assert_eq!(
        r.status, 401,
        "loopback reachable; XFF does not participate in the decision"
    );
    // Injected source addresses (the dispatch face): the VPN segment
    // allowed / out-of-bounds 403.
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
        assert_eq!(resp.status, 401, "{ip} allowed (session-layer 401)");
    }
    for ip in ["192.168.1.5", "8.8.8.8", "100.128.0.1"] {
        let resp = w
            .state
            .dispatch(mk(ip), format!("{ip}:40000").parse().unwrap())
            .await;
        assert_eq!(resp.status, 403, "{ip} ⇒ forbidden_origin");
    }
}

// Vehicle placeholder (BufRead's stdin semantics are not needed —— kept for
// future driver extensions).
#[allow(dead_code)]
fn _stdin_linesunused() {
    let _ = std::io::stdin().lock().lines();
}
