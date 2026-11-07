//! M8 webui HTTP-OPAQUE 驱动器（docs/design.md §7-M8.8/§M8.9——`webui_assert.sh`
//! 的 CLI 载具：登录/CRUD 探针）。
//!
//! 用法（`--base` 缺省 `http://127.0.0.1:9800`）：
//!
//! ```text
//! webui_login [--base URL] [--user U --pass P] <子命令> [参数…]
//!   bootstrap                      GET /api/bootstrap（打印 cluster/server）
//!   login                          OPAQUE 登录（anchor 验签；失败退出码非 0）
//!   me [--expect-admin 0|1]        /api/me（角色断言）
//!   users                          /api/users（admin）
//!   user-create <name>             POST /api/users → stdout: token=<hex32>
//!   user-disable <u> / user-enable <u> / user-reset-password <u>
//!   user-set-admin <u> <0|1>       （cannot_demote_self ⇒ 退出码 42）
//!   pw-set --user U --token T --pass P   公共引导链（pw-begin/commit，原生 OPAQUE）
//!   peers / summary / series --vip V     只读面
//!   audit-grep <action> [target]   /api/audit 行匹配（无匹配 ⇒ 退出码 3）
//!   probe-readonly                 me/peers/summary/series/config 全 200 断言
//!   probe-admin-denied             users/audit/user-create/peer-op 全 403 断言
//!   probe-unauth-401               未登录全部端点 401 断言（W1）
//!   logout                         /api/logout 后原 sid 401 断言
//! ```
//!
//! 退出码：0 成功；1 断言/协议失败；2 参数/连接失败；3 audit 无匹配；42 业务 409。

use std::io::{Read, Write};

use base64::Engine as _;
use serde_json::{json, Value};

use flock_protocol::ed25519_dalek::VerifyingKey;
use flock_protocol::pake::{login_start, reg_start};
use flock_protocol::rand;

// ============================================================================
// 最小 HTTP 客户端（std::net——无 tokio 依赖面；每请求一连接）
// ============================================================================

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_str(self.body.trim()).unwrap_or(Value::Null)
    }
    fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
    fn cookie(&self) -> Option<String> {
        let sc = self.header("set-cookie")?;
        sc.split(';')
            .next()?
            .strip_prefix("flock_session=")
            .map(|s| s.to_string())
    }
}

fn http(
    base: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<Resp, String> {
    let hostport = base
        .strip_prefix("http://")
        .ok_or_else(|| format!("base 需以 http:// 开头: {base}"))?;
    let mut io =
        std::net::TcpStream::connect(hostport).map_err(|e| format!("connect {hostport}: {e}"))?;
    let _ = io.set_read_timeout(Some(std::time::Duration::from_secs(20)));
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {hostport}\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    req.push_str(body);
    io.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    io.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    parse(&raw)
}

fn parse(raw: &[u8]) -> Result<Resp, String> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("响应无头体分隔")?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("坏状态行")?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok(Resp {
        status,
        headers,
        body: body.to_string(),
    })
}

fn post(path: &str, cookie: Option<&str>, body: &Value, base: &str) -> Result<Resp, String> {
    let mut h = vec![("X-Flock-Web", "1"), ("Content-Type", "application/json")];
    let ck;
    if let Some(c) = cookie {
        ck = format!("flock_session={c}");
        h.push(("Cookie", Box::leak(ck.into_boxed_str())));
    }
    http(base, "POST", path, &h, &body.to_string())
}

fn get(path: &str, cookie: Option<&str>, base: &str) -> Result<Resp, String> {
    match cookie {
        Some(c) => http(
            base,
            "GET",
            path,
            &[(
                "Cookie",
                Box::leak(format!("flock_session={c}").into_boxed_str()),
            )],
            "",
        ),
        None => http(base, "GET", path, &[], ""),
    }
}

// ============================================================================
// OPAQUE 登录（anchor 验签）
// ============================================================================

/// 登录 → cookie。Err 携带可读失败（用于断言 401 面）。
fn pake_login(base: &str, user: &str, pw: &str) -> Result<(String, Value), (u16, String)> {
    let boot = get("/api/bootstrap", None, base).map_err(|e| (0, e))?;
    let pub_bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(boot.json()["identity_pub"].as_str().unwrap_or(""))
        .map_err(|e| (0, e.to_string()))?;
    let identity_pub = VerifyingKey::from_bytes(pub_bytes.as_slice().try_into().unwrap())
        .map_err(|e| (0, e.to_string()))?;
    let (lstate, ke1) =
        login_start(&mut rand::rngs::OsRng, pw, user).map_err(|e| (0, e.to_string()))?;
    let r = post(
        "/api/login-begin",
        None,
        &json!({"user": user, "ke1_b64": ke1}),
        base,
    )
    .map_err(|e| (0, e))?;
    if r.status != 200 {
        return Err((r.status, r.code()));
    }
    let v = r.json();
    let bind_token: [u8; 16] = hex::decode(v["bind_token"].as_str().unwrap_or(""))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or((0, "bad bind_token".into()))?;
    let anchor_sig = hex::decode(v["anchor_sig"].as_str().unwrap_or(""))
        .map_err(|_| (0, "bad anchor_sig".into()))?;
    // server_id：bootstrap 已取（anchor canonical 用 ServerId 16B——从 bootstrap 行取）。
    let server_id: [u8; 16] = hex::decode(boot.json()["server_id"].as_str().unwrap_or(""))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or((0, "bad server_id".into()))?;
    let ke3 = flock_server::control::client_login_finish_anchored(
        lstate,
        pw,
        user,
        v["ke2_b64"].as_str().unwrap_or(""),
        flock_server::control::AnchorLoginExpectation {
            server_id,
            identity_pub,
            bind_token,
            anchor_sig,
        },
    )
    .map_err(|e| (0, format!("client finish: {e}")))?;
    let r = post(
        "/api/login-finish",
        None,
        &json!({"user": user, "ke3_b64": ke3}),
        base,
    )
    .map_err(|e| (0, e))?;
    if r.status != 200 {
        return Err((r.status, r.code()));
    }
    let ck = r.cookie().ok_or_else(|| (0_u16, "no cookie".to_string()))?;
    Ok((ck, r.json()))
}

// ============================================================================
// main：子命令分派
// ============================================================================

fn main() {
    let code: i32 = match run() {
        Ok(c) => c as i32,
        Err(e) => {
            eprintln!("webui_login: {e}");
            2
        }
    };
    std::process::exit(code);
}

fn run() -> Result<u32, String> {
    let mut base = "http://127.0.0.1:9800".to_string();
    let mut user = String::new();
    let mut pass = String::new();
    let mut cmd = String::new();
    let mut args: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1).peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--base" => base = it.next().ok_or("--base 值")?,
            "--user" => user = it.next().ok_or("--user 值")?,
            "--pass" => pass = it.next().ok_or("--pass 值")?,
            "--vip" => args.push(format!("--vip={}", it.next().ok_or("--vip 值")?)),
            "--token" => args.push(format!("--token={}", it.next().ok_or("--token 值")?)),
            other if cmd.is_empty() => cmd = other.to_string(),
            other => args.push(other.to_string()),
        }
    }
    if cmd.is_empty() {
        return Err("缺少子命令（bootstrap/login/me/users/user-create/pw-set/peers/summary/series/audit-grep/probe-*/logout）".into());
    }
    let arg = |i: usize| args.get(i).map(|s| s.as_str()).unwrap_or("");
    let flag = |name: &str| {
        args.iter()
            .find_map(|a| a.strip_prefix(&format!("{name}=")))
            .map(|s| s.to_string())
    };

    match cmd.as_str() {
        "bootstrap" => {
            let r = get("/api/bootstrap", None, &base)?;
            let v = r.json();
            println!("cluster_id={}", v["cluster_id"].as_str().unwrap_or(""));
            println!("server_id={}", v["server_id"].as_str().unwrap_or(""));
            Ok(0)
        }
        "login" => {
            if user.is_empty() || pass.is_empty() {
                return Err("login 需要 --user/--pass".into());
            }
            // login 子命令恒新登录（缓存复用走其余子命令的 logged 路径）。
            match pake_login(&base, &user, &pass) {
                Ok((sid, v)) => {
                    CookieJar::new(&base, &user).store(&sid);
                    println!("login=ok user={} admin={}", v["user"], v["admin"]);
                    Ok(0)
                }
                Err((s, c)) => {
                    println!("login=failed status={s} code={c}");
                    Ok(1)
                }
            }
        }
        "me" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let r = get("/api/me", Some(&ck), &base)?;
            let v = r.json();
            println!(
                "me={} admin={} origin={}",
                v["user"], v["admin"], v["origin"]
            );
            if let Some(exp) = arg(0).strip_prefix("--expect-admin=") {
                let want = exp == "1";
                let got = v["admin"].as_bool().unwrap_or(false);
                if want != got {
                    println!("expect-admin={want} got={got}");
                    return Ok(1);
                }
            }
            Ok(0)
        }
        "users" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let r = get("/api/users", Some(&ck), &base)?;
            print_list(r, "users")
        }
        "user-create" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let name = arg(0);
            if name.is_empty() {
                return Err("user-create <name>".into());
            }
            let r = post("/api/users", Some(&ck), &json!({"username": name}), &base)?;
            if r.status != 200 {
                println!("user-create={} status={} code={}", name, r.status, r.code());
                return Ok(match r.code().as_str() {
                    "user_exists" => 42,
                    _ => 1,
                });
            }
            println!(
                "user-create={} token={}",
                name,
                r.json()["pw_bootstrap_token"].as_str().unwrap_or("")
            );
            Ok(0)
        }
        "user-disable" | "user-enable" | "user-reset-password" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let name = arg(0);
            let suffix = match cmd.as_str() {
                "user-disable" => "disable",
                "user-enable" => "enable",
                _ => "reset-password",
            };
            let path = format!("/api/users/{name}/{suffix}");
            let r = post(&path, Some(&ck), &json!({}), &base)?;
            if r.status != 200 {
                println!("{cmd}={name} status={} code={}", r.status, r.code());
                return Ok(1);
            }
            if cmd == "user-reset-password" {
                println!(
                    "user-reset-password={name} token={}",
                    r.json()["pw_bootstrap_token"].as_str().unwrap_or("")
                );
            } else {
                println!("{cmd}={name} ok");
            }
            Ok(0)
        }
        "user-set-admin" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let name = arg(0);
            let admin = arg(1) == "1";
            let r = post(
                &format!("/api/users/{name}/admin"),
                Some(&ck),
                &json!({"admin": admin}),
                &base,
            )?;
            if r.status != 200 {
                println!(
                    "user-set-admin={name} status={} code={}",
                    r.status,
                    r.code()
                );
                return Ok(match r.code().as_str() {
                    "cannot_demote_self" => 42,
                    _ => 1,
                });
            }
            println!("user-set-admin={name} admin={admin} ok");
            Ok(0)
        }
        "pw-set" => {
            let target = user.clone();
            let token = flag("--token").ok_or("pw-set 需要 --token")?;
            let pw2 = if pass.is_empty() {
                return Err("pw-set 需要 --pass（新口令）".into());
            } else {
                pass.clone()
            };
            // 原生 OPAQUE 注册：pw-begin（令牌预检）→ reg_finish → pw-commit。
            let (cstate, m1) = reg_start(&mut rand::rngs::OsRng, &pw2, &target)
                .map_err(|e| format!("reg_start: {e}"))?;
            let r = post(
                "/api/pw-begin",
                None,
                &json!({"user": target, "token": token, "m1_b64": m1}),
                &base,
            )?;
            if r.status != 200 {
                println!("pw-begin status={} code={}", r.status, r.code());
                return Ok(1);
            }
            let m2 = r.json()["m2_b64"].as_str().unwrap_or("").to_string();
            let record = flock_protocol::pake::reg_finish(
                &mut rand::rngs::OsRng,
                cstate,
                &pw2,
                &target,
                &m2,
            )
            .map_err(|e| format!("reg_finish: {e}"))?;
            let r = post(
                "/api/pw-commit",
                None,
                &json!({"user": target, "token": token, "record_b64": record, "profile": 0}),
                &base,
            )?;
            if r.status != 200 {
                println!("pw-commit status={} code={}", r.status, r.code());
                return Ok(1);
            }
            println!("pw-set={target} ok");
            Ok(0)
        }
        "peers" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let r = get("/api/peers", Some(&ck), &base)?;
            print_list(r, "peers")
        }
        "summary" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let r = get("/api/dashboard/summary", Some(&ck), &base)?;
            let v = r.json();
            println!(
                "sync_mode={} servers={} devices={} devices_active={} users={}",
                v["cluster"]["sync_mode"],
                v["servers"].as_array().map(|a| a.len()).unwrap_or(0),
                v["totals"]["devices"],
                v["totals"]["devices_active"],
                v["totals"]["users"],
            );
            Ok(if r.status == 200 { 0 } else { 1 })
        }
        "series" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let vip = flag("--vip").unwrap_or_else(|| "100.64.0.1".into());
            let r = get(
                &format!("/api/dashboard/series?vip={vip}"),
                Some(&ck),
                &base,
            )?;
            if r.status != 200 {
                println!("series status={} code={}", r.status, r.code());
                return Ok(1);
            }
            let pts = r.json()["points"].as_array().map(|a| a.len()).unwrap_or(0);
            println!("series vip={vip} points={pts}");
            Ok(0)
        }
        "audit-grep" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let action = arg(0);
            let target = arg(1);
            let r = get("/api/audit", Some(&ck), &base)?;
            if r.status != 200 {
                println!("audit status={} code={}", r.status, r.code());
                return Ok(1);
            }
            let entries = r.json()["entries"].as_array().cloned().unwrap_or_default();
            let hits: Vec<&Value> = entries
                .iter()
                .filter(|e| e["action"] == action && (target.is_empty() || e["target"] == target))
                .collect();
            if hits.is_empty() {
                println!("audit-grep no-match action={action} target={target}");
                return Ok(3);
            }
            for e in hits {
                println!(
                    "audit ts={} user={} action={} target={} origin={} result={}",
                    e["ts"], e["user"], e["action"], e["target"], e["origin"], e["result"]
                );
            }
            Ok(0)
        }
        "probe-readonly" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let mut bad = 0;
            for path in [
                "/api/me",
                "/api/peers",
                "/api/dashboard/summary",
                "/api/dashboard/series?vip=100.64.0.1",
                "/api/config",
            ] {
                let r = get(path, Some(&ck), &base)?;
                let okk = r.status == 200;
                println!(
                    "readonly {path} => {} {}",
                    r.status,
                    if okk { "OK" } else { "FAIL" }
                );
                bad += u32::from(!okk);
            }
            Ok(bad)
        }
        "probe-admin-denied" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let mut bad = 0;
            // GET 面（users/audit）。
            for path in ["/api/users", "/api/audit"] {
                let r = get(path, Some(&ck), &base)?;
                let okk = r.status == 403 && r.code() == "forbidden";
                println!(
                    "denied GET {path} => {} {}",
                    r.status,
                    if okk { "OK" } else { "FAIL" }
                );
                bad += u32::from(!okk);
            }
            // POST 面（建号/设 admin/设备操作）。
            for (path, body) in [
                ("/api/users", json!({"username": "probe-denied"})),
                ("/api/users/probe-self/admin", json!({"admin": true})),
                ("/api/peers/00/revoke", json!({})),
                ("/api/peers/00/kick", json!({})),
            ] {
                let r = post(path, Some(&ck), &body, &base)?;
                let okk = r.status == 403 && r.code() == "forbidden";
                println!(
                    "denied POST {path} => {} {}",
                    r.status,
                    if okk { "OK" } else { "FAIL" }
                );
                bad += u32::from(!okk);
            }
            Ok(bad)
        }
        "probe-unauth-401" => {
            let mut bad = 0;
            for path in [
                "/api/me",
                "/api/peers",
                "/api/users",
                "/api/audit",
                "/api/dashboard/summary",
                "/api/config",
            ] {
                let r = get(path, None, &base)?;
                let okk = r.status == 401 && r.code() == "not_logged_in";
                println!(
                    "unauth {path} => {} {}",
                    r.status,
                    if okk { "OK" } else { "FAIL" }
                );
                bad += u32::from(!okk);
            }
            for path in [
                "/api/logout",
                "/api/users",
                "/api/users/x/disable",
                "/api/peers/00/revoke",
            ] {
                let r = post(path, None, &json!({}), &base)?;
                let okk = r.status == 401 && r.code() == "not_logged_in";
                println!(
                    "unauth POST {path} => {} {}",
                    r.status,
                    if okk { "OK" } else { "FAIL" }
                );
                bad += u32::from(!okk);
            }
            Ok(bad)
        }
        "logout" => {
            let (ck, _) = logged(&base, &user, &pass)?;
            let r = post("/api/logout", Some(&ck), &json!({}), &base)?;
            if r.status != 200 {
                return Ok(1);
            }
            CookieJar::new(&base, &user).clear();
            let after = get("/api/me", Some(&ck), &base)?;
            let okk = after.status == 401;
            println!("logout => sid-invalidated={} ({})", okk, after.status);
            Ok(u32::from(!okk))
        }
        other => Err(format!("未知子命令 {other:?}")),
    }
}

/// 会话 cookie 缓存（per base+user，进程外落 $TMPDIR——一次登录在 TTL 内复用：
/// 登录-begin 受 per-IP 桶限 10/min，逐子命令登录会耗尽配额；登出即删）。
struct CookieJar {
    path: std::path::PathBuf,
}

impl CookieJar {
    fn new(base: &str, user: &str) -> CookieJar {
        let dir = std::env::temp_dir();
        let tag: String = format!("{}-{}", base, user)
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        CookieJar {
            path: dir.join(format!("webui_login-{tag}.cookie")),
        }
    }
    fn load(&self) -> Option<String> {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }
    fn store(&self, sid: &str) {
        let _ = std::fs::write(&self.path, sid);
    }
    fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// 登录态获取：缓存 sid 经 /api/me 验活 ⇒ 复用；否则新登录（写缓存）。
fn logged(base: &str, user: &str, pass: &str) -> Result<(String, Value), String> {
    if user.is_empty() || pass.is_empty() {
        return Err("该子命令需要 --user/--pass（登录）".into());
    }
    let jar = CookieJar::new(base, user);
    if let Some(sid) = jar.load() {
        if let Ok(r) = get("/api/me", Some(&sid), base) {
            if r.status == 200 {
                return Ok((sid, r.json()));
            }
        }
    }
    let (sid, v) =
        pake_login(base, user, pass).map_err(|(s, c)| format!("登录失败 status={s} code={c}"))?;
    jar.store(&sid);
    Ok((sid, v))
}

/// 列表面打印：`<key>[ n]=…`（脚本 grep 面）+ 200/403 断言退出码。
fn print_list(r: Resp, key: &str) -> Result<u32, String> {
    if r.status != 200 {
        println!("{key} status={} code={}", r.status, r.code());
        return Ok(match r.code().as_str() {
            "forbidden" => 42,
            _ => 1,
        });
    }
    let items = r.json()[key].as_array().cloned().unwrap_or_default();
    println!("{key}_count={}", items.len());
    for item in items {
        let name = item["username"]
            .as_str()
            .unwrap_or_else(|| item["vip"].as_str().unwrap_or(""));
        println!(
            "{key} {name} admin={} disabled={} online={} status={}",
            item["admin"].as_bool().unwrap_or(false),
            item["disabled"].as_bool().unwrap_or(false),
            item["online"].as_bool().unwrap_or(false),
            item["status"].as_str().unwrap_or(""),
        );
    }
    Ok(0)
}
