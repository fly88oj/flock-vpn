//! M8 webui 模块根（docs/design.md §7-M8.2/M8.8——装配与文件落位）。
//!
//! 装配（`serve`）：
//! - **loopback 监听启动即绑定**（`127.0.0.1:port`；失败 ⇒ Err——装配方拒起）；
//! - **VIP 绑定由重试任务补上**（周期 5s：tun 未就绪/地址未配 ⇒ 绑定失败重试；失败
//!   记日志一次、状态变化时再记，**永不 crash**——loopback 面不受影响）；
//! - 会话清扫（60s）+ 时序采样（series_interval）；
//! - 并发上限 = 独立信号量（缺省 64）+ 单请求总时限 30s（慢速滴注不占许可，
//!   §M8.4）；handler panic 隔离为 500。
//!
//! 访问路径（W-A1/W-A2）：loopback 与本机 tun VIP:port；数据路径 peer → … → 目标
//! 服务器 tun0 → 内核 TCP 栈 → VIP:9800——与「peer ping 服务器 VIP」同路径。

pub mod access;
pub mod api;
pub mod assets;
pub mod http;
pub mod series;
pub mod session;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::server::ServerCore;

use api::WebState;
use http::Response;

/// VIP 绑定重试周期（§M8.2 定死 5s）。
const VIP_REBIND_PERIOD: std::time::Duration = std::time::Duration::from_secs(5);
/// accept 瞬态错误退避（fd 耗尽/连接竞态——等上收连接腾出句柄后自愈）。
const ACCEPT_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

/// accept 错误 errno 面：EMFILE/ENFILE（fd 耗尽——瞬态，退避续跑）。
/// 平台值不同（unix EMFILE=24/ENFILE=23；Windows EMFILE=4，无 ENFILE）——测试
/// 经同常量构造，跨平台确定性。
#[cfg(unix)]
const ACCEPT_TRANSIENT_ERRNOS: [i32; 2] = [24, 23];
#[cfg(windows)]
const ACCEPT_TRANSIENT_ERRNOS: [i32; 1] = [4];

/// accept 错误分类（🟡 评审项 2）：瞬态（WouldBlock/Interrupted/ConnAborted/
/// ConnReset/EMFILE/ENFILE——fd 耗尽或单连接竞态，记日志 + 退避续跑）vs 致命
/// （其余——监听面失效，退出；VIP 面由重试任务 5s 重绑兜回，与 loopback 面
/// 「任一错误即永久退出」的旧缺陷对齐消除）。
fn accept_error_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::WouldBlock
            | ErrorKind::Interrupted
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
    ) || e
        .raw_os_error()
        .is_some_and(|n| ACCEPT_TRANSIENT_ERRNOS.contains(&n))
}

/// 起服装配（`server::run` / `sync::run_raft` 经 `run` 调用；`[webui] enabled=false`
/// 时由调用方跳过）。返回 loopback accept 任务句柄 + 实际绑定地址（port=0 时
/// 调用方取随机端口；VIP/清扫/采样任务 detached）。
pub async fn serve(core: Arc<ServerCore>) -> Result<(JoinHandle<()>, SocketAddr), String> {
    let state = Arc::new(WebState::new(core.clone()));
    serve_state(core, state).await
}

/// [`serve`] 的注入态变体（tests/webui.rs 持有 WebState 驱动采样/断言）。
pub async fn serve_state(
    core: Arc<ServerCore>,
    state: Arc<WebState>,
) -> Result<(JoinHandle<()>, SocketAddr), String> {
    let port = core.cfg.webui.port;

    // ① loopback：启动即绑定（失败 ⇒ 装配失败——refuse to start）。
    let lo_addr: SocketAddr = (std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port).into();
    let listener = TcpListener::bind(lo_addr)
        .await
        .map_err(|e| format!("webui loopback bind {lo_addr}: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("webui local_addr: {e}"))?;
    eprintln!("flock-server: webui listening on http://{local}");

    // ② VIP 重试任务（tun 未就绪 ⇒ 5s 重试，永不 crash）。
    tokio::spawn(vip_rebind_loop(core.clone(), state.clone()));

    // ③ 会话清扫 + 退避/令牌桶清扫（60s 周期——SWEEP_PERIOD 同档复用，🟡 评审项 5：
    //     两表容量上限在写路径惰性执行，周期清扫兜底回收过期/惰性行）。
    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(session::SWEEP_PERIOD);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let now = flock_protocol::trust::now_unix();
                st.sessions.sweep(now);
                st.backoff.sweep(now);
                st.buckets.sweep(now);
            }
        });
    }

    // ④ 时序采样（series_interval 周期）。
    tokio::spawn(state.series.clone().sampler_loop(core.clone()));

    // ⑤ accept 循环（独立信号量 64；handler panic 隔离为 500）。
    Ok((tokio::spawn(accept_loop(listener, state)), local))
}

/// accept 循环（loopback 与 VIP 面共用语义：独立信号量 + panic 隔离 + 满载 429 +
/// 瞬态 accept 错误退避续跑——分类见 [`accept_error_transient`]）。
async fn accept_loop(listener: TcpListener, state: Arc<WebState>) {
    let permits = Arc::new(tokio::sync::Semaphore::new(api::MAX_CONCURRENCY));
    loop {
        // 瞬态错误（fd 耗尽/连接竞态）记日志 + 退避续跑；致命错误才退出循环
        //（VIP 面退出后由重试任务重绑；loopback 面退出 ⇒ serve 返回的任务句柄结束）。
        let (mut io, remote) = match listener.accept().await {
            Ok(v) => v,
            Err(e) if accept_error_transient(&e) => {
                eprintln!(
                    "flock-server: webui accept 瞬态错误（{e}）——{}ms 退避续跑",
                    ACCEPT_RETRY_BACKOFF.as_millis()
                );
                tokio::time::sleep(ACCEPT_RETRY_BACKOFF).await;
                continue;
            }
            Err(e) => {
                eprintln!("flock-server: webui accept 致命错误（{e}）——accept 循环退出");
                return;
            }
        };
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                // 满载：429 立即回并关连接——与接入面「礼貌关闭」同语义。
                let resp = too_many();
                write_and_close(&mut io, &resp).await;
                continue;
            }
        };
        let st = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let handler: http::Handler = Box::new(move |req, remote| {
                let st = st.clone();
                Box::pin(async move {
                    // panic 隔离：单请求故障不杀连接循环（500 信封）。
                    match futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(
                        st.dispatch(req, remote),
                    ))
                    .await
                    {
                        Ok(resp) => resp,
                        Err(_) => internal_err(),
                    }
                })
            });
            http::serve_conn(&mut io, remote, handler).await;
        });
    }
}

fn too_many() -> Response {
    Response::json(
        429,
        &serde_json::json!({"error": {"code": "rate_limited", "message": "rate limited"}}),
    )
}

fn internal_err() -> Response {
    Response::json(
        500,
        &serde_json::json!({"error": {"code": "internal", "message": "internal error"}}),
    )
}

/// 写一条响应并关连接（并发满载路径）。
async fn write_and_close(io: &mut tokio::net::TcpStream, resp: &Response) {
    use tokio::io::AsyncWriteExt as _;
    let mut out =
        format!("HTTP/1.1 {} {}\r\n", resp.status, http::reason(resp.status)).into_bytes();
    for (k, v) in &resp.headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("content-length: {}\r\n", resp.body.len()).as_bytes());
    out.extend_from_slice(b"connection: close\r\n\r\n");
    out.extend_from_slice(&resp.body);
    let _ = io.write_all(&out).await;
    let _ = io.shutdown().await;
}

/// VIP 绑定重试（周期 5s；状态变化才记日志——避免每 5s 刷屏）。
///
/// 数据面路径与「peer ping 服务器 VIP」相同（tun → 内核 TCP 栈）；无 tun 的部署
/// （控制流-only 宿主形态）该任务持续重试——loopback 面不受影响。
async fn vip_rebind_loop(core: Arc<ServerCore>, state: Arc<WebState>) {
    let vip = core.cfg.vip;
    let port = core.cfg.webui.port;
    let addr: SocketAddr = (std::net::IpAddr::V4(vip), port).into();
    let mut logged_fail = false;
    loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                eprintln!("flock-server: webui VIP listener on http://{addr}（VPN 段可达）");
                logged_fail = false;
                accept_loop(listener, state.clone()).await;
                // accept 循环退出（监听句柄失效）⇒ 落回重试。
                eprintln!("flock-server: webui VIP listener 退出——5s 后重绑");
            }
            Err(e) => {
                if !logged_fail {
                    eprintln!(
                        "flock-server: webui VIP bind {addr} 失败（tun 未就绪？{e}）——每 5s 重试（loopback 面不受影响）"
                    );
                    logged_fail = true;
                }
            }
        }
        tokio::time::sleep(VIP_REBIND_PERIOD).await;
    }
}

// ============================================================================
// 单元测试：装配级（dispatch 序：来源矩阵/CSRF/会话/角色先后——注入连接源地址）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::api::WebState;
    use super::http::Request;
    use super::*;

    /// accept 错误分类（🟡 评审项 2）：瞬态面（WouldBlock/Interrupted/
    /// ConnAborted/ConnReset/EMFILE/ENFILE-unix）退避续跑；其余（PermissionDenied/
    /// AddrInUse/其它 errno）致命退出——「任一错误即永久退出」缺陷消除。
    #[test]
    fn accept_error_classification_transient_vs_fatal() {
        use std::io::ErrorKind;
        // 瞬态：ErrorKind 面。
        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::Interrupted,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
        ] {
            let e = std::io::Error::from(kind);
            assert!(accept_error_transient(&e), "瞬态（kind）: {e}");
        }
        // 瞬态：errno 面（fd 耗尽——同常量构造，跨平台确定性）。
        for n in ACCEPT_TRANSIENT_ERRNOS {
            assert!(
                accept_error_transient(&std::io::Error::from_raw_os_error(n)),
                "errno {n} 瞬态"
            );
        }
        // 致命：监听面失效类。
        for e in [
            std::io::Error::from(ErrorKind::PermissionDenied),
            std::io::Error::from(ErrorKind::AddrInUse),
            std::io::Error::from(ErrorKind::Unsupported),
        ] {
            assert!(!accept_error_transient(&e), "致命: {e}");
        }
        // 致命：未分类 errno（例 13=EACCES——不在瞬态白名单）。
        assert!(!accept_error_transient(&std::io::Error::from_raw_os_error(
            13
        )));
    }

    fn req(method: &str, path: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: vec![],
            body: vec![],
        }
    }

    fn remote(ip: &str) -> SocketAddr {
        format!("{ip}:40000").parse().unwrap()
    }

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

    /// 来源矩阵经注入源地址（伪造 XFF 不影响——RemoteAddr 是唯一判定输入）。
    #[tokio::test]
    async fn dispatch_origin_matrix_with_injected_remote() {
        let st = state().await;
        // loopback / VPN 段放行（未登录 → 401 not_logged_in——非 403 origin）。
        for ip in ["127.0.0.1", "127.9.9.9", "100.64.0.11", "100.127.255.254"] {
            let resp = st.dispatch(req("GET", "/api/me"), remote(ip)).await;
            assert_eq!(resp.status, 401, "{ip} 放行（会话层 401）");
        }
        // 越界（LAN/公网）⇒ 403 forbidden_origin（先于会话判定）。
        for ip in ["192.168.1.5", "8.8.8.8", "100.128.0.1", "10.1.2.3"] {
            let resp = st.dispatch(req("GET", "/api/me"), remote(ip)).await;
            assert_eq!(resp.status, 403, "{ip} 拒");
            let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
            assert_eq!(body["error"]["code"], "forbidden_origin");
        }
        // 伪造 XFF：header 存在也不改变判定。
        let mut r = req("GET", "/api/me");
        r.headers
            .push(("X-Forwarded-For".into(), "127.0.0.1".into()));
        let resp = st.dispatch(r, remote("8.8.8.8")).await;
        assert_eq!(resp.status, 403, "XFF 不参与判定");
    }

    /// 分发序：CSRF（400）先于会话（401）先于角色（403）——三态注入。
    #[tokio::test]
    async fn dispatch_order_csrf_session_role() {
        let st = state().await;
        let mut r = req("POST", "/api/users");
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        // ① 缺 X-Flock-Web ⇒ 400（未登录也 400——CSRF 槽在前）。
        let resp = st.dispatch(r.clone(), remote("127.0.0.1")).await;
        assert_eq!(resp.status, 400);
        // ② 双门槛齐但无会话 ⇒ 401。
        r.headers.push(("X-Flock-Web".into(), "1".into()));
        r.body = br#"{"username":"bob"}"#.to_vec();
        let resp = st.dispatch(r.clone(), remote("127.0.0.1")).await;
        assert_eq!(resp.status, 401);
        // ③ 有会话非 admin ⇒ 403（先会话后角色：注入非 admin 会话；iat 取真实
        // 墙钟——惰性过期按 lookup 时的 now 校验。会话 user 须在注册表在册——
        // 评审项 6 起 dispatch 会话档回读 UserRow）。
        st.core.net.create_user("plain", [2; 16]).await.unwrap();
        st.core.net.create_user("boss", [3; 16]).await.unwrap();
        st.core.net.set_user_admin("boss", true).await.unwrap();
        let now = flock_protocol::trust::now_unix();
        let sid = st
            .sessions
            .issue("plain", false, session::Origin::Loopback, now, 3600);
        r.headers
            .push(("Cookie".into(), format!("flock_session={sid}")));
        let resp = st.dispatch(r.clone(), remote("127.0.0.1")).await;
        assert_eq!(resp.status, 403);
        // ④ admin 会话 ⇒ 200（创建成功——username 合法）。
        let sid2 = st
            .sessions
            .issue("boss", true, session::Origin::Loopback, now, 3600);
        r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
        r.headers
            .push(("Cookie".into(), format!("flock_session={sid2}")));
        let resp = st.dispatch(r, remote("127.0.0.1")).await;
        assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    }

    /// 静态资产与 SPA fallback：/ 与 /static/* 200（no-cache）；未知非 /api 路径
    /// 回 index.html（hash 路由接管——M8b）；未知 /api/* 404 JSON（API 客户端
    /// 不吞 HTML）；越界来源对静态资产同样 403。
    #[tokio::test]
    async fn dispatch_static_spa_fallback_and_404() {
        let st = state().await;
        let resp = st.dispatch(req("GET", "/"), remote("127.0.0.1")).await;
        assert_eq!(resp.status, 200);
        assert!(resp
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.starts_with("text/html")));
        assert!(resp
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("cache-control") && v == "no-cache"));
        let resp = st
            .dispatch(req("GET", "/static/index.html"), remote("127.0.0.1"))
            .await;
        assert_eq!(resp.status, 200);
        // SPA fallback：直击任意未知路径（如 /peers 刷新）⇒ index.html 200。
        for path in ["/nope", "/peers", "/static/missing.js"] {
            let resp = st.dispatch(req("GET", path), remote("127.0.0.1")).await;
            assert_eq!(resp.status, 200, "{path} SPA fallback 200");
            assert!(
                String::from_utf8_lossy(&resp.body).contains("flockApp"),
                "{path} 回 index"
            );
        }
        let resp = st.dispatch(req("GET", "/"), remote("8.8.8.8")).await;
        assert_eq!(resp.status, 403);
        let resp = st
            .dispatch(req("GET", "/api/unknown"), remote("127.0.0.1"))
            .await;
        assert_eq!(resp.status, 404);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
        assert_eq!(body["error"]["code"], "not_found");
    }
}
