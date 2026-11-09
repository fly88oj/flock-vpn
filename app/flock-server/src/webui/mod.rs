//! M8 webui module root (docs/design.md §7-M8.2/M8.8 —— assembly and file
//! placement).
//!
//! Assembly (`serve`):
//! - **the loopback listener binds at startup** (`127.0.0.1:port`; failure ⇒
//!   Err —— the assembler refuses to start);
//! - **the VIP bind is added by a retry task** (period 5s: tun not ready /
//!   address unassigned ⇒ bind fails and retries; a failure is logged once,
//!   re-logged on state change, **never crashes** —— the loopback surface is
//!   unaffected);
//! - session sweep (60s) + series sampling (series_interval);
//! - concurrency cap = an independent semaphore (default 64) + a 30s total
//!   per-request time limit (slow trickle does not hold a permit, §M8.4);
//!   handler panics are isolated as 500.
//!
//! Access paths (W-A1/W-A2): loopback and the local tun VIP:port; the data
//! path is peer → … → target server tun0 → kernel TCP stack → VIP:9800 ——
//! the same path as "peer pings the server VIP".

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

/// VIP bind retry period (fixed at 5s by §M8.2).
const VIP_REBIND_PERIOD: std::time::Duration = std::time::Duration::from_secs(5);
/// Accept transient-error backoff (fd exhaustion / connection race —— heals
/// itself once incoming connections are drained and handles free up).
const ACCEPT_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

/// Accept error errno surface: EMFILE/ENFILE (fd exhaustion —— transient,
/// back off and keep running). Platform values differ (unix EMFILE=24/ENFILE=23;
/// Windows EMFILE=4, no ENFILE) —— tests construct via the same constants for
/// cross-platform determinism.
#[cfg(unix)]
const ACCEPT_TRANSIENT_ERRNOS: [i32; 2] = [24, 23];
#[cfg(windows)]
const ACCEPT_TRANSIENT_ERRNOS: [i32; 1] = [4];

/// Accept error classification (UI/review item 2): transient
/// (WouldBlock/Interrupted/ConnAborted/ConnReset/EMFILE/ENFILE —— fd
/// exhaustion or a single-connection race: log + back off and keep running)
/// vs fatal (everything else —— the listening surface is dead, exit; the VIP
/// surface is brought back by the retry task's 5s rebind, eliminating the old
/// defect where "any error exits permanently" applied to the loopback surface
/// as well).
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

/// Assembly entry (`server::run` / `sync::run_raft` call via `run`; skipped
/// by the caller when `[webui] enabled=false`). Returns the loopback accept
/// task handle + the actually bound address (the caller takes a random port
/// when port=0; the VIP/sweep/sampling tasks are detached).
pub async fn serve(core: Arc<ServerCore>) -> Result<(JoinHandle<()>, SocketAddr), String> {
    let state = Arc::new(WebState::new(core.clone()));
    serve_state(core, state).await
}

/// Injected-state variant of [`serve`] (tests/webui.rs holds a WebState to
/// drive sampling/assertions).
pub async fn serve_state(
    core: Arc<ServerCore>,
    state: Arc<WebState>,
) -> Result<(JoinHandle<()>, SocketAddr), String> {
    let port = core.cfg.webui.port;

    // ① loopback: bind at startup (failure ⇒ assembly fails —— refuse to
    //    start).
    let lo_addr: SocketAddr = (std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port).into();
    let listener = TcpListener::bind(lo_addr)
        .await
        .map_err(|e| format!("webui loopback bind {lo_addr}: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("webui local_addr: {e}"))?;
    eprintln!("flock-server: webui listening on http://{local}");

    // ② VIP retry task (tun not ready ⇒ retry every 5s, never crash).
    tokio::spawn(vip_rebind_loop(core.clone(), state.clone()));

    // ③ session sweep + backoff/token-bucket sweep (60s period —— SWEEP_PERIOD
    //    reused at the same tier; review item 5: both tables' capacity caps
    //    run lazily on the write path, the periodic sweep reclaims expired/
    //    lazy rows as a backstop).
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

    // ④ Series sampling (series_interval period).
    tokio::spawn(state.series.clone().sampler_loop(core.clone()));

    // ⑤ Accept loop (independent semaphore of 64; handler panics isolated as
    //    500).
    Ok((tokio::spawn(accept_loop(listener, state)), local))
}

/// Accept loop (shared semantics for the loopback and VIP surfaces:
/// independent semaphore + panic isolation + 429 when saturated + transient
/// accept errors back off and keep running —— classification in
/// [`accept_error_transient`]).
async fn accept_loop(listener: TcpListener, state: Arc<WebState>) {
    let permits = Arc::new(tokio::sync::Semaphore::new(api::MAX_CONCURRENCY));
    loop {
        // Transient errors (fd exhaustion / connection race): log + back off
        // and keep running; only fatal errors exit the loop (the VIP surface
        // is rebound by the retry task after exit; a loopback-surface exit ⇒
        // the task handle returned by serve ends).
        let (mut io, remote) = match listener.accept().await {
            Ok(v) => v,
            Err(e) if accept_error_transient(&e) => {
                eprintln!(
                    "flock-server: webui transient accept error ({e}) - backing off {}ms and continuing",
                    ACCEPT_RETRY_BACKOFF.as_millis()
                );
                tokio::time::sleep(ACCEPT_RETRY_BACKOFF).await;
                continue;
            }
            Err(e) => {
                eprintln!("flock-server: webui fatal accept error ({e}) - accept loop exiting");
                return;
            }
        };
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                // Saturated: reply 429 immediately and close —— same semantics
                // as the "polite close" on the access surface.
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
                    // Panic isolation: a single request failure does not kill
                    // the connection loop (500 envelope).
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

/// Write one response and close the connection (saturated-concurrency path).
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

/// VIP bind retry (period 5s; logs only on state change —— avoids spamming
/// every 5s).
///
/// The data-plane path is the same as "peer pings the server VIP" (tun →
/// kernel TCP stack); on deployments without a tun (control-plane-only host
/// form) this task keeps retrying —— the loopback surface is unaffected.
async fn vip_rebind_loop(core: Arc<ServerCore>, state: Arc<WebState>) {
    let vip = core.cfg.vip;
    let port = core.cfg.webui.port;
    let addr: SocketAddr = (std::net::IpAddr::V4(vip), port).into();
    let mut logged_fail = false;
    loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                eprintln!("flock-server: webui VIP listener on http://{addr} (reachable on the VPN segment)");
                logged_fail = false;
                accept_loop(listener, state.clone()).await;
                // Accept loop exited (listen handle dead) ⇒ fall back to
                // retrying.
                eprintln!("flock-server: webui VIP listener exited - rebinding in 5s");
            }
            Err(e) => {
                if !logged_fail {
                    eprintln!(
                        "flock-server: webui VIP bind {addr} failed (tun not ready? {e}) - retrying every 5s (loopback surface unaffected)"
                    );
                    logged_fail = true;
                }
            }
        }
        tokio::time::sleep(VIP_REBIND_PERIOD).await;
    }
}

// ============================================================================
// Unit tests: assembly level (dispatch order: origin matrix / CSRF / session /
// role precedence —— injected connection source addresses)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::api::WebState;
    use super::http::Request;
    use super::*;

    /// Accept error classification (review item 2): the transient surface
    /// (WouldBlock/Interrupted/ConnAborted/ConnReset/EMFILE/ENFILE-unix)
    /// backs off and keeps running; the rest (PermissionDenied/AddrInUse/
    /// other errnos) exit fatally —— the "any error exits permanently" defect
    /// eliminated.
    #[test]
    fn accept_error_classification_transient_vs_fatal() {
        use std::io::ErrorKind;
        // Transient: the ErrorKind surface.
        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::Interrupted,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
        ] {
            let e = std::io::Error::from(kind);
            assert!(accept_error_transient(&e), "transient (kind): {e}");
        }
        // Transient: the errno surface (fd exhaustion —— constructed via the
        // same constants, cross-platform deterministic).
        for n in ACCEPT_TRANSIENT_ERRNOS {
            assert!(
                accept_error_transient(&std::io::Error::from_raw_os_error(n)),
                "errno {n} transient"
            );
        }
        // Fatal: dead-listening-surface classes.
        for e in [
            std::io::Error::from(ErrorKind::PermissionDenied),
            std::io::Error::from(ErrorKind::AddrInUse),
            std::io::Error::from(ErrorKind::Unsupported),
        ] {
            assert!(!accept_error_transient(&e), "fatal: {e}");
        }
        // Fatal: unclassified errno (e.g. 13=EACCES —— not on the transient
        // allowlist).
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

    /// Origin matrix via injected source addresses (a forged XFF changes
    /// nothing —— RemoteAddr is the sole decision input).
    #[tokio::test]
    async fn dispatch_origin_matrix_with_injected_remote() {
        let st = state().await;
        // loopback / VPN segment allowed (not logged in → 401 not_logged_in ——
        // not a 403 origin).
        for ip in ["127.0.0.1", "127.9.9.9", "100.64.0.11", "100.127.255.254"] {
            let resp = st.dispatch(req("GET", "/api/me"), remote(ip)).await;
            assert_eq!(resp.status, 401, "{ip} allowed (session-layer 401)");
        }
        // Out of bounds (LAN / public internet) ⇒ 403 forbidden_origin (ahead
        // of the session check).
        for ip in ["192.168.1.5", "8.8.8.8", "100.128.0.1", "10.1.2.3"] {
            let resp = st.dispatch(req("GET", "/api/me"), remote(ip)).await;
            assert_eq!(resp.status, 403, "{ip} rejected");
            let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
            assert_eq!(body["error"]["code"], "forbidden_origin");
        }
        // Forged XFF: the header's presence changes nothing.
        let mut r = req("GET", "/api/me");
        r.headers
            .push(("X-Forwarded-For".into(), "127.0.0.1".into()));
        let resp = st.dispatch(r, remote("8.8.8.8")).await;
        assert_eq!(resp.status, 403, "XFF does not participate in the decision");
    }

    /// Dispatch order: CSRF (400) before session (401) before role (403) ——
    /// three-state injection.
    #[tokio::test]
    async fn dispatch_order_csrf_session_role() {
        let st = state().await;
        let mut r = req("POST", "/api/users");
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        // ① Missing X-Flock-Web ⇒ 400 (even when not logged in —— the CSRF
        //    slot comes first).
        let resp = st.dispatch(r.clone(), remote("127.0.0.1")).await;
        assert_eq!(resp.status, 400);
        // ② Both gates present but no session ⇒ 401.
        r.headers.push(("X-Flock-Web".into(), "1".into()));
        r.body = br#"{"username":"bob"}"#.to_vec();
        let resp = st.dispatch(r.clone(), remote("127.0.0.1")).await;
        assert_eq!(resp.status, 401);
        // ③ Session present but not admin ⇒ 403 (session before role: inject a
        //    non-admin session; iat takes the real wall clock —— lazy expiry is
        //    validated against now at lookup time. The session user must exist
        //    in the registry —— since review item 6 the dispatch session slot
        //    reads back the UserRow).
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
        // ④ Admin session ⇒ 200 (creation succeeds —— username valid).
        let sid2 = st
            .sessions
            .issue("boss", true, session::Origin::Loopback, now, 3600);
        r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
        r.headers
            .push(("Cookie".into(), format!("flock_session={sid2}")));
        let resp = st.dispatch(r, remote("127.0.0.1")).await;
        assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    }

    /// Static assets and SPA fallback: / and /static/* are 200 (no-cache);
    /// unknown non-/api paths fall back to index.html (hash routing takes
    /// over —— M8b); unknown /api/* gets 404 JSON (API clients never swallow
    /// HTML); out-of-bounds origins also get 403 on static assets.
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
        // SPA fallback: directly hitting any unknown path (e.g. a /peers
        // refresh) ⇒ index.html 200.
        for path in ["/nope", "/peers", "/static/missing.js"] {
            let resp = st.dispatch(req("GET", path), remote("127.0.0.1")).await;
            assert_eq!(resp.status, 200, "{path} SPA fallback 200");
            assert!(
                String::from_utf8_lossy(&resp.body).contains("flockApp"),
                "{path} falls back to index"
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
