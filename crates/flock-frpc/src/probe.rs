//! Health probing (docs/design.md §3.9 implementation notes: local tunnel
//! port + frpc admin).
//!
//! Two probe paths, complementarily covering "frpc is alive" and "the link
//! actually works":
//!
//! - **Local tunnel port**: a direct TCP connection to the local service port
//!   frpc forwards to (`local_ip:local_port`) — proves the local service is
//!   up; does not prove frpc↔frps registration succeeded;
//! - **frpc admin**: HTTP GET `/healthz` (an unauthenticated endpoint present
//!   in both generations: original v0.71.1 `client/api_router.go:32`,
//!   ChmlFrp v0.51.2 `client/admin.go:38`) — proves the frpc process's admin
//!   listener works; when credentials are configured a basic auth header is
//!   attached (meaningful for `/api/status` semantics, harmless for
//!   `/healthz`).
//!
//! Process liveness itself is tracked by [`crate::supervisor`]'s state
//! machine (Running/Backoff/Stopped); the three combine into `RelayStatus`.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// frpc admin probe target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminEndpoint {
    /// Admin listen address (`admin_addr:admin_port` /
    /// `webServer.addr:webServer.port`).
    pub addr: SocketAddr,
    /// basic auth user (v0.51.2 `admin_user` / v0.71.1 `webServer.user`).
    pub user: Option<String>,
    /// basic auth password.
    pub password: Option<String>,
}

/// The probe-target set of one relay (both optional — if not configured,
/// there is nothing to probe; report honestly).
#[derive(Clone, Debug, Default)]
pub struct ProbeTargets {
    pub admin: Option<AdminEndpoint>,
    pub local_tunnel: Option<SocketAddr>,
}

/// A single probe result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    Ok,
    Err(String),
}

/// A snapshot of one probe round (written into `RelayStatus` by
/// [`crate::supervisor`]'s periodic task).
#[derive(Clone, Debug)]
pub struct ProbeReport {
    pub at: Instant,
    pub admin: Option<ProbeResult>,
    pub local_tunnel: Option<ProbeResult>,
}

impl ProbeReport {
    /// Both paths Ok (unconfigured paths count as not applicable, not
    /// failure — cannot probe ≠ unhealthy).
    pub fn all_ok(&self) -> bool {
        self.admin
            .as_ref()
            .map(|r| *r == ProbeResult::Ok)
            .unwrap_or(true)
            && self
                .local_tunnel
                .as_ref()
                .map(|r| *r == ProbeResult::Ok)
                .unwrap_or(true)
    }
}

/// Run one round of probes (each item with its own timeout; one item failing
/// does not affect the other).
pub async fn run_probes(targets: &ProbeTargets, timeout: Duration) -> ProbeReport {
    let admin = match &targets.admin {
        Some(ep) => Some(probe_admin(ep, timeout).await),
        None => None,
    };
    let local_tunnel = match targets.local_tunnel {
        Some(addr) => Some(probe_tcp(addr, timeout).await),
        None => None,
    };
    ProbeReport {
        at: Instant::now(),
        admin,
        local_tunnel,
    }
}

/// Direct TCP connection probe.
pub async fn probe_tcp(addr: SocketAddr, timeout: Duration) -> ProbeResult {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => ProbeResult::Ok,
        Ok(Err(e)) => ProbeResult::Err(format!("connect {addr}: {e}")),
        Err(_) => ProbeResult::Err(format!("connect {addr}: timed out {timeout:?}")),
    }
}

/// frpc admin probe: HTTP/1.0 GET `/healthz`, expecting a `200` status line.
///
/// No HTTP client dependency — the admin API is a single endpoint on the
/// machine's loopback; a hand-written minimal request suffices (a real HTTP
/// client's proxy/environment sniffing is an interference surface here).
pub async fn probe_admin(ep: &AdminEndpoint, timeout: Duration) -> ProbeResult {
    let fut = async {
        let mut stream = TcpStream::connect(ep.addr)
            .await
            .map_err(|e| e.to_string())?;
        let mut req = format!(
            "GET /healthz HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n",
            ep.addr.ip()
        );
        if let (Some(u), Some(p)) = (&ep.user, &ep.password) {
            let creds = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            req.push_str(&format!("Authorization: Basic {creds}\r\n"));
        }
        req.push_str("\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = Vec::with_capacity(256);
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        let head = String::from_utf8_lossy(&buf);
        let status = head.lines().next().unwrap_or_default();
        // "HTTP/1.x 200 ..." → any 2xx is healthy
        if status
            .split_whitespace()
            .nth(1)
            .map(|c| c.starts_with('2'))
            .unwrap_or(false)
        {
            Ok(())
        } else {
            Err(format!(
                "admin {}/healthz non-2xx response: {status:?}",
                ep.addr
            ))
        }
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(())) => ProbeResult::Ok,
        Ok(Err(e)) => ProbeResult::Err(e),
        Err(_) => ProbeResult::Err(format!("admin {}: timed out {timeout:?}", ep.addr)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn spawn_http_stub(resp: &'static str) -> SocketAddr {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = ln.accept().await else {
                    break;
                };
                let resp = resp;
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = tokio::time::timeout(Duration::from_secs(1), sock.read(&mut buf)).await;
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn probe_tcp_ok_and_refused() {
        let addr = spawn_http_stub("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        assert_eq!(
            probe_tcp(addr, Duration::from_secs(2)).await,
            ProbeResult::Ok
        );
        // A closed port: find one almost certainly not listening.
        let probe = probe_tcp("127.0.0.1:1".parse().unwrap(), Duration::from_secs(2)).await;
        assert!(matches!(probe, ProbeResult::Err(_)));
    }

    #[tokio::test]
    async fn probe_admin_2xx_ok_and_garbage_rejected() {
        let addr = spawn_http_stub("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let ep = AdminEndpoint {
            addr,
            user: Some("u".into()),
            password: Some("p".into()),
        };
        assert_eq!(
            probe_admin(&ep, Duration::from_secs(2)).await,
            ProbeResult::Ok
        );

        let bad = spawn_http_stub("not http at all\n").await;
        let ep = AdminEndpoint {
            addr: bad,
            user: None,
            password: None,
        };
        assert!(matches!(
            probe_admin(&ep, Duration::from_secs(2)).await,
            ProbeResult::Err(_)
        ));
    }

    #[tokio::test]
    async fn probe_admin_timeout() {
        // Accepts the connection but never answers → timeout.
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let (_s, _) = ln.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let ep = AdminEndpoint {
            addr,
            user: None,
            password: None,
        };
        let r = probe_admin(&ep, Duration::from_millis(300)).await;
        assert!(matches!(r, ProbeResult::Err(m) if m.contains("timed out")));
    }
}
