//! 健康探测（docs/design.md §3.9 实现要点：本地隧道口 + frpc admin）。
//!
//! 两条探测路径，互补覆盖「frpc 活着」与「链路真的通」：
//!
//! - **本地隧道口**：TCP 直连 frpc 转发的本地服务口（`local_ip:local_port`）——证明
//!   本地服务在；不证明 frpc↔frps 注册成功；
//! - **frpc admin**：HTTP GET `/healthz`（免认证端点，两代同有：原版 v0.71.1
//!   `client/api_router.go:32`、ChmlFrp v0.51.2 `client/admin.go:38`）——证明 frpc 进程
//!   的 admin 监听在工作；配置了凭据时附带 basic auth 头（对 `/api/status` 语义成立，
//!   对 `/healthz` 无害）。
//!
//! 进程存活本身由 [`crate::supervisor`] 的状态机跟踪（Running/Backoff/Stopped），
//! 三者合成 `RelayStatus`。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// frpc admin 探测目标。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminEndpoint {
    /// admin 监听地址（`admin_addr:admin_port` / `webServer.addr:webServer.port`）。
    pub addr: SocketAddr,
    /// basic auth 用户（v0.51.2 `admin_user` / v0.71.1 `webServer.user`）。
    pub user: Option<String>,
    /// basic auth 密码。
    pub password: Option<String>,
}

/// 一路中继的探测目标集（都可选——配置里没有就探不了，如实呈现）。
#[derive(Clone, Debug, Default)]
pub struct ProbeTargets {
    pub admin: Option<AdminEndpoint>,
    pub local_tunnel: Option<SocketAddr>,
}

/// 单项探测结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    Ok,
    Err(String),
}

/// 一次探测的报告快照（由 [`crate::supervisor`] 周期任务写入 `RelayStatus`）。
#[derive(Clone, Debug)]
pub struct ProbeReport {
    pub at: Instant,
    pub admin: Option<ProbeResult>,
    pub local_tunnel: Option<ProbeResult>,
}

impl ProbeReport {
    /// 两路都 Ok（或未配置的路视为不适用，不算失败——探不了 ≠ 不健康）。
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

/// 执行一轮探测（每项独立超时；单项失败不影响另一项）。
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

/// TCP 直连探测。
pub async fn probe_tcp(addr: SocketAddr, timeout: Duration) -> ProbeResult {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => ProbeResult::Ok,
        Ok(Err(e)) => ProbeResult::Err(format!("connect {addr}: {e}")),
        Err(_) => ProbeResult::Err(format!("connect {addr}: 超时 {timeout:?}")),
    }
}

/// frpc admin 探测：HTTP/1.0 GET `/healthz`，期待 `200` 状态行。
///
/// 不引入 HTTP 客户端依赖——admin API 是本机回环上的单端点，手写最小请求即可
/// （真 HTTP 客户端的代理/环境变量嗅探反而是这里的干扰面）。
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
        // "HTTP/1.x 200 ..." → 2xx 即健康
        if status
            .split_whitespace()
            .nth(1)
            .map(|c| c.starts_with('2'))
            .unwrap_or(false)
        {
            Ok(())
        } else {
            Err(format!("admin {}/healthz 应答非 2xx: {status:?}", ep.addr))
        }
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(())) => ProbeResult::Ok,
        Ok(Err(e)) => ProbeResult::Err(e),
        Err(_) => ProbeResult::Err(format!("admin {}: 超时 {timeout:?}", ep.addr)),
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
        // 关闭的端口：找一个几乎必然未监听的口
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
        // 建连后不回应 → 超时
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
        assert!(matches!(r, ProbeResult::Err(m) if m.contains("超时")));
    }
}
