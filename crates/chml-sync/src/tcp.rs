//! 生产织物：直接 TCP 监听/拨号（docs/design.md §3.10 接缝「Raft 网络传输直接 TCP /
//! 经中继」的直接形态；§6.2 srvmesh 内联网——服务器-服务器 profile E2E 会话跑在其上）。
//!
//! [`TcpFabric`] = `bind` 监听 + `NodeId → SocketAddr` 对端表：
//! - `accept`：收入连（交给 [`crate::wire::Interconnect::serve_loop`] 做 profile 应答）；
//! - `dial`：按 [`crate::wire::sid_of`] 的逆映射（ServerId 前 8B 大端）取对端地址拨号。
//!
//! 认证不在本层——织物只提供「一条 TCP 字节流」，互连认证由其上的服务器-服务器
//! profile 握手承担（无入群凭证的对端在握手层即被拒，§4-2）。

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::net::{TcpListener, TcpStream};

use crate::proto::NodeId;
use crate::wire::{Fabric, PeerIo};

/// 直接 TCP 织物（生产默认；监听端通常只对内联网暴露——§6.2 srvmesh）。
pub struct TcpFabric {
    listener: Arc<TcpListener>,
    /// 节点号 → `host:port`（容器网络别名/DNS 名——拨号时解析，§6.2 raft-N:9500）。
    peers: BTreeMap<NodeId, String>,
}

impl TcpFabric {
    /// 绑定监听端。`peers` = `节点号 → host:port`（配置驱动；缺本机条目无妨——
    /// 不会向自己拨号）。
    pub async fn bind(
        bind: std::net::SocketAddr,
        peers: BTreeMap<NodeId, String>,
    ) -> io::Result<Arc<Self>> {
        let listener = Arc::new(TcpListener::bind(bind).await?);
        Ok(Arc::new(TcpFabric { listener, peers }))
    }

    /// 监听本地地址（诊断/日志）。
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

impl Fabric for TcpFabric {
    fn dial(
        &self,
        target: &chml_protocol::session::ServerId,
    ) -> BoxFuture<'static, io::Result<PeerIo>> {
        // ServerId ↔ NodeId 逆映射（前 8B 大端——与 wire::sid_of 成对）。
        let mut b = [0u8; 8];
        b.copy_from_slice(&target.0[..8]);
        let nid = u64::from_be_bytes(b);
        let target = self.peers.get(&nid).cloned();
        Box::pin(async move {
            let target = target.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no raft peer address for node {nid}"),
                )
            })?;
            let (host, port) = split_host_port(&target)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            // (host, port) 形态 ⇒ tokio 侧 DNS 解析（容器网络别名 raft-N）。
            // 拨号预算 3s：对端宕机时 DNS（NXDOMAIN 在部分解析器上秒级）不得拖住
            // 调用方（Raft 心跳 500ms——M5 e2e A7 窗口实测教训）。
            let io = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                TcpStream::connect((host.as_str(), port)),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("dial {target} timeout")))??;
            let _ = io.set_nodelay(true);
            Ok(Box::new(io) as PeerIo)
        })
    }

    fn accept(&self) -> BoxFuture<'static, io::Result<PeerIo>> {
        // BoxFuture<'static>：监听柄克隆进 future（Arc 面，廉价）。
        let listener = self.listener.clone();
        Box::pin(async move {
            let (io, _peer) = listener.accept().await?;
            let _ = io.set_nodelay(true);
            Ok(Box::new(io) as PeerIo)
        })
    }
}

/// 配置串 `"1=raft-1:9500"` → `(1, "raft-1:9500")`（server.toml `sync.raft_peers`
/// 解析；host 允许 DNS 名——SocketAddr 字面量不接受主机名，解析推迟到拨号时）。
pub fn parse_peer_entry(s: &str) -> Result<(NodeId, String), String> {
    let (id, addr) = s
        .split_once('=')
        .ok_or_else(|| format!("raft_peers 条目 {s:?} 缺 '='（形如 1=host:port）"))?;
    let id: NodeId = id
        .trim()
        .parse()
        .map_err(|e| format!("raft_peers 节点号 {id:?}: {e}"))?;
    let addr = addr.trim();
    let _ = split_host_port(addr)?; // 形态校验（host 非空 + 端口数字）
    Ok((id, addr.to_string()))
}

/// `host:port` 拆分（末位 ':'——IPv6 字面量不在 e2e 面，容器别名/IPv4 均单冒号）。
fn split_host_port(s: &str) -> Result<(String, u16), String> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("raft_peers 地址 {s:?} 缺端口"))?;
    if host.is_empty() {
        return Err(format!("raft_peers 地址 {s:?} host 为空"));
    }
    let port: u16 = port
        .parse()
        .map_err(|e| format!("raft_peers 端口 {port:?}: {e}"))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_peer_entry_forms() {
        assert_eq!(parse_peer_entry("3=raft-3:9500").unwrap(), (3, "raft-3:9500".into()));
        assert_eq!(
            parse_peer_entry("1=172.29.0.10:9500").unwrap(),
            (1, "172.29.0.10:9500".into())
        );
        assert!(parse_peer_entry("raft-3:9500").is_err(), "缺 '=' ⇒ 拒");
        assert!(parse_peer_entry("x=raft-3:9500").is_err(), "非数字节点号 ⇒ 拒");
        assert!(parse_peer_entry("3=raft-3").is_err(), "缺端口 ⇒ 拒");
        assert!(parse_peer_entry("3=:9500").is_err(), "host 为空 ⇒ 拒");
        assert!(parse_peer_entry("3=raft-3:http").is_err(), "非数字端口 ⇒ 拒");
    }

    /// ServerId ↔ NodeId 映射与 wire::sid_of 往返一致（dial 寻址键）。
    #[test]
    fn server_id_node_id_roundtrip() {
        let sid = crate::wire::sid_of(7);
        let mut b = [0u8; 8];
        b.copy_from_slice(&sid.0[..8]);
        assert_eq!(u64::from_be_bytes(b), 7);
    }

    /// 监听/拨号地址配对真连通（accept 面真收发；dial 的表驱动部分已由
    /// parse_peer_entry/server_id_node_id_roundtrip 覆盖）。
    #[tokio::test]
    async fn tcp_fabric_accept_pair() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let fabric = TcpFabric::bind("127.0.0.1:0".parse().unwrap(), BTreeMap::new())
            .await
            .unwrap();
        let local = fabric.local_addr().unwrap();
        let fab = fabric.clone();
        let srv = tokio::spawn(async move {
            let mut io = fab.accept().await.unwrap();
            let mut buf = [0u8; 4];
            io.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        });
        let mut c = TcpStream::connect(local).await.unwrap();
        c.write_all(b"ping").await.unwrap();
        srv.await.unwrap();
    }
}
