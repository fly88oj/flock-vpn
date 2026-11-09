//! Production fabric: direct TCP listen/dial (docs/design.md §3.10 seam
//! "Raft network transport over direct TCP / via relay", the direct form;
//! §6.2 srvmesh internal network — server-server profile E2E sessions run on
//! top).
//!
//! [`TcpFabric`] = `bind` listener + a `NodeId → SocketAddr` peer table:
//! - `accept`: incoming connections (handed to
//!   [`crate::wire::Interconnect::serve_loop`] to answer the profile);
//! - `dial`: resolves the peer address via the inverse mapping of
//!   [`crate::wire::sid_of`] (first 8B of ServerId, big-endian) and dials.
//!
//! Authentication is not in this layer — the fabric only provides "a TCP
//! byte stream"; interconnect authentication is carried by the server-server
//! profile handshake above it (peers without enrollment credentials are
//! rejected right at the handshake layer, §4-2).

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::net::{TcpListener, TcpStream};

use crate::proto::NodeId;
use crate::wire::{Fabric, PeerIo};

/// Direct TCP fabric (production default; the listener is usually exposed
/// only to the internal network — §6.2 srvmesh).
pub struct TcpFabric {
    listener: Arc<TcpListener>,
    /// Node id → `host:port` (container network aliases/DNS names — resolved
    /// at dial time, §6.2 raft-N:9500).
    peers: BTreeMap<NodeId, String>,
}

impl TcpFabric {
    /// Bind the listener. `peers` = `node id → host:port` (configuration
    /// driven; a missing local entry is fine — it never dials itself).
    pub async fn bind(
        bind: std::net::SocketAddr,
        peers: BTreeMap<NodeId, String>,
    ) -> io::Result<Arc<Self>> {
        let listener = Arc::new(TcpListener::bind(bind).await?);
        Ok(Arc::new(TcpFabric { listener, peers }))
    }

    /// Local listen address (diagnostics/logging).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

impl Fabric for TcpFabric {
    fn dial(
        &self,
        target: &flock_protocol::session::ServerId,
    ) -> BoxFuture<'static, io::Result<PeerIo>> {
        // ServerId ↔ NodeId inverse mapping (first 8B big-endian — paired
        // with wire::sid_of).
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
            // (host, port) form ⇒ DNS resolution on the tokio side (container
            // network alias raft-N). Dial budget 3s: when the peer is down,
            // DNS (NXDOMAIN can take seconds on some resolvers) must not hang
            // the caller (Raft heartbeat 500ms — a lesson from the M5 e2e A7
            // window).
            let io = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                TcpStream::connect((host.as_str(), port)),
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, format!("dial {target} timeout"))
            })??;
            let _ = io.set_nodelay(true);
            Ok(Box::new(io) as PeerIo)
        })
    }

    fn accept(&self) -> BoxFuture<'static, io::Result<PeerIo>> {
        // BoxFuture<'static>: the listener handle is cloned into the future
        // (Arc surface, cheap).
        let listener = self.listener.clone();
        Box::pin(async move {
            let (io, _peer) = listener.accept().await?;
            let _ = io.set_nodelay(true);
            Ok(Box::new(io) as PeerIo)
        })
    }
}

/// Parse a config entry `"1=raft-1:9500"` → `(1, "raft-1:9500")` (server.toml
/// `sync.raft_peers` parsing; host may be a DNS name — SocketAddr literals do
/// not accept hostnames, resolution is deferred to dial time).
pub fn parse_peer_entry(s: &str) -> Result<(NodeId, String), String> {
    let (id, addr) = s
        .split_once('=')
        .ok_or_else(|| format!("raft_peers entry {s:?} missing '=' (expected 1=host:port)"))?;
    let id: NodeId = id
        .trim()
        .parse()
        .map_err(|e| format!("raft_peers node id {id:?}: {e}"))?;
    let addr = addr.trim();
    let _ = split_host_port(addr)?; // shape validation (non-empty host + numeric port)
    Ok((id, addr.to_string()))
}

/// Split `host:port` (at the last ':' — IPv6 literals are not on the e2e
/// surface; container aliases/IPv4 are both single-colon).
fn split_host_port(s: &str) -> Result<(String, u16), String> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("raft_peers address {s:?} missing port"))?;
    if host.is_empty() {
        return Err(format!("raft_peers address {s:?} has an empty host"));
    }
    let port: u16 = port
        .parse()
        .map_err(|e| format!("raft_peers port {port:?}: {e}"))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_peer_entry_forms() {
        assert_eq!(
            parse_peer_entry("3=raft-3:9500").unwrap(),
            (3, "raft-3:9500".into())
        );
        assert_eq!(
            parse_peer_entry("1=172.29.0.10:9500").unwrap(),
            (1, "172.29.0.10:9500".into())
        );
        assert!(
            parse_peer_entry("raft-3:9500").is_err(),
            "missing '=' ⇒ rejected"
        );
        assert!(
            parse_peer_entry("x=raft-3:9500").is_err(),
            "non-numeric node id ⇒ rejected"
        );
        assert!(
            parse_peer_entry("3=raft-3").is_err(),
            "missing port ⇒ rejected"
        );
        assert!(
            parse_peer_entry("3=:9500").is_err(),
            "empty host ⇒ rejected"
        );
        assert!(
            parse_peer_entry("3=raft-3:http").is_err(),
            "non-numeric port ⇒ rejected"
        );
    }

    /// The ServerId ↔ NodeId mapping agrees with the wire::sid_of round trip
    /// (the dial addressing key).
    #[test]
    fn server_id_node_id_roundtrip() {
        let sid = crate::wire::sid_of(7);
        let mut b = [0u8; 8];
        b.copy_from_slice(&sid.0[..8]);
        assert_eq!(u64::from_be_bytes(b), 7);
    }

    /// Listen/dial address pairs are genuinely connected (the accept side
    /// really sends/receives; the table-driven part of dial is covered by
    /// parse_peer_entry/server_id_node_id_roundtrip).
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
