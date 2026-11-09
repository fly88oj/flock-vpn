//! Data plane (docs/design.md §2.3 / §3.12): IP packets ↔ [`PacketChannel`].
//!
//! Client-side bridge: packets produced by the TUN read pump → upstream
//! frames; downstream frames → the TUN write pump. Any side's error/EOF ⇒
//! return (session over; the connector backs off and reconnects,
//! [`supervise`]).
//!
//! # Cancellation-safety structure (key invariant)
//!
//! Packet-channel framing (`[u16 len][pkt]`) is **two read_exacts** — it must
//! never be an arm future of a select!: when the other arm wins, the
//! half-completed future is dropped and the frame header/body bytes already
//! consumed are lost, permanently desynchronizing the downstream frame stream
//! (garbage packets written into tun; the red shape of the regression test
//! `bridge_survives_split_downstream_frames_with_interleaved_upstream`).
//! Therefore the read side uses no select: inside `futures::poll_fn` do a
//! **single** `poll_read` (a raw read has no cross-poll state — yielding
//! loses nothing) + a persistent receive buffer completes the framing; the
//! stream is borrowed only during one poll of the poll_fn, and the upstream
//! write (a whole-frame [`send_packet`] to completion) borrows separately
//! after the poll_fn returns.

use std::io;
use std::pin::pin;
use std::task::Poll;

use flock_protocol::mux::{send_packet, PacketChannel};
use futures::io::AsyncRead as _;

use crate::tun::TunSession;

/// Read chunk size (≤ single-frame cap; frames reassemble inside the
/// persistent buffer, so a read chunk need not hold a whole frame).
///
/// pub: the server-side dataplane (`flock-server`, §2.2 "the server is
/// itself a peer") shares the same cancellation-safe framing shape.
pub const READ_CHUNK: usize = 4096;

/// Downstream framing buffer: `[u16 len][pkt]` accumulates continuously;
/// whole frames are taken whenever available (the cancellation-safe
/// container for half-completed framing — bytes once in the buffer are never
/// lost).
pub struct FrameBuf {
    buf: Vec<u8>,
}

impl Default for FrameBuf {
    fn default() -> Self {
        FrameBuf::new()
    }
}

impl FrameBuf {
    pub fn new() -> Self {
        FrameBuf {
            buf: Vec::with_capacity(2048),
        }
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Take out one complete frame (less than a full frame ⇒ None).
    pub fn take_frame(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 2 {
            return None;
        }
        let len = u16::from_le_bytes([self.buf[0], self.buf[1]]) as usize;
        if self.buf.len() < 2 + len {
            return None;
        }
        let pkt = self.buf.drain(..2 + len).as_slice()[2..].to_vec();
        Some(pkt)
    }

    pub fn has_partial(&self) -> bool {
        !self.buf.is_empty()
    }
}

/// Single-step product of the poll_fn (neither poll carries cross-poll
/// state).
enum Step {
    Upstream(Option<Vec<u8>>),
    DownBytes(usize),
    DownErr(io::Error),
    DownEof,
}

/// Bridge loop: tun ↔ packet channel (returns on the first error;
/// cancellation-safety structure in the module docs).
pub async fn bridge(sess: &mut TunSession, ch: PacketChannel) -> io::Result<()> {
    let mut stream = ch.into_stream();
    let mut frames = FrameBuf::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        // Drain all complete buffered frames (before the EOF verdict, to
        // keep the "FIN with no partial packets" semantics).
        while let Some(pkt) = frames.take_frame() {
            if sess.tx.send(pkt).await.is_err() {
                return Err(io::Error::other("tun: write pump has exited"));
            }
        }
        // Single-step wait: upstream packet / downstream bytes / downstream
        // read error. Even when this poll_fn future is preempted by the layer
        // above, no bytes are lost (no cross-poll state; `poll_recv` and a
        // single `poll_read` are both safe).
        let step = std::future::poll_fn(|cx| {
            match sess.rx.poll_recv(cx) {
                Poll::Ready(up) => return Poll::Ready(Step::Upstream(up)),
                Poll::Pending => {}
            }
            match pin!(&mut stream).poll_read(cx, &mut chunk) {
                Poll::Ready(Ok(0)) => Poll::Ready(Step::DownEof),
                Poll::Ready(Ok(n)) => Poll::Ready(Step::DownBytes(n)),
                Poll::Ready(Err(e)) => Poll::Ready(Step::DownErr(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        match step {
            Step::Upstream(Some(pkt)) => send_packet(&mut stream, &pkt).await?,
            Step::Upstream(None) => return Err(io::Error::other("tun: read pump has exited")),
            Step::DownBytes(n) => frames.extend(&chunk[..n]),
            Step::DownErr(e) => return Err(e),
            Step::DownEof => {
                // Peer FIN: only a natural channel end when no partial
                // packets remain (a partial = half-frame truncation
                // violation).
                if frames.has_partial() {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                return Err(io::Error::other("packet: peer FIN (channel closed)"));
            }
        }
    }
}
// ============================================================================
// Integration tests (host-runnable: mock tun + real handshake/record
// layer/mux over TCP/duplex)
// ============================================================================

/// Test peer utilities (shared with the connector supervise-loop tests).
#[cfg(test)]
pub(crate) mod testutil {
    use std::sync::Arc;

    use flock_protocol::ed25519_dalek::SigningKey;
    use flock_protocol::session::{
        respond, ClusterId, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, ServerId,
        ServerIdentity, TunnelConfig,
    };
    use flock_protocol::trust::ClusterDirectory;
    use flock_protocol::{mux::PacketChannel, rand};

    /// Real respond-side material + device registry + per-stream echo +
    /// session-level kill switch.
    /// `chunked = true`: every echoed frame is delivered as "frame header →
    /// 250ms gap → frame body" — constructing a downstream half-frame state
    /// to force out the cancellation-unsafety of PacketChannel::recv inside a
    /// select loop (a dropped half-completed future ⇒ consumed bytes lost,
    /// frame stream desynchronized).
    pub(crate) struct EchoPeer {
        pub identity: ServerIdentity,
        pub directory: ClusterDirectory,
        pub root: SigningKey,
        pub chunked: bool,
        devices: std::sync::Mutex<InMemoryDirectory>,
        conns: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    }

    impl EchoPeer {
        pub(crate) fn new(endpoint: &str) -> Self {
            Self::with_mode(endpoint, false)
        }

        pub(crate) fn with_mode(endpoint: &str, chunked: bool) -> Self {
            let root = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
            let identity =
                ServerIdentity::enroll(&root, ClusterId([7; 16]), ServerId([1; 16]), endpoint);
            let directory = ClusterDirectory::issue(
                &root,
                identity.cluster_id,
                1,
                vec![identity.entry.clone()],
            );
            EchoPeer {
                identity,
                directory,
                root,
                chunked,
                devices: std::sync::Mutex::new(InMemoryDirectory::new()),
                conns: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// Register a device (Active).
        pub(crate) fn register(&self, device: &DeviceStaticKeys) {
            self.devices.lock().unwrap().register(DeviceRecord {
                device_x25519: device.x25519_public(),
                device_ed25519: device.ed25519_public(),
            });
        }

        /// Accept loop: respond per inbound connection → echo every stream as
        /// a PacketChannel (the client's first stream is the control-stream
        /// placeholder: no bytes ⇒ the echo task waits silently, behaviorally
        /// equivalent).
        pub(crate) async fn serve(self: Arc<Self>, listener: tokio::net::TcpListener) {
            loop {
                let Ok((io, _)) = listener.accept().await else {
                    return;
                };
                let conn_peer = self.clone();
                let h =
                    tokio::spawn(async move {
                        let dir = conn_peer.devices.lock().unwrap().clone();
                        let tunnel =
                            match respond(io, &conn_peer.identity, dir, TunnelConfig::default())
                                .await
                            {
                                Ok(t) => t,
                                Err(_) => return,
                            };
                        while let Some(stream) = tunnel.accept_stream().await {
                            let chunked = conn_peer.chunked;
                            let mut ch = PacketChannel::from_stream(stream);
                            tokio::spawn(async move {
                                while let Ok(pkt) = ch.recv().await {
                                    if chunked {
                                        // Split-frame echo: send the header
                                        // first, the body 250ms later.
                                        let mut s = ch.into_stream();
                                        if s.write_all(&(pkt.len() as u16).to_le_bytes())
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                        tokio::time::sleep(std::time::Duration::from_millis(250))
                                            .await;
                                        if s.write_all(&pkt).await.is_err() {
                                            break;
                                        }
                                        ch = PacketChannel::from_stream(s);
                                    } else if ch.send(&pkt).await.is_err() {
                                        break;
                                    }
                                }
                            });
                        }
                    });
                self.conns.lock().unwrap().push(h);
            }
        }

        /// Kill every established session (simulating a server-side link
        /// teardown; the listener keeps running ⇒ the client should be able
        /// to reconnect).
        pub(crate) fn kill_sessions(&self) {
            let mut g = self.conns.lock().unwrap();
            for h in g.iter() {
                h.abort();
            }
            g.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use flock_protocol::session::{
        respond, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, TunnelConfig,
    };

    use super::testutil::EchoPeer;
    use super::*;
    use crate::tun::{MockTunDevice, TunDevice as _, TunIo, TunSpec};

    /// End to end: mock tun packets → client tunnel (real TCP path) → peer
    /// echo → back to the mock's write side.
    #[tokio::test]
    async fn bridge_carries_packets_both_directions_over_real_session() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = listener.local_addr().unwrap().to_string();
        let peer = Arc::new(EchoPeer::new(&ep));
        let peer_dir = peer.clone();
        tokio::spawn(async move { peer_dir.serve(listener).await });

        let device = DeviceStaticKeys::generate();
        peer.register(&device);
        let pin = flock_protocol::session::ServerPin {
            cluster_id: peer.directory.cluster_id,
            cluster_root_pub: peer.root.verifying_key(),
            entry: peer.directory.servers[0].clone(),
        };

        // Tunnel + first-stream control placeholder + packet channel (same
        // ordering contract as supervise).
        let io = tokio::net::TcpStream::connect(&ep).await.unwrap();
        let tunnel = flock_protocol::session::initiate(io, &device, &pin, TunnelConfig::default())
            .await
            .expect("1-RTT initiate");
        let _control_hold = tunnel
            .open_stream(flock_protocol::mux::Prio::Control)
            .await
            .unwrap();
        let ch = tunnel.open_packet_channel().await.unwrap();

        // Mock tun + bridge task.
        let mock = Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = TunIo::from_arc(mock.clone());
        let mut sess = tun.session();
        let bridged = tokio::spawn(async move { bridge(&mut sess, ch).await });

        // Kernel → tunnel → echo → write side.
        mock.inject(b"\x45\x00\x00\x14echo-me");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            mock.written(),
            vec![b"\x45\x00\x00\x14echo-me".to_vec()],
            "packet round-trips through the tunnel (mock write side receives the echo)"
        );

        // Bulk (framing preserves boundaries: 100 packets echoed one by one,
        // no coalescing; the first echo is already on the write side — count
        // it in the base).
        let base = mock.written().len();
        for i in 0..100u16 {
            let mut pkt = vec![0x45u8, (i >> 8) as u8, i as u8];
            pkt.extend_from_slice(&i.to_le_bytes());
            mock.inject(&pkt);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while mock.written().len() < base + 100 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(mock.written().len(), base + 100, "all 100 packets echoed");
        assert_eq!(mock.written()[base + 99], {
            let mut pkt = vec![0x45u8, 0, 99];
            pkt.extend_from_slice(&99u16.to_le_bytes());
            pkt
        });

        // Session torn down ⇒ bridge returns (channel EOF).
        tunnel.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(3), bridged).await;
        tun.shutdown();
    }

    /// Regression (cancellation safety): the peer splits every echoed frame
    /// into "header → 250ms → body" and keeps injecting upstream packets
    /// during the gap — if bridge awaited PacketChannel::recv directly inside
    /// a select! (framing = two read_exacts), the upstream arm winning would
    /// drop the half-completed future: the consumed frame header/body bytes
    /// are lost and the downstream frame stream desynchronizes permanently
    /// (garbage/lost packets written into tun). With the dedicated read-task
    /// shape, every byte must round-trip completely.
    #[tokio::test]
    async fn bridge_survives_split_downstream_frames_with_interleaved_upstream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = listener.local_addr().unwrap().to_string();
        let peer = Arc::new(EchoPeer::with_mode(&ep, true));
        let peer_serve = peer.clone();
        tokio::spawn(async move { peer_serve.serve(listener).await });

        let device = DeviceStaticKeys::generate();
        peer.register(&device);
        let pin = flock_protocol::session::ServerPin {
            cluster_id: peer.directory.cluster_id,
            cluster_root_pub: peer.root.verifying_key(),
            entry: peer.directory.servers[0].clone(),
        };
        let io = tokio::net::TcpStream::connect(&ep).await.unwrap();
        let tunnel = flock_protocol::session::initiate(io, &device, &pin, TunnelConfig::default())
            .await
            .expect("1-RTT initiate");
        let _control_hold = tunnel
            .open_stream(flock_protocol::mux::Prio::Control)
            .await
            .unwrap();
        let ch = tunnel.open_packet_channel().await.unwrap();

        let mock = Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = TunIo::from_arc(mock.clone());
        let mut sess = tun.session();
        let bridged = tokio::spawn(async move { bridge(&mut sess, ch).await });

        // Payloads are identifiable (sequence number in byte 3); assert
        // byte-exact completeness and ordering.
        let pkt_i = |i: u8| -> Vec<u8> {
            let mut v = vec![0x45u8, 0x00, 0x14, i];
            v.extend_from_slice(&[0xA5; 12]);
            v
        };
        // Injection sequence: on even steps, inside the peer's split-frame
        // window (header arrived, body not yet), inject the next packet —
        // creating select-arm switching pressure on a half-completed frame
        // (exactly the trigger shape of the cancellation-unsafety defect).
        let mut expected: Vec<Vec<u8>> = Vec::new();
        let mut i = 0u8;
        while (i as usize) < 10 {
            mock.inject(&pkt_i(i));
            expected.push(pkt_i(i));
            if i.is_multiple_of(2) && (i as usize) + 1 < 10 {
                tokio::time::sleep(Duration::from_millis(120)).await;
                mock.inject(&pkt_i(i + 1));
                expected.push(pkt_i(i + 1));
                i += 2;
            } else {
                i += 1;
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while mock.written().len() < expected.len() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let got = mock.written();
        assert_eq!(
            got.len(),
            expected.len(),
            "all echoed (no loss/no duplication): {got:?}"
        );
        assert_eq!(
            got, expected,
            "every packet byte-complete and in order (downstream frame stream not desynchronized)"
        );

        tunnel.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(3), bridged).await;
        tun.shutdown();
    }

    /// duplex smoke: record layer/mux minimal path (TCP skipped).
    #[tokio::test]
    async fn session_duplex_smoke() {
        let peer = EchoPeer::new("127.0.0.1:9443");
        let device = DeviceStaticKeys::generate();
        peer.register(&device);
        let pin = flock_protocol::session::ServerPin {
            cluster_id: peer.directory.cluster_id,
            cluster_root_pub: peer.root.verifying_key(),
            entry: peer.directory.servers[0].clone(),
        };
        let (a, b) = tokio::io::duplex(64 * 1024);
        let identity = peer.identity;
        let device_srv = DeviceStaticKeys::from_bytes(&device.to_bytes());
        let server_side = tokio::spawn(async move {
            let mut registered = InMemoryDirectory::new();
            registered.register(DeviceRecord {
                device_x25519: device_srv.x25519_public(),
                device_ed25519: device_srv.ed25519_public(),
            });
            let t = match respond(b, &identity, registered, TunnelConfig::default()).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[duplex-smoke] respond failed: {e}");
                    return;
                }
            };
            // Note: yamux SYN is lazy (carried by the first frame) — the
            // control-stream placeholder carries no data ⇒ the first accepted
            // stream is the packet channel (same semantics as the M1
            // session_mux PacketChannel test).
            let Some(s) = t.accept_stream().await else {
                return;
            };
            let mut ch = PacketChannel::from_stream(s);
            while let Ok(p) = ch.recv().await {
                if ch.send(&p).await.is_err() {
                    break;
                }
            }
        });
        let tunnel = tokio::time::timeout(
            Duration::from_secs(5),
            flock_protocol::session::initiate(a, &device, &pin, TunnelConfig::default()),
        )
        .await;
        let tunnel = match tunnel {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => panic!("1-RTT handshake over duplex failed: {e}"),
            Err(_) => panic!("duplex initiate 5s timeout"),
        };
        let _hold = t_open_hold(&tunnel).await;
        let mut ch = tunnel.open_packet_channel().await.unwrap();
        ch.send(b"\x45\x00\x00\x03abc").await.unwrap();
        let back = tokio::time::timeout(Duration::from_secs(3), ch.recv())
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(back, b"\x45\x00\x00\x03abc");
        // The control-stream placeholder is held by the client ⇒ the server
        // echo loop does not end — wrap up after a bounded wait.
        let _ = tokio::time::timeout(Duration::from_secs(2), server_side).await;
    }

    /// Open the control-stream placeholder (first-stream ordering contract;
    /// returns a held handle to prevent a premature Drop).
    async fn t_open_hold(tunnel: &flock_protocol::session::Tunnel) -> flock_protocol::mux::Stream {
        tunnel
            .open_stream(flock_protocol::mux::Prio::Control)
            .await
            .expect("control stream")
    }
}
