//! Peers latency probing (M7 §7-M7.7): concurrent ICMP echo probes against
//! the online, non-self VIPs.
//!
//! **Selection (socket2 + a thin in-house layer, not a mature ping crate)**:
//! - The probe path must go "through the tun" — a raw ICMP socket sending to
//!   a VIP has its egress interface chosen by the kernel routing table
//!   (`100.64.0.0/16 → tun0` is already applied by route), and the peer
//!   VIP's replies likewise enter through tun. Datagram ICMP (Linux `ping`'s
//!   SOCK_DGRAM form) is uncontrollable and macOS/Windows have no such
//!   shape; raw is the only uniform tier across the three platforms.
//! - The daemon is a privileged service (Windows service/SYSTEM, Unix root),
//!   so raw capability is naturally in place (Windows raw ICMP needs
//!   administrator, Linux needs CAP_NET_RAW, macOS needs root).
//! - The in-house surface is ~200 lines and fully controllable: ICMP echo
//!   packet building/checksum (uniform across platforms — Windows/macOS
//!   kernels do not compute the ICMP checksum, so we always do; the
//!   Linux-computed value is equally correct), replies matched by
//!   `(source address, id, seq)`, explicit timeouts; socket2 (same API
//!   surface on all three platforms, already in the dependency tree) builds
//!   the socket, then converts to a std UdpSocket and into tokio (same
//!   scheduling domain as the named-pipe IPC).
//! - Cost (stated honestly): Windows/macOS real-machine testing is on the
//!   `docs/manual/service-install.md` checklist (the container Linux path is
//!   covered by the m7 live run; all three platforms' compile surface is
//!   gated in CI).
//!
//! Probe parameters (§7-M7.7): 3 probes per target, 2s timeout per probe,
//! **median** taken (with an even number of successes the upper median — the
//! conservative side: the larger of the two), concurrent across targets.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Single-probe timeout (§7-M7.7: 2s/probe).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Probes per target.
pub const PROBE_COUNT: u32 = 3;

/// Prober abstraction (production = raw ICMP; tests inject scripted
/// loopback/timeout/median behavior).
pub trait Pinger: Send + Sync {
    /// One ICMP echo round trip (None = timeout/failure).
    fn rtt(
        &self,
        target: Ipv4Addr,
        seq: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Option<Duration>> + Send + '_>>;
}

/// Per-target probing: 3 probes (sequential — probes of the same target
/// converge independently) → sort the successes and take the median (upper
/// median for an even count) → `Some(ms)`; all timed out ⇒ None.
pub async fn probe_latency(p: &dyn Pinger, target: Ipv4Addr) -> Option<u32> {
    probe_latency_with(p, target, PROBE_COUNT, PROBE_TIMEOUT).await
}

/// Parameter-injectable form of [`probe_latency`] (test surface).
pub async fn probe_latency_with(
    p: &dyn Pinger,
    target: Ipv4Addr,
    probes: u32,
    timeout: Duration,
) -> Option<u32> {
    let mut got: Vec<u128> = Vec::new();
    for i in 0..probes {
        if let Some(d) = p.rtt(target, i as u16, timeout).await {
            got.push(d.as_millis());
        }
    }
    if got.is_empty() {
        return None;
    }
    got.sort_unstable();
    Some(got[got.len() / 2] as u32)
}

// ============================================================================
// Raw ICMP implementation (socket2 → std UdpSocket → tokio; single socket +
// reply-dispatch task)
// ============================================================================

/// Reply waiter table: `(source VIP, seq) → wake channel`.
type Waiters = Arc<Mutex<HashMap<(Ipv4Addr, u16), tokio::sync::oneshot::Sender<()>>>>;

/// Raw ICMP prober (single-socket reuse; id = process-derived — multiple
/// daemons on one host do not disturb each other).
///
/// seq is supplied by the caller ([`probe_latency_with`] uses the `0..probes`
/// sequence); review item 8 removed the unwired `next_seq` global counter.
/// Residual effect (stated honestly): the same target reuses the same seq
/// values across rounds (two probes more than 5s apart, after roster-cache
/// expiry), so a late reply from the previous round can wake this round's
/// waiter — replies still match by `(source, id, seq)` (different targets
/// isolated), and with 3 probes and a median, a single polluted sample can
/// at most raise/lower one observation while the median stays stable; it
/// cannot flip an online verdict.
pub struct RawIcmpPinger {
    id: u16,
    socket: Arc<tokio::net::UdpSocket>,
    waiters: Waiters,
}

impl RawIcmpPinger {
    /// Create the raw ICMP socket (privilege requirements in the module
    /// docs; on failure ⇒ the caller degrades to the "no latency" mode).
    pub fn new() -> io::Result<Self> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        sock.set_nonblocking(true)?;
        // The raw socket handle goes through UdpSocket semantics for
        // send_to/recv_from (platform-isomorphic; on Windows, SOCK_RAW's
        // sendto/recvfrom semantics are identical).
        let std_sock = std::net::UdpSocket::from(sock);
        let socket = Arc::new(tokio::net::UdpSocket::from_std(std_sock)?);
        let waiters: Waiters = Arc::new(Mutex::new(HashMap::new()));
        let id = (std::process::id() as u16) & 0x7fff | 0x8000;
        // Reply dispatch: a single receive task wakes waiters by
        // (source, id, seq) (id goes into the closure — same value within
        // the process).
        let rx_socket = socket.clone();
        let rx_waiters = waiters.clone();
        let my_id = id;
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                match rx_socket.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        let SocketAddr::V4(v4) = addr else { continue };
                        let Some((id, seq)) = parse_echo_reply(&buf[..n]) else {
                            continue;
                        };
                        if id != my_id {
                            continue;
                        }
                        if let Some(tx) = rx_waiters
                            .lock()
                            .expect("ping waiters")
                            .remove(&(*v4.ip(), seq))
                        {
                            let _ = tx.send(());
                        }
                    }
                    Err(_) => return, // socket closed (daemon teardown)
                }
            }
        });
        Ok(RawIcmpPinger {
            id,
            socket,
            waiters,
        })
    }
}

impl Pinger for RawIcmpPinger {
    fn rtt(
        &self,
        target: Ipv4Addr,
        seq: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Option<Duration>> + Send + '_>> {
        let socket = self.socket.clone();
        let waiters = self.waiters.clone();
        let id = self.id;
        Box::pin(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            waiters
                .lock()
                .expect("ping waiters")
                .insert((target, seq), tx);
            let t0 = std::time::Instant::now();
            let echo = build_echo(id, seq);
            let sent = match socket.send_to(&echo, SocketAddr::from((target, 0))).await {
                Ok(n) => n == echo.len(),
                Err(_) => false,
            };
            if !sent {
                waiters.lock().expect("ping waiters").remove(&(target, seq));
                return None;
            }
            tokio::select! {
                r = rx => match r {
                    Ok(()) => Some(t0.elapsed()),
                    Err(_) => None,
                },
                _ = tokio::time::sleep(timeout) => {
                    waiters.lock().expect("ping waiters").remove(&(target, seq));
                    None
                }
            }
        })
    }
}

/// ICMP echo request (type 8 + id + seq + 32B pattern payload + checksum —
/// self-computed uniformly on all platforms).
fn build_echo(id: u16, seq: u16) -> [u8; 40] {
    let mut m = [0u8; 40];
    m[0] = 8; // Echo Request
    m[4..6].copy_from_slice(&id.to_be_bytes());
    m[6..8].copy_from_slice(&seq.to_be_bytes());
    for (i, b) in m[8..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let ck = icmp_checksum(&m);
    m[2..4].copy_from_slice(&ck.to_be_bytes());
    m
}

/// RFC 1071 checksum (the complement of the 16-bit one's-complement sum).
fn icmp_checksum(msg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in msg.as_chunks::<2>().0 {
        sum += u16::from_be_bytes(*c) as u32;
    }
    if msg.len() % 2 == 1 {
        sum += (*msg.last().expect("odd length implies a tail byte") as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parse an ICMP echo reply (the raw receive surface includes the IP header
/// — uniform across platforms) → (id, seq).
fn parse_echo_reply(pkt: &[u8]) -> Option<(u16, u16)> {
    if pkt.len() < 28 {
        return None; // 20B IP + 8B ICMP header floor
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let icmp = &pkt[ihl..];
    if icmp[0] != 0 {
        return None; // Echo Reply (0) only; request copies/error reports do not match
    }
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    Some((id, seq))
}

// ============================================================================
// Unit tests (mock loopback/timeout/median + parse/checksum pure functions +
// privilege-gated live raw test)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Scripted mock (ejects results in call order — reused across the
    /// loopback/timeout/median branches).
    struct MockPinger {
        script: Mutex<std::collections::VecDeque<Option<Duration>>>,
    }

    impl MockPinger {
        fn new(script: &[Option<Duration>]) -> Self {
            MockPinger {
                script: Mutex::new(script.iter().copied().collect()),
            }
        }
    }

    impl Pinger for MockPinger {
        fn rtt(
            &self,
            _target: Ipv4Addr,
            _seq: u16,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = Option<Duration>> + Send + '_>> {
            let next = self.script.lock().unwrap().pop_front();
            Box::pin(async move { next.flatten() })
        }
    }

    /// Loopback: all succeed ⇒ median = the median of the success values.
    #[tokio::test]
    async fn probe_median_of_three_successes() {
        let p = MockPinger::new(&[
            Some(Duration::from_millis(30)),
            Some(Duration::from_millis(10)),
            Some(Duration::from_millis(200)),
        ]);
        let got =
            probe_latency_with(&p, "100.64.0.2".parse().unwrap(), 3, Duration::from_secs(1)).await;
        assert_eq!(got, Some(30), "median of 3 values = 30ms");
    }

    /// Timeout: all None ⇒ None (the data source for the offline/unreachable
    /// "—" column).
    #[tokio::test]
    async fn probe_all_timeout_is_none() {
        let p = MockPinger::new(&[None, None, None]);
        let got = probe_latency_with(
            &p,
            "100.64.0.3".parse().unwrap(),
            3,
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(got, None);
    }

    /// Partial success: [10, timeout, 30] ⇒ upper median of the successes
    /// [10,30] = 30 (the larger of an even count — conservative side).
    #[tokio::test]
    async fn probe_partial_success_takes_upper_median() {
        let p = MockPinger::new(&[
            Some(Duration::from_millis(10)),
            None,
            Some(Duration::from_millis(30)),
        ]);
        let got =
            probe_latency_with(&p, "100.64.0.4".parse().unwrap(), 3, Duration::from_secs(1)).await;
        assert_eq!(
            got,
            Some(30),
            "upper median for an even number of successes"
        );
    }

    /// Checksum + parse pure functions: self-check of the packet build
    /// (recomputing over the checksum field yields 0).
    #[test]
    fn echo_checksum_and_parse_roundtrip() {
        let echo = build_echo(0x1234, 7);
        assert_eq!(echo[0], 8);
        assert_eq!(u16::from_be_bytes([echo[4], echo[5]]), 0x1234);
        assert_eq!(u16::from_be_bytes([echo[6], echo[7]]), 7);
        // Reply parsing (20B IP header + Echo Reply — type changed to 0 and
        // the checksum recomputed per the protocol).
        let mut pkt = [0u8; 60];
        pkt[0] = 0x45; // v4, IHL 5
        pkt[2..4].copy_from_slice(&60u16.to_be_bytes());
        pkt[20..60].copy_from_slice(&echo);
        pkt[20] = 0; // type = Echo Reply
        pkt[22..24].copy_from_slice(&[0, 0]); // zeroed for recompute
        let ck = icmp_checksum(&pkt[20..]);
        pkt[22..24].copy_from_slice(&ck.to_be_bytes());
        // Checksum self-consistency: recomputing over the packet including
        // the checksum ⇒ 0 (padding and payload included).
        assert_eq!(
            icmp_checksum(&pkt[20..]),
            0,
            "recompute over the coverage is 0"
        );
        assert_eq!(parse_echo_reply(&pkt), Some((0x1234, 7)));
        // Non-echo-reply (e.g. destination-unreachable type 3) does not
        // match.
        pkt[20] = 3;
        assert_eq!(parse_echo_reply(&pkt), None);
        // Truncated/bad-version rejection.
        assert_eq!(parse_echo_reply(&pkt[..10]), None);
        let mut v6 = pkt;
        v6[0] = 0x60;
        assert_eq!(parse_echo_reply(&v6), None);
    }

    /// Live raw test (privilege-gated): raw socket creation failure (no
    /// administrator/no CAP_NET_RAW) ⇒ record a skip; creation success ⇒
    /// three loopback probes yield a non-None median (a real end-to-end
    /// check of checksum/send/receive/matching).
    #[tokio::test]
    async fn raw_icmp_loopback_when_privileged() {
        let p = match RawIcmpPinger::new() {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "skipping: no raw-socket privilege (run the full chain as container root / \
                     an administrator session)"
                );
                return;
            }
            Err(e) => panic!("unexpected raw socket creation failure: {e}"),
        };
        let got =
            probe_latency_with(&p, "127.0.0.1".parse().unwrap(), 3, Duration::from_secs(1)).await;
        assert!(
            got.is_some(),
            "loopback echo should be reachable (privileged form)"
        );
    }
}
