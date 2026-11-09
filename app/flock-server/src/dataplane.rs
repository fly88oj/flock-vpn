//! Server-side data plane (docs/design.md §2.2/§3.11, the server half of
//! the M3 "data plane hookup").
//!
//! The server itself is also a peer: tun (VIP [`SERVER_VIP`] = 100.64.0.1,
//! MTU 1280) + routing (`100.64.0.0/16` pointing at the tun + rp_filter=1,
//! the same [`route`] adapter as the client). In-session dispatch: **the
//! first yamux stream = the control flow** (M2 semantics unchanged), the
//! remaining streams enter the data plane as [`PacketChannel`]s. Each
//! packet channel:
//!
//! 1. **step-0 source VIP binding check** (§2.2/R22): a packet's source
//!    address must equal the session device's registered VIP; mismatch ⇒
//!    drop + count (rp_filter only acts on kernel inbound; user-space
//!    streams must filter at the application layer);
//! 2. injected into the kernel via the tun write pump (packets with dst =
//!    the server VIP are answered by the local stack —— the A2 ping path);
//! 3. kernel return path (the tun read pump) routed by destination VIP to
//!    the corresponding session's packet channel (the single-server
//!    counterpart of the lease table; the cross-server ForwardEnvelope
//!    forwarding surface belongs to M4 `flock-sync`, §2.2 step 3).
//!
//! Environments without tun (host unit tests, deployments without
//! NET_ADMIN): [`PeerRouter::open`] logs and degrades to
//! "control-flow-only" —— packet channels FIN gracefully, the client
//! observes channel EOF (M2 behavior preserved).
//!
//! # Cancellation safety and session registration (key invariant)
//!
//! - Inbound framing follows the client contract (see the
//!   `flock_client::dataplane` module docs): awaiting the framing recv
//!   directly inside select! loses frames —— this side drives with
//!   `poll_fn` + a single `poll_read` + a persistent [`FrameBuf`];
//! - Re-registration of the same VIP (device reconnect, the §2.4 roaming
//!   model): [`SessionIndex`] guards with **generations** —— an old
//!   session's exit unregisters only its own registration and must never
//!   delete the new session's (otherwise the device's downlink blackholes).

use std::net::Ipv4Addr;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use flock_client::dataplane::{FrameBuf, READ_CHUNK};
use flock_protocol::mux::{send_packet, PacketChannel, Stream};
use futures::io::AsyncRead as _;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
use flock_client::route::{self, RoutePlan};
use flock_client::tun::TunIo;
#[cfg(target_os = "linux")]
use flock_client::tun::TunSpec;

/// The server's own VIP (§2.2 "the server itself is also a peer, VIP
/// 100.64.0.1"; netstate allocation starts at .2).
pub const SERVER_VIP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);

/// M7: the key of the "server itself" entry in the single-server traffic
/// meter (device entries are keyed by the 4-byte VIP).
pub const SERVER_TRAFFIC_KEY: &[u8] = b"flock-server-self";

// Data channels set **no** idle timeout (the review-item 8 layered
// correction —— the M5 e2e regression's root cause).
//
// Session-layer PING/PONG travels on the record layer (the whole
// connection), producing no yamux stream frames: a healthy data channel
// with no business traffic **necessarily** stays at zero frames for long
// stretches. If this layer closed channels on "3×keepalive without stream
// frames", an idle client would have its data channel torn down every 30s,
// and the client treats data-channel EOF as session termination
// (connector::supervise reconnects the whole chain + endpoint rotation),
// triggering a "lease evicted (device moved)" storm —— the e2e run measured
// 30 idle-closes / 35 evictions, wrecking the pinned endpoint topology
// (A2/A6/A7/A10/A11/A14 chained FAIL).
//
// Dead-link detection belongs to the correct layer: the record layer tears
// the whole session on 3×keepalive without inbound records (A9 semantics,
// including yamux channel FINs); a peer machine dying outright / NAT expiry
// is handled by the TCP keepalive set at connection acceptance (review item
// 8) letting the kernel error out the link; half-open handshakes are
// intercepted by the respond-side handshake budget. The channel loop exits
// naturally via EOF/error on all three termination paths —— a second idle
// scythe is neither needed nor appropriate.

/// Cumulative source VIP validation mismatches (assertion/alert surface;
/// §2.2 "drop + count").
pub fn src_vip_mismatches() -> u64 {
    SRC_MISMATCH.load(Ordering::Relaxed)
}

/// Session channels torn down for hitting the per-session source VIP
/// mismatch limit (the review-item 10 admin stats surface).
pub fn src_vip_mismatch_kills() -> u64 {
    SRC_MISMATCH_KILLS.load(Ordering::Relaxed)
}

static SRC_MISMATCH: AtomicU64 = AtomicU64::new(0);
static SRC_MISMATCH_KILLS: AtomicU64 = AtomicU64::new(0);

/// Per-session source VIP mismatch cap (review item 10): reaching it tears
/// down that session's channel (the client observes channel EOF →
/// backoff-reconnects; a session persistently forging its source no longer
/// lives forever under the silent "drop + count" backstop).
const SRC_MISMATCH_SESSION_LIMIT: u32 = 100;

/// Per-session source VIP mismatch counter (used inline in serve_stream;
/// split out so the cap semantics are unit-testable).
#[derive(Default)]
struct SrcMismatchCounter {
    count: u32,
}

impl SrcMismatchCounter {
    /// Record one mismatch (the global counter accumulates in step). Returns
    /// true ⇒ [`SRC_MISMATCH_SESSION_LIMIT`] reached; the caller should tear
    /// down the session channel.
    fn on_mismatch(&mut self) -> bool {
        self.count += 1;
        SRC_MISMATCH.fetch_add(1, Ordering::Relaxed);
        if self.count >= SRC_MISMATCH_SESSION_LIMIT {
            SRC_MISMATCH_KILLS.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

/// IPv4 packet source/destination addresses (taken from 12..16 / 16..20
/// after version/IHL validation). Not IPv4 / too short ⇒ None.
fn ipv4_src_dst(pkt: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let src: [u8; 4] = pkt[12..16].try_into().ok()?;
    let dst: [u8; 4] = pkt[16..20].try_into().ok()?;
    Some((src, dst))
}

/// Destination VIP → session outbound channel index (**generation
/// guard**).
///
/// Re-registration of the same VIP (device disconnect-reconnect) overwrites
/// the old channel via insert —— the old session loop exits as its sender is
/// dropped, and on exit it may unregister **only its own generation**
/// ([`SessionIndex::unregister`] compares the generation): otherwise the
/// old exit would delete the new session's registration too, blackholing
/// that device's downlink (until the client reconnects again).
/// VIP → (outbound channel, registration generation).
type SessionMap = std::collections::HashMap<[u8; 4], (mpsc::Sender<Vec<u8>>, u64)>;

struct SessionIndex {
    map: Mutex<SessionMap>,
    next_gen: AtomicU64,
}

impl SessionIndex {
    fn new() -> Self {
        SessionIndex {
            map: Mutex::new(std::collections::HashMap::new()),
            next_gen: AtomicU64::new(0),
        }
    }

    /// Register (same VIP overwrites the old channel), returning this
    /// generation (the unregister credential).
    fn register(&self, vip: [u8; 4], tx: mpsc::Sender<Vec<u8>>) -> u64 {
        let gen = self.next_gen.fetch_add(1, Ordering::Relaxed) + 1;
        self.map
            .lock()
            .expect("router poisoned")
            .insert(vip, (tx, gen));
        gen
    }

    /// The currently registered outbound channel (for kernel return-path
    /// routing). Call surface = the Linux compilation face's
    /// `with_kernel_router_task` + the test profile (`outbound_sender` /
    /// SessionIndex unit tests) —— the non-Linux non-test compilation face
    /// has no caller, and the cfg alone avoids needing allow (dead_code is
    /// analyzed per platform face; a Windows dev machine never sees the
    /// Linux call sites).
    #[cfg(any(test, target_os = "linux"))]
    fn get(&self, vip: &[u8; 4]) -> Option<mpsc::Sender<Vec<u8>>> {
        self.map
            .lock()
            .expect("router poisoned")
            .get(vip)
            .map(|(tx, _)| tx.clone())
    }

    /// Unregister **only if** the current registration is still generation
    /// `gen` (the same VIP already overwritten by a new session ⇒ leave the
    /// new registration alone).
    fn unregister(&self, vip: &[u8; 4], gen: u64) {
        let mut g = self.map.lock().expect("router poisoned");
        if g.get(vip).map(|(_, cur)| *cur == gen).unwrap_or(false) {
            g.remove(vip);
        }
    }
}

/// The single-server data-plane router (VIP → session packet channel).
pub struct PeerRouter {
    /// TUN device handle (**held alive**: the interface and routes live with
    /// the handle —— never being read is its entire purpose, pure RAII
    /// semantics; the real Linux assembly path writes Some, the non-Linux
    /// degraded path is always None, and no platform's compilation face has
    /// a read point). allow(dead_code) must cover all platforms
    /// unconditionally: dead_code triggers precisely on the Linux
    /// compilation face (written but never read), a unix face invisible to a
    /// Windows dev machine.
    #[allow(dead_code)]
    tun: Option<Arc<TunIo>>,
    /// Destination VIP → that session's outbound channel (kernel return path
    /// → peer; the generation guard is on [`SessionIndex`]).
    sessions: SessionIndex,
    /// Kernel injection channel (the tun write pump; no tun ⇒ None =
    /// control-flow-only degradation).
    kernel_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// M7: per-VIP traffic meter (EWMA/last_seen —— the roster's
    /// single-server data source; counting points per the §7-M7.3
    /// single-point principle: inbound (source check passed) = that device's
    /// tx, outbound delivery = that device's rx; inbound with dst = the
    /// server VIP = server rx, kernel return-path routing = server tx).
    traffic: Mutex<Option<Arc<flock_sync::lease::TrafficMeter>>>,
    /// This node's server VIP (M7: for deciding inbound-dst server rx; test
    /// assembly defaults to None).
    server_vip: Option<Ipv4Addr>,
}

impl PeerRouter {
    /// Open the tun + routes and assemble the router; any step's failure
    /// logs and degrades to control-flow-only (the M2 host-test /
    /// no-NET_ADMIN deployment path). async: route configuration goes
    /// through rtnetlink/tokio.
    ///
    /// `vip` = this node's tun VIP (single-server default [`SERVER_VIP`];
    /// in multi-primary form each node gets its own, §6.2).
    ///
    /// Non-Linux platforms assemble no real device (the Windows wintun
    /// runtime path is left for the M5 real-machine manual checklist per
    /// §7-M3 —— host `cargo test` must never touch host drivers; macOS is
    /// unverified, same §7-M3).
    pub async fn open(tun_name: &str, vip: Ipv4Addr) -> Arc<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun_name, vip);
            eprintln!(
                "flock-server: data plane assembles on Linux only (Windows real-machine M5 manual checklist / macOS unverified) - control-flow-only mode"
            );
            Self::none()
        }
        #[cfg(target_os = "linux")]
        {
            match open_tun_with_route(tun_name, vip).await {
                Ok(tun) => {
                    let sess = tun.session();
                    let kernel_tx = sess.tx.clone();
                    PeerRouter {
                        tun: Some(Arc::new(tun)),
                        sessions: SessionIndex::new(),
                        kernel_tx: Some(kernel_tx),
                        traffic: Mutex::new(None),
                        server_vip: Some(vip),
                    }
                    .with_kernel_router_task(sess, vip)
                }
                Err(()) => Arc::new(PeerRouter {
                    tun: None,
                    sessions: SessionIndex::new(),
                    kernel_tx: None,
                    traffic: Mutex::new(None),
                    server_vip: Some(vip),
                }),
            }
        }
    }

    /// The multi-primary form's tun assembly (§2.2 "the server itself is
    /// also a peer" + the §6.2 M5 batch): opens the tun + routes but does
    /// **not** start the single-server kernel routing task —— the session
    /// surface is carried by the flock-sync forwarding plane
    /// ([`crate::sync::wire_local_peer`]: dst = own VIP injected into the
    /// kernel; the kernel return-path read pump →
    /// `SyncNode::route_outbound`).
    ///
    /// Returns `(tun handle, session)`; failure ⇒ None
    /// (control-flow-only degradation, same semantics as single-server).
    pub async fn open_tun_session(
        tun_name: &str,
        vip: Ipv4Addr,
    ) -> Option<(Arc<TunIo>, flock_client::tun::TunSession)> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun_name, vip);
            eprintln!("flock-server: data plane assembles on Linux only - multi-primary form control-flow-only mode");
            None
        }
        #[cfg(target_os = "linux")]
        {
            match open_tun_with_route(tun_name, vip).await {
                Ok(tun) => {
                    let sess = tun.session();
                    Some((Arc::new(tun), sess))
                }
                Err(()) => None,
            }
        }
    }

    /// M7: inject the traffic meter (at run() assembly time;
    /// serve_stream/kernel routing task count through it).
    pub fn set_traffic_meter(&self, meter: Arc<flock_sync::lease::TrafficMeter>) {
        *self.traffic.lock().expect("router traffic") = Some(meter);
    }

    fn traffic_of(&self) -> Option<Arc<flock_sync::lease::TrafficMeter>> {
        self.traffic.lock().expect("router traffic").clone()
    }

    /// Kernel return-path routing task: tun read-pump output → dispatched by
    /// destination VIP to the session outbound channels (no matching session
    /// ⇒ dropped —— no ICMP unreachable/cross-server forwarding before M4,
    /// the §2.2 fault-tolerance strategy). M7: the kernel return path = the
    /// server's own tx (counting point, §7-M7.3).
    #[cfg(target_os = "linux")]
    fn with_kernel_router_task(
        self: PeerRouter,
        mut sess: flock_client::tun::TunSession,
        self_vip: Ipv4Addr,
    ) -> Arc<Self> {
        let arc = Arc::new(self);
        let router = arc.clone();
        tokio::spawn(async move {
            // (The TunSession moves in whole: rx for routing; tx's survival
            // keeps the write pump resident —— the server data plane never
            // tears down.)
            while let Some(pkt) = sess.rx.recv().await {
                let Some((src, dst)) = ipv4_src_dst(&pkt) else {
                    continue;
                };
                if src == self_vip.octets() {
                    if let Some(m) = router.traffic_of() {
                        m.note_tx(SERVER_TRAFFIC_KEY, pkt.len() as u64);
                    }
                }
                if let Some(tx) = router.sessions.get(&dst) {
                    let _ = tx.send(pkt).await;
                }
            }
        });
        arc
    }

    /// Explicitly no data plane (test assembly).
    pub fn none() -> Arc<Self> {
        Arc::new(PeerRouter {
            tun: None,
            sessions: SessionIndex::new(),
            kernel_tx: None,
            traffic: Mutex::new(None),
            server_vip: None,
        })
    }

    /// Test assembly: inject a kernel channel (no real tun; drives
    /// serve_stream in host integration tests).
    #[cfg(test)]
    pub(crate) fn with_kernel_tx(kernel_tx: mpsc::Sender<Vec<u8>>) -> Arc<Self> {
        Arc::new(PeerRouter {
            tun: None,
            sessions: SessionIndex::new(),
            kernel_tx: Some(kernel_tx),
            traffic: Mutex::new(None),
            server_vip: None,
        })
    }

    /// The currently registered outbound channel (for direct test driving
    /// —— on the non-test surface the kernel return path goes through
    /// [`SessionIndex::get`] (inlined in with_kernel_router_task); this
    /// method has no production caller, and the Linux compilation face once
    /// masked its unused-ness with a cfg_attr allow —— in truth a pure test
    /// profile).
    #[cfg(test)]
    fn outbound_sender(&self, vip: &[u8; 4]) -> Option<mpsc::Sender<Vec<u8>>> {
        self.sessions.get(vip)
    }

    /// Whether the data plane is in place (deployment diagnostics/
    /// assertions).
    pub fn is_up(&self) -> bool {
        self.kernel_tx.is_some()
    }

    /// Serve a session packet channel: register the outbound channel
    /// (destination VIP, generation guard) + inbound step-0 source VIP
    /// check + kernel injection + outbound return-path delivery.
    ///
    /// Return = channel end (EOF/error/kernel channel torn down/superseded
    /// by a new session —— same-VIP re-registration overwrites the sender ⇒
    /// this side's out_rx receives None).
    ///
    /// The cancellation-safety structure is in the module docs (inbound
    /// poll_fn + single poll_read + persistent FrameBuf framing, no direct
    /// await of the framing recv inside select!; outbound whole-frame writes
    /// complete inside the branch bodies).
    pub async fn serve_stream(self: &Arc<Self>, vip: [u8; 4], stream: Stream) {
        let Some(kernel_tx) = self.kernel_tx.clone() else {
            // No data plane degraded: graceful FIN (the client observes
            // channel EOF, the control flow is unaffected).
            let mut ch = PacketChannel::from_stream(stream);
            let _ = ch.finish().await;
            return;
        };
        let mut stream = stream;
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);
        let gen = self.sessions.register(vip, out_tx);
        let mut src_mismatch = SrcMismatchCounter::default();
        let mut frames = FrameBuf::new();
        let mut chunk = vec![0u8; READ_CHUNK];
        'tunnel: loop {
            // Buffered complete frames: step-0 source VIP check (§2.2) →
            // kernel injection / mismatch drop + count.
            while let Some(pkt) = frames.take_frame() {
                match ipv4_src_dst(&pkt) {
                    Some((src, dst)) if src == vip => {
                        // M7 counting points (the §7-M7.3 single-point
                        // principle): inbound entering the mesh = that
                        // device's tx; dst = the server's own VIP ⇒ server rx
                        // (the local single counting point).
                        if let Some(m) = self.traffic_of() {
                            m.note_tx(&vip, pkt.len() as u64);
                            if Some(dst) == self.server_vip.map(|v| v.octets()) {
                                m.note_rx(SERVER_TRAFFIC_KEY, pkt.len() as u64);
                            }
                        }
                        if kernel_tx.send(pkt).await.is_err() {
                            self.sessions.unregister(&vip, gen); // the tun write pump is gone
                            return;
                        }
                    }
                    // Mismatch/non-IPv4: drop + count (R22: no silent pass).
                    // Review item 10: per-session mismatch count ≥100 tears
                    // down that session's channel (persistent source forgery
                    // no longer rides on counting alerts alone).
                    _ => {
                        if src_mismatch.on_mismatch() {
                            eprintln!(
                                "flock-server: source VIP mismatch {} times >= {} - tearing down session channel vip={vip:?}",
                                src_mismatch.count, SRC_MISMATCH_SESSION_LIMIT
                            );
                            break 'tunnel;
                        }
                    }
                }
            }
            // Single-step wait (no cross-poll state: out_rx.poll_recv + a
            // single poll_read). No idle timeout —— dead-link ownership
            // lives with the record-layer DeadLink/TCP keepalive (see the
            // STREAM note block); an idle-but-healthy channel (no business
            // traffic) must live forever, otherwise idle clients get
            // periodically torn down.
            let step = std::future::poll_fn(|cx| {
                match out_rx.poll_recv(cx) {
                    Poll::Ready(out) => return Poll::Ready(Step::Outbound(out)),
                    Poll::Pending => {}
                }
                match pin!(&mut stream).poll_read(cx, &mut chunk) {
                    Poll::Ready(Ok(0)) => Poll::Ready(Step::InEof),
                    Poll::Ready(Ok(n)) => Poll::Ready(Step::InBytes(n)),
                    Poll::Ready(Err(_)) => Poll::Ready(Step::InErr),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            match step {
                Step::Outbound(Some(pkt)) => {
                    // M7 counting point: counted before successful outbound
                    // delivery (the delivery surface —— a write failure means
                    // the channel is torn down and the packet was not
                    // delivered; for EWMA semantics "counted = sent" is
                    // precise enough, the failure path being rare).
                    if let Some(m) = self.traffic_of() {
                        m.note_rx(&vip, pkt.len() as u64);
                    }
                    if send_packet(&mut stream, &pkt).await.is_err() {
                        break; // channel torn down (client session ended)
                    }
                }
                Step::Outbound(None) => break, // overwritten by a newer generation (same-VIP re-registration)
                Step::InBytes(n) => frames.extend(&chunk[..n]),
                Step::InErr => break, // channel EOF/error
                Step::InEof => {
                    if frames.has_partial() {
                        break; // partial-frame truncation violation, end as a channel error
                    }
                    break; // peer FIN: the channel ends naturally
                }
            }
        }
        // Generation-guarded unregister: when the same VIP has already been
        // overwritten by a new session, do not delete the new registration
        // (the bug-fix point —— the previous unconditional remove deleted
        // the new session's outbound channel too, blackholing that device's
        // downlink).
        self.sessions.unregister(&vip, gen);
    }
}

/// The poll_fn single-step product (no cross-poll state).
enum Step {
    Outbound(Option<Vec<u8>>),
    InBytes(usize),
    InErr,
    InEof,
}

/// Linux: open the tun + configure routes (`100.64.0.0/16 → tun + the
/// local VIP + rp_filter=1`). Failure logs and returns Err (the caller
/// degrades to control-flow-only).
#[cfg(target_os = "linux")]
async fn open_tun_with_route(tun_name: &str, vip: Ipv4Addr) -> Result<TunIo, ()> {
    let spec = TunSpec {
        name: tun_name.into(),
        mtu: flock_client::tun::MTU,
    };
    match TunIo::open(&spec) {
        Ok(tun) => {
            let ifname = tun.name().to_string();
            match route::apply(&RoutePlan::new(&ifname, vip)).await {
                Ok(()) => {
                    eprintln!(
                        "flock-server: dataplane up: tun {} vip {vip} route {}/{} + rp_filter=1",
                        tun.name(),
                        route::VIP_POOL.0,
                        route::VIP_POOL.1
                    );
                    Ok(tun)
                }
                Err(e) => {
                    eprintln!(
                        "flock-server: route configuration failed (control-flow-only mode): {e}"
                    );
                    Err(())
                }
            }
        }
        Err(e) => {
            eprintln!(
                "flock-server: tun open failed (control-flow-only mode; containers need --cap-add NET_ADMIN --device /dev/net/tun): {e}"
            );
            Err(())
        }
    }
}

// ============================================================================
// Multi-primary forwarding plane (feature `multi-primary`; the §2.2
// decision order + §3.10 ForwardPlane)
// ============================================================================

/// Local session delivery sink: the ForwardPlane's local delivery → the
/// session outbound channel (written out to the peer by the pump).
#[cfg(feature = "multi-primary")]
struct ChannelSink(mpsc::Sender<Vec<u8>>);

#[cfg(feature = "multi-primary")]
impl flock_sync::PacketSink for ChannelSink {
    fn deliver(&self, pkt: &[u8]) -> std::io::Result<()> {
        self.0.try_send(pkt.to_vec()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("session outbound full: {e}"),
            )
        })
    }
}

/// The multi-primary form's session packet channel service (the same
/// cancellation-safe structure as [`PeerRouter::serve_stream`]).
///
/// - Inbound: framing read out →
///   [`flock_sync::SyncNode::ingest_packet`] (completes the §2.2 decision
///   order internally: **step-0 source VIP binding check** → lease location
///   → local delivery / ForwardEnvelope cross-server forwarding / NOT_HERE
///   → one-shot location_query → still failing, drop + best-effort ICMP);
/// - Outbound: the ForwardPlane's local delivery (sink → out_rx) →
///   whole-frame delivery;
/// - Lifecycle: attach/detach_session (lease-domain registration) + the
///   generation semantics carried by the ForwardPlane's sessions table (a
///   new stream for the same device overwrites the old sink).
#[cfg(feature = "multi-primary")]
pub async fn serve_stream_sync(node: Arc<flock_sync::SyncNode>, device: [u8; 32], stream: Stream) {
    let mut stream = stream;
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);
    node.attach_session(device, Arc::new(ChannelSink(out_tx)));
    let mut frames = FrameBuf::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        // Buffered complete frames → the forwarding plane (the decision
        // order is inside ForwardPlane::ingest).
        while let Some(pkt) = frames.take_frame() {
            let _ = node.ingest_packet(&device, &pkt).await;
        }
        // Single-step wait (no cross-poll state). No idle timeout ——
        // dead-link ownership lives with the record-layer DeadLink/TCP
        // keepalive (see the STREAM note block); an idle-but-healthy channel
        // must live forever (same as serve_stream).
        let step = std::future::poll_fn(|cx| {
            match out_rx.poll_recv(cx) {
                Poll::Ready(out) => return Poll::Ready(Step::Outbound(out)),
                Poll::Pending => {}
            }
            match pin!(&mut stream).poll_read(cx, &mut chunk) {
                Poll::Ready(Ok(0)) => Poll::Ready(Step::InEof),
                Poll::Ready(Ok(n)) => Poll::Ready(Step::InBytes(n)),
                Poll::Ready(Err(_)) => Poll::Ready(Step::InErr),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        match step {
            Step::Outbound(Some(pkt)) => {
                if send_packet(&mut stream, &pkt).await.is_err() {
                    break;
                }
            }
            Step::Outbound(None) => break,
            Step::InBytes(n) => frames.extend(&chunk[..n]),
            Step::InErr => break,
            Step::InEof => break,
        }
    }
    node.detach_session(&device);
}

// ============================================================================
// Unit tests (host: the pure-function surface; the real tun/route paths are
// exercised in containers by deploy/m3_assert.sh)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// SRC_MISMATCH/SRC_MISMATCH_KILLS are process-level statics —— the
    /// server e2e tests that touch them serialize through this lock
    /// (otherwise parallel tests trample each other's exact-count
    /// assertions). tokio Mutex (LazyLock materialization —— new is not
    /// const): async tests hold the lock across await points (mutual
    /// exclusion for the whole test; holding a std Mutex across an await is
    /// a clippy-forbidden shape), synchronous unit tests serialize through
    /// try_lock/blocking acquisition of the same lock.
    static MISMATCH_COUNTER_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    #[test]
    fn ipv4_src_dst_parses_and_rejects() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // IPv4, IHL 5
        pkt[12..16].copy_from_slice(&[100, 64, 0, 2]);
        pkt[16..20].copy_from_slice(&[100, 64, 0, 1]);
        let (src, dst) = ipv4_src_dst(&pkt).unwrap();
        assert_eq!(src, [100, 64, 0, 2]);
        assert_eq!(dst, [100, 64, 0, 1]);
        assert!(ipv4_src_dst(&pkt[..19]).is_none(), "too short ⇒ None");
        pkt[0] = 0x65; // version 6
        assert!(ipv4_src_dst(&pkt).is_none(), "not IPv4 ⇒ None");
    }

    #[test]
    fn none_router_reports_down() {
        // Degraded-path flag (the end-to-end behavior of the FIN semantics
        // is reverse-covered by the m3 container: with tun ⇒ is_up).
        let router = PeerRouter::none();
        assert!(!router.is_up());
    }

    /// Review item 10: the per-session source VIP mismatch cap —— the first
    /// 99 occurrences only drop + count globally; the
    /// [`SRC_MISMATCH_SESSION_LIMIT`]th returns the teardown signal and
    /// accumulates kills.
    #[test]
    fn src_mismatch_counter_kills_at_limit() {
        let _g = futures::executor::block_on(MISMATCH_COUNTER_LOCK.lock());
        let mism_before = src_vip_mismatches();
        let kills_before = src_vip_mismatch_kills();
        let mut c = SrcMismatchCounter::default();
        for i in 1..SRC_MISMATCH_SESSION_LIMIT {
            assert!(!c.on_mismatch(), "occurrence {i} does not tear down");
        }
        assert_eq!(
            src_vip_mismatch_kills(),
            kills_before,
            "no kill counted before the limit"
        );
        assert!(
            c.on_mismatch(),
            "occurrence {} reaches the limit ⇒ tear down",
            SRC_MISMATCH_SESSION_LIMIT
        );
        assert_eq!(
            src_vip_mismatches(),
            mism_before + SRC_MISMATCH_SESSION_LIMIT as u64,
            "the global mismatch count accumulates per occurrence"
        );
        assert_eq!(src_vip_mismatch_kills(), kills_before + 1, "kill count +1");
    }

    /// Regression (bug: serve_stream exit did an unconditional remove):
    /// after same-VIP re-registration, the old generation's exit
    /// unregisters only itself —— the new registration must survive
    /// (otherwise that device's downlink blackholes until the next
    /// reconnect).
    #[test]
    fn session_index_old_generation_exit_keeps_new_registration() {
        let idx = SessionIndex::new();
        let vip = [100u8, 64, 0, 2];
        let (tx_a, rx_a) = mpsc::channel::<Vec<u8>>(4);
        let (tx_b, mut rx_b) = mpsc::channel::<Vec<u8>>(4);
        let gen_a = idx.register(vip, tx_a);
        let gen_b = idx.register(vip, tx_b); // device reconnect: overwrites A's sender
        assert_ne!(gen_a, gen_b);
        assert_eq!(
            idx.map.lock().unwrap().len(),
            1,
            "a single registration per VIP (new overwrites old)"
        );
        // A's sender overwritten ⇒ dropped ⇒ A's out_rx will observe None
        // (the old loop's exit path).
        drop(rx_a); // (the receiving end goes with the old session task's end)
                    // Old-generation unregister: must not delete B's registration.
        idx.unregister(&vip, gen_a);
        assert!(
            idx.get(&vip).is_some(),
            "an old generation's exit must not delete the new registration"
        );
        // The new generation's channel works.
        let cur = idx.get(&vip).expect("B registered");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            cur.send(vec![1, 2, 3]).await.unwrap();
            assert_eq!(rx_b.recv().await.unwrap(), vec![1, 2, 3]);
        });
        // Cleared after the new generation unregisters.
        idx.unregister(&vip, gen_b);
        assert!(idx.get(&vip).is_none());
        assert_eq!(idx.map.lock().unwrap().len(), 0);
    }

    /// serve_stream end-to-end (host, real session/record layer/muxer +
    /// injected kernel channel):
    /// ① inbound: packets with a legal src VIP enter the kernel, mismatched
    ///    packets are dropped + counted (§2.2 step 0);
    /// ② outbound: kernel return path → packet-channel delivery;
    /// ③ re-registration race (regression bug: unconditional remove on
    ///    exit): after a new stream takes over the same VIP, the old
    ///    stream's exit must not delete the new registration —— the new
    ///    stream's downlink must work as usual (under the old code that
    ///    device's downlink blackholed).
    #[tokio::test]
    async fn serve_stream_inbound_check_outbound_and_reregistration_race() {
        let _g = MISMATCH_COUNTER_LOCK.lock().await;
        use flock_protocol::session::{
            respond, ClusterId, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, ServerId,
            ServerIdentity, TunnelConfig,
        };
        use flock_protocol::trust::ClusterDirectory;
        use std::time::Duration;

        // Respond-side material + a registered device (isomorphic to the
        // client test harness).
        let root = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let identity = ServerIdentity::enroll(&root, ClusterId([7; 16]), ServerId([1; 16]), "t:1");
        let directory =
            ClusterDirectory::issue(&root, identity.cluster_id, 1, vec![identity.entry.clone()]);
        let device = DeviceStaticKeys::generate();
        let mut dir = InMemoryDirectory::new();
        dir.register(DeviceRecord {
            device_x25519: device.x25519_public(),
            device_ed25519: device.ed25519_public(),
        });
        let pin = flock_protocol::session::ServerPin {
            cluster_id: directory.cluster_id,
            cluster_root_pub: root.verifying_key(),
            entry: directory.servers[0].clone(),
        };

        let (a, b) = tokio::io::duplex(256 * 1024);
        let identity_srv = identity;
        let (stream_tx, mut stream_rx) = mpsc::channel::<Stream>(8);
        let srv = tokio::spawn(async move {
            let t = respond(b, &identity_srv, dir, TunnelConfig::default())
                .await
                .expect("respond");
            while let Some(s) = t.accept_stream().await {
                if stream_tx.send(s).await.is_err() {
                    break;
                }
            }
        });
        let tunnel = flock_protocol::session::initiate(a, &device, &pin, TunnelConfig::default())
            .await
            .expect("initiate");

        let (kernel_tx, mut kernel_rx) = mpsc::channel::<Vec<u8>>(64);
        let router = PeerRouter::with_kernel_tx(kernel_tx);
        let vip = [100u8, 64, 0, 2];

        let ip_pkt = |src: [u8; 4], tag: u8| -> Vec<u8> {
            let mut p = vec![0x45u8, 0, 0, tag];
            p.resize(20, 0);
            p[12..16].copy_from_slice(&src);
            p[16..20].copy_from_slice(&[100, 64, 0, 1]);
            p
        };
        let mism_before = src_vip_mismatches();

        // Control placeholder + channel 1 (lazy SYN: the first data frame
        // triggers the server accept producing the stream).
        let _hold = tunnel
            .open_stream(flock_protocol::mux::Prio::Control)
            .await
            .unwrap();
        let mut ch1 = tunnel.open_packet_channel().await.unwrap();
        ch1.send(&ip_pkt(vip, 1)).await.unwrap();
        let s1 = tokio::time::timeout(Duration::from_secs(5), stream_rx.recv())
            .await
            .expect("stream1 materialize")
            .unwrap();
        let r1 = router.clone();
        let t1 = tokio::spawn(async move { r1.serve_stream(vip, s1).await });
        // ① Legal src VIP ⇒ enters the kernel.
        let got = tokio::time::timeout(Duration::from_secs(5), kernel_rx.recv())
            .await
            .expect("kernel recv")
            .unwrap();
        assert_eq!(
            got,
            ip_pkt(vip, 1),
            "a legal-src-VIP packet is injected into the kernel"
        );
        // ① Mismatched src ⇒ dropped + counted (never enters the kernel).
        ch1.send(&ip_pkt([9, 9, 9, 9], 2)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            src_vip_mismatches(),
            mism_before + 1,
            "mismatched packet dropped + counted"
        );
        assert!(
            kernel_rx.try_recv().is_err(),
            "mismatched packets never enter the kernel"
        );
        // ② Outbound: the current registration (generation 1) delivers.
        router
            .outbound_sender(&vip)
            .expect("registration exists")
            .send(ip_pkt(vip, 3))
            .await
            .unwrap();
        let down = tokio::time::timeout(Duration::from_secs(5), ch1.recv())
            .await
            .expect("ch1 downlink")
            .unwrap();
        assert_eq!(down, ip_pkt(vip, 3));

        // ③ Same-VIP re-registration: channel 2 takes over (overwrites
        // generation 1's sender ⇒ t1 exits and unregisters the old
        // generation).
        let mut ch2 = tunnel.open_packet_channel().await.unwrap();
        ch2.send(&ip_pkt(vip, 4)).await.unwrap();
        let s2 = tokio::time::timeout(Duration::from_secs(5), stream_rx.recv())
            .await
            .expect("stream2 materialize")
            .unwrap();
        let r2 = router.clone();
        let t2 = tokio::spawn(async move { r2.serve_stream(vip, s2).await });
        let got = tokio::time::timeout(Duration::from_secs(5), kernel_rx.recv())
            .await
            .expect("kernel recv ch2")
            .unwrap();
        assert_eq!(
            got,
            ip_pkt(vip, 4),
            "the new channel's inbound works as usual"
        );
        // Wait for t1's exit (its sender overwritten → out_rx None →
        // unregister(old generation)).
        let _ = tokio::time::timeout(Duration::from_secs(5), t1).await;
        // Key assertion: the new registration was not deleted by the old
        // exit; the new channel's downlink works as usual (the old code
        // blackholed here).
        let sender2 = router
            .outbound_sender(&vip)
            .expect("the new registration survives (the old exit must not delete it)");
        sender2.send(ip_pkt(vip, 5)).await.unwrap();
        let down2 = tokio::time::timeout(Duration::from_secs(5), ch2.recv())
            .await
            .expect("ch2 downlink (not blackholed after re-registration)")
            .unwrap();
        assert_eq!(down2, ip_pkt(vip, 5));

        let _ = tokio::time::timeout(Duration::from_secs(3), t2).await;
        drop(srv);
    }

    /// Review item 10: per-session source VIP mismatches reaching the limit
    /// (100) ⇒ the session channel is torn down (the client observes channel
    /// EOF) + the kills counter increments —— a session persistently forging
    /// its source no longer lives forever under the "drop + count"
    /// backstop.
    #[tokio::test]
    async fn serve_stream_killed_after_100_src_vip_mismatches() {
        let _g = MISMATCH_COUNTER_LOCK.lock().await;
        use flock_protocol::session::{
            respond, ClusterId, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, ServerId,
            ServerIdentity, TunnelConfig,
        };
        use flock_protocol::trust::ClusterDirectory;
        use std::time::Duration;

        let root = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let identity = ServerIdentity::enroll(&root, ClusterId([7; 16]), ServerId([1; 16]), "t:1");
        let directory =
            ClusterDirectory::issue(&root, identity.cluster_id, 1, vec![identity.entry.clone()]);
        let device = DeviceStaticKeys::generate();
        let mut dir = InMemoryDirectory::new();
        dir.register(DeviceRecord {
            device_x25519: device.x25519_public(),
            device_ed25519: device.ed25519_public(),
        });
        let pin = flock_protocol::session::ServerPin {
            cluster_id: directory.cluster_id,
            cluster_root_pub: root.verifying_key(),
            entry: directory.servers[0].clone(),
        };

        let (a, b) = tokio::io::duplex(256 * 1024);
        let (stream_tx, mut stream_rx) = mpsc::channel::<Stream>(8);
        let srv = tokio::spawn(async move {
            let t = respond(b, &identity, dir, TunnelConfig::default())
                .await
                .expect("respond");
            while let Some(s) = t.accept_stream().await {
                if stream_tx.send(s).await.is_err() {
                    break;
                }
            }
        });
        let tunnel = flock_protocol::session::initiate(a, &device, &pin, TunnelConfig::default())
            .await
            .expect("initiate");

        let (kernel_tx, _kernel_rx) = mpsc::channel::<Vec<u8>>(64);
        let router = PeerRouter::with_kernel_tx(kernel_tx);
        let vip = [100u8, 64, 0, 2];
        let kills_before = src_vip_mismatch_kills();

        // Control placeholder + data channel materialization (lazy SYN: the
        // first frame triggers the server accept). Materialized with a
        // **legal** src VIP packet (entering no mismatch count).
        let _hold = tunnel
            .open_stream(flock_protocol::mux::Prio::Control)
            .await
            .unwrap();
        let mut ch = tunnel.open_packet_channel().await.unwrap();
        let ip_pkt = |src: [u8; 4], tag: u8| -> Vec<u8> {
            let mut p = vec![0x45u8, 0, 0, tag];
            p.resize(20, 0);
            p[12..16].copy_from_slice(&src);
            p[16..20].copy_from_slice(&[100, 64, 0, 1]);
            p
        };
        ch.send(&ip_pkt(vip, 1)).await.unwrap();
        let s = tokio::time::timeout(Duration::from_secs(5), stream_rx.recv())
            .await
            .expect("stream materialize")
            .unwrap();
        let r = router.clone();
        let task = tokio::spawn(async move { r.serve_stream(vip, s).await });

        // Send 100 mismatched packets in a row: the 100th reaches the limit
        // ⇒ the server tears down the channel (the client's recv observes
        // EOF/error; after teardown the residual sends report WriteZero and
        // stop —— the teardown itself is the goal).
        let bad = ip_pkt([9, 9, 9, 9], 2);
        for _ in 0..SRC_MISMATCH_SESSION_LIMIT {
            if ch.send(&bad).await.is_err() {
                break; // the channel was already torn down by the server
                       // (before all 100 were sent —— the count had already
                       // raced ahead on the server side)
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let closed = tokio::time::timeout_at(deadline.into(), async {
            loop {
                if ch.recv().await.is_err() {
                    break true; // channel closed (EOF/error) = the client's observation of the server-side teardown
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            closed,
            "the client channel must observe closure after the mismatch limit"
        );
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert_eq!(src_vip_mismatch_kills(), kills_before + 1, "kill count +1");
        drop(srv);
    }
}
