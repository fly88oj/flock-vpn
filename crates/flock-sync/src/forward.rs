//! Cross-server forwarding plane (§2.2 data-plane ForwardEnvelope + §3.10
//! forwarding plane, M4 part two).
//!
//! Forwarding decision order (§2.2):
//! 0. **Source VIP binding check (step 0, ahead of all forwarding logic)**:
//!    every outbound IP packet of a session's device must have a source
//!    address equal to that device's registered VIP (session DeviceId ↔ src
//!    VIP binding; rp_filter does not cover user-space traffic — per-node
//!    ingress filtering at the application layer). Mismatch ⇒ drop + count.
//!    The ForwardEnvelope's `src_dev` and the inner source address are
//!    **checked once each at the receiver and the sender**.
//! 1. Destination VIP → device holder: look up the **local lease table**
//!    (gossip) — the single source of truth for a device's current location
//!    (NetState stores only static registration info).
//! 2. Held locally ⇒ deliver straight to that session's PacketChannel
//!    (`PacketSink` seam).
//! 3. Held elsewhere ⇒ `ForwardEnvelope{ver, src_dev, dst_dev,
//!    origin_server, hop=1, payload}` sent on a dedicated FRWD stream of the
//!    server-interconnect E2E session; receiver: dst local ⇒ deliver;
//!    otherwise reply `NOT_HERE` (**second forwarding forbidden**, hop=1 loop
//!    prevention — re-forwarding with hop exhausted ⇒ drop + count).
//! 4. NOT_HERE ⇒ **one-shot location query** (location_query, fan-out ≤3)
//!    redirect once; still failing ⇒ **drop + best-effort ICMP unreachable**
//!    (no broadcast, no cached retry).
//!
//! # M7 per-device byte counting (§7-M7.3 "count at the successful delivery
//! point" single-point principle)
//!
//! Every unit of traffic is counted by **exactly one server** (no cross-server
//! double counting):
//! - **src device tx**: counted once by the **access server** (the src lease
//!   holder) after ingest passes the step-0 source VIP binding check
//!   (entering the mesh is success; no server on the dst side counts src);
//! - **dst device rx**: counted by **the server that delivers successfully** —
//!   local sink delivery success (same-server path) or the ForwardEnvelope
//!   receiver delivering locally (cross-server path; the receiver is the dst's
//!   true holder); NotHere/drops are not counted; the cross-server origin
//!   server does **not** count dst (it only counts src tx);
//! - **the server itself** (`server_self_device_id(me)` synthetic key):
//!   dst = own VIP injected into the kernel successfully ⇒ rx; kernel return
//!   path `route_outbound` ⇒ tx (the server's own entry is counted only by
//!   itself — other servers read it through the gossip view).

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::lease::{server_self_device_id, LeaseTable, LocateFanout};
use crate::proto::NodeId;
use crate::sm::SmCore;

/// ForwardEnvelope version.
pub const FORWARD_VER: u8 = 1;

/// Cross-server forwarding envelope (§2.2-3; carried on the FRWD stream of a
/// server-interconnect session — server-to-server encryption on the outer
/// layer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardEnvelope {
    pub ver: u8,
    /// The claimed sending device of the inner IP packet (cross-checked
    /// against the inner source address, once at each end).
    pub src_dev: [u8; 32],
    pub dst_dev: [u8; 32],
    /// The server originating the forward (NOT_HERE receipt target).
    pub origin_server: NodeId,
    /// Remaining hops: 1 = first hop. The receiver may only deliver locally /
    /// answer NOT_HERE; **second forwarding forbidden** (hop=1 loop
    /// prevention).
    pub hop: u8,
    /// Inner IP packet (plaintext in this segment — threat model in §2.5).
    pub payload: Vec<u8>,
}

/// Receiver reject reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    /// Version unsupported.
    Version,
    /// Hop exhausted (loop prevention: second forwarding).
    Hop,
    /// src_dev ↔ inner source address cross-check mismatch.
    SrcBinding,
}

/// Forward result (FRWD stream receipt).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForwardOutcome {
    /// Delivered to a local session.
    Delivered,
    /// dst not on this machine (origin uses this to run the one-shot
    /// location_query).
    NotHere,
    /// Rejected by the receiver (source binding mismatch / loop / bad
    /// packet).
    Rejected(RejectReason),
}

/// Local session delivery seam (the assembly layer maps the PacketChannel;
/// tests use a recording sink).
pub trait PacketSink: Send + Sync + 'static {
    fn deliver(&self, pkt: &[u8]) -> io::Result<()>;
}

/// Interconnect send seam (injected by the node assembly: WireRpc::Forward
/// over an E2E session).
pub trait ForwardTransport: Send + Sync + 'static {
    fn send(
        &self,
        peer: NodeId,
        env: ForwardEnvelope,
    ) -> BoxFuture<'static, io::Result<ForwardOutcome>>;
}

/// Forwarding-plane counters (assertion/alerting surface; §2.2-0 "drop +
/// count + alert over threshold").
#[derive(Debug, Default, Clone, Copy)]
pub struct ForwardStats {
    /// Step-0 source VIP binding mismatches (drop + count).
    pub src_violations: u64,
    /// Receiver-side src_dev ↔ inner source address cross-check mismatches
    /// (reject + count).
    pub src_mismatch_rejected: u64,
    /// Second forwarding with hop exhausted (loop prevention: drop + count).
    pub hop_dropped: u64,
    pub delivered_local: u64,
    /// Delivered to the local kernel (dst = this server's own VIP — the
    /// server is a peer too, §2.2).
    pub delivered_kernel: u64,
    /// Emitted by the local kernel (route_outbound: return path / local
    /// protocol-stack traffic into the mesh).
    pub outbound_kernel: u64,
    pub forwarded: u64,
    pub not_here: u64,
    /// Redirected successfully via a one-shot location_query after NOT_HERE.
    pub locate_redirected: u64,
    pub icmp_unreachable: u64,
    /// Still failing after redirect / unknown destination ⇒ dropped.
    pub dropped: u64,
}

/// Ingress processing result (returned by ingest; for test/assembly
/// assertions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestResult {
    /// Delivered to a local target session.
    DeliveredLocal,
    /// Forwarded cross-server (including the peer's outcome).
    Forwarded(ForwardOutcome),
    /// Source VIP binding mismatch ⇒ dropped (counted).
    SrcViolation,
    /// Dropped (with best-effort ICMP unreachable, counted).
    DroppedIcmp,
    /// Dropped (no ICMP recipient — source not local, best-effort semantics).
    Dropped,
}

/// Forwarding engine (one per server; the assembly injects sessions / lease
/// table / interconnect).
pub struct ForwardPlane {
    me: NodeId,
    sm: Arc<SmCore>,
    leases: Arc<LeaseTable>,
    transport: Mutex<Option<Arc<dyn ForwardTransport>>>,
    fanout: Mutex<Option<Arc<dyn LocateFanout>>>,
    sessions: Mutex<HashMap<[u8; 32], Arc<dyn PacketSink>>>,
    /// Local-kernel seam (local delivery of the server's own VIP + return-path
    /// routing, §2.2 "the server itself is a peer too"): `(own VIP, tun
    /// write-pump sink)` — packets with dst = own VIP go into the kernel
    /// (ICMP replies / iperf binding surface); packets read out of the kernel
    /// go back into the mesh via [`ForwardPlane::route_outbound`].
    local_peer: Mutex<Option<(Ipv4Addr, Arc<dyn PacketSink>)>>,
    stats: ForwardStatsAtomic,
}

#[derive(Default)]
struct ForwardStatsAtomic {
    src_violations: AtomicU64,
    src_mismatch_rejected: AtomicU64,
    hop_dropped: AtomicU64,
    delivered_local: AtomicU64,
    delivered_kernel: AtomicU64,
    outbound_kernel: AtomicU64,
    forwarded: AtomicU64,
    not_here: AtomicU64,
    locate_redirected: AtomicU64,
    icmp_unreachable: AtomicU64,
    dropped: AtomicU64,
}

impl ForwardPlane {
    pub fn new(me: NodeId, sm: Arc<SmCore>, leases: Arc<LeaseTable>) -> Arc<Self> {
        Arc::new(ForwardPlane {
            me,
            sm,
            leases,
            transport: Mutex::new(None),
            fanout: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            local_peer: Mutex::new(None),
            stats: ForwardStatsAtomic::default(),
        })
    }

    /// Inject the interconnect sender and the location-inquiry fan-out (node
    /// assembly time).
    pub fn set_transport(&self, t: Arc<dyn ForwardTransport>, f: Arc<dyn LocateFanout>) {
        *self.transport.lock().expect("fwd transport") = Some(t);
        *self.fanout.lock().expect("fwd fanout") = Some(f);
    }

    /// The local node id.
    pub fn me(&self) -> NodeId {
        self.me
    }

    /// Lease table reference (test/assembly diagnostics surface).
    pub fn leases(&self) -> &Arc<LeaseTable> {
        &self.leases
    }

    /// The set of locally registered session devices (for the lease refresh
    /// loop — lease re-publication for long-lived sessions, lease.rs).
    pub fn local_devices(&self) -> Vec<[u8; 32]> {
        self.sessions
            .lock()
            .expect("fwd sessions")
            .keys()
            .copied()
            .collect()
    }

    /// Attach/detach a local device session (established at login / torn down
    /// on disconnect).
    pub fn attach_session(&self, device: [u8; 32], sink: Arc<dyn PacketSink>) {
        self.sessions
            .lock()
            .expect("fwd sessions")
            .insert(device, sink);
    }

    pub fn detach_session(&self, device: &[u8; 32]) {
        self.sessions.lock().expect("fwd sessions").remove(device);
    }

    /// Counter snapshot.
    pub fn stats(&self) -> ForwardStats {
        ForwardStats {
            src_violations: self.stats.src_violations.load(Ordering::Relaxed),
            src_mismatch_rejected: self.stats.src_mismatch_rejected.load(Ordering::Relaxed),
            hop_dropped: self.stats.hop_dropped.load(Ordering::Relaxed),
            delivered_local: self.stats.delivered_local.load(Ordering::Relaxed),
            delivered_kernel: self.stats.delivered_kernel.load(Ordering::Relaxed),
            outbound_kernel: self.stats.outbound_kernel.load(Ordering::Relaxed),
            forwarded: self.stats.forwarded.load(Ordering::Relaxed),
            not_here: self.stats.not_here.load(Ordering::Relaxed),
            locate_redirected: self.stats.locate_redirected.load(Ordering::Relaxed),
            icmp_unreachable: self.stats.icmp_unreachable.load(Ordering::Relaxed),
            dropped: self.stats.dropped.load(Ordering::Relaxed),
        }
    }

    /// Attach the local kernel (the server's own peer surface): `vip` = the
    /// local tun VIP; `sink` = the tun write pump (packets with dst = own VIP
    /// are injected into the kernel). The assembly layer starts a separate
    /// read pump consuming [`Self::route_outbound`].
    pub fn set_local_peer(&self, vip: Ipv4Addr, sink: Arc<dyn PacketSink>) {
        *self.local_peer.lock().expect("fwd local peer") = Some((vip, sink));
    }

    /// Route packets emitted by the local kernel (ICMP return path / local
    /// protocol-stack traffic) into the mesh: skips the step-0 source binding
    /// check (the local kernel is a trusted source = own VIP), then follows
    /// the same decision order as [`Self::ingest`] by destination VIP (local
    /// session delivery / ForwardEnvelope cross-server / one-shot redirect /
    /// drop+ICMP — best-effort semantics when the peer device is not local;
    /// source is this machine ⇒ nowhere to send ICMP, plain drop).
    pub async fn route_outbound(&self, pkt: &[u8]) {
        self.stats.outbound_kernel.fetch_add(1, Ordering::Relaxed);
        // M7 counting point: the server's own tx (kernel return path into the
        // mesh — counted at this single point locally).
        self.leases
            .note_tx(&server_self_device_id(self.me), pkt.len() as u64);
        let Some(dst_vip) = ipv4_dst(pkt) else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        // dst = own VIP: this machine to itself (rare; drop outright to avoid
        // a loop).
        {
            let local = self.local_peer.lock().expect("fwd local peer").clone();
            if let Some((vip, _)) = local {
                if dst_vip == vip {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
        let dst_dev = match self.sm.device_by_vip(&dst_vip.octets()) {
            Some(d) => d,
            // Server-segment VIP fallback mapping (same source as ingest 1b;
            // inter-server mesh traffic — §6.2 the server segment is outside
            // the device table).
            None => match crate::proto::server_vip_node(&dst_vip.octets()) {
                Some(n) if n != self.me => server_self_device_id(n),
                _ => {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            },
        };
        // Source = this server's server-self synthetic key (the receiver
        // validates the source binding against the origin's deterministic
        // VIP; on the failure path drop_with_icmp finds no session for this
        // key ⇒ naturally a plain drop — best-effort semantics for kernel
        // egress).
        let src_dev = server_self_device_id(self.me);
        let _ = self.deliver_or_forward_fwd(&src_dev, dst_dev, pkt).await;
    }

    /// The device's registered VIP (source-binding check data source =
    /// NetState strongly consistent registry).
    pub fn vip_of(&self, device: &[u8; 32]) -> Option<Ipv4Addr> {
        self.sm.vip_of(device).map(Ipv4Addr::from)
    }

    /// **Step 0: source VIP binding check** (session device ↔ packet source
    /// address; mismatch ⇒ drop + count).
    fn check_src_binding(&self, device: &[u8; 32], pkt: &[u8]) -> bool {
        let Some(expect) = self.vip_of(device) else {
            return false; // No registered row (the session should not exist) ⇒ violation
        };
        match ipv4_src(pkt) {
            Some(src) => src == expect,
            None => false,
        }
    }

    /// Session ingress processing (§2.2 forwarding decision order 0→4).
    /// `device` = that session's device.
    pub async fn ingest(&self, device: &[u8; 32], pkt: &[u8]) -> IngestResult {
        // 0. Source VIP binding check — ahead of all forwarding logic.
        if !self.check_src_binding(device, pkt) {
            self.stats.src_violations.fetch_add(1, Ordering::Relaxed);
            return IngestResult::SrcViolation;
        }
        // M7 counting point: src tx is counted once by the access server
        // (this machine = src lease holder) as the packet enters the mesh
        // (binding check passed; the dst side does not double-count src —
        // single-point principle, see the module docs).
        self.leases.note_tx(device, pkt.len() as u64);
        // 1. Destination VIP.
        let Some(dst_vip) = ipv4_dst(pkt) else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return IngestResult::Dropped;
        };
        // 1a. dst = this server's own VIP ⇒ inject into the local kernel (the
        // server is a peer too, §2.2 — the local-server path of A2/A4 ping /
        // iperf).
        {
            let local = self.local_peer.lock().expect("fwd local peer").clone();
            if let Some((vip, kernel)) = local {
                if dst_vip == vip {
                    if kernel.deliver(pkt).is_ok() {
                        self.stats.delivered_kernel.fetch_add(1, Ordering::Relaxed);
                        // M7 counting point: the server's own rx (own VIP
                        // injected into the kernel successfully — counted at
                        // this single point locally).
                        self.leases
                            .note_rx(&server_self_device_id(self.me), pkt.len() as u64);
                        return IngestResult::DeliveredLocal;
                    }
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return IngestResult::Dropped;
                }
            }
        }
        // 1b. Destination VIP → device holder (device registry).
        // Server-segment VIPs (§6.2 .1–.10) are not in the device table —
        // map them by deterministic derivation to the corresponding server's
        // server-self synthetic device (the cross-server path of §7-M8.2
        // "any server VIP reachable": ForwardEnvelope to the receiver, then
        // injected into its kernel, receive side). The local server VIP was
        // already caught in 1a (during the window before local_peer is
        // assembled, treated as an unregistered destination — best-effort
        // ICMP).
        let dst_dev = match self.sm.device_by_vip(&dst_vip.octets()) {
            Some(dev) => dev,
            None => match crate::proto::server_vip_node(&dst_vip.octets()) {
                Some(n) if n != self.me => server_self_device_id(n),
                _ => return self.drop_with_icmp(device, pkt),
            },
        };
        self.deliver_or_forward_fwd(device, dst_dev, pkt).await
    }

    /// Decision order 2→4 (local delivery / cross-server ForwardEnvelope /
    /// NOT_HERE→redirect / drop+ICMP). Shared by ingress (ingest) and kernel
    /// egress (route_outbound — src has no session binding, no ICMP sent).
    async fn deliver_or_forward_fwd(
        &self,
        src_dev: &[u8; 32],
        dst_dev: [u8; 32],
        pkt: &[u8],
    ) -> IngestResult {
        // 2. Held locally ⇒ deliver directly.
        if let Some(sink) = self
            .sessions
            .lock()
            .expect("fwd sessions")
            .get(&dst_dev)
            .cloned()
        {
            if sink.deliver(pkt).is_ok() {
                self.stats.delivered_local.fetch_add(1, Ordering::Relaxed);
                // M7 counting point: dst rx (counted by the server that
                // delivers successfully — this machine is the dst holder).
                self.leases.note_rx(&dst_dev, pkt.len() as u64);
                return IngestResult::DeliveredLocal;
            }
        }
        // 3. Held elsewhere ⇒ ForwardEnvelope (hop=1) cross-server forward.
        match self.leases.observe(&dst_dev) {
            Some(lease) if lease.holder != self.me => {
                let env = ForwardEnvelope {
                    ver: FORWARD_VER,
                    src_dev: *src_dev,
                    dst_dev,
                    origin_server: self.me,
                    hop: 1,
                    payload: pkt.to_vec(),
                };
                let outcome = self.send_envelope(lease.holder, env).await;
                match outcome {
                    Ok(ForwardOutcome::Delivered) => {
                        self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                        IngestResult::Forwarded(ForwardOutcome::Delivered)
                    }
                    Ok(ForwardOutcome::NotHere) => {
                        // 4. One-shot location_query redirect; still failing ⇒
                        //    drop + ICMP.
                        self.stats.not_here.fetch_add(1, Ordering::Relaxed);
                        self.redirect_once(src_dev, dst_dev, pkt).await
                    }
                    Ok(ForwardOutcome::Rejected(_)) | Err(_) => {
                        self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        IngestResult::Dropped
                    }
                }
            }
            // Lease says local but the session is not here (just disconnected)
            // or no lease: one-shot inquiry, then drop.
            _ => {
                self.stats.not_here.fetch_add(1, Ordering::Relaxed);
                self.redirect_once(src_dev, dst_dev, pkt).await
            }
        }
    }

    /// NOT_HERE handling: one-shot location inquiry (fan-out ≤3, no retry, no
    /// caching) → redirect once. Note: the inquiry **asks peers only** — the
    /// local lease was exactly the answer that just failed (staleness is the
    /// root cause).
    async fn redirect_once(
        &self,
        src_dev: &[u8; 32],
        dst_dev: [u8; 32],
        pkt: &[u8],
    ) -> IngestResult {
        let holder = {
            let fanout = self.fanout.lock().expect("fwd fanout").clone();
            match fanout {
                Some(f) => f.locate(&dst_dev).await,
                None => None,
            }
        };
        if let Some(holder) = holder.filter(|h| *h != self.me) {
            let env = ForwardEnvelope {
                ver: FORWARD_VER,
                src_dev: *src_dev,
                dst_dev,
                origin_server: self.me,
                hop: 1,
                payload: pkt.to_vec(),
            };
            if let Ok(ForwardOutcome::Delivered) = self.send_envelope(holder, env).await {
                self.stats.locate_redirected.fetch_add(1, Ordering::Relaxed);
                return IngestResult::Forwarded(ForwardOutcome::Delivered);
            }
        }
        self.drop_with_icmp(src_dev, pkt)
    }

    async fn send_envelope(
        &self,
        peer: NodeId,
        env: ForwardEnvelope,
    ) -> io::Result<ForwardOutcome> {
        let t = self.transport.lock().expect("fwd transport").clone();
        let Some(t) = t else {
            return Err(io::Error::other("forward transport not wired"));
        };
        t.send(peer, env).await
    }

    /// Drop + best-effort ICMP unreachable (deliverable only if the source
    /// device is local; otherwise a plain drop).
    fn drop_with_icmp(&self, src_dev: &[u8; 32], pkt: &[u8]) -> IngestResult {
        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        let icmp = icmp_host_unreachable(pkt);
        let sink = self
            .sessions
            .lock()
            .expect("fwd sessions")
            .get(src_dev)
            .cloned();
        if let Some(sink) = sink {
            if sink.deliver(&icmp).is_ok() {
                self.stats.icmp_unreachable.fetch_add(1, Ordering::Relaxed);
                return IngestResult::DroppedIcmp;
            }
        }
        IngestResult::Dropped
    }

    /// **Receiver side**: a ForwardEnvelope arrived on the interconnect FRWD
    /// stream. Check order: ver → hop (loop prevention: a hop=0 "second
    /// forward" is dropped + counted) → src_dev cross-check (checked once more
    /// at the receiver) → local delivery / NOT_HERE (no re-forwarding).
    pub fn receive(&self, env: ForwardEnvelope) -> ForwardOutcome {
        if env.ver != FORWARD_VER {
            self.stats.hop_dropped.fetch_add(1, Ordering::Relaxed);
            return ForwardOutcome::Rejected(RejectReason::Version);
        }
        if env.hop == 0 {
            // Loop prevention: remaining hops exhausted (a constructed second
            // forward) ⇒ drop + count.
            self.stats.hop_dropped.fetch_add(1, Ordering::Relaxed);
            return ForwardOutcome::Rejected(RejectReason::Hop);
        }
        // Receiver-side source binding cross-check: the registered VIP of
        // envelope.src_dev == the inner packet's source address. Exception:
        // src_dev = the sending server's server-self synthetic key (the
        // sending server's kernel return path in route_outbound, not a
        // registered device) ⇒ the expected inner source is that server's
        // deterministic VIP (server_vip_of — the server vouches for its own
        // kernel traffic, inside the mesh trust domain).
        let ok = match self.vip_of(&env.src_dev) {
            Some(expect) => matches!(ipv4_src(&env.payload), Some(src) if src == expect),
            None if env.src_dev == server_self_device_id(env.origin_server) => {
                matches!(
                    (
                        crate::proto::server_vip_of(env.origin_server),
                        ipv4_src(&env.payload)
                    ),
                    (Some(expect), Some(src)) if Ipv4Addr::from(expect) == src
                )
            }
            None => false,
        };
        if !ok {
            self.stats
                .src_mismatch_rejected
                .fetch_add(1, Ordering::Relaxed);
            return ForwardOutcome::Rejected(RejectReason::SrcBinding);
        }
        // dst = this server itself (the server-self synthetic device has no
        // session sink) ⇒ inject into the local kernel — §7-M8.2 "cross-server
        // goes by ForwardEnvelope, the receiver injects into the kernel via
        // the fwd_delivered_kernel path" (the cross-server face of webui being
        // reachable at any server VIP; if the local VIP has no kernel
        // assembled ⇒ NOT_HERE).
        if env.dst_dev == server_self_device_id(self.me) {
            let local = self.local_peer.lock().expect("fwd local peer").clone();
            if let Some((_, kernel)) = local {
                if kernel.deliver(&env.payload).is_ok() {
                    self.stats.delivered_kernel.fetch_add(1, Ordering::Relaxed);
                    // M7 counting point: cross-server dst rx is counted by
                    // the receiver (= the dst's true holder) — the server's
                    // own entry is counted only by itself (single-point
                    // principle in the module docs).
                    self.leases.note_rx(&env.dst_dev, env.payload.len() as u64);
                    return ForwardOutcome::Delivered;
                }
            }
            return ForwardOutcome::NotHere;
        }
        // Local delivery or NOT_HERE (no second forwarding within hop
        // semantics).
        let sink = self
            .sessions
            .lock()
            .expect("fwd sessions")
            .get(&env.dst_dev)
            .cloned();
        match sink {
            Some(sink) if sink.deliver(&env.payload).is_ok() => {
                // M7 counting point: cross-server dst rx is counted by the
                // **receiver** (= the dst's true holder) — the origin only
                // counted src tx, no double counting (single-point principle,
                // module docs).
                self.leases.note_rx(&env.dst_dev, env.payload.len() as u64);
                ForwardOutcome::Delivered
            }
            _ => ForwardOutcome::NotHere,
        }
    }
}

// ============================================================================
// Minimal IPv4 parsing and ICMP unreachable construction
// ============================================================================

/// Parse the source address of an IPv4 packet (20B base header; non-IPv4 /
/// truncated ⇒ None).
pub fn ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    ipv4_header(pkt)?;
    (pkt.len() >= 20).then_some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

/// Parse the destination address of an IPv4 packet.
pub fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    ipv4_header(pkt)?;
    (pkt.len() >= 20).then_some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

fn ipv4_header(pkt: &[u8]) -> Option<usize> {
    if pkt.len() < 20 {
        return None;
    }
    let v = pkt[0] >> 4;
    if v != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    Some(ihl)
}

/// Construct ICMPv4 host unreachable (type 3 / code 1): RFC 792 — the original
/// IP header + first 8 bytes embedded; sent back to the original source
/// (best-effort: the caller delivers it to the source device's session).
pub fn icmp_host_unreachable(orig: &[u8]) -> Vec<u8> {
    let total_len = 20 + 8 + 28.min(orig.len());
    let mut pkt = vec![0u8; total_len];
    // IPv4 header: src = original packet's dst, dst = original packet's src
    // (back to the sender).
    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4] = 0x64; // id
    pkt[6] = 0x40; // DF
    pkt[8] = 64; // ttl
    pkt[9] = 0x01; // ICMP
    if orig.len() >= 20 {
        pkt[12..16].copy_from_slice(&orig[16..20]);
        pkt[16..20].copy_from_slice(&orig[12..16]);
    }
    let csum = ipv4_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    // ICMP: type=3 code=1 + unused 4B + original packet header 28B (IP header
    // + first 8B of payload).
    let icmp_off = 20;
    pkt[icmp_off] = 3;
    pkt[icmp_off + 1] = 1;
    let embedded = 28.min(orig.len());
    pkt[icmp_off + 8..icmp_off + 8 + embedded].copy_from_slice(&orig[..embedded]);
    let csum = icmp_checksum(&pkt[icmp_off..]);
    pkt[icmp_off + 2..icmp_off + 4].copy_from_slice(&csum.to_be_bytes());
    pkt
}

fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let chunks = bytes.as_chunks::<2>();
    for c in chunks.0 {
        sum = sum.wrapping_add(u16::from_be_bytes(*c) as u32);
    }
    if let Some(b) = chunks.1.first() {
        sum = sum.wrapping_add((*b as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn ipv4_checksum(hdr: &[u8]) -> u16 {
    ones_complement_sum(hdr)
}

fn icmp_checksum(body: &[u8]) -> u16 {
    ones_complement_sum(body)
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4 packet (20B header + payload).
    fn ip4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 0x11; // UDP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..].copy_from_slice(payload);
        p
    }

    #[test]
    fn ipv4_parse() {
        let p = ip4(
            "100.64.0.2".parse().unwrap(),
            "100.64.0.3".parse().unwrap(),
            b"x",
        );
        assert_eq!(ipv4_src(&p).unwrap().to_string(), "100.64.0.2");
        assert_eq!(ipv4_dst(&p).unwrap().to_string(), "100.64.0.3");
        assert_eq!(ipv4_src(b"short"), None);
        let mut v6 = p.clone();
        v6[0] = 0x60;
        assert_eq!(ipv4_src(&v6), None, "non-IPv4 ⇒ rejected");
    }

    // —— M8b cross-server server-VIP forwarding-plane test kit (§7-M8.2 "any
    //    server VIP reachable") ——

    use crate::hooks::HookRegistry;
    use crate::lease::{GossipMsg, LeaseTable};
    use crate::sm::SmCore;
    use openraft::Entry;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    /// Capturing PacketSink (shared by the session inbox / the kernel
    /// injection pump).
    struct CapSink(StdMutex<Vec<Vec<u8>>>);
    impl PacketSink for CapSink {
        fn deliver(&self, pkt: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().push(pkt.to_vec());
            Ok(())
        }
    }

    /// Capturing interconnect (records (peer, envelope), always reports
    /// Delivered).
    struct CapTransport(StdMutex<Vec<(NodeId, ForwardEnvelope)>>);
    impl ForwardTransport for CapTransport {
        fn send(
            &self,
            peer: NodeId,
            env: ForwardEnvelope,
        ) -> BoxFuture<'static, io::Result<ForwardOutcome>> {
            self.0.lock().unwrap().push((peer, env));
            Box::pin(async { Ok(ForwardOutcome::Delivered) })
        }
    }

    struct NoFanout;
    impl crate::lease::LocateFanout for NoFanout {
        fn locate(&self, _device: &[u8; 32]) -> BoxFuture<'static, Option<NodeId>> {
            Box::pin(async { None })
        }
    }

    fn entry_of(idx: u64, req: crate::proto::SyncRequest) -> Entry<crate::raft_types::SyncConfig> {
        Entry {
            log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), idx),
            payload: openraft::EntryPayload::Normal(req),
        }
    }

    /// The forwarding plane on node 1 (with the registered device
    /// dev=sha(ed25519=[1;32]) @ vip 100.64.0.11, session sink attached).
    async fn plane_with_device() -> (Arc<ForwardPlane>, [u8; 32], Arc<CapSink>, Arc<CapTransport>) {
        let dir = tempfile::tempdir().expect("tmp");
        let db = redb::Database::create(dir.path().join("fwd.redb")).expect("db");
        let sm = SmCore::empty(Arc::new(db), None);
        let root = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let dev: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest([1u8; 32]).into()
        };
        sm.apply_entries(&[
            entry_of(
                1,
                crate::proto::SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32]),
            ),
            entry_of(
                2,
                crate::proto::SyncRequest::RegisterDevice {
                    owner: "u".into(),
                    x25519: [2; 32],
                    ed25519: [1; 32],
                    hostname: "t".into(),
                    registered_at_unix: 1,
                },
            ),
        ])
        .await;
        let leases = LeaseTable::new(1, Duration::from_secs(60), HookRegistry::new());
        let plane = ForwardPlane::new(1, sm, leases);
        let sess = Arc::new(CapSink(StdMutex::new(Vec::new())));
        plane.attach_session(dev, sess.clone());
        let t = Arc::new(CapTransport(StdMutex::new(Vec::new())));
        plane.set_transport(t.clone(), Arc::new(NoFanout));
        (plane, dev, sess, t)
    }

    /// ingest: dst = a remote server VIP (100.64.0.2, not a device-table row)
    /// ⇒ server-segment fallback mapping → ForwardEnvelope(dst_dev =
    /// server_self(2)) sent to node 2.
    #[tokio::test]
    async fn ingest_to_remote_server_vip_forwards_to_self_device() {
        let (plane, dev, _sess, t) = plane_with_device().await;
        // Node 2's server-self lease (gossip view).
        plane.leases().merge_remote(GossipMsg::Publish {
            device: server_self_device_id(2),
            holder: 2,
            term_ms: 1,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 1,
        });
        let pkt = ip4(
            "100.64.0.11".parse().unwrap(),
            "100.64.0.2".parse().unwrap(),
            b"req",
        );
        let r = plane.ingest(&dev, &pkt).await;
        assert!(
            matches!(r, IngestResult::Forwarded(ForwardOutcome::Delivered)),
            "{r:?}"
        );
        let sent = t.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let (peer, env) = &sent[0];
        assert_eq!(*peer, 2, "sent to node 2 (lease holder)");
        assert_eq!(env.dst_dev, server_self_device_id(2));
        assert_eq!(env.src_dev, dev);
        assert_eq!(env.origin_server, 1);
        assert_eq!(env.hop, 1, "hop=1 (second forwarding forbidden)");
    }

    /// ingest: dst = an unregistered non-server-segment VIP ⇒ drop +
    /// best-effort ICMP (fallback mapping stays in range).
    #[tokio::test]
    async fn ingest_to_unknown_device_vip_still_icmp() {
        let (plane, dev, sess, _t) = plane_with_device().await;
        let pkt = ip4(
            "100.64.0.11".parse().unwrap(),
            "100.64.0.99".parse().unwrap(),
            b"x",
        );
        let r = plane.ingest(&dev, &pkt).await;
        assert!(matches!(r, IngestResult::DroppedIcmp), "{r:?}");
        assert_eq!(
            sess.0.lock().unwrap().len(),
            1,
            "best-effort ICMP back to the source session"
        );
    }

    /// receive: dst_dev = this server's server-self ⇒ inject into the local
    /// kernel (delivered_kernel).
    #[tokio::test]
    async fn receive_for_server_self_delivers_to_kernel() {
        let (plane, dev, _sess, _t) = plane_with_device().await;
        let kern = Arc::new(CapSink(StdMutex::new(Vec::new())));
        plane.set_local_peer("100.64.0.1".parse().unwrap(), kern.clone());
        let pkt = ip4(
            "100.64.0.11".parse().unwrap(),
            "100.64.0.1".parse().unwrap(),
            b"req",
        );
        let env = ForwardEnvelope {
            ver: FORWARD_VER,
            src_dev: dev,
            dst_dev: server_self_device_id(1),
            origin_server: 2,
            hop: 1,
            payload: pkt,
        };
        assert!(matches!(plane.receive(env), ForwardOutcome::Delivered));
        assert_eq!(
            kern.0.lock().unwrap().len(),
            1,
            "packet enters the local kernel write pump"
        );
        assert_eq!(plane.stats().delivered_kernel, 1);
    }

    /// receive: dst_dev = this server's server-self but the source binding
    /// mismatches (inner src ≠ registered VIP) ⇒ Rejected (server-self kernel
    /// injection does not relax the step-0 check).
    #[tokio::test]
    async fn receive_for_server_self_bad_src_rejected() {
        let (plane, dev, _sess, _t) = plane_with_device().await;
        let kern = Arc::new(CapSink(StdMutex::new(Vec::new())));
        plane.set_local_peer("100.64.0.1".parse().unwrap(), kern.clone());
        let pkt = ip4(
            "100.64.0.12".parse().unwrap(), // ≠ dev's registered VIP .11
            "100.64.0.1".parse().unwrap(),
            b"x",
        );
        let env = ForwardEnvelope {
            ver: FORWARD_VER,
            src_dev: dev,
            dst_dev: server_self_device_id(1),
            origin_server: 2,
            hop: 1,
            payload: pkt,
        };
        assert!(matches!(
            plane.receive(env),
            ForwardOutcome::Rejected(RejectReason::SrcBinding)
        ));
        assert!(kern.0.lock().unwrap().is_empty(), "kernel untouched");
    }

    /// route_outbound: local kernel → remote server VIP (inter-server mesh
    /// traffic surface, fallback mapping).
    #[tokio::test]
    async fn outbound_to_remote_server_vip_forwards() {
        let (plane, _dev, _sess, t) = plane_with_device().await;
        plane.leases().merge_remote(GossipMsg::Publish {
            device: server_self_device_id(2),
            holder: 2,
            term_ms: 1,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 1,
        });
        let pkt = ip4(
            "100.64.0.1".parse().unwrap(),
            "100.64.0.2".parse().unwrap(),
            b"srv",
        );
        plane.route_outbound(&pkt).await;
        let sent = t.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, 2);
        assert_eq!(sent[0].1.dst_dev, server_self_device_id(2));
        assert_eq!(
            sent[0].1.src_dev,
            server_self_device_id(1),
            "source of the server's kernel return path = the local server-self synthetic key (verifiable by the receiver)"
        );
        assert_eq!(sent[0].1.origin_server, 1);
    }

    /// receive: src_dev = the sending server's server-self (kernel return
    /// surface), dst = a local session device ⇒ source binding validated
    /// against the origin's deterministic VIP passes and delivers to the
    /// session.
    #[tokio::test]
    async fn receive_from_remote_server_kernel_delivers_to_session() {
        let (plane, dev, sess, _t) = plane_with_device().await;
        let pkt = ip4(
            "100.64.0.2".parse().unwrap(), // node 2's deterministic server VIP
            "100.64.0.11".parse().unwrap(),
            b"reply",
        );
        let env = ForwardEnvelope {
            ver: FORWARD_VER,
            src_dev: server_self_device_id(2),
            dst_dev: dev,
            origin_server: 2,
            hop: 1,
            payload: pkt,
        };
        assert!(matches!(plane.receive(env), ForwardOutcome::Delivered));
        assert_eq!(
            sess.0.lock().unwrap().len(),
            1,
            "return packet enters the client session"
        );
    }

    /// receive: server-self source but inner src ≠ that server's
    /// deterministic VIP ⇒ Rejected (the return surface does not relax the
    /// source binding).
    #[tokio::test]
    async fn receive_from_server_kernel_bad_src_rejected() {
        let (plane, dev, _sess, _t) = plane_with_device().await;
        let pkt = ip4(
            "100.64.0.3".parse().unwrap(), // ≠ node 2's .2
            "100.64.0.11".parse().unwrap(),
            b"x",
        );
        let env = ForwardEnvelope {
            ver: FORWARD_VER,
            src_dev: server_self_device_id(2),
            dst_dev: dev,
            origin_server: 2,
            hop: 1,
            payload: pkt,
        };
        assert!(matches!(
            plane.receive(env),
            ForwardOutcome::Rejected(RejectReason::SrcBinding)
        ));
    }

    /// server_vip_of / server_vip_node round trip (in-segment/out-of-segment
    /// boundary points).
    #[test]
    fn server_vip_roundtrip() {
        for n in 1u64..=10 {
            let v = crate::proto::server_vip_of(n).unwrap();
            assert_eq!(crate::proto::server_vip_node(&v), Some(n));
        }
        assert_eq!(crate::proto::server_vip_of(0), None);
        assert_eq!(crate::proto::server_vip_of(11), None);
        assert_eq!(
            crate::proto::server_vip_node(&[100, 64, 0, 11]),
            None,
            "device segment"
        );
        assert_eq!(crate::proto::server_vip_node(&[100, 64, 0, 0]), None);
        assert_eq!(
            crate::proto::server_vip_node(&[100, 64, 1, 2]),
            None,
            "third byte outside the segment"
        );
    }

    #[test]
    fn icmp_shape() {
        let orig = ip4(
            "100.64.0.2".parse().unwrap(),
            "100.64.0.9".parse().unwrap(),
            &[7u8; 32],
        );
        let icmp = icmp_host_unreachable(&orig);
        assert_eq!(icmp[20], 3, "type = destination unreachable");
        assert_eq!(icmp[21], 1, "code = host unreachable");
        // Embedded original header 28B: IP header 20 + first 8B of payload.
        assert_eq!(&icmp[28..48], &orig[..20]);
        assert_eq!(&icmp[48..56], &orig[20..28]);
        // Back to the original source: the ICMP packet's IP dst = the original
        // source .2.
        assert_eq!(icmp[16], 100);
        // Checksum non-zero (a passable "best-effort" packet).
        assert!(icmp[22] != 0 || icmp[23] != 0);
    }
}
