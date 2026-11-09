//! Gossip lease table (§3.10 `LeaseTable::{publish, observe}`; vpn-mesh §5.2).
//!
//! **The single source of truth for a device's current location = the lease
//! domain**: every server authoritatively publishes "the devices connected to
//! me", lease TTL 30s; event push ≤1s (publish broadcasts immediately) + 5s
//! anti-entropy (full-table digest; the assembly's anti-entropy loop calls
//! [`LeaseTable::anti_entropy_msg`]).
//!
//! **Conflict = newest wins + old-side session eviction**: terms are monotonic
//! (unix milliseconds + holder tie-break); when a remote lease newer than the
//! local one arrives while we hold it locally,
//! [`crate::hooks::SyncHooks::on_lease_evicted`] fires (the old server evicts
//! the device's session — the ZeroTer fast-revocation-propagation idea,
//! vpn-mesh §5.2).
//!
//! M7 (§7-M7.3): lease entries carry per-device **EWMA traffic**
//! (`tx_ewma/rx_ewma`, bytes/s, device view) and `last_seen_unix` — the
//! dynamics plane rides the lease (publish/anti-entropy synchronization, not
//! into Raft). Holder authority: only rows held locally get their EWMA folded
//! by this machine; remote rows take the holder-reported values.
//!
//! `location_query` (the one-shot cross-server location inquiry, fan-out ≤3)
//! belongs to the cross-server forwarding plane (§2.2-4), landed in the same
//! batch as ForwardEnvelope; this module first provides the local `observe`
//! (including TTL determination).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::hooks::HookRegistry;
use crate::proto::NodeId;

/// Default lease TTL (§3.10: 30s).
pub const LEASE_TTL: Duration = Duration::from_secs(30);
/// Anti-entropy period (§3.10: 5s).
pub const ANTI_ENTROPY: Duration = Duration::from_secs(5);
/// Local session lease refresh period (TTL/3 — **long-lived sessions must
/// re-publish periodically**: publish fires only once at connection setup;
/// without refresh the whole network "forgets" a still-online device after 30s
/// (exposed by the M5 e2e run — A1's 90s bulk transfer pushed A2 past the TTL
/// window and cross-server forwarding all degraded to NOT_HERE).
pub const LEASE_REFRESH: Duration = Duration::from_secs(10);
/// M7: EWMA update period (§7-M7.3 — 1s folding window; driven by the tick
/// loop assembled in node).
pub const EWMA_TICK: Duration = Duration::from_secs(1);
/// M7: EWMA α = 1/5 = 0.2 (§7-M7.3).
pub const EWMA_ALPHA_NUM: u64 = 1;
pub const EWMA_ALPHA_DEN: u64 = 5;

/// EWMA fold: `next = prev·(1−α) + rate·α` (integer arithmetic:
/// `(prev·(DEN−NUM) + rate·NUM)/DEN`).
pub fn ewma_fold(prev: u64, rate: u64) -> u64 {
    (prev.saturating_mul(EWMA_ALPHA_DEN - EWMA_ALPHA_NUM) + rate.saturating_mul(EWMA_ALPHA_NUM))
        / EWMA_ALPHA_DEN
}

/// M7 (§7-M7.3 revision): offline decay factor — rows whose TTL has expired
/// and that had no accumulation this window decay ×4/5 per window (an
/// independent constant unrelated to α: the semantics are "exponential
/// forgetting absent accumulation evidence", not a rate estimate).
pub const EWMA_OFFLINE_DECAY_NUM: u64 = 4;
pub const EWMA_OFFLINE_DECAY_DEN: u64 = 5;
/// Offline decay floor: once per-window decay drops below this rate (B/s) the
/// value is set to 0 — the roster no longer shows non-zero traffic for offline
/// devices.
pub const EWMA_OFFLINE_FLOOR_BPS: u64 = 8;

/// Offline decay single step: `v × 4/5`, set to 0 below
/// [`EWMA_OFFLINE_FLOOR_BPS`].
pub fn ewma_offline_decay(v: u64) -> u64 {
    let d = v.saturating_mul(EWMA_OFFLINE_DECAY_NUM) / EWMA_OFFLINE_DECAY_DEN;
    if d < EWMA_OFFLINE_FLOOR_BPS {
        0
    } else {
        d
    }
}

/// Synthetic device key for the server itself in the lease domain (M7: the
/// self-publish/counting anchor for roster Server entries). node_id
/// big-endian in the first 8B + a fixed marker suffix — real device ids are
/// sha256(ed25519), so the collision probability of the structured prefix is
/// negligible; each server self-publishes a lease under this key (carrying its
/// own EWMA), making the network-wide roster assemblable.
pub fn server_self_device_id(node_id: NodeId) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&node_id.to_be_bytes());
    id[8..].fill(0x5A);
    id
}

/// Anti-entropy single entry (M7: bandwidth/last_seen fields synchronized with
/// the table digest — holder-authoritative values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiEntry {
    pub device: Vec<u8>,
    pub holder: NodeId,
    pub term_ms: u64,
    pub tx_ewma: u64,
    pub rx_ewma: u64,
    pub last_seen_unix: u64,
}

/// Gossip wire message (M7: Publish/Anti both carry EWMA and last_seen).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipMsg {
    /// Single lease event push (publish broadcasts immediately, ≤1s
    /// semantics).
    Publish {
        device: [u8; 32],
        holder: NodeId,
        term_ms: u64,
        tx_ewma: u64,
        rx_ewma: u64,
        last_seen_unix: u64,
    },
    /// Full-table digest (anti-entropy; the receiver resets the TTL using its
    /// own clock).
    Anti { entries: Vec<AntiEntry> },
}

/// A single lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub holder: NodeId,
    pub term_ms: u64,
    pub expires_at: Instant,
    /// M7: device-view EWMA (bytes/s) — maintained by the holder, propagated
    /// with publish/anti-entropy.
    pub tx_ewma: u64,
    pub rx_ewma: u64,
    /// M7: last-seen moment (unix seconds; rows are retained after TTL expiry
    /// — for showing offline devices in the roster).
    pub last_seen_unix: u64,
}

/// Local lease-view statistics consumed by the roster/reaper (online
/// determination + EWMA + last_seen).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLeaseStats {
    /// Within TTL (local view of the single source of truth).
    pub online: bool,
    pub last_seen_unix: u64,
    pub tx_ewma: u64,
    pub rx_ewma: u64,
}

/// Per-device byte accumulator on this machine (EWMA folding source;
/// holder-side maintenance).
#[derive(Debug, Clone, Copy, Default)]
struct TrafficAcc {
    tx: u64,
    rx: u64,
    last_fold_ms: u64,
}

/// Local lease table.
pub struct LeaseTable {
    me: NodeId,
    ttl: Duration,
    hooks: HookRegistry,
    st: Mutex<BTreeMap<[u8; 32], Lease>>,
    /// Local measurement accumulator (M7; only rows "held locally" get folded
    /// into ewma — remote rows take the holder-reported values).
    acc: Mutex<BTreeMap<[u8; 32], TrafficAcc>>,
    /// High-water mark of seen remote terms (including rejected stale entries
    /// — any arrival raises it).
    ///
    /// Guard rail against "clock-skew wrongful eviction": a local
    /// publish/renewal takes a term of at least `floor + 1` — the local wall
    /// clock may sit behind already-seen remote terms (skew, or a remote clock
    /// running ahead); using `now` directly would let a genuinely online local
    /// device lose, in the "newest wins" comparison, against a stale remote
    /// entry it has already seen (repeatedly evicted under one-way
    /// connectivity). Residual dependency (honest disclosure): between two
    /// nodes that never exchanged terms, ordering still follows their own wall
    /// clocks — absolute clock skew can let the first arrival win temporarily;
    /// TTL expiry + anti-entropy backstop convergence.
    term_floor: AtomicU64,
    /// Count of remote gossip messages merged since creation (including empty
    /// anti-entropy digests — any arrival proves the interconnect/anti-entropy
    /// plane is alive). The signal for the reaper's "view ready" gate
    /// ([`LeaseTable::reaper_view_ready`]).
    remote_events: AtomicU64,
}

impl LeaseTable {
    /// `hooks` shares the same registry as the state machine
    /// (on_lease_evicted and on_revocation_applied share one source).
    pub fn new(me: NodeId, ttl: Duration, hooks: HookRegistry) -> Arc<Self> {
        Arc::new(LeaseTable {
            me,
            ttl,
            hooks,
            st: Mutex::new(BTreeMap::new()),
            acc: Mutex::new(BTreeMap::new()),
            term_floor: AtomicU64::new(0),
            remote_events: AtomicU64::new(0),
        })
    }

    /// The local node id.
    pub fn me(&self) -> NodeId {
        self.me
    }

    /// M7: record a unit of device traffic (called at successful
    /// forwarding-plane delivery points; holder-side maintenance — dst counting
    /// for cross-server FRWD happens at the receiving/holding end, origin does
    /// not count dst, see the note in forward.rs). Accumulates into acc and
    /// raises last_seen of locally held rows.
    pub fn note_tx(&self, device: &[u8; 32], bytes: u64) {
        self.note_traffic(device, bytes, 0);
    }

    pub fn note_rx(&self, device: &[u8; 32], bytes: u64) {
        self.note_traffic(device, 0, bytes);
    }

    fn note_traffic(&self, device: &[u8; 32], tx: u64, rx: u64) {
        {
            let mut acc = self.acc.lock().expect("lease acc");
            let e = acc.entry(*device).or_default();
            e.tx = e.tx.saturating_add(tx);
            e.rx = e.rx.saturating_add(rx);
        }
        // Locally held rows: traffic is evidence of liveness ⇒ raise
        // last_seen (remote rows untouched — holder authority).
        let now = now_unix();
        let mut st = self.st.lock().expect("lease table");
        if let Some(l) = st.get_mut(device) {
            if l.holder == self.me {
                l.last_seen_unix = l.last_seen_unix.max(now);
            }
        }
    }

    /// M7: EWMA folding (1s window; called by the tick loop assembled in
    /// node, `now_ms` injected explicitly for testability). Folds only rows
    /// held locally — remote device traffic sitting in acc (e.g. the transient
    /// before this machine acts as the FRWD receiver and hands counting over)
    /// must not overwrite the holder-published values.
    ///
    /// Offline decay (§7-M7.3 revision): rows whose TTL has expired and that
    /// have **no local accumulator** (remote rows / local rows never counted —
    /// out of reach of the folding loop below) decay ×4/5 per window and are
    /// zeroed below 8B/s — the roster no longer shows non-zero traffic for
    /// offline devices. Rows with accumulators decay naturally to 0 via the
    /// folding loop's zero-rate fold (the same ×4/5 math).
    pub fn tick_ewma(&self, now_ms_val: u64) {
        let mut acc = self.acc.lock().expect("lease acc");
        let mut st = self.st.lock().expect("lease table");
        // ① Fold: locally held + accumulated (existing logic).
        for (dev, a) in acc.iter_mut() {
            if a.last_fold_ms == 0 {
                a.last_fold_ms = now_ms_val;
                continue;
            }
            let dt = now_ms_val.saturating_sub(a.last_fold_ms);
            if dt < EWMA_TICK.as_millis() as u64 {
                continue;
            }
            let Some(l) = st.get_mut(dev) else { continue };
            if l.holder != self.me {
                // Not held locally: the accumulator waits until ownership
                // changes to be reset (publish resets acc).
                continue;
            }
            let secs = dt as f64 / 1000.0;
            let tx_rate = (a.tx as f64 / secs) as u64;
            let rx_rate = (a.rx as f64 / secs) as u64;
            l.tx_ewma = ewma_fold(l.tx_ewma, tx_rate);
            l.rx_ewma = ewma_fold(l.rx_ewma, rx_rate);
            a.tx = 0;
            a.rx = 0;
            a.last_fold_ms = now_ms_val;
        }
        // ② Offline decay: rows past TTL and out of reach of the folding loop
        //    (no acc entry).
        let now = Instant::now();
        for (dev, l) in st.iter_mut() {
            if l.expires_at > now {
                continue;
            }
            if acc.contains_key(dev) {
                continue;
            }
            l.tx_ewma = ewma_offline_decay(l.tx_ewma);
            l.rx_ewma = ewma_offline_decay(l.rx_ewma);
        }
    }

    /// Publish the local lease (newest wins). Returns the previous holder
    /// superseded locally (if any — the peer in the conflict scenario). Remote
    /// propagation is up to the caller (the node assembly) broadcasting
    /// [`GossipMsg::Publish`].
    ///
    /// The term is at least `max(seen remote terms) + 1` (max of that with the
    /// wall clock): local clock skew (running behind already-seen remote
    /// entries) must not let a genuinely online local device lose the "newest
    /// wins" race at renewal (see `term_floor`). M7: ewma is **inherited**
    /// from the existing row (renewal does not reset the traffic view); when
    /// taking over another machine's row (or publishing fresh), the local acc
    /// is reset — the old accumulator was the old holder's measurement and
    /// does not count.
    ///
    /// Lock discipline: st and acc are never nested here (tick_ewma nests in
    /// acc→st order — this function releases st before touching acc; the tick
    /// is the only nesting site in the table, no reverse order).
    pub fn publish(&self, device: &[u8; 32]) -> Option<NodeId> {
        let floor = self.term_floor.load(Ordering::SeqCst);
        let term = now_ms().max(floor.saturating_add(1));
        let prev = {
            let mut st = self.st.lock().expect("lease table");
            let prev = st.get(device).copied();
            st.insert(
                *device,
                Lease {
                    holder: self.me,
                    term_ms: term,
                    expires_at: Instant::now() + self.ttl,
                    tx_ewma: prev.map(|p| p.tx_ewma).unwrap_or(0),
                    rx_ewma: prev.map(|p| p.rx_ewma).unwrap_or(0),
                    last_seen_unix: now_unix(),
                },
            );
            prev
        };
        if prev.is_none_or(|p| p.holder != self.me) {
            self.acc.lock().expect("lease acc").remove(device);
        }
        prev.filter(|p| p.holder != self.me).map(|p| p.holder)
    }

    /// A remote publish/anti-entropy entry arrived: merge (newest wins); a
    /// locally held lease superseded by a newer one ⇒ fire the eviction hooks
    /// (old side evicts the session).
    ///
    /// Every arrival (including empty anti-entropy digests) counts toward
    /// `remote_events` — proof that "the interconnect/anti-entropy plane is
    /// alive", by which the reaper gate decides whether the post-restart
    /// lease view is ready (§7-M7.5).
    pub fn merge_remote(&self, msg: GossipMsg) {
        self.remote_events.fetch_add(1, Ordering::SeqCst);
        let entries: Vec<AntiEntry> = match msg {
            GossipMsg::Publish {
                device,
                holder,
                term_ms,
                tx_ewma,
                rx_ewma,
                last_seen_unix,
            } => vec![AntiEntry {
                device: device.to_vec(),
                holder,
                term_ms,
                tx_ewma,
                rx_ewma,
                last_seen_unix,
            }],
            GossipMsg::Anti { entries } => entries,
        };
        let mut evicted = Vec::new();
        {
            let mut st = self.st.lock().expect("lease table");
            for e in entries {
                let Ok(device) = <[u8; 32]>::try_from(e.device) else {
                    continue;
                };
                let AntiEntry {
                    holder,
                    term_ms: term,
                    tx_ewma,
                    rx_ewma,
                    last_seen_unix,
                    ..
                } = e;
                // Every arriving remote term (including rejected stale
                // entries) raises the local floor: the next local publish
                // takes at least term+1 (clock-skew guard rail, see
                // `term_floor`).
                self.term_floor.fetch_max(term, Ordering::SeqCst);
                let newer = match st.get(&device) {
                    Some(cur) => (term, holder) > (cur.term_ms, cur.holder),
                    None => true,
                };
                if newer {
                    // Held locally and superseded by a newer remote ⇒ old
                    // side evicts (newest wins).
                    if let Some(cur) = st.get(&device) {
                        if cur.holder == self.me && holder != self.me {
                            evicted.push(device);
                        }
                    }
                    st.insert(
                        device,
                        Lease {
                            holder,
                            term_ms: term,
                            expires_at: Instant::now() + self.ttl,
                            tx_ewma,
                            rx_ewma,
                            last_seen_unix,
                        },
                    );
                }
            }
        }
        for d in evicted {
            self.hooks.fire_lease_evict(&d);
        }
    }

    /// Query a device's current holder (TTL expired ⇒ None; the local view of
    /// "the lease domain is the single source of truth for device current
    /// location"). M7: expired rows are **retained** (no longer deleted) —
    /// last_seen/EWMA serve the roster's offline-device display;
    /// `live_len`/anti-entropy still filter by TTL.
    pub fn observe(&self, device: &[u8; 32]) -> Option<Lease> {
        let st = self.st.lock().expect("lease table");
        match st.get(device).copied() {
            Some(l) if l.expires_at > Instant::now() => Some(l),
            _ => None,
        }
    }

    /// M7: roster/reaper view (online determination + last_seen + EWMA; never
    /// seen a lease ⇒ None).
    pub fn peer_stats(&self, device: &[u8; 32]) -> Option<PeerLeaseStats> {
        let st = self.st.lock().expect("lease table");
        st.get(device).map(|l| PeerLeaseStats {
            online: l.expires_at > Instant::now(),
            last_seen_unix: l.last_seen_unix,
            tx_ewma: l.tx_ewma,
            rx_ewma: l.rx_ewma,
        })
    }

    /// One-shot cross-server location inquiry (§3.10 `location_query`:
    /// fan-out ≤3, no caching, no retries — failure is just a dropped packet +
    /// ICMP, recovery is up to the upper layer). Answer from a local lease
    /// domain hit (single source of truth); otherwise ask via [`LocateFanout`]
    /// the interconnected servers "who is hosting this device" and take the
    /// first positive answer.
    pub async fn location_query(
        &self,
        device: &[u8; 32],
        fanout: &dyn LocateFanout,
    ) -> Option<NodeId> {
        if let Some(l) = self.observe(device) {
            return Some(l.holder);
        }
        fanout.locate(device).await
    }

    /// Number of non-expired lease entries (diagnostics/assertion surface:
    /// whether gossip propagation works).
    pub fn live_len(&self) -> usize {
        let st = self.st.lock().expect("lease table");
        st.iter()
            .filter(|(_, l)| l.expires_at > Instant::now())
            .count()
    }

    /// Total rows in the table (**including TTL-expired retained rows** — M7
    /// keeps expired rows for the roster's offline display).
    pub fn total_rows(&self) -> usize {
        self.st.lock().expect("lease table").len()
    }

    /// Count of remote gossip messages merged since creation (including empty
    /// digests).
    pub fn remote_events(&self) -> u64 {
        self.remote_events.load(Ordering::SeqCst)
    }

    /// M7 reaper "view ready" gate (§7-M7.5, **minimal reliable form**):
    /// table non-empty **and** at least one remote gossip received since
    /// start ⇒ the local lease view is sufficient to support reaping
    /// decisions.
    ///
    /// Semantic trade-offs (noted honestly):
    /// - On a freshly restarted node the lease table is empty, and until the
    ///   first remote event arrives (peer anti-entropy digest within ≤1
    ///   period of 5s, or this machine's first device-connection publish), the
    ///   view cannot be judged ⇒ reaping is skipped — closing the
    ///   "anti-entropy backfill races the reaper's first tick" window (in that
    ///   window the lease row of a remotely hosted device is missing,
    ///   `last_seen=0` would anchor to `registered_at`, and a long-registered
    ///   online device could be wrongly finalized).
    /// - Residual 1: after the gate opens, the first tick can still precede
    ///   peer digest backfill (≤1 anti-entropy period) — backstopped jointly
    ///   by the 60s reaping period ≫ 5s and "only truly offline devices exceed
    ///   the anchor window"; the primary fix is the registered_at anchor; this
    ///   gate is defense in depth.
    /// - Residual 2: a single-node raft cluster (no peers) never sees remote
    ///   events ⇒ the gate stays closed and the retention period never
    ///   applies — that shape is not on the deployment surface (§6.2 ≥2
    ///   servers); to enable it, accept this residue or add a 2nd server.
    pub fn reaper_view_ready(&self) -> bool {
        self.total_rows() > 0 && self.remote_events() > 0
    }

    /// Full-table digest (anti-entropy message body).
    pub fn anti_entropy_msg(&self) -> GossipMsg {
        let st = self.st.lock().expect("lease table");
        GossipMsg::Anti {
            entries: st
                .iter()
                .filter(|(_, l)| l.expires_at > Instant::now())
                .map(|(d, l)| AntiEntry {
                    device: d.to_vec(),
                    holder: l.holder,
                    term_ms: l.term_ms,
                    tx_ewma: l.tx_ewma,
                    rx_ewma: l.rx_ewma,
                    last_seen_unix: l.last_seen_unix,
                })
                .collect(),
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Location-inquiry fan-out seam (the node assembly injects the wire
/// implementation: WireRpc::Locate, to at most 3 interconnected servers).
pub trait LocateFanout: Send + Sync + 'static {
    fn locate(&self, device: &[u8; 32]) -> BoxFuture<'static, Option<NodeId>>;
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ============================================================================
// TrafficMeter: standalone traffic meter for the single-server shape (same
// EWMA math, no gossip; §7-M7.3)
// ============================================================================

/// Per-key EWMA + last_seen meter for arbitrary keys (device VIP bytes / the
/// server's own key). In the single-server shape (no lease table) it is fed by
/// `PeerRouter` counting both directions; the multi-primary shape uses
/// `LeaseTable`.
pub struct TrafficMeter {
    st: Mutex<std::collections::HashMap<Vec<u8>, MeterEntry>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct MeterEntry {
    tx_acc: u64,
    rx_acc: u64,
    last_fold_ms: u64,
    tx_ewma: u64,
    rx_ewma: u64,
    last_seen_unix: u64,
}

impl TrafficMeter {
    pub fn new() -> Arc<Self> {
        Arc::new(TrafficMeter {
            st: Mutex::new(std::collections::HashMap::new()),
        })
    }

    pub fn note_tx(&self, key: &[u8], bytes: u64) {
        self.note(key, bytes, 0);
    }

    pub fn note_rx(&self, key: &[u8], bytes: u64) {
        self.note(key, 0, bytes);
    }

    fn note(&self, key: &[u8], tx: u64, rx: u64) {
        let now = now_unix();
        let mut st = self.st.lock().expect("traffic meter");
        let e = st.entry(key.to_vec()).or_default();
        e.tx_acc = e.tx_acc.saturating_add(tx);
        e.rx_acc = e.rx_acc.saturating_add(rx);
        e.last_seen_unix = e.last_seen_unix.max(now);
    }

    /// 1s-window folding (`now_ms` injected explicitly for testability).
    pub fn tick(&self, now_ms_val: u64) {
        let mut st = self.st.lock().expect("traffic meter");
        for e in st.values_mut() {
            if e.last_fold_ms == 0 {
                e.last_fold_ms = now_ms_val;
                continue;
            }
            let dt = now_ms_val.saturating_sub(e.last_fold_ms);
            if dt < EWMA_TICK.as_millis() as u64 {
                continue;
            }
            let secs = dt as f64 / 1000.0;
            e.tx_ewma = ewma_fold(e.tx_ewma, (e.tx_acc as f64 / secs) as u64);
            e.rx_ewma = ewma_fold(e.rx_ewma, (e.rx_acc as f64 / secs) as u64);
            e.tx_acc = 0;
            e.rx_acc = 0;
            e.last_fold_ms = now_ms_val;
        }
    }

    /// Roster view (no entry ⇒ None — never saw any traffic).
    pub fn stats(&self, key: &[u8]) -> Option<(u64, u64, u64)> {
        let st = self.st.lock().expect("traffic meter");
        st.get(key)
            .map(|e| (e.tx_ewma, e.rx_ewma, e.last_seen_unix))
    }

    /// Whether there has been any observation at all (empty table = no traffic
    /// counted since creation — used by the single-server reaper's restart
    /// gate, §7-M7.5: TrafficMeter is purely in-memory and resets on restart;
    /// empty table with a non-empty registry ⇒ just restarted).
    pub fn has_any(&self) -> bool {
        !self.st.lock().expect("traffic meter").is_empty()
    }
}

impl Default for TrafficMeter {
    fn default() -> Self {
        TrafficMeter {
            st: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

// ============================================================================
// Unit tests: newest wins + old-side eviction callback + TTL
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::HookRecorder;

    fn table(me: NodeId) -> Arc<LeaseTable> {
        LeaseTable::new(me, Duration::from_secs(30), HookRegistry::new())
    }

    fn table_with_hooks(me: NodeId, rec: Arc<HookRecorder>) -> Arc<LeaseTable> {
        let hooks = HookRegistry::new();
        hooks.add(rec);
        LeaseTable::new(me, Duration::from_secs(30), hooks)
    }

    #[test]
    fn newer_wins_and_old_side_evicted() {
        let rec = HookRecorder::new();
        let t1 = table_with_hooks(1, rec.clone());
        t1.publish(&[7; 32]);
        assert_eq!(t1.observe(&[7; 32]).unwrap().holder, 1);
        // Node 2's newer lease arrives at node 1 ⇒ newest wins + node 1's
        // eviction callback.
        t1.merge_remote(GossipMsg::Publish {
            device: [7; 32],
            holder: 2,
            term_ms: now_ms() + 50,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
        assert_eq!(t1.observe(&[7; 32]).unwrap().holder, 2, "newest wins");
        assert_eq!(
            rec.evictions(),
            vec![[7u8; 32]],
            "old-side eviction callback fired"
        );
        // A stale term arriving again ⇒ no rollback.
        t1.merge_remote(GossipMsg::Publish {
            device: [7; 32],
            holder: 1,
            term_ms: 1,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
        assert_eq!(
            t1.observe(&[7; 32]).unwrap().holder,
            2,
            "the older entry does not override"
        );
    }

    /// Refresh-period gate: LEASE_REFRESH must be well within the TTL (no
    /// expiry inside two refresh windows — the regression surface of the
    /// "long-lived session lease evaporation" exposed by M5 e2e).
    #[test]
    fn refresh_period_is_well_within_ttl() {
        assert!(
            LEASE_REFRESH + LEASE_REFRESH < LEASE_TTL,
            "two refresh periods must both fit within the TTL (survive one missed renewal — 10s refresh × 30s TTL)"
        );
    }

    #[test]
    fn ttl_expiry_and_anti_entropy() {
        let rec = HookRecorder::new();
        let t1 = table_with_hooks(1, rec.clone());
        let t2 = table(2);
        t1.publish(&[1; 32]);
        t1.publish(&[2; 32]);
        // Anti-entropy: t1's full table → t2.
        let msg = t1.anti_entropy_msg();
        t2.merge_remote(msg);
        assert_eq!(t2.observe(&[1; 32]).unwrap().holder, 1);
        assert_eq!(t2.observe(&[2; 32]).unwrap().holder, 1);
        // TTL expiry ⇒ observe None (short-TTL table).
        let t3 = LeaseTable::new(3, Duration::from_millis(20), HookRegistry::new());
        t3.publish(&[9; 32]);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(t3.observe(&[9; 32]), None, "invalid once TTL expires");
    }

    /// Clock-skew guard rail: when the local wall clock runs behind an
    /// already-seen remote term (remote clock 5s ahead + one-way
    /// connectivity — the local side can receive from the remote), a local
    /// renewal term still surpasses the seen remote term ⇒ the "newest wins"
    /// ordering is not inverted and the locally online device is not wrongly
    /// evicted.
    #[test]
    fn republish_beats_seen_remote_term_despite_clock_skew() {
        let t1 = table_with_hooks(1, HookRecorder::new());
        let t2 = table_with_hooks(2, HookRecorder::new());
        let dev = [0x5e; 32];
        // Node 1 holds first (local clock normal).
        t1.publish(&dev);
        let t1_term = t1.observe(&dev).unwrap().term_ms;
        // Node 2 sees node 1's lease (raising its floor), then the device
        // moves to node 2 — but node 2's wall clock lags (simulated: a remote
        // entry whose term is 5s ahead of local now arrives).
        let skewed_remote = now_ms() + 5_000;
        t2.merge_remote(GossipMsg::Publish {
            device: dev,
            holder: 3,
            term_ms: skewed_remote,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
        assert_eq!(
            t2.observe(&dev).unwrap().holder,
            3,
            "the ahead-of-time remote entry enters the table first"
        );
        // Node 2 renews locally (the device is genuinely on node 2): term ≥
        // skewed_remote+1 (past the seen remote term).
        t2.publish(&dev);
        let l2 = t2.observe(&dev).unwrap();
        assert_eq!(l2.holder, 2);
        assert!(
            l2.term_ms > skewed_remote,
            "local renewal term surpasses the seen remote term (no loss of newest-wins to clock lag)"
        );
        assert!(l2.term_ms > t1_term);
        // That renewal arrives at node 1 ⇒ newest wins + old side (node 3's
        // view, which to node 1 is simply overwritten) + eviction hook.
        t1.merge_remote(GossipMsg::Publish {
            device: dev,
            holder: 2,
            term_ms: l2.term_ms,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
        assert_eq!(
            t1.observe(&dev).unwrap().holder,
            2,
            "newest wins after renewal propagates"
        );
    }

    // ------------------------------------------------------------------
    // M7 (§7-M7.3): EWMA convergence / gossip bandwidth-field round trip /
    // last_seen maintenance
    // ------------------------------------------------------------------

    /// EWMA convergence: feed a constant rate (1000B per second) + 1s folding
    /// ⇒ ewma approaches 1000 (α=0.2: after 20 folds the residual ≈
    /// 1000·0.8²⁰ ≈ 1.2%, a 5% tolerance is ample); monotone non-decreasing
    /// along the way.
    #[test]
    fn ewma_converges_under_constant_rate() {
        let t = table(1);
        let dev = [0x11; 32];
        t.publish(&dev);
        let mut ms = 1_000_000u64;
        let mut prev_ewma = 0u64;
        for _ in 0..20 {
            t.note_tx(&dev, 1000);
            ms += 1000;
            t.tick_ewma(ms);
            let ewma = t.peer_stats(&dev).unwrap().tx_ewma;
            assert!(
                ewma >= prev_ewma,
                "folding monotone non-decreasing under a constant rate ({prev_ewma}→{ewma})"
            );
            prev_ewma = ewma;
        }
        let stats = t.peer_stats(&dev).unwrap();
        assert!(
            (stats.tx_ewma as i64 - 1000).abs() <= 50,
            "after 20 folds ewma converges to 1000±5%: {}",
            stats.tx_ewma
        );
        assert_eq!(stats.rx_ewma, 0, "rx never fed ⇒ 0");
        assert!(stats.online, "just published ⇒ online");
    }

    /// Gossip bandwidth-field round trip: the ewma/last_seen folded by the
    /// holder reach a remote node via both the Publish and anti-entropy paths
    /// — wire format (postcard) round trip + peer_stats values identical.
    #[test]
    fn gossip_carries_bandwidth_fields_roundtrip() {
        let t1 = table(1);
        let t2 = table(2);
        let dev = [0x22; 32];
        t1.publish(&dev);
        // Feed 2 seconds of constant rate and fold.
        let mut ms = 5_000_000u64;
        for _ in 0..10 {
            t1.note_tx(&dev, 500);
            t1.note_rx(&dev, 300);
            ms += 1000;
            t1.tick_ewma(ms);
        }
        let s1 = t1.peer_stats(&dev).unwrap();
        assert!(
            s1.tx_ewma > 0 && s1.rx_ewma > 0,
            "holder-side ewma non-zero"
        );

        // Publish path: wire-format round trip (postcard encode/decode), then
        // merge into t2.
        let l = t1.observe(&dev).unwrap();
        let msg = GossipMsg::Publish {
            device: dev,
            holder: 1,
            term_ms: l.term_ms,
            tx_ewma: s1.tx_ewma,
            rx_ewma: s1.rx_ewma,
            last_seen_unix: s1.last_seen_unix,
        };
        let wire = postcard::to_allocvec(&msg).expect("encode");
        let msg: GossipMsg = postcard::from_bytes(&wire).expect("decode");
        t2.merge_remote(msg);
        let s2 = t2.peer_stats(&dev).unwrap();
        assert_eq!(
            (s2.tx_ewma, s2.rx_ewma, s2.last_seen_unix),
            (s1.tx_ewma, s1.rx_ewma, s1.last_seen_unix),
            "bandwidth fields agree over the Publish path"
        );
        assert_eq!(t2.observe(&dev).unwrap().holder, 1);

        // Anti-entropy path: full-table digest (AntiEntry wire format) → a
        // third node.
        let t3 = table(3);
        let anti = t1.anti_entropy_msg();
        let wire = postcard::to_allocvec(&anti).expect("encode");
        let anti: GossipMsg = postcard::from_bytes(&wire).expect("decode");
        t3.merge_remote(anti);
        let s3 = t3.peer_stats(&dev).unwrap();
        assert_eq!(
            (s3.tx_ewma, s3.rx_ewma),
            (s1.tx_ewma, s1.rx_ewma),
            "anti-entropy path agrees"
        );
        assert!(
            s3.online,
            "the TTL of entries carried by anti-entropy is reset by the receiver ⇒ online"
        );
    }

    /// last_seen maintenance: traffic counting raises the holder row's
    /// last_seen; after TTL expiry the row is retained (observe None but
    /// peer_stats still reports last_seen/ewma — the roster's offline-device
    /// display surface).
    #[test]
    fn last_seen_bumped_by_traffic_and_retained_after_expiry() {
        // Short-TTL table (40ms) to observe expiry retention.
        let t = LeaseTable::new(9, Duration::from_millis(40), HookRegistry::new());
        let dev = [0x33; 32];
        t.publish(&dev);
        t.note_tx(&dev, 100);
        let before = t.peer_stats(&dev).unwrap().last_seen_unix;
        assert!(before > 0, "publish/note already set last_seen");
        // Expired: observe ⇒ None (online determination withdrawn), row
        // retained ⇒ peer_stats still there.
        std::thread::sleep(Duration::from_millis(80));
        assert!(t.observe(&dev).is_none(), "TTL expired ⇒ observe None");
        let s = t
            .peer_stats(&dev)
            .expect("row retained (M7: expiry does not delete — roster last_seen)");
        assert!(!s.online);
        assert_eq!(s.last_seen_unix, before);
        // Anti-entropy/online counts no longer include the expired row.
        let anti = t.anti_entropy_msg();
        let GossipMsg::Anti { entries } = anti else {
            panic!()
        };
        assert!(
            entries.is_empty(),
            "expired rows do not enter the anti-entropy digest"
        );
    }

    /// M7 (§7-M7.3 revision): offline decay after TTL expiry — **remote rows**
    /// (no local accumulator, out of reach of the folding loop) decay ×4/5 per
    /// window and are zeroed below 8B/s (the roster no longer shows non-zero
    /// traffic for offline devices); convergence is monotone non-increasing
    /// and reaches 0 within a bounded number of windows. Local accumulated
    /// rows decay via the zero-rate fold (same math).
    #[test]
    fn offline_ewma_decays_to_zero_after_ttl() {
        // Remote row: a remote publish carrying non-zero ewma → TTL expired
        // (short table 40ms) → no acc ⇒ decay branch.
        let t = LeaseTable::new(1, Duration::from_millis(40), HookRegistry::new());
        let remote = [0x55; 32];
        t.merge_remote(GossipMsg::Publish {
            device: remote,
            holder: 2,
            term_ms: now_ms() + 100,
            tx_ewma: 5_000,
            rx_ewma: 0,
            last_seen_unix: 100,
        });
        assert_eq!(t.peer_stats(&remote).unwrap().tx_ewma, 5_000);
        std::thread::sleep(Duration::from_millis(60)); // TTL expired (observe None, row retained)
        assert!(t.observe(&remote).is_none());
        let mut ms = 8_000_000u64;
        let mut rounds = 0u32;
        let mut prev = t.peer_stats(&remote).unwrap().tx_ewma;
        while t.peer_stats(&remote).unwrap().tx_ewma > 0 {
            ms += 1000;
            t.tick_ewma(ms);
            rounds += 1;
            let cur = t.peer_stats(&remote).unwrap().tx_ewma;
            assert!(cur <= prev, "decay monotone non-increasing ({prev}→{cur})");
            prev = cur;
            assert!(
                rounds < 100,
                "converges to 0 within a bounded window ({} rounds, now {})",
                rounds,
                cur
            );
        }
        assert_eq!(t.peer_stats(&remote).unwrap().rx_ewma, 0);

        // Locally held + accumulated row: after going offline it decays via
        // the zero-rate fold (same ×4/5 math) — first converge to non-zero
        // while online, then go to 0 after traffic stops and TTL expires.
        let t2 = LeaseTable::new(9, Duration::from_millis(40), HookRegistry::new());
        let local = [0x66; 32];
        t2.publish(&local);
        let mut ms2 = 9_000_000u64;
        for _ in 0..15 {
            t2.note_tx(&local, 1000);
            ms2 += 1000;
            t2.tick_ewma(ms2);
        }
        assert!(
            t2.peer_stats(&local).unwrap().tx_ewma > 100,
            "converges to non-zero while online ({})",
            t2.peer_stats(&local).unwrap().tx_ewma
        );
        std::thread::sleep(Duration::from_millis(60));
        let mut rounds = 0u32;
        while t2.peer_stats(&local).unwrap().tx_ewma > 0 {
            ms2 += 1000;
            t2.tick_ewma(ms2);
            rounds += 1;
            assert!(
                rounds < 100,
                "local row converges to 0 within a bounded window"
            );
        }
    }

    /// The server's own synthetic key: different node_ids do not collide, and
    /// it is structurally distinguishable from real device ids (sha256).
    #[test]
    fn server_self_device_id_distinct() {
        let a = server_self_device_id(1);
        let b = server_self_device_id(2);
        assert_ne!(a, b);
        assert_eq!(a, server_self_device_id(1));
        assert_eq!(&a[..8], &1u64.to_be_bytes());
        assert!(a[8..].iter().all(|&x| x == 0x5A), "fixed marker suffix");
    }

    /// TrafficMeter (single-server shape): constant-rate convergence +
    /// last_seen raised + stats key isolation.
    #[test]
    fn traffic_meter_converges_and_keys_isolated() {
        let m = TrafficMeter::new();
        let k1 = [100u8, 64, 0, 2];
        let k2 = [100u8, 64, 0, 3];
        let mut ms = 2_000_000u64;
        for _ in 0..15 {
            m.note_tx(&k1, 2000);
            ms += 1000;
            m.tick(ms);
        }
        m.note_rx(&k2, 777);
        let (tx1, rx1, ls1) = m.stats(&k1).expect("k1 has an entry");
        assert!((tx1 as i64 - 2000).abs() <= 100, "k1 tx converges: {tx1}");
        assert_eq!(rx1, 0);
        assert!(ls1 > 0);
        let (tx2, rx2, _) = m.stats(&k2).expect("k2 has an entry");
        assert_eq!((tx2, rx2), (0, 0), "k2 not folded yet (fed after the tick)");
        assert!(m.stats(&[9, 9, 9, 9]).is_none(), "unknown key ⇒ None");
    }
}
