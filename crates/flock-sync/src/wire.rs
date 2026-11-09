//! Server-server profile E2E session transport (§3.10 seam / §4-2
//! interconnect authentication) + RPC dispatch + apply-lag breaker monitoring
//! (§4 reads and caching).
//!
//! **Interconnect authentication**: server interconnects (Raft/gossip) run
//! the server-server profile of the flock-protocol session protocol — mutual
//! enrollment credentials:
//! - Initiating side `session::initiate`: uses this machine's
//!   identity/static keys as the "device" material; the peer ServerPin comes
//!   from the root-signed ClusterDirectory (I1's KEM is sealed to the peer's
//!   static hybrid public key; R1's identity signature is verified against
//!   the root-signed entry);
//! - Answering side `session::respond` + [`PeerDirectory`]: only accepts
//!   server identities inside the root-signed ClusterDirectory (a
//!   three-way directory lookup miss ⇒ the same opaque `DeviceRejected`).
//!   ⇒ **peers without valid enrollment credentials are rejected right at
//!   the handshake layer** (they can neither fetch snapshots nor enter Raft,
//!   the R19 red line).
//!
//! **RPC frame protocol**: inside one interconnect session (Tunnel), each RPC
//! opens one yamux stream; frame = `[u32 LE length] postcard(WireRpc)`, and
//! the response is isomorphic. Long-lived sessions are cached and reused by
//! [`Interconnect`] (rebuilt on stream break).
//!
//! **apply-lag breaker**: the dispatcher observes `leader_commit` when
//! receiving AppendEntries (openraft carries the leader's global commit
//! point) and, combined with the local SM's applied index, opens
//! [`LagMonitor::breaker_open`] once the lag exceeds the threshold (2s = the
//! A6 timing budget) — the local cache path is disabled, degrading to
//! linearizable reads (§4/R24). Full partition (observation stream gone) is
//! covered by the "heartbeat silence" dimension: no frame observed for more
//! than max(lag_threshold, election_timeout) likewise opens the breaker (see
//! the `LagMonitor` docs).

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use flock_protocol::mux::{Prio, Stream as MuxStream};
use flock_protocol::session::{
    self, ClusterId, DeviceDirectory, DeviceId, DeviceRecord, DeviceStaticKeys, LookupVerdict,
    ServerEntry, ServerIdentity, ServerPin,
};
use flock_protocol::trust::ClusterDirectory;
use futures::future::BoxFuture;
use openraft::error::{RPCError, RaftError, RemoteError, Timeout, Unreachable};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::{BasicNode, Raft};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::lease::{GossipMsg, LeaseTable};
use crate::proto::{NodeId, ReadQuery, ReadView, SyncError, SyncRequest};
use crate::raft_types::SyncConfig;
use crate::sm::SmCore;

/// Frame size cap (default snapshot chunk 512KiB + headroom).
const MAX_FRAME: usize = 8 * 1024 * 1024;

// ============================================================================
// Seam: raw IO fabric (in-memory duplex / TCP — the latter wired in by the
// server assembly batch)
// ============================================================================

/// Bidirectional async stream object type.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncReadWrite for T {}
/// Boxed peer IO.
pub type PeerIo = Box<dyn AsyncReadWrite + Unpin>;

/// Raw transport fabric seam: `dial` dials a peer, `accept` receives inbound
/// connections (production = TCP listener; tests = in-memory duplex pairs,
/// with RTT/failure injection layered on top).
pub trait Fabric: Send + Sync + 'static {
    fn dial(
        &self,
        target: &flock_protocol::session::ServerId,
    ) -> BoxFuture<'static, io::Result<PeerIo>>;
    fn accept(&self) -> BoxFuture<'static, io::Result<PeerIo>>;
}

/// NodeId(u64) ↔ ServerId([u8;16]) mapping (carried in the first 8B
/// big-endian, low bytes zero-padded — a one-to-one correspondence inside
/// the directory).
pub fn sid_of(node: NodeId) -> flock_protocol::session::ServerId {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&node.to_be_bytes());
    flock_protocol::session::ServerId(b)
}

// ============================================================================
// apply-lag breaker monitoring (§4 reads and caching / R24)
// ============================================================================

/// Follower-side apply lag monitoring — two dimensions; either one triggering
/// opens the breaker (disable the local cache, degrade to linearizable
/// reads):
///
/// 1. **apply-lag**: the gap between the leader commit index carried by
///    heartbeats/AppendEntries and the local applied index persistently
///    exceeds `threshold` (A6 timing budget 2s);
/// 2. **heartbeat silence**: no AppendEntries/heartbeat frame observed for
///    more than `max(threshold, election_timeout)`. Under a full partition
///    `leader_commit` freezes equal to the local applied — "not lagging" is a
///    blind spot (the leader may have committed a revocation this machine
///    cannot see); the observation stream itself disappearing is the reliable
///    signal. For a node never observed (offline since joining / a isolated
///    former leader), the clock starts at monitor construction.
///
/// Cost disclosure of the silence dimension: a stable leader receives no
/// AppendEntries, so its own breaker stays open due to silence — semantically
/// safe (the degraded path = the leader's local `ensure_linearizable`,
/// results consistent with the cache), the cost being that the leader-side
/// cache never engages (R18's storm absorption is carried by followers). When
/// the first frame after partition recovery observes `leader_commit >
/// applied`, the pending window's start point is backdated to the start of
/// the silence (already past the window at recovery, breaker opens
/// immediately, no fresh timing).
pub struct LagMonitor {
    threshold: Duration,
    /// Silence limit = max(threshold, election_timeout).
    silence_limit: Duration,
    applied: Arc<AtomicU64>,
    st: Mutex<MonitorSt>,
}

struct MonitorSt {
    leader_commit: u64,
    pending_since: Option<Instant>,
    /// The last time an AppendEntries/heartbeat observation was received
    /// (counted from construction time).
    last_obs: Instant,
    open: bool,
}

impl LagMonitor {
    /// `applied` = the highest applied index maintained by the SM (`SmCore`);
    /// `election_timeout` = this machine's election-timeout upper bound (the
    /// second dimension of the silence determination — below it means still
    /// inside the election window, not evidence of disconnection).
    pub fn new(
        threshold: Duration,
        election_timeout: Duration,
        applied: Arc<AtomicU64>,
    ) -> Arc<Self> {
        Arc::new(LagMonitor {
            threshold,
            silence_limit: threshold.max(election_timeout),
            applied,
            st: Mutex::new(MonitorSt {
                leader_commit: 0,
                pending_since: None,
                last_obs: Instant::now(),
                open: false,
            }),
        })
    }

    /// The dispatcher observes the leader commit index (carried by
    /// AppendEntries).
    pub fn observe_leader_commit(&self, idx: u64) {
        let mut st = self.st.lock().expect("lag monitor");
        let prev_obs = st.last_obs;
        st.last_obs = Instant::now();
        if idx > st.leader_commit {
            st.leader_commit = idx;
        }
        let applied = self.applied.load(Ordering::SeqCst);
        // Backdating: when lag is observed, the pending window's start point
        // is no later than the previous frame's observation time (the start
        // of the silence) — lag accumulated during the partition is treated
        // as already past the window on recovery's first frame.
        if st.leader_commit > applied {
            st.pending_since = Some(st.pending_since.unwrap_or(prev_obs).min(prev_obs));
        }
        self.recompute(&mut st);
    }

    /// Whether the breaker is open (lazily evaluates the time window).
    pub fn breaker_open(&self) -> bool {
        let mut st = self.st.lock().expect("lag monitor");
        self.recompute(&mut st);
        st.open
    }

    /// The observed leader commit index (diagnostics/assertions).
    pub fn leader_commit(&self) -> u64 {
        self.st.lock().expect("lag monitor").leader_commit
    }

    fn recompute(&self, st: &mut MonitorSt) {
        // Dimension two: heartbeat silence — a full partition (observation
        // stream gone) opens the breaker. No pending window opens during
        // silence (nothing to compare); the backdating on recovery's first
        // frame is done by observe_leader_commit.
        if st.last_obs.elapsed() > self.silence_limit {
            st.open = true;
            return;
        }
        // Dimension one: apply-lag.
        let applied = self.applied.load(Ordering::SeqCst);
        if st.leader_commit > applied {
            match st.pending_since {
                None => {
                    st.pending_since = Some(Instant::now());
                    st.open = false;
                }
                Some(since) => {
                    if since.elapsed() > self.threshold {
                        st.open = true;
                    }
                }
            }
        } else {
            st.pending_since = None;
            st.open = false;
        }
    }
}

// ============================================================================
// Server-server profile: directory and interconnect
// ============================================================================

/// Answer-side directory: only accepts server identities inside the
/// root-signed ClusterDirectory (the other half of enrollment-credential
/// authentication).
#[derive(Clone)]
pub struct PeerDirectory {
    entries: Arc<std::sync::RwLock<BTreeMap<NodeId, ServerEntry>>>,
}

impl PeerDirectory {
    pub fn new(entries: Arc<std::sync::RwLock<BTreeMap<NodeId, ServerEntry>>>) -> Self {
        PeerDirectory { entries }
    }
}

impl DeviceDirectory for PeerDirectory {
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict> {
        for e in self.entries.read().expect("peer dir").values() {
            if DeviceId::from_ed25519(&e.identity_pub) == *id {
                let rec = DeviceRecord {
                    device_x25519: *e.static_hybrid_pub.x25519_public(),
                    device_ed25519: e.identity_pub,
                };
                return Box::pin(async move { LookupVerdict::Active(rec) });
            }
        }
        // Not found ⇒ NotFound (respond funnels it into the same opaque
        // DeviceRejected — no credentials, no entry).
        Box::pin(async move { LookupVerdict::NotFound })
    }
}

/// Interconnect manager: caches E2E sessions to each peer (`session::Tunnel`
/// stored directly — the old empty `Pipe` wrapper was removed), opens a
/// stream per RPC; the answer-side `serve_loop` receives sessions/streams.
pub struct Interconnect {
    ident: Arc<ServerIdentity>,
    /// This machine's "device" material as initiator = identity Ed25519 +
    /// static hybrid X25519 (same source as the enrollment credential).
    self_keys: DeviceStaticKeys,
    cluster_id: ClusterId,
    root_pub: VerifyingKey,
    nodes: Arc<std::sync::RwLock<BTreeMap<NodeId, ServerEntry>>>,
    fabric: Arc<dyn Fabric>,
    pipes: tokio::sync::Mutex<BTreeMap<NodeId, Arc<session::Tunnel>>>,
    /// Per-peer RPC gate (at most one in-flight RPC per interconnect session
    /// — the mux drives a single pending stream-open and yamux ACK backlog
    /// is per-stream; after serialization each RPC runs its full lifecycle
    /// without tripping over the others).
    gates: std::sync::Mutex<BTreeMap<NodeId, Arc<tokio::sync::Mutex<()>>>>,
    session_cfg: session::TunnelConfig,
    /// Session establishment/RPC budget (default 5s).
    pub rpc_timeout: Duration,
    /// Answer-side handshake rejection count (no credentials / bad handshake
    /// — appears to the initiator as an opaque connection termination).
    rejected_handshakes: AtomicU64,
    /// Answer-side transient accept error count (continue after backoff — the
    /// inbound service must not exit on a single failure).
    accept_errors: AtomicU64,
    /// Interconnect diagnostics counters (M5 troubleshooting surface:
    /// dial/RPC successes and failures).
    pub(crate) diag_dial_ok: AtomicU64,
    pub(crate) diag_dial_err: AtomicU64,
    pub(crate) diag_rpc_ok: AtomicU64,
    pub(crate) diag_rpc_err: AtomicU64,
}

impl Interconnect {
    /// Construct from the root-signed directory and this machine's identity.
    /// `directory` provides all peer ServerEntries (root verification is done
    /// by the caller at assembly time — `ClusterDirectory::verify`).
    pub fn new(
        ident: Arc<ServerIdentity>,
        directory: &ClusterDirectory,
        fabric: Arc<dyn Fabric>,
    ) -> Arc<Self> {
        let mut nodes = BTreeMap::new();
        for e in &directory.servers {
            // ServerId ↔ NodeId mapping (first 8B).
            let nid = u64::from_be_bytes(e.server_id.0[..8].try_into().expect("8B"));
            nodes.insert(nid, e.clone());
        }
        let nodes: Arc<std::sync::RwLock<BTreeMap<NodeId, ServerEntry>>> =
            Arc::new(std::sync::RwLock::new(nodes));
        // Initiator "device" material = this machine's static X25519 +
        // identity Ed25519 (same source as the enrollment credential — the
        // answer-side PeerDirectory compares against the same two public
        // keys from the root-signed entry).
        let key_bytes = {
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(&ident.static_hybrid.x25519_secret().to_bytes());
            b[32..].copy_from_slice(&ident.identity.to_bytes());
            b
        };
        Arc::new(Interconnect {
            self_keys: DeviceStaticKeys::from_bytes(&key_bytes),
            cluster_id: directory.cluster_id,
            root_pub: ident.root_pub,
            ident,
            nodes,
            fabric,
            pipes: tokio::sync::Mutex::new(BTreeMap::new()),
            gates: std::sync::Mutex::new(BTreeMap::new()),
            session_cfg: session::TunnelConfig::default(),
            rpc_timeout: Duration::from_secs(5),
            rejected_handshakes: AtomicU64::new(0),
            accept_errors: AtomicU64::new(0),
            diag_dial_ok: AtomicU64::new(0),
            diag_dial_err: AtomicU64::new(0),
            diag_rpc_ok: AtomicU64::new(0),
            diag_rpc_err: AtomicU64::new(0),
        })
    }

    /// The cluster root public key (the enrollment-credential verification
    /// anchor; identical to `ServerIdentity::root_pub`).
    pub fn root_pub(&self) -> &VerifyingKey {
        &self.root_pub
    }

    /// All node ids in the directory (for gossip fan-out / location_query
    /// fan-out).
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.nodes
            .read()
            .expect("ic nodes")
            .keys()
            .copied()
            .collect()
    }

    /// Hot-update the interconnect directory mapping (admitting a new
    /// server: called after the root-signed new directory is installed
    /// network-wide).
    pub fn update_nodes(&self, entries: BTreeMap<NodeId, ServerEntry>) {
        *self.nodes.write().expect("ic nodes") = entries;
    }

    /// Answer-side handshake rejection count (no credentials / forged
    /// credentials — the admission assertion surface).
    pub fn rejected_handshakes(&self) -> u64 {
        self.rejected_handshakes.load(Ordering::Relaxed)
    }

    /// Answer-side transient accept error count (diagnostics surface — the
    /// inbound service's resilience made observable).
    pub fn accept_errors(&self) -> u64 {
        self.accept_errors.load(Ordering::Relaxed)
    }

    fn peer_entry(&self, peer: NodeId) -> io::Result<ServerEntry> {
        self.nodes
            .read()
            .expect("ic nodes")
            .get(&peer)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no directory entry for node {peer}"),
                )
            })
    }

    async fn connect_pipe(&self, peer: NodeId) -> io::Result<Arc<session::Tunnel>> {
        let entry = self.peer_entry(peer)?;
        let io = match self.fabric.dial(&entry.server_id).await {
            Ok(io) => {
                self.diag_dial_ok.fetch_add(1, Ordering::Relaxed);
                io
            }
            Err(e) => {
                self.diag_dial_err.fetch_add(1, Ordering::Relaxed);
                eprintln!("interconnect: dial node {peer} failed: {e}");
                return Err(e);
            }
        };
        let pin = ServerPin {
            cluster_id: self.cluster_id,
            cluster_root_pub: self.root_pub,
            entry: entry.clone(),
        };
        let tunnel = tokio::time::timeout(
            self.rpc_timeout,
            session::initiate(io, &self.self_keys, &pin, self.session_cfg.clone()),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "interconnect handshake timeout"))?
        .map_err(|e| io::Error::other(format!("interconnect handshake: {e}")))?;
        Ok(Arc::new(tunnel))
    }

    /// Open one RPC stream to a peer (cached sessions first; rebuilt once on
    /// failure).
    ///
    /// **Lock discipline (a lesson from M5 e2e runs)**: the global pipes lock
    /// must never be held across a network await — when a peer is down, its
    /// dial (DNS NXDOMAIN can take seconds) + handshake would block the RPCs
    /// of **all** peers (including Raft heartbeats), and with 500ms
    /// heartbeats/1.5s election timeouts that triggers election flapping
    /// (observed in the A7 window). Stream-open/dial/handshake all happen
    /// outside the lock; back inside only for lookup+insert (a racing double
    /// connect is harmless — last writer wins).
    async fn open_stream(&self, peer: NodeId) -> io::Result<MuxStream> {
        let cached = self.pipes.lock().await.get(&peer).cloned();
        if let Some(tunnel) = cached {
            match tunnel.open_stream(Prio::Control).await {
                Ok(s) => return Ok(s),
                Err(_) => {
                    self.pipes.lock().await.remove(&peer);
                }
            }
        }
        let tunnel = self.connect_pipe(peer).await?;
        let s = tunnel.open_stream(Prio::Control).await?;
        self.pipes.lock().await.insert(peer, tunnel.clone());
        Ok(s)
    }

    /// The per-peer RPC gate (created if absent).
    fn gate_of(&self, peer: NodeId) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self.gates.lock().expect("ic gates");
        gates
            .entry(peer)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Evict a peer's cached session (rebuilt by the next RPC after a
    /// timeout/IO failure).
    async fn evict(&self, peer: NodeId) {
        self.pipes.lock().await.remove(&peer);
    }

    /// One RPC round trip (inside the gate: open stream → frame request →
    /// frame response; on timeout/IO error evict the session for rebuild).
    ///
    /// **Gate-queuing budget**: acquiring the gate is also bounded by
    /// `timeout` (openraft passes `hard_ttl`) — while a slow snapshot holds
    /// the gate, subsequent heartbeats/RPCs must not queue forever (queuing
    /// time counts toward the total budget; on expiry return
    /// [`WireCallError::TimedOut`] and let openraft retry, rather than
    /// queueing until the end of time).
    pub async fn call(
        &self,
        peer: NodeId,
        rpc: WireRpc,
        timeout: Duration,
    ) -> Result<WireResp, WireCallError> {
        let gate = self.gate_of(peer);
        let t0 = Instant::now();
        let _guard = match tokio::time::timeout(timeout, gate.lock()).await {
            Ok(guard) => guard,
            Err(_) => {
                self.diag_rpc_err.fetch_add(1, Ordering::Relaxed);
                eprintln!("interconnect: rpc to {peer} queued on gate over {timeout:?}");
                return Err(WireCallError::TimedOut);
            }
        };
        // Queuing time is deducted from the RPC budget (the total round trip
        // stays within the caller's budget).
        let rpc_budget = timeout.saturating_sub(t0.elapsed());
        let mut stream = match self.open_stream(peer).await {
            Ok(s) => s,
            Err(e) => {
                return Err(WireCallError::Io(e));
            }
        };
        let req = postcard::to_allocvec(&rpc)
            .map_err(|e| WireCallError::Io(io::Error::other(format!("encode: {e}"))))?;
        let fut = async {
            send_frame(&mut stream, &req).await?;
            let resp = recv_frame(&mut stream).await?;
            postcard::from_bytes::<WireResp>(&resp)
                .map_err(|e| io::Error::other(format!("decode: {e}")))
        };
        match tokio::time::timeout(rpc_budget, fut).await {
            Ok(Ok(resp)) => {
                self.diag_rpc_ok.fetch_add(1, Ordering::Relaxed);
                Ok(resp)
            }
            Ok(Err(e)) => {
                // Stream-level IO error: the session may be half-dead —
                // evict; the next RPC re-handshakes.
                self.diag_rpc_err.fetch_add(1, Ordering::Relaxed);
                eprintln!("interconnect: rpc to {peer} io-error: {e}");
                self.evict(peer).await;
                Err(WireCallError::Io(e))
            }
            Err(_) => {
                self.diag_rpc_err.fetch_add(1, Ordering::Relaxed);
                eprintln!("interconnect: rpc to {peer} timed out ({rpc_budget:?})");
                self.evict(peer).await;
                Err(WireCallError::TimedOut)
            }
        }
    }

    /// Interconnect diagnostics counters (M5 troubleshooting surface).
    pub fn diag(&self) -> (u64, u64, u64, u64) {
        (
            self.diag_dial_ok.load(Ordering::Relaxed),
            self.diag_dial_err.load(Ordering::Relaxed),
            self.diag_rpc_ok.load(Ordering::Relaxed),
            self.diag_rpc_err.load(Ordering::Relaxed),
        )
    }

    /// Answer-side main loop: inbound connection → server-server profile
    /// answer (no credentials ⇒ rejected) → per-stream dispatch.
    ///
    /// **Resilience discipline**: transient accept errors (WouldBlock/
    /// ConnAborted/EMFILE etc. — fd exhaustion, mid-handshake resets and the
    /// like) are only counted + retried after exponential backoff — a single
    /// inbound failure must not permanently kill the inbound service (the
    /// old implementation exited on any Err, taking Raft
    /// replication/snapshot down with it). The only exit condition = the
    /// fabric explicitly closing ([`is_fabric_closed`]).
    pub async fn serve_loop(self: Arc<Self>, target: RpcTarget) {
        let mut backoff = Duration::from_millis(10);
        loop {
            let io = match self.fabric.accept().await {
                Ok(io) => io,
                Err(e) => {
                    if is_fabric_closed(&e) {
                        // The fabric was explicitly closed (listener torn
                        // down / in-memory fabric channel gone) — exit the
                        // serve loop.
                        return;
                    }
                    self.accept_errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!("interconnect: accept transient error: {e}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(1));
                    continue;
                }
            };
            backoff = Duration::from_millis(10);
            let this = self.clone();
            let target = target.clone();
            tokio::spawn(async move {
                let dir = PeerDirectory::new(this.nodes.clone());
                match session::respond(io, &this.ident, dir, this.session_cfg.clone()).await {
                    Ok(tunnel) => this.serve_tunnel(tunnel, target).await,
                    Err(_) => {
                        // No credentials / bad handshake ⇒ session rejected
                        // (§4-2: rejected right at the handshake layer — no
                        // snapshot, no Raft: the dispatcher only exists
                        // inside authenticated sessions).
                        this.rejected_handshakes.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    }

    async fn serve_tunnel(&self, tunnel: session::Tunnel, target: RpcTarget) {
        loop {
            match tunnel.accept_stream().await {
                Some(stream) => {
                    let target = target.clone();
                    // One task per stream: an IO break/decode failure ends
                    // only that stream (the session persists).
                    tokio::spawn(async move {
                        let _ = handle_stream(stream, target).await;
                    });
                }
                None => return,
            }
        }
    }
}

/// Whether an accept error means "the fabric was explicitly closed" (the only
/// legitimate exit condition of `serve_loop`).
///
/// Convention: the in-memory fabric closing its channel ⇒ `NotConnected`
/// (testutil); the TCP listener has no explicit-close path (listener
/// lifetime = fabric = process) — every other error (WouldBlock/ConnAborted/
/// EMFILE etc., including unknown future kinds) is treated as transient:
/// back off and continue.
fn is_fabric_closed(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotConnected
}

/// Single-stream handling: one request, one response.
async fn handle_stream(mut stream: MuxStream, target: RpcTarget) -> io::Result<()> {
    let req = recv_frame(&mut stream).await?;
    let rpc: WireRpc =
        postcard::from_bytes(&req).map_err(|e| io::Error::other(format!("rpc decode: {e}")))?;
    let resp = dispatch(&target, rpc).await;
    let bytes =
        postcard::to_allocvec(&resp).map_err(|e| io::Error::other(format!("resp encode: {e}")))?;
    send_frame(&mut stream, &bytes).await?;
    stream.finish().await?;
    Ok(())
}

// ============================================================================
// Wire format
// ============================================================================

/// Interconnect RPC requests (the three Raft kinds + client write/read
/// forwarding + gossip leases). Snapshot chunks:
/// `InstallSnapshotRequest.data` is a plain `Vec<u8>` (openraft 0.9.25's
/// non-generic snapshot transport shape), carried directly by serde.
#[derive(Serialize, Deserialize)]
pub enum WireRpc {
    Append(AppendEntriesRequest<SyncConfig>),
    Vote(VoteRequest<u64>),
    Snapshot(InstallSnapshotRequest<SyncConfig>),
    Write(SyncRequest),
    Read(ReadQuery),
    Gossip(GossipMsg),
    /// Location inquiry (a single hop of the location_query fan-out: ask
    /// "who is hosting this device").
    Locate([u8; 32]),
    /// Cross-server forwarding (FRWD stream carrying a ForwardEnvelope,
    /// §2.2-3).
    Forward(crate::forward::ForwardEnvelope),
    /// dir_pull (initiated by the client over the control plane; here is the
    /// server-side serve implementation, §3.10).
    DirPull {
        since: u64,
    },
}

/// Interconnect RPC responses (remote Raft fatal errors are uniformly folded
/// into `Err(String)` → the caller treats them as Unreachable; ForwardToLeader
/// semantics are preserved structurally as [`SyncError`] on the Write/Read
/// paths).
#[derive(Serialize, Deserialize)]
pub enum WireResp {
    Append(Result<AppendEntriesResponse<u64>, RaftError<u64>>),
    Vote(Result<VoteResponse<u64>, RaftError<u64>>),
    Snapshot(Result<InstallSnapshotResponse<u64>, String>),
    Write(Result<crate::proto::SyncResponse, SyncError>),
    Read(Result<ReadView, SyncError>),
    Gossip(bool),
    /// The holder's node id (answered only on a local lease-domain hit).
    Locate(Option<NodeId>),
    Forward(crate::forward::ForwardOutcome),
    DirPull(crate::directory::DirPullResp),
}

/// Interconnect call failure.
#[derive(Debug)]
pub enum WireCallError {
    Io(io::Error),
    TimedOut,
    /// Response shape does not match the request (protocol error).
    Mismatch,
}

impl std::fmt::Display for WireCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireCallError::Io(e) => write!(f, "wire io: {e}"),
            WireCallError::TimedOut => write!(f, "wire rpc timeout"),
            WireCallError::Mismatch => write!(f, "wire rpc response mismatch"),
        }
    }
}
impl std::error::Error for WireCallError {}
impl From<WireCallError> for io::Error {
    fn from(e: WireCallError) -> Self {
        match e {
            WireCallError::Io(e) => e,
            other => io::Error::other(other.to_string()),
        }
    }
}

/// Dispatch target (Raft handle + SM core + lag monitor + lease table +
/// forwarding plane + directory service).
#[derive(Clone)]
pub struct RpcTarget {
    pub raft: Raft<SyncConfig>,
    pub sm: Arc<SmCore>,
    pub lag: Arc<LagMonitor>,
    pub lease: Arc<LeaseTable>,
    pub forward: Arc<crate::forward::ForwardPlane>,
    pub directory: Arc<crate::directory::Directory>,
}

/// Inbound RPC dispatch (the answer-side core).
pub async fn dispatch(target: &RpcTarget, rpc: WireRpc) -> WireResp {
    match rpc {
        WireRpc::Append(req) => {
            // §4: heartbeats/AppendEntries carry the leader commit index —
            // followers self-monitor lag on it.
            target
                .lag
                .observe_leader_commit(req.leader_commit.map(|l| l.index).unwrap_or(0));
            WireResp::Append(target.raft.append_entries(req).await)
        }
        WireRpc::Vote(req) => WireResp::Vote(target.raft.vote(req).await),
        WireRpc::Snapshot(req) => {
            WireResp::Snapshot(match target.raft.install_snapshot(req).await {
                Ok(r) => Ok(r),
                Err(e) => Err(format!("{e}")),
            })
        }
        WireRpc::Write(req) => {
            let r = target
                .raft
                .client_write(req)
                .await
                .map(|r| r.data)
                .map_err(sync_error_from_write);
            WireResp::Write(r)
        }
        WireRpc::Read(q) => {
            // Leader-side linearizable read: ensure_linearizable, then read
            // this machine's applied state.
            match target.raft.ensure_linearizable().await {
                Ok(_) => WireResp::Read(Ok(read_view(&target.sm, q))),
                Err(e) => WireResp::Read(Err(sync_error_from_check(e))),
            }
        }
        WireRpc::Gossip(m) => {
            target.lease.merge_remote(m);
            WireResp::Gossip(true)
        }
        WireRpc::Locate(device) => {
            // "The single source of truth for a device's current location =
            // the lease domain": answer only from the local lease (valid
            // within TTL).
            WireResp::Locate(target.lease.observe(&device).map(|l| l.holder))
        }
        WireRpc::Forward(env) => WireResp::Forward(target.forward.receive(env)),
        WireRpc::DirPull { since } => WireResp::DirPull(target.directory.dir_pull_response(since)),
    }
}

/// Leader-side linearizable read view.
pub fn read_view(sm: &SmCore, q: ReadQuery) -> ReadView {
    use crate::proto::{ReadQuery as Q, ReadView as V};
    sm.with_data(|d| match q {
        Q::Lookup(id) => V::Verdict(d.lookup(&id)),
        Q::Epoch => V::Epoch(d.epoch),
        Q::DeviceRow(id) => V::Device(d.devices.get(&id).cloned()),
        Q::Wrap(server) => V::Wrap(d.wraps.get(&server).cloned()),
        Q::User(u) => V::User(d.users.get(&u).cloned()),
        Q::DevicesOf(owner) => V::Devices(
            d.devices
                .iter()
                .filter(|(_, r)| r.owner == *owner)
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        ),
        Q::State => V::State(d.state_view()),
    })
}

fn sync_error_from_write(
    e: RaftError<u64, openraft::error::ClientWriteError<u64, BasicNode>>,
) -> SyncError {
    match e {
        RaftError::APIError(openraft::error::ClientWriteError::ForwardToLeader(f)) => {
            SyncError::ForwardToLeader {
                leader: f.leader_id,
            }
        }
        other => SyncError::Raft(other.to_string()),
    }
}

fn sync_error_from_check(
    e: RaftError<u64, openraft::error::CheckIsLeaderError<u64, BasicNode>>,
) -> SyncError {
    match e {
        RaftError::APIError(openraft::error::CheckIsLeaderError::ForwardToLeader(f)) => {
            SyncError::ForwardToLeader {
                leader: f.leader_id,
            }
        }
        other => SyncError::Raft(other.to_string()),
    }
}

// ============================================================================
// Frame encode/decode
// ============================================================================

/// Frame send (`[u32 LE length][payload]`; mux::Stream implements futures
/// IO).
async fn send_frame<W: futures::AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::other("frame too large"));
    }
    use futures::AsyncWriteExt;
    w.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    w.write_all(bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Frame receive (read up to the declared length; EOF is expressed by the
/// peer closing).
async fn recv_frame<R: futures::AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    use futures::AsyncReadExt;
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame length"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

// ============================================================================
// RPCError mapping helpers (consumed by network.rs)
// ============================================================================

/// Interconnect call error → openraft RPCError (timeout ⇒ Timeout; the rest ⇒
/// Unreachable).
pub fn rpc_error_of(peer: NodeId, e: WireCallError) -> RPCError<u64, BasicNode, RaftError<u64>> {
    match e {
        WireCallError::TimedOut => RPCError::Timeout(Timeout {
            action: openraft::network::RPCTypes::Vote, // field is diagnostic only
            id: peer,
            target: peer,
            timeout: Duration::ZERO,
        }),
        WireCallError::Io(e) => RPCError::Unreachable(Unreachable::new(&e)),
        WireCallError::Mismatch => {
            RPCError::Unreachable(Unreachable::new(&io::Error::other("rpc response mismatch")))
        }
    }
}

/// Remote Raft fatal error → RemoteError wrapper (the Append/Vote wire format
/// already carries RaftError).
pub fn remote_error(peer: NodeId, e: RaftError<u64>) -> RPCError<u64, BasicNode, RaftError<u64>> {
    RPCError::RemoteError(RemoteError {
        target: peer,
        target_node: None,
        source: e,
    })
}

// ============================================================================
// Unit tests: frame encode/decode + LagMonitor timing
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Minimal in-memory futures IO pair (the vehicle for frame codec unit
    /// tests).
    struct MemIo {
        inbox: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>,
        outbox: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>,
        woken: std::sync::Arc<futures::task::AtomicWaker>,
    }

    impl futures::AsyncWrite for MemIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.outbox
                .lock()
                .expect("mem io")
                .extend(buf.iter().copied());
            self.woken.wake();
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl futures::AsyncRead for MemIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut inbox = self.inbox.lock().expect("mem io");
            if inbox.is_empty() {
                self.woken.register(cx.waker());
                return Poll::Pending;
            }
            let n = inbox.len().min(buf.len());
            for (i, b) in inbox.drain(..n).enumerate() {
                buf[i] = b;
            }
            Poll::Ready(Ok(n))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn frame_roundtrip() {
        use std::collections::VecDeque;
        let q1 = std::sync::Arc::new(std::sync::Mutex::new(VecDeque::<u8>::new()));
        let q2 = std::sync::Arc::new(std::sync::Mutex::new(VecDeque::<u8>::new()));
        let w1 = std::sync::Arc::new(futures::task::AtomicWaker::default());
        let w2 = std::sync::Arc::new(futures::task::AtomicWaker::default());
        let a = MemIo {
            inbox: q1.clone(),
            outbox: q2.clone(),
            woken: w2,
        };
        let b = MemIo {
            inbox: q2,
            outbox: q1,
            woken: w1,
        };
        let (mut a, mut b) = (a, b);
        send_frame(&mut a, b"hello wire").await.expect("send");
        let got = recv_frame(&mut b).await.expect("recv");
        assert_eq!(got, b"hello wire");
    }

    #[tokio::test]
    async fn lag_monitor_opens_after_threshold_and_closes_on_catchup() {
        let applied = Arc::new(AtomicU64::new(10));
        let mon = LagMonitor::new(
            Duration::from_millis(100),
            Duration::from_secs(1),
            applied.clone(),
        );
        mon.observe_leader_commit(12);
        assert!(
            !mon.breaker_open(),
            "freshly observed lag does not trip the breaker immediately"
        );
        assert_eq!(mon.leader_commit(), 12);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            mon.breaker_open(),
            "lag persisting past the threshold ⇒ breaker opens"
        );
        // Caught up ⇒ recovers.
        applied.store(12, Ordering::SeqCst);
        mon.observe_leader_commit(12);
        assert!(!mon.breaker_open(), "breaker closes after catching up");
    }

    /// Heartbeat-silence dimension: a long stretch with no
    /// AppendEntries/heartbeat observation (full partition) ⇒ breaker opens.
    ///
    /// The old assertion (lag_monitor_not_open_without_observation) codified
    /// "no breaker under partition" as a misfeature: under a full partition
    /// `leader_commit` freezes equal to the local applied, so judging "not
    /// lagging" is a blind spot — during the partition a revocation cannot
    /// be blocked from passing through the cache path (§4/R24). This
    /// assertion fixes the correct semantics: the observation stream
    /// disappearing is itself evidence of disconnection; silence beyond
    /// max(threshold, election_timeout) opens the breaker.
    #[tokio::test]
    async fn lag_monitor_opens_on_heartbeat_silence() {
        let applied = Arc::new(AtomicU64::new(5));
        // silence_limit = max(50ms, 100ms) = 100ms.
        let mon = LagMonitor::new(
            Duration::from_millis(50),
            Duration::from_millis(100),
            applied,
        );
        assert!(
            !mon.breaker_open(),
            "counted from construction; silence under the limit does not open"
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            mon.breaker_open(),
            "long stretch with no observation (full partition) ⇒ breaker opens"
        );
    }

    /// Partition recovery: after silence opened the breaker, the first frame
    /// observing leader_commit >> applied keeps it open immediately
    /// (pending_since backdated to the start of the silence, no fresh
    /// timing); it closes only after catching up.
    #[tokio::test]
    async fn lag_monitor_recovery_backdates_pending_window() {
        let applied = Arc::new(AtomicU64::new(10));
        let mon = LagMonitor::new(
            Duration::from_millis(100),
            Duration::from_millis(150),
            applied.clone(),
        );
        mon.observe_leader_commit(10);
        assert!(!mon.breaker_open(), "healthy (no lag)");
        // Full partition 200ms > silence_limit(150ms) ⇒ breaker.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(mon.breaker_open(), "silence opens the breaker");
        // Recovery's first frame: the leader has moved far ahead (commit 30
        // >> applied 10) ⇒ stays open immediately (the pending window is
        // backdated to the start of the silence; elapsed 200ms > threshold
        // 100ms).
        mon.observe_leader_commit(30);
        assert!(
            mon.breaker_open(),
            "recovery's first frame observing a large lag ⇒ stays open immediately (no fresh timing)"
        );
        // Caught up ⇒ closes.
        applied.store(30, Ordering::SeqCst);
        mon.observe_leader_commit(30);
        assert!(!mon.breaker_open(), "breaker closes after catching up");
    }

    /// Accept error classification: only NotConnected (the fabric's explicit
    /// close convention) exits the serve loop; transient errors such as
    /// WouldBlock/ConnAborted/EMFILE all retry with backoff (serve_loop never
    /// dies).
    #[test]
    fn accept_error_classification() {
        assert!(
            is_fabric_closed(&io::Error::new(
                io::ErrorKind::NotConnected,
                "fabric closed"
            )),
            "NotConnected = fabric closed (the only exit condition)"
        );
        assert!(!is_fabric_closed(&io::Error::new(
            io::ErrorKind::WouldBlock,
            "x"
        )));
        assert!(!is_fabric_closed(&io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "x"
        )));
        assert!(!is_fabric_closed(&io::Error::new(
            io::ErrorKind::Interrupted,
            "x"
        )));
        assert!(!is_fabric_closed(&io::Error::from_raw_os_error(23))); // EMFILE
        assert!(!is_fabric_closed(&io::Error::from_raw_os_error(24))); // ENFILE
    }
}
