//! [`SyncNode`]: the single-server-side synchronization assembly (the
//! outward facade of docs/design.md §3.10 part one).
//!
//! - **Write on any node**: local `client_write`; not the leader ⇒
//!   ForwardToLeader ⇒ forwarded to the leader over an interconnect session
//!   (§4 "write forwarding to the leader", one extra relay hop of latency);
//! - **Linearizable read on any node**: the leader locally runs
//!   `ensure_linearizable` then reads applied state; followers forward to the
//!   leader (`read_linearizable`);
//! - **Two-tier directory reads**: [`crate::dir::SyncDirectory`] (cache +
//!   epoch + lag breaker);
//! - **Lease gossip**: publish broadcasts immediately + the anti-entropy loop
//!   (§3.10 LeaseTable);
//! - **Ticket issuing**: the key root comes from Raft state (available after
//!   Bootstrap).

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use flock_protocol::session::ServerIdentity;
use flock_protocol::trust::ClusterDirectory;
use futures::future::BoxFuture;
use openraft::error::{CheckIsLeaderError, ClientWriteError, RaftError};
use openraft::{BasicNode, Raft};
use redb::Database;

use crate::dir::{DirHandle, LinearizableReader, SyncDirectory};
use crate::directory::Directory;
use crate::forward::{ForwardEnvelope, ForwardOutcome, ForwardPlane, ForwardTransport, PacketSink};
use crate::hooks::SyncHooks;
use crate::lease::{LeaseTable, LocateFanout, ANTI_ENTROPY};
use crate::proto::{NodeId, ReadQuery, ReadView, SyncError, SyncRequest, SyncResponse};
use crate::raft_types::SyncConfig;
use crate::sm::{RedbStateMachine, SmCore};
use crate::store::RedbLogStore;
use crate::ticket::TicketIssuer;
use crate::wire::{Fabric, Interconnect, LagMonitor, RpcTarget, WireResp, WireRpc};

/// Cluster runtime parameters (§4: heartbeat 500ms / election 1.5s~3s —
/// calibrated for a relay RTT of 100ms; lag breaker 2s).
#[derive(Debug, Clone)]
pub struct SyncSettings {
    pub heartbeat_ms: u64,
    pub election_min_ms: u64,
    pub election_max_ms: u64,
    /// apply-lag breaker threshold (A6 timing budget: 2s).
    pub lag_threshold: Duration,
    /// Budget of a single interconnect RPC.
    pub rpc_timeout: Duration,
    /// Total budget for write/read forwarding retries.
    pub forward_deadline: Duration,
    pub lease_ttl: Duration,
}

impl Default for SyncSettings {
    fn default() -> Self {
        SyncSettings {
            heartbeat_ms: 500,
            election_min_ms: 1500,
            election_max_ms: 3000,
            lag_threshold: Duration::from_secs(2),
            rpc_timeout: Duration::from_secs(5),
            forward_deadline: Duration::from_secs(12),
            lease_ttl: crate::lease::LEASE_TTL,
        }
    }
}

/// Node construction inputs.
pub struct SyncNodeBuilder {
    pub settings: SyncSettings,
    /// The local enrollment identity (root-signed ServerIdentity — the enroll
    /// product).
    pub ident: Arc<ServerIdentity>,
    /// The root-signed cluster directory (peer access material; `verify` runs
    /// at build time).
    pub directory: ClusterDirectory,
    /// The raw fabric (in-memory duplex / TCP).
    pub fabric: Arc<dyn Fabric>,
    /// redb database file path.
    pub db_path: PathBuf,
    /// The locally pinned cluster root public key (defaults to
    /// ident.root_pub).
    pub pinned_root: Option<ed25519_dalek::VerifyingKey>,
    hooks: Vec<Arc<dyn SyncHooks>>,
    members: BTreeMap<NodeId, BasicNode>,
    node_id: NodeId,
}

impl SyncNodeBuilder {
    pub fn new(
        settings: SyncSettings,
        ident: Arc<ServerIdentity>,
        directory: ClusterDirectory,
        fabric: Arc<dyn Fabric>,
        db_path: PathBuf,
    ) -> Self {
        let node_id = node_id_of(&ident.server_id);
        SyncNodeBuilder {
            settings,
            ident,
            directory,
            fabric,
            db_path,
            pinned_root: None,
            hooks: Vec::new(),
            members: BTreeMap::new(),
            node_id,
        }
    }

    /// The initial member set (all voters; used by `initialize`).
    pub fn voters(mut self, ids: &[NodeId]) -> Self {
        self.members = ids
            .iter()
            .map(|id| (*id, BasicNode::new(format!("node-{id}"))))
            .collect();
        self
    }

    /// Register an apply/lease hook.
    pub fn hook(mut self, h: Arc<dyn SyncHooks>) -> Self {
        self.hooks.push(h);
        self
    }

    /// Pin the root public key (default = ident.root_pub).
    pub fn pinned_root(mut self, root: ed25519_dalek::VerifyingKey) -> Self {
        self.pinned_root = Some(root);
        self
    }

    /// Assemble and start (Raft task + interconnect serve loop + anti-entropy
    /// loop + membership initialization).
    pub async fn build(self) -> Result<SyncNode, SyncError> {
        // Root-signed directory verification (no signature / a different root
        // ⇒ refuse to assemble).
        if !self.directory.verify(&self.ident.root_pub) {
            return Err(SyncError::Raft(
                "cluster directory failed root verification".into(),
            ));
        }
        let pinned = self.pinned_root.unwrap_or(self.ident.root_pub);

        let cfg = openraft::Config {
            cluster_name: "flock-sync".into(),
            heartbeat_interval: self.settings.heartbeat_ms,
            election_timeout_min: self.settings.election_min_ms,
            election_timeout_max: self.settings.election_max_ms,
            install_snapshot_timeout: 10_000,
            ..Default::default()
        };
        let cfg = Arc::new(
            cfg.validate()
                .map_err(|e| SyncError::Raft(format!("config: {e}")))?,
        );

        let db = Database::create(&self.db_path)
            .map_err(|e| SyncError::Raft(format!("redb open {}: {e}", self.db_path.display())))?;
        let db = Arc::new(db);
        RedbLogStore::init_tables(&db).map_err(|e| SyncError::Raft(format!("redb init: {e}")))?;
        let log_store = RedbLogStore::from_db(db.clone());
        let sm = SmCore::restore_or_empty(db.clone(), Some(pinned));
        for h in self.hooks {
            sm.register_hook(h);
        }

        let ic = Interconnect::new(self.ident.clone(), &self.directory, self.fabric.clone());
        let net = crate::network::SyncNetFactory { ic: ic.clone() };
        let ic_serve_ic = ic.clone();
        let raft = Raft::new(
            self.node_id,
            cfg,
            net,
            log_store,
            RedbStateMachine::new(sm.clone()),
        )
        .await
        .map_err(|e| SyncError::Raft(format!("raft start: {e}")))?;

        let lag = LagMonitor::new(
            self.settings.lag_threshold,
            Duration::from_millis(self.settings.election_max_ms),
            sm.applied_counter(),
        );
        let lease = LeaseTable::new(self.node_id, self.settings.lease_ttl, sm.shared_hooks());
        let directory = Arc::new(
            Directory::new(self.ident.root_pub, &self.directory)
                .map_err(|e| SyncError::Raft(format!("directory: {e}")))?,
        );
        let forward = ForwardPlane::new(self.node_id, sm.clone(), lease.clone());

        // Interconnect answer loop (peers without credentials are rejected at
        // this layer).
        let target = RpcTarget {
            raft: raft.clone(),
            sm: sm.clone(),
            lag: lag.clone(),
            lease: lease.clone(),
            forward: forward.clone(),
            directory: directory.clone(),
        };
        tokio::spawn(async move {
            ic_serve_ic.serve_loop(target).await;
        });

        // Anti-entropy loop (5s full-table digest fan-out) + local session
        // lease refresh (TTL/3 re-publication) + EWMA folding (1s window —
        // M7).
        tokio::spawn(anti_entropy_loop(ic.clone(), lease.clone(), self.node_id));
        tokio::spawn(lease_refresh_loop(
            ic.clone(),
            lease.clone(),
            forward.clone(),
            self.node_id,
        ));
        tokio::spawn(ewma_tick_loop(lease.clone()));

        // Membership initialization (concurrent initialize from multiple
        // nodes with the same config is safe — the openraft contract).
        if !self.members.is_empty() {
            if let Err(e) = raft.initialize(self.members.clone()).await {
                // NotAllowed = the cluster already has logs/membership
                // (another node initialized first, or this machine rejoining
                // after a restart) — a normal convergence path, silently
                // allowed; other errors (NotInMembers etc.) are logged: an
                // initial-member-set assembly failure must be observable,
                // silently swallowing it would leave a "sick startup"
                // traceless.
                if !matches!(
                    e,
                    RaftError::APIError(openraft::error::InitializeError::NotAllowed(_))
                ) {
                    eprintln!("raft initialize failed: {e}");
                }
            }
        }

        // Forwarding-plane interconnect seams (FRWD stream + location_query
        // fan-out).
        let fwd_transport = Arc::new(IcForwardTransport { ic: ic.clone() });
        let fwd_fanout = Arc::new(IcLocateFanout {
            ic: ic.clone(),
            me: self.node_id,
        });
        forward.set_transport(fwd_transport, fwd_fanout);

        let inner = Arc::new(NodeInner {
            id: self.node_id,
            entry: self.ident.entry.clone(),
            raft,
            sm,
            lag,
            lease,
            ic,
            directory,
            forward,
            settings: self.settings,
            ticket_seq: AtomicU64::new(0),
        });
        let reader = Arc::new(NodeReader(inner.clone()));
        let dir = SyncDirectory::new(reader, inner.lag.clone(), inner.sm.epoch_watch());
        Ok(SyncNode { inner, dir })
    }
}

/// Local session lease refresh: every [`LEASE_REFRESH`] (TTL/3), re-publish
/// and broadcast the devices still online locally (publish fires only once at
/// connection setup — without this loop, leases network-wide evaporate after
/// 30s). M7: the same loop **self-publishes the server's own lease**
/// (synthetic device key — the roster Server entry's ewma/online state
/// becomes visible network-wide over the existing gossip path).
async fn lease_refresh_loop(
    ic: Arc<Interconnect>,
    lease: Arc<LeaseTable>,
    forward: Arc<crate::forward::ForwardPlane>,
    me: NodeId,
) {
    let mut tick = tokio::time::interval(crate::lease::LEASE_REFRESH);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let mut devices = forward.local_devices();
        devices.push(crate::lease::server_self_device_id(me));
        for device in devices {
            let _ = lease.publish(&device);
            broadcast_publish(&ic, &lease, me, device);
        }
    }
}

/// M7: the EWMA folding loop (1s window, §7-M7.3) — the holder side folds the
/// per-device byte accumulators into the row's ewma (carried out by the next
/// refresh/anti-entropy).
async fn ewma_tick_loop(lease: Arc<LeaseTable>) {
    let mut tick = tokio::time::interval(crate::lease::EWMA_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        lease.tick_ewma(now_ms());
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Broadcast of a single lease event (shared by publish/refresh). M7: the
/// message carries the row's ewma/last_seen (holder-authoritative values);
/// the term is the one just published into the table (eliminating the old
/// implementation's millisecond-level mismatch of "the broadcast term and
/// the table term each read the clock once").
fn broadcast_publish(
    ic: &Arc<Interconnect>,
    lease: &Arc<LeaseTable>,
    me: NodeId,
    device: [u8; 32],
) {
    let Some(l) = lease.observe(&device) else {
        return;
    };
    let msg = crate::lease::GossipMsg::Publish {
        device,
        holder: me,
        term_ms: l.term_ms,
        tx_ewma: l.tx_ewma,
        rx_ewma: l.rx_ewma,
        last_seen_unix: l.last_seen_unix,
    };
    for peer in ic.node_ids() {
        if peer != me {
            let ic = ic.clone();
            let m = msg.clone();
            tokio::spawn(async move {
                let _ = ic
                    .call(peer, WireRpc::Gossip(m), Duration::from_secs(2))
                    .await;
            });
        }
    }
}

async fn anti_entropy_loop(ic: Arc<Interconnect>, lease: Arc<LeaseTable>, me: NodeId) {
    let mut tick = tokio::time::interval(ANTI_ENTROPY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let msg = lease.anti_entropy_msg();
        for peer in ic_peer_ids(&ic) {
            // Self-digest merged into self is a pure waste (the same (term,
            // holder) can never be "newer" ⇒ always a no-op), and it would
            // pollute LeaseTable::remote_events' "remote view has been
            // backfilled" signal (used by the reaper gate, §7-M7.5) — the
            // same discipline as broadcast_publish/locate's self-filtering.
            if peer == me {
                continue;
            }
            let _ = ic
                .call(peer, WireRpc::Gossip(msg.clone()), Duration::from_secs(2))
                .await;
        }
    }
}

fn ic_peer_ids(ic: &Interconnect) -> Vec<NodeId> {
    ic.node_ids()
}

/// ServerId([u8;16]) ↔ NodeId(u64) (first 8B big-endian).
pub fn node_id_of(sid: &flock_protocol::session::ServerId) -> NodeId {
    u64::from_be_bytes(sid.0[..8].try_into().expect("8B"))
}

pub(crate) struct NodeInner {
    pub id: NodeId,
    pub entry: flock_protocol::session::ServerEntry,
    pub raft: Raft<SyncConfig>,
    pub sm: Arc<SmCore>,
    pub lag: Arc<LagMonitor>,
    pub lease: Arc<LeaseTable>,
    pub ic: Arc<Interconnect>,
    pub directory: Arc<Directory>,
    pub forward: Arc<ForwardPlane>,
    pub settings: SyncSettings,
    ticket_seq: AtomicU64,
}

/// FRWD stream send seam: ForwardEnvelope over an interconnect E2E session
/// (server-to-server encryption on the outer layer).
struct IcForwardTransport {
    ic: Arc<Interconnect>,
}

impl ForwardTransport for IcForwardTransport {
    fn send(
        &self,
        peer: NodeId,
        env: ForwardEnvelope,
    ) -> BoxFuture<'static, io::Result<ForwardOutcome>> {
        let ic = self.ic.clone();
        Box::pin(async move {
            match ic
                .call(peer, WireRpc::Forward(env), Duration::from_secs(3))
                .await
            {
                Ok(WireResp::Forward(r)) => Ok(r),
                Ok(_) => Err(io::Error::other("forward rpc response mismatch")),
                Err(e) => Err(io::Error::from(e)),
            }
        })
    }
}

/// location_query fan-out seam: ask ≤3 interconnected servers "who is hosting
/// this device" (one-shot, no retries).
struct IcLocateFanout {
    ic: Arc<Interconnect>,
    me: NodeId,
}

impl LocateFanout for IcLocateFanout {
    fn locate(&self, device: &[u8; 32]) -> BoxFuture<'static, Option<NodeId>> {
        let ic = self.ic.clone();
        let me = self.me;
        let device = *device;
        Box::pin(async move {
            let peers: Vec<NodeId> = ic
                .node_ids()
                .into_iter()
                .filter(|p| *p != me)
                .take(3)
                .collect();
            for peer in peers {
                if let Ok(WireResp::Locate(Some(holder))) = ic
                    .call(peer, WireRpc::Locate(device), Duration::from_secs(2))
                    .await
                {
                    return Some(holder);
                }
            }
            None
        })
    }
}

/// Linearizable-read handle for the directory (the `'static` future
/// requirement — clone the inner handle).
struct NodeReader(Arc<NodeInner>);

impl LinearizableReader for NodeReader {
    fn read(&self, q: ReadQuery) -> BoxFuture<'static, Result<ReadView, SyncError>> {
        let me = self.0.clone();
        Box::pin(async move { me.read_linearizable(q).await })
    }
}

impl NodeInner {
    /// Write (leader local / follower forwards; §4 write forwarding).
    ///
    /// Forwarding retry discipline: when the remote again answers
    /// `ForwardToLeader` (leader change in progress) or `NoLeader`, it is
    /// **not passed through to the caller** — back to the loop, retrying
    /// within the `forward_deadline` (12s) budget, same as the local
    /// client_write path; only deterministic remote errors (Raft fatal etc.)
    /// return directly.
    pub async fn write(&self, req: SyncRequest) -> Result<SyncResponse, SyncError> {
        let deadline = Instant::now() + self.settings.forward_deadline;
        loop {
            match self.raft.client_write(req.clone()).await {
                Ok(r) => return Ok(r.data),
                Err(RaftError::APIError(ClientWriteError::ForwardToLeader(f))) => {
                    if let Some(leader) = f.leader_id.filter(|l| *l != self.id) {
                        match self
                            .ic
                            .call(
                                leader,
                                WireRpc::Write(req.clone()),
                                self.settings.rpc_timeout,
                            )
                            .await
                        {
                            Ok(WireResp::Write(Ok(resp))) => return Ok(resp),
                            // The remote is also mid-leader-change ⇒ loop and
                            // retry (within budget), no pass-through.
                            Ok(WireResp::Write(Err(
                                SyncError::ForwardToLeader { .. } | SyncError::NoLeader,
                            ))) => {}
                            Ok(WireResp::Write(Err(other))) => return Err(other),
                            Ok(_) => {
                                return Err(SyncError::Wire("write rpc response mismatch".into()))
                            }
                            Err(e) => eprintln!("write forward to {leader} failed: {e}"),
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(SyncError::NoLeader);
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                Err(RaftError::APIError(ClientWriteError::ChangeMembershipError(e))) => {
                    return Err(SyncError::Raft(format!("change membership: {e}")));
                }
                Err(RaftError::Fatal(f)) => return Err(SyncError::Raft(format!("fatal: {f}"))),
            }
        }
    }

    /// Linearizable read (leader locally ensures; followers forward to the
    /// leader).
    pub async fn read_linearizable(&self, q: ReadQuery) -> Result<ReadView, SyncError> {
        let deadline = Instant::now() + self.settings.forward_deadline;
        loop {
            match self.raft.ensure_linearizable().await {
                Ok(_) => return Ok(crate::wire::read_view(&self.sm, q)),
                Err(RaftError::APIError(CheckIsLeaderError::ForwardToLeader(f))) => {
                    if let Some(leader) = f.leader_id.filter(|l| *l != self.id) {
                        if let Ok(WireResp::Read(r)) = self
                            .ic
                            .call(leader, WireRpc::Read(q.clone()), self.settings.rpc_timeout)
                            .await
                        {
                            return r;
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(SyncError::NoLeader);
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                Err(RaftError::APIError(CheckIsLeaderError::QuorumNotEnough(e))) => {
                    if Instant::now() >= deadline {
                        return Err(SyncError::Raft(format!("quorum: {e}")));
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                Err(RaftError::Fatal(f)) => return Err(SyncError::Raft(format!("fatal: {f}"))),
            }
        }
    }

    /// Ticket issuer (the key root is inside Raft state; None before
    /// Bootstrap).
    pub fn ticket_issuer(&self) -> Option<TicketIssuer> {
        self.sm.ticket_root().map(|r| TicketIssuer::from_root(&r))
    }

    fn next_ticket_seq(&self) -> u64 {
        self.ticket_seq.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// Server synchronization facade.
pub struct SyncNode {
    pub(crate) inner: Arc<NodeInner>,
    pub(crate) dir: Arc<SyncDirectory>,
}

impl SyncNode {
    /// Node id.
    pub fn id(&self) -> NodeId {
        self.inner.id
    }

    /// NetState write operations (enter at any node; auto-forwarded to the
    /// leader).
    pub async fn write(&self, req: SyncRequest) -> Result<SyncResponse, SyncError> {
        self.inner.write(req).await
    }

    /// Linearizable read (enter at any node).
    pub async fn read_linearizable(&self, q: ReadQuery) -> Result<ReadView, SyncError> {
        self.inner.read_linearizable(q).await
    }

    /// DeviceDirectory seam handle (injected into session::respond).
    pub fn device_directory(&self) -> DirHandle {
        DirHandle(self.dir.clone())
    }

    /// The directory itself (for stats / cache invalidation).
    pub fn dir(&self) -> &Arc<SyncDirectory> {
        &self.dir
    }

    /// Current leader (metrics view; None = election in progress).
    pub async fn current_leader(&self) -> Option<NodeId> {
        self.inner.raft.current_leader().await
    }

    /// Wait for a leader to appear (tests/assembly).
    pub async fn wait_leader(&self, budget: Duration) -> Option<NodeId> {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if let Some(l) = self.inner.raft.current_leader().await {
                return Some(l);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    }

    /// Local epoch (advances with apply).
    pub fn local_epoch(&self) -> u64 {
        self.inner.sm.epoch()
    }

    /// apply-lag breaker state.
    pub fn breaker_open(&self) -> bool {
        self.inner.lag.breaker_open()
    }

    /// The lease table (publish/observe; conflicts newest-wins + old-side
    /// eviction callbacks).
    pub fn lease(&self) -> &Arc<LeaseTable> {
        &self.inner.lease
    }

    /// Issue a local ticket (TTL 60s, bound to device + the current local
    /// epoch).
    pub fn issue_ticket(
        &self,
        device: [u8; 32],
        now_unix: u64,
    ) -> Result<crate::ticket::Ticket, SyncError> {
        let issuer = self
            .inner
            .ticket_issuer()
            .ok_or(SyncError::Raft("not bootstrapped".into()))?;
        Ok(issuer.issue(
            device,
            self.inner.sm.epoch(),
            now_unix,
            self.inner.next_ticket_seq(),
        ))
    }

    /// Verify a ticket (against this machine's current epoch — §2.2-3
    /// outstanding-ticket rejection semantics).
    pub fn verify_ticket(
        &self,
        t: &crate::ticket::Ticket,
        device: &[u8; 32],
        now_unix: u64,
    ) -> Result<(), crate::ticket::TicketError> {
        let issuer = self
            .inner
            .ticket_issuer()
            .ok_or(crate::ticket::TicketError::BadSignature)?;
        issuer.verify(t, device, self.inner.sm.epoch(), now_unix)
    }

    /// Publish a local device lease (gossip event broadcast ≤1s + anti-entropy
    /// backstop + TTL/3 refresh loop).
    pub async fn publish_lease(&self, device: &[u8; 32]) -> Option<NodeId> {
        let prev = self.inner.lease.publish(device);
        broadcast_publish(&self.inner.ic, &self.inner.lease, self.inner.id, *device);
        prev
    }

    /// Raft handle (**`test-util` profile only**: this crate's integration
    /// tests use `.raft().metrics()` from an external-crate viewpoint to
    /// assert membership convergence — tests/cluster, tests/admission etc.).
    ///
    /// Visibility convergence (review item 13): no bare Raft accessor exists
    /// in production builds — what external consumers (flock-server etc.)
    /// need is provided via allowlisted methods
    /// ([`SyncNode::membership_voters`]/[`SyncNode::raft_state` etc.]);
    /// in-crate code holds `inner.raft` directly.
    #[cfg(feature = "test-util")]
    pub fn raft(&self) -> &Raft<SyncConfig> {
        &self.inner.raft
    }

    /// The voter set of openraft's real membership (an allowlisted query —
    /// for external reconciliation, replacing the bare handle).
    pub fn membership_voters(&self) -> std::collections::BTreeSet<NodeId> {
        self.inner
            .raft
            .metrics()
            .borrow()
            .membership_config
            .voter_ids()
            .collect()
    }

    /// Raft metrics digest: this node's server state
    /// (Leader/Follower/Candidate/Learner).
    pub fn raft_state(&self) -> openraft::ServerState {
        self.inner.raft.metrics().borrow().state
    }

    /// The public part of this machine's enrollment credential (ServerEntry
    /// — the target of server_keys/rewrap wrapping etc.).
    pub fn entry(&self) -> &flock_protocol::session::ServerEntry {
        &self.inner.entry
    }

    /// Answer-side handshake rejection count (no credentials / forged
    /// credentials rejected at the handshake layer — the admission assertion
    /// surface).
    pub fn rejected_handshakes(&self) -> u64 {
        self.inner.ic.rejected_handshakes()
    }

    /// Interconnect diagnostics counters (dial ok/err, RPC ok/err — the M5
    /// troubleshooting surface).
    pub fn interconnect_diag(&self) -> (u64, u64, u64, u64) {
        self.inner.ic.diag()
    }

    // ------------------------------------------------------------------
    // Cluster admission (§4-3: learner → snapshot sync → add_voter root
    // signature → promotion; §3.10)
    // ------------------------------------------------------------------

    /// Install a new root-signed directory (root verification + version
    /// rollback rejection; interconnect mapping hot update — after admitting
    /// a new server, the whole network can dial it).
    pub fn install_directory(&self, dir: &ClusterDirectory) -> Result<(), SyncError> {
        self.inner
            .directory
            .install(dir)
            .map_err(|e| SyncError::Raft(format!("install directory: {e}")))?;
        self.inner
            .ic
            .update_nodes(self.inner.directory.node_entries());
        Ok(())
    }

    /// Directory service (dir_pull distributes the root-signed
    /// ClusterDirectory, §3.10 `Directory::serve`).
    pub fn directory(&self) -> &Arc<Directory> {
        &self.inner.directory
    }

    /// Join the cluster as a learner (called on the leader; blocking = wait
    /// for log/snapshot catch-up).
    pub async fn add_learner(&self, node_id: NodeId) -> Result<(), SyncError> {
        self.inner
            .raft
            .add_learner(
                node_id,
                openraft::BasicNode::new(format!("node-{node_id}")),
                true,
            )
            .await
            .map(|_| ())
            .map_err(|e| SyncError::Raft(format!("add_learner: {e}")))
    }

    /// Snapshot trigger + log purge (for the admission pipeline: forces the
    /// new learner down the snapshot-sync path).
    ///
    /// **Purge precondition**: purge only after the snapshot is confirmed on
    /// disk and covers `applied` — if the snapshot is not confirmed within
    /// the budget, return [`SyncError::Raft`] and **skip the purge** (purging
    /// logs below an unpersisted snapshot = state loss after restart;
    /// openraft's `get_snapshot` may return an old snapshot, hence the check
    /// that its boundary ≥ applied).
    pub async fn snapshot_and_purge(&self) -> Result<u64, SyncError> {
        let applied = self.inner.sm.applied_index();
        if applied == 0 {
            // Purging an empty log is pointless (and there is no state to
            // lose).
            return Ok(0);
        }
        self.inner
            .raft
            .trigger()
            .snapshot()
            .await
            .map_err(|e| SyncError::Raft(format!("trigger snapshot: {e}")))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let confirmed = loop {
            let snap_idx = self
                .inner
                .raft
                .get_snapshot()
                .await
                .ok()
                .flatten()
                .and_then(|s| s.meta.last_log_id.map(|l| l.index));
            if snap_idx.is_some_and(|i| i >= applied) {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        if !confirmed {
            return Err(SyncError::Raft(format!(
                "snapshot covering index {applied} not confirmed within 5s; purge skipped"
            )));
        }
        self.inner
            .raft
            .trigger()
            .purge_log(applied)
            .await
            .map_err(|e| SyncError::Raft(format!("purge: {e}")))?;
        Ok(applied)
    }

    /// The add_voter administrative operation (§4-3): first commit the
    /// root-signed AdminOp::AddVoter through the Raft state machine (after
    /// verification it records voters + config_version), then perform the
    /// openraft membership promotion (joint consensus). A state-machine
    /// rejection (no root signature / not bootstrapped) ⇒ no promotion; the
    /// rejection response returned as-is.
    ///
    /// **Pre-promotion reconciliation**: the state machine's voters and
    /// openraft's real membership (`raft.metrics()`) are two sources of truth
    /// and can drift (missed membership entries / a partially completed
    /// promotion). On drift (beyond the node_id being added here), warn and
    /// **merge on the basis of the real membership** (union — admin
    /// admissions already committed in the state machine are not lost, and
    /// voters openraft already has are not wrongly deleted; the old
    /// implementation looked only at the state-machine copy and would
    /// silently drop voters or resurrect dead nodes on drift).
    pub async fn add_voter_signed(
        &self,
        root: &ed25519_dalek::SigningKey,
        node_id: NodeId,
    ) -> Result<SyncResponse, SyncError> {
        let resp = self
            .write(SyncRequest::add_voter_signed(root, node_id))
            .await?;
        if matches!(resp, SyncResponse::Error(_)) {
            return Ok(resp);
        }
        // The real membership (openraft metrics — the member set Raft actually
        // consensus-agrees on).
        let real: std::collections::BTreeSet<NodeId> = self
            .inner
            .raft
            .metrics()
            .borrow()
            .membership_config
            .voter_ids()
            .collect();
        let sm: std::collections::BTreeSet<NodeId> = self.inner.sm.with_data(|d| d.voters.clone());
        let drift: Vec<NodeId> = real
            .symmetric_difference(&sm)
            .copied()
            .filter(|id| *id != node_id)
            .collect();
        if !drift.is_empty() {
            eprintln!(
                "add_voter: SM voters and openraft membership diverged ({drift:?}) — \
                 merging the promotion set on the basis of the real membership"
            );
        }
        let mut voters = real;
        voters.extend(sm);
        voters.insert(self.inner.id);
        voters.insert(node_id);
        self.inner
            .raft
            .change_membership(openraft::ChangeMembers::ReplaceAllVoters(voters), false)
            .await
            .map_err(|e| SyncError::Raft(format!("change membership: {e}")))?;
        Ok(resp)
    }

    // ------------------------------------------------------------------
    // Forwarding plane + leases (§2.2/§3.10)
    // ------------------------------------------------------------------

    /// The forwarding plane (local delivery / cross-server forwarding /
    /// source VIP verification).
    pub fn forward(&self) -> &Arc<ForwardPlane> {
        &self.inner.forward
    }

    /// Attach a local device session delivery sink (the assembly layer maps
    /// the PacketChannel).
    pub fn attach_session(&self, device: [u8; 32], sink: Arc<dyn PacketSink>) {
        self.inner.forward.attach_session(device, sink);
    }

    /// Detach a local device session.
    pub fn detach_session(&self, device: &[u8; 32]) {
        self.inner.forward.detach_session(device);
    }

    /// Session ingress processing (§2.2 forwarding decision order; called by
    /// the assembly layer after reading from the PacketChannel).
    pub async fn ingest_packet(
        &self,
        device: &[u8; 32],
        pkt: &[u8],
    ) -> crate::forward::IngestResult {
        self.inner.forward.ingest(device, pkt).await
    }

    /// Attach the local kernel (the server's own peer surface, §2.2): `vip` =
    /// the local tun VIP, `sink` = the tun write pump. Inbound packets with
    /// dst = own VIP are injected into the kernel (the local-server path of
    /// A2 ping / A4 iperf).
    pub fn set_local_peer(
        &self,
        vip: std::net::Ipv4Addr,
        sink: Arc<dyn crate::forward::PacketSink>,
    ) {
        self.inner.forward.set_local_peer(vip, sink);
    }

    /// Local kernel egress (tun read pump output: ICMP return path / local
    /// protocol-stack traffic) routed into the mesh.
    pub async fn route_outbound(&self, pkt: &[u8]) {
        self.inner.forward.route_outbound(pkt).await
    }

    /// One-shot location inquiry (local lease domain first; fan-out ≤3
    /// interconnected servers).
    pub async fn location_query(&self, device: &[u8; 32]) -> Option<NodeId> {
        let fanout = IcLocateFanout {
            ic: self.inner.ic.clone(),
            me: self.inner.id,
        };
        self.inner.lease.location_query(device, &fanout).await
    }

    /// The SM core (**`test-util` profile only**: the observation surface of
    /// this crate's integration tests — the lag injector (the apply-lag
    /// breaker case in tests/cluster) / VIP reverse-lookup assertions etc.
    /// Review item 13 convergence: no bare SM accessor exists in production
    /// builds — what externals (flock-server) need is obtained via the
    /// allowlisted methods below (register_hook/oprf_b64/local_wrap), no more
    /// reaching straight into the state machine core.
    #[cfg(feature = "test-util")]
    pub fn sm(&self) -> &Arc<SmCore> {
        &self.inner.sm
    }

    /// Register an apply/lease hook (the post-build equivalent of
    /// [`SyncNodeBuilder::hook`] — the assembly layer (flock-server
    /// `open_sync`) only obtains the sessions/node handles needed by hooks
    /// after the node is built, so not everything can be front-loaded into
    /// the builder; review item 13 allowlisted method).
    pub fn register_hook(&self, h: Arc<dyn SyncHooks>) {
        self.inner.sm.register_hook(h);
    }

    /// The cluster-shared OPRF key (b64; the locally applied view; not
    /// registered ⇒ None). (Review item 13: the allowlisted form of the old
    /// `sm().oprf_b64()`.)
    pub fn oprf_b64(&self) -> Option<String> {
        self.inner.sm.oprf_b64()
    }

    /// M7 (§7-M7.4): registry snapshot — **the locally applied view** (the
    /// two-tier cache profile suffices; a linearizable read is not forced:
    /// the roster is a display surface, tolerating seconds of staleness in a
    /// follower's view). Review item 13 allowlisted method (externals do not
    /// fetch the full table through a bare SM accessor).
    pub fn devices_snapshot(&self) -> Vec<([u8; 32], crate::proto::DeviceRow)> {
        self.inner
            .sm
            .with_data(|d| d.devices.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    /// M8 (§7-M8.4 `/api/users`·`/api/dashboard/summary`): user table
    /// snapshot — the locally applied view (display-surface tier, same
    /// consistency level as [`SyncNode::devices_snapshot`]).
    pub fn users_snapshot(&self) -> Vec<(String, crate::proto::UserRow)> {
        self.inner.sm.with_data(|d| {
            d.users
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
    }

    /// M7 (§7-M7.4): server_keys snapshot (the locally applied view — the
    /// data source of the roster Server entry's vip/node id).
    pub fn server_keys_snapshot(&self) -> Vec<(NodeId, crate::proto::ServerKeyEntry)> {
        self.inner
            .sm
            .with_data(|d| d.server_keys.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    /// A server's secrets-rewrap wrapped copy within this machine's applied
    /// view (the OPRF wrapping surface: at startup each server fetches its
    /// own wrap and unwraps it with its local hybrid sk; None = that server's
    /// wrap has not been applied on this node yet).
    pub fn local_wrap(&self, server_id: NodeId) -> Option<Vec<u8>> {
        self.inner
            .sm
            .with_data(|d| d.wraps.get(&server_id).cloned())
    }

    /// Shut down (Raft shutdown; the interconnect fabric is managed
    /// externally).
    pub async fn shutdown(&self) -> Result<(), SyncError> {
        self.inner
            .raft
            .shutdown()
            .await
            .map_err(|e| SyncError::Raft(format!("shutdown: {e}")))
    }
}
