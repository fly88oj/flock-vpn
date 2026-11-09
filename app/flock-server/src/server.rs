//! Server assembly core (docs/design.md §2.2/§3.11).
//!
//! Responsibility chain: access (one E2E session per inbound connection,
//! `session::respond` + the redb NetState directory adapter) →
//! authentication (control-flow OPAQUE login + anchor) → registry
//! (NetState) → sessions (tickets/kill sessions) → (M4:
//! forwarding/sync).
//!
//! Revocation propagation bound (§2.2, single-machine form): revoke
//! advances the revocation_epoch **inside the same process** + kills that
//! device's local sessions ([`LiveSessions::kill`]); "ticket epoch <
//! current epoch ⇒ reject" backstops cross-connection replay.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

use flock_protocol::ed25519_dalek::{Signer, SigningKey};
use flock_protocol::kem::HybridKeypair;
use flock_protocol::pake::{server_setup_load, server_setup_new, Suite};
use flock_protocol::rand;
use flock_protocol::session::{
    respond, sign_server_entry, ClusterId, DeviceId, ServerEntry, ServerId, ServerIdentity,
    TunnelConfig,
};
use flock_protocol::trust::ClusterDirectory;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::backend::NetBackend;
use crate::config::{ListenerMode, ServerConfig};
use crate::control::{serve_control, CtrlGuard};
use crate::dataplane::PeerRouter;
use crate::netstate::{DirAdapter, StateStore};
use crate::ticket::TicketIssuer;

/// META keys (cluster identity material + ticket root seed; a one-time
/// bootstrap write).
mod keys {
    pub const ROOT_SEED: &str = "root_seed";
    pub const IDENTITY_SEED: &str = "identity_seed";
    pub const HYBRID_SK: &str = "hybrid_sk";
    pub const CLUSTER_ID: &str = "cluster_id";
    pub const SERVER_ID: &str = "server_id";
    pub const OPRF_B64: &str = "oprf_b64";
    pub const TICKET_SEED: &str = "ticket_seed";
}

/// Session-layer keepalive (the record-layer PING/PONG period;
/// flock-protocol session::KEEPALIVE = 10s).
const KEEPALIVE: std::time::Duration = flock_protocol::session::KEEPALIVE;
/// E2E handshake budget (review item 8): a timeout is rejected as a class.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// TCP keepalive (best-effort —— failure only loses one layer of dead-link
/// detection, no functional impact).
fn set_tcp_keepalive(io: &TcpStream) {
    let sock = socket2::SockRef::from(io);
    let ka = socket2::TcpKeepalive::new().with_time(KEEPALIVE);
    // Probe interval aligned with the session-layer keepalive (10s); probe
    // count uses the kernel default.
    #[cfg(any(unix, windows))]
    let ka = ka.with_interval(KEEPALIVE);
    let _ = sock.set_tcp_keepalive(&ka);
}

/// Per-device local session table (kill on revocation, the single-machine
/// counterpart of the §2.2 apply-callback semantics).
///
/// kill broadcasts via `watch` (state retained; no events lost in
/// register/notify races); the session task consumes it in a `serve_conn`
/// select arm and tears down the tunnel.
#[derive(Default)]
pub struct LiveSessions {
    inner: Mutex<std::collections::HashMap<[u8; 32], Vec<tokio::sync::watch::Sender<bool>>>>,
}

impl LiveSessions {
    /// Register (the session task); `pub` —— the M7 roster unit tests and
    /// the M8 webui integration tests drive the "online" state (the only
    /// registration surface outside serve_conn serves tests).
    pub fn register(&self, device: [u8; 32]) -> tokio::sync::watch::Receiver<bool> {
        let (tx, rx) = tokio::sync::watch::channel(false);
        self.inner
            .lock()
            .expect("live sessions poisoned")
            .entry(device)
            .or_default()
            .push(tx);
        rx
    }

    fn deregister(&self, device: [u8; 32]) {
        let mut g = self.inner.lock().expect("live sessions poisoned");
        if let Some(v) = g.get_mut(&device) {
            v.retain(|tx| !tx.is_closed());
            if v.is_empty() {
                g.remove(&device);
            }
        }
    }

    /// Kill all local sessions of this device (called by the control
    /// flow/admin after revoke/disable).
    pub fn kill(&self, device: &[u8; 32]) {
        if let Some(senders) = self
            .inner
            .lock()
            .expect("live sessions poisoned")
            .remove(device)
        {
            for tx in senders {
                let _ = tx.send(true);
            }
        }
    }

    /// Online session count of a device (diagnostics/tests).
    pub fn online(&self, device: &[u8; 32]) -> usize {
        self.inner
            .lock()
            .expect("live sessions poisoned")
            .get(device)
            .map(|v| v.iter().filter(|tx| !tx.is_closed()).count())
            .unwrap_or(0)
    }

    /// Number of online devices (the M5 assertion surface: admin stats'
    /// sessions_online).
    pub fn device_count(&self) -> usize {
        self.inner.lock().expect("live sessions poisoned").len()
    }
}

/// Multi-primary apply/lease hooks (the §2.2 revocation propagation bound +
/// vpn-mesh §5.2 lease conflicts).
///
/// Each server triggers them **at its own log apply site**: (a) kill the
/// device's local sessions (watch broadcast → serve_conn tears down the
/// tunnel); (b) ticket rejection is carried by "ticket epoch < current
/// epoch ⇒ reject" (TicketAuthority verifies against the locally-applied
/// epoch).
#[cfg(feature = "multi-primary")]
struct ServerSyncHooks {
    sessions: Arc<LiveSessions>,
    node: Arc<flock_sync::SyncNode>,
}

#[cfg(feature = "multi-primary")]
impl flock_sync::hooks::SyncHooks for ServerSyncHooks {
    fn on_revocation_applied(&self, ev: flock_sync::hooks::RevocationEvent) {
        eprintln!(
            "flock-server: revocation applied (epoch={}, log={}) killing local sessions",
            ev.new_epoch, ev.log_index
        );
        self.sessions.kill(&ev.device);
        self.node.detach_session(&ev.device);
    }
    fn on_lease_evicted(&self, device: &[u8; 32]) {
        // Lease conflict, newest wins (the device has moved to another
        // server): the old end is kicked (§3.10 LeaseTable).
        eprintln!("flock-server: lease evicted (device moved) killing local session");
        self.sessions.kill(device);
    }
}

// ============================================================================
// OPRF key per-server sealing (review item 2: design §2.4 "encrypt-sealed
// to each server's hybrid public key")
// ============================================================================

/// The transient-error prefix of `open_sync` (sync.rs's ready-retry loop
/// distinguishes "not ready, retryable" from "permanent error, propagate
/// now" by it).
#[cfg(feature = "multi-primary")]
pub const SYNC_NOT_READY_PREFIX: &str = "cluster not ready: ";

/// Seal the OPRF key (a b64 ServerSetup) to one server's hybrid public key
/// with envelope v2.
///
/// The product is the `wrapped` of `AdminOp::Rewrap { server_id, wrapped }`
/// —— the Raft state machine stores only the sealed bytes (the plaintext
/// never appears in any persistent layer); both the recipient server's
/// `server_keys` registration and the rewrap submission require the cluster
/// root key's signature (the §4-3 red line: a single compromised server
/// cannot self-grant or re-seal).
#[cfg(feature = "multi-primary")]
pub fn seal_oprf_wrap(
    oprf_b64: &str,
    recipient: &flock_protocol::kem::HybridPubkey,
) -> Result<Vec<u8>, String> {
    let mut sealed = Vec::new();
    flock_protocol::envelope::seal_v2(
        recipient,
        std::io::Cursor::new(oprf_b64.as_bytes()),
        &mut sealed,
    )
    .map_err(|e| format!("envelope seal: {e}"))?;
    Ok(sealed)
}

/// The inverse of [`seal_oprf_wrap`]: unseal with the local hybrid sk to
/// retrieve the OPRF b64 (in-memory use only). An error = recipient
/// mismatch / corrupted seal / plaintext not UTF-8 —— for the server that
/// means "OPAQUE unavailable".
#[cfg(feature = "multi-primary")]
pub fn open_oprf_wrap(
    sk: &flock_protocol::kem::HybridKeypair,
    wrapped: &[u8],
) -> Result<String, String> {
    let mut plain = Vec::new();
    flock_protocol::envelope::open_v2(sk, std::io::Cursor::new(wrapped), &mut plain)
        .map_err(|e| format!("envelope open: {e}"))?;
    String::from_utf8(plain).map_err(|_| "oprf plaintext is not UTF-8".to_string())
}

/// The server core (built at assembly time; Arc-shared with the accept/admin
/// tasks).
pub struct ServerCore {
    pub cfg: ServerConfig,
    /// The read/write backend (§2.2/§3.11): Single = local redb (the M2
    /// form); Sync = flock-sync Raft (feature `multi-primary` ——
    /// leader-forwarding writes / linearizable reads / two-level-read
    /// directory).
    pub net: NetBackend,
    /// Cluster root signing key (single server = the in-store root;
    /// multi-primary = **None** —— the root key is kept offline, directory/
    /// invite issuance goes through the operations-side init-cluster flow,
    /// servers hold only root_pub).
    pub root: Option<SigningKey>,
    pub identity: ServerIdentity,
    /// The OPAQUE server-side OPRF key (§2.4: resident; rotation voids all
    /// pass.opaque. Multi-primary form = shared inside Raft (SetOprf
    /// root-signed registration) —— OPAQUE records verifiable
    /// network-wide).
    pub oprf: flock_protocol::opaque_ke::ServerSetup<Suite>,
    /// Ticket authority (Local = the state-store seed; Sync = the ticket
    /// root inside Raft, verifiable by any server).
    pub guard: CtrlGuard,
    /// Local session table (Arc: shared with the SyncHooks assembly side ——
    /// apply-callback session kills / lease-conflict kicks).
    pub sessions: Arc<LiveSessions>,
    /// M7: the single-server traffic meter (per-VIP EWMA/last_seen —— the
    /// roster data source; multi-primary uses the lease table, this meter
    /// serves only single-server PeerRouter counting). The 1s tick is driven
    /// by the task assembled in [`run`].
    pub traffic: Arc<flock_sync::lease::TrafficMeter>,
    /// Multi-primary sync node (feature `multi-primary`; single-server =
    /// None).
    #[cfg(feature = "multi-primary")]
    pub sync: Option<Arc<flock_sync::SyncNode>>,
    /// M3 data-plane router (injected by run() after assembling the tun;
    /// None = control-flow-only —— the host-test path).
    router: RwLock<Option<Arc<PeerRouter>>>,
}

impl ServerCore {
    /// The current data-plane router (unassembled ⇒ None).
    pub fn router(&self) -> Option<Arc<PeerRouter>> {
        self.router.read().expect("router lock poisoned").clone()
    }

    /// Assemble the data plane (tun + routes; a failure degrades and logs
    /// inside [`PeerRouter::open`]).
    pub fn set_router(&self, router: Arc<PeerRouter>) {
        *self.router.write().expect("router lock poisoned") = Some(router);
    }

    /// Post-registration admission for the revoke-register race (review
    /// item 5): a second directory verdict after `sessions.register` ——
    /// there is a millisecond-scale window between `respond`'s first lookup
    /// and the register; when a revoke lands inside the window the kill
    /// broadcast misses, and this verdict backstops by tearing down the
    /// connection. false ⇒ the caller tears down the tunnel.
    pub async fn post_register_admission(&self, device: &DeviceId) -> bool {
        matches!(
            self.net.lookup(device).await,
            flock_protocol::session::LookupVerdict::Active(_)
        )
    }
}

impl ServerCore {
    /// Open the existing state or bootstrap a new cluster
    /// (`init-cluster` semantics; already initialized loads as-is). Returns
    /// `(core, created)`.
    pub fn open_or_init(cfg: ServerConfig) -> Result<(Arc<Self>, bool), String> {
        // Single-server VIP validation (the other half of the
        // server_vip_of consistency surface): cfg.vip must not fall inside
        // the device allocation segment (VIP_FIRST..=VIP_LAST) —— the
        // server's own VIP colliding with the device pool means the first
        // device registration gets the same IP, misaligning routing/roster/
        // source VIP validation wholesale. The server itself uses
        // 100.64.0.1 (§2.2).
        let vip_u32 = u32::from(cfg.vip);
        if (crate::netstate::VIP_FIRST..=crate::netstate::VIP_LAST).contains(&vip_u32) {
            let lo = std::net::Ipv4Addr::from(crate::netstate::VIP_FIRST);
            let hi = std::net::Ipv4Addr::from(crate::netstate::VIP_LAST);
            return Err(format!(
                "cfg.vip {} falls inside the device allocation segment {lo}..={hi} (VIP_FIRST..=VIP_LAST) - \
                 the server's own VIP colliding with the device pool is a conflict; refusing to start (the server itself uses 100.64.0.1)",
                cfg.vip
            ));
        }
        let db_path = cfg.state_dir.join("netstate.redb");
        let store = StateStore::open(&db_path).map_err(|e| e.to_string())?;
        let created = store.meta_get(keys::CLUSTER_ID).is_none();

        let cluster_id: ClusterId = match store.meta_get(keys::CLUSTER_ID) {
            Some(b) => ClusterId(b.try_into().map_err(|_| "cluster_id length")?),
            None => {
                let v: [u8; 16] = rand::random();
                store
                    .meta_put(keys::CLUSTER_ID, &v)
                    .map_err(|e| e.to_string())?;
                ClusterId(v)
            }
        };
        let server_id: ServerId = match store.meta_get(keys::SERVER_ID) {
            Some(b) => ServerId(b.try_into().map_err(|_| "server_id length")?),
            None => {
                let v: [u8; 16] = rand::random();
                store
                    .meta_put(keys::SERVER_ID, &v)
                    .map_err(|e| e.to_string())?;
                ServerId(v)
            }
        };
        let root = match store.meta_get(keys::ROOT_SEED) {
            Some(b) => SigningKey::from_bytes(&b.try_into().map_err(|_| "root_seed length")?),
            None => {
                let seed: [u8; 32] = rand::random();
                store
                    .meta_put(keys::ROOT_SEED, &seed)
                    .map_err(|e| e.to_string())?;
                SigningKey::from_bytes(&seed)
            }
        };
        let identity = match store.meta_get(keys::IDENTITY_SEED) {
            Some(b) => SigningKey::from_bytes(&b.try_into().map_err(|_| "identity_seed length")?),
            None => {
                let seed: [u8; 32] = rand::random();
                store
                    .meta_put(keys::IDENTITY_SEED, &seed)
                    .map_err(|e| e.to_string())?;
                SigningKey::from_bytes(&seed)
            }
        };
        let static_hybrid = match store.meta_get(keys::HYBRID_SK) {
            Some(b) => {
                let sk: [u8; 96] = b.try_into().map_err(|_| "hybrid_sk length")?;
                HybridKeypair::from_bytes(&sk).map_err(|e| e.to_string())?
            }
            None => {
                let kp = HybridKeypair::generate(&mut rand::rngs::OsRng);
                store
                    .meta_put(keys::HYBRID_SK, &kp.to_bytes())
                    .map_err(|e| e.to_string())?;
                kp
            }
        };
        let oprf = match store.meta_get(keys::OPRF_B64) {
            Some(b) => {
                let s = String::from_utf8(b).map_err(|_| "oprf_b64 encoding")?;
                server_setup_load(&s).map_err(|e| format!("oprf key: {e}"))?
            }
            None => {
                let b64 = server_setup_new(&mut rand::rngs::OsRng);
                store
                    .meta_put(keys::OPRF_B64, b64.as_bytes())
                    .map_err(|e| e.to_string())?;
                server_setup_load(&b64).map_err(|e| format!("oprf key: {e}"))?
            }
        };
        let ticket_seed: [u8; 32] = match store.meta_get(keys::TICKET_SEED) {
            Some(b) => b.try_into().map_err(|_| "ticket_seed length")?,
            None => {
                let s = TicketIssuer::generate_seed();
                store
                    .meta_put(keys::TICKET_SEED, &s)
                    .map_err(|e| e.to_string())?;
                s
            }
        };

        // ServerEntry (the advertise endpoint; the root re-signs entry_sig
        // —— the root key is in-store, deterministic reconstruction).
        let entry = ServerEntry {
            server_id,
            relay_endpoint: cfg.advertise_endpoint.clone(),
            identity_pub: identity.verifying_key(),
            static_hybrid_pub: static_hybrid.public(),
        };
        let sid = ServerIdentity {
            cluster_id,
            server_id,
            identity,
            static_hybrid,
            entry: entry.clone(),
            root_pub: root.verifying_key(),
            entry_sig: sign_server_entry(&root, &cluster_id, &entry),
        };

        let core = ServerCore {
            cfg,
            net: NetBackend::Single(Arc::new(store)),
            root: Some(root),
            identity: sid,
            oprf,
            guard: CtrlGuard::new(crate::ticket::TicketAuthority::Local(Box::new(
                TicketIssuer::from_seed(ticket_seed),
            ))),
            sessions: Arc::new(LiveSessions::default()),
            traffic: flock_sync::lease::TrafficMeter::new(),
            #[cfg(feature = "multi-primary")]
            sync: None,
            router: RwLock::new(None),
        };
        Ok((Arc::new(core), created))
    }

    /// Multi-primary assembly (feature `multi-primary`; the §2.2/§3.11 M4
    /// batch).
    ///
    /// - Directory = [`flock_sync::SyncNode::device_directory`] injected
    ///   into `session::respond` (two-level read: record cache + epoch +
    ///   apply-lag breaker degrading to linearizable reads, §4);
    /// - Ticket root = inside Raft state (Bootstrap persists it);
    /// - OPRF key = **sealed per server inside Raft state** (§2.4
    ///   "encrypt-sealed to each server's hybrid public key" —— envelope
    ///   v2 sealed to every on-record server, the state machine stores only
    ///   wraps (AdminOp::Rewrap); at startup this node unseals into memory
    ///   with its own hybrid sk, an unsealing failure ⇒ OPAQUE unavailable
    ///   with an explicit error, review item 2);
    /// - Revocations/lease conflicts kill local sessions at the apply site
    ///   via [`flock_sync::hooks::SyncHooks`] (§2.2).
    ///
    /// Preconditions: the cluster has Bootstrap + ServerKeys registered +
    /// this server's Rewrap persisted —— done by `cluster-bootstrap` (the
    /// root-key side) or the assembling side (tests/multi_primary.rs).
    #[cfg(feature = "multi-primary")]
    pub async fn open_sync(
        cfg: ServerConfig,
        ident: Arc<ServerIdentity>,
        node: Arc<flock_sync::SyncNode>,
    ) -> Result<Arc<Self>, String> {
        Self::open_sync_with_wait(cfg, ident, node, std::time::Duration::from_secs(15)).await
    }

    /// The adjustable-wait variant of [`ServerCore::open_sync`] (tests use
    /// a short window to verify "no wrap ⇒ explicit failure"; error
    /// convention: transient errors start with [`SYNC_NOT_READY_PREFIX`] ——
    /// the sync.rs retry loop retries only that class, permanent errors
    /// (wrap unsealing failures etc.) propagate immediately).
    #[cfg(feature = "multi-primary")]
    pub async fn open_sync_with_wait(
        cfg: ServerConfig,
        ident: Arc<ServerIdentity>,
        node: Arc<flock_sync::SyncNode>,
        wait: std::time::Duration,
    ) -> Result<Arc<Self>, String> {
        // This node's node_id (the wrap's key = node_id_of(server_id) —— the
        // same key as ServerKeys/Rewrap).
        let my_node = flock_sync::node::node_id_of(&ident.server_id);
        // server_vip_of consistency assertion (the §6.2 server segment .1–
        // .10 deterministic derivation): cfg.vip must equal the derived
        // value for this node_id —— both the root-signed ServerKeys
        // registration and the roster Server entries use the derived value,
        // and configuration drift would misalign routing/rosters as
        // "registered VIP ≠ locally configured VIP". Mismatch ⇒ refuse to
        // start, the error names the expected value (a permanent error ——
        // not the SYNC_NOT_READY prefix; the ready-retry loop must not
        // swallow it).
        match flock_sync::proto::server_vip_of(my_node) {
            Some(expected) if expected == cfg.vip.octets() => {}
            Some(expected) => {
                let want = std::net::Ipv4Addr::from(expected);
                return Err(format!(
                    "cfg.vip {my_vip} does not match the deterministic server VIP {want} of node {my_node} \
                     (the §6.2 server segment .1–.10 — ServerKeys registration and the roster Server entries both use the derived value) \
                     — refusing to start; change vip to {want}",
                    my_vip = cfg.vip
                ));
            }
            None => {
                return Err(format!(
                    "node_id {my_node} is outside the reserved server VIP segment (1..=10) - no server VIP can be derived \
                     (server_vip_of); refusing to start"
                ));
            }
        }
        // Wait for this server's OPRF wrap to apply on this node (the
        // Bootstrap → ServerKeys → Rewrap submission order ⇒ wrap visibility
        // implies Bootstrap/ticket-root readiness). Capabilities go through
        // SyncNode whitelisted methods (review item 13).
        let deadline = std::time::Instant::now() + wait;
        let wrapped = loop {
            if let Some(w) = node.local_wrap(my_node) {
                break w;
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "{SYNC_NOT_READY_PREFIX}no OPRF wrap for this server (node {my_node}) seen within {wait:?} \
                     (AdminOp::Rewrap not applied on this node — cluster-bootstrap must register each server's \
                     hybrid public key via ServerKeys and rewrap them one by one)"
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        };
        // Unseal with the local hybrid sk (review item 2: the plaintext
        // lives only in memory —— never persisted into Raft state/the state
        // store).
        let oprf_b64 = open_oprf_wrap(&ident.static_hybrid, &wrapped).map_err(|e| {
            format!(
                "OPRF wrap unsealing failed (local hybrid private key does not match the wrap, or the seal is corrupted) - \
                 OPAQUE unavailable: {e}"
            )
        })?;
        let oprf = flock_protocol::pake::server_setup_load(&oprf_b64)
            .map_err(|e| format!("cluster OPRF key: {e}"))?;
        let sessions = Arc::new(LiveSessions::default());
        node.register_hook(Arc::new(ServerSyncHooks {
            sessions: sessions.clone(),
            node: node.clone(),
        }));
        let src = &*ident;
        let identity = ServerIdentity {
            cluster_id: src.cluster_id,
            server_id: src.server_id,
            identity: flock_protocol::ed25519_dalek::SigningKey::from_bytes(
                &src.identity.to_bytes(),
            ),
            static_hybrid: flock_protocol::kem::HybridKeypair::from_bytes(
                &src.static_hybrid.to_bytes(),
            )
            .map_err(|e| e.to_string())?,
            entry: src.entry.clone(),
            root_pub: src.root_pub,
            entry_sig: src.entry_sig,
        };
        let core = ServerCore {
            cfg,
            net: NetBackend::Sync(crate::backend::SyncNetState::new(node.clone())),
            root: None,
            identity,
            oprf,
            guard: CtrlGuard::new(crate::ticket::TicketAuthority::Sync(node.clone())),
            sessions,
            traffic: flock_sync::lease::TrafficMeter::new(),
            sync: Some(node),
            router: RwLock::new(None),
        };
        Ok(Arc::new(core))
    }

    /// The root-signed cluster directory.
    ///
    /// - Single server: signed now (advertise + extras —— the same server's
    ///   other exposure openings; the root key is in-store);
    /// - Multi-primary: **the installed root-signed directory**
    ///   (network-wide distribution by init-cluster; the server holds no
    ///   root key and cannot self-sign).
    pub fn build_directory(&self) -> ClusterDirectory {
        #[cfg(feature = "multi-primary")]
        if let Some(node) = &self.sync {
            if let Some(dir) = node.directory().current() {
                return dir;
            }
        }
        self.local_directory()
    }

    /// The freshly-signed directory of the single-server form.
    fn local_directory(&self) -> ClusterDirectory {
        let mut servers = vec![self.identity.entry.clone()];
        for ep in &self.cfg.extra_endpoints {
            servers.push(ServerEntry {
                server_id: self.identity.server_id,
                relay_endpoint: ep.clone(),
                identity_pub: self.identity.identity.verifying_key(),
                static_hybrid_pub: self.identity.static_hybrid.public(),
            });
        }
        let root = self
            .root
            .as_ref()
            .expect("single-server form keeps the root key in-store (multi-primary returns via the installed directory)");
        ClusterDirectory::issue(
            root,
            self.identity.cluster_id,
            self.cfg.dir_version,
            servers,
        )
    }

    /// Mint an invite (the admin path; §1.3.3f invite generation = an admin
    /// operation in the root-key context).
    ///
    /// Multi-primary servers **hold no root key** ⇒ rejected (issuance goes
    /// through the operations-side init-cluster flow); invite registration
    /// (Raft RecordInvite) can still be done through the NetBackend.
    pub async fn mint_invite(&self, ttl_secs: u64) -> Result<Vec<u8>, String> {
        let Some(root) = &self.root else {
            return Err("invite minting in multi-primary form requires the cluster root key (an operations-side init-cluster product)".into());
        };
        let invite_id: [u8; 16] = rand::random();
        let expiry = flock_protocol::trust::now_unix() + ttl_secs;
        self.net
            .record_invite(&invite_id, expiry)
            .await
            .map_err(|e| e.to_string())?;
        let dir = self.build_directory();
        let inv = flock_protocol::trust::InviteFile::issue(
            root,
            self.identity.cluster_id,
            dir.dir_version,
            dir.servers.clone(),
            expiry,
            invite_id,
        );
        Ok(inv.to_bytes())
    }

    /// One inbound connection: E2E handshake (respond) → session
    /// registration (killable by revocation signals) → stream dispatch.
    ///
    /// Stream dispatch (M3): the **first** accepted yamux stream = the
    /// control flow (M2 semantics unchanged; the client, after initiate,
    /// first calls `open_stream(Prio::Control)` —— the ordering contract is
    /// in the flock-client connector); the remaining streams = data-plane
    /// packet channels ([`PeerRouter::serve_stream`]).
    pub async fn serve_conn(self: Arc<Self>, io: TcpStream) {
        // TCP keepalive (review item 8): set right after accepting —— the
        // interval aligned with the session-layer keepalive (10s). The
        // session layer's PING/PONG can only detect silence when "both sides
        // are sending"; when the peer machine dies outright or the NAT table
        // entry expires, this end's record-layer sends report no error while
        // the peer sends nothing back —— TCP keepalive lets the kernel error
        // out the link after 3×interval without ACK, so dead links do not
        // hold session slots.
        set_tcp_keepalive(&io);
        // respond's directory-injection dispatch: Single = the redb adapter;
        // Sync = flock-sync's two-level read (cache + epoch + apply-lag
        // breaker degrading to linearizable reads, §4 —— this batch's hookup
        // point). Wrapped in a 10s handshake budget (review item 8): a
        // timeout is rejected as a class —— a silently half-open connection
        // must not occupy session permits or thread surfaces (the same
        // log/behavior surface as protocol rejections).
        let handshake = match tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            match &self.net {
                NetBackend::Single(store) => {
                    respond(
                        io,
                        &self.identity,
                        DirAdapter(store.clone()),
                        TunnelConfig::default(),
                    )
                    .await
                }
                #[cfg(feature = "multi-primary")]
                NetBackend::Sync(s) => {
                    respond(
                        io,
                        &self.identity,
                        s.node.device_directory(),
                        TunnelConfig::default(),
                    )
                    .await
                }
            }
        })
        .await
        {
            Ok(h) => h,
            Err(_) => {
                eprintln!("flock-server: handshake rejected: timeout (> {HANDSHAKE_TIMEOUT:?})");
                return;
            }
        };
        let tunnel = match handshake {
            Ok(t) => t,
            Err(e) => {
                eprintln!("flock-server: handshake rejected: {e}");
                return;
            }
        };
        let Some(device) = tunnel.peer_device_id() else {
            return;
        };
        let mut kill = self.sessions.register(device.0);
        // Revoke-register race closure (review item 5): there is a
        // millisecond-scale window between respond's directory lookup and
        // the register here —— when a revoke lands exactly inside the
        // window the kill broadcast happens before the register (missed),
        // and the old implementation let the session survive silently. A
        // second lookup right after the register tears down the connection
        // unless Active.
        if !self.post_register_admission(&device).await {
            eprintln!(
                "flock-server: device not Active after session register \
                 (revoke raced the handshake) — dropping session"
            );
            self.sessions.deregister(device.0);
            tunnel.shutdown().await;
            return;
        }
        // This session device's registration row (the VIP = the data-plane
        // source-check/routing key; not found ⇒ control flow only).
        let device_row = self.net.device_row(&device).await;
        let device_vip = device_row.as_ref().map(|r| r.vip);
        // Multi-primary: publish the local lease (gossip events ≤1s +
        // anti-entropy backstop; the device's current location is the single
        // source of truth, §2.2-1).
        #[cfg(feature = "multi-primary")]
        if let Some(node) = &self.sync {
            let _ = node.publish_lease(&device.0).await;
        }
        let mut handlers = Vec::new();
        loop {
            tokio::select! {
                // Revoke/disable ⇒ kill the local session (§2.2): tearing
                // down the tunnel cuts the record layer/muxer.
                _ = kill.changed() => break,
                stream = tunnel.accept_stream() => match stream {
                    Some(s) => {
                        // Stream dispatch (M3): by yamux stream ID, not
                        // arrival order —— the client's first stream (id=1)
                        // = the control flow (M2 semantics); id≥3 =
                        // data-plane packet channels. Dispatching by ID is
                        // immune to yamux lazy SYN: when the control stream
                        // is silently held (the M3 client sends no control
                        // business) and never materializes, the first
                        // materializing data stream is not mis-dispatched to
                        // the control-flow handler.
                        if s.id() == 1 {
                            let core = self.clone();
                            handlers.push(tokio::spawn(async move {
                                let mut s = s;
                                let _ = serve_control(&core, device, &mut s).await;
                            }));
                        } else {
                            // Multi-primary: packet channels go through the
                            // flock-sync forwarding plane (attach_session
                            // sink + ingest: step-0 source VIP check → lease
                            // location → local delivery or ForwardEnvelope
                            // cross-server, the §2.2 decision order).
                            #[cfg(feature = "multi-primary")]
                            if let Some(node) = self.sync.clone() {
                                let dev = device.0;
                                handlers.push(tokio::spawn(async move {
                                    crate::dataplane::serve_stream_sync(node, dev, s).await;
                                }));
                                continue;
                            }
                            // Single server: the local router (tun
                            // injection/return path).
                            let router = self.router();
                            let has_router = router.is_some();
                            match (router, device_vip) {
                                (Some(router), Some(vip)) => {
                                    handlers.push(tokio::spawn(async move {
                                        router.serve_stream(vip, s).await;
                                    }));
                                }
                                // No data plane (host/no NET_ADMIN) or a
                                // missing registry row: drop the stream (the
                                // client's data plane observes channel EOF →
                                // backoff-reconnects; the control flow is
                                // unaffected).
                                _ => {
                                    eprintln!(
                                        "flock-server: data-plane stream dropped (router={has_router} vip={})",
                                        device_vip.is_some()
                                    );
                                    drop(s)
                                }
                            }
                        }
                    }
                    None => break,
                },
            }
        }
        // Graceful wind-down (order is critical —— **never abort the
        // data-plane tasks**): tear down the tunnel first (all streams close
        // ⇒ serve_stream/serve_stream_sync exit naturally and detach —— an
        // abort skips the detach, leaving dead sessions in forward.sessions;
        // the lease-renewal loop would repeatedly republish the leftovers as
        // online devices, fighting "lease wars" with the new holder and
        // kicking live sessions —— the root cause of the M5 e2e storm).
        let close_reason = tunnel.stats().closed;
        tunnel.shutdown().await;
        for h in handlers {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h).await;
        }
        // Session end reason (A9 server side: a silent dead link ⇒
        // "dead-link" greppable).
        let reason = close_reason;
        eprintln!(
            "flock-server: session ended device={device} reason={}",
            reason
                .map(|r| r.to_string())
                .unwrap_or_else(|| "none(io/fin)".into())
        );
        self.sessions.deregister(device.0);
    }

    /// Accept loop (one session task per inbound connection).
    ///
    /// Robustness (review item 7):
    /// - **transient accept errors tolerated**: EMFILE/ENFILE/ConnAborted/
    ///   WouldBlock/Interrupted etc. log + exponential backoff (50ms→1s
    ///   capped) then continue —— a single inbound failure no longer
    ///   permanently kills the inbound service; only unrecoverable errors
    ///   propagate up and out;
    /// - **concurrent session cap**: a Semaphore of `cfg.max_sessions`
    ///   (default 1024) permits —— inbound connections over the cap are
    ///   **politely closed right after acceptance** (FIN) and counted
    ///   ([`sessions_overlimit`], the admin stats surface).
    pub async fn serve_listener(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        let permits = Arc::new(tokio::sync::Semaphore::new(self.cfg.max_sessions.max(1)));
        let mut backoff_ms = 50u64;
        loop {
            let (mut io, _peer) = match listener.accept().await {
                Ok(a) => a,
                Err(e) if is_transient_accept_error(&e) => {
                    eprintln!(
                        "flock-server: transient accept error ({e}) - continuing in {backoff_ms}ms"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(1000);
                    continue;
                }
                Err(e) => return Err(e),
            };
            backoff_ms = 50;
            // Concurrency cap: when saturated, politely close after
            // accepting (the peer sees a FIN immediately instead of hanging
            // on the SYN queue).
            let permit = match permits.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    SESSIONS_OVERLIMIT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    eprintln!(
                        "flock-server: concurrent session cap {} saturated - politely closing new inbound connection and counting",
                        self.cfg.max_sessions
                    );
                    let _ = io.shutdown().await;
                    continue;
                }
            };
            let core = self.clone();
            tokio::spawn(async move {
                let _permit = permit; // the permit is held for the session task's lifetime
                core.serve_conn(io).await;
            });
        }
    }
}

/// Cumulative inbound connections politely closed at the concurrency cap
/// (the admin stats surface, review item 7).
pub fn sessions_overlimit() -> u64 {
    SESSIONS_OVERLIMIT.load(std::sync::atomic::Ordering::Relaxed)
}

static SESSIONS_OVERLIMIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Transient accept-error verdict (review item 7): resource exhaustion /
/// peer closed first / blockable-restartable classes —— log, back off,
/// continue; the rest (a dead listen handle etc.) is treated as
/// unrecoverable.
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionAborted | ConnectionReset | WouldBlock | Interrupted | NotConnected
    ) || {
        // EMFILE(24)/ENFILE(23): fd-table exhaustion —— the classic
        // transient failure (unix semantics; the Windows native error-code
        // space does not contain this pair, no misjudgment).
        #[cfg(unix)]
        {
            matches!(e.raw_os_error(), Some(23) | Some(24))
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

/// The running listen endpoint (the Direct branch has zero flock-frpc
/// types; the Frp branch holds the managed handle —— Arc lets the health
/// monitoring task and the assembling side share its lifetime, review item
/// 11).
pub enum RunningListener {
    Direct {
        local: SocketAddr,
    },
    Frp {
        local: SocketAddr,
        managed: Arc<crate::frp::Managed>,
    },
}

impl RunningListener {
    /// The local listen address.
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            RunningListener::Direct { local } | RunningListener::Frp { local, .. } => *local,
        }
    }
}

/// Start the server by mode (assembly-time dispatch; the admin endpoint
/// starts with it; since M3 the data plane is assembled along the way).
///
/// `serve_listener` is an infinite loop —— the JoinHandle returned by `run`
/// does not normally end; abort stops the accepts.
pub async fn run(
    core: Arc<ServerCore>,
    mode: ListenerMode,
) -> Result<
    (
        RunningListener,
        JoinHandle<std::io::Result<()>>,
        JoinHandle<()>,
    ),
    String,
> {
    // M3 data plane (§2.2 the server itself is also a peer): tun + routes;
    // a failure degrades to control-flow-only and logs inside
    // PeerRouter::open (the host-test path is exactly this form).
    // The multi-primary form (sync::run_raft) has already assembled the tun
    // for its own peer surface (router pre-set) ⇒ skip here, avoiding
    // opening a same-named device twice.
    if core.router().is_none() {
        core.set_router(PeerRouter::open(&core.cfg.tun_name, core.cfg.vip).await);
    }
    // M7: hang the traffic meter on the router (single-server counting) +
    // the folding loop + the reaper (§7-M7.3/§7-M7.5).
    if let Some(router) = core.router() {
        router.set_traffic_meter(core.traffic.clone());
    }
    tokio::spawn(traffic_meter_loop(core.traffic.clone()));
    if core.cfg.peer_retention_days > 0 {
        tokio::spawn(reaper_loop(core.clone()));
    }
    // The admin loopback endpoint (the in-process single-writer entry for
    // CLI subcommands).
    let admin = crate::admin::serve(core.clone(), core.cfg.admin_bind)
        .await
        .map_err(|e| format!("admin bind {}: {e}", core.cfg.admin_bind))?;
    // M8 (§7-M8.2): the Web UI admin surface —— loopback binds immediately
    // (a failure refuses to start) + the VIP 5s retry task. (The
    // multi-primary assembly of sync::run_raft ultimately goes through this
    // run() too ⇒ one hookup point for both forms.)
    if core.cfg.webui.enabled {
        crate::webui::serve(core.clone()).await?;
    }
    match mode {
        ListenerMode::Direct { bind } => {
            // Direct assembly path: bind is listen —— zero frp logic (the
            // §2.1/§3.11 hard constraint).
            let listener = TcpListener::bind(bind)
                .await
                .map_err(|e| format!("bind {bind}: {e}"))?;
            let local = listener
                .local_addr()
                .map_err(|e| format!("local_addr: {e}"))?;
            let task = tokio::spawn(core.clone().serve_listener(listener));
            Ok((RunningListener::Direct { local }, task, admin))
        }
        ListenerMode::Frp { bind, plan } => {
            let (listener, managed) = crate::frp::start(plan, bind)
                .await
                .map_err(|e| format!("frp: {e}"))?;
            // Low-frequency health monitoring (review item 11): poll
            // RelayStatus every 10s —— unhealthy/recovery both leave a trail
            // + count.
            let managed = Arc::new(managed);
            managed.spawn_health_monitor();
            let local = listener
                .local_addr()
                .map_err(|e| format!("local_addr: {e}"))?;
            let task = tokio::spawn(core.clone().serve_listener(listener));
            Ok((RunningListener::Frp { local, managed }, task, admin))
        }
    }
}

/// Signing convenience: the root key signs arbitrary bytes (for
/// invite/directory extensions; tests can assert it too).
pub fn root_sign(root: &SigningKey, bytes: &[u8]) -> [u8; 64] {
    root.sign(bytes).to_bytes()
}

// ============================================================================
// M7: the reaper (§7-M7.5 —— devices offline past the retention period are
// set to Expired via Raft/local write operations + their VIPs return to the
// pool)
// ============================================================================

/// Reaper period (a low-frequency task, §7-M7.5: 60s).
pub const REAPER_PERIOD: std::time::Duration = std::time::Duration::from_secs(60);
/// Retention conversion (days → seconds).
const SECS_PER_DAY: u64 = 86_400;

/// One reaper pass (injectable clock for tests): submits Expire one by one
/// for devices that are "Active with last_seen older than the retention
/// period". `retention_days = 0` ⇒ never expires (an empty pass). Concurrent
/// reaping by multiple servers is idempotent (the state machine admits
/// Expire replays). Returns the devices expired in this pass.
///
/// last_seen semantics (the §7-M7.5 correction —— landing "counted from
/// registration"):
/// - With an observation (single server = the TrafficMeter; multi-primary =
///   the local lease row) ⇒ the observed value (maxed with registered_at
///   —— an observation older than the registration time is a clock anomaly;
///   take the nearer anchor);
/// - **No observation ⇒ `DeviceRow.registered_at` is the starting anchor**.
///   The old implementation's `map_or(0)` counted from epoch 0: `0 <=
///   cutoff` always held ⇒ when the single server restarted (TrafficMeter
///   purely in-memory, cleared) or the multi-primary lease table had not yet
///   been anti-entropy backfilled, the **first pass terminalized every
///   Active device (including online ones)** —— with the invite already
///   consumed, the user was bricked (Expired irreversible, the VIP already
///   returned to the pool).
///
/// Restart/view-not-ready gate (defense in depth, minimal reliable form):
/// - Single server: the TrafficMeter has had **zero observations** since
///   creation (empty table with a non-empty registry ⇒ just restarted) ⇒
///   skip this pass. Residue: deployments with no traffic at all (including
///   the no-tun control-flow-only form) keep the gate closed and the
///   retention period inert for now —— it opens as soon as the first
///   observation arrives (any device's / the server's own traffic);
/// - Multi-primary: the local lease table is empty **or** no remote lease
///   events have been received since startup (the race window between the
///   ≤1-period 5s anti-entropy backfill and the reaper's first pass) ⇒ skip
///   this pass (see the residue note on
///   `LeaseTable::reaper_view_ready`).
pub async fn reap_once(core: &ServerCore, retention_days: u64, now_unix: u64) -> Vec<DeviceId> {
    if retention_days == 0 {
        return Vec::new();
    }
    let retention_secs = retention_days.saturating_mul(SECS_PER_DAY);
    let cutoff = now_unix.saturating_sub(retention_secs);
    // Candidates = the locally-applied view's Active rows (the same roster
    // snapshot —— the display-surface consistency tier).
    let rows: Vec<(DeviceId, flock_sync::proto::DeviceRow)> = match &core.net {
        NetBackend::Single(s) => s.devices_all(),
        #[cfg(feature = "multi-primary")]
        NetBackend::Sync(s) => s
            .node
            .devices_snapshot()
            .into_iter()
            .map(|(id, row)| (DeviceId(id), row))
            .collect(),
    };
    // Restart/view-not-ready gate (see the function docs): skip the whole
    // pass; re-judge on the next one (60s later).
    if !rows.is_empty() {
        match &core.net {
            NetBackend::Single(_) => {
                if !core.traffic.has_any() {
                    eprintln!(
                        "flock-server: reaper: zero traffic observations since startup (likely just restarted) - \
                         skipping this pass (prevents the first pass from terminalizing online devices)"
                    );
                    return Vec::new();
                }
            }
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                if !s.node.lease().reaper_view_ready() {
                    eprintln!(
                        "flock-server: reaper: local lease view not ready (empty table / no remote events) - \
                         skipping this pass (prevents terminalizing remotely-hosted devices before anti-entropy backfill)"
                    );
                    return Vec::new();
                }
            }
        }
    }
    let mut expired = Vec::new();
    for (id, row) in rows {
        if row.status != crate::netstate::DeviceStatus::Active {
            continue;
        }
        // last_seen: multi-primary = the local lease view; single server =
        // the TrafficMeter; no observation ⇒ the registered_at anchor
        // (counted from registration).
        let last_seen = match &core.net {
            NetBackend::Single(_) => core
                .traffic
                .stats(&row.vip)
                .map_or(row.registered_at, |(_, _, ls)| ls.max(row.registered_at)),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => s
                .node
                .lease()
                .peer_stats(&id.0)
                .map_or(row.registered_at, |st| {
                    st.last_seen_unix.max(row.registered_at)
                }),
        };
        if last_seen <= cutoff {
            match core.net.expire(&id, now_unix).await {
                Ok(_) => {
                    // Local session backstop (multi-primary's apply hook
                    // also kills; single server immediately).
                    core.sessions.kill(&id.0);
                    expired.push(id);
                }
                Err(e) => eprintln!("flock-server: reaper: expire {id} failed: {e}"),
            }
        }
    }
    expired
}

/// The reaper loop (assembled by run; not assembled when
/// `peer_retention_days = 0`).
async fn reaper_loop(core: Arc<ServerCore>) {
    let mut tick = tokio::time::interval(REAPER_PERIOD);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let now = flock_protocol::trust::now_unix();
        let expired = reap_once(&core, core.cfg.peer_retention_days, now).await;
        if !expired.is_empty() {
            eprintln!(
                "flock-server: reaper: {} device(s) expired (VIPs returned to the pool)",
                expired.len()
            );
        }
    }
}

/// M7: the single-server traffic-meter folding loop (a 1s window —— the
/// same math as flock-sync's LeaseTable, §7-M7.3).
async fn traffic_meter_loop(meter: Arc<flock_sync::lease::TrafficMeter>) {
    let mut tick = tokio::time::interval(flock_sync::lease::EWMA_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        meter.tick(now_ms);
    }
}

#[cfg(all(test, feature = "multi-primary"))]
mod tests {
    use super::*;

    /// Review item 2: per-server OPRF sealing —— the sealed product
    /// contains no plaintext (the b64 plaintext cannot be read out of the
    /// wraps in Raft state); the correct recipient unseals and recovers;
    /// the wrong recipient (a server without a matching wrap) fails
    /// explicitly.
    #[test]
    fn oprf_wrap_sealed_not_plaintext_and_recipient_bound() {
        let recipient = HybridKeypair::generate(&mut flock_protocol::rand::rngs::OsRng);
        let other = HybridKeypair::generate(&mut flock_protocol::rand::rngs::OsRng);
        let oprf_b64 =
            flock_protocol::pake::server_setup_new(&mut flock_protocol::rand::rngs::OsRng);

        let wrapped = seal_oprf_wrap(&oprf_b64, &recipient.public()).expect("seal");
        // The sealed store is unreadable as plaintext: no long substring of
        // the plaintext b64 appears in the sealed bytes.
        let probe = &oprf_b64[oprf_b64.len() / 2..];
        assert!(
            !wrapped.windows(probe.len()).any(|w| w == probe.as_bytes()),
            "the sealed bytes must not contain plaintext fragments"
        );
        assert_eq!(
            wrapped[0],
            flock_protocol::envelope::V2_VER,
            "envelope v2 header"
        );
        // The recipient unseals and recovers (round trip).
        assert_eq!(
            open_oprf_wrap(&recipient, &wrapped).expect("open"),
            oprf_b64,
            "the correct recipient unseals and recovers the OPRF b64"
        );
        // A non-recipient fails explicitly (a server without a matching
        // wrap ⇒ the OPAQUE-unavailable path).
        let err = open_oprf_wrap(&other, &wrapped).expect_err("wrong recipient");
        assert!(
            err.contains("envelope open"),
            "the error must be attributable (envelope authentication failed): {err}"
        );
        // A corrupted seal fails explicitly.
        let mut tampered = wrapped.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 1;
        assert!(
            open_oprf_wrap(&recipient, &tampered).is_err(),
            "tampering rejected"
        );
        // server_setup_load accepts the unsealed product (closing the real
        // OPRF semantic loop).
        assert!(flock_protocol::pake::server_setup_load(&oprf_b64).is_ok());
    }
}

// ============================================================================
// M7 unit tests: the reaper window logic (injected clock, §7-M7.5)
// ============================================================================

#[cfg(test)]
mod reaper_tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::netstate::DeviceStatus;
    use flock_protocol::session::DeviceId;

    fn m7_cfg(state_dir: std::path::PathBuf, retention: u64) -> ServerConfig {
        ServerConfig {
            state_dir,
            bind: "127.0.0.1:9443".parse().unwrap(),
            mode: "direct".into(),
            advertise_endpoint: "127.0.0.1:9443".into(),
            extra_endpoints: vec![],
            dir_version: 1,
            ticket_ttl_secs: 60,
            peer_retention_days: retention,
            admin_bind: "127.0.0.1:9444".parse().unwrap(),
            max_sessions: 1024,
            tun_name: "tun0".into(),
            vip: "100.64.0.1".parse().unwrap(),
            frp: None,
            sync: None,
            webui: Default::default(),
        }
    }

    fn dev_id(seed: u8) -> DeviceId {
        use sha2::Digest as _;
        DeviceId(sha2::Sha256::digest(ed_of(seed)).into())
    }

    fn ed_of(seed: u8) -> [u8; 32] {
        let vk = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        *vk.verifying_key().as_bytes()
    }

    /// Window logic (the corrected §7-M7.5 semantics): untouched within the
    /// retention period; out of bounds (last_seen older than the retention
    /// period) ⇒ an Expire submission + row set Expired + the VIP returned
    /// to the pool (a new registration gets that VIP); retention=0 ⇒ never
    /// expires.
    ///
    /// Old→new (the corrected, frozen behavior): the old assertion "B,
    /// never online (last_seen=0), is reaped on the very first pass
    /// (counted from epoch 0)" —— that was precisely the restart-bricking
    /// defect's window semantics (0 <= cutoff always true); under the new
    /// semantics a never-online device uses `registered_at` as its anchor:
    /// anchor age 29d < the 30d retention period ⇒ **untouched**, reaped
    /// only once the anchor passes the window.
    #[tokio::test]
    async fn reaper_window_logic_with_injected_clock() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) =
            ServerCore::open_or_init(m7_cfg(dir.path().to_path_buf(), 30)).expect("core");
        let store = match &core.net {
            crate::backend::NetBackend::Single(s) => s.clone(),
            #[cfg(feature = "multi-primary")]
            _ => panic!("single"),
        };
        // Devices A (active —— the traffic meter has a recent last_seen),
        // B (never online —— the registered_at anchor), C (revoked ——
        // cannot Expire).
        let row_a = store.register_device("u", [1; 32], ed_of(1), "a").unwrap();
        let row_b = store.register_device("u", [2; 32], ed_of(2), "b").unwrap();
        let _row_c = store.register_device("u", [3; 32], ed_of(3), "c").unwrap();
        store.revoke(&dev_id(3)).unwrap();
        assert!(
            store.device_row(&dev_id(2)).unwrap().registered_at > 0,
            "registration lands the registered_at anchor"
        );
        // A's last_seen = the real wall clock's "now" (the traffic meter ——
        // a note lifts it).
        core.traffic.note_tx(&row_a.vip, 100);
        let now_real = flock_protocol::trust::now_unix();

        // ① 29 days later: A (observed 29d < 30d) and B (anchor 29d < 30d)
        //    are both within the retention period ⇒ an empty pass (the old
        //    semantics would have reaped the never-online B here —— see the
        //    test docs); the revoked C untouched.
        let now1 = now_real + 29 * 86_400;
        let expired = reap_once(&core, 30, now1).await;
        assert!(
            expired.is_empty(),
            "29d < 30d: both A/B inside the window: {expired:?}"
        );
        assert_eq!(
            store.device_row(&dev_id(1)).unwrap().status,
            DeviceStatus::Active,
            "A (observed 29d < 30d) does not expire"
        );
        assert_eq!(
            store.device_row(&dev_id(2)).unwrap().status,
            DeviceStatus::Active,
            "B (registered_at anchor 29d < 30d) does not expire - counted from registration, not epoch 0"
        );
        assert_eq!(
            store.device_row(&dev_id(3)).unwrap().status,
            DeviceStatus::Revoked,
            "C stays Revoked (does not become Expired)"
        );

        // ② 31 days later: A (observation past the window) and B (anchor
        //    past the window) are both reaped; C still untouched.
        let now2 = now_real + 31 * 86_400;
        let expired = reap_once(&core, 30, now2).await;
        assert_eq!(expired.len(), 2, "both A and B out of bounds: {expired:?}");
        assert!(
            expired.contains(&dev_id(1)),
            "A reaped, observation past the window"
        );
        assert!(
            expired.contains(&dev_id(2)),
            "B reaped, anchor past the window (never online and past the window)"
        );
        for id in [dev_id(1), dev_id(2)] {
            let row = store.device_row(&id).unwrap();
            assert_eq!(row.status, DeviceStatus::Expired);
            assert_eq!(
                row.expired_at,
                Some(now2),
                "the injected clock lands expired_at deterministically"
            );
        }
        assert_eq!(
            store.device_row(&dev_id(3)).unwrap().status,
            DeviceStatus::Revoked
        );
        // Idempotent: another pass in the same window ⇒ an empty pass.
        let expired = reap_once(&core, 30, now2).await;
        assert!(
            expired.is_empty(),
            "idempotent (already-Expired rows are not resubmitted)"
        );
        // VIPs returned to the pool: a new registration takes the pool's
        // smallest (A's .2 before B's .3 regardless of pool-entry order ——
        // the smallest key wins).
        let row_d = store.register_device("u", [4; 32], ed_of(4), "d").unwrap();
        assert_eq!(
            row_d.vip, row_a.vip,
            "the pool's smallest VIP reassigned (A's .2)"
        );
        // The pool's remainder (B's .3) goes to the next device.
        let row_e = store.register_device("u", [5; 32], ed_of(5), "e").unwrap();
        assert_eq!(row_e.vip, row_b.vip, "the pool order continues (B's .3)");

        // ③ retention = 0 ⇒ never expires (an empty pass).
        let (core0, _) =
            ServerCore::open_or_init(m7_cfg(tempfile::tempdir().unwrap().path().to_path_buf(), 0))
                .expect("core0");
        let store0 = match &core0.net {
            crate::backend::NetBackend::Single(s) => s.clone(),
            #[cfg(feature = "multi-primary")]
            _ => panic!("single"),
        };
        store0.register_device("u", [1; 32], ed_of(1), "a").unwrap();
        let expired = reap_once(&core0, 0, u64::MAX / 2).await;
        assert!(expired.is_empty(), "0 = never expires (legacy-compatible)");
        assert_eq!(
            store0.device_row(&dev_id(1)).unwrap().status,
            DeviceStatus::Active
        );
    }

    /// Single-server restart gate: the TrafficMeter is purely in-memory ——
    /// a restart clears it while the registry persists on disk. The first
    /// pass after a restart (zero observations + non-empty registry ⇒ just
    /// restarted) **must be skipped** —— the old behavior's `last_seen=0 <=
    /// cutoff` was always true and terminalized every Active device
    /// (including online ones) even with the clock far past the retention
    /// period (invite consumed = user bricked). After the gate opens (the
    /// first observation arrives), reaping at the same instant resumes.
    #[tokio::test]
    async fn reaper_skips_fresh_restart_single_form() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_path_buf();
        {
            let (core, _) = ServerCore::open_or_init(m7_cfg(state_dir.clone(), 30)).expect("core");
            let store = match &core.net {
                crate::backend::NetBackend::Single(s) => s.clone(),
                #[cfg(feature = "multi-primary")]
                _ => panic!("single"),
            };
            let row_a = store.register_device("u", [1; 32], ed_of(1), "a").unwrap();
            store.register_device("u", [2; 32], ed_of(2), "b").unwrap();
            // Traffic observation of an online device (the pre-restart
            // world).
            core.traffic.note_tx(&row_a.vip, 100);
        }
        // "Restart": reopen the same state directory (the registry's two
        // rows survive), the TrafficMeter brand new (zero observations).
        let (core2, _) = ServerCore::open_or_init(m7_cfg(state_dir, 30)).expect("reopen");
        let store2 = match &core2.net {
            crate::backend::NetBackend::Single(s) => s.clone(),
            #[cfg(feature = "multi-primary")]
            _ => panic!("single"),
        };
        assert_eq!(
            store2.devices_all().len(),
            2,
            "the registry survives the restart"
        );
        assert!(
            !core2.traffic.has_any(),
            "the traffic meter cleared by the restart (zero observations)"
        );

        // Even a clock far past the retention period (100 days) reaps no
        // row —— the gate is in effect (the old behavior bricked both
        // here).
        let now = flock_protocol::trust::now_unix() + 100 * 86_400;
        let expired = reap_once(&core2, 30, now).await;
        assert!(
            expired.is_empty(),
            "just restarted ⇒ this pass skipped: {expired:?}"
        );
        for seed in 1u8..=2 {
            assert_eq!(
                store2.device_row(&dev_id(seed)).unwrap().status,
                DeviceStatus::Active,
                "the first pass after restart terminalizes no row"
            );
        }

        // After the gate opens (the first observation —— any traffic of any
        // device), reaping at the same instant resumes: A has an observation
        // (last_seen=now_real) but a 100d-old observation is past the
        // window, and B's anchor is past the window ⇒ both reaped —— proving
        // the earlier empty pass was carried by the gate (not a broken
        // window verdict).
        let row_a = store2.device_row(&dev_id(1)).unwrap();
        core2.traffic.note_tx(&row_a.vip, 1);
        let expired = reap_once(&core2, 30, now).await;
        assert_eq!(
            expired.len(),
            2,
            "after the gate opens, reaping by window: {expired:?}"
        );
    }
}

// ============================================================================
// Unit tests: server_vip_of consistency —— the single-server VIP
// collision-segment start refusal (the multi-primary assertion surface is in
// tests/multi_primary.rs::open_sync_rejects_vip_mismatch_with_expected_value)
// ============================================================================

#[cfg(test)]
mod vip_guard_tests {
    use super::*;
    use crate::config::ServerConfig;

    fn cfg_with_vip(vip: &str) -> ServerConfig {
        ServerConfig {
            state_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
            bind: "127.0.0.1:9443".parse().unwrap(),
            mode: "direct".into(),
            advertise_endpoint: "127.0.0.1:9443".into(),
            extra_endpoints: vec![],
            dir_version: 1,
            ticket_ttl_secs: 60,
            peer_retention_days: 30,
            admin_bind: "127.0.0.1:9444".parse().unwrap(),
            max_sessions: 1024,
            tun_name: "tun0".into(),
            vip: vip.parse().unwrap(),
            frp: None,
            sync: None,
            webui: Default::default(),
        }
    }

    /// Single server: cfg.vip inside the device allocation segment
    /// (VIP_FIRST..=VIP_LAST, i.e. from 100.64.0.2) ⇒ refuses to start and
    /// the error names the segment bounds and the correct value; .1 (the
    /// server's own reserved slot) passes.
    #[test]
    fn single_form_vip_in_device_segment_refuses_start() {
        // Segment head (100.64.0.2 = the first device's VIP), middle, and
        // tail all rejected.
        for bad in ["100.64.0.2", "100.64.0.11", "100.127.255.254"] {
            let err = match ServerCore::open_or_init(cfg_with_vip(bad)) {
                Err(e) => e,
                Ok(_) => panic!("{bad} inside the device allocation segment must refuse to start"),
            };
            assert!(
                err.contains("device allocation segment"),
                "{bad} rejected: {err}"
            );
            assert!(
                err.contains("100.64.0.1"),
                "the error gives the correct value: {err}"
            );
        }
        // The server's own reserved slot passes.
        ServerCore::open_or_init(cfg_with_vip("100.64.0.1"))
            .expect(".1 = the server's own VIP, passes");
        // Outside the segment (e.g. 100.128.0.1 —— beyond the /10) passes:
        // the validation only guards segment collisions, not siting
        // judgment.
        ServerCore::open_or_init(cfg_with_vip("100.128.0.1"))
            .expect("addresses outside the segment are not on this validation surface (siting is the deployment's responsibility)");
    }
}
