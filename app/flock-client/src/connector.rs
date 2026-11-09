//! Connector (docs/design.md §2.3 / §3.12): endpoint list → TCP dial →
//! `session::initiate` (with [`ServerPin`]); disconnect backoff is exponential
//! (5s base + jitter, wireguard-go RekeyTimeout cadence, crypto-2026 §6) with
//! endpoint rotation.
//!
//! - Identity trio (resident in the state directory): device static keys
//!   `device.keys` (0600), pins `pins.bin` ([`PinStore`], cluster_id →
//!   cluster root public key), root-signed directory `directory.bin`
//!   ([`ClusterDirectory`] — endpoint list and credentials signed as one,
//!   §1.3.3f option ②).
//! - Invite file (the `invite` subcommand): v3 structural verification (root
//!   signature) → expiry check → pin comparison (change ⇒ explicit warning
//!   error, **never silent**) → `record_directory` (version rollback
//!   rejected).
//! - Endpoint rotation: each connection attempt takes the next endpoint from
//!   the directory (a Direct connect address or an Frp relay user port —
//!   indistinguishable to the client, §2.1); any endpoint is 1-RTT (pinning
//!   material complete, §1.3.3c).
//!
//! Control-stream business (OPAQUE login/tickets/dir_pull periodic refresh)
//! follows the M2 control protocol (§2.2) and is assembled in later
//! milestones; the M3 data plane keeps the "first stream = control stream"
//! ordering contract (see [`lib`]/server dispatch), reserving room for that
//! business.

use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use flock_protocol::rand;
use flock_protocol::session::{
    initiate, CloseReason, DeviceStaticKeys, ServerPin, Tunnel, TunnelConfig,
};
use flock_protocol::trust::{ClusterDirectory, InviteFile, PinStore, PinVerdict, TrustError};
use tokio::net::TcpStream;

use crate::ctrl::ControlPlane;
use crate::dataplane;
use crate::tun::TunIo;

/// Disconnect-reconnect backoff: 5s base (§2.3), doubling, capped at 60s.
pub const BACKOFF_BASE: Duration = Duration::from_secs(5);
/// Backoff cap.
pub const BACKOFF_CAP: Duration = Duration::from_secs(60);
/// Jitter ceiling fraction (+0..25%: avoids synchronized reconnect storms
/// across clients).
pub const BACKOFF_JITTER: f64 = 0.25;
/// Per-endpoint dial timeout (TCP connect + handshake as a whole; on timeout
/// rotate to the next endpoint).
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(8);

// ============================================================================
// Errors
// ============================================================================

/// Client assembly/connection error.
#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    Session(flock_protocol::session::SessionError),
    Trust(TrustError),
    /// Dial timeout (TCP connect + handshake together exceeded
    /// [`DIAL_TIMEOUT`]; R1 black hole and other silent peers). Carries the
    /// target endpoint.
    DialTimeout(String),
    /// State-directory/config problem (message carries its own context).
    State(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "client: io: {e}"),
            ClientError::Session(e) => write!(f, "client: session: {e}"),
            ClientError::Trust(e) => write!(f, "client: trust: {e}"),
            ClientError::DialTimeout(ep) => {
                write!(
                    f,
                    "client: dial timeout (connect+handshake > {DIAL_TIMEOUT:?}): {ep}"
                )
            }
            ClientError::State(m) => write!(f, "client: {m}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Io(e) => Some(e),
            ClientError::Session(e) => Some(e),
            ClientError::Trust(e) => Some(e),
            ClientError::DialTimeout(_) | ClientError::State(_) => None,
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

impl From<TrustError> for ClientError {
    fn from(e: TrustError) -> Self {
        ClientError::Trust(e)
    }
}

impl From<flock_protocol::session::SessionError> for ClientError {
    fn from(e: flock_protocol::session::SessionError) -> Self {
        ClientError::Session(e)
    }
}

// ============================================================================
// State directory (identity trio)
// ============================================================================

/// Client local state (the state-directory trio).
#[derive(Debug)]
pub struct ClientState {
    /// Device static keys (never leave the machine once generated, §2.4).
    pub device: DeviceStaticKeys,
    /// Pin store (cluster_id → cluster root public key).
    pub pins: PinStore,
    /// Root-signed cluster directory (endpoint list + the full set of
    /// connection material).
    pub directory: ClusterDirectory,
}

const DEVICE_KEYS: &str = "device.keys";
const PINS: &str = "pins.bin";
const DIRECTORY: &str = "directory.bin";
/// VIP file (written by deployment orchestration; read when config.vip is
/// absent).
pub const VIP_FILE: &str = "vip";

impl ClientState {
    /// Load the device keys; with `create = true`, generate and persist them
    /// when missing (0600, unix). (The deployment order runs `gen-keys`
    /// before `invite`: keys do not depend on the directory existing.)
    pub fn load_keys(state_dir: &Path, create: bool) -> Result<DeviceStaticKeys, ClientError> {
        let keys_path = state_dir.join(DEVICE_KEYS);
        match std::fs::read(&keys_path) {
            Ok(b) => {
                let arr: [u8; 64] = b
                    .try_into()
                    .map_err(|_| ClientError::State("device.keys: expected 64B".into()))?;
                Ok(DeviceStaticKeys::from_bytes(&arr))
            }
            Err(_) if create => {
                let d = DeviceStaticKeys::generate();
                std::fs::create_dir_all(state_dir).map_err(|e| {
                    ClientError::State(format!("mkdir {}: {e}", state_dir.display()))
                })?;
                write_keys(state_dir, &d)?;
                Ok(d)
            }
            Err(e) => Err(ClientError::State(format!(
                "read {}: {e} (run gen-keys/invite bootstrap first)",
                keys_path.display()
            ))),
        }
    }

    /// Load the full state (device keys + pins + directory; `create` as in
    /// [`Self::load_keys`]).
    pub fn load(state_dir: &Path, create: bool) -> Result<Self, ClientError> {
        let device = Self::load_keys(state_dir, create)?;
        let pins = match std::fs::read(state_dir.join(PINS)) {
            Ok(b) => PinStore::from_bytes(&b)
                .map_err(|e| ClientError::State(format!("pins.bin parse: {e}")))?,
            Err(_) => PinStore::new(),
        };
        let directory =
            match std::fs::read(state_dir.join(DIRECTORY)) {
                Ok(b) => ClusterDirectory::from_bytes(&b)
                    .map_err(|e| ClientError::State(format!("directory.bin parse: {e}")))?,
                Err(_) => return Err(ClientError::State(
                    "no root-signed directory (run `flock-client invite <file>` bootstrap first, \
                     §1.3.3f)"
                        .into(),
                )),
            };
        // State-consistency warning (explicit, not silent): directory.bin
        // present but the pins for its cluster are missing (pins.bin
        // incomplete/not synced with the directory) ⇒ pin_for always None and
        // supervise spins in backoff across all endpoints.
        if pins.pinned_root(&directory.cluster_id).is_none() {
            eprintln!(
                "flock-client: warning: directory.bin exists but cluster {} has no pin \
                 (pins.bin missing or out of sync) — re-run `flock-client invite <file>` to repair",
                hex::encode(directory.cluster_id.0)
            );
        }
        Ok(ClientState {
            device,
            pins,
            directory,
        })
    }

    /// Persist the trio.
    pub fn save(&self, state_dir: &Path) -> Result<(), ClientError> {
        std::fs::create_dir_all(state_dir)
            .map_err(|e| ClientError::State(format!("mkdir {}: {e}", state_dir.display())))?;
        write_keys(state_dir, &self.device)?;
        self.pins
            .save(&state_dir.join(PINS))
            .map_err(|e| ClientError::State(format!("write pins.bin: {e}")))?;
        std::fs::write(state_dir.join(DIRECTORY), self.directory.to_bytes())
            .map_err(|e| ClientError::State(format!("write directory.bin: {e}")))?;
        Ok(())
    }

    /// Endpoint list (directory order, deduplicated).
    pub fn endpoints(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for e in &self.directory.servers {
            if !out.contains(&e.relay_endpoint) {
                out.push(e.relay_endpoint.clone());
            }
        }
        out
    }

    /// Connection pin for a target endpoint (cluster root = the pin; not
    /// pinned ⇒ None, the caller bootstraps first).
    pub fn pin_for(&self, endpoint: &str) -> Option<ServerPin> {
        let root = self.pins.pinned_root(&self.directory.cluster_id)?;
        let entry = self
            .directory
            .servers
            .iter()
            .find(|e| e.relay_endpoint == endpoint)?;
        Some(ServerPin {
            cluster_id: self.directory.cluster_id,
            cluster_root_pub: *root,
            entry: entry.clone(),
        })
    }

    /// Local VIP (config override or the state directory's `vip` file).
    pub fn resolve_vip(
        &self,
        state_dir: &Path,
        cfg_vip: Option<Ipv4Addr>,
    ) -> Result<Ipv4Addr, ClientError> {
        if let Some(v) = cfg_vip {
            return Ok(v);
        }
        let text = std::fs::read_to_string(state_dir.join(VIP_FILE)).map_err(|e| {
            ClientError::State(format!(
                "read {VIP_FILE}: {e} (deployment must write the VIP)"
            ))
        })?;
        text.trim()
            .parse()
            .map_err(|e| ClientError::State(format!("{VIP_FILE} is not an IPv4: {e}")))
    }
}

/// Persist the device keys (0600, unix).
fn write_keys(state_dir: &Path, device: &DeviceStaticKeys) -> Result<(), ClientError> {
    std::fs::write(state_dir.join(DEVICE_KEYS), device.to_bytes())
        .map_err(|e| ClientError::State(format!("write device.keys: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(
            state_dir.join(DEVICE_KEYS),
            std::fs::Permissions::from_mode(0o600),
        );
    }
    Ok(())
}

/// Invite file ingestion (§1.3.3f): structural signature verification →
/// expiry check → pinning (NotPinned = first pin / Match = pass / Mismatch =
/// **explicit warning rejection**) → `record_directory` (version rollback
/// rejected) → persist the trio.
pub fn ingest_invite(state_dir: &Path, invite: &InviteFile) -> Result<ClientState, ClientError> {
    invite
        .check(flock_protocol::trust::now_unix())
        .map_err(ClientError::Trust)?;
    let device = ClientState::load_keys(state_dir, true)?;
    let mut pins = match std::fs::read(state_dir.join(PINS)) {
        Ok(b) => PinStore::from_bytes(&b)
            .map_err(|e| ClientError::State(format!("pins.bin parse: {e}")))?,
        Err(_) => PinStore::new(),
    };
    match pins.verify_pinned(&invite.directory.cluster_id, &invite.cluster_root_pub) {
        PinVerdict::NotPinned => {
            pins.pin(&invite.directory.cluster_id, &invite.cluster_root_pub);
        }
        PinVerdict::Match => {}
        PinVerdict::Mismatch { .. } => {
            return Err(ClientError::Trust(TrustError::RootChanged {
                cluster_id: invite.directory.cluster_id,
                pinned: Box::new(
                    pins.pinned_root(&invite.directory.cluster_id)
                        .copied()
                        .expect("Mismatch ⇒ an old value exists"),
                ),
                presented: Box::new(invite.cluster_root_pub),
            }))
        }
    }
    pins.record_directory(&invite.cluster_root_pub, &invite.directory)
        .map_err(ClientError::Trust)?;
    let state = ClientState {
        device,
        pins,
        directory: invite.directory.clone(),
    };
    state.save(state_dir)?;
    Ok(state)
}

/// Endpoint override (§3.12 config surface; shared by run/service): only
/// endpoints inside the directory are accepted (material must match —
/// §1.3.3f endpoint↔material signed together); duplicates warn and are
/// deduplicated (first-occurrence order preserved — without dedup
/// [`EndpointRing`] would dial the same endpoint repeatedly).
pub fn override_endpoints(mut state: ClientState, eps: &[String]) -> Result<ClientState, String> {
    let known = state.endpoints();
    let mut seen: Vec<String> = Vec::new();
    for ep in eps {
        if !known.contains(ep) {
            return Err(format!(
                "override endpoint {ep} is not in the root-signed directory (endpoint↔material \
                 signed together; unsigned endpoints rejected)"
            ));
        }
        if seen.contains(ep) {
            eprintln!(
                "flock-client: config warning: duplicate override endpoint {ep} (deduplicated, \
                 first-occurrence order kept)"
            );
        } else {
            seen.push(ep.clone());
        }
    }
    let mut servers = Vec::new();
    for ep in &seen {
        if let Some(e) = state
            .directory
            .servers
            .iter()
            .find(|s| &s.relay_endpoint == ep)
        {
            servers.push(e.clone());
        }
    }
    state.directory.servers = servers;
    Ok(state)
}

// ============================================================================
// Backoff and endpoint rotation
// ============================================================================

/// Exponential backoff (pure function, testable): `min(cap, base · 2^attempt)`
/// plus `[0, 25%)` jitter.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            base: BACKOFF_BASE,
            cap: BACKOFF_CAP,
            attempt: 0,
        }
    }
}

impl Backoff {
    pub fn new(base: Duration, cap: Duration) -> Self {
        Backoff {
            base,
            cap,
            attempt: 0,
        }
    }

    /// Reset after success.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Next wait (`rnd ∈ [0,1)`; jitter fraction [`BACKOFF_JITTER`]).
    /// Returns the un-jittered base step.
    pub fn next_jitter(&mut self, rnd: f64) -> Duration {
        let n = self.attempt.min(16);
        self.attempt += 1;
        let exp = self.base.saturating_mul(1u32 << n.min(16));
        let base = exp.min(self.cap);
        let jitter = 1.0 + BACKOFF_JITTER * rnd.clamp(0.0, 0.9999);
        base.mul_f64(jitter)
    }
}

/// Endpoint rotation (round-robin): each connection attempt takes the next
/// endpoint (§2.3 endpoint rotation).
#[derive(Debug, Clone)]
pub struct EndpointRing {
    endpoints: Vec<String>,
    next: usize,
}

impl EndpointRing {
    pub fn new(endpoints: Vec<String>) -> Self {
        EndpointRing { endpoints, next: 0 }
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// Take the next endpoint and advance (empty ⇒ None).
    pub fn next_endpoint(&mut self) -> Option<String> {
        if self.endpoints.is_empty() {
            return None;
        }
        let ep = self.endpoints[self.next % self.endpoints.len()].clone();
        self.next = self.next.wrapping_add(1);
        Some(ep)
    }
}

// ============================================================================
// Dialing and the supervise loop
// ============================================================================

/// One dial: TCP connect + `session::initiate` (1-RTT, pinned form) bounded
/// **as a whole** by [`DIAL_TIMEOUT`] — with an R1 black hole (TCP up,
/// handshake silent) the timeout rotates to the next endpoint, and supervise
/// cannot hang forever on an un-timed `initiate`.
pub async fn dial(
    pin: &ServerPin,
    device: &DeviceStaticKeys,
    cfg: TunnelConfig,
) -> Result<Tunnel, ClientError> {
    dial_with_timeout(pin, device, cfg, DIAL_TIMEOUT).await
}

/// Timeout-injectable form of [`dial`] (tests reproduce the "TCP up, R1
/// never arrives" black-hole shape with a short timeout).
pub async fn dial_with_timeout(
    pin: &ServerPin,
    device: &DeviceStaticKeys,
    cfg: TunnelConfig,
    timeout: Duration,
) -> Result<Tunnel, ClientError> {
    tokio::time::timeout(timeout, async {
        let io = TcpStream::connect(&pin.entry.relay_endpoint).await?;
        initiate(io, device, pin, cfg)
            .await
            .map_err(ClientError::Session)
    })
    .await
    .map_err(|_| ClientError::DialTimeout(pin.entry.relay_endpoint.clone()))?
}

/// Supervise-loop event (log/assertion surface: A9's "detected and
/// reconnecting" is a grep-able record built from [`ConnEvent::SessionEnded`]
/// carrying the `dead-link` reason + the next-attempt timing; A10's seamless
/// rekey is logged directly as `flock-client: rekey epoch=N` by the epoch
/// watcher task inside supervise — the `events` callback is not Send and
/// cannot enter the spawn, so the epoch line does not occupy the event enum).
#[derive(Debug)]
pub enum ConnEvent {
    /// Attempting an endpoint (attempt starts at 1).
    Dialing { endpoint: String, attempt: u32 },
    /// Tunnel established (server = the peer server identity).
    Connected {
        endpoint: String,
        server: flock_protocol::session::ServerId,
    },
    /// Data plane ended (reason = session-layer close reason; None = channel
    /// IO error ahead of any session verdict).
    SessionEnded {
        endpoint: String,
        reason: Option<CloseReason>,
    },
}

/// Supervise loop: dial → tunnel → tun ↔ PacketChannel data plane → on end,
/// backoff and reconnect.
///
/// Never returns normally (a process-lifetime loop); tests terminate it via
/// `tokio::select!`/abort. `backoff` lets tests inject small steps; the
/// `events` callback receives [`ConnEvent`] (the process entry point turns it
/// into eprintln).
pub async fn supervise(
    state: &ClientState,
    tun: &TunIo,
    tunnel_cfg: TunnelConfig,
    backoff: Backoff,
    events: impl FnMut(ConnEvent),
) {
    supervise_inner(state, tun, tunnel_cfg, backoff, events, None, None).await
}

/// [`supervise`] + epoch observation (§7-M6 service assembly): on connection
/// establishment publish the current epoch's initial value, then forward
/// every rekey bump into `epoch_tx` (the epoch source of the IPC Status
/// snapshot; a lost receiver is just ignored).
pub async fn supervise_with_epoch(
    state: &ClientState,
    tun: &TunIo,
    tunnel_cfg: TunnelConfig,
    backoff: Backoff,
    events: impl FnMut(ConnEvent),
    epoch_tx: tokio::sync::watch::Sender<u64>,
) {
    supervise_inner(
        state,
        tun,
        tunnel_cfg,
        backoff,
        events,
        Some(epoch_tx),
        None,
    )
    .await
}

/// [`supervise_with_epoch`] + the control-stream shared slot (M7 §7-M7.7
/// service assembly): on session establishment the control stream goes into
/// `plane` (consumed by login keepalive/roster pulls), and comes out on
/// session end/poisoning; the plane's poison signal (request timeout — the
/// stream may be misaligned) ends the data plane early and reconnects (a
/// fresh stream, never continuing misaligned).
pub async fn supervise_with_control(
    state: &ClientState,
    tun: &TunIo,
    tunnel_cfg: TunnelConfig,
    backoff: Backoff,
    events: impl FnMut(ConnEvent),
    epoch_tx: tokio::sync::watch::Sender<u64>,
    plane: ControlPlane,
) {
    supervise_inner(
        state,
        tun,
        tunnel_cfg,
        backoff,
        events,
        Some(epoch_tx),
        Some(plane),
    )
    .await
}

async fn supervise_inner(
    state: &ClientState,
    tun: &TunIo,
    tunnel_cfg: TunnelConfig,
    mut backoff: Backoff,
    mut events: impl FnMut(ConnEvent),
    epoch_tx: Option<tokio::sync::watch::Sender<u64>>,
    plane: Option<ControlPlane>,
) {
    let mut ring = EndpointRing::new(state.endpoints());
    loop {
        let Some(endpoint) = ring.next_endpoint() else {
            eprintln!("flock-client: directory has no endpoints, rechecking in 5s");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        let Some(pin) = state.pin_for(&endpoint) else {
            // Back off instead of busy-spinning (the original shape was a
            // 100% CPU spin): no pin is a persistent state (directory
            // present, pins missing — see the consistency warning in
            // ClientState::load); retry after the 5s endpoint-recheck
            // cadence.
            eprintln!(
                "flock-client: endpoint {endpoint} has no connection material / not pinned, \
                 rechecking in 5s"
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        let attempt = backoff.attempt + 1;
        events(ConnEvent::Dialing {
            endpoint: endpoint.clone(),
            attempt,
        });
        match dial(&pin, &state.device, tunnel_cfg.clone()).await {
            Ok(tunnel) => {
                // First stream = control stream (ordering contract, see the
                // module docs): open the placeholder and **hold it until the
                // session ends** (ordering + avoids a premature-Drop stream
                // lifetime variable); since M7 the service form installs the
                // stream into the ControlPlane shared slot for login/roster
                // business reuse (poison signal ⇒ early reconnect). Control
                // stream unopenable ⇒ the session is already bad; go
                // straight to backoff (the packet channel must not become
                // the first stream and break dispatch).
                let control = match tunnel.open_stream(flock_protocol::mux::Prio::Control).await {
                    Ok(s) => {
                        let shared = Arc::new(tokio::sync::Mutex::new(s));
                        if let Some(p) = &plane {
                            p.install_arc(shared.clone());
                        }
                        shared
                    }
                    Err(_) => {
                        events(ConnEvent::SessionEnded {
                            endpoint: endpoint.clone(),
                            reason: tunnel.stats().closed,
                        });
                        tunnel.shutdown().await;
                        let d = backoff.next_jitter(rand::random::<f64>());
                        eprintln!(
                            "flock-client: reconnecting in {d:?} (control stream open failed)"
                        );
                        tokio::time::sleep(d).await;
                        continue;
                    }
                };
                match tunnel.open_packet_channel().await {
                    Ok(ch) => {
                        backoff.reset();
                        if let Some(server) = tunnel.peer_server_id() {
                            events(ConnEvent::Connected {
                                endpoint: endpoint.clone(),
                                server,
                            });
                        }
                        // Rekey observation (A10): subscribe to the epoch
                        // watch, report every bump (invisible to the data
                        // plane — the bridge runs in parallel with this
                        // task). When epoch_tx exists, also forward outward
                        // (the service snapshot source).
                        let mut epoch_rx = tunnel.epoch_watch();
                        if let Some(tx) = &epoch_tx {
                            let _ = tx.send(*epoch_rx.borrow());
                        }
                        let ep_for_rekey = endpoint.clone();
                        let epoch_fwd = epoch_tx.clone();
                        let rekey_watcher = tokio::spawn(async move {
                            loop {
                                if epoch_rx.changed().await.is_err() {
                                    return;
                                }
                                // The callback side only logs — event order
                                // is preserved by the watch.
                                eprintln!(
                                    "flock-client: rekey epoch={} endpoint={ep_for_rekey}",
                                    *epoch_rx.borrow_and_update()
                                );
                                if let Some(tx) = &epoch_fwd {
                                    let _ = tx.send(*epoch_rx.borrow_and_update());
                                }
                            }
                        });
                        let mut sess = tun.session();
                        // M7: control-stream poisoning (business request
                        // timeout — misalignment risk) ⇒ end this session's
                        // data plane early and reconnect (without a plane,
                        // the select arm never fires; behavior unchanged).
                        let bridge_fut = dataplane::bridge(&mut sess, ch);
                        let bridge_err = tokio::select! {
                            r = bridge_fut => r.err(),
                            _ = async {
                                match &plane {
                                    Some(p) => p.killed().await,
                                    None => std::future::pending::<()>().await,
                                }
                            } => {
                                eprintln!("flock-client: control stream poisoned => ending this session, reconnecting");
                                None
                            }
                        };
                        if let Some(e) = &bridge_err {
                            eprintln!("flock-client: dataplane ended: {e}");
                        }
                        drop(sess);
                        rekey_watcher.abort();
                        let reason = tunnel.stats().closed;
                        if let Some(p) = &plane {
                            p.remove();
                        }
                        drop(control); // control stream ends with the session (explicit: FIN order ahead of shutdown)
                        events(ConnEvent::SessionEnded {
                            endpoint: endpoint.clone(),
                            reason,
                        });
                        tunnel.shutdown().await;
                    }
                    Err(e) => {
                        eprintln!("flock-client: open packet channel failed: {e}");
                        tunnel.shutdown().await;
                    }
                }
            }
            Err(e) => {
                eprintln!("flock-client: dial failed (attempt {attempt}): {e}");
            }
        }
        let d = backoff.next_jitter(rand::random::<f64>());
        eprintln!("flock-client: reconnecting in {d:?} (rotating to the next endpoint)");
        tokio::time::sleep(d).await;
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::testutil::EchoPeer;
    use crate::tun::{MockTunDevice, TunDevice as _, TunIo, TunSpec};
    use flock_protocol::trust::PinStore;

    fn state_with(endpoints: &[&str]) -> ClientState {
        use flock_protocol::session::{ClusterId, ServerEntry, ServerId};
        use flock_protocol::trust::ClusterDirectory;
        let mut servers = Vec::new();
        for (i, ep) in endpoints.iter().enumerate() {
            let identity =
                flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[i as u8 + 1; 32]);
            servers.push(ServerEntry {
                server_id: ServerId([i as u8 + 1; 16]),
                relay_endpoint: (*ep).to_string(),
                identity_pub: identity.verifying_key(),
                static_hybrid_pub: flock_protocol::kem::HybridKeypair::generate(
                    &mut rand::rngs::OsRng,
                )
                .public(),
            });
        }
        let directory = ClusterDirectory {
            cluster_id: ClusterId([7; 16]),
            dir_version: 1,
            servers,
            root_sig: flock_protocol::ed25519_dalek::Signature::from_bytes(&[0; 64]),
        };
        ClientState {
            device: flock_protocol::session::DeviceStaticKeys::generate(),
            pins: PinStore::new(),
            directory,
        }
    }

    /// Override endpoints: dedup (order-preserving) + unsigned-endpoint
    /// rejection (§1.3.3f original semantics must not regress; shared by
    /// run/service since M6).
    #[test]
    fn override_endpoints_dedups_repeats_and_keeps_gate() {
        let state = state_with(&["a:1", "b:2", "c:3"]);
        // Duplicates: dedup, first occurrence order kept.
        let eps = vec!["b:2".to_string(), "a:1".to_string(), "b:2".to_string()];
        let out = override_endpoints(state, &eps).expect("valid override");
        assert_eq!(out.endpoints(), vec!["b:2".to_string(), "a:1".to_string()]);
        // Unsigned endpoints still rejected.
        let state2 = state_with(&["a:1"]);
        let bad = vec!["evil:9".to_string()];
        assert!(
            override_endpoints(state2, &bad).is_err(),
            "unsigned endpoints must be rejected"
        );
    }

    /// supervise_with_epoch: publishes the initial epoch on connection
    /// (IPC Status snapshot-source semantics, §7-M6.2).
    #[tokio::test]
    async fn supervise_with_epoch_publishes_initial_epoch_on_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = listener.local_addr().unwrap().to_string();
        let peer = std::sync::Arc::new(EchoPeer::new(&ep));
        let peer_serve = peer.clone();
        tokio::spawn(async move { peer_serve.serve(listener).await });

        let device = DeviceStaticKeys::generate();
        peer.register(&device);
        let mut pins = PinStore::new();
        pins.pin(&peer.directory.cluster_id, &peer.root.verifying_key());
        let state = ClientState {
            device,
            pins,
            directory: peer.directory.clone(),
        };

        let mock = std::sync::Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = std::sync::Arc::new(TunIo::from_arc(mock.clone()));
        let tun_sup = tun.clone();

        let (epoch_tx, epoch_rx) = tokio::sync::watch::channel(99u64);
        let sup = tokio::spawn(async move {
            supervise_with_epoch(
                &state,
                tun_sup.as_ref(),
                TunnelConfig::default(),
                Backoff::new(Duration::from_millis(80), Duration::from_millis(300)),
                |_| {},
                epoch_tx,
            )
            .await;
        });

        // Connection established ⇒ the epoch is overwritten with the
        // session's real value (no longer the construction-time 99).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let v = *epoch_rx.borrow();
            assert!(
                tokio::time::Instant::now() < deadline,
                "connection epoch not seen within 15s (still {v})"
            );
            if v != 99 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        sup.abort();
        tun.shutdown();
    }

    /// Supervise-loop integration: connect → data plane → peer kills the
    /// link → SessionEnded → backoff → successful reconnect (the
    /// host-runnable counterpart of A9's "detected and reconnecting" client
    /// semantics; the silent-dead-link timer was already covered at the
    /// session layer in M1 by timer_deadlink_after_3x_keepalive_silence, the
    /// container A9 exercises the real 30s).
    #[tokio::test]
    async fn supervise_reconnects_after_session_death() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = listener.local_addr().unwrap().to_string();
        let peer = std::sync::Arc::new(EchoPeer::new(&ep));
        let peer_serve = peer.clone();
        tokio::spawn(async move { peer_serve.serve(listener).await });

        let device = DeviceStaticKeys::generate();
        peer.register(&device);
        let mut pins = PinStore::new();
        pins.pin(&peer.directory.cluster_id, &peer.root.verifying_key());
        let state = ClientState {
            device,
            pins,
            directory: peer.directory.clone(),
        };

        let mock = std::sync::Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = std::sync::Arc::new(TunIo::from_arc(mock.clone()));
        let tun_sup = tun.clone();

        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let sup = tokio::spawn(async move {
            supervise(
                &state,
                tun_sup.as_ref(),
                TunnelConfig::default(),
                Backoff::new(Duration::from_millis(80), Duration::from_millis(300)),
                |ev| {
                    let _ = ev_tx.send(match ev {
                        ConnEvent::Dialing { endpoint, attempt } => {
                            format!("dial {endpoint} #{attempt}")
                        }
                        ConnEvent::Connected { endpoint, server } => {
                            format!("connected {endpoint} server-{:x?}", server.0.first())
                        }
                        ConnEvent::SessionEnded { endpoint, reason } => format!(
                            "ended {endpoint} reason={}",
                            reason.map(|r| r.to_string()).unwrap_or_else(|| "io".into())
                        ),
                    });
                },
            )
            .await;
        });

        // (1) First connection + data-plane echo.
        wait_event(&mut ev_rx, "connected").await;
        mock.inject(b"\x45\x00\x00\x14first");
        wait_written(&mock, 1).await;
        assert_eq!(mock.written()[0], b"\x45\x00\x00\x14first");

        // (2) Peer kills all sessions ⇒ SessionEnded ⇒ backoff ⇒ reconnect.
        peer.kill_sessions();
        wait_event(&mut ev_rx, "ended").await;
        wait_event(&mut ev_rx, "connected").await;

        // (3) Data plane works after reconnect (tun device resident and
        //     reused).
        let base = mock.written().len();
        mock.inject(b"\x45\x00\x00\x14again");
        wait_written(&mock, base + 1).await;
        assert_eq!(mock.written()[base], b"\x45\x00\x00\x14again");

        sup.abort();
        tun.shutdown();
    }

    async fn wait_event(rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>, needle: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(ev)) => {
                    if ev.contains(needle) {
                        return;
                    }
                }
                _ => panic!("event {needle:?} not seen within 15s"),
            }
        }
    }

    async fn wait_written(mock: &std::sync::Arc<MockTunDevice>, n: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while mock.written().len() < n && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            mock.written().len() >= n,
            "write side did not reach {n} (now {})",
            mock.written().len()
        );
    }

    /// Regression (review-confirmed defect): when TCP connects but R1 never
    /// arrives (black-hole peer), dial must not hang forever — connect +
    /// initiate are bounded as a whole and return
    /// [`ClientError::DialTimeout`] (the old shape wrapped only connect in
    /// DIAL_TIMEOUT, `initiate` had no timeout ⇒ supervise hung).
    #[tokio::test]
    async fn dial_times_out_when_r1_never_arrives() {
        use flock_protocol::session::{ClusterId, ServerEntry, ServerId};

        // Black-hole peer: accepts and holds the connection but sends zero
        // bytes (R1 never arrives).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });

        let identity = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let entry = ServerEntry {
            server_id: ServerId([9; 16]),
            relay_endpoint: ep.clone(),
            identity_pub: identity.verifying_key(),
            static_hybrid_pub: flock_protocol::kem::HybridKeypair::generate(&mut rand::rngs::OsRng)
                .public(),
        };
        let pin = ServerPin {
            cluster_id: ClusterId([7; 16]),
            cluster_root_pub: flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                .verifying_key(),
            entry,
        };
        let device = DeviceStaticKeys::generate();

        let res = tokio::time::timeout(
            Duration::from_secs(5),
            dial_with_timeout(
                &pin,
                &device,
                TunnelConfig::default(),
                Duration::from_millis(300),
            ),
        )
        .await
        .expect("dial must return on time (never hang on a black-hole peer)");
        match res {
            Err(ClientError::DialTimeout(ep_got)) => assert_eq!(ep_got, ep),
            other => panic!("expected DialTimeout, got {other:?}"),
        }
    }

    #[test]
    fn backoff_sequence_and_jitter_bounds() {
        let mut b = Backoff::new(Duration::from_secs(5), Duration::from_secs(60));
        // No jitter: 5,10,20,40,60 (capped),60…
        let seq: Vec<Duration> = (0..6).map(|_| b.next_jitter(0.0)).collect();
        assert_eq!(
            seq,
            vec![
                Duration::from_secs(5),
                Duration::from_secs(10),
                Duration::from_secs(20),
                Duration::from_secs(40),
                Duration::from_secs(60),
                Duration::from_secs(60),
            ],
            "5s base, doubling, capped at 60s (§2.3)"
        );
        // Jitter bounds: each step d ∈ [step, step·1.25] (step = that step's
        // un-jittered base).
        let mut b2 = Backoff::new(Duration::from_secs(5), Duration::from_secs(60));
        for k in 0..8u32 {
            let step = Duration::from_secs(5u64.saturating_mul(1 << k.min(4)))
                .min(Duration::from_secs(60));
            let d = b2.next_jitter(0.999);
            assert!(
                d >= step && d <= step.mul_f64(1.25 + 1e-9),
                "attempt {k}: {d:?} not within [{step:?}, {:.2?}]",
                step.mul_f64(1.25)
            );
        }
        // Reset after success.
        let mut b3 = Backoff::default();
        let _ = b3.next_jitter(0.0);
        let _ = b3.next_jitter(0.0);
        b3.reset();
        assert_eq!(
            b3.next_jitter(0.0),
            Duration::from_secs(5),
            "back to the 5s base after reset"
        );
    }

    #[test]
    fn endpoint_ring_rotates() {
        let mut r = EndpointRing::new(vec!["a:1".into(), "b:2".into(), "a:1".into(), "c:3".into()]);
        assert_eq!(r.len(), 4); // rotation does not dedup here (the directory endpoint set is deduped in endpoints())
        let got: Vec<String> = (0..5).map(|_| r.next_endpoint().unwrap()).collect();
        assert_eq!(
            got,
            ["a:1", "b:2", "a:1", "c:3", "a:1"],
            "round-robin rotation"
        );
        let mut empty = EndpointRing::new(vec![]);
        assert!(empty.next_endpoint().is_none());
    }

    /// M7 control-stream shared slot × supervise: silent peer (real session,
    /// control stream never answers) ⇒ (1) plane in place after connecting;
    /// (2) a short-timeout request ⇒ timeout + **poisoning** (plane down) +
    /// killed signal ⇒ supervise ends this session early → backoff → after
    /// reconnecting the plane is back in place (fresh stream).
    #[tokio::test]
    async fn supervise_with_control_poisons_and_reconnects_on_timeout() {
        use flock_protocol::session::{
            respond, ClusterId, DeviceRecord, InMemoryDirectory, ServerId, ServerIdentity,
        };
        use flock_protocol::trust::ClusterDirectory;

        // Silent peer: real respond session + control stream held and never
        // answered (the control-plane replica of the R1 black-hole shape).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = listener.local_addr().unwrap().to_string();
        let root = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let identity = std::sync::Arc::new(ServerIdentity::enroll(
            &root,
            ClusterId([7; 16]),
            ServerId([9; 16]),
            &ep,
        ));
        let directory =
            ClusterDirectory::issue(&root, identity.cluster_id, 1, vec![identity.entry.clone()]);
        let device = DeviceStaticKeys::generate();
        let dev_dir = std::sync::Arc::new({
            let mut d = InMemoryDirectory::new();
            d.register(DeviceRecord {
                device_x25519: device.x25519_public(),
                device_ed25519: device.ed25519_public(),
            });
            d
        });
        let silent = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((io, _)) = listener.accept().await {
                let dir = (*dev_dir).clone();
                let identity = identity.clone();
                held.push(tokio::spawn(async move {
                    // After the session is established, hold every stream and
                    // never answer (silent — control-stream black hole).
                    if let Ok(tunnel) = respond(io, &identity, dir, TunnelConfig::default()).await {
                        let _streams: Vec<_> = {
                            let mut v = Vec::new();
                            while let Some(s) = tunnel.accept_stream().await {
                                v.push(s);
                            }
                            v
                        };
                    }
                }));
            }
        });

        let mut pins = PinStore::new();
        pins.pin(&directory.cluster_id, &root.verifying_key());
        let state = ClientState {
            device,
            pins,
            directory: directory.clone(),
        };

        let mock = std::sync::Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = std::sync::Arc::new(TunIo::from_arc(mock.clone()));
        let tun_sup = tun.clone();

        let plane = crate::ctrl::ControlPlane::new();
        let plane_sup = plane.clone();
        let (epoch_tx, _epoch_rx) = tokio::sync::watch::channel(0u64);
        let sup = tokio::spawn(async move {
            supervise_with_control(
                &state,
                tun_sup.as_ref(),
                TunnelConfig::default(),
                Backoff::new(Duration::from_millis(80), Duration::from_millis(300)),
                |_| {},
                epoch_tx,
                plane_sup,
            )
            .await;
        });

        // (1) Connection established ⇒ plane in place.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while !plane.is_up() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "not connected within 15s"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // (2) Short-timeout request (silent peer) ⇒ TimedOut + poisoning
        //     (plane down).
        let r = plane
            .request_timeout(
                flock_protocol::roster::CtrlRequest::Hello { ver: 1 },
                Duration::from_millis(150),
            )
            .await;
        assert!(r.is_err() && r.unwrap_err().kind() == std::io::ErrorKind::TimedOut);
        assert!(!plane.is_up(), "poisoned ⇒ down");
        // Request with no session ⇒ immediate "not ready" error.
        assert!(plane
            .request(flock_protocol::roster::CtrlRequest::Hello { ver: 1 })
            .await
            .is_err());
        // (3) killed ⇒ supervise tears the session down → backoff →
        //     reconnect ⇒ plane back in place (fresh stream).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while !plane.is_up() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "not reconnected within 15s"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        sup.abort();
        silent.abort();
        tun.shutdown();
    }

    fn invite_fixture(
        root: &flock_protocol::ed25519_dalek::SigningKey,
        ttl: u64,
    ) -> flock_protocol::trust::InviteFile {
        use flock_protocol::session::{ClusterId, ServerEntry, ServerId};
        let identity = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let entry = ServerEntry {
            server_id: ServerId([9; 16]),
            relay_endpoint: "frps.test:27500".into(),
            identity_pub: identity.verifying_key(),
            static_hybrid_pub: flock_protocol::kem::HybridKeypair::generate(&mut rand::rngs::OsRng)
                .public(),
        };
        flock_protocol::trust::InviteFile::issue(
            root,
            ClusterId([7; 16]),
            1,
            vec![entry],
            flock_protocol::trust::now_unix() + ttl,
            [5; 16],
        )
    }

    #[test]
    fn ingest_invite_pins_root_and_persists_state() {
        let dir = tempfile::tempdir().unwrap();
        let root = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let inv = invite_fixture(&root, 3600);
        let state = ingest_invite(dir.path(), &inv).expect("ingest");
        assert_eq!(state.endpoints(), vec!["frps.test:27500".to_string()]);
        // Reload (trio persisted; the keys generated by gen-keys first stay
        // the same).
        let re = ClientState::load(dir.path(), false).expect("reload");
        assert_eq!(
            re.device.to_bytes(),
            state.device.to_bytes(),
            "device keys stable across invite/load (never leave the machine)"
        );
        assert_eq!(re.directory.dir_version, 1);
        // pin_for yields dialable material (root = the pinned value).
        let pin = re.pin_for("frps.test:27500").expect("pin");
        assert_eq!(pin.cluster_root_pub, root.verifying_key());
        // Unknown endpoint ⇒ None (endpoint↔material signed together).
        assert!(re.pin_for("evil:1").is_none());
    }

    #[test]
    fn ingest_invite_rejects_expired_and_root_change() {
        let dir = tempfile::tempdir().unwrap();
        let root = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        // Expired: rejected.
        let expired = flock_protocol::trust::InviteFile {
            expiry_unix: 1,
            ..invite_fixture(&root, 3600)
        };
        assert!(
            matches!(
                ingest_invite(dir.path(), &expired),
                Err(ClientError::Trust(_))
            ),
            "expired invite rejected"
        );
        // Root change: pin A first, then an invite signed by B ⇒ RootChanged
        // (explicit warning, not silent).
        ingest_invite(dir.path(), &invite_fixture(&root, 3600)).expect("first pin");
        let other = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        match ingest_invite(dir.path(), &invite_fixture(&other, 3600)) {
            Err(ClientError::Trust(flock_protocol::trust::TrustError::RootChanged { .. })) => {}
            other_res => panic!("expected RootChanged, got {other_res:?}"),
        }
    }

    #[test]
    fn load_requires_directory_and_vip_resolution() {
        let dir = tempfile::tempdir().unwrap();
        // Keys only, no directory ⇒ the run path rejects (with an invite
        // hint).
        let _ = ClientState::load_keys(dir.path(), true).unwrap();
        assert!(matches!(
            ClientState::load(dir.path(), false),
            Err(ClientError::State(_))
        ));
        // VIP resolution: config override wins; default reads the vip file.
        let state = {
            let root = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
            ingest_invite(dir.path(), &invite_fixture(&root, 3600)).unwrap()
        };
        assert_eq!(
            state
                .resolve_vip(dir.path(), Some("100.64.0.11".parse().unwrap()))
                .unwrap(),
            "100.64.0.11".parse::<std::net::Ipv4Addr>().unwrap()
        );
        std::fs::write(dir.path().join(VIP_FILE), "100.64.0.42\n").unwrap();
        assert_eq!(
            state.resolve_vip(dir.path(), None).unwrap(),
            "100.64.0.42".parse::<std::net::Ipv4Addr>().unwrap()
        );
    }
}
