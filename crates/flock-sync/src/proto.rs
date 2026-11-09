//! NetState write-operation set and read queries (docs/design.md §3.10
//! interface; semantically aligned with the M2 single-server `NetState` trait
//! — see the discipline note in app/flock-server/src/netstate.rs).
//!
//! All writes = [`SyncRequest`], executed deterministically by
//! [`crate::state::NetStateData::apply`] after Raft commit. **admin_op
//! (add_voter/rewrap/revoke_invite) and server_keys must carry a cluster root
//! key signature** ([`RootSigned`]), effective after the state machine
//! verifies it (§4 admission red line R19: a single compromised in-register
//! server does not hold the root key, cannot self-grant admission, cannot
//! trigger a rewrap).

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

/// Hand-rolled serde bridge for `[u8; 64]` (serde's built-in array impls only
/// go up to 32).
pub(crate) mod arr64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v = Vec::<u8>::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

/// Raft node ID (openraft NodeId = u64).
pub type NodeId = u64;

/// VIP pool: `100.64.0.0/10` (RFC 6598, §2.1). `100.64.0.1`–`100.64.0.10` are
/// reserved for the servers themselves (in the multi-primary shape every
/// server gets one tun VIP each — §6.2 topology: server-a/b/c = .1/.2/.3);
/// device allocation starts at `.11` (§6.2 client VIPs 100.64.0.11/.12/.13).
pub const VIP_FIRST: u32 = u32::from_be_bytes([100, 64, 0, 11]);
/// Pool end (the last usable address in the /10 block).
pub const VIP_LAST: u32 = u32::from_be_bytes([100, 127, 255, 254]);

/// Deterministic derivation of a server's own VIP (§6.2 server segment
/// .1–.10): node 1..=10 → `100.64.0.<node_id>`; out of range (0 or >10) ⇒
/// None. ServerKeys root-signed registration uses this as
/// `ServerKeyEntry.vip` (the data source of the M7 roster's Server entry —
/// one network-wide derivation, no second source of truth).
pub fn server_vip_of(node_id: NodeId) -> Option<[u8; 4]> {
    (1..=10)
        .contains(&node_id)
        .then_some([100, 64, 0, node_id as u8])
}

/// Inverse of [`server_vip_of`]: server-segment VIP (`100.64.0.1`–`.10`) →
/// node id; non-server-segment address ⇒ None. Used by the M8b forwarding
/// plane (client packet dst = remote server VIP ⇒ mapped to that server's
/// server-self synthetic device to ride a ForwardEnvelope — §7-M8.2 "any
/// server VIP reachable").
pub fn server_vip_node(vip: &[u8; 4]) -> Option<NodeId> {
    match vip {
        [100, 64, 0, n @ 1..=10] => Some(u64::from(*n)),
        _ => None,
    }
}

/// Domain-separation label for admin operations (canonical byte prefix).
const L_ADMIN: &[u8] = b"flock-sync/admin/v1";
/// Domain-separation label for server_keys (a missed spot of the ch-sync→
/// flock-sync directory rename — wire-format change allowed within the
/// unreleased window; the state machine stores only entries, no label-derived
/// data, signing/verification recompute from the same source, no migration
/// surface).
const L_SERVER_KEYS: &[u8] = b"flock-sync/server-keys/v1";
/// Domain-separation label for the Bootstrap self-attestation.
const L_BOOTSTRAP: &[u8] = b"flock-sync/bootstrap/v1";

// ============================================================================
// Row types (same semantics as M2 netstate.rs; a later M4 batch converges the
// trait on the server-assembly side)
// ============================================================================

/// Device status (disable-not-delete: row retained, VIP not reclaimed, §2.1;
/// Expired = time-based eviction after being offline past the retention
/// period — row retained for audit, VIP returned to the allocation pool,
/// §7-M7 IP-reuse policy revision).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    Active,
    Disabled,
    Revoked,
    /// M7: offline beyond the retention period (terminal; Expired ≠ Revoked —
    /// the roster/audit can distinguish).
    Expired,
}

impl DeviceStatus {
    pub fn code(self) -> u8 {
        match self {
            DeviceStatus::Active => 1,
            DeviceStatus::Disabled => 2,
            DeviceStatus::Revoked => 3,
            DeviceStatus::Expired => 4,
        }
    }
    pub fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(DeviceStatus::Active),
            2 => Some(DeviceStatus::Disabled),
            3 => Some(DeviceStatus::Revoked),
            4 => Some(DeviceStatus::Expired),
            _ => None,
        }
    }
}

// hostname contract (M7 client batch hoisted into
// flock_protocol::roster — the client reporting side and the server
// persistence side share the same truncation/empty-string semantics, no
// second source of truth; the existing paths `flock_sync::proto::*`/
// `flock_sync::*` stay unchanged).
pub use flock_protocol::roster::{normalize_hostname, HOSTNAME_MAX, HOSTNAME_UNKNOWN};

/// Registry device row (§2.2: a device = (DeviceId, owner, VIP, static public
/// key set, status, hostname, expired_at, registered_at) — the last three
/// fields added in M7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRow {
    pub owner: String,
    pub device_x25519: [u8; 32],
    pub device_ed25519: [u8; 32],
    pub vip: [u8; 4],
    pub status: DeviceStatus,
    /// The revocation_epoch at which the status determination
    /// (disable/revocation) took effect.
    pub since_epoch: u64,
    /// M7: hostname reported by the client at onboarding (empty ⇒
    /// "(unknown)"; updatable on re-register).
    pub hostname: String,
    /// M7: the unix second the row was set to Expired (audit); always None
    /// for non-Expired.
    pub expired_at: Option<u64>,
    /// M7 (reaper semantics fix, §7-M7.5): registration moment (unix seconds,
    /// **injected by the submitter** — apply has no clock, a determinism
    /// requirement). The retention-period anchor when `last_seen` has no
    /// observation (0) — the landing form of "the clock starts at
    /// registration"; anchoring at epoch 0 would finalize online devices that
    /// had not yet been observed after a restart. Snapshot/wire-format
    /// compatibility: postcard has no field tags, so after adding fields old
    /// snapshots/old logs no longer decode — allowed within the unreleased
    /// window (§7-M7.1, same discipline).
    pub registered_at: u64,
}

/// User row: OPAQUE registration record + SR-SIG1 user public key set (§2.4) +
/// the three M8 web-admin fields (§7-M8.3 verbatim: admin/disabled/
/// pw_bootstrap — postcard has no field tags ⇒ old snapshots/old logs no
/// longer decode, allowed within the unreleased window (§7-M7.1, same
/// discipline; on upgrade, leftover old databases are rebuilt)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRow {
    pub opaque_record: Option<String>,
    pub opaque_profile: u16,
    pub sr_sig_pubs: Vec<[u8; 32]>,
    /// M8: web-admin role (decides webui admin-endpoint authorization).
    pub admin: bool,
    /// M8: disabled ⇒ blocks Web and control-plane login (existing sessions
    /// are not retroactively disconnected; device-level disconnects go through
    /// disable/revoke).
    pub disabled: bool,
    /// M8: one-shot bootstrap token for the initial/reset password (set to
    /// None once consumed; same trust level as invite_id — readable inside
    /// Raft state, single-use).
    pub pw_bootstrap: Option<[u8; 16]>,
}

/// Invite status (one-shot credential, §1.3.3f).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InviteStatus {
    Valid,
    Used,
    Revoked,
}

/// Invite row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRow {
    pub expiry_unix: u64,
    pub status: InviteStatus,
}

/// Server key entry (server_keys write-operation record; the 1216B hybrid is
/// carried as a Vec). `vip` = that server's mesh VIP (M7: the data source of
/// the roster's Server entry; signed together with the identity/hybrid keys —
/// fixed at root-signed registration, readable from any node's local view).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerKeyEntry {
    pub server_id: NodeId,
    pub identity_pub: [u8; 32],
    pub hybrid_pub: Vec<u8>,
    pub vip: [u8; 4],
}

// ============================================================================
// Root-signed administrative operations
// ============================================================================

/// Cluster root key signature carrier: `sig` covers the canonical bytes of
/// `op` (domain separation per the various `*_canonical` functions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSigned<T> {
    pub op: T,
    #[serde(with = "arr64")]
    pub sig: [u8; 64],
}

/// The three admin_op forms (§3.10/§4: must carry a cluster root key
/// signature, effective after state-machine verification).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminOp {
    /// New voter admission (interlocked with openraft change_membership, §4
    /// admission pipeline).
    AddVoter { node_id: NodeId },
    /// secrets rewrap: extend the per-server-wrapped shared secret to a new
    /// server (an independent administrative operation, §4-3).
    Rewrap { server_id: NodeId, wrapped: Vec<u8> },
    /// Revoke an unredeemed invite.
    RevokeInvite { invite_id: [u8; 16] },
}

/// Canonical bytes of [`AdminOp`] (signature coverage; length-prefixed
/// delimiting eliminates concatenation ambiguity).
pub fn admin_canonical(op: &AdminOp) -> Vec<u8> {
    let mut v = Vec::with_capacity(96);
    v.extend_from_slice(L_ADMIN);
    match op {
        AdminOp::AddVoter { node_id } => {
            v.push(1);
            v.extend_from_slice(&node_id.to_le_bytes());
        }
        AdminOp::Rewrap { server_id, wrapped } => {
            v.push(2);
            v.extend_from_slice(&server_id.to_le_bytes());
            v.extend_from_slice(&(wrapped.len() as u32).to_le_bytes());
            v.extend_from_slice(wrapped);
        }
        AdminOp::RevokeInvite { invite_id } => {
            v.push(3);
            v.extend_from_slice(invite_id);
        }
    }
    v
}

/// Canonical bytes of the server_keys write operation (M7: the entry's added
/// `vip` is inside the signature coverage — registered root-signed in the
/// same batch, signing/verification recompute from the same source, no
/// migration surface).
pub fn server_keys_canonical(entries: &[ServerKeyEntry]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + entries.len() * 1280);
    v.extend_from_slice(L_SERVER_KEYS);
    v.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        v.extend_from_slice(&e.server_id.to_le_bytes());
        v.extend_from_slice(&e.identity_pub);
        v.extend_from_slice(&(e.hybrid_pub.len() as u32).to_le_bytes());
        v.extend_from_slice(&e.hybrid_pub);
        v.extend_from_slice(&e.vip);
    }
    v
}

/// Canonical bytes of the Bootstrap write operation (root key
/// self-attestation: root_pub's signature over these bytes).
pub fn bootstrap_canonical(
    cluster_id: &[u8; 16],
    root_pub: &[u8; 32],
    ticket_root: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(L_BOOTSTRAP.len() + 80);
    v.extend_from_slice(L_BOOTSTRAP);
    v.extend_from_slice(cluster_id);
    v.extend_from_slice(root_pub);
    v.extend_from_slice(ticket_root);
    v
}

// ============================================================================
// Write request / response
// ============================================================================

/// NetState write operations (committed through Raft; §3.10
/// `NetState::{register_device, revoke, allocate_ip, redeem_invite,
/// revoke_invite, config_version, server_keys, rewrap, admin_op}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Cluster identity bootstrap (the first administrative write; accepted
    /// only once, idempotent replay allowed): cluster_id + the cluster root
    /// public key + the ticket key root (32B random, **the ticket key root
    /// lives inside Raft**, §4). `sig` = the root key's signature over
    /// [`bootstrap_canonical`] (self-attestation).
    Bootstrap {
        cluster_id: [u8; 16],
        root_pub: [u8; 32],
        ticket_root: [u8; 32],
        #[serde(with = "arr64")]
        sig: [u8; 64],
    },
    /// Register a device (allocates a VIP, monotonic, never reused; M7 added
    /// hostname — empty string lands as "(unknown)"). `registered_at_unix` is
    /// injected by the submitter (apply has no clock — determinism; lands in
    /// `DeviceRow.registered_at`, the retention-period anchor for the reaper).
    RegisterDevice {
        owner: String,
        x25519: [u8; 32],
        ed25519: [u8; 32],
        hostname: String,
        registered_at_unix: u64,
    },
    /// Revoke a device: status set to Revoked (row retained, VIP not
    /// reclaimed) + global revocation_epoch +1 (§2.2).
    Revoke { device: [u8; 32] },
    /// Disable a device (no deletion; epoch advances with it, invalidating
    /// outstanding tickets).
    Disable { device: [u8; 32] },
    /// Re-enable (Disabled → Active only; Revoked/Expired are irreversible
    /// terminal states).
    Enable { device: [u8; 32] },
    /// M7: expire a device (submitted by the reaper; row retained for audit +
    /// VIP returned to the allocation pool + epoch advanced + revocation
    /// propagation hooks — Expired ≠ Revoked, §7-M2/§7-M7). `now_unix` is
    /// injected by the submitter (deterministically lands in expired_at).
    /// Idempotent: replay over an already-Expired row is allowed, epoch
    /// untouched.
    Expire { device: [u8; 32], now_unix: u64 },
    /// M7: update a device's hostname (re-register path; Active/Disabled rows
    /// only).
    SetHostname { device: [u8; 32], hostname: String },
    /// VIP allocation (monotonic watermark; not reclaimed).
    AllocateIp,
    /// Invite registration (recorded at issue time together with the
    /// InviteFile).
    RecordInvite {
        invite_id: [u8; 16],
        expiry_unix: u64,
    },
    /// Invite redemption (dedup + revocation/expiry checks + user/device
    /// creation + VIP allocation inside the Raft state machine, done
    /// atomically in a single commit, §1.3.3f "an invite's lifetime"; M7
    /// added hostname).
    RedeemInvite {
        invite_bytes: Vec<u8>,
        username: String,
        x25519: [u8; 32],
        ed25519: [u8; 32],
        hostname: String,
        now_unix: u64,
    },
    /// Set a user's password record (only when unset; the replicated form of
    /// the control-plane PwCommit).
    SetPassword {
        user: String,
        record_b64: String,
        profile: u16,
    },
    /// Register an SR-SIG1 user public key (the replicated form of the
    /// key-bind path).
    AddUserSigKey { user: String, pub32: [u8; 32] },
    /// One-shot consumption of a bind_token (the replicated form of the §2.4
    /// linearizable dedup).
    ConsumeBindToken { token: [u8; 16] },
    /// Network configuration version bump (derived data versioned by the
    /// state machine, vpn-mesh §5.2).
    BumpConfigVersion,
    /// Server key set registration/rotation (root-signed administrative
    /// operation).
    ServerKeys(RootSigned<Vec<ServerKeyEntry>>),
    /// Cluster OPRF key registration (root-signed administrative operation;
    /// OPAQUE records verifiable network-wide — §2.4 "the OPRF key lives
    /// inside the Raft state machine". Idempotent: replay with the same value
    /// allowed, different value rejected).
    SetOprf(RootSigned<String>),
    /// admin_op (add_voter/rewrap/revoke_invite; root-signed administrative
    /// operation, effective after state-machine verification).
    AdminOp(RootSigned<AdminOp>),
    // —— M8 (§7-M8.3) appended at the tail: ordinary writes of the web admin
    //    plane (no root-signature requirement — authorization lives in the
    //    submitter's handler/CLI layer, same shape as
    //    SetPassword/AddUserSigKey). ——
    /// Create a user (no password record, carrying a one-shot bootstrap
    /// token); already exists ⇒ `StateError::UserExists` (the submitter may
    /// ignore idempotently as needed — the multi-primary path of
    /// `web-admin-add`).
    CreateUser {
        username: String,
        pw_bootstrap: [u8; 16],
    },
    /// Land a password record via the bootstrap token (atomic: token matches
    /// AND record empty ⇒ land record + clear token; wrong/consumed token ⇒
    /// `StateError::BadBootstrapToken`; record already present ⇒
    /// `StateError::PasswordExists`).
    SetPasswordBootstrap {
        user: String,
        token: [u8; 16],
        record_b64: String,
        profile: u16,
    },
    /// Admin password reset: clear the password record + set a new bootstrap
    /// token (the old password becomes invalid immediately).
    ResetPassword { user: String, new_token: [u8; 16] },
    /// Set/unset the web-admin role (the session-side adjudication of
    /// `cannot_demote_self` lives in the webui handler layer — the state
    /// machine does not know the session principal).
    SetUserAdmin { user: String, admin: bool },
    /// Disable/enable a user (blocks Web and control-plane login; existing
    /// sessions are not retroactively disconnected).
    SetUserDisabled { user: String, disabled: bool },
}

impl SyncRequest {
    /// Convenience constructor: a root-key-signed rewrap administrative
    /// operation.
    pub fn rewrap_signed(
        root: &ed25519_dalek::SigningKey,
        server_id: NodeId,
        wrapped: Vec<u8>,
    ) -> Self {
        let op = AdminOp::Rewrap { server_id, wrapped };
        let sig = root.sign(&admin_canonical(&op)).to_bytes();
        SyncRequest::AdminOp(RootSigned { op, sig })
    }

    /// Convenience constructor: a root-key-signed add_voter administrative
    /// operation.
    pub fn add_voter_signed(root: &ed25519_dalek::SigningKey, node_id: NodeId) -> Self {
        let op = AdminOp::AddVoter { node_id };
        let sig = root.sign(&admin_canonical(&op)).to_bytes();
        SyncRequest::AdminOp(RootSigned { op, sig })
    }

    /// Convenience constructor: a root-key-signed server_keys administrative
    /// operation.
    pub fn server_keys_signed(
        root: &ed25519_dalek::SigningKey,
        entries: Vec<ServerKeyEntry>,
    ) -> Self {
        let sig = root.sign(&server_keys_canonical(&entries)).to_bytes();
        SyncRequest::ServerKeys(RootSigned { op: entries, sig })
    }

    /// Convenience constructor: Bootstrap (root-key self-attestation
    /// signature).
    pub fn bootstrap_signed(
        root: &ed25519_dalek::SigningKey,
        cluster_id: [u8; 16],
        ticket_root: [u8; 32],
    ) -> Self {
        let root_pub = *root.verifying_key().as_bytes();
        let sig = root
            .sign(&bootstrap_canonical(&cluster_id, &root_pub, &ticket_root))
            .to_bytes();
        SyncRequest::Bootstrap {
            cluster_id,
            root_pub,
            ticket_root,
            sig,
        }
    }
}

/// State-machine-level rejection (deterministic: all nodes produce the same
/// rejection for the same log entry, no divergence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateError {
    NotBootstrapped,
    AlreadyBootstrapped,
    BadRootSignature,
    RootMismatch,
    DeviceExists,
    DeviceNotFound,
    RevokedIsTerminal,
    /// Expired is terminal (like Revoked: the old VIP may already be back in
    /// the pool and assigned to a new device; revival breaks injectivity).
    ExpiredIsTerminal,
    UserExists,
    AlreadyUsed,
    InviteRevoked,
    InviteExpired {
        now_unix: u64,
        expiry_unix: u64,
    },
    UnknownInvite,
    BadInvite(String),
    IpExhausted,
    NotFound(String),
    /// Password already set (changing it goes through the logged-in path, an
    /// unimplemented surface).
    PasswordExists,
    NoSuchUser,
    /// bind_token already consumed (one-shot credential replay).
    BindTokenUsed,
    /// M8: the password bootstrap token mismatches/has been consumed (one-shot
    /// credential; the state-machine-level rejection of SetPasswordBootstrap
    /// — an idempotent replay yields the same error).
    BadBootstrapToken,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::NotBootstrapped => write!(f, "cluster not bootstrapped"),
            StateError::AlreadyBootstrapped => write!(f, "cluster already bootstrapped"),
            StateError::BadRootSignature => write!(f, "admin op: cluster root signature mismatch"),
            StateError::RootMismatch => write!(f, "bootstrap root != locally pinned root"),
            StateError::DeviceExists => write!(f, "device already registered"),
            StateError::DeviceNotFound => write!(f, "device not found"),
            StateError::RevokedIsTerminal => write!(f, "revoked is terminal"),
            StateError::ExpiredIsTerminal => write!(f, "expired is terminal"),
            StateError::UserExists => write!(f, "username already exists"),
            StateError::AlreadyUsed => write!(f, "invite already redeemed"),
            StateError::InviteRevoked => write!(f, "invite revoked"),
            StateError::InviteExpired {
                now_unix,
                expiry_unix,
            } => {
                write!(f, "invite expired (now={now_unix}, expiry={expiry_unix})")
            }
            StateError::UnknownInvite => write!(f, "unknown invite_id"),
            StateError::BadInvite(m) => write!(f, "bad invite: {m}"),
            StateError::IpExhausted => write!(f, "VIP pool exhausted"),
            StateError::NotFound(m) => write!(f, "not found: {m}"),
            StateError::PasswordExists => write!(f, "password already set"),
            StateError::NoSuchUser => write!(f, "no such user"),
            StateError::BindTokenUsed => write!(f, "bind_token already consumed"),
            StateError::BadBootstrapToken => write!(f, "bad or consumed password bootstrap token"),
        }
    }
}
impl std::error::Error for StateError {}

/// Client-facing errors (write forwarding / linearizable read paths; the wire
/// format carries the ForwardToLeader semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncError {
    /// This node is not the leader (`leader` = the known leader, possibly
    /// None — election in progress).
    ForwardToLeader { leader: Option<NodeId> },
    /// No usable leader found within the budget.
    NoLeader,
    /// Raft-internal error (fatal/storage).
    Raft(String),
    /// Interconnect call failure.
    Wire(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::ForwardToLeader { leader } => write!(f, "forward to leader: {leader:?}"),
            SyncError::NoLeader => write!(f, "no leader available within budget"),
            SyncError::Raft(m) => write!(f, "raft: {m}"),
            SyncError::Wire(m) => write!(f, "wire: {m}"),
        }
    }
}
impl std::error::Error for SyncError {}

/// admin_op execution receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminAck {
    AddVoter {
        node_id: NodeId,
    },
    /// Wrapped byte count after the rewrap landed (the OPRF key copy is
    /// observable, for §7-M4 admission assertions).
    Rewrap {
        server_id: NodeId,
        bytes: usize,
    },
    RevokeInvite,
}

/// Write-operation products.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncResponse {
    Ok,
    Device(DeviceRow),
    /// The global revocation_epoch after revoke/disable/enable (including
    /// unchanged paths).
    Epoch(u64),
    Ip([u8; 4]),
    Redeem {
        username: String,
        device_id: [u8; 32],
        vip: [u8; 4],
    },
    ConfigVersion(u64),
    ServerKeys {
        servers: usize,
    },
    Admin(AdminAck),
    /// State-machine-level rejection (see [`StateError`]).
    Error(StateError),
}

// ============================================================================
// Read queries (linearizable reads: executed on the leader after
// ensure_linearizable)
// ============================================================================

/// Wire format of the directory's three-way verdict (a serializable isomorph
/// of `LookupVerdict`; §1.3.3c).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictW {
    NotFound,
    Revoked { since_epoch: u64 },
    Active { x25519: [u8; 32], ed25519: [u8; 32] },
}

impl VerdictW {
    /// Convert to the protocol-library verdict (corrupt public keys treated
    /// as untrusted → NotFound, fail-closed).
    pub fn to_verdict(&self) -> flock_protocol::session::LookupVerdict {
        use ed25519_dalek::VerifyingKey;
        use flock_protocol::session::{DeviceRecord, LookupVerdict};
        match self {
            VerdictW::NotFound => LookupVerdict::NotFound,
            VerdictW::Revoked { since_epoch } => LookupVerdict::Revoked {
                since_epoch: *since_epoch,
            },
            VerdictW::Active { x25519, ed25519 } => match VerifyingKey::from_bytes(ed25519) {
                Ok(device_ed25519) => LookupVerdict::Active(DeviceRecord {
                    device_x25519: flock_protocol::x25519_dalek::PublicKey::from(*x25519),
                    device_ed25519,
                }),
                Err(_) => LookupVerdict::NotFound,
            },
        }
    }

    /// Convert from the protocol-library verdict to the wire format.
    pub fn from_verdict(v: &flock_protocol::session::LookupVerdict) -> Self {
        use flock_protocol::session::LookupVerdict;
        match v {
            LookupVerdict::NotFound => VerdictW::NotFound,
            LookupVerdict::Revoked { since_epoch } => VerdictW::Revoked {
                since_epoch: *since_epoch,
            },
            LookupVerdict::Active(rec) => VerdictW::Active {
                x25519: *rec.device_x25519.as_bytes(),
                ed25519: *rec.device_ed25519.as_bytes(),
            },
        }
    }
}

/// Cluster state digest (for the "no lost commits" / replication-plane
/// assertions).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateView {
    pub epoch: u64,
    pub config_version: u64,
    pub devices: usize,
    pub revoked: usize,
    /// M7: count of Expired rows (VIP already returned to the pool; listed
    /// separately from revoked — different audit/roster semantics).
    pub expired: usize,
    pub invites_used: usize,
    pub server_keys: usize,
    pub wraps: Vec<(NodeId, usize)>,
    pub voters: Vec<NodeId>,
    pub ticket_root_present: bool,
    pub last_applied: Option<u64>,
}

/// Linearizable read queries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReadQuery {
    Lookup([u8; 32]),
    Epoch,
    DeviceRow([u8; 32]),
    /// Fetch a server's rewrap wrapped copy (for local unwrapping checks on
    /// that server).
    Wrap(NodeId),
    /// User row (password record + SR-SIG1 public key set; for control-plane
    /// login/signature verification).
    User(String),
    /// All devices under an owner (for the registry List operation).
    DevicesOf(String),
    /// Full state digest (for assertions).
    State,
}

/// Linearizable read products.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReadView {
    Verdict(VerdictW),
    Epoch(u64),
    Device(Option<DeviceRow>),
    Wrap(Option<Vec<u8>>),
    User(Option<UserRow>),
    Devices(Vec<([u8; 32], DeviceRow)>),
    State(StateView),
}

// ============================================================================
// Unit tests: domain separation and delimiting of the canonical bytes
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_canonical_no_concat_ambiguity() {
        let a = admin_canonical(&AdminOp::Rewrap {
            server_id: 7,
            wrapped: vec![1, 2],
        });
        // Same prefix, different length ⇒ different products (length
        // delimiting).
        let b = admin_canonical(&AdminOp::Rewrap {
            server_id: 7,
            wrapped: vec![1, 2, 0],
        });
        assert_ne!(a, b);
        // Different op tag ⇒ different.
        let c = admin_canonical(&AdminOp::AddVoter { node_id: 7 });
        assert_ne!(a, c);
    }

    #[test]
    fn signed_constructors_verify() {
        use ed25519_dalek::{Signature, Verifier};
        let root = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let req = SyncRequest::rewrap_signed(&root, 9, vec![7; 32]);
        let RootSigned { op, sig } = match &req {
            SyncRequest::AdminOp(rs) => rs.clone(),
            _ => panic!("rewrap_signed must produce AdminOp"),
        };
        assert!(root
            .verifying_key()
            .verify(&admin_canonical(&op), &Signature::from_bytes(&sig))
            .is_ok());
        // Tampering with op ⇒ verification fails.
        let tampered = AdminOp::Rewrap {
            server_id: 10,
            wrapped: vec![7; 32],
        };
        assert!(root
            .verifying_key()
            .verify(&admin_canonical(&tampered), &Signature::from_bytes(&sig))
            .is_err());
    }

    #[test]
    fn verdict_wire_roundtrip() {
        use flock_protocol::session::{DeviceRecord, LookupVerdict};
        let v = LookupVerdict::Active(DeviceRecord {
            device_x25519: flock_protocol::x25519_dalek::PublicKey::from([9u8; 32]),
            device_ed25519: ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key(),
        });
        let w = VerdictW::from_verdict(&v);
        assert!(matches!(w.to_verdict(), LookupVerdict::Active(_)));
        assert!(matches!(
            VerdictW::Revoked { since_epoch: 4 }.to_verdict(),
            LookupVerdict::Revoked { since_epoch: 4 }
        ));
        assert!(matches!(
            VerdictW::NotFound.to_verdict(),
            LookupVerdict::NotFound
        ));
    }
}
