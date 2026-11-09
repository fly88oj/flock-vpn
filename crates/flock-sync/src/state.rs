//! Pure state machine data: NetState's deterministic execution core
//! (docs/design.md §3.10/§2.2 semantic discipline).
//!
//! Semantic discipline (same as the M2 single-server StateStore; M4 = the
//! Raft-replicated form of the same semantics):
//! - **VIP 100.64.0.0/10 allocation**: `100.64.0.1`–`.10` reserved for the
//!   servers themselves, the watermark only moves forward. IP-reuse policy
//!   (§2.1 M7 revision): **revoked/disabled → IP never reused** (row
//!   retained); **Expired (offline past the retention period) → the VIP is
//!   returned to the `vip_pool`** allocation pool and a new device may get it
//!   — the expired row stays on the books (audit) and is excluded from roster
//!   queries.
//! - **invite_id single-use consumption**: redeem dedups + marks within one
//!   state transition (a single Raft commit = atomic).
//! - **Revocation advances the global revocation_epoch**: only blocking
//!   transitions (→Disabled/→Revoked/→Expired) increment; Enable is a
//!   restoration and does not touch the epoch (otherwise it would
//!   harmlessly invalidate in-flight tickets network-wide).
//! - **The ticket key root lives inside Raft** (landed by Bootstrap, §4).
//!
//! `apply` is a pure, deterministic transition: all nodes produce the same
//! result for the same log entry — administrative operations that fail
//! verification return [`SyncResponse::Error`] (uniform rejection, no
//! divergence).

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use openraft::StoredMembership;
use openraft::{BasicNode, LogId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::proto::{
    admin_canonical, bootstrap_canonical, server_keys_canonical, AdminAck, AdminOp, DeviceRow,
    DeviceStatus, InviteRow, InviteStatus, NodeId, RootSigned, ServerKeyEntry, StateError,
    SyncRequest, SyncResponse, UserRow, VerdictW, VIP_FIRST, VIP_LAST,
};

/// Cluster identity (Bootstrap product).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterIdent {
    pub cluster_id: [u8; 16],
    pub root_pub: [u8; 32],
}

/// Revocation side effect (produced by apply; the [`crate::sm`] wrapper fires
/// the hooks: kill local session / reject outstanding tickets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationEffect {
    pub device: [u8; 32],
    pub new_epoch: u64,
}

/// Apply product of a single write operation.
#[derive(Debug, Clone, PartialEq)]
pub struct ApplyOutcome {
    pub resp: SyncResponse,
    /// Non-empty for blocking status transitions (Revoke/Disable) ⇒ fire the
    /// revocation-propagation hooks (§2.2).
    pub revoked: Option<RevocationEffect>,
}

impl ApplyOutcome {
    fn ok(resp: SyncResponse) -> Self {
        ApplyOutcome {
            resp,
            revoked: None,
        }
    }
    fn err(e: StateError) -> Self {
        ApplyOutcome {
            resp: SyncResponse::Error(e),
            revoked: None,
        }
    }
}

/// NetState state machine data (snapshot = serialization of this struct).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetStateData {
    pub cluster: Option<ClusterIdent>,
    pub epoch: u64,
    pub vip_next: u32,
    pub config_version: u64,
    pub devices: BTreeMap<[u8; 32], DeviceRow>,
    /// M7: the VIP allocation pool of VIPs returned by Expired rows (ordered
    /// — allocation takes the smallest; serialized into the snapshot).
    pub vip_pool: BTreeSet<[u8; 4]>,
    /// VIP → device reverse-lookup index (**derived data** of `devices`, not
    /// serialized — rebuilt after snapshot/replay by
    /// [`NetStateData::reindex_vips`], maintained incrementally on the apply
    /// registration path). Takes the per-packet forwarding hot path
    /// (`sm::SmCore::device_by_vip`) from an O(N) full-table scan down to
    /// O(log N). Injectivity is maintained by "Expired rows do not enter the
    /// index (their VIP is already back in the pool)" — pool VIPs and index
    /// keys are disjoint, so re-assigning from the pool inserts a new row.
    #[serde(skip, default)]
    pub vip_index: BTreeMap<[u8; 4], [u8; 32]>,
    pub users: BTreeMap<String, UserRow>,
    pub invites: BTreeMap<[u8; 16], InviteRow>,
    pub bind_tokens: BTreeSet<[u8; 16]>,
    pub server_keys: BTreeMap<NodeId, ServerKeyEntry>,
    pub wraps: BTreeMap<NodeId, Vec<u8>>,
    pub ticket_root: Option<[u8; 32]>,
    /// Cluster-shared OPRF key (b64 ServerSetup; registered by root-signed
    /// SetOprf — OPAQUE records verifiable network-wide, §2.4).
    pub oprf_b64: Option<String>,
    pub voters: BTreeSet<NodeId>,
    /// The last applied normal/membership entry (snapshot boundary;
    /// maintained by the sm wrapper).
    pub last_applied: Option<LogId<u64>>,
    pub last_membership: StoredMembership<u64, BasicNode>,
}

impl NetStateData {
    /// Empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize (snapshot wire format; postcard deterministic encoding).
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("netstate serialize")
    }

    /// Deserialize.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
    }

    /// Directory three-way query (the session::DeviceDirectory data source;
    /// corrupt rows fail-closed = NotFound). Expired is likewise a blocking
    /// state (time-based eviction after being offline past the retention
    /// period — refuses handshakes the same as Revoked, §7-M7).
    pub fn lookup(&self, id: &[u8; 32]) -> VerdictW {
        match self.devices.get(id) {
            Some(row) => match row.status {
                DeviceStatus::Active => VerdictW::Active {
                    x25519: row.device_x25519,
                    ed25519: row.device_ed25519,
                },
                DeviceStatus::Disabled | DeviceStatus::Revoked | DeviceStatus::Expired => {
                    VerdictW::Revoked {
                        since_epoch: row.since_epoch,
                    }
                }
            },
            None => VerdictW::NotFound,
        }
    }

    /// Current global revocation_epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Fully rebuild the VIP reverse-lookup index (for restore/snapshot
    /// install/consistency self-checks; idempotent). **Expired rows do not
    /// enter the index** (their VIP is already back in `vip_pool` — after the
    /// pool re-assigns it, the same pool VIP appears in a new row; the index
    /// only collects non-Expired rows ⇒ unique keys).
    pub fn reindex_vips(&mut self) {
        self.vip_index = self
            .devices
            .iter()
            .filter(|(_, row)| row.status != DeviceStatus::Expired)
            .map(|(dev, row)| (row.vip, *dev))
            .collect();
    }

    /// Reverse lookup of a device by VIP (per-packet forwarding hot path —
    /// index O(log N)). VIP watermark is monotonic with no reuse ⇒ a hit is
    /// unique. NetState stores only static registration info — no current
    /// location.
    pub fn device_by_vip(&self, vip: &[u8; 4]) -> Option<[u8; 32]> {
        self.vip_index.get(vip).copied()
    }

    /// Cluster-shared OPRF key (b64; unregistered ⇒ None).
    pub fn oprf_b64(&self) -> Option<&str> {
        self.oprf_b64.as_deref()
    }

    /// State digest (linearizable read ReadQuery::State).
    pub fn state_view(&self) -> crate::proto::StateView {
        crate::proto::StateView {
            epoch: self.epoch,
            config_version: self.config_version,
            devices: self.devices.len(),
            revoked: self
                .devices
                .values()
                .filter(|r| matches!(r.status, DeviceStatus::Disabled | DeviceStatus::Revoked))
                .count(),
            expired: self
                .devices
                .values()
                .filter(|r| r.status == DeviceStatus::Expired)
                .count(),
            invites_used: self
                .invites
                .values()
                .filter(|r| r.status == InviteStatus::Used)
                .count(),
            server_keys: self.server_keys.len(),
            wraps: self.wraps.iter().map(|(k, v)| (*k, v.len())).collect(),
            voters: self.voters.iter().copied().collect(),
            ticket_root_present: self.ticket_root.is_some(),
            last_applied: self.last_applied.map(|l| l.index),
        }
    }

    // ------------------------------------------------------------------

    /// Deterministically execute one write operation.
    ///
    /// `expected_root`: the cluster root public key pinned by this node's
    /// config (None = not configured; only the Bootstrap self-attestation is
    /// enforced).
    pub fn apply(
        &mut self,
        req: &SyncRequest,
        expected_root: Option<&VerifyingKey>,
    ) -> ApplyOutcome {
        match req {
            SyncRequest::Bootstrap {
                cluster_id,
                root_pub,
                ticket_root,
                sig,
            } => self.apply_bootstrap(*cluster_id, *root_pub, *ticket_root, *sig, expected_root),
            SyncRequest::RegisterDevice {
                owner,
                x25519,
                ed25519,
                hostname,
                registered_at_unix,
            } => self.apply_register(owner, *x25519, *ed25519, hostname, *registered_at_unix),
            SyncRequest::Revoke { device } => self.apply_set_status(device, DeviceStatus::Revoked),
            SyncRequest::Disable { device } => {
                self.apply_set_status(device, DeviceStatus::Disabled)
            }
            SyncRequest::Enable { device } => self.apply_set_status(device, DeviceStatus::Active),
            SyncRequest::Expire { device, now_unix } => self.apply_expire(device, *now_unix),
            SyncRequest::SetHostname { device, hostname } => {
                self.apply_set_hostname(device, hostname)
            }
            SyncRequest::AllocateIp => match self.alloc_vip() {
                Ok(vip) => ApplyOutcome::ok(SyncResponse::Ip(vip)),
                Err(e) => ApplyOutcome::err(e),
            },
            SyncRequest::RecordInvite {
                invite_id,
                expiry_unix,
            } => {
                // Idempotent registration: same id + same expiry + unconsumed
                // ⇒ duplicate registration allowed (issuer-side replay).
                match self.invites.get(invite_id) {
                    Some(row)
                        if row.expiry_unix == *expiry_unix && row.status == InviteStatus::Valid =>
                    {
                        ApplyOutcome::ok(SyncResponse::Ok)
                    }
                    Some(_) => ApplyOutcome::err(StateError::AlreadyUsed),
                    None => {
                        self.invites.insert(
                            *invite_id,
                            InviteRow {
                                expiry_unix: *expiry_unix,
                                status: InviteStatus::Valid,
                            },
                        );
                        ApplyOutcome::ok(SyncResponse::Ok)
                    }
                }
            }
            SyncRequest::RedeemInvite {
                invite_bytes,
                username,
                x25519,
                ed25519,
                hostname,
                now_unix,
            } => self.apply_redeem(
                invite_bytes,
                username,
                *x25519,
                *ed25519,
                hostname,
                *now_unix,
            ),
            SyncRequest::SetPassword {
                user,
                record_b64,
                profile,
            } => {
                let Some(row) = self.users.get_mut(user) else {
                    return ApplyOutcome::err(StateError::NoSuchUser);
                };
                if row.opaque_record.is_some() {
                    return ApplyOutcome::err(StateError::PasswordExists);
                }
                row.opaque_record = Some(record_b64.clone());
                row.opaque_profile = *profile;
                ApplyOutcome::ok(SyncResponse::Ok)
            }
            SyncRequest::AddUserSigKey { user, pub32 } => {
                let Some(row) = self.users.get_mut(user) else {
                    return ApplyOutcome::err(StateError::NoSuchUser);
                };
                if !row.sr_sig_pubs.contains(pub32) {
                    row.sr_sig_pubs.push(*pub32);
                }
                ApplyOutcome::ok(SyncResponse::Ok)
            }
            SyncRequest::ConsumeBindToken { token } => {
                if self.bind_tokens.contains(token) {
                    return ApplyOutcome::err(StateError::BindTokenUsed);
                }
                self.bind_tokens.insert(*token);
                ApplyOutcome::ok(SyncResponse::Ok)
            }
            SyncRequest::SetOprf(rs) => self.apply_set_oprf(rs, expected_root),
            SyncRequest::BumpConfigVersion => {
                self.config_version += 1;
                ApplyOutcome::ok(SyncResponse::ConfigVersion(self.config_version))
            }
            SyncRequest::ServerKeys(rs) => self.apply_server_keys(rs, expected_root),
            SyncRequest::AdminOp(rs) => self.apply_admin(rs, expected_root),
            // —— M8 (§7-M8.3): ordinary writes of the web admin plane
            //    (appended at the tail; authorization lives in the submitter
            //    layer). ——
            SyncRequest::CreateUser {
                username,
                pw_bootstrap,
            } => {
                if self.users.contains_key(username) {
                    return ApplyOutcome::err(StateError::UserExists);
                }
                self.users.insert(
                    username.clone(),
                    UserRow {
                        pw_bootstrap: Some(*pw_bootstrap),
                        ..UserRow::default()
                    },
                );
                ApplyOutcome::ok(SyncResponse::Ok)
            }
            SyncRequest::SetPasswordBootstrap {
                user,
                token,
                record_b64,
                profile,
            } => {
                let Some(row) = self.users.get_mut(user) else {
                    return ApplyOutcome::err(StateError::NoSuchUser);
                };
                // Atomic triple determination (a single Raft commit): token
                // matches (None = already consumed ⇒ same error — replay
                // rejected) AND record empty ⇒ land record + clear token.
                // Determination order: token before record (a wrong token
                // must not leak "whether a password already exists").
                if row.pw_bootstrap != Some(*token) {
                    return ApplyOutcome::err(StateError::BadBootstrapToken);
                }
                if row.opaque_record.is_some() {
                    return ApplyOutcome::err(StateError::PasswordExists);
                }
                row.opaque_record = Some(record_b64.clone());
                row.opaque_profile = *profile;
                row.pw_bootstrap = None;
                ApplyOutcome::ok(SyncResponse::Ok)
            }
            SyncRequest::ResetPassword { user, new_token } => {
                let Some(row) = self.users.get_mut(user) else {
                    return ApplyOutcome::err(StateError::NoSuchUser);
                };
                // Clear record + set the new token (the old password becomes
                // invalid immediately — record=None on the login side takes
                // the dummy path).
                row.opaque_record = None;
                row.opaque_profile = 0;
                row.pw_bootstrap = Some(*new_token);
                ApplyOutcome::ok(SyncResponse::Ok)
            }
            SyncRequest::SetUserAdmin { user, admin } => {
                let Some(row) = self.users.get_mut(user) else {
                    return ApplyOutcome::err(StateError::NoSuchUser);
                };
                row.admin = *admin;
                ApplyOutcome::ok(SyncResponse::Ok)
            }
            SyncRequest::SetUserDisabled { user, disabled } => {
                let Some(row) = self.users.get_mut(user) else {
                    return ApplyOutcome::err(StateError::NoSuchUser);
                };
                row.disabled = *disabled;
                ApplyOutcome::ok(SyncResponse::Ok)
            }
        }
    }

    fn apply_bootstrap(
        &mut self,
        cluster_id: [u8; 16],
        root_pub: [u8; 32],
        ticket_root: [u8; 32],
        sig: [u8; 64],
        expected_root: Option<&VerifyingKey>,
    ) -> ApplyOutcome {
        let vk = match VerifyingKey::from_bytes(&root_pub) {
            Ok(vk) => vk,
            Err(_) => return ApplyOutcome::err(StateError::BadRootSignature),
        };
        // Self-attestation: the root public key's signature over the canonical
        // bytes (guards against field concatenation).
        if vk
            .verify(
                &bootstrap_canonical(&cluster_id, &root_pub, &ticket_root),
                &Signature::from_bytes(&sig),
            )
            .is_err()
        {
            return ApplyOutcome::err(StateError::BadRootSignature);
        }
        match &self.cluster {
            Some(existing) => {
                if existing.cluster_id == cluster_id
                    && existing.root_pub == root_pub
                    && self.ticket_root == Some(ticket_root)
                {
                    // Idempotent replay allowed (Raft replay/catch-up path).
                    ApplyOutcome::ok(SyncResponse::Ok)
                } else {
                    ApplyOutcome::err(StateError::AlreadyBootstrapped)
                }
            }
            None => {
                // Compare against the locally pinned root (prevents "someone
                // else's signed root" entering the cluster identity).
                if let Some(pinned) = expected_root {
                    if pinned.as_bytes() != &root_pub {
                        return ApplyOutcome::err(StateError::RootMismatch);
                    }
                }
                self.cluster = Some(ClusterIdent {
                    cluster_id,
                    root_pub,
                });
                self.ticket_root = Some(ticket_root);
                ApplyOutcome::ok(SyncResponse::Ok)
            }
        }
    }

    fn apply_set_oprf(
        &mut self,
        rs: &RootSigned<String>,
        expected_root: Option<&VerifyingKey>,
    ) -> ApplyOutcome {
        let _ = expected_root; // The root public key is fixed to the bootstrap identity (compared against `cluster` below)
        let Some(cluster) = &self.cluster else {
            return ApplyOutcome::err(StateError::NotBootstrapped);
        };
        let Ok(root_vk) = VerifyingKey::from_bytes(&cluster.root_pub) else {
            return ApplyOutcome::err(StateError::BadRootSignature);
        };
        let l_oprf: &[u8] = b"flock-sync/set-oprf/v1";
        let mut canon = Vec::with_capacity(l_oprf.len() + 4 + rs.op.len());
        canon.extend_from_slice(l_oprf);
        canon.extend_from_slice(&(rs.op.len() as u32).to_le_bytes());
        canon.extend_from_slice(rs.op.as_bytes());
        if root_vk
            .verify(&canon, &Signature::from_bytes(&rs.sig))
            .is_err()
        {
            return ApplyOutcome::err(StateError::BadRootSignature);
        }
        match &self.oprf_b64 {
            Some(cur) if cur == &rs.op => ApplyOutcome::ok(SyncResponse::Ok), // Idempotent replay
            Some(_) => ApplyOutcome::err(StateError::AlreadyBootstrapped),
            None => {
                self.oprf_b64 = Some(rs.op.clone());
                ApplyOutcome::ok(SyncResponse::Ok)
            }
        }
    }

    fn apply_register(
        &mut self,
        owner: &str,
        x25519: [u8; 32],
        ed25519: [u8; 32],
        hostname: &str,
        registered_at: u64,
    ) -> ApplyOutcome {
        let device_id: [u8; 32] = Sha256::digest(ed25519).into();
        if self.devices.contains_key(&device_id) {
            return ApplyOutcome::err(StateError::DeviceExists);
        }
        if !self.users.contains_key(owner) {
            self.users.insert(owner.to_string(), UserRow::default());
        }
        let vip = match self.alloc_vip() {
            Ok(v) => v,
            Err(e) => return ApplyOutcome::err(e),
        };
        let row = DeviceRow {
            owner: owner.to_string(),
            device_x25519: x25519,
            device_ed25519: ed25519,
            vip,
            status: DeviceStatus::Active,
            since_epoch: 0,
            hostname: crate::proto::normalize_hostname(hostname),
            expired_at: None,
            registered_at,
        };
        self.devices.insert(device_id, row.clone());
        self.vip_index.insert(vip, device_id);
        ApplyOutcome::ok(SyncResponse::Device(row))
    }

    fn apply_set_status(&mut self, device: &[u8; 32], status: DeviceStatus) -> ApplyOutcome {
        let Some(row) = self.devices.get_mut(device) else {
            return ApplyOutcome::err(StateError::DeviceNotFound);
        };
        if matches!(row.status, DeviceStatus::Revoked) && status != DeviceStatus::Revoked {
            return ApplyOutcome::err(StateError::RevokedIsTerminal);
        }
        if matches!(row.status, DeviceStatus::Expired) && status != DeviceStatus::Expired {
            // Expired is an irreversible terminal state (the old VIP may
            // already belong to another device — revival breaks index
            // injectivity, §7-M7).
            return ApplyOutcome::err(StateError::ExpiredIsTerminal);
        }
        let mut effect = None;
        if row.status != status {
            // Only blocking transitions (→Disabled/→Revoked) advance the
            // global revocation_epoch (§2.2).
            if status != DeviceStatus::Active {
                self.epoch += 1;
                row.since_epoch = self.epoch;
                effect = Some(RevocationEffect {
                    device: *device,
                    new_epoch: self.epoch,
                });
            }
            row.status = status;
        }
        ApplyOutcome {
            resp: SyncResponse::Epoch(self.epoch),
            revoked: effect,
        }
    }

    /// M7: the Expire transition (submitted by the reaper) — **the VIP is
    /// returned to the allocation pool** (the core difference from Revoked:
    /// the row is retained for audit, and the pooled VIP can be re-assigned;
    /// it reuses the revocation epoch advancement + propagation-hook path,
    /// only the status semantics differ). Idempotent: replay over an
    /// already-Expired row is allowed (the convergence path for the reaper's
    /// concurrent multi-machine submissions) and does not touch the epoch.
    fn apply_expire(&mut self, device: &[u8; 32], now_unix: u64) -> ApplyOutcome {
        let Some(row) = self.devices.get_mut(device) else {
            return ApplyOutcome::err(StateError::DeviceNotFound);
        };
        if row.status == DeviceStatus::Expired {
            return ApplyOutcome::ok(SyncResponse::Epoch(self.epoch));
        }
        if row.status == DeviceStatus::Revoked {
            // A Revoked row's VIP is never reused (§2.1) — revocation does not
            // convert into re-assignability with the passage of time.
            return ApplyOutcome::err(StateError::RevokedIsTerminal);
        }
        // Blocking transition: epoch advancement + revocation propagation
        // hooks (kill leftover sessions / void tickets — same path as
        // Revoked, §7-M2).
        self.epoch += 1;
        row.since_epoch = self.epoch;
        row.status = DeviceStatus::Expired;
        row.expired_at = Some(now_unix);
        let effect = RevocationEffect {
            device: *device,
            new_epoch: self.epoch,
        };
        // Release the VIP: delete the old index entry + return to the pool
        // (ordered set — re-assignment takes the smallest).
        let released = row.vip;
        self.vip_index.remove(&released);
        self.vip_pool.insert(released);
        ApplyOutcome {
            resp: SyncResponse::Epoch(self.epoch),
            revoked: Some(effect),
        }
    }

    /// M7: hostname update (re-register path; non-terminal rows only).
    fn apply_set_hostname(&mut self, device: &[u8; 32], hostname: &str) -> ApplyOutcome {
        let Some(row) = self.devices.get_mut(device) else {
            return ApplyOutcome::err(StateError::DeviceNotFound);
        };
        if matches!(row.status, DeviceStatus::Revoked) {
            return ApplyOutcome::err(StateError::RevokedIsTerminal);
        }
        if matches!(row.status, DeviceStatus::Expired) {
            return ApplyOutcome::err(StateError::ExpiredIsTerminal);
        }
        row.hostname = crate::proto::normalize_hostname(hostname);
        ApplyOutcome::ok(SyncResponse::Device(row.clone()))
    }

    fn apply_redeem(
        &mut self,
        invite_bytes: &[u8],
        username: &str,
        x25519: [u8; 32],
        ed25519: [u8; 32],
        hostname: &str,
        now_unix: u64,
    ) -> ApplyOutcome {
        // Root-signature/structure checks + pinning to this cluster's
        // identity, before any state is touched (same as M2).
        let Some(cluster) = self.cluster.clone() else {
            return ApplyOutcome::err(StateError::NotBootstrapped);
        };
        let invite = match flock_protocol::trust::InviteFile::from_bytes(invite_bytes) {
            Ok(i) => i,
            Err(e) => return ApplyOutcome::err(StateError::BadInvite(e.to_string())),
        };
        if !invite.verify() {
            return ApplyOutcome::err(StateError::BadInvite("root signature mismatch".into()));
        }
        if *invite.cluster_root_pub.as_bytes() != cluster.root_pub
            || invite.directory.cluster_id.0 != cluster.cluster_id
        {
            return ApplyOutcome::err(StateError::BadInvite(
                "invite not signed by this cluster's root".into(),
            ));
        }
        let invite_id = invite.invite_id;
        let Some(row) = self.invites.get(&invite_id) else {
            return ApplyOutcome::err(StateError::UnknownInvite);
        };
        // One-shot triple determination (§1.3.3f an invite's lifetime).
        match row.status {
            InviteStatus::Used => return ApplyOutcome::err(StateError::AlreadyUsed),
            InviteStatus::Revoked => return ApplyOutcome::err(StateError::InviteRevoked),
            InviteStatus::Valid => {}
        }
        let expiry = row.expiry_unix;
        if now_unix >= expiry {
            return ApplyOutcome::err(StateError::InviteExpired {
                now_unix,
                expiry_unix: expiry,
            });
        }
        let device_id: [u8; 32] = Sha256::digest(ed25519).into();
        if self.devices.contains_key(&device_id) {
            return ApplyOutcome::err(StateError::DeviceExists);
        }
        if self.users.contains_key(username) {
            return ApplyOutcome::err(StateError::UserExists);
        }
        self.users.insert(username.to_string(), UserRow::default());
        let vip = match self.alloc_vip() {
            Ok(v) => v,
            Err(e) => return ApplyOutcome::err(e),
        };
        self.devices.insert(
            device_id,
            DeviceRow {
                owner: username.to_string(),
                device_x25519: x25519,
                device_ed25519: ed25519,
                vip,
                status: DeviceStatus::Active,
                since_epoch: 0,
                hostname: crate::proto::normalize_hostname(hostname),
                expired_at: None,
                // The redemption moment is the registration moment (the
                // reaper's anchor, §7-M7.5).
                registered_at: now_unix,
            },
        );
        self.vip_index.insert(vip, device_id);
        // Mark used within the same state transition (no window between dedup
        // and marking — a single Raft commit).
        self.invites.insert(
            invite_id,
            InviteRow {
                expiry_unix: expiry,
                status: InviteStatus::Used,
            },
        );
        ApplyOutcome::ok(SyncResponse::Redeem {
            username: username.to_string(),
            device_id,
            vip,
        })
    }

    fn apply_server_keys(
        &mut self,
        rs: &RootSigned<Vec<ServerKeyEntry>>,
        expected_root: Option<&VerifyingKey>,
    ) -> ApplyOutcome {
        let Some(vk) = self.root_verifier(expected_root) else {
            return ApplyOutcome::err(StateError::NotBootstrapped);
        };
        if vk
            .verify(
                &server_keys_canonical(&rs.op),
                &Signature::from_bytes(&rs.sig),
            )
            .is_err()
        {
            return ApplyOutcome::err(StateError::BadRootSignature);
        }
        self.server_keys.clear();
        for e in &rs.op {
            self.server_keys.insert(e.server_id, e.clone());
        }
        self.config_version += 1;
        ApplyOutcome::ok(SyncResponse::ServerKeys {
            servers: self.server_keys.len(),
        })
    }

    fn apply_admin(
        &mut self,
        rs: &RootSigned<AdminOp>,
        expected_root: Option<&VerifyingKey>,
    ) -> ApplyOutcome {
        let Some(vk) = self.root_verifier(expected_root) else {
            return ApplyOutcome::err(StateError::NotBootstrapped);
        };
        if vk
            .verify(&admin_canonical(&rs.op), &Signature::from_bytes(&rs.sig))
            .is_err()
        {
            return ApplyOutcome::err(StateError::BadRootSignature);
        }
        match &rs.op {
            AdminOp::AddVoter { node_id } => {
                self.voters.insert(*node_id);
                self.config_version += 1;
                ApplyOutcome::ok(SyncResponse::Admin(AdminAck::AddVoter {
                    node_id: *node_id,
                }))
            }
            AdminOp::Rewrap { server_id, wrapped } => {
                if !self.server_keys.contains_key(server_id) {
                    return ApplyOutcome::err(StateError::NotFound(format!(
                        "server {server_id} not in server_keys (record keys first)"
                    )));
                }
                let bytes = wrapped.len();
                self.wraps.insert(*server_id, wrapped.clone());
                ApplyOutcome::ok(SyncResponse::Admin(AdminAck::Rewrap {
                    server_id: *server_id,
                    bytes,
                }))
            }
            AdminOp::RevokeInvite { invite_id } => {
                let Some(row) = self.invites.get_mut(invite_id) else {
                    return ApplyOutcome::err(StateError::UnknownInvite);
                };
                if row.status == InviteStatus::Used {
                    return ApplyOutcome::err(StateError::AlreadyUsed);
                }
                row.status = InviteStatus::Revoked;
                ApplyOutcome::ok(SyncResponse::Admin(AdminAck::RevokeInvite))
            }
        }
    }

    /// The in-state root public key (the anchor for admin verification);
    /// `expected_root` wins when present (local pinning, a second line of
    /// defense).
    fn root_verifier(&self, expected_root: Option<&VerifyingKey>) -> Option<VerifyingKey> {
        if let Some(pinned) = expected_root {
            return Some(*pinned);
        }
        self.cluster
            .as_ref()
            .and_then(|c| VerifyingKey::from_bytes(&c.root_pub).ok())
    }

    /// VIP allocation (M7 two-tier: **the Expired return pool first** (take
    /// the smallest — deterministic), fall back to the monotonic watermark
    /// `vip_next` when the pool is empty (only moves forward; the VIPs of
    /// revoked/disabled rows never enter the pool, §2.1); past [`VIP_LAST`]
    /// means exhausted).
    fn alloc_vip(&mut self) -> Result<[u8; 4], StateError> {
        if let Some(pool_vip) = self.vip_pool.iter().next().copied() {
            self.vip_pool.remove(&pool_vip);
            return Ok(pool_vip);
        }
        let cur = if self.vip_next == 0 {
            VIP_FIRST
        } else {
            self.vip_next
        };
        if cur > VIP_LAST {
            return Err(StateError::IpExhausted);
        }
        self.vip_next = cur + 1;
        Ok(cur.to_be_bytes())
    }
}

// ============================================================================
// Unit tests: pure state machine semantics (VIP discipline / invite
// single-use / epoch advancement / admin verification)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrapped(root: &ed25519_dalek::SigningKey) -> NetStateData {
        let mut d = NetStateData::new();
        let out = d.apply(
            &SyncRequest::bootstrap_signed(root, [7; 16], [9; 32]),
            Some(&root.verifying_key()),
        );
        assert!(
            matches!(out.resp, SyncResponse::Ok),
            "bootstrap: {:?}",
            out.resp
        );
        d
    }

    fn dev_id(ed: &[u8; 32]) -> [u8; 32] {
        Sha256::digest(ed).into()
    }

    #[test]
    fn vip_monotonic_and_never_reused() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let mut d = bootstrapped(&root);
        let a = d
            .apply(
                &SyncRequest::RegisterDevice {
                    owner: "u".into(),
                    x25519: [1; 32],
                    ed25519: [1; 32],
                    hostname: String::new(),
                    registered_at_unix: 1_700_000_000,
                },
                None,
            )
            .resp;
        let SyncResponse::Device(a) = a else { panic!() };
        let id: [u8; 32] = Sha256::digest([1u8; 32]).into();
        let e1 = d.apply(&SyncRequest::Revoke { device: id }, None).resp;
        assert!(
            matches!(e1, SyncResponse::Epoch(1)),
            "revocation advances the epoch"
        );
        let b = d
            .apply(
                &SyncRequest::RegisterDevice {
                    owner: "u".into(),
                    x25519: [2; 32],
                    ed25519: [2; 32],
                    hostname: String::new(),
                    registered_at_unix: 1_700_000_000,
                },
                None,
            )
            .resp;
        let SyncResponse::Device(b) = b else { panic!() };
        let (ia, ib) = (u32::from_be_bytes(a.vip), u32::from_be_bytes(b.vip));
        assert_eq!(ia, VIP_FIRST, "first VIP = 100.64.0.2");
        assert!(ib > ia, "IP not reused (watermark only moves forward)");
        // Re-registering the same device rejected (row retained).
        assert!(matches!(
            d.apply(
                &SyncRequest::RegisterDevice {
                    owner: "u".into(),
                    x25519: [1; 32],
                    ed25519: [1; 32],
                    hostname: String::new(),
                    registered_at_unix: 1_700_000_000,
                },
                None,
            )
            .resp,
            SyncResponse::Error(StateError::DeviceExists)
        ));
        // Disable does not delete: row retained, VIP not reclaimed.
        let id2: [u8; 32] = Sha256::digest([2u8; 32]).into();
        assert!(matches!(
            d.apply(&SyncRequest::Disable { device: id2 }, None).resp,
            SyncResponse::Epoch(2)
        ));
        assert_eq!(d.devices.get(&id2).unwrap().vip, b.vip, "VIP not reclaimed");
        assert!(matches!(d.lookup(&id2), VerdictW::Revoked { .. }));
        // Revoked is an irreversible terminal state.
        assert!(matches!(
            d.apply(&SyncRequest::Enable { device: id }, None).resp,
            SyncResponse::Error(StateError::RevokedIsTerminal)
        ));
        // Empty hostname lands as "(unknown)" (the M7 default-value chain).
        assert_eq!(a.hostname, crate::proto::HOSTNAME_UNKNOWN);
    }

    /// M7: Expire releases the VIP back to the pool + a new device gets that
    /// VIP + Expired ≠ Revoked distinguishable + idempotent replay allowed +
    /// terminal irreversibility + index injectivity maintained.
    #[test]
    fn expire_releases_vip_to_pool_and_reassigns() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let mut d = bootstrapped(&root);
        let reg = |seed: u8, host: &str| SyncRequest::RegisterDevice {
            owner: "u".into(),
            x25519: [seed; 32],
            ed25519: [seed; 32],
            hostname: host.into(),
            registered_at_unix: 1_700_000_000,
        };
        let a = d.apply(&reg(1, "laptop-a"), None).resp;
        let SyncResponse::Device(a_row) = a else {
            panic!()
        };
        let _b = d.apply(&reg(2, "laptop-b"), None).resp;
        let id_a: [u8; 32] = Sha256::digest([1u8; 32]).into();

        // Expire (clock injected): epoch advanced + expired_at landed + VIP
        // returned to the pool.
        let e = d
            .apply(
                &SyncRequest::Expire {
                    device: id_a,
                    now_unix: 1_700_000_000,
                },
                None,
            )
            .resp;
        assert!(
            matches!(e, SyncResponse::Epoch(1)),
            "expire advances the epoch: {e:?}"
        );
        let row = d.devices.get(&id_a).unwrap();
        assert_eq!(row.status, DeviceStatus::Expired, "Expired ≠ Revoked");
        assert_eq!(row.expired_at, Some(1_700_000_000));
        assert_eq!(
            row.vip, a_row.vip,
            "row retained (audit): the VIP field is untouched"
        );
        assert!(d.vip_pool.contains(&a_row.vip), "VIP returned to the pool");
        assert_eq!(
            d.device_by_vip(&a_row.vip),
            None,
            "index drops the old entry"
        );
        assert!(
            !d.vip_pool.contains(&d.devices[&dev_id(&[2u8; 32])].vip),
            "the VIP of a non-expired device does not enter the pool"
        );

        // Idempotent replay: already Expired ⇒ allowed and the epoch is
        // untouched.
        let e2 = d
            .apply(
                &SyncRequest::Expire {
                    device: id_a,
                    now_unix: 1_700_100_000,
                },
                None,
            )
            .resp;
        assert!(matches!(e2, SyncResponse::Epoch(1)));
        assert_eq!(d.epoch, 1);
        assert_eq!(
            d.devices.get(&id_a).unwrap().expired_at,
            Some(1_700_000_000),
            "replay does not refresh expired_at"
        );

        // A new device gets the released VIP (the pool beats the watermark).
        let c = d.apply(&reg(3, "laptop-c"), None).resp;
        let SyncResponse::Device(c_row) = c else {
            panic!()
        };
        assert_eq!(
            c_row.vip, a_row.vip,
            "the pooled VIP is re-assigned to the new device"
        );

        // Index injectivity: the same VIP now points only to the new device;
        // identical after a rebuild (Expired rows do not enter the index).
        assert_eq!(d.device_by_vip(&a_row.vip), Some(dev_id(&[3u8; 32])));
        let incremental = d.vip_index.clone();
        d.reindex_vips();
        assert_eq!(
            d.vip_index, incremental,
            "rebuild == incremental (Expired excluded)"
        );

        // Terminal irreversibility: Enable/Disable/re-Expire with a different
        // moment are all rejected or idempotent.
        assert!(matches!(
            d.apply(&SyncRequest::Enable { device: id_a }, None).resp,
            SyncResponse::Error(StateError::ExpiredIsTerminal)
        ));
        assert!(matches!(
            d.apply(&SyncRequest::Disable { device: id_a }, None).resp,
            SyncResponse::Error(StateError::ExpiredIsTerminal)
        ));
        // Hostname update rejected (terminal row).
        assert!(matches!(
            d.apply(
                &SyncRequest::SetHostname {
                    device: id_a,
                    hostname: "x".into()
                },
                None,
            )
            .resp,
            SyncResponse::Error(StateError::ExpiredIsTerminal)
        ));
        // lookup: Expired blocks handshakes (the Revoked verdict shape).
        assert!(matches!(d.lookup(&id_a), VerdictW::Revoked { .. }));

        // Revoked does not convert into re-assignability with time: Expire
        // after Revoke ⇒ rejected.
        let id_c: [u8; 32] = Sha256::digest([3u8; 32]).into();
        d.apply(&SyncRequest::Revoke { device: id_c }, None);
        assert!(matches!(
            d.apply(
                &SyncRequest::Expire {
                    device: id_c,
                    now_unix: 1_800_000_000
                },
                None,
            )
            .resp,
            SyncResponse::Error(StateError::RevokedIsTerminal)
        ));
        assert!(
            !d.vip_pool.contains(&c_row.vip),
            "a revoked VIP does not enter the pool (never reused)"
        );
    }

    /// M7: hostname normalization (empty ⇒ "(unknown)"; trim; overlong
    /// truncated) + SetHostname update.
    #[test]
    fn hostname_normalize_and_set_update() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[10; 32]);
        let mut d = bootstrapped(&root);
        let out = d
            .apply(
                &SyncRequest::RegisterDevice {
                    owner: "u".into(),
                    x25519: [1; 32],
                    ed25519: [1; 32],
                    hostname: "  my-laptop  ".into(),
                    registered_at_unix: 1_700_000_000,
                },
                None,
            )
            .resp;
        let SyncResponse::Device(row) = out else {
            panic!()
        };
        assert_eq!(row.hostname, "my-laptop", "trim");
        let id: [u8; 32] = Sha256::digest([1u8; 32]).into();

        // Overlong truncated (char-boundary safe).
        let long = "x".repeat(100);
        let out = d
            .apply(
                &SyncRequest::SetHostname {
                    device: id,
                    hostname: long,
                },
                None,
            )
            .resp;
        let SyncResponse::Device(row) = out else {
            panic!()
        };
        assert_eq!(row.hostname.len(), crate::proto::HOSTNAME_MAX);

        // Re-register update (SetHostname).
        let out = d
            .apply(
                &SyncRequest::SetHostname {
                    device: id,
                    hostname: "renamed".into(),
                },
                None,
            )
            .resp;
        assert!(matches!(out, SyncResponse::Device(_)));
        assert_eq!(d.devices.get(&id).unwrap().hostname, "renamed");

        // Unknown device rejected.
        assert!(matches!(
            d.apply(
                &SyncRequest::SetHostname {
                    device: [7; 32],
                    hostname: "x".into()
                },
                None,
            )
            .resp,
            SyncResponse::Error(StateError::DeviceNotFound)
        ));
    }

    #[test]
    fn redeem_single_consumption_and_epoch_rules() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let mut d = bootstrapped(&root);
        // Invite fixture (root-signed v3).
        let entry = flock_protocol::session::ServerEntry {
            server_id: flock_protocol::session::ServerId([1; 16]),
            relay_endpoint: "127.0.0.1:9443".into(),
            identity_pub: ed25519_dalek::SigningKey::from_bytes(&[5; 32]).verifying_key(),
            static_hybrid_pub: flock_protocol::kem::HybridKeypair::generate(
                &mut flock_protocol::rand::rngs::OsRng,
            )
            .public(),
        };
        let inv = flock_protocol::trust::InviteFile::issue(
            &root,
            flock_protocol::session::ClusterId([7; 16]),
            1,
            vec![entry],
            999_999,
            [1; 16],
        );
        d.apply(
            &SyncRequest::RecordInvite {
                invite_id: [1; 16],
                expiry_unix: 999_999,
            },
            None,
        );
        // First redemption succeeds.
        let r = d
            .apply(
                &SyncRequest::RedeemInvite {
                    invite_bytes: inv.to_bytes(),
                    username: "alice".into(),
                    x25519: [3; 32],
                    ed25519: [3; 32],
                    hostname: "alice-phone".into(),
                    now_unix: 1000,
                },
                None,
            )
            .resp;
        assert!(matches!(r, SyncResponse::Redeem { .. }), "{r:?}");
        // Second redemption rejected (single-use consumption dedup).
        let r2 = d
            .apply(
                &SyncRequest::RedeemInvite {
                    invite_bytes: inv.to_bytes(),
                    username: "bob".into(),
                    x25519: [4; 32],
                    ed25519: [4; 32],
                    hostname: String::new(),
                    now_unix: 1000,
                },
                None,
            )
            .resp;
        assert_eq!(r2, SyncResponse::Error(StateError::AlreadyUsed));
    }

    #[test]
    fn admin_requires_root_signature() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let other = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let mut d = bootstrapped(&root);
        // Signed by someone else (no root key) ⇒ rejected.
        let forged = SyncRequest::rewrap_signed(&other, 2, vec![1; 16]);
        assert_eq!(
            d.apply(&forged, Some(&root.verifying_key())).resp,
            SyncResponse::Error(StateError::BadRootSignature)
        );
        // server_keys lands first (root-signed), then rewrap (root-signed) ⇒
        // effective.
        let entries = vec![ServerKeyEntry {
            server_id: 2,
            identity_pub: *other.verifying_key().as_bytes(),
            hybrid_pub: vec![7; 64],
            vip: [100, 64, 0, 1],
        }];
        let sk = SyncRequest::server_keys_signed(&root, entries);
        assert!(matches!(
            d.apply(&sk, Some(&root.verifying_key())).resp,
            SyncResponse::ServerKeys { servers: 1 }
        ));
        let rw = SyncRequest::rewrap_signed(&root, 2, vec![1, 2, 3]);
        assert_eq!(
            d.apply(&rw, Some(&root.verifying_key())).resp,
            SyncResponse::Admin(AdminAck::Rewrap {
                server_id: 2,
                bytes: 3
            })
        );
        assert_eq!(d.wraps.get(&2).map(|v| v.len()), Some(3), "rewrap landed");
        // rewrap to an unregistered server ⇒ rejected.
        let rw2 = SyncRequest::rewrap_signed(&root, 9, vec![1]);
        assert!(matches!(
            d.apply(&rw2, Some(&root.verifying_key())).resp,
            SyncResponse::Error(StateError::NotFound(_))
        ));
        // add_voter (root-signed) ⇒ voters + config_version.
        let av = SyncRequest::add_voter_signed(&root, 5);
        assert_eq!(
            d.apply(&av, Some(&root.verifying_key())).resp,
            SyncResponse::Admin(AdminAck::AddVoter { node_id: 5 })
        );
        assert!(d.voters.contains(&5));
        assert_eq!(d.config_version, 2, "server_keys/add_voter each +1");
    }

    #[test]
    fn bootstrap_once_and_root_pin() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let mut d = NetStateData::new();
        // With no pinned root, the self-attestation signature alone suffices.
        assert!(matches!(
            d.apply(
                &SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32]),
                None
            )
            .resp,
            SyncResponse::Ok
        ));
        // Idempotent replay allowed.
        assert!(matches!(
            d.apply(
                &SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32]),
                None
            )
            .resp,
            SyncResponse::Ok
        ));
        // Bootstrapping a different identity ⇒ rejected.
        assert!(matches!(
            d.apply(
                &SyncRequest::bootstrap_signed(&root, [7; 16], [8; 32]),
                None
            )
            .resp,
            SyncResponse::Error(StateError::AlreadyBootstrapped)
        ));
        // Pinned root mismatch ⇒ rejected (guards against someone else's
        // signed root).
        let mut e = NetStateData::new();
        let pinned = root.verifying_key();
        let other = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        assert!(matches!(
            e.apply(
                &SyncRequest::bootstrap_signed(&other, [7; 16], [9; 32]),
                Some(&pinned)
            )
            .resp,
            SyncResponse::Error(StateError::RootMismatch)
        ));
    }

    #[test]
    fn snapshot_roundtrip() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let mut d = bootstrapped(&root);
        d.apply(
            &SyncRequest::RegisterDevice {
                owner: "u".into(),
                x25519: [1; 32],
                ed25519: [1; 32],
                hostname: "host-rt".into(),
                registered_at_unix: 1_700_000_000,
            },
            None,
        );
        let bytes = d.to_bytes();
        let mut back = NetStateData::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(back.devices.len(), 1);
        assert_eq!(back.epoch, d.epoch);
        assert_eq!(back.ticket_root, d.ticket_root);
        // M7 new fields survive the snapshot round trip.
        let id: [u8; 32] = Sha256::digest([1u8; 32]).into();
        assert_eq!(back.devices.get(&id).unwrap().hostname, "host-rt");
        assert_eq!(back.devices.get(&id).unwrap().expired_at, None);
        // The VIP index is not serialized (derived data) — after rebuilding it
        // matches the original state.
        assert!(
            back.vip_index.is_empty(),
            "the index is not in the snapshot bytes"
        );
        back.reindex_vips();
        assert_eq!(back.vip_index, d.vip_index, "index identical after rebuild");
    }

    /// M7 snapshot compatibility statement (asserted honestly): after
    /// DeviceRow gains fields (hostname/expired_at/registered_at), **old-format
    /// snapshots no longer decode** — postcard has no field tags, from_bytes
    /// fails cleanly on old bytes (returns None; the node recovers via the
    /// log/rebuild path). Allowed within the unreleased window (§7-M7.1);
    /// this test pins down "the failure must be clean" (no panic / no partial
    /// decode): old-row encoded bytes and arbitrary truncated bytes both give
    /// None.
    ///
    /// The "old row bytes" are a **mirror approximation**: `LegacyRow` is a
    /// hand-maintained postcard mirror of the pre-M7 shape — not a genuine
    /// sample of old-code output (the old format cannot be regenerated by the
    /// current code); its value is not byte-for-byte replication but
    /// constructing a "valid postcard with a misaligned field layout" byte
    /// stream to verify the decoder fails cleanly. When adding fields later,
    /// update the mirror accordingly (the current mirror = the pre-M7 shape;
    /// the post-M7 "old" = the earlier three-field shape without
    /// registered_at, same reasoning applies).
    #[test]
    fn legacy_snapshot_bytes_fail_clean() {
        // The old DeviceRow shape (no hostname/expired_at/registered_at) — a
        // postcard encoding mirror (source above: mirror approximation, not a
        // real sample).
        #[derive(serde::Serialize)]
        struct LegacyRow {
            owner: String,
            device_x25519: [u8; 32],
            device_ed25519: [u8; 32],
            vip: [u8; 4],
            status: u8,
            since_epoch: u64,
        }
        let legacy_row = postcard::to_allocvec(&LegacyRow {
            owner: "u".into(),
            device_x25519: [1; 32],
            device_ed25519: [2; 32],
            vip: [100, 64, 0, 11],
            status: 1,
            since_epoch: 0,
        })
        .expect("legacy encode");
        // To the new decoder the old row bytes are a misaligned stream
        // (hostname cannot read a valid varint/length) ⇒ None.
        assert!(
            NetStateData::from_bytes(&legacy_row).is_none(),
            "old-format bytes must fail cleanly (None)"
        );
        // Truncated new-format bytes likewise None (no panic, no partial
        // decode).
        let fresh = NetStateData::new().to_bytes();
        assert!(NetStateData::from_bytes(&fresh[..fresh.len() - 1]).is_none());
        assert!(NetStateData::from_bytes(b"\x01\x00").is_none());
    }

    /// VIP reverse-lookup index consistency: apply maintenance
    /// (registration/redemption/revocation keeps rows without deletion) +
    /// full rebuild idempotent + query results equivalent to a full-table scan
    /// (M7: Expired rows do not enter the index — revoked rows are retained).
    #[test]
    fn vip_index_consistency_across_apply_and_rebuild() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let mut d = bootstrapped(&root);
        // Register 3 devices + revoke 1 (disable does not delete: row and VIP
        // both retained ⇒ the index entry is retained).
        for i in 1u8..=3 {
            let out = d
                .apply(
                    &SyncRequest::RegisterDevice {
                        owner: format!("u{i}"),
                        x25519: [i; 32],
                        ed25519: [i; 32],
                        hostname: String::new(),
                        registered_at_unix: 1_700_000_000,
                    },
                    None,
                )
                .resp;
            assert!(matches!(out, SyncResponse::Device(_)));
        }
        let revoked_dev: [u8; 32] = Sha256::digest([2u8; 32]).into();
        d.apply(
            &SyncRequest::Revoke {
                device: revoked_dev,
            },
            None,
        );
        // Consistency: index ↔ devices full-table scan (equivalent query
        // result for every VIP; equal entry counts).
        let expect: Vec<([u8; 4], [u8; 32])> = d
            .devices
            .iter()
            .filter(|(_, r)| r.status != DeviceStatus::Expired)
            .map(|(dev, row)| (row.vip, *dev))
            .collect();
        assert_eq!(
            d.vip_index.len(),
            expect.len(),
            "revocation keeps the row ⇒ the index does not shrink (Expired excluded)"
        );
        for (vip, dev) in &expect {
            assert_eq!(
                d.device_by_vip(vip),
                Some(*dev),
                "index query = full-table scan"
            );
        }
        // Unallocated VIP ⇒ None.
        assert_eq!(d.device_by_vip(&[127, 0, 0, 1]), None);
        // Full rebuild is idempotent and matches incremental maintenance.
        let incremental = d.vip_index.clone();
        d.reindex_vips();
        assert_eq!(
            d.vip_index, incremental,
            "rebuild == incremental maintenance"
        );
        // serialize→deserialize→rebuild also matches (the snapshot-restore
        // path).
        let mut back = NetStateData::from_bytes(&d.to_bytes()).expect("roundtrip");
        back.reindex_vips();
        assert_eq!(
            back.vip_index, incremental,
            "rebuild after snapshot round trip matches"
        );
    }

    // ------------------------------------------------------------------
    // M8 (§7-M8.3): UserRow's three new fields + the semantics of the five
    // write variants
    // ------------------------------------------------------------------

    /// UserRow new fields postcard round trip + old-format (three-field
    /// shape) bytes fail cleanly on the new decoder (§7-M7.1 same discipline:
    /// mirror approximation — not a genuine sample of old-code output,
    /// verifying the failure is clean).
    #[test]
    fn user_row_new_fields_roundtrip_and_legacy_fails_clean() {
        let row = UserRow {
            opaque_record: Some("rec-b64".into()),
            opaque_profile: 0,
            sr_sig_pubs: vec![[7; 32]],
            admin: true,
            disabled: false,
            pw_bootstrap: Some([9; 16]),
        };
        let bytes = postcard::to_allocvec(&row).unwrap();
        assert_eq!(postcard::from_bytes::<UserRow>(&bytes).unwrap(), row);
        // The all-zero Default face (the user does not exist before
        // CreateUser; RegisterDevice's auto user-creation takes this shape).
        assert_eq!(
            UserRow::default(),
            UserRow {
                opaque_record: None,
                opaque_profile: 0,
                sr_sig_pubs: vec![],
                admin: false,
                disabled: false,
                pw_bootstrap: None,
            }
        );
        // Old format (pre-M8 three fields) postcard mirror: decoding must fail
        // (no panic, no partial decode).
        #[derive(serde::Serialize)]
        struct LegacyUserRow {
            opaque_record: Option<String>,
            opaque_profile: u16,
            sr_sig_pubs: Vec<[u8; 32]>,
        }
        let legacy = postcard::to_allocvec(&LegacyUserRow {
            opaque_record: Some("r".into()),
            opaque_profile: 0,
            sr_sig_pubs: vec![[1; 32]],
        })
        .unwrap();
        assert!(
            postcard::from_bytes::<UserRow>(&legacy).is_err(),
            "old-format UserRow bytes must fail cleanly"
        );
        // A whole snapshot containing the old-format user row likewise fails
        // cleanly (NetStateData::from_bytes → None). Construction: hand-
        // embedding the legacy bytes is impossible (map keys live inside the
        // structure), so instead verify the "any UserRow byte stream that is
        // not the new shape" path — feeding the legacy row bytes directly as
        // NetStateData snapshot bytes ⇒ None.
        assert!(NetStateData::from_bytes(&legacy).is_none());
    }

    /// CreateUser: user creation lands the token; duplicate name ⇒ UserExists
    /// (the submitter may ignore idempotently as needed — a CLI-layer
    /// responsibility).
    #[test]
    fn m8_create_user_semantics() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let mut d = bootstrapped(&root);
        let create = |u: &str, t: u8| SyncRequest::CreateUser {
            username: u.into(),
            pw_bootstrap: [t; 16],
        };
        assert!(matches!(
            d.apply(&create("web-admin", 1), None).resp,
            SyncResponse::Ok
        ));
        let row = d.users.get("web-admin").unwrap();
        assert_eq!(
            row.pw_bootstrap,
            Some([1; 16]),
            "token landed with user creation"
        );
        assert!(
            !row.admin && !row.disabled,
            "a new user defaults to non-admin, not disabled"
        );
        assert!(
            row.opaque_record.is_none(),
            "a new user has no password record"
        );
        // Duplicate name rejected.
        assert!(matches!(
            d.apply(&create("web-admin", 2), None).resp,
            SyncResponse::Error(StateError::UserExists)
        ));
        assert_eq!(
            d.users.get("web-admin").unwrap().pw_bootstrap,
            Some([1; 16]),
            "the rejection path does not touch the original row"
        );
    }

    /// SetPasswordBootstrap: atomic consumption (token matches AND record
    /// empty ⇒ land record + clear token); wrong token/replay ⇒
    /// BadBootstrapToken; record already present ⇒ PasswordExists; unknown
    /// user ⇒ NoSuchUser; the token determination precedes the record
    /// determination (a wrong token does not leak "whether a password already
    /// exists").
    #[test]
    fn m8_set_password_bootstrap_atomic_token_consumption() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
        let mut d = bootstrapped(&root);
        d.apply(
            &SyncRequest::CreateUser {
                username: "alice".into(),
                pw_bootstrap: [0xA1; 16],
            },
            None,
        );
        let commit = |user: &str, tok: [u8; 16], rec: &str| SyncRequest::SetPasswordBootstrap {
            user: user.into(),
            token: tok,
            record_b64: rec.into(),
            profile: 0,
        };
        // Unknown user ⇒ NoSuchUser.
        assert!(matches!(
            d.apply(&commit("ghost", [0xA1; 16], "r"), None).resp,
            SyncResponse::Error(StateError::NoSuchUser)
        ));
        // Wrong token ⇒ BadBootstrapToken.
        assert!(matches!(
            d.apply(&commit("alice", [0xB2; 16], "r"), None).resp,
            SyncResponse::Error(StateError::BadBootstrapToken)
        ));
        // Correct token ⇒ land record + clear token.
        assert!(matches!(
            d.apply(&commit("alice", [0xA1; 16], "rec-alice"), None)
                .resp,
            SyncResponse::Ok
        ));
        let row = d.users.get("alice").unwrap();
        assert_eq!(row.opaque_record.as_deref(), Some("rec-alice"));
        assert_eq!(row.opaque_profile, 0);
        assert_eq!(row.pw_bootstrap, None, "token cleared upon consumption");
        // Token replay (already consumed = None ≠ any token) ⇒
        // BadBootstrapToken (same error — does not leak the difference
        // between "already consumed" and "wrong token").
        assert!(matches!(
            d.apply(&commit("alice", [0xA1; 16], "rec-2"), None).resp,
            SyncResponse::Error(StateError::BadBootstrapToken)
        ));
        // Record present and the token still valid (bypassing after
        // ResetPassword? — the token was already cleared; this path needs a
        // fresh token from ResetPassword; direct construction: after a
        // password reset the token is valid + the record empty ⇒ another
        // commit succeeds). First exercise the PasswordExists branch: hand-set
        // the token with the record non-empty.
        d.apply(
            &SyncRequest::ResetPassword {
                user: "alice".into(),
                new_token: [0xC3; 16],
            },
            None,
        );
        let row = d.users.get("alice").unwrap();
        assert!(
            row.opaque_record.is_none(),
            "reset clears the record (old password invalidated)"
        );
        assert_eq!(row.pw_bootstrap, Some([0xC3; 16]));
        // Hand-simulate "token valid but record already present": first commit
        // successfully, then hand-set the token back (constructible only
        // inside the state machine — the outer ResetPassword path always
        // clears the record; this assertion pins the state-machine-level
        // determination order).
        assert!(matches!(
            d.apply(&commit("alice", [0xC3; 16], "rec-3"), None).resp,
            SyncResponse::Ok
        ));
        d.users.get_mut("alice").unwrap().pw_bootstrap = Some([0xD4; 16]);
        assert!(matches!(
            d.apply(&commit("alice", [0xD4; 16], "rec-4"), None).resp,
            SyncResponse::Error(StateError::PasswordExists)
        ));
    }

    /// ResetPassword: clear record + set a new token (the old password becomes
    /// invalid immediately — record=None ⇒ the login side takes the dummy
    /// path); unknown user ⇒ NoSuchUser; idempotent replay (same token)
    /// allowed without error.
    #[test]
    fn m8_reset_password_invalidates_old_record() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
        let mut d = bootstrapped(&root);
        d.apply(
            &SyncRequest::CreateUser {
                username: "bob".into(),
                pw_bootstrap: [1; 16],
            },
            None,
        );
        d.apply(
            &SyncRequest::SetPasswordBootstrap {
                user: "bob".into(),
                token: [1; 16],
                record_b64: "old-record".into(),
                profile: 0,
            },
            None,
        );
        // Unknown user.
        assert!(matches!(
            d.apply(
                &SyncRequest::ResetPassword {
                    user: "ghost".into(),
                    new_token: [2; 16]
                },
                None
            )
            .resp,
            SyncResponse::Error(StateError::NoSuchUser)
        ));
        // Reset: the old record is invalidated immediately (login side
        // record=None → dummy — same shape for enumeration).
        assert!(matches!(
            d.apply(
                &SyncRequest::ResetPassword {
                    user: "bob".into(),
                    new_token: [2; 16]
                },
                None
            )
            .resp,
            SyncResponse::Ok
        ));
        let row = d.users.get("bob").unwrap();
        assert_eq!(row.opaque_record, None, "old password record invalidated");
        assert_eq!(row.opaque_profile, 0);
        assert_eq!(row.pw_bootstrap, Some([2; 16]), "new token in place");
        // The new token can land a new record.
        assert!(matches!(
            d.apply(
                &SyncRequest::SetPasswordBootstrap {
                    user: "bob".into(),
                    token: [2; 16],
                    record_b64: "new-record".into(),
                    profile: 0
                },
                None
            )
            .resp,
            SyncResponse::Ok
        ));
        assert_eq!(
            d.users.get("bob").unwrap().opaque_record.as_deref(),
            Some("new-record")
        );
    }

    /// SetUserAdmin/SetUserDisabled: set/unset + unknown user rejected;
    /// disabling does not retroactively clear the password (`disabled` and
    /// the record are two orthogonal dimensions — after enable, the original
    /// password keeps working).
    #[test]
    fn m8_set_user_admin_disabled_semantics() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[14; 32]);
        let mut d = bootstrapped(&root);
        d.apply(
            &SyncRequest::CreateUser {
                username: "carol".into(),
                pw_bootstrap: [1; 16],
            },
            None,
        );
        d.apply(
            &SyncRequest::SetPasswordBootstrap {
                user: "carol".into(),
                token: [1; 16],
                record_b64: "rec".into(),
                profile: 0,
            },
            None,
        );
        assert!(matches!(
            d.apply(
                &SyncRequest::SetUserAdmin {
                    user: "carol".into(),
                    admin: true
                },
                None
            )
            .resp,
            SyncResponse::Ok
        ));
        assert!(d.users.get("carol").unwrap().admin);
        assert!(matches!(
            d.apply(
                &SyncRequest::SetUserAdmin {
                    user: "carol".into(),
                    admin: false
                },
                None
            )
            .resp,
            SyncResponse::Ok
        ));
        assert!(!d.users.get("carol").unwrap().admin);
        // Disable/enable round trip: the password record is retained (after
        // enable, the original password keeps working — design semantics:
        // disabled only blocks login, it is not a credential revocation).
        assert!(matches!(
            d.apply(
                &SyncRequest::SetUserDisabled {
                    user: "carol".into(),
                    disabled: true
                },
                None
            )
            .resp,
            SyncResponse::Ok
        ));
        let row = d.users.get("carol").unwrap();
        assert!(row.disabled);
        assert_eq!(
            row.opaque_record.as_deref(),
            Some("rec"),
            "disabling does not clear the password record"
        );
        assert!(matches!(
            d.apply(
                &SyncRequest::SetUserDisabled {
                    user: "carol".into(),
                    disabled: false
                },
                None
            )
            .resp,
            SyncResponse::Ok
        ));
        assert!(!d.users.get("carol").unwrap().disabled);
        // Both writes reject an unknown user.
        for req in [
            SyncRequest::SetUserAdmin {
                user: "ghost".into(),
                admin: true,
            },
            SyncRequest::SetUserDisabled {
                user: "ghost".into(),
                disabled: true,
            },
        ] {
            assert!(
                matches!(
                    d.apply(&req, None).resp,
                    SyncResponse::Error(StateError::NoSuchUser)
                ),
                "{req:?} unknown user ⇒ NoSuchUser"
            );
        }
        // Idempotent: same-value replay allowed (the Raft replay path).
        assert!(matches!(
            d.apply(
                &SyncRequest::SetUserAdmin {
                    user: "carol".into(),
                    admin: false
                },
                None
            )
            .resp,
            SyncResponse::Ok
        ));
    }

    /// Snapshot round trip: UserRow's new three-field set survives
    /// NetStateData snapshot serialization/deserialization (the positive
    /// anchor for snapshot compatibility after the M8 field additions —
    /// paired with the legacy failure test).
    #[test]
    fn m8_user_fields_survive_snapshot_roundtrip() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[15; 32]);
        let mut d = bootstrapped(&root);
        d.apply(
            &SyncRequest::CreateUser {
                username: "dave".into(),
                pw_bootstrap: [0x5E; 16],
            },
            None,
        );
        d.apply(
            &SyncRequest::SetUserAdmin {
                user: "dave".into(),
                admin: true,
            },
            None,
        );
        d.apply(
            &SyncRequest::SetUserDisabled {
                user: "dave".into(),
                disabled: true,
            },
            None,
        );
        let back = NetStateData::from_bytes(&d.to_bytes()).expect("roundtrip");
        let row = back.users.get("dave").unwrap();
        assert!(row.admin && row.disabled);
        assert_eq!(row.pw_bootstrap, Some([0x5E; 16]));
    }
}
