//! NetBackend: the unified **async** read/write facade of the control/admin
//! planes (docs/design.md §2.2/§3.11 M4 batch).
//!
//! Two forms (`server.toml [sync].mode`, default `single` —— m2/m2-direct
//! deployments unaffected):
//!
//! - [`NetBackend::Single`]: the M2 local redb state store (synchronous
//!   [`StateStore`] —— methods complete immediately);
//! - [`NetBackend::Sync`] (feature `multi-primary`): writes committed over
//!   Raft (enter at any node, non-leaders automatically forward to the
//!   leader, §4 write forwarding); reads by consistency tier —— registry
//!   rows/user surface take the **linearizable read** (enter at any node,
//!   cross-node read-then-write correct), the directory three-state takes
//!   the **two-level read** of `SyncNode::device_directory()` (record
//!   cache + epoch + apply-lag breaker, §4 reads and caching —— precisely
//!   the injection point of `session::respond`).
//!
//! Why an async facade instead of making [`crate::netstate::NetState`] async:
//! the single-server form's synchronous trait stays untouched (redb is
//! synchronous IO), while Raft writes/linearizable reads are network round
//! trips —— block_on over a synchronous trait inside async dispatch paths is
//! a deadlock trap, so the facade goes async at the assembly layer (the same
//! reason the `§1.3.3c` lookup seam already demanded BoxFuture).

use flock_protocol::ed25519_dalek::VerifyingKey;
use flock_protocol::session::{DeviceId, LookupVerdict};

use crate::netstate::{
    DeviceRow, DeviceStatus, NetError, RedeemError, RedeemOutcome, RedeemRequest, StateStore,
    UserOpError,
};

#[cfg(feature = "multi-primary")]
use flock_sync::proto as sync_proto;

/// The unified backend behind the form dispatch.
pub enum NetBackend {
    /// Single server: the local state store (M2 form; m2-direct.yml and
    /// similar deployments).
    Single(std::sync::Arc<StateStore>),
    /// Multi-primary: the flock-sync Raft state machine (feature
    /// `multi-primary`).
    #[cfg(feature = "multi-primary")]
    Sync(std::sync::Arc<SyncNetState>),
}

impl NetBackend {
    /// Current global revocation_epoch (Sync = this node's applied epoch).
    pub async fn epoch(&self) -> u64 {
        match self {
            NetBackend::Single(s) => s.epoch(),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => s.node.local_epoch(),
        }
    }

    /// Directory three-state (the respond/ticket device-state data source).
    /// Sync takes the two-level read (cache+epoch+breaker).
    pub async fn lookup(&self, id: &DeviceId) -> LookupVerdict {
        match self {
            NetBackend::Single(s) => s.lookup(id),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => s.node.dir().lookup_async(*id).await,
        }
    }

    /// Registry row (owner panel/VIP). Sync = linearizable read.
    pub async fn device_row(&self, id: &DeviceId) -> Option<DeviceRow> {
        match self {
            NetBackend::Single(s) => s.device_row(id),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => match s
                .node
                .read_linearizable(flock_sync::proto::ReadQuery::DeviceRow(id.0))
                .await
            {
                Ok(sync_proto::ReadView::Device(Some(row))) => Some(row),
                _ => None,
            },
        }
    }

    /// All devices under an owner (DeviceList).
    pub async fn devices_of(&self, owner: &str) -> Vec<(DeviceId, DeviceRow)> {
        match self {
            NetBackend::Single(s) => s.devices_of(owner),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                match s
                    .node
                    .read_linearizable(flock_sync::proto::ReadQuery::DevicesOf(owner.to_string()))
                    .await
                {
                    Ok(sync_proto::ReadView::Devices(rows)) => rows
                        .into_iter()
                        .map(|(id, row)| (DeviceId(id), row))
                        .collect(),
                    _ => Vec::new(),
                }
            }
        }
    }

    /// Register a device (assigns a VIP; M7 adds hostname —— empty string
    /// lands as "(unknown)").
    pub async fn register_device(
        &self,
        owner: &str,
        x25519: [u8; 32],
        ed25519: [u8; 32],
        hostname: &str,
    ) -> Result<DeviceRow, NetError> {
        match self {
            NetBackend::Single(s) => s.register_device(owner, x25519, ed25519, hostname),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                let resp = s
                    .write(sync_proto::SyncRequest::RegisterDevice {
                        owner: owner.to_string(),
                        x25519,
                        ed25519,
                        hostname: hostname.to_string(),
                        // Registration time injected by the submitting side
                        // (apply has no clock —— deterministic; the reaper's
                        // anchor).
                        registered_at_unix: flock_protocol::trust::now_unix(),
                    })
                    .await?;
                match resp {
                    sync_proto::SyncResponse::Device(row) => Ok(row),
                    sync_proto::SyncResponse::Error(e) => Err(net_err(&e)),
                    _ => Err(NetError::Internal("unexpected register response".into())),
                }
            }
        }
    }

    /// M7: update a device hostname (the re-register path; non-terminal rows
    /// only).
    pub async fn set_hostname(&self, id: &DeviceId, hostname: &str) -> Result<DeviceRow, NetError> {
        match self {
            NetBackend::Single(s) => s.set_hostname(id, hostname),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                match s
                    .write(sync_proto::SyncRequest::SetHostname {
                        device: id.0,
                        hostname: hostname.to_string(),
                    })
                    .await?
                {
                    sync_proto::SyncResponse::Device(row) => Ok(row),
                    sync_proto::SyncResponse::Error(e) => Err(net_err(&e)),
                    _ => Err(NetError::Internal(
                        "unexpected set_hostname response".into(),
                    )),
                }
            }
        }
    }

    /// M7: expire a device (submitted by the reaper; row retained for audit +
    /// VIP returned to the pool + epoch advance —— idempotent).
    pub async fn expire(&self, id: &DeviceId, now_unix: u64) -> Result<u64, NetError> {
        match self {
            NetBackend::Single(s) => s.expire(id, now_unix),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                match s
                    .write(sync_proto::SyncRequest::Expire {
                        device: id.0,
                        now_unix,
                    })
                    .await?
                {
                    sync_proto::SyncResponse::Epoch(e) => Ok(e),
                    sync_proto::SyncResponse::Error(e) => Err(net_err(&e)),
                    _ => Err(NetError::Internal("unexpected expire response".into())),
                }
            }
        }
    }

    /// Revoke (row retained, VIP not recycled, epoch +1; local session kills
    /// via the apply hook, §2.2).
    pub async fn revoke(&self, id: &DeviceId) -> Result<u64, NetError> {
        self.set_status(id, DeviceStatus::Revoked).await
    }

    /// Disable (no deletion; epoch +1).
    pub async fn disable(&self, id: &DeviceId) -> Result<u64, NetError> {
        self.set_status(id, DeviceStatus::Disabled).await
    }

    /// Re-enable (Disabled → Active only; epoch untouched).
    pub async fn enable(&self, id: &DeviceId) -> Result<(), NetError> {
        self.set_status(id, DeviceStatus::Active).await.map(|_| ())
    }

    async fn set_status(&self, id: &DeviceId, status: DeviceStatus) -> Result<u64, NetError> {
        match self {
            NetBackend::Single(s) => match status {
                DeviceStatus::Revoked => s.revoke(id),
                DeviceStatus::Disabled => s.disable(id),
                DeviceStatus::Active => s.enable(id).map(|_| s.epoch()),
                // Expired goes through [`NetBackend::expire`] (carries
                // now_unix —— time semantics moved there).
                DeviceStatus::Expired => Err(NetError::InvalidState(
                    "expire goes through expire() (needs now_unix)".into(),
                )),
            },
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                let req = match status {
                    DeviceStatus::Revoked => sync_proto::SyncRequest::Revoke { device: id.0 },
                    DeviceStatus::Disabled => sync_proto::SyncRequest::Disable { device: id.0 },
                    DeviceStatus::Active => sync_proto::SyncRequest::Enable { device: id.0 },
                    DeviceStatus::Expired => {
                        return Err(NetError::InvalidState(
                            "expire goes through expire() (needs now_unix)".into(),
                        ))
                    }
                };
                match s.write(req).await? {
                    sync_proto::SyncResponse::Epoch(e) => Ok(e),
                    sync_proto::SyncResponse::Error(e) => Err(net_err(&e)),
                    _ => Err(NetError::Internal("unexpected status response".into())),
                }
            }
        }
    }

    /// Invite redemption (dedup+revocation+expiry checks → create user/device
    /// + assign VIP; one Raft commit = atomic; M7 adds hostname).
    pub async fn redeem_invite(
        &self,
        req: RedeemRequest<'_>,
    ) -> Result<RedeemOutcome, RedeemError> {
        match self {
            NetBackend::Single(s) => s.redeem_invite(req),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                // Cluster identity pinning is carried by the state machine's
                // bootstrap identity (root public key compared inside
                // apply_redeem).
                let resp = s
                    .write(sync_proto::SyncRequest::RedeemInvite {
                        invite_bytes: req.invite_bytes.to_vec(),
                        username: req.username.to_string(),
                        x25519: req.device_x25519,
                        ed25519: req.device_ed25519,
                        hostname: req.hostname.to_string(),
                        now_unix: req.now_unix,
                    })
                    .await
                    .map_err(redeem_io)?;
                match resp {
                    sync_proto::SyncResponse::Redeem {
                        username,
                        device_id,
                        vip,
                    } => Ok(RedeemOutcome {
                        username,
                        device_id,
                        vip,
                    }),
                    sync_proto::SyncResponse::Error(e) => Err(redeem_err(&e)),
                    _ => Err(RedeemError::Internal("unexpected redeem response".into())),
                }
            }
        }
    }

    /// Revoke an unredeemed invite (a root-signed admin operation —— the
    /// multi-primary form requires the operations-side root key; servers do
    /// not hold it).
    pub async fn revoke_invite(&self, invite_id: &[u8; 16]) -> Result<(), NetError> {
        match self {
            NetBackend::Single(s) => s.revoke_invite(invite_id),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(_) => Err(NetError::InvalidState(
                "revoke_invite in multi-primary form is a root-signed admin operation (run on the ops side)".into(),
            )),
        }
    }

    /// Invite registration (the single-server mint path; in multi-primary
    /// form minting happens on the root-key side).
    pub async fn record_invite(
        &self,
        invite_id: &[u8; 16],
        expiry_unix: u64,
    ) -> Result<(), NetError> {
        match self {
            NetBackend::Single(s) => s.record_invite(invite_id, expiry_unix),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                match s
                    .write(sync_proto::SyncRequest::RecordInvite {
                        invite_id: *invite_id,
                        expiry_unix,
                    })
                    .await?
                {
                    sync_proto::SyncResponse::Ok => Ok(()),
                    sync_proto::SyncResponse::Error(e) => Err(net_err(&e)),
                    _ => Err(NetError::Internal(
                        "unexpected record_invite response".into(),
                    )),
                }
            }
        }
    }

    /// Set the password record (only when unset; cross-node login ⇒ the
    /// replication form, §2.4 shared OPRF).
    pub async fn set_password(
        &self,
        user: &str,
        record_b64: &str,
        profile: u16,
    ) -> Result<(), NetError> {
        match self {
            NetBackend::Single(s) => s.set_password(user, record_b64, profile),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                match s
                    .write(sync_proto::SyncRequest::SetPassword {
                        user: user.to_string(),
                        record_b64: record_b64.to_string(),
                        profile,
                    })
                    .await?
                {
                    sync_proto::SyncResponse::Ok => Ok(()),
                    sync_proto::SyncResponse::Error(e) => Err(net_err(&e)),
                    _ => Err(NetError::Internal(
                        "unexpected set_password response".into(),
                    )),
                }
            }
        }
    }

    /// Password record (linearizable read).
    pub async fn password(&self, user: &str) -> Option<(String, u16)> {
        match self {
            NetBackend::Single(s) => s.password(user),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => match s
                .node
                .read_linearizable(flock_sync::proto::ReadQuery::User(user.to_string()))
                .await
            {
                Ok(sync_proto::ReadView::User(Some(row))) => {
                    row.opaque_record.map(|r| (r, row.opaque_profile))
                }
                _ => None,
            },
        }
    }

    /// Register an SR-SIG1 user public key (the key-bind path).
    pub async fn add_user_sig_key(&self, user: &str, pub32: [u8; 32]) -> Result<(), NetError> {
        match self {
            NetBackend::Single(s) => s.add_user_sig_key(user, pub32),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                match s
                    .write(sync_proto::SyncRequest::AddUserSigKey {
                        user: user.to_string(),
                        pub32,
                    })
                    .await?
                {
                    sync_proto::SyncResponse::Ok => Ok(()),
                    sync_proto::SyncResponse::Error(e) => Err(net_err(&e)),
                    _ => Err(NetError::Internal(
                        "unexpected add_user_sig_key response".into(),
                    )),
                }
            }
        }
    }

    /// SR-SIG1 verification public key set (linearizable read).
    pub async fn user_sig_pubs(&self, user: &str) -> Vec<VerifyingKey> {
        match self {
            NetBackend::Single(s) => s.user_sig_pubs(user),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => match s
                .node
                .read_linearizable(flock_sync::proto::ReadQuery::User(user.to_string()))
                .await
            {
                Ok(sync_proto::ReadView::User(Some(row))) => row
                    .sr_sig_pubs
                    .iter()
                    .filter_map(|k| VerifyingKey::from_bytes(k).ok())
                    .collect(),
                _ => Vec::new(),
            },
        }
    }

    /// One-time bind_token consumption (§2.4 linearizable dedup).
    pub async fn consume_bind_token(&self, token: &[u8; 16]) -> bool {
        match self {
            NetBackend::Single(s) => s.consume_bind_token(token),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                matches!(
                    s.write(sync_proto::SyncRequest::ConsumeBindToken { token: *token })
                        .await,
                    Ok(sync_proto::SyncResponse::Ok)
                )
            }
        }
    }

    /// VIP allocation (monotonic watermark; not recycled).
    pub async fn allocate_ip(&self) -> Result<std::net::Ipv4Addr, NetError> {
        match self {
            NetBackend::Single(s) => s.allocate_ip(),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => match s.write(sync_proto::SyncRequest::AllocateIp).await? {
                sync_proto::SyncResponse::Ip(vip) => Ok(std::net::Ipv4Addr::from(vip)),
                sync_proto::SyncResponse::Error(e) => Err(net_err(&e)),
                _ => Err(NetError::Internal("unexpected allocate response".into())),
            },
        }
    }

    /// Verbatim write pass-through (feature `multi-primary`; admin
    /// SignedWrite → operations-side root-signed operations:
    /// Bootstrap/SetOprf/RecordInvite —— signature verification entirely
    /// inside the Raft state machine).
    #[cfg(feature = "multi-primary")]
    pub async fn write_sync(
        &self,
        req: sync_proto::SyncRequest,
    ) -> Result<sync_proto::SyncResponse, NetError> {
        match self {
            NetBackend::Sync(s) => s.write(req).await,
            NetBackend::Single(_) => Err(NetError::InvalidState(
                "no SignedWrite in single-server form (admin operations go through invite/redeem/device-add/revoke)".into(),
            )),
        }
    }

    // ------------------------------------------------------------------
    // M8 (§7-M8.3): Web admin-plane user operations (dual-armed like
    // DeviceOp: Single = local redb direct write; Sync = the five Raft
    // writes. Authorization at the submitting handler/CLI layer —— same
    // shape as the control-plane DeviceOp)
    // ------------------------------------------------------------------

    /// User row (admin/disabled/pw_bootstrap; the login disabled decision +
    /// the webui list surface).
    pub async fn user_row(&self, user: &str) -> Option<StateStoreUserRow> {
        match self {
            NetBackend::Single(s) => s.user_row(user),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => match s
                .node
                .read_linearizable(flock_sync::proto::ReadQuery::User(user.to_string()))
                .await
            {
                Ok(sync_proto::ReadView::User(row)) => row,
                _ => None,
            },
        }
    }

    /// All user rows (locally applied view —— the display tier, same tier as
    /// the roster in §7-M7.4).
    pub async fn users_all(&self) -> Vec<(String, StateStoreUserRow)> {
        match self {
            NetBackend::Single(s) => s.users_all(),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => s.node.users_snapshot(),
        }
    }

    /// Create a user (carrying the one-time bootstrap token); already exists
    /// ⇒ [`UserOpError::UserExists`] (the submitting side ignores it
    /// idempotently as needed —— the multi-primary path of
    /// `web-admin-add`).
    pub async fn create_user(&self, username: &str, token: [u8; 16]) -> Result<(), UserOpError> {
        match self {
            NetBackend::Single(s) => s.create_user(username, token),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => match s
                .write(sync_proto::SyncRequest::CreateUser {
                    username: username.to_string(),
                    pw_bootstrap: token,
                })
                .await
                .map_err(sync_op_int)?
            {
                sync_proto::SyncResponse::Ok => Ok(()),
                sync_proto::SyncResponse::Error(e) => Err(user_op_err(&e)),
                _ => Err(UserOpError::Internal(
                    "unexpected create_user response".into(),
                )),
            },
        }
    }

    /// Persist the password record via the bootstrap token (atomic
    /// consumption: token matches and record empty ⇒ persist the record +
    /// clear the token).
    pub async fn set_password_bootstrap(
        &self,
        user: &str,
        token: [u8; 16],
        record_b64: &str,
        profile: u16,
    ) -> Result<(), UserOpError> {
        match self {
            NetBackend::Single(s) => s.set_password_bootstrap(user, token, record_b64, profile),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => match s
                .write(sync_proto::SyncRequest::SetPasswordBootstrap {
                    user: user.to_string(),
                    token,
                    record_b64: record_b64.to_string(),
                    profile,
                })
                .await
                .map_err(sync_op_int)?
            {
                sync_proto::SyncResponse::Ok => Ok(()),
                sync_proto::SyncResponse::Error(e) => Err(user_op_err(&e)),
                _ => Err(UserOpError::Internal(
                    "unexpected set_password_bootstrap response".into(),
                )),
            },
        }
    }

    /// Administrator password reset (clears the record + sets a new token ——
    /// the old password stops working immediately).
    pub async fn reset_password(&self, user: &str, new_token: [u8; 16]) -> Result<(), UserOpError> {
        match self {
            NetBackend::Single(s) => s.reset_password(user, new_token),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => match s
                .write(sync_proto::SyncRequest::ResetPassword {
                    user: user.to_string(),
                    new_token,
                })
                .await
                .map_err(sync_op_int)?
            {
                sync_proto::SyncResponse::Ok => Ok(()),
                sync_proto::SyncResponse::Error(e) => Err(user_op_err(&e)),
                _ => Err(UserOpError::Internal(
                    "unexpected reset_password response".into(),
                )),
            },
        }
    }

    /// Grant/revoke the Web admin role.
    pub async fn set_user_admin(&self, user: &str, admin: bool) -> Result<(), UserOpError> {
        match self {
            NetBackend::Single(s) => s.set_user_admin(user, admin),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => match s
                .write(sync_proto::SyncRequest::SetUserAdmin {
                    user: user.to_string(),
                    admin,
                })
                .await
                .map_err(sync_op_int)?
            {
                sync_proto::SyncResponse::Ok => Ok(()),
                sync_proto::SyncResponse::Error(e) => Err(user_op_err(&e)),
                _ => Err(UserOpError::Internal(
                    "unexpected set_user_admin response".into(),
                )),
            },
        }
    }

    /// Disable/enable a user (blocks login; does not retroactively drop
    /// established sessions).
    pub async fn set_user_disabled(&self, user: &str, disabled: bool) -> Result<(), UserOpError> {
        match self {
            NetBackend::Single(s) => s.set_user_disabled(user, disabled),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => match s
                .write(sync_proto::SyncRequest::SetUserDisabled {
                    user: user.to_string(),
                    disabled,
                })
                .await
                .map_err(sync_op_int)?
            {
                sync_proto::SyncResponse::Ok => Ok(()),
                sync_proto::SyncResponse::Error(e) => Err(user_op_err(&e)),
                _ => Err(UserOpError::Internal(
                    "unexpected set_user_disabled response".into(),
                )),
            },
        }
    }
}

/// User row type re-export (netstate and flock-sync share the definition;
/// avoids importing two names at the top of backend).
use crate::netstate::UserRow as StateStoreUserRow;

#[cfg(feature = "multi-primary")]
fn sync_op_int(e: NetError) -> UserOpError {
    UserOpError::Internal(format!("sync: {e}"))
}

#[cfg(feature = "multi-primary")]
fn user_op_err(e: &sync_proto::StateError) -> UserOpError {
    use sync_proto::StateError;
    match e {
        StateError::UserExists => UserOpError::UserExists,
        StateError::PasswordExists => UserOpError::PasswordExists,
        StateError::BadBootstrapToken => UserOpError::BadBootstrapToken,
        StateError::NoSuchUser => UserOpError::NoSuchUser,
        other => UserOpError::Internal(format!("state: {other}")),
    }
}

// ============================================================================
// Multi-primary adapter (feature multi-primary)
// ============================================================================

#[cfg(feature = "multi-primary")]
pub use adapter::SyncNetState;

#[cfg(feature = "multi-primary")]
mod adapter {
    use std::sync::Arc;

    use flock_sync::proto::{SyncError, SyncRequest, SyncResponse};

    use crate::netstate::NetError;

    /// The NetBackend adapter over SyncNode (leader-forwarding writes /
    /// linearizable reads via the node facade).
    pub struct SyncNetState {
        pub node: Arc<flock_sync::SyncNode>,
    }

    impl SyncNetState {
        pub fn new(node: Arc<flock_sync::SyncNode>) -> Arc<Self> {
            Arc::new(SyncNetState { node })
        }

        /// Write (enter at any node; non-leaders auto-forward, §4).
        pub async fn write(&self, req: SyncRequest) -> Result<SyncResponse, NetError> {
            self.node.write(req).await.map_err(net_of_sync)
        }
    }

    pub(crate) fn net_of_sync(e: SyncError) -> NetError {
        NetError::Internal(format!("sync: {e}"))
    }
}

// (Review item 12: the former `mod conv` glue layer converting flock-sync
// rows → server rows was deleted —— netstate.rs's row types are re-exported
// directly from flock_sync::proto, one type for both arms.)

// —— StateError → server error surface mapping ——

#[cfg(feature = "multi-primary")]
fn net_err(e: &flock_sync::proto::StateError) -> NetError {
    use flock_sync::proto::StateError;
    match e {
        StateError::DeviceExists => NetError::DeviceExists,
        StateError::DeviceNotFound => NetError::NotFound,
        StateError::RevokedIsTerminal => NetError::InvalidState("revoked is terminal".into()),
        StateError::ExpiredIsTerminal => NetError::InvalidState("expired is terminal".into()),
        StateError::IpExhausted => NetError::IpExhausted,
        StateError::PasswordExists => NetError::InvalidState("password already set".into()),
        StateError::NoSuchUser => NetError::NotFound,
        StateError::BindTokenUsed => NetError::InvalidState("bind_token used".into()),
        StateError::AlreadyUsed
        | StateError::InviteRevoked
        | StateError::InviteExpired { .. }
        | StateError::UnknownInvite
        | StateError::BadInvite(_) => NetError::InvalidState(format!("invite: {e}")),
        other => NetError::Internal(format!("state: {other}")),
    }
}

#[cfg(feature = "multi-primary")]
fn redeem_io(e: NetError) -> crate::netstate::RedeemError {
    crate::netstate::RedeemError::Internal(e.to_string())
}

#[cfg(feature = "multi-primary")]
fn redeem_err(e: &flock_sync::proto::StateError) -> crate::netstate::RedeemError {
    use crate::netstate::RedeemError;
    use flock_sync::proto::StateError;
    match e {
        StateError::AlreadyUsed => RedeemError::AlreadyUsed,
        StateError::InviteRevoked => RedeemError::InviteRevoked,
        StateError::InviteExpired {
            now_unix,
            expiry_unix,
        } => RedeemError::Expired {
            now_unix: *now_unix,
            expiry_unix: *expiry_unix,
        },
        StateError::UnknownInvite => RedeemError::Unknown,
        StateError::BadInvite(m) => RedeemError::BadInvite(m.clone()),
        StateError::UserExists => RedeemError::UserExists,
        StateError::DeviceExists => RedeemError::DeviceExists,
        StateError::IpExhausted => RedeemError::IpExhausted,
        StateError::NotBootstrapped => RedeemError::Internal("cluster not bootstrapped".into()),
        other => RedeemError::Internal(format!("state: {other}")),
    }
}
