//! Control flow (docs/design.md §2.2 / §3.11: yamux control flow, postcard
//! messages, versioning).
//!
//! Carries: OPAQUE login (`anchor`: the server identity signature covering
//! SERVER_ID‖user‖ke2‖bind_token) → session ticket issuance (TTL,
//! revocation_epoch; the ticket root = a local seed (single server) or the
//! root inside Raft state (multi-primary, verifiable by any server —— the
//! closure precondition of the SR-SIG1 cross-server replay surface, §2.2)) →
//! key-bind (device public key registration) → device registry operations →
//! SR-SIG1 request verification → dir_pull (the root-signed
//! ClusterDirectory pushed down).
//!
//! # Ticket enforcement contract (§2.2, interface-contract level)
//!
//! All SR-SIG1-protected **state change** requests must carry a valid
//! ticket; the check order of [`CtrlGuard::admit_state_change`] =
//! **ticket (signature+TTL+epoch+revocation) → SR-SIG1 verification → nonce
//! accounting** —— on ticket/signature failure the nonce is **not
//! recorded** (`ticket.rs::tests` + `tests/control_flow.rs::full_chain_*`
//! assert this order: bad ticket + fresh nonce ⇒ rejected and not
//! recorded).
//!
//! # Async dispatch (M4 multi-primary batch)
//!
//! Reads/writes go through [`NetBackend`] (single = local redb completes
//! immediately; multi-primary = Raft commit/linearizable read —— a network
//! round trip, hence dispatched as async; the same reason as the §1.3.3c
//! lookup seam).
//!
//! # Frame format
//!
//! The control flow = the first yamux stream inside the tunnel (client
//! `open_stream(Prio::Control)`; the server dispatches by stream id=1).
//! Each message = `[u32 LE len][postcard CtrlRequest/CtrlResponse]`.

use ed25519_dalek::{Signature, Verifier};
use flock_protocol::opaque_ke;
use flock_protocol::pake::{
    anchor_sign, login_finish_anchored, server_login_finish, server_login_start, server_reg_start,
    AnchorExpectation, Profile as PakeProfile,
};
use flock_protocol::rand;
use flock_protocol::session::DeviceId;
use flock_protocol::sig;
use flock_protocol::{ed25519_dalek, x25519_dalek};

use crate::backend::NetBackend;
use crate::netstate::{NetError, RedeemError, RedeemRequest};
use crate::server::ServerCore;
use crate::ticket::{NonceLedger, TicketAuthority};

// ============================================================================
// Shared contract re-exports (M7 type uplift —— defined in
// flock_protocol::roster, the same type on both ends with no second source
// of truth; existing reference paths `flock_server::control::*` unchanged)
// ============================================================================

pub use flock_protocol::roster::{
    keybind_canonical, recv_ctrl_msg, send_ctrl_msg, CtrlError, CtrlRequest, CtrlResponse,
    DeviceOp, DevicePubs, DeviceRowWire, PeerInfo, PeerKind, SrAuth, TicketWire,
    CTRL_PROTO_VERSION, KEYBIND_LABEL, MAX_CTRL_MSG,
};

/// The method slot of the SR-SIG1 canonical (the unified control-plane
/// method name; the path distinguishes operations).
pub const CTRL_METHOD: &str = "CTRL";
/// The path of each SR-SIG1-protected operation (goes into the canonical
/// seven fields, §1.3.2 wire format unchanged).
pub const PATH_TICKET_RENEW: &str = "/ticket-renew";
pub const PATH_REDEEM_INVITE: &str = "/redeem-invite";
pub const PATH_DEVICE_OP: &str = "/device-op";

fn err(code: CtrlError) -> CtrlResponse {
    CtrlResponse::Err {
        code,
        msg: code.msg().to_string(),
    }
}

fn state_err(e: NetError) -> CtrlResponse {
    let code = match &e {
        NetError::NotFound => CtrlError::DeviceUnknown,
        NetError::InvalidState(_) => CtrlError::InvalidState,
        NetError::DeviceExists => CtrlError::DeviceExists,
        NetError::IpExhausted => CtrlError::IpExhausted,
        NetError::Internal(_) => CtrlError::Internal,
    };
    eprintln!("flock-server: netstate: {e}");
    err(code)
}

fn redeem_err_code(e: &RedeemError) -> CtrlError {
    match e {
        RedeemError::AlreadyUsed => CtrlError::InviteUsed,
        RedeemError::InviteRevoked => CtrlError::InviteRevoked,
        RedeemError::Expired { .. } => CtrlError::InviteExpired,
        RedeemError::Unknown => CtrlError::InviteUnknown,
        RedeemError::BadInvite(_) => CtrlError::InviteBadSig,
        RedeemError::UserExists => CtrlError::UserExists,
        RedeemError::DeviceExists => CtrlError::DeviceExists,
        RedeemError::IpExhausted => CtrlError::IpExhausted,
        RedeemError::Internal(_) => CtrlError::Internal,
    }
}

// ============================================================================
// CtrlGuard: the ticket enforcement contract + SR-SIG1 + nonce accounting
// (§2.2, interface-contract level)
// ============================================================================

/// Unified admission for state changes: **ticket
/// (signature+TTL+epoch+revocation) → SR-SIG1 verification → nonce
/// accounting**.
///
/// Contract (set in stone, the ordering has test assertions):
/// 1. Missing/invalid ticket ⇒ immediate rejection —— the **nonce is not
///    recorded** (after a bad ticket + fresh nonce is rejected, the same
///    nonce can still reach the later checks with a valid ticket); the
///    equivalent replay window = min(±300s, ticket TTL).
/// 2. SR-SIG1: any hit among the user's registered public keys (key-bind
///    persisted); ±300s window; header user == ticket user and the ticket's
///    bound device == the current session device (tickets bind the device,
///    §2.2).
/// 3. Nonce dedup + recording (the last step; executed only after both
///    previous steps pass).
pub struct CtrlGuard {
    /// Ticket authority (Local seed / Sync = the root inside Raft —— the
    /// verification semantics match, see [`TicketAuthority`]).
    pub authority: TicketAuthority,
    pub nonces: NonceLedger,
}

impl CtrlGuard {
    pub fn new(authority: TicketAuthority) -> Self {
        CtrlGuard {
            authority,
            nonces: NonceLedger::new(),
        }
    }

    /// Ticket verification + user resolution (shared by KeyBind and admit;
    /// epoch/device state come from the NetBackend).
    async fn ticket_principal(
        &self,
        net: &NetBackend,
        session_device: &DeviceId,
        ticket: &TicketWire,
        now_unix: u64,
    ) -> Result<String, crate::ticket::TicketReason> {
        let epoch = net.epoch().await;
        let verdict = net.lookup(session_device).await;
        let principal = self
            .authority
            .verify(ticket, session_device, now_unix, epoch, |_| verdict)?;
        match principal.user {
            // Local tickets embed the user; Sync tickets bind the device ——
            // the user is resolved from the registry owner.
            None => net
                .device_row(session_device)
                .await
                .map(|r| r.owner)
                .filter(|u| !u.is_empty())
                .ok_or(crate::ticket::TicketReason::DeviceNotActive),
            Some(u) => Ok(u),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn admit_state_change(
        &self,
        net: &NetBackend,
        session_device: &DeviceId,
        ticket: &TicketWire,
        auth: &SrAuth,
        path: &str,
        body: &[u8],
        now_unix: i64,
    ) -> Result<String, CtrlError> {
        // ① Ticket (ahead of any nonce accounting —— the §2.2 contract
        //    order).
        let user = self
            .ticket_principal(net, session_device, ticket, now_unix as u64)
            .await
            .map_err(|r| {
                eprintln!("flock-server: ticket rejected: {r}");
                CtrlError::TicketBad
            })?;
        // ② SR-SIG1 verification (the user's public key set comes from the
        //    registry —— linearizable).
        let keys = net.user_sig_pubs(&user).await;
        let verified = sig::verify(&auth.header, &keys, CTRL_METHOD, path, body, now_unix)
            .map_err(|e| match e {
                sig::AuthError::Format => CtrlError::SigFormat,
                sig::AuthError::Stale => CtrlError::SigStale,
                sig::AuthError::BadSignature => CtrlError::SigBad,
            })?;
        if verified.user != user {
            return Err(CtrlError::SigBad);
        }
        // ③ Nonce accounting (dedup + record; reached only after the first
        //    two steps pass).
        if !self
            .nonces
            .check_and_record(&verified.user, &verified.nonce, verified.ts, now_unix)
        {
            return Err(CtrlError::NonceReplay);
        }
        Ok(user)
    }
}

// ============================================================================
// Server dispatch
// ============================================================================

/// Session context of one control connection.
struct ConnCtx {
    /// The tunnel's peer device (authenticated by respond).
    device: DeviceId,
    /// The in-flight OPAQUE state of LoginBegin.
    pending_login: Option<Vec<u8>>,
}

/// Control-flow idle timeout (review item 8): no frame at all for
/// 3×keepalive (30s) closes the stream.
///
/// Relationship with the session-layer PING/PONG: PING/PONG travels on the
/// **record layer** (the whole connection), producing no yamux stream frames
/// visible to this layer —— it keeps the tunnel alive, **not** the idle
/// exemption of a single stream. After the control stream closes, the tunnel
/// and data channels are unaffected; the client just reopens a control
/// stream when it needs control business (the current M3 client's control
/// stream is a silent placeholder sending no business, so an idle close has
/// no functional impact).
const CTRL_IDLE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3 * flock_protocol::session::KEEPALIVE.as_secs());

/// Serve one control stream until EOF/error. Err means only an IO-layer
/// failure (business errors go through CtrlResponse::Err).
pub async fn serve_control<S: futures::io::AsyncRead + futures::io::AsyncWrite + Unpin>(
    core: &ServerCore,
    device: DeviceId,
    io: &mut S,
) -> std::io::Result<()> {
    let mut ctx = ConnCtx {
        device,
        pending_login: None,
    };
    loop {
        // Idle timeout (review item 8): no inbound frame for 3×keepalive ⇒
        // gracefully end the control stream.
        let req: CtrlRequest = match tokio::time::timeout(CTRL_IDLE_TIMEOUT, recv_ctrl_msg(io))
            .await
        {
            Ok(r) => match r {
                Ok(r) => r,
                Err(_) => return Ok(()), // EOF/bad frame: the control stream ends
            },
            Err(_) => {
                eprintln!("flock-server: control stream idle > {CTRL_IDLE_TIMEOUT:?} — closing");
                return Ok(());
            }
        };
        let resp = dispatch(core, &mut ctx, req).await;
        send_ctrl_msg(io, &resp).await?;
    }
}

async fn dispatch(core: &ServerCore, ctx: &mut ConnCtx, req: CtrlRequest) -> CtrlResponse {
    let net = &core.net;
    let now_unix = flock_protocol::trust::now_unix();
    match req {
        CtrlRequest::Hello { ver } => {
            if ver != CTRL_PROTO_VERSION {
                return err(CtrlError::ProtoVersion);
            }
            CtrlResponse::Hello {
                ver: CTRL_PROTO_VERSION,
                cluster_id: core.identity.cluster_id.0,
                server_id: core.identity.server_id.0,
            }
        }

        // —— OPAQUE registration (set password; authorization = this session
        //    device's owner) ——
        CtrlRequest::PwBegin { user, m1_b64 } => {
            if owner_of_device(net, &ctx.device).await.as_deref() != Some(user.as_str()) {
                return err(CtrlError::NotAuthorized);
            }
            if net.password(&user).await.is_some() {
                return err(CtrlError::PasswordExists);
            }
            match server_reg_start(&core.oprf, &m1_b64, &user) {
                Ok(m2_b64) => CtrlResponse::PwChallenge { m2_b64 },
                Err(_) => err(CtrlError::Internal),
            }
        }
        CtrlRequest::PwCommit {
            record_b64,
            profile,
        } => {
            let Some(owner) = owner_of_device(net, &ctx.device).await else {
                return err(CtrlError::NotAuthorized);
            };
            // Record-side canonicalization (decode validation).
            let canonical = match flock_protocol::pake::server_reg_canonical(&record_b64) {
                Ok(c) => c,
                Err(_) => return err(CtrlError::Internal),
            };
            match net.set_password(&owner, &canonical, profile).await {
                Ok(()) => CtrlResponse::Ok,
                Err(e) => state_err(e),
            }
        }

        // —— OPAQUE login (anchor) → ticket issuance ——
        CtrlRequest::LoginBegin { user, ke1_b64 } => {
            let Some(owner) = owner_of_device(net, &ctx.device).await else {
                return err(CtrlError::NotAuthorized);
            };
            if owner != user {
                return err(CtrlError::NotAuthorized);
            }
            // M8 (§7-M8.3): the disabled check —— disabled users are blocked
            // from control-flow login (the session device's owner is already
            // authenticated, so this NotAuthorized forms no anonymous
            // enumeration surface; established sessions are not
            // retroactively dropped).
            if net.user_row(&user).await.is_some_and(|r| r.disabled) {
                eprintln!("flock-server: login rejected (user disabled): {user}");
                return err(CtrlError::NotAuthorized);
            }
            let record = net
                .password(&user)
                .await
                .and_then(|(r, _)| flock_protocol::pake::server_record_from_b64(&r).ok());
            match server_login_start(
                &mut rand::rngs::OsRng,
                &core.oprf,
                record.as_ref(),
                &ke1_b64,
                &user,
            ) {
                Ok((ke2_b64, state)) => {
                    // anchor: the server identity signature covers
                    // SERVER_ID‖user‖ke2‖bind_token (§1.3.3f).
                    let bind_token: [u8; 16] = rand::random();
                    let anchor_sig = anchor_sign(
                        &core.identity.identity,
                        &core.identity.server_id.0,
                        &user,
                        &ke2_b64,
                        &bind_token,
                    );
                    ctx.pending_login = Some(state);
                    CtrlResponse::LoginChallenge {
                        ke2_b64,
                        bind_token,
                        anchor_sig: anchor_sig.to_bytes().to_vec(),
                    }
                }
                Err(_) => err(CtrlError::LoginFailed),
            }
        }
        CtrlRequest::LoginFinish { ke3_b64 } => {
            let Some(state) = ctx.pending_login.take() else {
                return err(CtrlError::NotAuthorized);
            };
            if server_login_finish(&state, &ke3_b64).is_err() {
                return err(CtrlError::LoginFailed);
            }
            let Some(user) = owner_of_device(net, &ctx.device).await else {
                return err(CtrlError::NotAuthorized);
            };
            let epoch = net.epoch().await;
            let ticket = match core.guard.authority.issue(
                &user,
                ctx.device,
                epoch,
                now_unix,
                core.cfg.ticket_ttl_secs,
            ) {
                Ok(t) => t,
                Err(m) => {
                    eprintln!("flock-server: ticket issue: {m}");
                    return err(CtrlError::Internal);
                }
            };
            CtrlResponse::LoginOk { ticket, epoch }
        }

        // —— key-bind: device public key registration (§1.3.3f "public keys
        //    registered through the logged-in state") ——
        CtrlRequest::KeyBind {
            ticket,
            bind_token,
            device,
            sr_sig_pub,
            device_sig,
        } => {
            // Ticket (mandatory on state changes; includes the session-device
            // binding check).
            let user = match core
                .guard
                .ticket_principal(net, &ctx.device, &ticket, now_unix)
                .await
            {
                Ok(u) => u,
                Err(r) => {
                    eprintln!("flock-server: key-bind ticket rejected: {r}");
                    return err(CtrlError::TicketBad);
                }
            };
            // bind_token one-time (§2.4 linearizable dedup).
            if !net.consume_bind_token(&bind_token).await {
                return err(CtrlError::BindTokenUsed);
            }
            // Device signature (proof of possession): covers
            // cluster‖user‖bind_token‖device public key‖SR-SIG1 public key.
            let sig_bytes = keybind_canonical(
                &core.identity.cluster_id.0,
                &user,
                &bind_token,
                &device,
                &sr_sig_pub,
            );
            let (Ok(vk), Ok(signature)) = (
                ed25519_dalek::VerifyingKey::from_bytes(&device.ed25519),
                Signature::from_slice(&device_sig),
            ) else {
                return err(CtrlError::BindSigBad);
            };
            if vk.verify(&sig_bytes, &signature).is_err() {
                return err(CtrlError::BindSigBad);
            }
            match net
                .register_device(&user, device.x25519, device.ed25519, &device.hostname)
                .await
            {
                Ok(row) => {
                    // A failed SR-SIG1 public key registration must be visible
                    // (review item 6: no silent success allowed) —— the device
                    // row exists but the user's verification key is missing ⇒
                    // every later SR-SIG1 state change would SigBad. Return an
                    // explicit error + a log trail (the response surface has
                    // no alert field; the wire format stays unchanged —— the
                    // client can retry another account path by the semantics
                    // of the unconsumed bind_token).
                    if let Err(e) = net.add_user_sig_key(&user, sr_sig_pub).await {
                        eprintln!(
                            "flock-server: key-bind: device registered but SR-SIG1 public key registration failed (user={user}): {e}"
                        );
                        return err(CtrlError::Internal);
                    }
                    CtrlResponse::KeyBound {
                        device_id: DeviceId::from_ed25519(&vk).0,
                        vip: row.vip,
                    }
                }
                // M7 re-register: key-binding again with the same device
                // (same key set) ⇒ update the hostname, VIP unchanged (a
                // same-device reconnect within the window keeps the same IP,
                // §7-M7). The bind_token is consumed and the device signature
                // verified —— the same authorization strength as a first
                // registration. Dispatched as the **DeviceExists variant**
                // (eliminating the `contains("already registered")` string
                // contract) + owner check: target row owner != ticket user ⇒
                // NotAuthorized (changing another user's device hostname
                // cross-account is rejected —— the device signature only
                // proves device-side possession, not account ownership).
                Err(NetError::DeviceExists) => {
                    let dev_id = DeviceId::from_ed25519(&vk);
                    match net.device_row(&dev_id).await {
                        Some(row) if row.owner != user => {
                            eprintln!(
                                "flock-server: key-bind(re): cross-owner rebind rejected (device owner={} != ticket user={user})",
                                row.owner
                            );
                            return err(CtrlError::NotAuthorized);
                        }
                        Some(_) => {}
                        None => return err(CtrlError::DeviceUnknown),
                    }
                    match net.set_hostname(&dev_id, &device.hostname).await {
                        Ok(row) => {
                            if let Err(e) = net.add_user_sig_key(&user, sr_sig_pub).await {
                                eprintln!(
                                    "flock-server: key-bind(re): SR-SIG1 public key registration failed (user={user}): {e}"
                                );
                                return err(CtrlError::Internal);
                            }
                            CtrlResponse::KeyBound {
                                device_id: dev_id.0,
                                vip: row.vip,
                            }
                        }
                        Err(e) => state_err(e),
                    }
                }
                Err(e) => state_err(e),
            }
        }

        // —— State changes with SR-SIG1 + ticket + nonce ——
        CtrlRequest::TicketRenew { ticket, auth } => {
            let Some(ticket) = ticket else {
                return err(CtrlError::TicketMissing);
            };
            match core
                .guard
                .admit_state_change(
                    net,
                    &ctx.device,
                    &ticket,
                    &auth,
                    PATH_TICKET_RENEW,
                    b"",
                    now_unix as i64,
                )
                .await
            {
                Ok(user) => {
                    let epoch = net.epoch().await;
                    let t = match core.guard.authority.issue(
                        &user,
                        ctx.device,
                        epoch,
                        now_unix,
                        core.cfg.ticket_ttl_secs,
                    ) {
                        Ok(t) => t,
                        Err(m) => {
                            eprintln!("flock-server: ticket issue: {m}");
                            return err(CtrlError::Internal);
                        }
                    };
                    CtrlResponse::TicketRenewed { ticket: t }
                }
                Err(code) => err(code),
            }
        }
        CtrlRequest::RedeemInvite {
            ticket,
            auth,
            invite_b64,
            username,
            device,
        } => {
            let Some(ticket) = ticket else {
                return err(CtrlError::TicketMissing);
            };
            let body = redeem_body(&username, &device);
            match core
                .guard
                .admit_state_change(
                    net,
                    &ctx.device,
                    &ticket,
                    &auth,
                    PATH_REDEEM_INVITE,
                    &body,
                    now_unix as i64,
                )
                .await
            {
                Ok(_) => {
                    let Ok(invite_bytes) = b64_decode(&invite_b64) else {
                        return err(CtrlError::InviteBadSig);
                    };
                    // Cluster identity pinning: the Sync form is
                    // self-attested by the state machine's bootstrap
                    // identity; single-server compares against the in-store
                    // root.
                    match net
                        .redeem_invite(RedeemRequest {
                            invite_bytes: &invite_bytes,
                            username: &username,
                            device_x25519: device.x25519,
                            device_ed25519: device.ed25519,
                            hostname: &device.hostname,
                            expected_root_pub: *core.identity.root_pub.as_bytes(),
                            expected_cluster_id: core.identity.cluster_id.0,
                            now_unix,
                        })
                        .await
                    {
                        Ok(out) => CtrlResponse::Redeemed {
                            device_id: out.device_id,
                            vip: out.vip,
                        },
                        Err(e) => err(redeem_err_code(&e)),
                    }
                }
                Err(code) => err(code),
            }
        }
        CtrlRequest::DeviceOp { ticket, auth, op } => {
            let Some(ticket) = ticket else {
                return err(CtrlError::TicketMissing);
            };
            let body = postcard::to_allocvec(&op).unwrap_or_default();
            let user = match core
                .guard
                .admit_state_change(
                    net,
                    &ctx.device,
                    &ticket,
                    &auth,
                    PATH_DEVICE_OP,
                    &body,
                    now_unix as i64,
                )
                .await
            {
                Ok(u) => u,
                Err(code) => return err(code),
            };
            match op {
                DeviceOp::Revoke { device } => {
                    if !authorize_owner(net, &user, &DeviceId(device)).await {
                        return err(CtrlError::NotAuthorized);
                    }
                    match net.revoke(&DeviceId(device)).await {
                        Ok(_) => {
                            // Kill this device's local sessions (§2.2
                            // revocation propagation bound: executed locally
                            // inside the apply callback —— in multi-primary
                            // form triggered per node at the apply site via
                            // SyncHooks; executed immediately on a single
                            // node).
                            core.sessions.kill(&DeviceId(device).0);
                            CtrlResponse::Ok
                        }
                        Err(e) => state_err(e),
                    }
                }
                DeviceOp::Disable { device } => {
                    if !authorize_owner(net, &user, &DeviceId(device)).await {
                        return err(CtrlError::NotAuthorized);
                    }
                    match net.disable(&DeviceId(device)).await {
                        Ok(_) => {
                            core.sessions.kill(&DeviceId(device).0);
                            CtrlResponse::Ok
                        }
                        Err(e) => state_err(e),
                    }
                }
                DeviceOp::Enable { device } => {
                    if !authorize_owner(net, &user, &DeviceId(device)).await {
                        return err(CtrlError::NotAuthorized);
                    }
                    match net.enable(&DeviceId(device)).await {
                        Ok(()) => CtrlResponse::Ok,
                        Err(e) => state_err(e),
                    }
                }
                DeviceOp::List => {
                    let rows = net
                        .devices_of(&user)
                        .await
                        .into_iter()
                        .map(|(id, row)| DeviceRowWire {
                            device_id: id.0,
                            owner: row.owner,
                            vip: row.vip,
                            status: match row.status {
                                crate::netstate::DeviceStatus::Active => 1,
                                crate::netstate::DeviceStatus::Disabled => 2,
                                crate::netstate::DeviceStatus::Revoked => 3,
                                crate::netstate::DeviceStatus::Expired => 4,
                            },
                        })
                        .collect();
                    CtrlResponse::DeviceList { rows }
                }
            }
        }

        // —— Directory pull (read-only; the root-signed directory, §1.3.3f) ——
        CtrlRequest::DirPull { since_version } => {
            let dir = core.build_directory();
            if dir.dir_version == since_version {
                return CtrlResponse::Directory {
                    dir_version: dir.dir_version,
                    bytes: Vec::new(),
                };
            }
            CtrlResponse::Directory {
                dir_version: dir.dir_version,
                bytes: dir.to_bytes(),
            }
        }

        // —— M7: the member roster (ticket-protected; ticket verification
        //    precedes data assembly, §7-M7.4) ——
        CtrlRequest::PeerListPull { ticket } => {
            let Some(ticket) = ticket else {
                return err(CtrlError::TicketMissing);
            };
            // Contract order: roster assembly is **never touched** before the
            // ticket (signature+TTL+epoch+device state) passes —— a bad
            // ticket ⇒ TicketBad with the assembly counter unmoved (tests
            // assert this order).
            if let Err(r) = core
                .guard
                .ticket_principal(net, &ctx.device, &ticket, now_unix)
                .await
            {
                eprintln!("flock-server: peer-list ticket rejected: {r}");
                return err(CtrlError::TicketBad);
            }
            CtrlResponse::PeerList {
                peers: assemble_roster(core).await,
            }
        }
    }
}

// ============================================================================
// M7: roster assembly (§7-M7.4 —— registry snapshot ⋈ local lease view; VIP
// ascending)
// ============================================================================

/// Cumulative roster assemblies (diagnostics/test surface —— the probe for
/// the "ticket first" order assertion: a bad ticket ⇒ the counter stays
/// put).
pub fn roster_assemblies() -> u64 {
    ROSTER_ASSEMBLIES.load(std::sync::atomic::Ordering::Relaxed)
}

static ROSTER_ASSEMBLIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Assemble the roster: registry snapshot (**locally applied view** —— the
/// two-level-read cache tier suffices, allowing a follower view seconds
/// stale) ⋈ local lease view (online verdict + last_seen + EWMA) + Server
/// entries.
///
/// - Device entries: only `status == Active` rows (Disabled/Revoked/Expired
///   excluded —— the roster = current members; auditing goes through
///   DeviceList);
/// - Server entries: multi-primary = the Raft server_keys local view (vip) +
///   the root-signed directory endpoint (hostname) + each server's
///   self-published lease (online/traffic); single-server = one local entry
///   (vip = cfg.vip, hostname = advertise_endpoint, traffic = the local
///   TrafficMeter);
/// - Output ascending by VIP.
pub async fn assemble_roster(core: &ServerCore) -> Vec<PeerInfo> {
    ROSTER_ASSEMBLIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut out: Vec<PeerInfo> = Vec::new();
    match &core.net {
        NetBackend::Single(store) => {
            for (id, row) in store.devices_all() {
                if row.status != crate::netstate::DeviceStatus::Active {
                    continue;
                }
                let (tx, rx, last_seen) = core.traffic.stats(&row.vip).unwrap_or((0, 0, 0));
                out.push(PeerInfo {
                    vip: row.vip,
                    hostname: row.hostname,
                    owner: row.owner,
                    kind: PeerKind::Device,
                    online: core.sessions.online(&id.0) > 0,
                    last_seen_unix: last_seen,
                    tx_bps: tx,
                    rx_bps: rx,
                });
            }
            // The server itself (the single Server entry in single-server
            // form).
            let (stx, srx, sls) = core
                .traffic
                .stats(crate::dataplane::SERVER_TRAFFIC_KEY)
                .unwrap_or((0, 0, 0));
            out.push(PeerInfo {
                vip: core.cfg.vip.octets(),
                hostname: core.cfg.advertise_endpoint.clone(),
                owner: flock_sync::node::node_id_of(&core.identity.server_id).to_string(),
                kind: PeerKind::Server,
                online: true,
                last_seen_unix: sls,
                tx_bps: stx,
                rx_bps: srx,
            });
        }
        #[cfg(feature = "multi-primary")]
        NetBackend::Sync(s) => {
            let node = &s.node;
            let leases = node.lease();
            for (dev, row) in node.devices_snapshot() {
                if row.status != crate::netstate::DeviceStatus::Active {
                    continue;
                }
                let st = leases.peer_stats(&dev);
                out.push(PeerInfo {
                    vip: row.vip,
                    hostname: row.hostname,
                    owner: row.owner,
                    kind: PeerKind::Device,
                    online: st.is_some_and(|x| x.online),
                    last_seen_unix: st.map_or(0, |x| x.last_seen_unix),
                    tx_bps: st.map_or(0, |x| x.tx_ewma),
                    rx_bps: st.map_or(0, |x| x.rx_ewma),
                });
            }
            // Server entries: server_keys (the root-signed registered mesh
            // VIP) + directory endpoint (hostname) + self-published leases
            // (online/traffic synced via the existing gossip).
            let dir_hosts: std::collections::BTreeMap<u64, String> = node
                .directory()
                .current()
                .map(|d| {
                    d.servers
                        .iter()
                        .map(|e| {
                            (
                                flock_sync::node::node_id_of(&e.server_id),
                                e.relay_endpoint.clone(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            for (node_id, entry) in node.server_keys_snapshot() {
                let st = leases.peer_stats(&flock_sync::lease::server_self_device_id(node_id));
                out.push(PeerInfo {
                    vip: entry.vip,
                    hostname: dir_hosts
                        .get(&node_id)
                        .cloned()
                        .unwrap_or_else(|| flock_sync::HOSTNAME_UNKNOWN.to_string()),
                    owner: node_id.to_string(),
                    kind: PeerKind::Server,
                    online: st.is_some_and(|x| x.online),
                    last_seen_unix: st.map_or(0, |x| x.last_seen_unix),
                    tx_bps: st.map_or(0, |x| x.tx_ewma),
                    rx_bps: st.map_or(0, |x| x.rx_ewma),
                });
            }
        }
    }
    out.sort_by_key(|p| p.vip);
    out
}

async fn owner_of_device(net: &NetBackend, device: &DeviceId) -> Option<String> {
    net.device_row(device).await.map(|r| r.owner)
}

/// Owner check (users may only operate their own devices).
async fn authorize_owner(net: &NetBackend, user: &str, device: &DeviceId) -> bool {
    net.device_row(device)
        .await
        .map(|r| r.owner == user)
        .unwrap_or(false)
}

/// The SR-SIG1-signed body of RedeemInvite (byte-identical to the client's
/// construction).
fn redeem_body(username: &str, device: &DevicePubs) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct RedeemBody<'a> {
        username: &'a str,
        device: &'a DevicePubs,
    }
    postcard::to_allocvec(&RedeemBody { username, device }).unwrap_or_default()
}

fn b64_decode(s: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine as _;
    let t = s.trim();
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(t))
        .map_err(|_| ())
}

/// The expected-identity input of [`client_login_finish_anchored`] (the
/// expected identity comes from the pinned ServerPin).
#[derive(Debug, Clone)]
pub struct AnchorLoginExpectation {
    pub server_id: [u8; 16],
    pub identity_pub: ed25519_dalek::VerifyingKey,
    pub bind_token: [u8; 16],
    pub anchor_sig: Vec<u8>,
}

/// Client-side anchored login-finish wrapper (shared by tests/smoke).
pub fn client_login_finish_anchored(
    state: opaque_ke::ClientLogin<flock_protocol::pake::Suite>,
    pw: &str,
    user: &str,
    ke2_b64: &str,
    expect: AnchorLoginExpectation,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut sig = [0u8; 64];
    if expect.anchor_sig.len() != 64 {
        return Err("anchor sig length".into());
    }
    sig.copy_from_slice(&expect.anchor_sig);
    let exp = AnchorExpectation {
        server_id: expect.server_id,
        identity_pub: expect.identity_pub,
        bind_token: expect.bind_token,
    };
    login_finish_anchored(state, pw, user, ke2_b64, PakeProfile::default(), &exp, &sig)
}

// Avoids an unused-import warning (x25519_dalek is used only at the
// device-public-key conversion via type inference).
const _: fn([u8; 32]) -> x25519_dalek::PublicKey = x25519_dalek::PublicKey::from;

// ============================================================================
// Unit tests: contract order (ticket before nonce accounting)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::NetBackend;
    use crate::netstate::{DeviceStatus, StateStore};
    use crate::ticket::{TicketIssuer, TicketWire};
    use flock_protocol::session::{DeviceRecord, LookupVerdict};
    use flock_protocol::x25519_dalek::PublicKey;

    fn dummy_auth(user: &str, nonce: &str, now: i64) -> SrAuth {
        use base64::Engine as _;
        SrAuth {
            header: format!(
                "SR-SIG1 {user}:{now}:{nonce}:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64])
            ),
        }
    }

    fn local(t: TicketWire) -> crate::ticket::SignedTicket {
        match t {
            TicketWire::Local(s) => s,
            TicketWire::Sync(_) => panic!("local authority"),
        }
    }

    /// Bad ticket + fresh nonce ⇒ rejected and the nonce not recorded; the
    /// same nonce with a valid ticket reaches the next layer (order proof).
    #[tokio::test]
    async fn ticket_checked_before_nonce_accounting() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(StateStore::open(&dir.path().join("n.redb")).unwrap());
        let vk = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key();
        store
            .register_device("alice", [1; 32], *vk.as_bytes(), "")
            .unwrap();
        let device = DeviceId::from_ed25519(&vk);

        let guard = CtrlGuard::new(TicketAuthority::Local(Box::new(TicketIssuer::from_seed(
            [9u8; 32],
        ))));
        let net = NetBackend::Single(store.clone());
        let now = 10_000i64;
        let good = local(
            guard
                .authority
                .issue("alice", device, 0, now as u64, 60)
                .unwrap(),
        );
        let mut bad = good.clone();
        bad.exp += 100; // tamper a covered field ⇒ BadSignature

        // ① Bad ticket + fresh nonce ⇒ TicketBad, and the nonce is not
        //    recorded.
        let e = guard
            .admit_state_change(
                &net,
                &device,
                &TicketWire::Local(bad),
                &dummy_auth("alice", "n1", now),
                PATH_TICKET_RENEW,
                b"",
                now,
            )
            .await
            .unwrap_err();
        assert_eq!(e, CtrlError::TicketBad, "bad ticket rejected");
        assert!(
            !guard.nonces.contains("alice", "n1"),
            "fresh nonce not recorded (contract: ticket before nonce accounting)"
        );
        // ② The same nonce with a valid ticket ⇒ reaches the SR-SIG1 layer
        //    (SigBad: no registered key) rather than TicketBad.
        let e2 = guard
            .admit_state_change(
                &net,
                &device,
                &TicketWire::Local(good.clone()),
                &dummy_auth("alice", "n1", now),
                PATH_TICKET_RENEW,
                b"",
                now,
            )
            .await
            .unwrap_err();
        assert_eq!(
            e2,
            CtrlError::SigBad,
            "valid ticket ⇒ checking advances to the signature layer"
        );
        assert!(
            !guard.nonces.contains("alice", "n1"),
            "signature failure also not recorded"
        );
        // ③ Ticket-bound device ≠ session device ⇒ rejected.
        let other = DeviceId([9; 32]);
        let e3 = guard
            .admit_state_change(
                &net,
                &other,
                &TicketWire::Local(good.clone()),
                &dummy_auth("alice", "n2", now),
                PATH_TICKET_RENEW,
                b"",
                now,
            )
            .await
            .unwrap_err();
        assert_eq!(e3, CtrlError::TicketBad);
        // ④ Session device already revoked ⇒ rejected at the ticket layer
        //    (DeviceNotActive → TicketBad).
        store.revoke(&device).unwrap();
        let e4 = guard
            .admit_state_change(
                &net,
                &device,
                &TicketWire::Local(good),
                &dummy_auth("alice", "n3", now),
                PATH_TICKET_RENEW,
                b"",
                now,
            )
            .await
            .unwrap_err();
        assert_eq!(
            e4,
            CtrlError::TicketBad,
            "ticket rejected after revocation (epoch/device state)"
        );
        assert_eq!(
            store.device_row(&device).unwrap().status,
            DeviceStatus::Revoked
        );
        let _ = LookupVerdict::Active(DeviceRecord {
            device_x25519: PublicKey::from([0u8; 32]),
            device_ed25519: vk,
        });
    }

    // ------------------------------------------------------------------
    // M7 (§7-M7.4): roster assembly three-states + Server entries + the
    // ticket-first order
    // ------------------------------------------------------------------

    fn m7_cfg(state_dir: std::path::PathBuf) -> crate::config::ServerConfig {
        crate::config::ServerConfig {
            state_dir,
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
            vip: "100.64.0.1".parse().unwrap(),
            frp: None,
            sync: None,
            webui: Default::default(),
        }
    }

    fn store_of(core: &crate::server::ServerCore) -> std::sync::Arc<StateStore> {
        match &core.net {
            NetBackend::Single(s) => s.clone(),
            #[cfg(feature = "multi-primary")]
            _ => panic!("single"),
        }
    }

    /// Three states (online/offline/expired) + Server entry + VIP ascending +
    /// the hostname default chain.
    #[tokio::test]
    async fn roster_three_states_and_server_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = crate::server::ServerCore::open_or_init(m7_cfg(dir.path().to_path_buf()))
            .expect("core");
        let store = store_of(&core);

        let vk_on = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let vk_off = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let vk_exp = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let row_on = store
            .register_device(
                "alice",
                [1; 32],
                *vk_on.verifying_key().as_bytes(),
                "online-pad",
            )
            .unwrap();
        let row_off = store
            .register_device("bob", [2; 32], *vk_off.verifying_key().as_bytes(), "")
            .unwrap();
        let row_exp = store
            .register_device(
                "carol",
                [3; 32],
                *vk_exp.verifying_key().as_bytes(),
                "expired-pad",
            )
            .unwrap();

        // Online device: session registered + traffic fed (two EWMA folds
        // converge to non-zero).
        let id_on = DeviceId::from_ed25519(&vk_on.verifying_key());
        let _kill = core.sessions.register(id_on.0);
        let mut ms = 1_000_000u64;
        for _ in 0..3 {
            core.traffic.note_tx(&row_on.vip, 8192);
            core.traffic.note_rx(&row_on.vip, 4096);
            ms += 1000;
            core.traffic.tick(ms);
        }
        // Expired device.
        let id_exp = DeviceId::from_ed25519(&vk_exp.verifying_key());
        store.expire(&id_exp, 1_700_000_000).unwrap();

        let peers = assemble_roster(&core).await;
        // Three entries: two Active devices + this server; Expired excluded.
        assert_eq!(peers.len(), 3, "{peers:?}");
        // VIP ascending (server .1 < devices .2/.3).
        let vips: Vec<[u8; 4]> = peers.iter().map(|p| p.vip).collect();
        let mut sorted = vips.clone();
        sorted.sort();
        assert_eq!(vips, sorted, "VIP ascending");

        let srv = peers
            .iter()
            .find(|p| p.kind == PeerKind::Server)
            .expect("Server entry");
        assert_eq!(srv.vip, [100, 64, 0, 1]);
        assert_eq!(
            srv.hostname, "127.0.0.1:9443",
            "single-server Server hostname = advertise"
        );
        assert!(
            !srv.owner.is_empty(),
            "owner = carried by server_id (node number)"
        );
        assert!(
            srv.online,
            "the server itself is always online (local view)"
        );

        let p_on = peers.iter().find(|p| p.vip == row_on.vip).unwrap();
        assert_eq!(p_on.hostname, "online-pad");
        assert_eq!(p_on.owner, "alice");
        assert!(p_on.online, "session on record ⇒ online");
        assert!(
            p_on.tx_bps > 0 && p_on.rx_bps > 0,
            "EWMA non-zero (tx={} rx={})",
            p_on.tx_bps,
            p_on.rx_bps
        );
        assert!(p_on.last_seen_unix > 0);

        let p_off = peers.iter().find(|p| p.vip == row_off.vip).unwrap();
        assert!(!p_off.online, "no session ⇒ offline");
        assert_eq!(p_off.tx_bps, 0, "never counted traffic");
        assert_eq!(
            p_off.hostname,
            flock_sync::HOSTNAME_UNKNOWN,
            "empty-hostname default"
        );

        assert!(
            peers.iter().all(|p| p.vip != row_exp.vip),
            "Expired devices do not enter the roster"
        );
    }

    /// Ticket-first order: no ticket ⇒ TicketMissing; a bad ticket ⇒
    /// TicketBad with the **assembly counter unmoved** (bad ticket + valid
    /// roster data ⇒ rejected —— the data assembly never happened); a good
    /// ticket ⇒ PeerList + counter +1.
    #[tokio::test]
    async fn peer_list_pull_ticket_checked_before_assembly() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = crate::server::ServerCore::open_or_init(m7_cfg(dir.path().to_path_buf()))
            .expect("core");
        let store = store_of(&core);
        let vk = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        store
            .register_device("dave", [7; 32], *vk.verifying_key().as_bytes(), "")
            .unwrap();
        let device = DeviceId::from_ed25519(&vk.verifying_key());
        let now = flock_protocol::trust::now_unix();
        let good = core
            .guard
            .authority
            .issue("dave", device, core.net.epoch().await, now, 60)
            .expect("ticket");
        let mut ctx = ConnCtx {
            device,
            pending_login: None,
        };

        // ① No ticket ⇒ TicketMissing.
        let r = dispatch(&core, &mut ctx, CtrlRequest::PeerListPull { ticket: None }).await;
        assert!(
            matches!(
                r,
                CtrlResponse::Err {
                    code: CtrlError::TicketMissing,
                    ..
                }
            ),
            "{r:?}"
        );

        // ② Bad ticket (tampered exp ⇒ BadSignature) ⇒ TicketBad with the
        //    assembly counter unmoved (order proof).
        let mut bad = match &good {
            TicketWire::Local(s) => {
                let mut c = s.clone();
                c.exp += 100;
                TicketWire::Local(c)
            }
            TicketWire::Sync(_) => panic!("single authority"),
        };
        let before = roster_assemblies();
        let r = dispatch(
            &core,
            &mut ctx,
            CtrlRequest::PeerListPull {
                ticket: Some(bad.clone()),
            },
        )
        .await;
        assert!(
            matches!(
                r,
                CtrlResponse::Err {
                    code: CtrlError::TicketBad,
                    ..
                }
            ),
            "{r:?}"
        );
        assert_eq!(
            roster_assemblies(),
            before,
            "bad ticket ⇒ roster assembly never happened (ticket first)"
        );

        // ③ Good ticket ⇒ PeerList (with the Server entry) + counter +1.
        bad = good.clone();
        let r = dispatch(
            &core,
            &mut ctx,
            CtrlRequest::PeerListPull { ticket: Some(bad) },
        )
        .await;
        match r {
            CtrlResponse::PeerList { peers } => {
                assert!(!peers.is_empty());
                assert!(peers.iter().any(|p| p.kind == PeerKind::Server));
            }
            other => panic!("peer list: {other:?}"),
        }
        assert_eq!(
            roster_assemblies(),
            before + 1,
            "only a good ticket assembles"
        );
    }

    /// M8 (§7-M8.3): the disabled check of control-flow LoginBegin ——
    /// disabled ⇒ NotAuthorized (the login chain breaks at begin, never
    /// entering OPAQUE); restored after enable.
    #[tokio::test]
    async fn login_begin_rejects_disabled_user() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = crate::server::ServerCore::open_or_init(m7_cfg(dir.path().to_path_buf()))
            .expect("core");
        let store = store_of(&core);
        // dave's session device (owner surface).
        let vk = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        store
            .register_device("dave", [11; 32], *vk.verifying_key().as_bytes(), "")
            .unwrap();
        let device = DeviceId::from_ed25519(&vk.verifying_key());
        // Create the account (RegisterDevice auto-creates an empty one) + set
        // a password + disable.
        store.set_password("dave", "rec-dave", 0).unwrap();
        store.set_user_disabled("dave", true).unwrap();

        let mut ctx = ConnCtx {
            device,
            pending_login: None,
        };
        let mut ke1 = String::new();
        // An invalid ke1 does not matter —— the check precedes OPAQUE.
        ke1.push_str("AAAA");
        let resp = dispatch(
            &core,
            &mut ctx,
            CtrlRequest::LoginBegin {
                user: "dave".into(),
                ke1_b64: ke1,
            },
        )
        .await;
        assert!(
            matches!(
                &resp,
                CtrlResponse::Err {
                    code: CtrlError::NotAuthorized,
                    ..
                }
            ),
            "disabled user's login begin rejected: {resp:?}"
        );
        assert!(
            ctx.pending_login.is_none(),
            "never entered the OPAQUE in-flight state"
        );

        // Restored after enable (a bad ke1 takes LoginFailed —— the check
        // advanced to the OPAQUE layer).
        store.set_user_disabled("dave", false).unwrap();
        let resp = dispatch(
            &core,
            &mut ctx,
            CtrlRequest::LoginBegin {
                user: "dave".into(),
                ke1_b64: "AAAA".into(),
            },
        )
        .await;
        assert!(
            matches!(
                &resp,
                CtrlResponse::Err {
                    code: CtrlError::LoginFailed,
                    ..
                }
            ),
            "after restore it advances to OPAQUE (bad ke1 ⇒ LoginFailed): {resp:?}"
        );
    }

    /// The owner check of KeyBind re-register (DeviceExists variant
    /// dispatch): re-binding another user's device cross-account (changing
    /// the hostname) ⇒ NotAuthorized with the original row untouched;
    /// re-registering oneself ⇒ hostname updated + VIP unchanged.
    #[tokio::test]
    async fn keybind_reregister_rejects_cross_owner_hostname_change() {
        use ed25519_dalek::Signer as _;

        let dir = tempfile::tempdir().unwrap();
        let (core, _) = crate::server::ServerCore::open_or_init(m7_cfg(dir.path().to_path_buf()))
            .expect("core");
        let store = store_of(&core);

        // alice's device (registered); bob's session device (the ticket
        // principal).
        let vk_alice_dev = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let row_a = store
            .register_device(
                "alice",
                [5; 32],
                *vk_alice_dev.verifying_key().as_bytes(),
                "alice-pad",
            )
            .unwrap();
        let vk_bob = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        store
            .register_device("bob", [6; 32], *vk_bob.verifying_key().as_bytes(), "")
            .unwrap();
        // Variant contract: re-registering the same keys ⇒
        // NetError::DeviceExists (not an InvalidState string).
        assert!(matches!(
            store
                .register_device(
                    "anyone",
                    [5; 32],
                    *vk_alice_dev.verifying_key().as_bytes(),
                    ""
                )
                .unwrap_err(),
            crate::netstate::NetError::DeviceExists
        ));

        let alice_dev = DeviceId::from_ed25519(&vk_alice_dev.verifying_key());
        let bob_dev = DeviceId::from_ed25519(&vk_bob.verifying_key());
        let now = flock_protocol::trust::now_unix();
        let epoch = core.net.epoch().await;
        let ticket_bob = match core
            .guard
            .authority
            .issue("bob", bob_dev, epoch, now, 60)
            .expect("bob ticket")
        {
            TicketWire::Local(t) => t,
            other => panic!("local authority: {other:?}"),
        };

        // bob re-binding with alice's device public keys: the device
        // signature **can pass** (signed by alice's device key over bob's
        // canonical —— proof of possession is device-side), but the target
        // row owner=alice != ticket user=bob ⇒ NotAuthorized, the hostname
        // untampered.
        let bind_token = [0xA7u8; 16];
        let pubs = DevicePubs {
            x25519: [5; 32],
            ed25519: *vk_alice_dev.verifying_key().as_bytes(),
            hostname: "hijacked".into(),
        };
        let canon = keybind_canonical(
            &core.identity.cluster_id.0,
            "bob",
            &bind_token,
            &pubs,
            &[9; 32],
        );
        let mut ctx = ConnCtx {
            device: bob_dev,
            pending_login: None,
        };
        let resp = dispatch(
            &core,
            &mut ctx,
            CtrlRequest::KeyBind {
                ticket: TicketWire::Local(ticket_bob),
                bind_token,
                device: pubs,
                sr_sig_pub: [9; 32],
                device_sig: vk_alice_dev.sign(&canon).to_bytes().to_vec(),
            },
        )
        .await;
        assert!(
            matches!(
                &resp,
                CtrlResponse::Err {
                    code: CtrlError::NotAuthorized,
                    ..
                }
            ),
            "cross-owner hostname change rejected: {resp:?}"
        );
        assert_eq!(
            store.device_row(&alice_dev).unwrap().hostname,
            "alice-pad",
            "the original row is untampered"
        );

        // Control: re-registering oneself (alice's ticket + alice's device)
        // ⇒ hostname updated + VIP unchanged (the positive path of the
        // DeviceExists dispatch).
        let ticket_alice = match core
            .guard
            .authority
            .issue("alice", alice_dev, epoch, now, 60)
            .expect("alice ticket")
        {
            TicketWire::Local(t) => t,
            other => panic!("local authority: {other:?}"),
        };
        let bind_token2 = [0xB7u8; 16];
        let pubs2 = DevicePubs {
            x25519: [5; 32],
            ed25519: *vk_alice_dev.verifying_key().as_bytes(),
            hostname: "renamed".into(),
        };
        let canon2 = keybind_canonical(
            &core.identity.cluster_id.0,
            "alice",
            &bind_token2,
            &pubs2,
            &[9; 32],
        );
        let mut ctx2 = ConnCtx {
            device: alice_dev,
            pending_login: None,
        };
        let resp = dispatch(
            &core,
            &mut ctx2,
            CtrlRequest::KeyBind {
                ticket: TicketWire::Local(ticket_alice),
                bind_token: bind_token2,
                device: pubs2,
                sr_sig_pub: [9; 32],
                device_sig: vk_alice_dev.sign(&canon2).to_bytes().to_vec(),
            },
        )
        .await;
        match resp {
            CtrlResponse::KeyBound { device_id, vip } => {
                assert_eq!(device_id, alice_dev.0);
                assert_eq!(vip, row_a.vip, "re-register keeps the VIP (§7-M7)");
            }
            other => panic!("self re-register: {other:?}"),
        }
        assert_eq!(store.device_row(&alice_dev).unwrap().hostname, "renamed");
    }
}
