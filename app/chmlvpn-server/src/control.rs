//! 控制流（docs/design.md §2.2 / §3.11：yamux 控制流、postcard 消息、版本化）。
//!
//! 承载：OPAQUE 登录（`anchor`：服务端身份签名覆盖 SERVER_ID‖user‖ke2‖bind_token）→
//! 会话票据签发（TTL、revocation_epoch）→ key-bind（设备公钥登记）→ 设备注册表操作 →
//! SR-SIG1 请求验签 → dir_pull（根签 ClusterDirectory 下发）。
//!
//! # 票据强制契约（§2.2，接口契约级）
//!
//! 所有受 SR-SIG1 保护的**状态变更**请求必须携带有效票据；[`CtrlGuard::admit_state_change`]
//! 的校验顺序 = **票据（签名+TTL+epoch+吊销）→ SR-SIG1 验签 → nonce 记账**——票据/签名
//! 失败时 nonce **不入账**（`ticket.rs::tests` + `tests/control_flow.rs::ticket_contract_*`
//! 断言该顺序：错误票据 + 全新 nonce ⇒ 拒且不记账）。
//!
//! # 帧格式
//!
//! 控制流 = 隧道内首条 yamux 流（客户端 `open_stream(Prio::Control)`；服务端 accept 首流）。
//! 每条消息 = `[u32 LE len][postcard CtrlRequest/CtrlResponse]`。

use chml_protocol::opaque_ke;
use chml_protocol::pake::{
    anchor_sign, login_finish_anchored, server_login_finish, server_login_start, server_reg_start,
    AnchorExpectation, Profile as PakeProfile,
};
use chml_protocol::rand;
use chml_protocol::session::DeviceId;
use chml_protocol::sig;
use chml_protocol::{ed25519_dalek, x25519_dalek};
use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};

use crate::netstate::{NetError, NetState, RedeemError, RedeemRequest, StateStore};
use crate::server::ServerCore;
use crate::ticket::{NonceLedger, SignedTicket, TicketIssuer};

/// 控制协议版本（Hello 交换；不匹配即拒——版本化，§3.11）。
pub const CTRL_PROTO_VERSION: u32 = 1;
/// SR-SIG1 canonical 的 method 槽（控制面统一方法名；path 区分操作）。
pub const CTRL_METHOD: &str = "CTRL";
/// 各 SR-SIG1 保护操作的 path（进 canonical 七字段，§1.3.2 线上格式不变）。
pub const PATH_TICKET_RENEW: &str = "/ticket-renew";
pub const PATH_REDEEM_INVITE: &str = "/redeem-invite";
pub const PATH_DEVICE_OP: &str = "/device-op";
/// key-bind 设备签名域分离标签（公钥经登录态登记，受服务端身份签名覆盖的 bind_token 佐证）。
pub const KEYBIND_LABEL: &[u8] = b"chmlvpn-server/control/key-bind/v1";

/// 单条控制消息上限（防御性；远小于记录层 1MiB 上限）。
pub const MAX_CTRL_MSG: usize = 256 * 1024;

// ============================================================================
// 线上消息（postcard）
// ============================================================================

/// 设备静态公钥集（key-bind/redeem 携带）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePubs {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
}

/// SR-SIG1 授权头（`SR-SIG1 user:ts:nonce:sig_b64url`，§1.3.2 逐字节同格式）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrAuth {
    pub header: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceOp {
    Revoke {
        device: [u8; 32],
    },
    Disable {
        device: [u8; 32],
    },
    Enable {
        device: [u8; 32],
    },
    /// owner 名下设备清单（断言/诊断面）。
    List,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CtrlRequest {
    Hello {
        ver: u32,
    },
    /// OPAQUE 注册第一步（设置口令；仅账号未设口令时）。
    PwBegin {
        user: String,
        m1_b64: String,
    },
    /// OPAQUE 注册收尾（落 pass.opaque 记录）。
    PwCommit {
        record_b64: String,
        profile: u16,
    },
    LoginBegin {
        user: String,
        ke1_b64: String,
    },
    LoginFinish {
        ke3_b64: String,
    },
    /// 设备公钥登记（状态变更：需票据 + bind_token 一次性 + 设备签名）。
    KeyBind {
        ticket: SignedTicket,
        bind_token: [u8; 16],
        device: DevicePubs,
        sr_sig_pub: [u8; 32],
        device_sig: Vec<u8>,
    },
    /// 票据换发（状态变更：SR-SIG1 + 票据 + nonce； = 无票据 ⇒ TicketMissing）。
    TicketRenew {
        ticket: Option<SignedTicket>,
        auth: SrAuth,
    },
    /// 邀请兑换（状态变更：SR-SIG1 + 票据 + nonce）。
    RedeemInvite {
        ticket: Option<SignedTicket>,
        auth: SrAuth,
        invite_b64: String,
        username: String,
        device: DevicePubs,
    },
    /// 注册表操作（状态变更：SR-SIG1 + 票据 + nonce）。
    DeviceOp {
        ticket: Option<SignedTicket>,
        auth: SrAuth,
        op: DeviceOp,
    },
    /// 目录拉取（只读，无需票据；根签 ClusterDirectory，§1.3.3f）。
    DirPull {
        since_version: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CtrlResponse {
    Hello {
        ver: u32,
        cluster_id: [u8; 16],
        server_id: [u8; 16],
    },
    PwChallenge {
        m2_b64: String,
    },
    Ok,
    LoginChallenge {
        ke2_b64: String,
        bind_token: [u8; 16],
        anchor_sig: Vec<u8>,
    },
    LoginOk {
        ticket: SignedTicket,
        epoch: u64,
    },
    KeyBound {
        device_id: [u8; 32],
        vip: [u8; 4],
    },
    TicketRenewed {
        ticket: SignedTicket,
    },
    Redeemed {
        device_id: [u8; 32],
        vip: [u8; 4],
    },
    DeviceList {
        rows: Vec<DeviceRowWire>,
    },
    /// dir_version 未变 ⇒ bytes 为空（客户端保留既有目录）。
    Directory {
        dir_version: u64,
        bytes: Vec<u8>,
    },
    Err {
        code: CtrlError,
        msg: String,
    },
}

/// 注册表行的线上形态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRowWire {
    pub device_id: [u8; 32],
    pub owner: String,
    pub vip: [u8; 4],
    pub status: u8, // 1=Active 2=Disabled 3=Revoked
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtrlError {
    ProtoVersion,
    NotAuthorized,
    PasswordExists,
    LoginFailed,
    TicketMissing,
    TicketBad,
    SigFormat,
    SigStale,
    SigBad,
    NonceReplay,
    BindTokenUsed,
    BindSigBad,
    DeviceUnknown,
    InviteUsed,
    InviteRevoked,
    InviteExpired,
    InviteUnknown,
    InviteBadSig,
    UserExists,
    DeviceExists,
    IpExhausted,
    InvalidState,
    Internal,
}

impl CtrlError {
    fn msg(self) -> &'static str {
        match self {
            CtrlError::ProtoVersion => "control protocol version mismatch",
            CtrlError::NotAuthorized => "not authorized for this operation",
            CtrlError::PasswordExists => "password already set",
            CtrlError::LoginFailed => "opaque login rejected",
            CtrlError::TicketMissing => "state-changing request requires a valid ticket",
            CtrlError::TicketBad => "ticket rejected (signature/ttl/epoch/revocation)",
            CtrlError::SigFormat => "SR-SIG1 malformed",
            CtrlError::SigStale => "SR-SIG1 timestamp outside ±300s window",
            CtrlError::SigBad => "SR-SIG1 signature verification failed",
            CtrlError::NonceReplay => "nonce replayed",
            CtrlError::BindTokenUsed => "bind_token already consumed",
            CtrlError::BindSigBad => "key-bind device signature rejected",
            CtrlError::DeviceUnknown => "unknown device",
            CtrlError::InviteUsed => "invite already redeemed",
            CtrlError::InviteRevoked => "invite revoked",
            CtrlError::InviteExpired => "invite expired",
            CtrlError::InviteUnknown => "unknown invite",
            CtrlError::InviteBadSig => "invite root signature mismatch",
            CtrlError::UserExists => "username exists",
            CtrlError::DeviceExists => "device already registered",
            CtrlError::IpExhausted => "VIP pool exhausted",
            CtrlError::InvalidState => "invalid state transition",
            CtrlError::Internal => "internal error",
        }
    }
}

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
        NetError::IpExhausted => CtrlError::IpExhausted,
        NetError::Internal(_) => CtrlError::Internal,
    };
    eprintln!("chmlvpn-server: netstate: {e}");
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
// 帧编解码（futures-io 面：mux::Stream 实现的是 futures 的 AsyncRead/Write）
// ============================================================================

/// 发送一条控制消息（`[u32 LE len][postcard]`）。
pub async fn send_ctrl_msg<S: futures::io::AsyncWrite + Unpin, M: Serialize>(
    io: &mut S,
    msg: &M,
) -> std::io::Result<()> {
    use futures::io::AsyncWriteExt as _;
    let bytes = postcard::to_allocvec(msg).map_err(|e| std::io::Error::other(e.to_string()))?;
    if bytes.len() > MAX_CTRL_MSG {
        return Err(std::io::Error::other("ctrl msg too large"));
    }
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(&bytes);
    io.write_all(&frame).await?;
    io.flush().await
}

/// 接收一条控制消息。
pub async fn recv_ctrl_msg<S: futures::io::AsyncRead + Unpin, M: for<'de> Deserialize<'de>>(
    io: &mut S,
) -> std::io::Result<M> {
    use futures::io::AsyncReadExt as _;
    let mut hdr = [0u8; 4];
    io.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > MAX_CTRL_MSG {
        return Err(std::io::Error::other("ctrl frame length"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    postcard::from_bytes(&buf).map_err(|e| std::io::Error::other(e.to_string()))
}

// ============================================================================
// CtrlGuard：票据强制契约 + SR-SIG1 + nonce 记账（§2.2，接口契约级）
// ============================================================================

/// 状态变更的统一准入：**票据（签名+TTL+epoch+吊销）→ SR-SIG1 验签 → nonce 记账**。
///
/// 契约（写死、顺序有测试断言）：
/// 1. 票据缺失/无效 ⇒ 立即拒——**nonce 不入账**（错误票据 + 全新 nonce 被拒后，同一 nonce
///    仍可持有效票据走到后续校验）；等效重放窗 = min(±300s, 票据 TTL)。
/// 2. SR-SIG1：用户登记公钥（key-bind 落库）任一命中；±300s 窗；header user == 票据 user
///    且票据绑定设备 == 当前会话设备（票据绑 device，§2.2）。
/// 3. nonce 查重 + 入账（最后一步；只有前两步都过才执行）。
pub struct CtrlGuard {
    pub tickets: TicketIssuer,
    pub nonces: NonceLedger,
}

impl CtrlGuard {
    pub fn new(tickets: TicketIssuer) -> Self {
        CtrlGuard {
            tickets,
            nonces: NonceLedger::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit_state_change(
        &self,
        net: &dyn NetState,
        session_device: &DeviceId,
        ticket: &SignedTicket,
        auth: &SrAuth,
        path: &str,
        body: &[u8],
        now_unix: i64,
    ) -> Result<String, CtrlError> {
        // ① 票据（先于一切 nonce 记账——§2.2 契约序）。
        let claims = self
            .tickets
            .verify(ticket, now_unix as u64, net.epoch(), |id| net.lookup(id))
            .map_err(|r| {
                eprintln!("chmlvpn-server: ticket rejected: {r}");
                CtrlError::TicketBad
            })?;
        if claims.device != session_device.0 {
            eprintln!("chmlvpn-server: ticket device != session device");
            return Err(CtrlError::TicketBad);
        }
        // ② SR-SIG1 验签（user 公钥集来自注册表）。
        let keys = net.user_sig_pubs(&claims.user);
        let verified = sig::verify(&auth.header, &keys, CTRL_METHOD, path, body, now_unix)
            .map_err(|e| match e {
                sig::AuthError::Format => CtrlError::SigFormat,
                sig::AuthError::Stale => CtrlError::SigStale,
                sig::AuthError::BadSignature => CtrlError::SigBad,
            })?;
        if verified.user != claims.user {
            return Err(CtrlError::SigBad);
        }
        // ③ nonce 记账（查重 + 入账；仅在前两步通过后到达此处）。
        if !self
            .nonces
            .check_and_record(&verified.user, &verified.nonce, verified.ts, now_unix)
        {
            return Err(CtrlError::NonceReplay);
        }
        Ok(claims.user)
    }
}

// ============================================================================
// 服务端分发
// ============================================================================

/// 单条控制连接的会话上下文。
struct ConnCtx {
    /// 隧道对端设备（respond 已认证）。
    device: DeviceId,
    /// LoginBegin 的在途 OPAQUE 状态。
    pending_login: Option<Vec<u8>>,
}

/// 处理一条控制流直到 EOF/错误。返回 Err 仅表示 IO 层失败（业务错误走 CtrlResponse::Err）。
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
        let req: CtrlRequest = match recv_ctrl_msg(io).await {
            Ok(r) => r,
            Err(_) => return Ok(()), // EOF/坏帧：控制流结束
        };
        let resp = dispatch(core, &mut ctx, req);
        send_ctrl_msg(io, &resp).await?;
    }
}

fn dispatch(core: &ServerCore, ctx: &mut ConnCtx, req: CtrlRequest) -> CtrlResponse {
    let net: &StateStore = &core.store;
    let net_dyn: &dyn NetState = net;
    let now_unix = chml_protocol::trust::now_unix();
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

        // —— OPAQUE 注册（设置口令；授权 = 本会话设备 owner）——
        CtrlRequest::PwBegin { user, m1_b64 } => {
            if owner_of_device(net_dyn, &ctx.device).as_deref() != Some(user.as_str()) {
                return err(CtrlError::NotAuthorized);
            }
            if net.password(&user).is_some() {
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
            let Some(owner) = owner_of_device(net_dyn, &ctx.device) else {
                return err(CtrlError::NotAuthorized);
            };
            // 记录侧规范化（解码验证）。
            let canonical = match chml_protocol::pake::server_reg_canonical(&record_b64) {
                Ok(c) => c,
                Err(_) => return err(CtrlError::Internal),
            };
            match net.set_password(&owner, &canonical, profile) {
                Ok(()) => CtrlResponse::Ok,
                Err(e) => state_err(e),
            }
        }

        // —— OPAQUE 登录（anchor）→ 票据签发 ——
        CtrlRequest::LoginBegin { user, ke1_b64 } => {
            let Some(owner) = owner_of_device(net_dyn, &ctx.device) else {
                return err(CtrlError::NotAuthorized);
            };
            if owner != user {
                return err(CtrlError::NotAuthorized);
            }
            let record = net
                .password(&user)
                .and_then(|(r, _)| chml_protocol::pake::server_record_from_b64(&r).ok());
            match server_login_start(
                &mut rand::rngs::OsRng,
                &core.oprf,
                record.as_ref(),
                &ke1_b64,
                &user,
            ) {
                Ok((ke2_b64, state)) => {
                    // anchor：服务端身份签名覆盖 SERVER_ID‖user‖ke2‖bind_token（§1.3.3f）。
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
            let Some(user) = owner_of_device(net_dyn, &ctx.device) else {
                return err(CtrlError::NotAuthorized);
            };
            let epoch = net.epoch();
            let ticket = core.guard.tickets.issue(
                &user,
                ctx.device,
                epoch,
                now_unix,
                core.cfg.ticket_ttl_secs,
            );
            CtrlResponse::LoginOk { ticket, epoch }
        }

        // —— key-bind：设备公钥登记（§1.3.3f「公钥经登录态登记」）——
        CtrlRequest::KeyBind {
            ticket,
            bind_token,
            device,
            sr_sig_pub,
            device_sig,
        } => {
            // 票据（状态变更必带；含会话设备绑定检查）。
            let user = {
                match core
                    .guard
                    .tickets
                    .verify(&ticket, now_unix, net.epoch(), |id| net.lookup(id))
                {
                    Ok(c) if c.device == ctx.device.0 => c.user,
                    Ok(_) => {
                        eprintln!("chmlvpn-server: key-bind ticket bound to another device");
                        return err(CtrlError::TicketBad);
                    }
                    Err(r) => {
                        eprintln!("chmlvpn-server: key-bind ticket rejected: {r}");
                        return err(CtrlError::TicketBad);
                    }
                }
            };
            // bind_token 一次性（§2.4 线性一致查重）。
            if !net.consume_bind_token(&bind_token) {
                return err(CtrlError::BindTokenUsed);
            }
            // 设备签名（占有证明）：覆盖 cluster‖user‖bind_token‖设备公钥‖SR-SIG1 公钥。
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
            match net.register_device(&user, device.x25519, device.ed25519) {
                Ok(row) => {
                    let _ = net.add_user_sig_key(&user, sr_sig_pub);
                    CtrlResponse::KeyBound {
                        device_id: DeviceId::from_ed25519(&vk).0,
                        vip: row.vip,
                    }
                }
                Err(e) => state_err(e),
            }
        }

        // —— SR-SIG1 + 票据 + nonce 的状态变更 ——
        CtrlRequest::TicketRenew { ticket, auth } => {
            let Some(ticket) = ticket else {
                return err(CtrlError::TicketMissing);
            };
            match core.guard.admit_state_change(
                net_dyn,
                &ctx.device,
                &ticket,
                &auth,
                PATH_TICKET_RENEW,
                b"",
                now_unix as i64,
            ) {
                Ok(user) => {
                    let t = core.guard.tickets.issue(
                        &user,
                        ctx.device,
                        net.epoch(),
                        now_unix,
                        core.cfg.ticket_ttl_secs,
                    );
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
            match core.guard.admit_state_change(
                net_dyn,
                &ctx.device,
                &ticket,
                &auth,
                PATH_REDEEM_INVITE,
                &body,
                now_unix as i64,
            ) {
                Ok(_) => {
                    let Ok(invite_bytes) = b64_decode(&invite_b64) else {
                        return err(CtrlError::InviteBadSig);
                    };
                    match net.redeem_invite(RedeemRequest {
                        invite_bytes: &invite_bytes,
                        username: &username,
                        device_x25519: device.x25519,
                        device_ed25519: device.ed25519,
                        expected_root_pub: *core.identity.root_pub.as_bytes(),
                        expected_cluster_id: core.identity.cluster_id.0,
                        now_unix,
                    }) {
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
            let user = match core.guard.admit_state_change(
                net_dyn,
                &ctx.device,
                &ticket,
                &auth,
                PATH_DEVICE_OP,
                &body,
                now_unix as i64,
            ) {
                Ok(u) => u,
                Err(code) => return err(code),
            };
            match op {
                DeviceOp::Revoke { device } => {
                    if !authorize_owner(net_dyn, &user, &DeviceId(device)) {
                        return err(CtrlError::NotAuthorized);
                    }
                    match net.revoke(&DeviceId(device)) {
                        Ok(_) => {
                            // 杀本地该设备会话（§2.2 吊销传播界：apply 回调内本地执行）。
                            core.sessions.kill(&device);
                            CtrlResponse::Ok
                        }
                        Err(e) => state_err(e),
                    }
                }
                DeviceOp::Disable { device } => {
                    if !authorize_owner(net_dyn, &user, &DeviceId(device)) {
                        return err(CtrlError::NotAuthorized);
                    }
                    match net.disable(&DeviceId(device)) {
                        Ok(_) => {
                            core.sessions.kill(&device);
                            CtrlResponse::Ok
                        }
                        Err(e) => state_err(e),
                    }
                }
                DeviceOp::Enable { device } => {
                    if !authorize_owner(net_dyn, &user, &DeviceId(device)) {
                        return err(CtrlError::NotAuthorized);
                    }
                    match net.enable(&DeviceId(device)) {
                        Ok(()) => CtrlResponse::Ok,
                        Err(e) => state_err(e),
                    }
                }
                DeviceOp::List => {
                    let rows = net
                        .devices_of(&user)
                        .into_iter()
                        .map(|(id, row)| DeviceRowWire {
                            device_id: id.0,
                            owner: row.owner,
                            vip: row.vip,
                            status: match row.status {
                                crate::netstate::DeviceStatus::Active => 1,
                                crate::netstate::DeviceStatus::Disabled => 2,
                                crate::netstate::DeviceStatus::Revoked => 3,
                            },
                        })
                        .collect();
                    CtrlResponse::DeviceList { rows }
                }
            }
        }

        // —— 目录拉取（只读；根签目录，§1.3.3f）——
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
    }
}

fn owner_of_device(net: &dyn NetState, device: &DeviceId) -> Option<String> {
    net.device_row(device).map(|r| r.owner)
}

/// owner 检查（用户只能操作自己名下设备）。
fn authorize_owner(net: &dyn NetState, user: &str, device: &DeviceId) -> bool {
    net.device_row(device)
        .map(|r| r.owner == user)
        .unwrap_or(false)
}

pub fn keybind_canonical(
    cluster_id: &[u8; 16],
    user: &str,
    bind_token: &[u8; 16],
    device: &DevicePubs,
    sr_sig_pub: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(KEYBIND_LABEL.len() + 16 + 4 + user.len() + 116);
    v.extend_from_slice(KEYBIND_LABEL);
    v.extend_from_slice(cluster_id);
    v.extend_from_slice(&(user.len() as u32).to_le_bytes());
    v.extend_from_slice(user.as_bytes());
    v.extend_from_slice(bind_token);
    v.extend_from_slice(&device.x25519);
    v.extend_from_slice(&device.ed25519);
    v.extend_from_slice(sr_sig_pub);
    v
}

/// RedeemInvite 的 SR-SIG1 签名覆盖 body（与客户端构造逐字节一致）。
fn redeem_body(username: &str, device: &DevicePubs) -> Vec<u8> {
    #[derive(Serialize)]
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

/// [`client_login_finish_anchored`] 的期望身份入参（期望身份来自钉扎 ServerPin）。
#[derive(Debug, Clone)]
pub struct AnchorLoginExpectation {
    pub server_id: [u8; 16],
    pub identity_pub: ed25519_dalek::VerifyingKey,
    pub bind_token: [u8; 16],
    pub anchor_sig: Vec<u8>,
}

/// 客户端 anchor 版 login-finish 封装（tests/smoke 共用）。
pub fn client_login_finish_anchored(
    state: opaque_ke::ClientLogin<chml_protocol::pake::Suite>,
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

// 避免 unused-import 警告（x25519_dalek 仅在设备公钥转换处经由类型推断使用）。
const _: fn([u8; 32]) -> x25519_dalek::PublicKey = x25519_dalek::PublicKey::from;

// ============================================================================
// 单元测试：契约顺序（票据先于 nonce 记账）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chml_protocol::session::{DeviceRecord, LookupVerdict};
    use chml_protocol::x25519_dalek::PublicKey;

    fn dummy_auth(user: &str, nonce: &str, now: i64) -> SrAuth {
        use base64::Engine as _;
        SrAuth {
            header: format!(
                "SR-SIG1 {user}:{now}:{nonce}:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64])
            ),
        }
    }

    /// 错误票据 + 全新 nonce ⇒ 拒且 nonce 不入账；同 nonce 持有效票据走到下一层（顺序证明）。
    #[test]
    fn ticket_checked_before_nonce_accounting() {
        let dir = tempfile::tempdir().unwrap();
        let net = StateStore::open(&dir.path().join("n.redb")).unwrap();
        let vk = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key();
        net.register_device("alice", [1; 32], *vk.as_bytes())
            .unwrap();
        let device = DeviceId::from_ed25519(&vk);

        let guard = CtrlGuard::new(TicketIssuer::from_seed([9u8; 32]));
        let now = 10_000i64;
        let good = guard.tickets.issue("alice", device, 0, now as u64, 60);
        let mut bad = good.clone();
        bad.exp += 100; // 篡改覆盖字段 ⇒ BadSignature

        // ① 错误票据 + 全新 nonce ⇒ TicketBad，且 nonce 不入账。
        let e = guard
            .admit_state_change(
                &net,
                &device,
                &bad,
                &dummy_auth("alice", "n1", now),
                PATH_TICKET_RENEW,
                b"",
                now,
            )
            .unwrap_err();
        assert_eq!(e, CtrlError::TicketBad, "错误票据被拒");
        assert!(
            !guard.nonces.contains("alice", "n1"),
            "全新 nonce 未入账（契约：票据先于 nonce 记账）"
        );
        // ② 同 nonce 持有效票据 ⇒ 走到 SR-SIG1 层（SigBad：无登记公钥）而非 TicketBad。
        let e2 = guard
            .admit_state_change(
                &net,
                &device,
                &good,
                &dummy_auth("alice", "n1", now),
                PATH_TICKET_RENEW,
                b"",
                now,
            )
            .unwrap_err();
        assert_eq!(e2, CtrlError::SigBad, "有效票据 ⇒ 校验推进到签名层");
        assert!(!guard.nonces.contains("alice", "n1"), "签名失败亦不入账");
        // ③ 票据绑定设备 ≠ 会话设备 ⇒ 拒。
        let other = DeviceId([9; 32]);
        let e3 = guard
            .admit_state_change(
                &net,
                &other,
                &good,
                &dummy_auth("alice", "n2", now),
                PATH_TICKET_RENEW,
                b"",
                now,
            )
            .unwrap_err();
        assert_eq!(e3, CtrlError::TicketBad);
        // ④ 会话设备已吊销 ⇒ 票据层拒（DeviceNotActive → TicketBad）。
        net.revoke(&device).unwrap();
        let e4 = guard
            .admit_state_change(
                &net,
                &device,
                &good,
                &dummy_auth("alice", "n3", now),
                PATH_TICKET_RENEW,
                b"",
                now,
            )
            .unwrap_err();
        assert_eq!(e4, CtrlError::TicketBad, "吊销后票据被拒（epoch/设备态）");
        let _ = (LookupVerdict::Active(DeviceRecord {
            device_x25519: PublicKey::from([0u8; 32]),
            device_ed25519: vk,
        }),);
    }
}
