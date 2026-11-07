//! 控制流（docs/design.md §2.2 / §3.11：yamux 控制流、postcard 消息、版本化）。
//!
//! 承载：OPAQUE 登录（`anchor`：服务端身份签名覆盖 SERVER_ID‖user‖ke2‖bind_token）→
//! 会话票据签发（TTL、revocation_epoch；票据根 = 本地种子（单服）或 Raft 状态内根
//! （多主，任何服务器都验得了——SR-SIG1 跨服重放面的闭合前提，§2.2））→ key-bind
//! （设备公钥登记）→ 设备注册表操作 → SR-SIG1 请求验签 → dir_pull（根签
//! ClusterDirectory 下发）。
//!
//! # 票据强制契约（§2.2，接口契约级）
//!
//! 所有受 SR-SIG1 保护的**状态变更**请求必须携带有效票据；[`CtrlGuard::admit_state_change`]
//! 的校验顺序 = **票据（签名+TTL+epoch+吊销）→ SR-SIG1 验签 → nonce 记账**——票据/签名
//! 失败时 nonce **不入账**（`ticket.rs::tests` + `tests/control_flow.rs::full_chain_*`
//! 断言该顺序：错误票据 + 全新 nonce ⇒ 拒且不记账）。
//!
//! # 异步派发（M4 多主批次）
//!
//! 写读经 [`NetBackend`]（single = 本地 redb 立即完成；multi-primary = Raft 提交/线性
//! 一致读——网络往返，故派发为 async；§1.3.3c lookup 接缝的同一理由）。
//!
//! # 帧格式
//!
//! 控制流 = 隧道内首条 yamux 流（客户端 `open_stream(Prio::Control)`；服务端按流 id=1
//! 分派）。每条消息 = `[u32 LE len][postcard CtrlRequest/CtrlResponse]`。

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
// 共享契约再导出（M7 类型上收——定义在 flock_protocol::roster，两端同类型无第二
// 真相源；既有引用路径 `flock_server::control::*` 不变）
// ============================================================================

pub use flock_protocol::roster::{
    keybind_canonical, recv_ctrl_msg, send_ctrl_msg, CtrlError, CtrlRequest, CtrlResponse,
    DeviceOp, DevicePubs, DeviceRowWire, PeerInfo, PeerKind, SrAuth, TicketWire,
    CTRL_PROTO_VERSION, KEYBIND_LABEL, MAX_CTRL_MSG,
};

/// SR-SIG1 canonical 的 method 槽（控制面统一方法名；path 区分操作）。
pub const CTRL_METHOD: &str = "CTRL";
/// 各 SR-SIG1 保护操作的 path（进 canonical 七字段，§1.3.2 线上格式不变）。
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
    /// 票据权威（Local 种子 / Sync = Raft 内根——校验语义一致，见 [`TicketAuthority`]）。
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

    /// 票据校验 + user 解析（KeyBind 与 admit 共用；epoch/设备态来自 NetBackend）。
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
            // Local 票据内嵌 user；Sync 票据绑 device——user 由注册表 owner 解析。
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
        // ① 票据（先于一切 nonce 记账——§2.2 契约序）。
        let user = self
            .ticket_principal(net, session_device, ticket, now_unix as u64)
            .await
            .map_err(|r| {
                eprintln!("flock-server: ticket rejected: {r}");
                CtrlError::TicketBad
            })?;
        // ② SR-SIG1 验签（user 公钥集来自注册表——线性一致）。
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
        // ③ nonce 记账（查重 + 入账；仅在前两步通过后到达此处）。
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
// 服务端分发
// ============================================================================

/// 单条控制连接的会话上下文。
struct ConnCtx {
    /// 隧道对端设备（respond 已认证）。
    device: DeviceId,
    /// LoginBegin 的在途 OPAQUE 状态。
    pending_login: Option<Vec<u8>>,
}

/// 控制流空闲超时（评审项 8）：3×keepalive（30s）无任何帧即关闭该流。
///
/// 与会话层 PING/PONG 的关系：PING/PONG 走**记录层**（整条连接），不产生 yamux 流
/// 帧本层可见——它维持的是隧道存活，**不维持**单条流的空闲豁免。控制流关闭后隧道
/// 与数据通道不受影响；客户端需要控制业务时重开控制流即可（当前 M3 客户端的控制
/// 流为静默占位、不发业务，被空闲关闭无功能影响）。
const CTRL_IDLE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3 * flock_protocol::session::KEEPALIVE.as_secs());

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
        // 空闲超时（评审项 8）：3×keepalive 无任何入站帧 ⇒ 优雅结束控制流。
        let req: CtrlRequest = match tokio::time::timeout(CTRL_IDLE_TIMEOUT, recv_ctrl_msg(io))
            .await
        {
            Ok(r) => match r {
                Ok(r) => r,
                Err(_) => return Ok(()), // EOF/坏帧：控制流结束
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

        // —— OPAQUE 注册（设置口令；授权 = 本会话设备 owner）——
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
            // 记录侧规范化（解码验证）。
            let canonical = match flock_protocol::pake::server_reg_canonical(&record_b64) {
                Ok(c) => c,
                Err(_) => return err(CtrlError::Internal),
            };
            match net.set_password(&owner, &canonical, profile).await {
                Ok(()) => CtrlResponse::Ok,
                Err(e) => state_err(e),
            }
        }

        // —— OPAQUE 登录（anchor）→ 票据签发 ——
        CtrlRequest::LoginBegin { user, ke1_b64 } => {
            let Some(owner) = owner_of_device(net, &ctx.device).await else {
                return err(CtrlError::NotAuthorized);
            };
            if owner != user {
                return err(CtrlError::NotAuthorized);
            }
            // M8（§7-M8.3）：禁用判定——disabled 用户阻断控制流登录（会话设备 owner
            // 已认证，此处的 NotAuthorized 不构成匿名枚举面；已建会话不追溯断开）。
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

        // —— key-bind：设备公钥登记（§1.3.3f「公钥经登录态登记」）——
        CtrlRequest::KeyBind {
            ticket,
            bind_token,
            device,
            sr_sig_pub,
            device_sig,
        } => {
            // 票据（状态变更必带；含会话设备绑定检查）。
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
            // bind_token 一次性（§2.4 线性一致查重）。
            if !net.consume_bind_token(&bind_token).await {
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
            match net
                .register_device(&user, device.x25519, device.ed25519, &device.hostname)
                .await
            {
                Ok(row) => {
                    // SR-SIG1 公钥登记失败必须可见（评审项 6：禁止无痕成功）——设备行
                    // 已建但用户验签公钥缺失 ⇒ 后续全部 SR-SIG1 状态变更将 SigBad。
                    // 返回明确错误 + 日志留痕（响应面无告警字段，不改线格式——客户端
                    // 可凭 bind_token 未消费的语义重试其他账号路径）。
                    if let Err(e) = net.add_user_sig_key(&user, sr_sig_pub).await {
                        eprintln!(
                            "flock-server: key-bind: 设备已注册但 SR-SIG1 公钥登记失败\
                             （user={user}）: {e}"
                        );
                        return err(CtrlError::Internal);
                    }
                    CtrlResponse::KeyBound {
                        device_id: DeviceId::from_ed25519(&vk).0,
                        vip: row.vip,
                    }
                }
                // M7 re-register：同设备（同公钥集）再次 key-bind ⇒ 更新 hostname，
                // VIP 不变（窗口内重连同设备保持同 IP，§7-M7）。bind_token 已消费、
                // 设备签名已验——与首注册同授权强度。按 **DeviceExists 变体**分流
                // （消灭 `contains("already registered")` 字符串契约）+ owner 校验：
                // 目标行 owner != 票据 user ⇒ NotAuthorized（跨户改他人设备 hostname
                // 被拒——设备签名只证明设备侧占有，不证明账户归属）。
                Err(NetError::DeviceExists) => {
                    let dev_id = DeviceId::from_ed25519(&vk);
                    match net.device_row(&dev_id).await {
                        Some(row) if row.owner != user => {
                            eprintln!(
                                "flock-server: key-bind(re): 跨户重绑定被拒\
                                 （device owner={} != ticket user={user}）",
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
                                    "flock-server: key-bind(re): SR-SIG1 公钥登记失败\
                                     （user={user}）: {e}"
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

        // —— SR-SIG1 + 票据 + nonce 的状态变更 ——
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
                    // 集群身份钉扎：Sync 形态由状态机 bootstrap 身份自证；单服以库内根比对。
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
                            // 杀本地该设备会话（§2.2 吊销传播界：apply 回调内本地执行——
                            // 多主形态经 SyncHooks 于各节点 apply 现场触发；单机即时执行）。
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

        // —— M7：成员名册（票据保护；票据校验先于数据装配，§7-M7.4）——
        CtrlRequest::PeerListPull { ticket } => {
            let Some(ticket) = ticket else {
                return err(CtrlError::TicketMissing);
            };
            // 契约序：票据（签名+TTL+epoch+设备态）通过之前**不触碰**名册装配——
            // 坏票据 ⇒ TicketBad 且装配计数不动（tests 断言该顺序）。
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
// M7：名册装配（§7-M7.4——注册表快照 ⋈ 本地租约视图；VIP 升序）
// ============================================================================

/// 名册装配累计（诊断/测试面——「票据先行」顺序断言的探针：坏票据 ⇒ 计数不动）。
pub fn roster_assemblies() -> u64 {
    ROSTER_ASSEMBLIES.load(std::sync::atomic::Ordering::Relaxed)
}

static ROSTER_ASSEMBLIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 装配名册：注册表快照（**本地已 apply 视图**——两级读缓存档即可，允许 follower
/// 视图秒级陈旧）⋈ 本地租约视图（在线判定 + last_seen + EWMA）+ Server 条目。
///
/// - 设备条目：仅 `status == Active` 行（Disabled/Revoked/Expired 排除——名册 =
///   现任成员；审计走 DeviceList）；
/// - Server 条目：多主 = Raft server_keys 本地视图（vip）+ 根签目录 endpoint
///   （hostname）+ 各服务器自发布租约（在线/流量）；单服 = 本机一条
///   （vip = cfg.vip，hostname = advertise_endpoint，流量 = 本机 TrafficMeter）；
/// - 输出按 VIP 升序。
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
            // 服务器自身（单服形态唯一 Server 条目）。
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
            // Server 条目：server_keys（根签登记的 mesh VIP）+ 目录 endpoint（hostname）
            // + 自发布租约（在线/流量经既有 gossip 同步）。
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

/// owner 检查（用户只能操作自己名下设备）。
async fn authorize_owner(net: &NetBackend, user: &str, device: &DeviceId) -> bool {
    net.device_row(device)
        .await
        .map(|r| r.owner == user)
        .unwrap_or(false)
}

/// RedeemInvite 的 SR-SIG1 签名覆盖 body（与客户端构造逐字节一致）。
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

// 避免 unused-import 警告（x25519_dalek 仅在设备公钥转换处经由类型推断使用）。
const _: fn([u8; 32]) -> x25519_dalek::PublicKey = x25519_dalek::PublicKey::from;

// ============================================================================
// 单元测试：契约顺序（票据先于 nonce 记账）
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

    /// 错误票据 + 全新 nonce ⇒ 拒且 nonce 不入账；同 nonce 持有效票据走到下一层（顺序证明）。
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
        bad.exp += 100; // 篡改覆盖字段 ⇒ BadSignature

        // ① 错误票据 + 全新 nonce ⇒ TicketBad，且 nonce 不入账。
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
                &TicketWire::Local(good.clone()),
                &dummy_auth("alice", "n1", now),
                PATH_TICKET_RENEW,
                b"",
                now,
            )
            .await
            .unwrap_err();
        assert_eq!(e2, CtrlError::SigBad, "有效票据 ⇒ 校验推进到签名层");
        assert!(!guard.nonces.contains("alice", "n1"), "签名失败亦不入账");
        // ③ 票据绑定设备 ≠ 会话设备 ⇒ 拒。
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
        // ④ 会话设备已吊销 ⇒ 票据层拒（DeviceNotActive → TicketBad）。
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
        assert_eq!(e4, CtrlError::TicketBad, "吊销后票据被拒（epoch/设备态）");
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
    // M7（§7-M7.4）：名册装配三态 + Server 条目 + 票据先行顺序
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

    /// 三态（在线/离线/过期）+ Server 条目 + VIP 升序 + hostname 默认值链路。
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

        // 在线设备：会话登记 + 喂流量（EWMA 两折收敛出非零）。
        let id_on = DeviceId::from_ed25519(&vk_on.verifying_key());
        let _kill = core.sessions.register(id_on.0);
        let mut ms = 1_000_000u64;
        for _ in 0..3 {
            core.traffic.note_tx(&row_on.vip, 8192);
            core.traffic.note_rx(&row_on.vip, 4096);
            ms += 1000;
            core.traffic.tick(ms);
        }
        // 过期设备。
        let id_exp = DeviceId::from_ed25519(&vk_exp.verifying_key());
        store.expire(&id_exp, 1_700_000_000).unwrap();

        let peers = assemble_roster(&core).await;
        // 三条：两台 Active 设备 + 本服务器；Expired 排除。
        assert_eq!(peers.len(), 3, "{peers:?}");
        // VIP 升序（服务器 .1 < 设备 .2/.3）。
        let vips: Vec<[u8; 4]> = peers.iter().map(|p| p.vip).collect();
        let mut sorted = vips.clone();
        sorted.sort();
        assert_eq!(vips, sorted, "VIP 升序");

        let srv = peers
            .iter()
            .find(|p| p.kind == PeerKind::Server)
            .expect("Server 条目");
        assert_eq!(srv.vip, [100, 64, 0, 1]);
        assert_eq!(
            srv.hostname, "127.0.0.1:9443",
            "单服 Server hostname = advertise"
        );
        assert!(!srv.owner.is_empty(), "owner = server_id 承载（node 号）");
        assert!(srv.online, "服务器自身恒在线（本机视角）");

        let p_on = peers.iter().find(|p| p.vip == row_on.vip).unwrap();
        assert_eq!(p_on.hostname, "online-pad");
        assert_eq!(p_on.owner, "alice");
        assert!(p_on.online, "会话在册 ⇒ 在线");
        assert!(
            p_on.tx_bps > 0 && p_on.rx_bps > 0,
            "EWMA 非零（tx={} rx={}）",
            p_on.tx_bps,
            p_on.rx_bps
        );
        assert!(p_on.last_seen_unix > 0);

        let p_off = peers.iter().find(|p| p.vip == row_off.vip).unwrap();
        assert!(!p_off.online, "无会话 ⇒ 离线");
        assert_eq!(p_off.tx_bps, 0, "从未计到流量");
        assert_eq!(
            p_off.hostname,
            flock_sync::HOSTNAME_UNKNOWN,
            "空 hostname 默认值"
        );

        assert!(
            peers.iter().all(|p| p.vip != row_exp.vip),
            "Expired 设备不进名册"
        );
    }

    /// 票据先行顺序：无票据 ⇒ TicketMissing；坏票据 ⇒ TicketBad 且**装配计数不动**
    ///（坏票据 + 有效名册数据 ⇒ 拒——数据装配未发生）；好票据 ⇒ PeerList + 计数 +1。
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

        // ① 无票据 ⇒ TicketMissing。
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

        // ② 坏票据（篡改 exp ⇒ BadSignature）⇒ TicketBad 且装配计数不动（顺序证明）。
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
            "坏票据 ⇒ 名册装配未发生（票据先行）"
        );

        // ③ 好票据 ⇒ PeerList（含 Server 条目）+ 计数 +1。
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
        assert_eq!(roster_assemblies(), before + 1, "好票据才装配");
    }

    /// M8（§7-M8.3）：控制流 LoginBegin 的 disabled 判定——禁用 ⇒ NotAuthorized
    ///（登录链在 begin 即断，不进 OPAQUE）；enable 后恢复。
    #[tokio::test]
    async fn login_begin_rejects_disabled_user() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = crate::server::ServerCore::open_or_init(m7_cfg(dir.path().to_path_buf()))
            .expect("core");
        let store = store_of(&core);
        // dave 的会话设备（owner 面）。
        let vk = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        store
            .register_device("dave", [11; 32], *vk.verifying_key().as_bytes(), "")
            .unwrap();
        let device = DeviceId::from_ed25519(&vk.verifying_key());
        // 建户（RegisterDevice 自动建空户）+ 设口令 + 禁用。
        store.set_password("dave", "rec-dave", 0).unwrap();
        store.set_user_disabled("dave", true).unwrap();

        let mut ctx = ConnCtx {
            device,
            pending_login: None,
        };
        let mut ke1 = String::new();
        // 非法 ke1 无所谓——判定在 OPAQUE 之前。
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
            "禁用用户登录 begin 即拒: {resp:?}"
        );
        assert!(ctx.pending_login.is_none(), "未进 OPAQUE 在途态");

        // enable 后恢复（坏 ke1 走 LoginFailed——判定推进到 OPAQUE 层）。
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
            "恢复后推进到 OPAQUE（坏 ke1 ⇒ LoginFailed）: {resp:?}"
        );
    }

    /// KeyBind re-register 的 owner 校验（DeviceExists 变体分流）：跨户对他人设备
    /// 重绑定（改 hostname）⇒ NotAuthorized 且原行不动；本人 re-register ⇒ hostname
    /// 更新 + VIP 不变。
    #[tokio::test]
    async fn keybind_reregister_rejects_cross_owner_hostname_change() {
        use ed25519_dalek::Signer as _;

        let dir = tempfile::tempdir().unwrap();
        let (core, _) = crate::server::ServerCore::open_or_init(m7_cfg(dir.path().to_path_buf()))
            .expect("core");
        let store = store_of(&core);

        // alice 的设备（已注册）；bob 的会话设备（票据主体）。
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
        // 变体契约：同钥匙重注册 ⇒ NetError::DeviceExists（非 InvalidState 串）。
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

        // bob 携 alice 设备公钥重绑定：设备签名**可过**（由 alice 设备密钥签 bob 的
        // canonical——占有证明是设备侧的），但目标行 owner=alice != 票据 user=bob ⇒
        // NotAuthorized，hostname 不被篡改。
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
            "跨户改 hostname 被拒: {resp:?}"
        );
        assert_eq!(
            store.device_row(&alice_dev).unwrap().hostname,
            "alice-pad",
            "原行不被篡改"
        );

        // 对照：本人 re-register（alice 的票据 + alice 的设备）⇒ hostname 更新 +
        // VIP 不变（DeviceExists 分流的正路径）。
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
                assert_eq!(vip, row_a.vip, "re-register 保持 VIP（§7-M7）");
            }
            other => panic!("本人 re-register: {other:?}"),
        }
        assert_eq!(store.device_row(&alice_dev).unwrap().hostname, "renamed");
    }
}
