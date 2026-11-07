//! NetBackend：控制面/管理面的统一**异步**写读门面（docs/design.md §2.2/§3.11 M4 批次）。
//!
//! 两形态（`server.toml [sync].mode`，缺省 `single`——m2/m2-direct 部署不受影响）：
//!
//! - [`NetBackend::Single`]：M2 本地 redb 状态库（同步 [`StateStore`]——方法立即完成）；
//! - [`NetBackend::Sync`]（feature `multi-primary`）：写经 Raft 提交（任意节点进入，
//!   非 leader 自动转发 leader，§4 写转发）；读按一致性档位——注册表行/用户面走
//!   **线性一致读**（任意节点进入，跨节点读后写正确），目录三态走
//!   `SyncNode::device_directory()` 的**两级读**（记录缓存 + epoch + apply-lag 熔断，
//!   §4 读与缓存——正是 `session::respond` 的注入点）。
//!
//! 为什么是异步门面而非给 [`crate::netstate::NetState`] 加 async：单服形态的同步 trait
//! 保持不动（redb 是同步 IO），Raft 写/线性一致读是网络往返——同步 trait 上 block_on
//! 在异步派发路径内是死锁陷阱，故门面在装配层异步化（`§1.3.3c` lookup 接缝本就要求
//! BoxFuture 的同一理由）。

use flock_protocol::ed25519_dalek::VerifyingKey;
use flock_protocol::session::{DeviceId, LookupVerdict};

use crate::netstate::{
    DeviceRow, DeviceStatus, NetError, RedeemError, RedeemOutcome, RedeemRequest, StateStore,
    UserOpError,
};

#[cfg(feature = "multi-primary")]
use flock_sync::proto as sync_proto;

/// 形态分派的统一后端。
pub enum NetBackend {
    /// 单服：本地状态库（M2 形态；m2-direct.yml 等部署）。
    Single(std::sync::Arc<StateStore>),
    /// 多主：flock-sync Raft 状态机（feature `multi-primary`）。
    #[cfg(feature = "multi-primary")]
    Sync(std::sync::Arc<SyncNetState>),
}

impl NetBackend {
    /// 当前全局 revocation_epoch（Sync = 本机已 apply 的 epoch）。
    pub async fn epoch(&self) -> u64 {
        match self {
            NetBackend::Single(s) => s.epoch(),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => s.node.local_epoch(),
        }
    }

    /// 目录三态（respond/票据设备态数据源）。Sync 走两级读（缓存+epoch+熔断）。
    pub async fn lookup(&self, id: &DeviceId) -> LookupVerdict {
        match self {
            NetBackend::Single(s) => s.lookup(id),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => s.node.dir().lookup_async(*id).await,
        }
    }

    /// 注册表行（owner 面板/VIP）。Sync = 线性一致读。
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

    /// owner 名下全部设备（DeviceList）。
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

    /// 注册设备（分配 VIP；M7 增 hostname——空串落 "(unknown)"）。
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
                        // 注册时刻由提交方注入（apply 无时钟——确定性；回收器锚）。
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

    /// M7：更新设备 hostname（re-register 路径；仅非终态行）。
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

    /// M7：过期设备（回收器提交；行保留审计 + VIP 归还池 + epoch 推进——幂等）。
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

    /// 吊销（行保留、VIP 不回收、epoch +1；本地杀会话经 apply 钩子，§2.2）。
    pub async fn revoke(&self, id: &DeviceId) -> Result<u64, NetError> {
        self.set_status(id, DeviceStatus::Revoked).await
    }

    /// 禁用（不删除；epoch +1）。
    pub async fn disable(&self, id: &DeviceId) -> Result<u64, NetError> {
        self.set_status(id, DeviceStatus::Disabled).await
    }

    /// 重新启用（仅 Disabled → Active；不动 epoch）。
    pub async fn enable(&self, id: &DeviceId) -> Result<(), NetError> {
        self.set_status(id, DeviceStatus::Active).await.map(|_| ())
    }

    async fn set_status(&self, id: &DeviceId, status: DeviceStatus) -> Result<u64, NetError> {
        match self {
            NetBackend::Single(s) => match status {
                DeviceStatus::Revoked => s.revoke(id),
                DeviceStatus::Disabled => s.disable(id),
                DeviceStatus::Active => s.enable(id).map(|_| s.epoch()),
                // Expired 走 [`NetBackend::expire`]（携带 now_unix——时间语义转移）。
                DeviceStatus::Expired => Err(NetError::InvalidState(
                    "expire 经 expire()（需 now_unix）".into(),
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
                            "expire 经 expire()（需 now_unix）".into(),
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

    /// 邀请兑换（查重+吊销+expiry → 建用户/设备+分 VIP；Raft 单次提交 = 原子；
    /// M7 增 hostname）。
    pub async fn redeem_invite(
        &self,
        req: RedeemRequest<'_>,
    ) -> Result<RedeemOutcome, RedeemError> {
        match self {
            NetBackend::Single(s) => s.redeem_invite(req),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                // 集群身份钉扎由状态机 bootstrap 身份承担（apply_redeem 内比对根公钥）。
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

    /// 吊销未兑换邀请（根签管理操作——多主形态须运维侧根密钥，服务器不持有）。
    pub async fn revoke_invite(&self, invite_id: &[u8; 16]) -> Result<(), NetError> {
        match self {
            NetBackend::Single(s) => s.revoke_invite(invite_id),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(_) => Err(NetError::InvalidState(
                "多主形态 revoke_invite 为根签管理操作（运维侧执行）".into(),
            )),
        }
    }

    /// 邀请登记（单服 mint 路径；多主形态 mint 在根密钥侧）。
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

    /// 设置口令记录（仅未设置时；跨节点登录 ⇒ 复制形态，§2.4 OPRF 共享）。
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

    /// 口令记录（线性一致读）。
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

    /// 登记 SR-SIG1 用户公钥（key-bind 路径）。
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

    /// SR-SIG1 验签公钥集（线性一致读）。
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

    /// bind_token 一次性消费（§2.4 线性一致查重）。
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

    /// VIP 分配（单调水位；不回收）。
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

    /// 原样写透传（feature `multi-primary`；admin SignedWrite → 运维侧根签操作：
    /// Bootstrap/SetOprf/RecordInvite——签名验证全部在 Raft 状态机内）。
    #[cfg(feature = "multi-primary")]
    pub async fn write_sync(
        &self,
        req: sync_proto::SyncRequest,
    ) -> Result<sync_proto::SyncResponse, NetError> {
        match self {
            NetBackend::Sync(s) => s.write(req).await,
            NetBackend::Single(_) => Err(NetError::InvalidState(
                "单服形态无 SignedWrite（管理操作走 invite/redeem/device-add/revoke）".into(),
            )),
        }
    }

    // ------------------------------------------------------------------
    // M8（§7-M8.3）：Web 管理面用户操作（与 DeviceOp 同型双臂：Single = 本地 redb
    // 直写；Sync = Raft 五写。授权在提交方 handler/CLI 层——与控制流 DeviceOp 同型）
    // ------------------------------------------------------------------

    /// 用户行（admin/disabled/pw_bootstrap；登录 disabled 判定 + webui 列表面）。
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

    /// 全部用户行（本地已 apply 视图——展示面档位，与名册同 §7-M7.4 档位）。
    pub async fn users_all(&self) -> Vec<(String, StateStoreUserRow)> {
        match self {
            NetBackend::Single(s) => s.users_all(),
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => s.node.users_snapshot(),
        }
    }

    /// 创建用户（携一次性引导令牌）；已存在 ⇒ [`UserOpError::UserExists`]（提交方
    /// 按需幂等忽略——`web-admin-add` 的多主路径）。
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

    /// 引导令牌落口令记录（原子消费：令牌匹配且记录为空 ⇒ 落记录 + 清令牌）。
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

    /// 管理员重置口令（清记录 + 置新令牌——旧口令即刻失效）。
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

    /// 设/撤 Web 管理角色。
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

    /// 禁用/启用用户（阻断登录；不追溯断开已建会话）。
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

/// 用户行类型再导出（netstate 与 flock-sync 同源定义；避免在 backend 顶头引两个名）。
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
// 多主适配（feature multi-primary）
// ============================================================================

#[cfg(feature = "multi-primary")]
pub use adapter::SyncNetState;

#[cfg(feature = "multi-primary")]
mod adapter {
    use std::sync::Arc;

    use flock_sync::proto::{SyncError, SyncRequest, SyncResponse};

    use crate::netstate::NetError;

    /// SyncNode 的 NetBackend 适配体（写转发 leader / 线性一致读经节点门面）。
    pub struct SyncNetState {
        pub node: Arc<flock_sync::SyncNode>,
    }

    impl SyncNetState {
        pub fn new(node: Arc<flock_sync::SyncNode>) -> Arc<Self> {
            Arc::new(SyncNetState { node })
        }

        /// 写（任意节点进入；非 leader 自动转发，§4）。
        pub async fn write(&self, req: SyncRequest) -> Result<SyncResponse, NetError> {
            self.node.write(req).await.map_err(net_of_sync)
        }
    }

    pub(crate) fn net_of_sync(e: SyncError) -> NetError {
        NetError::Internal(format!("sync: {e}"))
    }
}

// （评审项 12：原 `mod conv` 的 flock-sync 行 → 服务器行 From 转换黏合层删除——
// netstate.rs 的行类型已直接再导出自 flock_sync::proto，两臂同一类型。）

// —— StateError → 服务器错误面映射 ——

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
