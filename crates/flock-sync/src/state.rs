//! 纯状态机数据：NetState 的确定性执行核（docs/design.md §3.10/§2.2 语义纪律）。
//!
//! 语义纪律（与 M2 单服 StateStore 一致，M4 = 同语义的 Raft 复制形态）：
//! - **VIP 100.64.0.0/10 分配**：`100.64.0.1`–`.10` 保留服务器自身，水位线只进不退。
//!   IP 复用策略（§2.1 M7 修订）：**吊销/禁用 → IP 永不复用**（行保留）；**Expired
//!   （离线超保留期）→ VIP 归还 `vip_pool` 分配池**，新设备可分到——过期行保留在册
//!   （审计），名册查询排除。
//! - **invite_id 单次消费**：redeem 在同一状态转移内查重 + 标记（Raft 单次提交 = 原子）。
//! - **吊销推进全局 revocation_epoch**：仅阻断性转移（→Disabled/→Revoked/→Expired）+1；
//!   Enable 是恢复，不动 epoch（否则会无害地废掉全网在途票据）。
//! - **票据密钥根在 Raft 内**（Bootstrap 落库，§4）。
//!
//! `apply` 是纯函数式的确定性转移：所有节点对同一日志条目产生同一结果——验证失败的
//! 管理操作返回 [`SyncResponse::Error`]（一致拒绝，不发散）。

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

/// 集群身份（Bootstrap 产物）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterIdent {
    pub cluster_id: [u8; 16],
    pub root_pub: [u8; 32],
}

/// 吊销副作用（apply 产出，由 [`crate::sm`] 包装层触发钩子：杀本地会话/清拒票据）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationEffect {
    pub device: [u8; 32],
    pub new_epoch: u64,
}

/// 单条写操作的 apply 产物。
#[derive(Debug, Clone, PartialEq)]
pub struct ApplyOutcome {
    pub resp: SyncResponse,
    /// 阻断性状态转移（Revoke/Disable）非空 ⇒ 触发吊销传播钩子（§2.2）。
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

/// NetState 状态机数据（快照 = 本结构序列化）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetStateData {
    pub cluster: Option<ClusterIdent>,
    pub epoch: u64,
    pub vip_next: u32,
    pub config_version: u64,
    pub devices: BTreeMap<[u8; 32], DeviceRow>,
    /// M7：Expired 归还的 VIP 分配池（有序——分配取最小；序列化进快照）。
    pub vip_pool: BTreeSet<[u8; 4]>,
    /// VIP → 设备反查索引（`devices` 的**派生数据**，不序列化——快照/重放后由
    /// [`NetStateData::reindex_vips`] 重建，apply 注册路径增量维护）。每包转发热路径
    /// （`sm::SmCore::device_by_vip`）从 O(N) 全表扫描降为 O(log N)。单射性由
    /// 「Expired 行不进索引（其 VIP 已归还池）」维持——池内 VIP 与索引键不相交，
    /// 池重派即插入新行。
    #[serde(skip, default)]
    pub vip_index: BTreeMap<[u8; 4], [u8; 32]>,
    pub users: BTreeMap<String, UserRow>,
    pub invites: BTreeMap<[u8; 16], InviteRow>,
    pub bind_tokens: BTreeSet<[u8; 16]>,
    pub server_keys: BTreeMap<NodeId, ServerKeyEntry>,
    pub wraps: BTreeMap<NodeId, Vec<u8>>,
    pub ticket_root: Option<[u8; 32]>,
    /// 集群共享 OPRF key（b64 ServerSetup；根签 SetOprf 登记——OPAQUE 记录全网可验，§2.4）。
    pub oprf_b64: Option<String>,
    pub voters: BTreeSet<NodeId>,
    /// 最后一条已 apply 的普通/成员日志（快照边界；由 sm 包装层维护）。
    pub last_applied: Option<LogId<u64>>,
    pub last_membership: StoredMembership<u64, BasicNode>,
}

impl NetStateData {
    /// 空状态。
    pub fn new() -> Self {
        Self::default()
    }

    /// 序列化（快照线格式；postcard 确定性编码）。
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("netstate serialize")
    }

    /// 反序列化。
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
    }

    /// 目录三态查询（session::DeviceDirectory 数据源；损坏行 fail-closed = NotFound）。
    /// Expired 同为阻断态（离线超保留期的时间性淘汰——与 Revoked 同拒握手，§7-M7）。
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

    /// 当前全局 revocation_epoch。
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// 全量重建 VIP 反查索引（恢复/快照安装/一致性自检用；幂等）。**Expired 行不进
    /// 索引**（其 VIP 已归还 `vip_pool`——池重派后同池 VIP 会出现在新行；索引只收
    /// 非 Expired 行 ⇒ 键唯一）。
    pub fn reindex_vips(&mut self) {
        self.vip_index = self
            .devices
            .iter()
            .filter(|(_, row)| row.status != DeviceStatus::Expired)
            .map(|(dev, row)| (row.vip, *dev))
            .collect();
    }

    /// 按 VIP 反查设备（每包转发热路径——索引 O(log N)）。VIP 水位单调不复用 ⇒ 命中
    /// 唯一。NetState 只存静态注册信息——不含当前位置。
    pub fn device_by_vip(&self, vip: &[u8; 4]) -> Option<[u8; 32]> {
        self.vip_index.get(vip).copied()
    }

    /// 集群共享 OPRF key（b64；未登记 ⇒ None）。
    pub fn oprf_b64(&self) -> Option<&str> {
        self.oprf_b64.as_deref()
    }

    /// 状态摘要（线性一致读 ReadQuery::State）。
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

    /// 确定性执行一条写操作。
    ///
    /// `expected_root`：本机配置钉住的集群根公钥（None = 未配置，仅 Bootstrap 自证生效）。
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
                // 幂等登记：同 id 同 expiry 且未消费 ⇒ 重复登记放行（签发侧重放）。
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
        // 自证：根公钥对 canonical 字节的签名（防字段拼接）。
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
                    // 幂等重放放行（Raft 重放/追赶路径）。
                    ApplyOutcome::ok(SyncResponse::Ok)
                } else {
                    ApplyOutcome::err(StateError::AlreadyBootstrapped)
                }
            }
            None => {
                // 本机钉扎根比对（防「他签根」进集群身份）。
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
        let _ = expected_root; // 根公钥固定为 bootstrap 身份（下方与 cluster 比对）
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
            Some(cur) if cur == &rs.op => ApplyOutcome::ok(SyncResponse::Ok), // 幂等重放
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
            // Expired 终态不可逆（旧 VIP 可能已属他设备——复活破索引单射，§7-M7）。
            return ApplyOutcome::err(StateError::ExpiredIsTerminal);
        }
        let mut effect = None;
        if row.status != status {
            // 仅阻断性转移（→Disabled/→Revoked）推进全局 revocation_epoch（§2.2）。
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

    /// M7：过期转移（回收器提交）——**VIP 归还分配池**（Expired ≠ Revoked 的核心差异：
    /// 行保留审计、池内 VIP 可重派；复用吊销的 epoch 推进 + 传播钩子路径，仅状态语义
    /// 不同）。幂等：已 Expired 的重放放行（回收器多机并发提交的收敛路径）、不动 epoch。
    fn apply_expire(&mut self, device: &[u8; 32], now_unix: u64) -> ApplyOutcome {
        let Some(row) = self.devices.get_mut(device) else {
            return ApplyOutcome::err(StateError::DeviceNotFound);
        };
        if row.status == DeviceStatus::Expired {
            return ApplyOutcome::ok(SyncResponse::Epoch(self.epoch));
        }
        if row.status == DeviceStatus::Revoked {
            // Revoked 行 VIP 永不复用（§2.1）——吊销不因时间推进转化为可重派。
            return ApplyOutcome::err(StateError::RevokedIsTerminal);
        }
        // 阻断性转移：epoch 推进 + 吊销传播钩子（杀残留会话/废票据——与 Revoked 同
        // 路径，§7-M2）。
        self.epoch += 1;
        row.since_epoch = self.epoch;
        row.status = DeviceStatus::Expired;
        row.expired_at = Some(now_unix);
        let effect = RevocationEffect {
            device: *device,
            new_epoch: self.epoch,
        };
        // 释放 VIP：索引删旧条目 + 归还池（有序集合——重派取最小）。
        let released = row.vip;
        self.vip_index.remove(&released);
        self.vip_pool.insert(released);
        ApplyOutcome {
            resp: SyncResponse::Epoch(self.epoch),
            revoked: Some(effect),
        }
    }

    /// M7：hostname 更新（re-register 路径；仅非终态行）。
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
        // 根签名/结构校验 + 本集群身份钉死，先于任何状态触碰（同 M2）。
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
        // 一次性三判定（§1.3.3f 邀请一生）。
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
                // 兑换时刻即注册时刻（回收器锚，§7-M7.5）。
                registered_at: now_unix,
            },
        );
        self.vip_index.insert(vip, device_id);
        // 同一状态转移内标记 used（查重与标记间无窗口——Raft 单次提交）。
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

    /// 状态内根公钥（admin 验签锚）；`expected_root` 优先（本机钉扎，双保险）。
    fn root_verifier(&self, expected_root: Option<&VerifyingKey>) -> Option<VerifyingKey> {
        if let Some(pinned) = expected_root {
            return Some(*pinned);
        }
        self.cluster
            .as_ref()
            .and_then(|c| VerifyingKey::from_bytes(&c.root_pub).ok())
    }

    /// VIP 分配（M7 两级：**Expired 归还池优先**（取最小——确定性），池空回退单调
    /// 水位线 `vip_next`（只进不退，吊销/禁用行的 VIP 永不进池，§2.1）；越
    /// [`VIP_LAST`] 即耗尽）。
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
// 单元测试：纯状态机语义（VIP 纪律/邀请一次性/epoch 推进/admin 验签）
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
        assert!(matches!(e1, SyncResponse::Epoch(1)), "吊销推进 epoch");
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
        assert_eq!(ia, VIP_FIRST, "首 VIP = 100.64.0.2");
        assert!(ib > ia, "IP 不复用（水位线只进不退）");
        // 同设备重注册拒（行保留）。
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
        // 禁用不删除：行保留、VIP 不回收。
        let id2: [u8; 32] = Sha256::digest([2u8; 32]).into();
        assert!(matches!(
            d.apply(&SyncRequest::Disable { device: id2 }, None).resp,
            SyncResponse::Epoch(2)
        ));
        assert_eq!(d.devices.get(&id2).unwrap().vip, b.vip, "VIP 不回收");
        assert!(matches!(d.lookup(&id2), VerdictW::Revoked { .. }));
        // Revoked 终态不可逆。
        assert!(matches!(
            d.apply(&SyncRequest::Enable { device: id }, None).resp,
            SyncResponse::Error(StateError::RevokedIsTerminal)
        ));
        // hostname 空串落 "(unknown)"（M7 默认值链路）。
        assert_eq!(a.hostname, crate::proto::HOSTNAME_UNKNOWN);
    }

    /// M7：Expired 释放 VIP 回池 + 新设备拿到该 VIP + Expired ≠ Revoked 可区分 +
    /// 幂等重放放行 + 终态不可逆 + 索引单射维持。
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

        // Expire（注入时钟）：epoch 推进 + expired_at 落库 + VIP 归还池。
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
            "expire 推进 epoch: {e:?}"
        );
        let row = d.devices.get(&id_a).unwrap();
        assert_eq!(row.status, DeviceStatus::Expired, "Expired ≠ Revoked");
        assert_eq!(row.expired_at, Some(1_700_000_000));
        assert_eq!(row.vip, a_row.vip, "行保留（审计）：VIP 字段不动");
        assert!(d.vip_pool.contains(&a_row.vip), "VIP 归还池");
        assert_eq!(d.device_by_vip(&a_row.vip), None, "索引删旧条目");
        assert!(
            !d.vip_pool.contains(&d.devices[&dev_id(&[2u8; 32])].vip),
            "未过期设备的 VIP 不进池"
        );

        // 幂等重放：已 Expired ⇒ 放行且不动 epoch。
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
            "重放不刷新 expired_at"
        );

        // 新设备拿到被释放的 VIP（池优先于水位线）。
        let c = d.apply(&reg(3, "laptop-c"), None).resp;
        let SyncResponse::Device(c_row) = c else {
            panic!()
        };
        assert_eq!(c_row.vip, a_row.vip, "池内 VIP 重派给新设备");

        // 索引单射：同 VIP 现在只指向新设备；重建后一致（Expired 行不进索引）。
        assert_eq!(d.device_by_vip(&a_row.vip), Some(dev_id(&[3u8; 32])));
        let incremental = d.vip_index.clone();
        d.reindex_vips();
        assert_eq!(d.vip_index, incremental, "重建 == 增量（Expired 排除）");

        // 终态不可逆：Enable/Disable/再 Expire 换时刻均拒或幂等。
        assert!(matches!(
            d.apply(&SyncRequest::Enable { device: id_a }, None).resp,
            SyncResponse::Error(StateError::ExpiredIsTerminal)
        ));
        assert!(matches!(
            d.apply(&SyncRequest::Disable { device: id_a }, None).resp,
            SyncResponse::Error(StateError::ExpiredIsTerminal)
        ));
        // hostname 更新拒（终态行）。
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
        // lookup：Expired 阻断握手（Revoked 判定外形）。
        assert!(matches!(d.lookup(&id_a), VerdictW::Revoked { .. }));

        // Revoked 不因时间转化为可重派：吊销后再 Expire ⇒ 拒。
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
            "吊销 VIP 不进池（永不复用）"
        );
    }

    /// M7：hostname 规范化（空 ⇒ "(unknown)"；trim；超长截断）+ SetHostname 更新。
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

        // 超长截断（char 边界安全）。
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

        // re-register 更新（SetHostname）。
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

        // 未知设备拒。
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
        // 邀请 fixture（根签 v3）。
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
        // 首次兑换成功。
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
        // 二次兑换拒（单次消费查重）。
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
        // 他签（无根密钥）⇒ 拒。
        let forged = SyncRequest::rewrap_signed(&other, 2, vec![1; 16]);
        assert_eq!(
            d.apply(&forged, Some(&root.verifying_key())).resp,
            SyncResponse::Error(StateError::BadRootSignature)
        );
        // server_keys 先落库（根签），再 rewrap（根签）⇒ 生效。
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
        assert_eq!(d.wraps.get(&2).map(|v| v.len()), Some(3), "rewrap 落库");
        // rewrap 到未登记 server ⇒ 拒。
        let rw2 = SyncRequest::rewrap_signed(&root, 9, vec![1]);
        assert!(matches!(
            d.apply(&rw2, Some(&root.verifying_key())).resp,
            SyncResponse::Error(StateError::NotFound(_))
        ));
        // add_voter（根签）⇒ voters + config_version。
        let av = SyncRequest::add_voter_signed(&root, 5);
        assert_eq!(
            d.apply(&av, Some(&root.verifying_key())).resp,
            SyncResponse::Admin(AdminAck::AddVoter { node_id: 5 })
        );
        assert!(d.voters.contains(&5));
        assert_eq!(d.config_version, 2, "server_keys/add_voter 各 +1");
    }

    #[test]
    fn bootstrap_once_and_root_pin() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let mut d = NetStateData::new();
        // 未钉扎根时自证签名即可成立。
        assert!(matches!(
            d.apply(
                &SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32]),
                None
            )
            .resp,
            SyncResponse::Ok
        ));
        // 幂等重放放行。
        assert!(matches!(
            d.apply(
                &SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32]),
                None
            )
            .resp,
            SyncResponse::Ok
        ));
        // 不同身份再 bootstrap ⇒ 拒。
        assert!(matches!(
            d.apply(
                &SyncRequest::bootstrap_signed(&root, [7; 16], [8; 32]),
                None
            )
            .resp,
            SyncResponse::Error(StateError::AlreadyBootstrapped)
        ));
        // 钉扎根不符 ⇒ 拒（防他签根）。
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
        // M7 新字段随快照往返。
        let id: [u8; 32] = Sha256::digest([1u8; 32]).into();
        assert_eq!(back.devices.get(&id).unwrap().hostname, "host-rt");
        assert_eq!(back.devices.get(&id).unwrap().expired_at, None);
        // VIP 索引不序列化（派生数据）——重建后与原状态一致。
        assert!(back.vip_index.is_empty(), "索引不进快照字节");
        back.reindex_vips();
        assert_eq!(back.vip_index, d.vip_index, "重建后索引一致");
    }

    /// M7 快照兼容性声明（如实断言）：DeviceRow 加字段（hostname/expired_at）后，
    /// **旧格式快照不可解码**——postcard 无字段标签，from_bytes 对旧字节干净失败
    /// （返回 None，节点从日志/重建路径恢复）。未发布窗口允许（§7-M7.1）；本测试
    /// 固化「失败必须干净」（不得 panic/半解码）：旧行编码字节与任意截断字节均 None。
    #[test]
    fn legacy_snapshot_bytes_fail_clean() {
        // 旧 DeviceRow 形状（无 hostname/expired_at）——postcard 编码镜像。
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
        // 旧行字节对新解码器是错位流（hostname 读不到合法 varint/长度）⇒ None。
        assert!(
            NetStateData::from_bytes(&legacy_row).is_none(),
            "旧格式字节必须干净失败（None）"
        );
        // 截断的新格式字节同样 None（不 panic、不半解码）。
        let fresh = NetStateData::new().to_bytes();
        assert!(NetStateData::from_bytes(&fresh[..fresh.len() - 1]).is_none());
        assert!(NetStateData::from_bytes(b"\x01\x00").is_none());
    }

    /// VIP 反查索引一致性：apply 维护（注册/兑换/吊销后行保留不删除）+ 全量重建
    /// 幂等 + 查询结果与全表扫描等价（M7：Expired 行不进索引——吊销行保留）。
    #[test]
    fn vip_index_consistency_across_apply_and_rebuild() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let mut d = bootstrapped(&root);
        // 注册 3 台 + 吊销 1 台（禁用不删除：行与 VIP 均保留 ⇒ 索引条目保留）。
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
        // 一致性：索引 ↔ devices 全表扫描（对每个 VIP 查询结果等价；条目数相等）。
        let expect: Vec<([u8; 4], [u8; 32])> = d
            .devices
            .iter()
            .filter(|(_, r)| r.status != DeviceStatus::Expired)
            .map(|(dev, row)| (row.vip, *dev))
            .collect();
        assert_eq!(
            d.vip_index.len(),
            expect.len(),
            "吊销不删行 ⇒ 索引不缩（Expired 排除）"
        );
        for (vip, dev) in &expect {
            assert_eq!(d.device_by_vip(vip), Some(*dev), "索引查询 = 全表扫描");
        }
        // 未分配 VIP ⇒ None。
        assert_eq!(d.device_by_vip(&[127, 0, 0, 1]), None);
        // 全量重建幂等且与增量维护结果一致。
        let incremental = d.vip_index.clone();
        d.reindex_vips();
        assert_eq!(d.vip_index, incremental, "重建 == 增量维护");
        // 序列化→反序列化→重建也一致（快照恢复路径）。
        let mut back = NetStateData::from_bytes(&d.to_bytes()).expect("roundtrip");
        back.reindex_vips();
        assert_eq!(back.vip_index, incremental, "快照往返后重建一致");
    }
}
