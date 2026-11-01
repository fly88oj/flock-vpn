//! 纯状态机数据：NetState 的确定性执行核（docs/design.md §3.10/§2.2 语义纪律）。
//!
//! 语义纪律（与 M2 单服 StateStore 一致，M4 = 同语义的 Raft 复制形态）：
//! - **VIP 100.64.0.0/10 单调分配**：`.1` 保留服务器自身，从 `.2` 起水位线只进不退
//!   ——**禁用不删除、IP 不复用**（§2.1，innernet 先例）。
//! - **invite_id 单次消费**：redeem 在同一状态转移内查重 + 标记（Raft 单次提交 = 原子）。
//! - **吊销推进全局 revocation_epoch**：仅阻断性转移（→Disabled/→Revoked）+1；
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
    pub fn lookup(&self, id: &[u8; 32]) -> VerdictW {
        match self.devices.get(id) {
            Some(row) => match row.status {
                DeviceStatus::Active => VerdictW::Active {
                    x25519: row.device_x25519,
                    ed25519: row.device_ed25519,
                },
                DeviceStatus::Disabled | DeviceStatus::Revoked => VerdictW::Revoked {
                    since_epoch: row.since_epoch,
                },
            },
            None => VerdictW::NotFound,
        }
    }

    /// 当前全局 revocation_epoch。
    pub fn epoch(&self) -> u64 {
        self.epoch
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
                .filter(|r| r.status != DeviceStatus::Active)
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
            } => self.apply_register(owner, *x25519, *ed25519),
            SyncRequest::Revoke { device } => self.apply_set_status(device, DeviceStatus::Revoked),
            SyncRequest::Disable { device } => {
                self.apply_set_status(device, DeviceStatus::Disabled)
            }
            SyncRequest::Enable { device } => self.apply_set_status(device, DeviceStatus::Active),
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
                now_unix,
            } => self.apply_redeem(invite_bytes, username, *x25519, *ed25519, *now_unix),
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
        let l_oprf: &[u8] = b"chml-sync/set-oprf/v1";
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

    fn apply_register(&mut self, owner: &str, x25519: [u8; 32], ed25519: [u8; 32]) -> ApplyOutcome {
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
        };
        self.devices.insert(device_id, row.clone());
        ApplyOutcome::ok(SyncResponse::Device(row))
    }

    fn apply_set_status(&mut self, device: &[u8; 32], status: DeviceStatus) -> ApplyOutcome {
        let Some(row) = self.devices.get_mut(device) else {
            return ApplyOutcome::err(StateError::DeviceNotFound);
        };
        if row.status == DeviceStatus::Revoked && status != DeviceStatus::Revoked {
            return ApplyOutcome::err(StateError::RevokedIsTerminal);
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

    fn apply_redeem(
        &mut self,
        invite_bytes: &[u8],
        username: &str,
        x25519: [u8; 32],
        ed25519: [u8; 32],
        now_unix: u64,
    ) -> ApplyOutcome {
        // 根签名/结构校验 + 本集群身份钉死，先于任何状态触碰（同 M2）。
        let Some(cluster) = self.cluster.clone() else {
            return ApplyOutcome::err(StateError::NotBootstrapped);
        };
        let invite = match chml_protocol::trust::InviteFile::from_bytes(invite_bytes) {
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
            },
        );
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

    /// VIP 水位分配（单调 +1；首分配 [`VIP_FIRST`]，越 [`VIP_LAST`] 即耗尽）。
    fn alloc_vip(&mut self) -> Result<[u8; 4], StateError> {
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
                    ed25519: [1; 32]
                },
                None
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
    }

    #[test]
    fn redeem_single_consumption_and_epoch_rules() {
        let root = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let mut d = bootstrapped(&root);
        // 邀请 fixture（根签 v3）。
        let entry = chml_protocol::session::ServerEntry {
            server_id: chml_protocol::session::ServerId([1; 16]),
            relay_endpoint: "127.0.0.1:9443".into(),
            identity_pub: ed25519_dalek::SigningKey::from_bytes(&[5; 32]).verifying_key(),
            static_hybrid_pub: chml_protocol::kem::HybridKeypair::generate(
                &mut chml_protocol::rand::rngs::OsRng,
            )
            .public(),
        };
        let inv = chml_protocol::trust::InviteFile::issue(
            &root,
            chml_protocol::session::ClusterId([7; 16]),
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
            },
            None,
        );
        let bytes = d.to_bytes();
        let back = NetStateData::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(back.devices.len(), 1);
        assert_eq!(back.epoch, d.epoch);
        assert_eq!(back.ticket_root, d.ticket_root);
    }
}
