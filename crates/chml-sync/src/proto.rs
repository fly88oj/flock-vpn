//! NetState 写操作集与读查询（docs/design.md §3.10 接口；与 M2 单服 `NetState` trait
//! 语义对齐——见 app/chmlvpn-server/src/netstate.rs 的纪律注记）。
//!
//! 全部写操作 = [`SyncRequest`]，经 Raft 提交后由 [`crate::state::NetStateData::apply`]
//! 确定性执行。**admin_op（add_voter/rewrap/revoke_invite）与 server_keys 必须带集群根
//! 密钥签名**（[`RootSigned`]），状态机验签后生效（§4 准入红线 R19：被入侵的单台在册
//! 服务器没有根密钥，无法自授准入、无法触发 rewrap）。

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

/// serde 对 `[u8; 64]` 的手工桥（serde 内建数组 impl 只到 32）。
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

/// Raft 节点 ID（openraft NodeId = u64）。
pub type NodeId = u64;

/// VIP 池：`100.64.0.0/10`（RFC 6598，§2.1）。`100.64.0.1`–`100.64.0.10` 保留给服务器
/// 自身（多主形态每台服务器各一个 tun VIP——§6.2 拓扑：server-a/b/c = .1/.2/.3），
/// 设备分配从 `.11` 起（§6.2 客户端 VIP 100.64.0.11/.12/.13）。
pub const VIP_FIRST: u32 = u32::from_be_bytes([100, 64, 0, 11]);
/// 池末（/10 段最后一个可用地址）。
pub const VIP_LAST: u32 = u32::from_be_bytes([100, 127, 255, 254]);

/// 管理操作签名域分离标签（canonical 字节前缀）。
const L_ADMIN: &[u8] = b"chml-sync/admin/v1";
/// server_keys 签名域分离标签。
const L_SERVER_KEYS: &[u8] = b"ch-sync/server-keys/v1";
/// Bootstrap 自证签名域分离标签。
const L_BOOTSTRAP: &[u8] = b"chml-sync/bootstrap/v1";

// ============================================================================
// 行类型（与 M2 netstate.rs 同语义；M4 后续批次做服务器装配侧的 trait 收敛）
// ============================================================================

/// 设备状态（禁用不删除：行保留、VIP 不回收，§2.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatus {
    Active,
    Disabled,
    Revoked,
}

impl DeviceStatus {
    pub fn code(self) -> u8 {
        match self {
            DeviceStatus::Active => 1,
            DeviceStatus::Disabled => 2,
            DeviceStatus::Revoked => 3,
        }
    }
    pub fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(DeviceStatus::Active),
            2 => Some(DeviceStatus::Disabled),
            3 => Some(DeviceStatus::Revoked),
            _ => None,
        }
    }
}

/// 注册表设备行（§2.2：设备 = (DeviceId, owner, VIP, 静态公钥集, status)）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRow {
    pub owner: String,
    pub device_x25519: [u8; 32],
    pub device_ed25519: [u8; 32],
    pub vip: [u8; 4],
    pub status: DeviceStatus,
    /// 状态判定（禁用/吊销）生效的 revocation_epoch。
    pub since_epoch: u64,
}

/// 用户行：OPAQUE 注册记录 + SR-SIG1 用户公钥集（§2.4）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRow {
    pub opaque_record: Option<String>,
    pub opaque_profile: u16,
    pub sr_sig_pubs: Vec<[u8; 32]>,
}

/// 邀请状态（一次性凭据，§1.3.3f）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InviteStatus {
    Valid,
    Used,
    Revoked,
}

/// 邀请行。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteRow {
    pub expiry_unix: u64,
    pub status: InviteStatus,
}

/// 服务器密钥条目（server_keys 写操作记录；hybrid 1216B 以 Vec 承载）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerKeyEntry {
    pub server_id: NodeId,
    pub identity_pub: [u8; 32],
    pub hybrid_pub: Vec<u8>,
}

// ============================================================================
// 根签管理操作
// ============================================================================

/// 集群根密钥签名承载：`sig` 覆盖 `op` 的 canonical 字节（域分离见各 `*_canonical`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSigned<T> {
    pub op: T,
    #[serde(with = "arr64")]
    pub sig: [u8; 64],
}

/// admin_op 三形态（§3.10/§4：必须带集群根密钥签名，状态机验签后生效）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminOp {
    /// 新 voter 准入（与 openraft change_membership 联动，§4 准入流水）。
    AddVoter { node_id: NodeId },
    /// secrets rewrap：把逐服务器封装的共享秘密扩到新服务器（独立管理操作，§4-3）。
    Rewrap { server_id: NodeId, wrapped: Vec<u8> },
    /// 吊销未兑换邀请。
    RevokeInvite { invite_id: [u8; 16] },
}

/// [`AdminOp`] 的 canonical 字节（签名覆盖面；长度前缀定界，杜绝拼接歧义）。
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

/// server_keys 写操作的 canonical 字节。
pub fn server_keys_canonical(entries: &[ServerKeyEntry]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + entries.len() * 1280);
    v.extend_from_slice(L_SERVER_KEYS);
    v.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        v.extend_from_slice(&e.server_id.to_le_bytes());
        v.extend_from_slice(&e.identity_pub);
        v.extend_from_slice(&(e.hybrid_pub.len() as u32).to_le_bytes());
        v.extend_from_slice(&e.hybrid_pub);
    }
    v
}

/// Bootstrap 写操作的 canonical 字节（根密钥自证：root_pub 对这些字节的签名）。
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
// 写请求 / 响应
// ============================================================================

/// NetState 写操作（经 Raft 提交；§3.10 `NetState::{register_device, revoke,
/// allocate_ip, redeem_invite, revoke_invite, config_version, server_keys, rewrap,
/// admin_op}`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncRequest {
    /// 集群身份引导（首条管理写；只接受一次，幂等重放放行）：
    /// cluster_id + 集群根公钥 + 票据密钥根（32B 随机，**票据密钥根在 Raft 内**，§4）。
    /// `sig` = 根密钥对 [`bootstrap_canonical`] 的签名（自证）。
    Bootstrap {
        cluster_id: [u8; 16],
        root_pub: [u8; 32],
        ticket_root: [u8; 32],
        #[serde(with = "arr64")]
        sig: [u8; 64],
    },
    /// 注册设备（分配 VIP，单调不复用）。
    RegisterDevice {
        owner: String,
        x25519: [u8; 32],
        ed25519: [u8; 32],
    },
    /// 吊销设备：状态置 Revoked（行保留、VIP 不回收）+ 全局 revocation_epoch +1（§2.2）。
    Revoke { device: [u8; 32] },
    /// 禁用设备（不删除；epoch 同步推进，票据随之失效）。
    Disable { device: [u8; 32] },
    /// 重新启用（仅 Disabled → Active；Revoked 终态不可逆）。
    Enable { device: [u8; 32] },
    /// VIP 分配（单调水位；不回收）。
    AllocateIp,
    /// 邀请登记（签发侧与 InviteFile 同刻落库）。
    RecordInvite {
        invite_id: [u8; 16],
        expiry_unix: u64,
    },
    /// 邀请兑换（Raft 状态机内查重 + 吊销/expiry 检查 + 建用户/设备 + 分 VIP，单次提交
    /// 原子完成，§1.3.3f「邀请一生」）。
    RedeemInvite {
        invite_bytes: Vec<u8>,
        username: String,
        x25519: [u8; 32],
        ed25519: [u8; 32],
        now_unix: u64,
    },
    /// 设置用户口令记录（仅未设置时；控制流 PwCommit 的复制形态）。
    SetPassword {
        user: String,
        record_b64: String,
        profile: u16,
    },
    /// 登记 SR-SIG1 用户公钥（key-bind 路径的复制形态）。
    AddUserSigKey { user: String, pub32: [u8; 32] },
    /// bind_token 一次性消费（§2.4 线性一致查重的复制形态）。
    ConsumeBindToken { token: [u8; 16] },
    /// 网络配置版本推进（派生数据由状态机版本化，vpn-mesh §5.2）。
    BumpConfigVersion,
    /// 服务器密钥集登记/轮换（根签管理操作）。
    ServerKeys(RootSigned<Vec<ServerKeyEntry>>),
    /// 集群 OPRF key 登记（根签管理操作；OPAQUE 记录全网可验——§2.4「OPRF key 在
    /// Raft 状态机内」。幂等：同值重放放行，异值拒绝）。
    SetOprf(RootSigned<String>),
    /// admin_op（add_voter/rewrap/revoke_invite；根签管理操作，状态机验签后生效）。
    AdminOp(RootSigned<AdminOp>),
}

impl SyncRequest {
    /// 便捷构造：根密钥签名的 rewrap 管理操作。
    pub fn rewrap_signed(
        root: &ed25519_dalek::SigningKey,
        server_id: NodeId,
        wrapped: Vec<u8>,
    ) -> Self {
        let op = AdminOp::Rewrap { server_id, wrapped };
        let sig = root.sign(&admin_canonical(&op)).to_bytes();
        SyncRequest::AdminOp(RootSigned { op, sig })
    }

    /// 便捷构造：根密钥签名的 add_voter 管理操作。
    pub fn add_voter_signed(root: &ed25519_dalek::SigningKey, node_id: NodeId) -> Self {
        let op = AdminOp::AddVoter { node_id };
        let sig = root.sign(&admin_canonical(&op)).to_bytes();
        SyncRequest::AdminOp(RootSigned { op, sig })
    }

    /// 便捷构造：根密钥签名的 revoke_invite 管理操作。
    pub fn revoke_invite_signed(root: &ed25519_dalek::SigningKey, invite_id: [u8; 16]) -> Self {
        let op = AdminOp::RevokeInvite { invite_id };
        let sig = root.sign(&admin_canonical(&op)).to_bytes();
        SyncRequest::AdminOp(RootSigned { op, sig })
    }

    /// 便捷构造：根密钥签名的 server_keys 管理操作。
    pub fn server_keys_signed(
        root: &ed25519_dalek::SigningKey,
        entries: Vec<ServerKeyEntry>,
    ) -> Self {
        let sig = root.sign(&server_keys_canonical(&entries)).to_bytes();
        SyncRequest::ServerKeys(RootSigned { op: entries, sig })
    }

    /// 便捷构造：Bootstrap（根密钥自证签名）。
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

/// 状态机级拒绝（确定性：所有节点对同一日志条目产生同一拒绝，不发散）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateError {
    NotBootstrapped,
    AlreadyBootstrapped,
    BadRootSignature,
    RootMismatch,
    DeviceExists,
    DeviceNotFound,
    RevokedIsTerminal,
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
    /// 口令已设置（改密走登录态，未实现面）。
    PasswordExists,
    NoSuchUser,
    /// bind_token 已消费（一次性凭据重放）。
    BindTokenUsed,
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
        }
    }
}
impl std::error::Error for StateError {}

/// 客户端面错误（写转发/线性一致读路径；线格式承载 ForwardToLeader 语义）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncError {
    /// 本节点非 leader（`leader` = 已知 leader，可能为 None——选举中）。
    ForwardToLeader { leader: Option<NodeId> },
    /// 预算内未找到可用 leader。
    NoLeader,
    /// Raft 内部错误（致命/存储）。
    Raft(String),
    /// 互连调用失败。
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

/// admin_op 执行回执。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminAck {
    AddVoter {
        node_id: NodeId,
    },
    /// rewrap 落库后的封装字节数（OPRF key 副本可观测，§7-M4 admission 断言用）。
    Rewrap {
        server_id: NodeId,
        bytes: usize,
    },
    RevokeInvite,
}

/// 写操作产物。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncResponse {
    Ok,
    Device(DeviceRow),
    /// 吊销/禁用/启用后的全局 revocation_epoch（含未变化路径）。
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
    /// 状态机级拒绝（见 [`StateError`]）。
    Error(StateError),
}

// ============================================================================
// 读查询（线性一致读：ensure_linearizable 后 leader 侧执行）
// ============================================================================

/// 目录三态判定的线格式（`LookupVerdict` 的可序列化同构；§1.3.3c）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictW {
    NotFound,
    Revoked { since_epoch: u64 },
    Active { x25519: [u8; 32], ed25519: [u8; 32] },
}

impl VerdictW {
    /// 转协议库判定（损坏公钥按不可信处理 → NotFound，fail-closed）。
    pub fn to_verdict(&self) -> flock_protocol::session::LookupVerdict {
        use flock_protocol::session::{DeviceRecord, LookupVerdict};
        use ed25519_dalek::VerifyingKey;
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

    /// 由协议库判定转线格式。
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

/// 集群状态摘要（「无丢提交」/复制面断言用）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateView {
    pub epoch: u64,
    pub config_version: u64,
    pub devices: usize,
    pub revoked: usize,
    pub invites_used: usize,
    pub server_keys: usize,
    pub wraps: Vec<(NodeId, usize)>,
    pub voters: Vec<NodeId>,
    pub ticket_root_present: bool,
    pub last_applied: Option<u64>,
}

/// 线性一致读查询。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReadQuery {
    Lookup([u8; 32]),
    Epoch,
    DeviceRow([u8; 32]),
    /// 取某服务器的 rewrap 封装副本（服务器本地开封校验用）。
    Wrap(NodeId),
    /// 用户行（口令记录 + SR-SIG1 公钥集；控制面登录/验签用）。
    User(String),
    /// owner 名下全部设备（注册表操作 List 用）。
    DevicesOf(String),
    /// 全状态摘要（断言用）。
    State,
}

/// 线性一致读产物。
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
// 单元测试：canonical 字节的域分离与定界
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
        // 相同前缀不同长度的 wrapped 产物不同（长度定界）。
        let b = admin_canonical(&AdminOp::Rewrap {
            server_id: 7,
            wrapped: vec![1, 2, 0],
        });
        assert_ne!(a, b);
        // 不同 op tag 不同。
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
            _ => panic!("rewrap_signed 产 AdminOp"),
        };
        assert!(root
            .verifying_key()
            .verify(&admin_canonical(&op), &Signature::from_bytes(&sig))
            .is_ok());
        // 篡改 op ⇒ 验签失败。
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
