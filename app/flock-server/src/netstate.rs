//! 单服 NetState：注册表/邀请/VIP 分配的强一致本地状态机（docs/design.md §3.11 / §7-M2）。
//!
//! **接口与 M4 `chml-sync` 对齐**（§3.10 `NetState::{register_device, revoke, allocate_ip,
//! redeem_invite, revoke_invite, …}`）：本模块定义 [`NetState`] trait，redb 单机版
//! [`StateStore`] 为 M2 唯一实现；M4 落地时 openraft 状态机实现同一 trait，装配点零改动。
//! 语义纪律（§2.1/§1.3.3f，M4 同样成立）：
//!
//! - **VIP 100.64.0.0/10 池单调分配**：`100.64.0.1` 保留给服务器自身，从 `.2` 起单调递增，
//!   **禁用不删除、IP 不复用**（innernet 先例，§2.1）——回收靠高位水位线永不动。
//! - **邀请一次性**：`redeem_invite` = 查重（used ⇒ 拒）+ 吊销检查 + expiry 检查 →
//!   同一事务内标记 used + 建用户/设备 + 分 VIP（§1.3.3f「邀请一生」；M2 的单机事务 =
//!   M4 Raft 状态机内的原子提交）。
//! - **吊销推进全局 revocation_epoch**（§2.2 吊销传播界）：每次 revoke/disable 单调 +1，
//!   票据层以「票据 epoch < 当前 epoch 即拒」消费它。
//! - redb 单文件嵌入、单写者（服务进程独占写；CLI/管理操作经 admin 端点进入本进程，
//!   见 `admin.rs`——避免多进程写者）。

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

use flock_protocol::session::{DeviceId, DeviceRecord, LookupVerdict};
use flock_protocol::{ed25519_dalek, x25519_dalek};
use ed25519_dalek::VerifyingKey;
use futures::future::BoxFuture;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use sha2::{Digest, Sha256};

/// 设备表：DeviceId(32B) → DeviceRow。
const DEVICES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("devices");
/// 用户表：username → UserRow（OPAQUE 记录 + SR-SIG1 公钥集）。
const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
/// 邀请表：invite_id(16B) → InviteRow（一次性消费凭据，§1.3.3f）。
const INVITES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("invites");
/// bind_token 一次性消费表（§2.4：控制面关键一次性操作的线性一致查重）。
const BIND_TOKENS: TableDefinition<&[u8], ()> = TableDefinition::new("bind_tokens");
/// 杂项 KV（epoch/vip 水位；server.rs 的集群身份材料也住这里）。
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// VIP 池：`100.64.0.0/10`（RFC 6598，§2.1）；`.1` 保留给服务器自身（§2.2「服务端自身
/// 也是 peer，VIP 100.64.0.1」），分配从 `.2` 起。
pub const VIP_FIRST: u32 = u32::from_be_bytes([100, 64, 0, 2]);
/// 池末（/10 段的最后一个可用地址）。
pub const VIP_LAST: u32 = u32::from_be_bytes([100, 127, 255, 254]);

/// 设备状态（禁用不删除：行保留、VIP 不回收，§2.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Disabled,
    Revoked,
}

impl DeviceStatus {
    fn code(self) -> u8 {
        match self {
            DeviceStatus::Active => 1,
            DeviceStatus::Disabled => 2,
            DeviceStatus::Revoked => 3,
        }
    }

    fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(DeviceStatus::Active),
            2 => Some(DeviceStatus::Disabled),
            3 => Some(DeviceStatus::Revoked),
            _ => None,
        }
    }
}

/// 注册表设备行（§2.2 设备 = (DeviceId, owner, VIP, 静态公钥集, status)）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub owner: String,
    pub device_x25519: [u8; 32],
    pub device_ed25519: [u8; 32],
    pub vip: [u8; 4],
    pub status: DeviceStatus,
    /// 状态判定（禁用/吊销）生效的 revocation_epoch。
    pub since_epoch: u64,
}

/// 用户行：OPAQUE 注册记录（账号口令）+ SR-SIG1 用户公钥集。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserRow {
    pub opaque_record: Option<String>,
    pub opaque_profile: u16,
    pub sr_sig_pubs: Vec<[u8; 32]>,
}

/// 邀请行（一次性凭据，§1.3.3f）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteStatus {
    Valid,
    Used,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteRow {
    pub expiry_unix: u64,
    pub status: InviteStatus,
}

/// `redeem_invite` 拒绝原因（接口契约级：三态一次性语义各自的判定，§7-M2 开户测试逐项断言）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedeemError {
    /// 同 invite_id 二次兑换（已标记 used）。
    AlreadyUsed,
    /// `revoke_invite` 后。
    InviteRevoked,
    /// expiry 检查失败（携带双方时刻）。
    Expired { now_unix: u64, expiry_unix: u64 },
    /// 服务端不认识该 invite_id（非本集群签发/未登记）。
    Unknown,
    /// 根签名/结构校验失败。
    BadInvite(String),
    /// 用户名已被占用。
    UserExists,
    /// 设备已注册。
    DeviceExists,
    /// VIP 池耗尽。
    IpExhausted,
    /// 内部错误（IO/编码）。
    Internal(String),
}

impl std::fmt::Display for RedeemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedeemError::AlreadyUsed => write!(f, "invite already redeemed"),
            RedeemError::InviteRevoked => write!(f, "invite revoked"),
            RedeemError::Expired {
                now_unix,
                expiry_unix,
            } => {
                write!(f, "invite expired (now={now_unix}, expiry={expiry_unix})")
            }
            RedeemError::Unknown => write!(f, "unknown invite_id"),
            RedeemError::BadInvite(m) => write!(f, "bad invite: {m}"),
            RedeemError::UserExists => write!(f, "username already exists"),
            RedeemError::DeviceExists => write!(f, "device already registered"),
            RedeemError::IpExhausted => write!(f, "VIP pool exhausted"),
            RedeemError::Internal(m) => write!(f, "internal: {m}"),
        }
    }
}

/// 兑换入参（设备公钥随兑换入注册表，§1.3.3f 开户流程）。
///
/// `expected_root_pub`/`expected_cluster_id` = 本集群的身份（调用方从 ServerCore 注入）：
/// 邀请文件自洽（内嵌根公钥可验自己的签名）**不够**——必须钉死「这个根签的」才算本集群
/// 邀请（防攻击者自签一套根 + 凭据兑换开户）。
pub struct RedeemRequest<'a> {
    pub invite_bytes: &'a [u8],
    pub username: &'a str,
    pub device_x25519: [u8; 32],
    pub device_ed25519: [u8; 32],
    pub expected_root_pub: [u8; 32],
    pub expected_cluster_id: [u8; 16],
    pub now_unix: u64,
}

/// 兑换产物。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemOutcome {
    pub username: String,
    pub device_id: [u8; 32],
    pub vip: [u8; 4],
}

/// 写操作错误。
#[derive(Debug)]
pub enum NetError {
    NotFound,
    InvalidState(String),
    IpExhausted,
    Internal(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::NotFound => write!(f, "netstate: not found"),
            NetError::InvalidState(m) => write!(f, "netstate: invalid state: {m}"),
            NetError::IpExhausted => write!(f, "netstate: VIP pool exhausted"),
            NetError::Internal(m) => write!(f, "netstate: internal: {m}"),
        }
    }
}

/// NetState：注册表/邀请/VIP 的强一致写读面（§3.10 接口对齐；M4 = 同 trait 的 Raft 实现）。
pub trait NetState: Send + Sync + 'static {
    /// 注册设备（分配 VIP，单调不复用）。
    fn register_device(
        &self,
        owner: &str,
        x25519: [u8; 32],
        ed25519: [u8; 32],
    ) -> Result<DeviceRow, NetError>;
    /// 吊销设备：状态置 Revoked（行保留、VIP 不回收）+ 全局 revocation_epoch +1（§2.2）。
    fn revoke(&self, id: &DeviceId) -> Result<u64, NetError>;
    /// 禁用设备（不删除；epoch 同步推进，票据随之失效）。
    fn disable(&self, id: &DeviceId) -> Result<u64, NetError>;
    /// 重新启用（仅 Disabled → Active；Revoked 终态不可逆）。
    fn enable(&self, id: &DeviceId) -> Result<(), NetError>;
    /// 目录三态查询（session::DeviceDirectory 的数据源）。
    fn lookup(&self, id: &DeviceId) -> LookupVerdict;
    /// 注册表行查询（断言/管理面）。
    fn device_row(&self, id: &DeviceId) -> Option<DeviceRow>;
    /// owner 名下全部设备。
    fn devices_of(&self, owner: &str) -> Vec<(DeviceId, DeviceRow)>;
    /// VIP 分配（单调水位；不回收）。
    fn allocate_ip(&self) -> Result<Ipv4Addr, NetError>;
    /// 邀请兑换（查重+吊销+expiry → 建用户/设备+分 VIP，单事务）。
    fn redeem_invite(&self, req: RedeemRequest<'_>) -> Result<RedeemOutcome, RedeemError>;
    /// 吊销未兑换邀请。
    fn revoke_invite(&self, invite_id: &[u8; 16]) -> Result<(), NetError>;
    /// 当前全局 revocation_epoch。
    fn epoch(&self) -> u64;
    // —— 用户面（OPAQUE 记录 + SR-SIG1 公钥集）——
    /// 设置口令记录（仅未设置时；改密走登录态，M2 外）。
    fn set_password(&self, user: &str, record_b64: &str, profile: u16) -> Result<(), NetError>;
    /// 取口令记录。
    fn password(&self, user: &str) -> Option<(String, u16)>;
    /// 登记 SR-SIG1 用户公钥（key-bind 路径）。
    fn add_user_sig_key(&self, user: &str, pub32: [u8; 32]) -> Result<(), NetError>;
    /// SR-SIG1 验签公钥集。
    fn user_sig_pubs(&self, user: &str) -> Vec<VerifyingKey>;
    /// bind_token 一次性消费（§2.4 线性一致查重；false = 已用过）。
    fn consume_bind_token(&self, token: &[u8; 16]) -> bool;
}

// ============================================================================
// 行编解码（定长手动编解码：字段的字节级布局即存储契约）
// ============================================================================

fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_str(v: &mut Vec<u8>, s: &str) {
    put_u16(v, s.len() as u16);
    v.extend_from_slice(s.as_bytes());
}

struct RowRd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> RowRd<'a> {
    fn new(b: &'a [u8]) -> Self {
        RowRd { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|s| u16::from_le_bytes(s.try_into().expect("2B")))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|s| u64::from_le_bytes(s.try_into().expect("8B")))
    }
    fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32).map(|s| s.try_into().expect("32B"))
    }
    fn str(&mut self) -> Option<String> {
        let n = self.u16()? as usize;
        let s = self.take(n)?;
        String::from_utf8(s.to_vec()).ok()
    }
    fn done(&self) -> bool {
        self.pos == self.b.len()
    }
}

fn encode_device(row: &DeviceRow) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + row.owner.len() + 86);
    put_str(&mut v, &row.owner);
    v.extend_from_slice(&row.device_x25519);
    v.extend_from_slice(&row.device_ed25519);
    v.extend_from_slice(&row.vip);
    v.push(row.status.code());
    put_u64(&mut v, row.since_epoch);
    v
}

fn decode_device(b: &[u8]) -> Option<DeviceRow> {
    let mut r = RowRd::new(b);
    let owner = r.str()?;
    let device_x25519 = r.arr32()?;
    let device_ed25519 = r.arr32()?;
    let vip: [u8; 4] = r.take(4)?.try_into().expect("4B");
    let status = DeviceStatus::from_code(r.u8()?)?;
    let since_epoch = r.u64()?;
    if !r.done() {
        return None;
    }
    Some(DeviceRow {
        owner,
        device_x25519,
        device_ed25519,
        vip,
        status,
        since_epoch,
    })
}

fn encode_user(row: &UserRow) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    match &row.opaque_record {
        Some(rec) => {
            v.push(1);
            put_str(&mut v, rec);
            put_u16(&mut v, row.opaque_profile);
        }
        None => v.push(0),
    }
    put_u16(&mut v, row.sr_sig_pubs.len() as u16);
    for k in &row.sr_sig_pubs {
        v.extend_from_slice(k);
    }
    v
}

fn decode_user(b: &[u8]) -> Option<UserRow> {
    let mut r = RowRd::new(b);
    let (opaque_record, opaque_profile) = match r.u8()? {
        0 => (None, 0),
        1 => {
            let rec = r.str()?;
            let p = r.u16()?;
            (Some(rec), p)
        }
        _ => return None,
    };
    let n = r.u16()? as usize;
    let mut sr_sig_pubs = Vec::with_capacity(n);
    for _ in 0..n {
        sr_sig_pubs.push(r.arr32()?);
    }
    if !r.done() {
        return None;
    }
    Some(UserRow {
        opaque_record,
        opaque_profile,
        sr_sig_pubs,
    })
}

fn encode_invite(row: &InviteRow) -> Vec<u8> {
    let mut v = Vec::with_capacity(9);
    v.push(match row.status {
        InviteStatus::Valid => 1,
        InviteStatus::Used => 2,
        InviteStatus::Revoked => 3,
    });
    put_u64(&mut v, row.expiry_unix);
    v
}

fn decode_invite(b: &[u8]) -> Option<InviteRow> {
    let mut r = RowRd::new(b);
    let status = match r.u8()? {
        1 => InviteStatus::Valid,
        2 => InviteStatus::Used,
        3 => InviteStatus::Revoked,
        _ => return None,
    };
    let expiry_unix = r.u64()?;
    if !r.done() {
        return None;
    }
    Some(InviteRow {
        expiry_unix,
        status,
    })
}

// ============================================================================
// redb 实现
// ============================================================================

fn int_err(e: impl std::fmt::Display) -> NetError {
    NetError::Internal(format!("redb: {e}"))
}

fn internal(e: impl std::fmt::Display) -> RedeemError {
    RedeemError::Internal(format!("redb: {e}"))
}

fn meta_u64(meta: &redb::Table<'_, &str, &[u8]>, key: &str) -> Result<u64, redb::StorageError> {
    Ok(meta
        .get(key)?
        .and_then(|v| v.value().try_into().ok().map(u64::from_be_bytes))
        .unwrap_or(0))
}

/// redb 单机状态机（单写者 = 服务进程；`Arc` 共享给会话/控制/admin 任务）。
pub struct StateStore {
    db: Database,
}

impl std::fmt::Debug for StateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateStore").finish_non_exhaustive()
    }
}

impl StateStore {
    /// 打开/创建状态库（文件不存在则创建空库）。
    pub fn open(path: &Path) -> Result<Self, NetError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| NetError::Internal(format!("state dir {}: {e}", dir.display())))?;
        }
        let db = Database::create(path)
            .map_err(|e| NetError::Internal(format!("redb open {}: {e}", path.display())))?;
        let txn = db
            .begin_write()
            .map_err(|e| NetError::Internal(format!("redb tx: {e}")))?;
        {
            let _ = txn.open_table(DEVICES).map_err(int_err)?;
            let _ = txn.open_table(USERS).map_err(int_err)?;
            let _ = txn.open_table(INVITES).map_err(int_err)?;
            let _ = txn.open_table(BIND_TOKENS).map_err(int_err)?;
            let _ = txn.open_table(META).map_err(int_err)?;
        }
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(StateStore { db })
    }

    /// META 读（server.rs 的集群身份材料住这里）。
    pub fn meta_get(&self, key: &str) -> Option<Vec<u8>> {
        let txn = self.db.begin_read().ok()?;
        let t = txn.open_table(META).ok()?;
        t.get(key).ok().flatten().map(|v| v.value().to_vec())
    }

    /// META 写（bootstrap 一次性写；运行期只读）。
    pub fn meta_put(&self, key: &str, val: &[u8]) -> Result<(), NetError> {
        let txn = self.db.begin_write().map_err(int_err)?;
        {
            let mut t = txn.open_table(META).map_err(int_err)?;
            t.insert(key, val).map_err(int_err)?;
        }
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(())
    }

    /// 邀请登记（签发侧：mint 时与 InviteFile 同刻落库）。
    pub fn record_invite(&self, invite_id: &[u8; 16], expiry_unix: u64) -> Result<(), NetError> {
        let txn = self.db.begin_write().map_err(int_err)?;
        {
            let mut t = txn.open_table(INVITES).map_err(int_err)?;
            let row = InviteRow {
                expiry_unix,
                status: InviteStatus::Valid,
            };
            t.insert(invite_id.as_slice(), encode_invite(&row).as_slice())
                .map_err(int_err)?;
        }
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(())
    }

    /// VIP 水位分配（事务内单调 +1；首分配缺省 [`VIP_FIRST`]，越 [`VIP_LAST`] 即耗尽）。
    fn alloc_vip_tx(meta: &mut redb::Table<'_, &str, &[u8]>) -> Result<u32, RedeemError> {
        let cur = meta
            .get("vip_next")
            .map_err(internal)?
            .and_then(|v| v.value().try_into().ok().map(u32::from_be_bytes))
            .unwrap_or(VIP_FIRST);
        if cur > VIP_LAST {
            return Err(RedeemError::IpExhausted);
        }
        meta.insert("vip_next", (cur + 1).to_be_bytes().as_slice())
            .map_err(internal)?;
        Ok(cur)
    }

    fn set_device_status(
        &self,
        id: &DeviceId,
        status: DeviceStatus,
    ) -> Result<(DeviceRow, u64), NetError> {
        let txn = self.db.begin_write().map_err(int_err)?;
        let ret: Result<(DeviceRow, u64), NetError> = {
            let mut devices = txn.open_table(DEVICES).map_err(int_err)?;
            let mut meta = txn.open_table(META).map_err(int_err)?;
            let raw = devices
                .get(id.0.as_slice())
                .map_err(int_err)?
                .ok_or(NetError::NotFound)?
                .value()
                .to_vec();
            let mut row = decode_device(&raw)
                .ok_or_else(|| NetError::Internal(format!("corrupt device row for {id}")))?;
            if row.status == DeviceStatus::Revoked {
                return Err(NetError::InvalidState("revoked is terminal".into()));
            }
            if row.status != status {
                // 仅「阻断性」转移（→ Disabled/Revoked）推进全局 revocation_epoch（§2.2）；
                // Enable（→ Active）是恢复，不动 epoch——否则会无害地废掉全网在途票据。
                if status != DeviceStatus::Active {
                    let epoch = meta_u64(&meta, "epoch").map_err(int_err)? + 1;
                    meta.insert("epoch", epoch.to_be_bytes().as_slice())
                        .map_err(int_err)?;
                    row.since_epoch = epoch;
                }
                row.status = status;
                devices
                    .insert(id.0.as_slice(), encode_device(&row).as_slice())
                    .map_err(int_err)?;
            }
            let epoch = meta_u64(&meta, "epoch").map_err(int_err)?;
            Ok((row, epoch))
        };
        let out = ret?;
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(out)
    }

    /// 兑换的邀请校验 + 建账（一个写事务：原子性 = M4 Raft 单次提交的本地对应物）。
    fn redeem_tx(
        &self,
        invite_id: [u8; 16],
        req: RedeemRequest<'_>,
        device_id: [u8; 32],
    ) -> Result<RedeemOutcome, RedeemError> {
        let txn = self.db.begin_write().map_err(internal)?;
        let out = {
            let mut invites = txn.open_table(INVITES).map_err(internal)?;
            let mut users = txn.open_table(USERS).map_err(internal)?;
            let mut devices = txn.open_table(DEVICES).map_err(internal)?;
            let mut meta = txn.open_table(META).map_err(internal)?;

            let raw = invites
                .get(invite_id.as_slice())
                .map_err(internal)?
                .ok_or(RedeemError::Unknown)?
                .value()
                .to_vec();
            let row = decode_invite(&raw)
                .ok_or_else(|| RedeemError::Internal("corrupt invite row".into()))?;
            // 一次性三判定（§7-M2 开户测试逐一断言）。
            match row.status {
                InviteStatus::Used => return Err(RedeemError::AlreadyUsed),
                InviteStatus::Revoked => return Err(RedeemError::InviteRevoked),
                InviteStatus::Valid => {}
            }
            // 过期判定以库内行（签发侧登记的 expiry）为准。
            if req.now_unix >= row.expiry_unix {
                return Err(RedeemError::Expired {
                    now_unix: req.now_unix,
                    expiry_unix: row.expiry_unix,
                });
            }
            if devices
                .get(device_id.as_slice())
                .map_err(internal)?
                .is_some()
            {
                return Err(RedeemError::DeviceExists);
            }
            // 建用户（不存在时）。
            if users.get(req.username).map_err(internal)?.is_some() {
                return Err(RedeemError::UserExists);
            }
            users
                .insert(req.username, encode_user(&UserRow::default()).as_slice())
                .map_err(internal)?;

            // VIP 单调分配（禁用不删除、不复用：水位线只进不退，§2.1）。
            let vip = Self::alloc_vip_tx(&mut meta)?.to_be_bytes();

            let dev_row = DeviceRow {
                owner: req.username.to_string(),
                device_x25519: req.device_x25519,
                device_ed25519: req.device_ed25519,
                vip,
                status: DeviceStatus::Active,
                since_epoch: 0,
            };
            devices
                .insert(device_id.as_slice(), encode_device(&dev_row).as_slice())
                .map_err(internal)?;

            // 标记 used（同事务：查重与标记间无窗口）。
            invites
                .insert(
                    invite_id.as_slice(),
                    encode_invite(&InviteRow {
                        expiry_unix: row.expiry_unix,
                        status: InviteStatus::Used,
                    })
                    .as_slice(),
                )
                .map_err(internal)?;

            RedeemOutcome {
                username: req.username.to_string(),
                device_id,
                vip,
            }
        };
        txn.commit()
            .map_err(|e| RedeemError::Internal(format!("redb commit: {e}")))?;
        Ok(out)
    }
}

impl NetState for StateStore {
    fn register_device(
        &self,
        owner: &str,
        x25519: [u8; 32],
        ed25519: [u8; 32],
    ) -> Result<DeviceRow, NetError> {
        let device_id: [u8; 32] = Sha256::digest(ed25519).into();
        let txn = self.db.begin_write().map_err(int_err)?;
        let out = {
            let mut devices = txn.open_table(DEVICES).map_err(int_err)?;
            let mut users = txn.open_table(USERS).map_err(int_err)?;
            let mut meta = txn.open_table(META).map_err(int_err)?;
            if devices
                .get(device_id.as_slice())
                .map_err(int_err)?
                .is_some()
            {
                return Err(NetError::InvalidState("device already registered".into()));
            }
            if users.get(owner).map_err(int_err)?.is_none() {
                users
                    .insert(owner, encode_user(&UserRow::default()).as_slice())
                    .map_err(int_err)?;
            }
            let cur = Self::alloc_vip_tx(&mut meta).map_err(|e| match e {
                RedeemError::IpExhausted => NetError::IpExhausted,
                RedeemError::Internal(m) => NetError::Internal(m),
                other => NetError::Internal(other.to_string()),
            })?;
            let row = DeviceRow {
                owner: owner.to_string(),
                device_x25519: x25519,
                device_ed25519: ed25519,
                vip: cur.to_be_bytes(),
                status: DeviceStatus::Active,
                since_epoch: 0,
            };
            devices
                .insert(device_id.as_slice(), encode_device(&row).as_slice())
                .map_err(int_err)?;
            row
        };
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(out)
    }

    fn revoke(&self, id: &DeviceId) -> Result<u64, NetError> {
        self.set_device_status(id, DeviceStatus::Revoked)
            .map(|(_, epoch)| epoch)
    }

    fn disable(&self, id: &DeviceId) -> Result<u64, NetError> {
        self.set_device_status(id, DeviceStatus::Disabled)
            .map(|(_, epoch)| epoch)
    }

    fn enable(&self, id: &DeviceId) -> Result<(), NetError> {
        self.set_device_status(id, DeviceStatus::Active).map(|_| ())
    }

    fn lookup(&self, id: &DeviceId) -> LookupVerdict {
        match self.device_row(id) {
            Some(row) => match row.status {
                DeviceStatus::Active => {
                    let (x, ed) = (row.device_x25519, row.device_ed25519);
                    match (
                        x25519_dalek::PublicKey::from(x),
                        VerifyingKey::from_bytes(&ed),
                    ) {
                        (device_x25519, Ok(device_ed25519)) => {
                            LookupVerdict::Active(DeviceRecord {
                                device_x25519,
                                device_ed25519,
                            })
                        }
                        // 行损坏按不可信处理（fail-closed，同 NotFound 外形）。
                        _ => LookupVerdict::NotFound,
                    }
                }
                DeviceStatus::Disabled | DeviceStatus::Revoked => LookupVerdict::Revoked {
                    since_epoch: row.since_epoch,
                },
            },
            None => LookupVerdict::NotFound,
        }
    }

    fn device_row(&self, id: &DeviceId) -> Option<DeviceRow> {
        let txn = self.db.begin_read().ok()?;
        let t = txn.open_table(DEVICES).ok()?;
        let raw = t.get(id.0.as_slice()).ok()??;
        decode_device(raw.value())
    }

    fn devices_of(&self, owner: &str) -> Vec<(DeviceId, DeviceRow)> {
        let mut out = Vec::new();
        let Ok(txn) = self.db.begin_read() else {
            return out;
        };
        let Ok(t) = txn.open_table(DEVICES) else {
            return out;
        };
        let Ok(iter) = t.iter() else { return out };
        for e in iter.flatten() {
            let Ok(idb) = <[u8; 32]>::try_from(e.0.value()) else {
                continue;
            };
            let bytes = e.1.value().to_vec();
            if let Some(row) = decode_device(&bytes) {
                if row.owner == owner {
                    out.push((DeviceId(idb), row));
                }
            }
        }
        out
    }

    fn allocate_ip(&self) -> Result<Ipv4Addr, NetError> {
        let txn = self.db.begin_write().map_err(int_err)?;
        let out = {
            let mut meta = txn.open_table(META).map_err(int_err)?;
            let cur = Self::alloc_vip_tx(&mut meta).map_err(|e| match e {
                RedeemError::IpExhausted => NetError::IpExhausted,
                RedeemError::Internal(m) => NetError::Internal(m),
                other => NetError::Internal(other.to_string()),
            })?;
            Ipv4Addr::from(cur)
        };
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(out)
    }

    fn redeem_invite(&self, req: RedeemRequest<'_>) -> Result<RedeemOutcome, RedeemError> {
        let device_id: [u8; 32] = Sha256::digest(req.device_ed25519).into();
        // 根签名/结构校验 + 本集群身份钉死，先于任何状态触碰。
        let invite = flock_protocol::trust::InviteFile::from_bytes(req.invite_bytes)
            .map_err(|e| RedeemError::BadInvite(e.to_string()))?;
        if !invite.verify() {
            return Err(RedeemError::BadInvite("root signature mismatch".into()));
        }
        if *invite.cluster_root_pub.as_bytes() != req.expected_root_pub
            || invite.directory.cluster_id.0 != req.expected_cluster_id
        {
            return Err(RedeemError::BadInvite(
                "invite not signed by this cluster's root".into(),
            ));
        }
        self.redeem_tx(invite.invite_id, req, device_id)
    }

    fn revoke_invite(&self, invite_id: &[u8; 16]) -> Result<(), NetError> {
        let txn = self.db.begin_write().map_err(int_err)?;
        {
            let mut t = txn.open_table(INVITES).map_err(int_err)?;
            let raw = t
                .get(invite_id.as_slice())
                .map_err(int_err)?
                .ok_or(NetError::NotFound)?
                .value()
                .to_vec();
            let mut row = decode_invite(&raw)
                .ok_or_else(|| NetError::Internal("corrupt invite row".into()))?;
            if row.status == InviteStatus::Used {
                return Err(NetError::InvalidState("already redeemed".into()));
            }
            row.status = InviteStatus::Revoked;
            t.insert(invite_id.as_slice(), encode_invite(&row).as_slice())
                .map_err(int_err)?;
        }
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(())
    }

    fn epoch(&self) -> u64 {
        self.meta_get("epoch")
            .and_then(|v| v.try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0)
    }

    fn set_password(&self, user: &str, record_b64: &str, profile: u16) -> Result<(), NetError> {
        let txn = self.db.begin_write().map_err(int_err)?;
        {
            let mut users = txn.open_table(USERS).map_err(int_err)?;
            let raw = users
                .get(user)
                .map_err(int_err)?
                .ok_or(NetError::NotFound)?
                .value()
                .to_vec();
            let mut row =
                decode_user(&raw).ok_or_else(|| NetError::Internal("corrupt user row".into()))?;
            if row.opaque_record.is_some() {
                return Err(NetError::InvalidState("password already set".into()));
            }
            row.opaque_record = Some(record_b64.to_string());
            row.opaque_profile = profile;
            users
                .insert(user, encode_user(&row).as_slice())
                .map_err(int_err)?;
        }
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(())
    }

    fn password(&self, user: &str) -> Option<(String, u16)> {
        let txn = self.db.begin_read().ok()?;
        let t = txn.open_table(USERS).ok()?;
        let raw = t.get(user).ok()??;
        let row = decode_user(raw.value())?;
        row.opaque_record.map(|r| (r, row.opaque_profile))
    }

    fn add_user_sig_key(&self, user: &str, pub32: [u8; 32]) -> Result<(), NetError> {
        let txn = self.db.begin_write().map_err(int_err)?;
        {
            let mut users = txn.open_table(USERS).map_err(int_err)?;
            let raw = users
                .get(user)
                .map_err(int_err)?
                .ok_or(NetError::NotFound)?
                .value()
                .to_vec();
            let mut row =
                decode_user(&raw).ok_or_else(|| NetError::Internal("corrupt user row".into()))?;
            if !row.sr_sig_pubs.contains(&pub32) {
                row.sr_sig_pubs.push(pub32);
            }
            users
                .insert(user, encode_user(&row).as_slice())
                .map_err(int_err)?;
        }
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(())
    }

    fn user_sig_pubs(&self, user: &str) -> Vec<VerifyingKey> {
        let Ok(txn) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(t) = txn.open_table(USERS) else {
            return Vec::new();
        };
        let Some(raw) = t.get(user).ok().flatten() else {
            return Vec::new();
        };
        let Some(row) = decode_user(raw.value()) else {
            return Vec::new();
        };
        row.sr_sig_pubs
            .iter()
            .filter_map(|k| VerifyingKey::from_bytes(k).ok())
            .collect()
    }

    fn consume_bind_token(&self, token: &[u8; 16]) -> bool {
        let Ok(txn) = self.db.begin_write() else {
            return false;
        };
        {
            let Ok(mut t) = txn.open_table(BIND_TOKENS) else {
                return false;
            };
            if t.get(token.as_slice()).ok().flatten().is_some() {
                return false; // 已消费（判定读，不 commit）
            }
            if t.insert(token.as_slice(), ()).is_err() {
                return false;
            }
        }
        txn.commit().map(|_| true).unwrap_or(false)
    }
}

/// session::DeviceDirectory 适配（respond 侧注入，§3.5 lookup 接缝）。
pub struct DirAdapter(pub Arc<StateStore>);

impl flock_protocol::session::DeviceDirectory for DirAdapter {
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict> {
        let v = NetState::lookup(&*self.0, id);
        Box::pin(async move { v })
    }
}

// ============================================================================
// 单元测试：邀请一次性三态 / VIP 池纪律 / 禁用不删除
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use flock_protocol::session::{ClusterId, ServerEntry, ServerId};
    use flock_protocol::trust::InviteFile;
    use flock_protocol::{rand, sig::UserKey};
    use ed25519_dalek::SigningKey;

    fn store() -> StateStore {
        let dir = tempfile::tempdir().expect("tmp");
        StateStore::open(&dir.path().join("netstate.redb")).expect("open")
    }

    fn invite_fixture(root: &SigningKey, expiry_unix: u64, invite_id: [u8; 16]) -> Vec<u8> {
        let entry = ServerEntry {
            server_id: ServerId([7; 16]),
            relay_endpoint: "127.0.0.1:9443".into(),
            identity_pub: SigningKey::from_bytes(&[1; 32]).verifying_key(),
            static_hybrid_pub: flock_protocol::kem::HybridKeypair::generate(&mut rand::rngs::OsRng)
                .public(),
        };
        let inv = InviteFile::issue(
            root,
            ClusterId([9; 16]),
            1,
            vec![entry],
            expiry_unix,
            invite_id,
        );
        inv.to_bytes()
    }

    fn dev_keys(seed: u8) -> ([u8; 32], [u8; 32]) {
        let ed = SigningKey::from_bytes(&[seed; 32]);
        ([seed; 32], *ed.verifying_key().as_bytes())
    }

    /// 兑换请求构造（身份 = fixture 的 root/cluster）。`root_override` 模拟「他签」邀请。
    fn req<'a>(
        invite: &'a [u8],
        username: &'a str,
        device_seed: u8,
        root: &SigningKey,
    ) -> RedeemRequest<'a> {
        let (x, ed) = dev_keys(device_seed);
        RedeemRequest {
            invite_bytes: invite,
            username,
            device_x25519: x,
            device_ed25519: ed,
            expected_root_pub: *root.verifying_key().as_bytes(),
            expected_cluster_id: [9; 16],
            now_unix: 1000,
        }
    }

    #[test]
    fn redeem_creates_user_device_and_vip() {
        let s = store();
        let root = SigningKey::from_bytes(&[3; 32]);
        let bytes = invite_fixture(&root, 999_999, [1; 16]);
        s.record_invite(&[1; 16], 999_999).unwrap();
        let out = s
            .redeem_invite(req(&bytes, "alice", 5, &root))
            .expect("first redeem");
        assert_eq!(out.username, "alice");
        assert_eq!(
            out.vip,
            VIP_FIRST.to_be_bytes(),
            "首个 VIP = 100.64.0.2（.1 留给服务器）"
        );
        let id = DeviceId(out.device_id);
        let row = s.device_row(&id).expect("row");
        assert_eq!(row.owner, "alice");
        assert_eq!(row.status, DeviceStatus::Active);
        // 同 invite_id 二次兑换拒。
        let err = s.redeem_invite(req(&bytes, "bob", 6, &root)).unwrap_err();
        assert_eq!(err, RedeemError::AlreadyUsed);
    }

    #[test]
    fn redeem_rejects_revoked_expired_unknown_and_forged() {
        let s = store();
        let root = SigningKey::from_bytes(&[3; 32]);
        // revoke_invite 后拒。
        s.record_invite(&[2; 16], 999_999).unwrap();
        s.revoke_invite(&[2; 16]).unwrap();
        let bytes = invite_fixture(&root, 999_999, [2; 16]);
        assert_eq!(
            s.redeem_invite(req(&bytes, "u1", 1, &root)).unwrap_err(),
            RedeemError::InviteRevoked
        );
        // 过期拒。
        s.record_invite(&[3; 16], 500).unwrap();
        let expired = invite_fixture(&root, 500, [3; 16]);
        assert_eq!(
            s.redeem_invite(req(&expired, "u2", 2, &root)).unwrap_err(),
            RedeemError::Expired {
                now_unix: 1000,
                expiry_unix: 500
            }
        );
        // 未登记（非本集群签发记录）拒。
        let unknown = invite_fixture(&root, 999_999, [4; 16]);
        assert_eq!(
            s.redeem_invite(req(&unknown, "u3", 3, &root)).unwrap_err(),
            RedeemError::Unknown
        );
        // 伪造（换根签发——即便 invite_id 已被他人在库内登记）拒：钉扎本集群根。
        let other_root = SigningKey::from_bytes(&[8; 32]);
        let forged = invite_fixture(&other_root, 999_999, [5; 16]);
        s.record_invite(&[5; 16], 999_999).unwrap();
        assert!(matches!(
            s.redeem_invite(req(&forged, "u4", 4, &root)).unwrap_err(),
            RedeemError::BadInvite(_)
        ));
    }

    #[test]
    fn vip_pool_monotonic_never_reused_and_disable_keeps_row() {
        let s = store();
        let a = s.register_device("u", [1; 32], [1; 32]).unwrap();
        let b = s.register_device("u", [2; 32], [2; 32]).unwrap();
        let ip2 = u32::from_be_bytes(b.vip);
        let ip1 = u32::from_be_bytes(a.vip);
        assert!(ip2 > ip1, "单调递增");
        // 吊销 a 后再注册：不复用 a 的 VIP（水位线只进不退）。
        let id_a = DeviceId(Sha256::digest([1u8; 32]).into());
        let epoch = s.revoke(&id_a).unwrap();
        assert!(epoch >= 1, "吊销推进 revocation_epoch");
        let c = s.register_device("u", [3; 32], [3; 32]).unwrap();
        assert_eq!(u32::from_be_bytes(c.vip), ip2 + 1, "IP 不复用");
        // 禁用不删除：行仍在、状态 Disabled、VIP 不回收；lookup 给 Revoked 判定。
        let id_b = DeviceId(Sha256::digest([2u8; 32]).into());
        let epoch2 = s.disable(&id_b).unwrap();
        assert!(epoch2 > epoch, "禁用同样推进 epoch");
        let row = s.device_row(&id_b).expect("行保留（禁用不删除）");
        assert_eq!(row.status, DeviceStatus::Disabled);
        assert_eq!(row.vip, b.vip, "VIP 不回收");
        assert!(matches!(s.lookup(&id_b), LookupVerdict::Revoked { .. }));
        assert!(matches!(s.lookup(&id_a), LookupVerdict::Revoked { .. }));
        // 重新启用：Disabled → Active；epoch 不回退。
        s.enable(&id_b).unwrap();
        assert_eq!(s.device_row(&id_b).unwrap().status, DeviceStatus::Active);
        assert_eq!(s.epoch(), epoch2, "enable 不动 epoch");
        // Revoked 终态不可逆。
        assert!(s.enable(&id_a).is_err());
    }

    #[test]
    fn bind_token_single_use_and_user_keys() {
        let s = store();
        s.register_device("u", [1; 32], [1; 32]).unwrap();
        let tok = [7u8; 16];
        assert!(s.consume_bind_token(&tok), "首次消费");
        assert!(!s.consume_bind_token(&tok), "二次拒绝");
        let key = UserKey::from_seed(&[9; 32]);
        let pub32 = *UserKey::from_pub_string(&key.pub_string())
            .unwrap()
            .as_bytes();
        s.add_user_sig_key("u", pub32).unwrap();
        assert_eq!(s.user_sig_pubs("u").len(), 1);
        assert_eq!(s.password("u"), None, "未设口令");
        s.set_password("u", "rec", 0).unwrap();
        assert_eq!(s.password("u"), Some(("rec".into(), 0)));
        assert!(s.set_password("u", "rec2", 0).is_err(), "已设置不可重复设");
    }
}
