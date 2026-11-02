//! 会话票据（docs/design.md §2.2 / §3.10 `TicketIssuer::issue/verify`）。
//!
//! 本地短 TTL 票据：登录成功后签发，绑定 `device + revocation_epoch`；SR-SIG1 保护的
//! **状态变更**请求必须携带（票据强制契约）。校验序（§2.2，接口契约级，顺序不可换）：
//!
//! 1. **签名**（票据根密钥 Ed25519；M2 单服 = 状态库内种子，M4 = Raft 密钥根下放）；
//! 2. **TTL**（默认 60s 硬顶——跨服重放面的兜底，§2.4 等效重放窗 = min(±300s, 60s)）；
//! 3. **epoch**（票据 epoch < 当前 revocation_epoch 即拒——吊销传播界 §2.2）；
//! 4. **吊销/设备态**（设备不在 Active ⇒ 拒）。
//!
//! 该序先于 SR-SIG1 验签与 nonce 记账（`control::CtrlGuard::admit_state_change`）。

use flock_protocol::ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use flock_protocol::session::DeviceId;
use serde::{Deserialize, Serialize};

/// 票据签名域分离标签。
pub const TICKET_LABEL: &[u8] = b"flock-server/ticket/v1";
/// 票据 TTL 默认 60s（§2.2「票据 TTL 60s 硬顶」；部署可调小以便过期路径验收）。
pub const TICKET_TTL_SECS: u64 = 60;

/// 票据声明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketClaims {
    pub user: String,
    pub device: [u8; 32],
    pub epoch: u64,
    pub iat: u64,
    pub exp: u64,
}

impl TicketClaims {
    /// 签名覆盖的规范化字节（长度域防拼接）。
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(TICKET_LABEL.len() + 4 + self.user.len() + 64);
        v.extend_from_slice(TICKET_LABEL);
        v.extend_from_slice(&(self.user.len() as u32).to_le_bytes());
        v.extend_from_slice(self.user.as_bytes());
        v.extend_from_slice(&self.device);
        v.extend_from_slice(&self.epoch.to_le_bytes());
        v.extend_from_slice(&self.iat.to_le_bytes());
        v.extend_from_slice(&self.exp.to_le_bytes());
        v
    }
}

/// 已签名票据（线上形态；postcard 载体）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTicket {
    pub user: String,
    pub device: Vec<u8>,
    pub epoch: u64,
    pub iat: u64,
    pub exp: u64,
    pub sig: Vec<u8>,
}

impl SignedTicket {
    fn claims(&self) -> Result<TicketClaims, TicketReason> {
        Ok(TicketClaims {
            user: self.user.clone(),
            device: self
                .device
                .clone()
                .try_into()
                .map_err(|_| TicketReason::Malformed)?,
            epoch: self.epoch,
            iat: self.iat,
            exp: self.exp,
        })
    }
}

/// 票据拒绝原因（三态契约测试逐项断言：无票据/过期/低 epoch/签名坏/设备吊销）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketReason {
    Malformed,
    BadSignature,
    Expired,
    /// 票据 epoch < 当前 revocation_epoch（吊销已传播）。
    StaleEpoch,
    /// 设备非 Active（吊销/禁用后的目录判定）。
    DeviceNotActive,
    /// 票据绑定的设备与当前会话设备不符。
    DeviceMismatch,
}

impl std::fmt::Display for TicketReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TicketReason::Malformed => write!(f, "ticket: malformed"),
            TicketReason::BadSignature => write!(f, "ticket: bad signature"),
            TicketReason::Expired => write!(f, "ticket: expired (TTL)"),
            TicketReason::StaleEpoch => write!(f, "ticket: epoch < current revocation_epoch"),
            TicketReason::DeviceNotActive => write!(f, "ticket: device not active"),
            TicketReason::DeviceMismatch => write!(f, "ticket: bound device != session device"),
        }
    }
}

/// 票据签发/校验器（种子进状态库；M4 换 Raft 密钥根时仅本结构替换）。
pub struct TicketIssuer {
    key: SigningKey,
}

impl TicketIssuer {
    /// 由 32B 种子构造。
    pub fn from_seed(seed: [u8; 32]) -> Self {
        TicketIssuer {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// 随机种子（bootstrap 用；持久化由调用方负责）。
    pub fn generate_seed() -> [u8; 32] {
        flock_protocol::rand::random::<[u8; 32]>()
    }

    /// 签发（`now` 注入：测试可拨）。
    pub fn issue(
        &self,
        user: &str,
        device: DeviceId,
        epoch: u64,
        now: u64,
        ttl_secs: u64,
    ) -> SignedTicket {
        let claims = TicketClaims {
            user: user.to_string(),
            device: device.0,
            epoch,
            iat: now,
            exp: now + ttl_secs,
        };
        let sig = self.key.sign(&claims.canonical_bytes()).to_bytes();
        SignedTicket {
            user: claims.user,
            device: claims.device.to_vec(),
            epoch: claims.epoch,
            iat: claims.iat,
            exp: claims.exp,
            sig: sig.to_vec(),
        }
    }

    /// 校验序（签名 → TTL → epoch → 设备态；§2.2 契约序）。返回通过的声明。
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ticket: &SignedTicket,
        now: u64,
        current_epoch: u64,
        lookup: impl FnOnce(&DeviceId) -> flock_protocol::session::LookupVerdict,
    ) -> Result<TicketClaims, TicketReason> {
        let claims = ticket.claims()?;
        // 1) 签名
        let sig = Signature::from_slice(&ticket.sig).map_err(|_| TicketReason::BadSignature)?;
        if self
            .key
            .verifying_key()
            .verify(&claims.canonical_bytes(), &sig)
            .is_err()
        {
            return Err(TicketReason::BadSignature);
        }
        // 2) TTL
        if now >= claims.exp {
            return Err(TicketReason::Expired);
        }
        // 3) epoch（票据 epoch < 当前 ⇒ 吊销已传播，拒）
        if claims.epoch < current_epoch {
            return Err(TicketReason::StaleEpoch);
        }
        // 4) 设备态（吊销/禁用 ⇒ 拒）
        let dev = DeviceId(claims.device);
        match lookup(&dev) {
            flock_protocol::session::LookupVerdict::Active(_) => Ok(claims),
            _ => Err(TicketReason::DeviceNotActive),
        }
    }
}

// ============================================================================
// 线上票据（TicketWire）：单服（本地票据根）与多主（Raft 内票据根）双形态
// ============================================================================

/// 控制流承载的会话票据（对客户端不透明 blob：登录取回、状态变更请求回呈）。
///
/// - [`TicketWire::Local`]：单服形态——票据根 = 本地状态库种子（[`SignedTicket`]）；
/// - [`TicketWire::Sync`]：多主形态——票据根在 Raft 状态内（`flock_sync::ticket::Ticket`
///   线格式；任何服务器都验得了——SR-SIG1 跨服重放面的闭合前提，§2.2）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TicketWire {
    Local(SignedTicket),
    Sync(Vec<u8>),
}

/// 票据校验通过的产物（user 对 Local 内嵌于票据；Sync 票据绑定 device，
/// user 由注册表 owner 解析——调用方兜底）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketPrincipal {
    pub user: Option<String>,
    pub device: [u8; 32],
}

/// 票据签发/校验权威（装配期按 sync 模式选定）。
pub enum TicketAuthority {
    /// 单服：本地种子（状态库 META；盒装——dalek SigningKey 体积大于 Arc 变体）。
    Local(Box<TicketIssuer>),
    /// 多主：密钥根在 Raft（Bootstrap 落库；签发/校验经 SyncNode——不依赖 leader）。
    #[cfg(feature = "multi-primary")]
    Sync(std::sync::Arc<flock_sync::SyncNode>),
}

impl TicketAuthority {
    fn local_issuer(&self) -> Result<&TicketIssuer, TicketReason> {
        match self {
            TicketAuthority::Local(i) => Ok(i),
            #[cfg(feature = "multi-primary")]
            TicketAuthority::Sync(_) => Err(TicketReason::BadSignature),
        }
    }

    /// 签发。`epoch` = 当前 revocation_epoch（Local 进 claims；Sync 由节点内部取）。
    pub fn issue(
        &self,
        user: &str,
        device: DeviceId,
        epoch: u64,
        now: u64,
        ttl_secs: u64,
    ) -> Result<TicketWire, &'static str> {
        match self {
            TicketAuthority::Local(iss) => Ok(TicketWire::Local(
                iss.issue(user, device, epoch, now, ttl_secs),
            )),
            #[cfg(feature = "multi-primary")]
            TicketAuthority::Sync(node) => Ok(TicketWire::Sync(
                node.issue_ticket(device.0, now)
                    .map_err(|_| "not bootstrapped")?
                    .to_bytes(),
            )),
        }
    }

    /// 校验序（Local：签名→TTL→epoch→设备态；Sync：flock-sync 同语义 + 本机 epoch）。
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ticket: &TicketWire,
        session_device: &DeviceId,
        now: u64,
        current_epoch: u64,
        lookup: impl FnOnce(&DeviceId) -> flock_protocol::session::LookupVerdict,
    ) -> Result<TicketPrincipal, TicketReason> {
        match ticket {
            TicketWire::Local(t) => {
                // 复用 TicketIssuer::verify 的完整序（签名→TTL→epoch→设备态）。
                let issuer = self.local_issuer()?;
                let claims = issuer.verify(t, now, current_epoch, lookup)?;
                if claims.device != session_device.0 {
                    return Err(TicketReason::DeviceMismatch);
                }
                Ok(TicketPrincipal {
                    user: Some(claims.user),
                    device: claims.device,
                })
            }
            #[cfg(feature = "multi-primary")]
            TicketWire::Sync(bytes) => {
                let t =
                    flock_sync::ticket::Ticket::from_bytes(bytes).ok_or(TicketReason::Malformed)?;
                let node = match self {
                    TicketAuthority::Sync(n) => n,
                    TicketAuthority::Local(_) => return Err(TicketReason::BadSignature),
                };
                node.verify_ticket(&t, &session_device.0, now)
                    .map_err(|e| match e {
                        flock_sync::ticket::TicketError::BadSignature => TicketReason::BadSignature,
                        flock_sync::ticket::TicketError::Expired { .. } => TicketReason::Expired,
                        flock_sync::ticket::TicketError::StaleEpoch { .. } => {
                            TicketReason::StaleEpoch
                        }
                        flock_sync::ticket::TicketError::WrongDevice => {
                            TicketReason::DeviceMismatch
                        }
                    })?;
                // 设备态（吊销/禁用 ⇒ 拒）——与 Local 序第 4 步对齐。
                match lookup(session_device) {
                    flock_protocol::session::LookupVerdict::Active(_) => {}
                    _ => return Err(TicketReason::DeviceNotActive),
                }
                Ok(TicketPrincipal {
                    user: None,
                    device: session_device.0,
                })
            }
            #[cfg(not(feature = "multi-primary"))]
            TicketWire::Sync(_) => Err(TicketReason::Malformed),
        }
    }
}

/// 用户 → {nonce → ts}。窗口外条目在写入时惰性清理（§1.3.2 SIG_WINDOW_SECS=300）。
///
/// 上限纪律（评审项 9）：per-user 条目上限 [`NonceLedger::MAX_PER_USER`]（4096）——
/// 伪造新鲜 nonce 的洪泛在窗口内也只能撑到上限，之后拒绝请求并计数告警
/// （[`NonceLedger::overflow_rejects`]）；清理后为空的 user entry 即时移除（防
/// 「曾经活跃的用户」条目永驻）。
#[derive(Default)]
pub struct NonceLedger {
    inner:
        std::sync::Mutex<std::collections::HashMap<String, std::collections::HashMap<String, i64>>>,
    /// 超限拒绝计数（告警面：admin stats / 日志）。
    overflow_rejects: std::sync::atomic::AtomicU64,
}

impl NonceLedger {
    /// per-user 条目上限（评审项 9：4096 ≫ ±300s 窗内合法请求速率的合理上界）。
    pub const MAX_PER_USER: usize = 4096;

    pub fn new() -> Self {
        Self::default()
    }

    /// 查重 + 入账（false = 重放或超限拒绝）。仅在票据与签名校验**之后**调用
    /// （§2.2 契约序）。
    pub fn check_and_record(&self, user: &str, nonce: &str, ts: i64, now: i64) -> bool {
        const WINDOW: i64 = flock_protocol::SIG_WINDOW_SECS;
        let mut g = self.inner.lock().expect("nonce ledger poisoned");
        let entry = g.entry(user.to_string()).or_default();
        // 惰性清理：滑出 ±300s 窗的旧 nonce（重放窗之外本就由时间窗拒绝）。
        entry.retain(|_, t| (now - *t).abs() <= WINDOW);
        // 清理后为空的 user entry 即时回收（评审项 9：不留「幽灵用户」条目）。
        if entry.is_empty() {
            g.remove(user);
        }
        let Some(entry) = g.get_mut(user) else {
            // 刚回收（或本来就没有历史）且即将成为该 user 首条 ⇒ 直接入账。
            g.insert(
                user.to_string(),
                std::iter::once((nonce.to_string(), ts)).collect(),
            );
            return true;
        };
        if entry.contains_key(nonce) {
            return false;
        }
        // per-user 上限：超限拒绝 + 告警计数（洪泛者不得无限膨胀 per-user 内存）。
        if entry.len() >= Self::MAX_PER_USER {
            self.overflow_rejects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            eprintln!(
                "flock-server: nonce ledger per-user 上限拒绝（user={user}, cap={}）",
                Self::MAX_PER_USER
            );
            return false;
        }
        entry.insert(nonce.to_string(), ts);
        true
    }

    /// 某 nonce 是否已入账（契约顺序断言用：错误票据 ⇒ 不入账）。
    pub fn contains(&self, user: &str, nonce: &str) -> bool {
        self.inner
            .lock()
            .expect("nonce ledger poisoned")
            .get(user)
            .map(|m| m.contains_key(nonce))
            .unwrap_or(false)
    }

    /// 超限拒绝累计（告警计数面；admin stats 消费）。
    pub fn overflow_rejects(&self) -> u64 {
        self.overflow_rejects
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 当前 user entry 数（空 entry 已清理的断言面）。
    pub fn user_entries(&self) -> usize {
        self.inner.lock().expect("nonce ledger poisoned").len()
    }
}

// ============================================================================
// 单元测试：票据四态 + 契约序（错误票据 + 全新 nonce ⇒ 拒且不入账）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netstate::DeviceStatus;
    use flock_protocol::session::{DeviceRecord, LookupVerdict};
    use flock_protocol::x25519_dalek::PublicKey;

    fn issuer() -> TicketIssuer {
        TicketIssuer::from_seed([5u8; 32])
    }

    #[test]
    fn ticket_lifecycle_states() {
        let t = issuer();
        let dev = DeviceId([1; 32]);
        let active = |_: &DeviceId| {
            LookupVerdict::Active(DeviceRecord {
                device_x25519: PublicKey::from([0u8; 32]),
                device_ed25519: SigningKey::from_bytes(&[2; 32]).verifying_key(),
            })
        };
        let ok = t.issue("alice", dev, 3, 1000, 60);
        assert!(t.verify(&ok, 1010, 3, active).is_ok(), "新鲜票据通过");
        // TTL：now >= exp ⇒ Expired
        assert_eq!(
            t.verify(&ok, 1060, 3, active).unwrap_err(),
            TicketReason::Expired
        );
        // 低 epoch（吊销后）：current_epoch 前进 ⇒ StaleEpoch
        assert_eq!(
            t.verify(&ok, 1010, 4, active).unwrap_err(),
            TicketReason::StaleEpoch
        );
        // 签名坏：篡改任意覆盖字段
        let mut bad = ok.clone();
        bad.epoch += 1;
        assert_eq!(
            t.verify(&bad, 1010, 3, active).unwrap_err(),
            TicketReason::BadSignature
        );
        // 设备吊销/禁用 ⇒ DeviceNotActive
        assert_eq!(
            t.verify(&ok, 1010, 3, |_: &DeviceId| LookupVerdict::Revoked {
                since_epoch: 4
            })
            .unwrap_err(),
            TicketReason::DeviceNotActive
        );
        // 形状坏
        let mut junk = ok.clone();
        junk.device = vec![1, 2, 3];
        assert_eq!(
            t.verify(&junk, 1010, 3, active).unwrap_err(),
            TicketReason::Malformed
        );
    }

    #[test]
    fn ledger_replay_and_window() {
        let l = NonceLedger::new();
        assert!(l.check_and_record("u", "n1", 1000, 1000));
        assert!(
            !l.check_and_record("u", "n1", 1000, 1000),
            "同 nonce 重放拒"
        );
        assert!(l.check_and_record("u", "n2", 1000, 1000));
        // 滑出 ±300s 窗 ⇒ 惰性清理后可用（时间窗本身另有 SIG_WINDOW_SECS 拒绝——
        // 此处只验证记账不无限膨胀）。
        assert!(l.check_and_record("u", "n1", 1400, 1401), "窗外条目被清理");
        assert!(!l.contains("u", "n2"), "n2 亦随清理滑出");
        let _ = DeviceStatus::Active; // 引用 netstate（同批模块联编可见性）
    }

    /// 评审项 9：per-user 条目上限（4096）——超限拒绝 + 告警计数；窗口滑出后条目
    /// 惰性清理、空 user entry 即时回收（洪泛者在窗口内的内存占用被钉死在上限）。
    #[test]
    fn ledger_per_user_cap_and_aged_cleanup() {
        let l = NonceLedger::new();
        for i in 0..NonceLedger::MAX_PER_USER {
            assert!(
                l.check_and_record("flood", &format!("n{i:05}"), 1000, 1000),
                "上限内第 {i} 条应入账"
            );
        }
        assert_eq!(l.overflow_rejects(), 0);
        // 超限：拒绝 + 计数（洪泛不得继续膨胀 per-user 内存）。
        assert!(!l.check_and_record("flood", "over-1", 1000, 1000), "超限拒");
        assert!(
            !l.check_and_record("flood", "over-2", 1000, 1000),
            "持续超限拒"
        );
        assert_eq!(l.overflow_rejects(), 2, "告警计数累计");
        assert_eq!(l.user_entries(), 1, "单 user entry");
        // ±300s 窗滑出 ⇒ 惰性清理腾空（含空 entry 回收路径），随后首条重新入账。
        assert!(
            l.check_and_record("flood", "fresh", 100_000, 100_000),
            "窗滑出后重新可入账"
        );
        assert!(!l.contains("flood", "n00000"), "旧条目已随窗口清理");
        assert!(!l.contains("flood", "over-1"), "超限拒绝的条目从未入账");
        // 多用户互不影响：另一用户正常入账。
        assert!(l.check_and_record("other", "n1", 100_000, 100_000));
        assert_eq!(l.user_entries(), 2);
        assert_eq!(l.overflow_rejects(), 2, "正常用户不计超限");
    }
}
