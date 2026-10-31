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

use chml_protocol::ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use chml_protocol::session::DeviceId;
use serde::{Deserialize, Serialize};

/// 票据签名域分离标签。
pub const TICKET_LABEL: &[u8] = b"chmlvpn-server/ticket/v1";
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
        chml_protocol::rand::random::<[u8; 32]>()
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
        lookup: impl FnOnce(&DeviceId) -> chml_protocol::session::LookupVerdict,
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
            chml_protocol::session::LookupVerdict::Active(_) => Ok(claims),
            _ => Err(TicketReason::DeviceNotActive),
        }
    }
}

// ============================================================================
// nonce 记账（SR-SIG1 请求级，本地 ±300s 窗；§2.4 分级归属）
// ============================================================================

/// 用户 → {nonce → ts}。窗口外条目在写入时惰性清理（§1.3.2 SIG_WINDOW_SECS=300）。
#[derive(Default)]
pub struct NonceLedger {
    inner:
        std::sync::Mutex<std::collections::HashMap<String, std::collections::HashMap<String, i64>>>,
}

impl NonceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// 查重 + 入账（false = 重放）。仅在票据与签名校验**之后**调用（§2.2 契约序）。
    pub fn check_and_record(&self, user: &str, nonce: &str, ts: i64, now: i64) -> bool {
        const WINDOW: i64 = chml_protocol::SIG_WINDOW_SECS;
        let mut g = self.inner.lock().expect("nonce ledger poisoned");
        let entry = g.entry(user.to_string()).or_default();
        // 惰性清理：滑出 ±300s 窗的旧 nonce（重放窗之外本就由时间窗拒绝）。
        entry.retain(|_, t| (now - *t).abs() <= WINDOW);
        if entry.contains_key(nonce) {
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
}

// ============================================================================
// 单元测试：票据四态 + 契约序（错误票据 + 全新 nonce ⇒ 拒且不入账）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netstate::DeviceStatus;
    use chml_protocol::session::{DeviceRecord, LookupVerdict};
    use chml_protocol::x25519_dalek::PublicKey;

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
}
