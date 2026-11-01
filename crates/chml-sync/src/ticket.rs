//! 本地短 TTL 会话票据（§3.10 `TicketIssuer`；**票据密钥根在 Raft 内**——§4 第二阶段
//! 能力直接吸收进首版：登录路径不依赖 leader）。
//!
//! 契约（§2.2 票据强制契约）：
//! 1. **签名**：票据密钥根（Bootstrap 进 Raft 状态、全网复制）派生的 Ed25519；
//! 2. **TTL 60s 硬顶**（跨服重放窗的兜底）；
//! 3. **epoch 绑定**：票据 epoch < 当前 revocation_epoch 即拒（吊销传播界的票据侧
//!    落点——`verify` 以本机 epoch watch 的当前值消费）。

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 票据 TTL（§2.2：60s 硬顶）。
pub const TICKET_TTL_SECS: u64 = 60;

const L_TICKET: &[u8] = b"chml-sync/ticket/v1";
const L_ROOT_DERIVE: &[u8] = b"chml-sync/ticket-root-derive/v1";

/// 票据校验失败原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    BadSignature,
    Expired { now_unix: u64, expiry_unix: u64 },
    /// 票据 epoch < 当前 revocation_epoch（吊销已传播，§2.2-3）。
    StaleEpoch { ticket_epoch: u64, current_epoch: u64 },
    WrongDevice,
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TicketError::BadSignature => write!(f, "ticket: signature mismatch"),
            TicketError::Expired { now_unix, expiry_unix } => {
                write!(f, "ticket: expired (now={now_unix}, expiry={expiry_unix})")
            }
            TicketError::StaleEpoch { ticket_epoch, current_epoch } => {
                write!(f, "ticket: epoch {ticket_epoch} < current {current_epoch}")
            }
            TicketError::WrongDevice => write!(f, "ticket: bound to another device"),
        }
    }
}
impl std::error::Error for TicketError {}

/// 会话票据（本地签发；绑定 device + revocation_epoch）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    pub device: [u8; 32],
    pub epoch: u64,
    pub expiry_unix: u64,
    pub seq: u64,
    #[serde(with = "crate::proto::arr64")]
    pub sig: [u8; 64],
}

impl Ticket {
    fn canonical(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(L_TICKET.len() + 56);
        v.extend_from_slice(L_TICKET);
        v.extend_from_slice(&self.device);
        v.extend_from_slice(&self.epoch.to_le_bytes());
        v.extend_from_slice(&self.expiry_unix.to_le_bytes());
        v.extend_from_slice(&self.seq.to_le_bytes());
        v
    }

    /// 序列化（控制流下发线格式）。
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("ticket serialize")
    }

    /// 反序列化。
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
    }
}

/// 票据签发器（密钥根派生自 Raft 内 ticket_root——任何服务器都能验，任何一台都签得）。
#[derive(Clone)]
pub struct TicketIssuer {
    key: SigningKey,
}

impl TicketIssuer {
    /// 由 Raft 状态内的票据密钥根派生（域分离，避免根直接暴露为签名钥）。
    pub fn from_root(root: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(L_ROOT_DERIVE);
        h.update(root);
        let seed: [u8; 32] = h.finalize().into();
        TicketIssuer { key: SigningKey::from_bytes(&seed) }
    }

    /// 签发（TTL = [`TICKET_TTL_SECS`]；`epoch` = 签发时的当前 revocation_epoch）。
    pub fn issue(&self, device: [u8; 32], epoch: u64, now_unix: u64, seq: u64) -> Ticket {
        let mut t = Ticket { device, epoch, expiry_unix: now_unix + TICKET_TTL_SECS, seq, sig: [0; 64] };
        t.sig = self.key.sign(&t.canonical()).to_bytes();
        t
    }

    /// 校验：签名 → TTL → epoch（票据 epoch < 当前即拒）→ 设备绑定。
    pub fn verify(&self, t: &Ticket, for_device: &[u8; 32], current_epoch: u64, now_unix: u64) -> Result<(), TicketError> {
        if self.key.verifying_key().verify(&t.canonical(), &Signature::from_bytes(&t.sig)).is_err() {
            return Err(TicketError::BadSignature);
        }
        if t.device != *for_device {
            return Err(TicketError::WrongDevice);
        }
        if now_unix >= t.expiry_unix {
            return Err(TicketError::Expired { now_unix, expiry_unix: t.expiry_unix });
        }
        if t.epoch < current_epoch {
            return Err(TicketError::StaleEpoch { ticket_epoch: t.epoch, current_epoch });
        }
        Ok(())
    }
}

impl std::fmt::Debug for TicketIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketIssuer").finish_non_exhaustive()
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_verify_roundtrip_and_epoch_reject() {
        let root = [9u8; 32];
        let a = TicketIssuer::from_root(&root);
        let b = TicketIssuer::from_root(&root);
        let t = a.issue([1; 32], 3, 1000, 1);
        // 同根派生 ⇒ 另一节点可验（票据密钥根在 Raft 内全网一致）。
        assert!(b.verify(&t, &[1; 32], 3, 1001).is_ok());
        assert!(a.verify(&t, &[1; 32], 3, 1059).is_ok(), "TTL 60s 内");
        assert!(matches!(
            a.verify(&t, &[1; 32], 3, 1061).unwrap_err(),
            TicketError::Expired { .. }
        ), "TTL 硬顶");
        // 吊销推进 epoch ⇒ 旧票据拒。
        assert!(matches!(
            a.verify(&t, &[1; 32], 4, 1001).unwrap_err(),
            TicketError::StaleEpoch { ticket_epoch: 3, current_epoch: 4 }
        ));
        // 换根 ⇒ 验签失败。
        let c = TicketIssuer::from_root(&[8u8; 32]);
        assert!(matches!(c.verify(&t, &[1; 32], 3, 1001).unwrap_err(), TicketError::BadSignature));
        // 换设备 ⇒ 拒。
        assert!(matches!(a.verify(&t, &[2; 32], 3, 1001).unwrap_err(), TicketError::WrongDevice));
        // 序列化往返。
        let back = Ticket::from_bytes(&t.to_bytes()).expect("roundtrip");
        assert_eq!(back, t);
    }
}
