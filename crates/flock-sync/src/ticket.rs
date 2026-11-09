//! Local short-TTL session tickets (§3.10 `TicketIssuer`; **the ticket key
//! root lives inside Raft** — the §4 phase-two capability absorbed into the
//! first release: the login path does not depend on the leader).
//!
//! Contract (§2.2 mandatory ticket contract):
//! 1. **Signature**: Ed25519 derived from the ticket key root (bootstrapped
//!    into Raft state, replicated network-wide);
//! 2. **TTL 60s hard cap** (the backstop for the cross-server replay
//!    window);
//! 3. **epoch binding**: a ticket whose epoch < the current
//!    revocation_epoch is rejected (the ticket-side landing point of the
//!    revocation-propagation boundary — `verify` consumes the current value
//!    of the local epoch watch).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Ticket TTL (§2.2: 60s hard cap).
pub const TICKET_TTL_SECS: u64 = 60;

const L_TICKET: &[u8] = b"flock-sync/ticket/v1";
const L_ROOT_DERIVE: &[u8] = b"flock-sync/ticket-root-derive/v1";

/// Ticket verification failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    BadSignature,
    Expired {
        now_unix: u64,
        expiry_unix: u64,
    },
    /// The ticket's epoch < the current revocation_epoch (the revocation has
    /// propagated, §2.2-3).
    StaleEpoch {
        ticket_epoch: u64,
        current_epoch: u64,
    },
    WrongDevice,
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TicketError::BadSignature => write!(f, "ticket: signature mismatch"),
            TicketError::Expired {
                now_unix,
                expiry_unix,
            } => {
                write!(f, "ticket: expired (now={now_unix}, expiry={expiry_unix})")
            }
            TicketError::StaleEpoch {
                ticket_epoch,
                current_epoch,
            } => {
                write!(f, "ticket: epoch {ticket_epoch} < current {current_epoch}")
            }
            TicketError::WrongDevice => write!(f, "ticket: bound to another device"),
        }
    }
}
impl std::error::Error for TicketError {}

/// Session ticket (issued locally; bound to device + revocation_epoch).
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

    /// Serialize (control-plane wire format).
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("ticket serialize")
    }

    /// Deserialize.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        postcard::from_bytes(b).ok()
    }
}

/// Ticket issuer (key derived from the in-Raft ticket_root — any server can
/// verify, any one can sign).
#[derive(Clone)]
pub struct TicketIssuer {
    key: SigningKey,
}

impl TicketIssuer {
    /// Derive from the in-Raft-state ticket key root (domain separation, so
    /// the root is never directly exposed as a signing key).
    pub fn from_root(root: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(L_ROOT_DERIVE);
        h.update(root);
        let seed: [u8; 32] = h.finalize().into();
        TicketIssuer {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// Issue (TTL = [`TICKET_TTL_SECS`]; `epoch` = the current
    /// revocation_epoch at issue time).
    pub fn issue(&self, device: [u8; 32], epoch: u64, now_unix: u64, seq: u64) -> Ticket {
        let mut t = Ticket {
            device,
            epoch,
            expiry_unix: now_unix + TICKET_TTL_SECS,
            seq,
            sig: [0; 64],
        };
        t.sig = self.key.sign(&t.canonical()).to_bytes();
        t
    }

    /// Verify: signature → TTL → epoch (a ticket epoch below current is
    /// rejected) → device binding.
    pub fn verify(
        &self,
        t: &Ticket,
        for_device: &[u8; 32],
        current_epoch: u64,
        now_unix: u64,
    ) -> Result<(), TicketError> {
        if self
            .key
            .verifying_key()
            .verify(&t.canonical(), &Signature::from_bytes(&t.sig))
            .is_err()
        {
            return Err(TicketError::BadSignature);
        }
        if t.device != *for_device {
            return Err(TicketError::WrongDevice);
        }
        if now_unix >= t.expiry_unix {
            return Err(TicketError::Expired {
                now_unix,
                expiry_unix: t.expiry_unix,
            });
        }
        if t.epoch < current_epoch {
            return Err(TicketError::StaleEpoch {
                ticket_epoch: t.epoch,
                current_epoch,
            });
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
// Unit tests
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
        // Same root derivation ⇒ another node can verify (the ticket key root
        // is network-wide consistent inside Raft).
        assert!(b.verify(&t, &[1; 32], 3, 1001).is_ok());
        assert!(
            a.verify(&t, &[1; 32], 3, 1059).is_ok(),
            "within the 60s TTL"
        );
        assert!(
            matches!(
                a.verify(&t, &[1; 32], 3, 1061).unwrap_err(),
                TicketError::Expired { .. }
            ),
            "TTL hard cap"
        );
        // A revocation advanced the epoch ⇒ the old ticket is rejected.
        assert!(matches!(
            a.verify(&t, &[1; 32], 4, 1001).unwrap_err(),
            TicketError::StaleEpoch {
                ticket_epoch: 3,
                current_epoch: 4
            }
        ));
        // A different root ⇒ signature verification fails.
        let c = TicketIssuer::from_root(&[8u8; 32]);
        assert!(matches!(
            c.verify(&t, &[1; 32], 3, 1001).unwrap_err(),
            TicketError::BadSignature
        ));
        // A different device ⇒ rejected.
        assert!(matches!(
            a.verify(&t, &[2; 32], 3, 1001).unwrap_err(),
            TicketError::WrongDevice
        ));
        // Serialization round trip.
        let back = Ticket::from_bytes(&t.to_bytes()).expect("roundtrip");
        assert_eq!(back, t);
    }
}
