//! Session tickets (docs/design.md §2.2 / §3.10 `TicketIssuer::issue/verify`).
//!
//! Local short-TTL tickets: issued after a successful login, bound to
//! `device + revocation_epoch`; required on SR-SIG1-protected **state
//! change** requests (the ticket enforcement contract). Verification order
//! (§2.2, interface-contract level, order not interchangeable):
//!
//! 1. **Signature** (ticket root key Ed25519; M2 single server = the seed in
//!    the state store, M4 = the Raft key root handed down);
//! 2. **TTL** (default 60s hard cap —— the backstop for the cross-server
//!    replay surface, §2.4 equivalent replay window = min(±300s, 60s));
//! 3. **epoch** (ticket epoch < current revocation_epoch ⇒ reject —— the
//!    revocation propagation bound of §2.2);
//! 4. **revocation/device state** (device not Active ⇒ reject).
//!
//! This order precedes SR-SIG1 verification and nonce accounting
//! (`control::CtrlGuard::admit_state_change`).

use flock_protocol::ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use flock_protocol::session::DeviceId;

// M7 type uplift: the ticket **wire format** (SignedTicket/TicketWire) is
// defined in flock_protocol::roster (same type on both ends); this file keeps
// the authoritative ticket logic (issuing/verification/nonce accounting ——
// the server-internal surface).
pub use flock_protocol::roster::{SignedTicket, TicketWire};

/// Ticket signature domain-separation label.
pub const TICKET_LABEL: &[u8] = b"flock-server/ticket/v1";
/// Ticket TTL default 60s (§2.2 "ticket TTL 60s hard cap"; deployments may
/// lower it to exercise the expiry path).
pub const TICKET_TTL_SECS: u64 = 60;

/// Ticket claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketClaims {
    pub user: String,
    pub device: [u8; 32],
    pub epoch: u64,
    pub iat: u64,
    pub exp: u64,
}

impl TicketClaims {
    /// Canonical signed bytes (length fields prevent splicing).
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

/// Signed ticket → claims (shape validation; after the SignedTicket wire
/// format was uplifted, claims became a server-side free function).
fn claims_of(t: &SignedTicket) -> Result<TicketClaims, TicketReason> {
    Ok(TicketClaims {
        user: t.user.clone(),
        device: t
            .device
            .clone()
            .try_into()
            .map_err(|_| TicketReason::Malformed)?,
        epoch: t.epoch,
        iat: t.iat,
        exp: t.exp,
    })
}

/// Ticket rejection reason (the three-state contract tests assert each item:
/// no ticket / expired / low epoch / bad signature / revoked device).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketReason {
    Malformed,
    BadSignature,
    Expired,
    /// Ticket epoch < current revocation_epoch (revocation already
    /// propagated).
    StaleEpoch,
    /// Device not Active (the directory verdict after revoke/disable).
    DeviceNotActive,
    /// The ticket's bound device does not match the current session device.
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

/// Ticket issuer/verifier (seed goes into the state store; when M4 switches
/// to the Raft key root, only this structure is replaced).
pub struct TicketIssuer {
    key: SigningKey,
}

impl TicketIssuer {
    /// Construct from a 32B seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        TicketIssuer {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// Random seed (for bootstrap; persistence is the caller's
    /// responsibility).
    pub fn generate_seed() -> [u8; 32] {
        flock_protocol::rand::random::<[u8; 32]>()
    }

    /// Issue (`now` injected: tests can dial it).
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

    /// Verification order (signature → TTL → epoch → device state; the §2.2
    /// contract order). Returns the passing claims.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        ticket: &SignedTicket,
        now: u64,
        current_epoch: u64,
        lookup: impl FnOnce(&DeviceId) -> flock_protocol::session::LookupVerdict,
    ) -> Result<TicketClaims, TicketReason> {
        let claims = claims_of(ticket)?;
        // 1) Signature
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
        // 3) epoch (ticket epoch < current ⇒ revocation already propagated,
        //    reject)
        if claims.epoch < current_epoch {
            return Err(TicketReason::StaleEpoch);
        }
        // 4) Device state (revoked/disabled ⇒ reject)
        let dev = DeviceId(claims.device);
        match lookup(&dev) {
            flock_protocol::session::LookupVerdict::Active(_) => Ok(claims),
            _ => Err(TicketReason::DeviceNotActive),
        }
    }
}

/// The product of a passing ticket verification (user is embedded in the
/// ticket for Local; Sync tickets bind the device, and the user is resolved
/// from the registry owner —— the caller backstops).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketPrincipal {
    pub user: Option<String>,
    pub device: [u8; 32],
}

/// The ticket issuing/verification authority (chosen at assembly time by the
/// sync mode).
pub enum TicketAuthority {
    /// Single server: local seed (state store META; boxed —— the dalek
    /// SigningKey is larger than the Arc variant).
    Local(Box<TicketIssuer>),
    /// Multi-primary: the key root is in Raft (Bootstrap persists it;
    /// issue/verify go through the SyncNode —— no leader dependency).
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

    /// Issue. `epoch` = the current revocation_epoch (Local goes into the
    /// claims; Sync takes it internally from the node).
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

    /// Verification order (Local: signature→TTL→epoch→device state; Sync:
    /// same semantics in flock-sync + the local epoch).
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
                // Reuse TicketIssuer::verify's full order
                // (signature→TTL→epoch→device state).
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
                // Device state (revoked/disabled ⇒ reject) —— aligned with
                // step 4 of the Local order.
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

/// user → {nonce → ts}. Out-of-window entries are lazily cleaned on write
/// (§1.3.2 SIG_WINDOW_SECS=300).
///
/// Cap discipline (review item 9): per-user entry cap
/// [`NonceLedger::MAX_PER_USER`] (4096) —— a flood of forged fresh nonces can
/// only reach the cap within the window; afterwards requests are rejected and
/// the alert counter increments ([`NonceLedger::overflow_rejects`]); a user
/// entry emptied by cleanup is removed immediately (prevents "once-active
/// user" entries from lingering forever).
#[derive(Default)]
pub struct NonceLedger {
    inner:
        std::sync::Mutex<std::collections::HashMap<String, std::collections::HashMap<String, i64>>>,
    /// Over-cap rejection counter (alert surface: admin stats / logs).
    overflow_rejects: std::sync::atomic::AtomicU64,
}

impl NonceLedger {
    /// Per-user entry cap (review item 9: 4096 ≫ a reasonable upper bound on
    /// legitimate request rates within the ±300s window).
    pub const MAX_PER_USER: usize = 4096;

    pub fn new() -> Self {
        Self::default()
    }

    /// Dedup + record (false = replay or over-cap rejection). Called only
    /// **after** ticket and signature verification (the §2.2 contract
    /// order).
    pub fn check_and_record(&self, user: &str, nonce: &str, ts: i64, now: i64) -> bool {
        const WINDOW: i64 = flock_protocol::SIG_WINDOW_SECS;
        let mut g = self.inner.lock().expect("nonce ledger poisoned");
        let entry = g.entry(user.to_string()).or_default();
        // Lazy cleanup: old nonces that slid out of the ±300s window
        // (outside the replay window they are rejected by the time window
        // anyway).
        entry.retain(|_, t| (now - *t).abs() <= WINDOW);
        // A user entry emptied by cleanup is reclaimed immediately (review
        // item 9: no "ghost user" entries left behind).
        if entry.is_empty() {
            g.remove(user);
        }
        let Some(entry) = g.get_mut(user) else {
            // Just reclaimed (or never had history) and about to become this
            // user's first entry ⇒ record directly.
            g.insert(
                user.to_string(),
                std::iter::once((nonce.to_string(), ts)).collect(),
            );
            return true;
        };
        if entry.contains_key(nonce) {
            return false;
        }
        // Per-user cap: over-cap rejection + alert counter (a flooder cannot
        // grow per-user memory without bound).
        if entry.len() >= Self::MAX_PER_USER {
            self.overflow_rejects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            eprintln!(
                "flock-server: nonce ledger per-user cap rejection (user={user}, cap={})",
                Self::MAX_PER_USER
            );
            return false;
        }
        entry.insert(nonce.to_string(), ts);
        true
    }

    /// Whether some nonce is already recorded (for contract-order
    /// assertions: a bad ticket ⇒ not recorded).
    pub fn contains(&self, user: &str, nonce: &str) -> bool {
        self.inner
            .lock()
            .expect("nonce ledger poisoned")
            .get(user)
            .map(|m| m.contains_key(nonce))
            .unwrap_or(false)
    }

    /// Cumulative over-cap rejections (alert counter surface; consumed by
    /// admin stats).
    pub fn overflow_rejects(&self) -> u64 {
        self.overflow_rejects
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Current user-entry count (assertion surface for emptied entries being
    /// cleaned).
    pub fn user_entries(&self) -> usize {
        self.inner.lock().expect("nonce ledger poisoned").len()
    }
}

// ============================================================================
// Unit tests: the four ticket states + contract order (bad ticket + fresh
// nonce ⇒ rejected and not recorded)
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
        assert!(
            t.verify(&ok, 1010, 3, active).is_ok(),
            "fresh ticket passes"
        );
        // TTL: now >= exp ⇒ Expired
        assert_eq!(
            t.verify(&ok, 1060, 3, active).unwrap_err(),
            TicketReason::Expired
        );
        // Low epoch (after revocation): current_epoch advanced ⇒ StaleEpoch
        assert_eq!(
            t.verify(&ok, 1010, 4, active).unwrap_err(),
            TicketReason::StaleEpoch
        );
        // Bad signature: tamper any covered field
        let mut bad = ok.clone();
        bad.epoch += 1;
        assert_eq!(
            t.verify(&bad, 1010, 3, active).unwrap_err(),
            TicketReason::BadSignature
        );
        // Device revoked/disabled ⇒ DeviceNotActive
        assert_eq!(
            t.verify(&ok, 1010, 3, |_: &DeviceId| LookupVerdict::Revoked {
                since_epoch: 4
            })
            .unwrap_err(),
            TicketReason::DeviceNotActive
        );
        // Malformed shape
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
            "same-nonce replay rejected"
        );
        assert!(l.check_and_record("u", "n2", 1000, 1000));
        // Slid out of the ±300s window ⇒ usable again after lazy cleanup
        // (outside the window the time window itself rejects via
        // SIG_WINDOW_SECS —— this only verifies the ledger does not grow
        // without bound).
        assert!(
            l.check_and_record("u", "n1", 1400, 1401),
            "out-of-window entry cleaned"
        );
        assert!(!l.contains("u", "n2"), "n2 also slid out with the cleanup");
        let _ = DeviceStatus::Active; // reference netstate (same-batch module visibility)
    }

    /// Review item 9: per-user entry cap (4096) —— over-cap rejection + alert
    /// counter; entries lazily cleaned once the window slides, emptied user
    /// entries reclaimed immediately (a flooder's in-window memory footprint
    /// is pinned at the cap).
    #[test]
    fn ledger_per_user_cap_and_aged_cleanup() {
        let l = NonceLedger::new();
        for i in 0..NonceLedger::MAX_PER_USER {
            assert!(
                l.check_and_record("flood", &format!("n{i:05}"), 1000, 1000),
                "entry {i} within the cap should be recorded"
            );
        }
        assert_eq!(l.overflow_rejects(), 0);
        // Over the cap: reject + count (the flood cannot keep growing
        // per-user memory).
        assert!(
            !l.check_and_record("flood", "over-1", 1000, 1000),
            "over-cap rejected"
        );
        assert!(
            !l.check_and_record("flood", "over-2", 1000, 1000),
            "persistent over-cap rejected"
        );
        assert_eq!(l.overflow_rejects(), 2, "alert counter accumulates");
        assert_eq!(l.user_entries(), 1, "single user entry");
        // ±300s window slid out ⇒ lazy cleanup empties it (including the
        // empty-entry reclaim path); the next first entry records again.
        assert!(
            l.check_and_record("flood", "fresh", 100_000, 100_000),
            "recordable again after the window slides out"
        );
        assert!(
            !l.contains("flood", "n00000"),
            "old entries cleaned with the window"
        );
        assert!(
            !l.contains("flood", "over-1"),
            "over-cap-rejected entries were never recorded"
        );
        // Multiple users do not affect each other: another user records
        // normally.
        assert!(l.check_and_record("other", "n1", 100_000, 100_000));
        assert_eq!(l.user_entries(), 2);
        assert_eq!(
            l.overflow_rejects(),
            2,
            "legitimate users do not count as over-cap"
        );
    }
}
