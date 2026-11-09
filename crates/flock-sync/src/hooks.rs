//! Apply callback hooks (§2.2 revocation-propagation boundary + vpn-mesh
//! §5.2 lease conflicts).
//!
//! Every server, in **its own log apply callback**:
//! (a) advances revocation_epoch and invalidates the record cache (maintained
//!     by [`crate::sm`]);
//! (b) **kills the device's local session**
//!     ([`SyncHooks::on_revocation_applied`] — the assembly layer injects the
//!     session manager; this crate provides the registry and a test recorder);
//! (c) rejects its outstanding tickets (a ticket whose epoch < current epoch is
//!     rejected — [`crate::ticket`] consumes the epoch).
//!
//! Lease conflict (newest wins + old-side session eviction):
//! [`SyncHooks::on_lease_evicted`].

use std::sync::{Arc, Mutex};

use crate::state::RevocationEffect;

/// Revocation-propagation event (produced at the apply-callback site).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationEvent {
    pub device: [u8; 32],
    pub new_epoch: u64,
    /// Log index of the transition that triggered it (for locating and
    /// assertions).
    pub log_index: u64,
}

/// Local side-effect hooks injected by the assembly layer (all empty by
/// default; the server assembly batch wires the session manager).
pub trait SyncHooks: Send + Sync + 'static {
    /// Revocation/disable applied on this node: kill the device's local
    /// session + reject outstanding tickets.
    fn on_revocation_applied(&self, _ev: RevocationEvent) {}
    /// The device's online lease was superseded by a newer lease (newest
    /// wins): evict the local session.
    fn on_lease_evicted(&self, _device: &[u8; 32]) {}
}

/// Hook registry (called from the state machine apply and the lease-conflict
/// paths; shared internally via `Arc` — the SM core and LeaseTable can share
/// one instance; register once and it takes effect network-wide).
#[derive(Clone, Default)]
pub struct HookRegistry {
    hooks: Arc<Mutex<Vec<Arc<dyn SyncHooks>>>>,
}

impl HookRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a hook.
    pub fn add(&self, h: Arc<dyn SyncHooks>) {
        self.hooks.lock().expect("hook registry").push(h);
    }

    /// Fire the revocation-propagation hooks (idempotent: exactly once per
    /// blocking transition).
    pub fn fire_revocation(&self, ev: RevocationEffect, log_index: u64) {
        let event = RevocationEvent {
            device: ev.device,
            new_epoch: ev.new_epoch,
            log_index,
        };
        for h in self.hooks.lock().expect("hook registry").iter() {
            h.on_revocation_applied(event);
        }
    }

    /// Fire the lease-conflict eviction hooks.
    pub fn fire_lease_evict(&self, device: &[u8; 32]) {
        for h in self.hooks.lock().expect("hook registry").iter() {
            h.on_lease_evicted(device);
        }
    }
}

impl std::fmt::Debug for HookRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookRegistry")
            .field("n", &self.hooks.lock().expect("hook registry").len())
            .finish()
    }
}

/// Test recorder (for cluster assertions: epoch advancement + kill-session
/// hook timing).
///
/// Test surface only (`test-util` feature-gated — not in the production
/// default profile; both the integration tests and the flock-server test
/// dev-dependency enable that feature).
#[cfg(feature = "test-util")]
#[derive(Debug, Default)]
pub struct HookRecorder {
    pub revocations: Mutex<Vec<RevocationEvent>>,
    pub evictions: Mutex<Vec<[u8; 32]>>,
}

#[cfg(feature = "test-util")]
impl HookRecorder {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn revocations(&self) -> Vec<RevocationEvent> {
        self.revocations.lock().expect("revocations").clone()
    }

    pub fn evictions(&self) -> Vec<[u8; 32]> {
        self.evictions.lock().expect("evictions").clone()
    }

    /// Number of revocation events for the given device.
    pub fn revocation_count(&self, device: &[u8; 32]) -> usize {
        self.revocations()
            .iter()
            .filter(|e| &e.device == device)
            .count()
    }
}

#[cfg(feature = "test-util")]
impl SyncHooks for HookRecorder {
    fn on_revocation_applied(&self, ev: RevocationEvent) {
        self.revocations.lock().expect("revocations").push(ev);
    }
    fn on_lease_evicted(&self, device: &[u8; 32]) {
        self.evictions.lock().expect("evictions").push(*device);
    }
}
