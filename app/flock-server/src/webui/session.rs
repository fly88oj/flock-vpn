//! M8 webui session table (docs/design.md §7-M8.3 —— parameters verbatim:
//! 32B random sid, TTL, cap 256 evicting the oldest, lazy expiry + 60s
//! sweep).
//!
//! In-process memory per server (**never enters Raft**): a cookie from a VIP
//! login on server-a is invalid on server-b (cookies are host-scoped anyway)
//! —— simply sign in again on b (stated by design).
//!
//! Clock injection: every method takes `now_unix` (the sweep task / login
//! handler inject the real wall clock; unit tests inject fixed-point clocks
//! —— the backoff/expiry curves become deterministically testable).
//!
//! Mutex poison: the webui table locks uniformly use
//! `unwrap_or_else(|e| e.into_inner())` —— a panic while holding the lock
//! does not cascade its poisoning into a surface-wide 500/process death (the
//! table data itself is intact; green review item 7).

use std::collections::HashMap;

use flock_protocol::rand;

/// Session-table cap (over the cap, evict the oldest by iat —— assertion
/// surface).
pub const SESSION_CAP: usize = 256;
/// Sweep period (a backstop beyond lazy expiry —— frees slots held by dead
/// sessions).
pub const SWEEP_PERIOD: std::time::Duration = std::time::Duration::from_secs(60);

/// Session origin (tier decided by RemoteAddr at login-finish; both classes
/// are legal and both are recorded —— cross-segment cookie reuse is not
/// rejected, per the requirement's original semantics; echoed by /api/me and
/// in audit lines).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Loopback,
    Vpn,
}

impl Origin {
    /// JSON echo value (the origin field of §M8.4 `/api/me`).
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Loopback => "loopback",
            Origin::Vpn => "vpn",
        }
    }
}

/// Session row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub admin: bool,
    pub origin: Origin,
    pub iat_unix: u64,
    pub exp_unix: u64,
}

/// Session table (`Mutex<HashMap<sid, Session>>`; sid = 32B random hex, 64
/// characters).
#[derive(Default)]
pub struct Sessions {
    inner: std::sync::Mutex<HashMap<String, Session>>,
}

impl Sessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a session (32B random sid); over the cap, first evict the oldest
    /// by iat.
    pub fn issue(
        &self,
        user: &str,
        admin: bool,
        origin: Origin,
        now_unix: u64,
        ttl_secs: u64,
    ) -> String {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        evict_to_cap(&mut g);
        // 32B random (256bit); hex 64 characters. A collision (2^-256) is not
        // a realistic path —— just redraw.
        let sid = loop {
            let s = hex::encode(rand::random::<[u8; 32]>());
            if !g.contains_key(&s) {
                break s;
            }
        };
        g.insert(
            sid.clone(),
            Session {
                user: user.to_string(),
                admin,
                origin,
                iat_unix: now_unix,
                exp_unix: now_unix.saturating_add(ttl_secs),
            },
        );
        sid
    }

    /// Look up a session (lazy expiry: a hit validates exp —— expired returns
    /// None but the row remains, awaiting sweep/slot reuse).
    pub fn lookup(&self, sid: &str, now_unix: u64) -> Option<Session> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.get(sid).filter(|s| s.exp_unix > now_unix).cloned()
    }

    /// Delete a session (logout). Returns whether it existed (including
    /// already-expired rows —— same-name deletion semantics).
    pub fn logout(&self, sid: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sid)
            .is_some()
    }

    /// Sweep expired rows (60s periodic task; returns the number cleared ——
    /// test surface).
    pub fn sweep(&self, now_unix: u64) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = g.len();
        g.retain(|_, s| s.exp_unix > now_unix);
        before - g.len()
    }

    /// Rows on record (including un-expired lazy rows —— diagnostics/test
    /// surface).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Cap eviction: over [`SESSION_CAP`], evict the oldest by iat (ties on iat
/// pick any seat —— same-millisecond ties are a boundary state; which seat is
/// evicted is semantically equivalent: both are dead sessions issued at the
/// same instant).
fn evict_to_cap(g: &mut HashMap<String, Session>) {
    while g.len() >= SESSION_CAP {
        let Some(oldest) = g
            .iter()
            .min_by_key(|(_, s)| s.iat_unix)
            .map(|(sid, _)| sid.clone())
        else {
            break;
        };
        g.remove(&oldest);
    }
}

/// Set-Cookie value (§M8.3 verbatim: HttpOnly + SameSite=Strict + Path=/ +
/// Max-Age=TTL; **no Secure** —— no TLS, trust-domain declaration §M8.7).
pub fn set_cookie_value(sid: &str, ttl_secs: u64) -> String {
    format!("flock_session={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl_secs}")
}

/// The same-name deleting cookie for logout (Max-Age=0).
pub fn clear_cookie_value() -> String {
    "flock_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
}

// ============================================================================
// Unit tests (§M8.9: issue / hit / expiry rejection / logout deletes / 256-cap
// oldest eviction / lazy + periodic sweep)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_lookup_and_expiry() {
        let s = Sessions::new();
        let sid = s.issue("alice", true, Origin::Loopback, 1000, 3600);
        assert_eq!(sid.len(), 64, "sid = 32B hex, 64 characters");
        assert!(sid.bytes().all(|b| b.is_ascii_hexdigit()));

        let sess = s.lookup(&sid, 1000).expect("hit");
        assert_eq!(sess.user, "alice");
        assert!(sess.admin);
        assert_eq!(sess.origin, Origin::Loopback);
        assert_eq!(sess.exp_unix, 4600);

        // Lazy expiry: rejected from the exp instant on (only > exp is valid
        // —— exp itself is already expired).
        assert!(s.lookup(&sid, 4600).is_none(), "invalid at exp");
        assert!(
            s.lookup(&sid, 4599).is_some(),
            "valid one second before exp"
        );

        // Unknown sid.
        assert!(s.lookup(&"0".repeat(64), 1000).is_none());
    }

    #[test]
    fn logout_removes() {
        let s = Sessions::new();
        let sid = s.issue("alice", false, Origin::Vpn, 0, 100);
        assert!(s.logout(&sid));
        assert!(s.lookup(&sid, 0).is_none(), "logout deletes immediately");
        assert!(!s.logout(&sid), "second logout = no such row");
    }

    /// 256 cap: before the 256th issue the oldest is evicted (eviction by iat
    /// ascending; iat ties deterministic by sid order).
    #[test]
    fn cap_256_evicts_oldest_by_iat() {
        let s = Sessions::new();
        let first = s.issue("u0", false, Origin::Loopback, 100, 10_000);
        for i in 1..SESSION_CAP - 1 {
            s.issue(&format!("u{i}"), false, Origin::Loopback, 200, 10_000);
        }
        assert_eq!(s.len(), SESSION_CAP - 1);
        // The 256th seat: still no eviction (the cap is 256).
        let edge = s.issue("u-edge", false, Origin::Loopback, 250, 10_000);
        assert_eq!(s.len(), SESSION_CAP, "exactly 256 on record (no eviction)");
        assert!(
            s.lookup(&first, 300).is_some(),
            "the oldest within 256 remains"
        );
        // The 257th seat: the oldest (u0@100) evicted before issuing.
        let _new = s.issue("u-new", false, Origin::Loopback, 300, 10_000);
        assert_eq!(
            s.len(),
            SESSION_CAP,
            "maintains 256 after over-cap eviction"
        );
        assert!(
            s.lookup(&first, 300).is_none(),
            "the oldest (iat=100) evicted"
        );
        // The rest survive (including the previous edge seat).
        assert!(s.lookup(&edge, 300).is_some());
        assert!(s.lookup(&_new, 300).is_some());
    }

    /// Periodic sweep: expired rows cleared, un-expired kept; returns the
    /// count cleared.
    #[test]
    fn sweep_removes_expired_only() {
        let s = Sessions::new();
        let alive = s.issue("alive", false, Origin::Loopback, 0, 1000);
        let _dead = s.issue("dead", false, Origin::Vpn, 0, 10);
        assert_eq!(s.len(), 2);
        // now=100: dead expired (exp=10), alive not (exp=1000).
        assert_eq!(s.sweep(100), 1);
        assert_eq!(s.len(), 1);
        assert!(s.lookup(&alive, 100).is_some());
        // Lazy rows are also freed after sweep (the cap assertions do not
        // depend on this other sweep path).
        assert_eq!(s.sweep(2000), 1, "alive cleared by sweep once expired");
        assert!(s.is_empty());
    }

    /// Cookie strings verbatim (§M8.3: HttpOnly/SameSite=Strict/Path=//
    /// Max-Age; no Secure).
    #[test]
    fn cookie_strings_literal() {
        let v = set_cookie_value("ab", 28800);
        assert_eq!(
            v,
            "flock_session=ab; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"
        );
        assert!(!v.contains("Secure"), "no Secure (no TLS, §M8.7)");
        let c = clear_cookie_value();
        assert!(c.starts_with("flock_session=;"));
        assert!(c.ends_with("Max-Age=0"), "{c}");
    }
}
