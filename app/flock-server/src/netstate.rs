//! Single-server NetState: the strongly consistent local state machine for
//! the registry/invites/VIP allocation (docs/design.md §3.11 / §7-M2).
//!
//! **Row types share provenance with `flock-sync` proto.rs** (review item 12
//! dedup): `DeviceRow`/`DeviceStatus`/`UserRow` take flock-sync's
//! definitions as the single authority (the Raft state-machine snapshot/wire
//! format share the same source); this module re-exports them. Semantic
//! discipline (§2.1/§1.3.3f, equally valid in both forms):
//!
//! - **VIP 100.64.0.0/10 allocation**: `100.64.0.1` is reserved for the
//!   server itself. IP reuse policy (the §2.1 M7 revision): revoke/disable
//!   → row retained, **the IP is never reused**; **Expired (offline past
//!   the retention period) → the VIP returns to the allocation pool**
//!   (the `VIP_POOL` table; on allocation the pool's smallest key is taken
//!   first, falling back to the monotonic watermark when empty) —— expired
//!   rows stay on record (audit), excluded from roster queries.
//! - **One-time invites**: `redeem_invite` = dedup check (used ⇒ reject) +
//!   revocation check + expiry check → mark used + create user/device +
//!   assign a VIP inside the same transaction (§1.3.3f "an invite's life";
//!   the single-machine transaction = the local counterpart of the Raft
//!   state machine's atomic commit).
//! - **Revocation advances the global revocation_epoch** (the §2.2
//!   revocation propagation bound): every revoke/disable/expire advances it
//!   monotonically by 1; the ticket layer consumes it as "ticket epoch <
//!   current epoch ⇒ reject".
//! - redb single-file embedded, single writer (the server process writes
//!   exclusively; CLI/admin operations enter this process through the admin
//!   endpoint, see `admin.rs` —— avoiding multi-process writers).

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use flock_protocol::session::{DeviceId, DeviceRecord, LookupVerdict};
use flock_protocol::{ed25519_dalek, x25519_dalek};
use futures::future::BoxFuture;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use sha2::{Digest, Sha256};

// Row-type dedup (review item 12): this module's same-named local
// definitions were deleted in favor of flock-sync proto.rs's single
// authoritative definitions —— single-server redb encoding and the
// multi-primary Raft state machine share the same row types from here on,
// and backend.rs's From-conversion glue layer was deleted with them.
pub use flock_sync::proto::{DeviceRow, DeviceStatus, UserRow};

/// Devices table: DeviceId(32B) → DeviceRow.
const DEVICES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("devices");
/// Users table: username → UserRow (OPAQUE record + SR-SIG1 key set).
const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
/// Invites table: invite_id(16B) → InviteRow (a one-time consumption
/// credential, §1.3.3f).
const INVITES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("invites");
/// bind_token one-time consumption table (§2.4: linearizable dedup of
/// critical one-time control-plane operations).
const BIND_TOKENS: TableDefinition<&[u8], ()> = TableDefinition::new("bind_tokens");
/// M7: the VIP allocation pool returned by Expired rows (key = the 4-byte
/// VIP; allocation takes the smallest —— the first key of redb range
/// iteration).
const VIP_POOL: TableDefinition<&[u8], ()> = TableDefinition::new("vip_pool");
/// Misc KV (epoch/vip watermark; server.rs's cluster identity material also
/// lives here).
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// VIP pool: `100.64.0.0/10` (RFC 6598, §2.1); `.1` is reserved for the
/// server itself (§2.2 "the server itself is also a peer, VIP 100.64.0.1");
/// allocation starts at `.2`.
pub const VIP_FIRST: u32 = u32::from_be_bytes([100, 64, 0, 2]);
/// Pool end (the last usable address of the /10 block).
pub const VIP_LAST: u32 = u32::from_be_bytes([100, 127, 255, 254]);

/// Invite row (a one-time credential, §1.3.3f; a local row —— flock-sync's
/// InviteRow is the wire-format mirror, the single-server in-store encoding
/// is owned by this module).
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

/// `redeem_invite` rejection reason (interface-contract level: each
/// three-state one-time verdict, asserted item by item by the §7-M2
/// account-creation tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedeemError {
    /// A second redemption of the same invite_id (already marked used).
    AlreadyUsed,
    /// After `revoke_invite`.
    InviteRevoked,
    /// Expiry check failed (carrying both timestamps).
    Expired { now_unix: u64, expiry_unix: u64 },
    /// The server does not know this invite_id (not issued by this cluster /
    /// never registered).
    Unknown,
    /// Root signature/structure validation failed.
    BadInvite(String),
    /// Username already taken.
    UserExists,
    /// Device already registered.
    DeviceExists,
    /// VIP pool exhausted.
    IpExhausted,
    /// Internal error (IO/encoding).
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

/// Redemption input (device public keys enter the registry with the
/// redemption, §1.3.3f account creation; M7 adds hostname —— empty string
/// lands as "(unknown)", client reporting is a later stage).
///
/// `expected_root_pub`/`expected_cluster_id` = this cluster's identity
/// (injected by the caller from ServerCore): a self-consistent invite file
/// (its embedded root public key verifies its own signature) is **not
/// enough** —— it must be pinned as "signed by *this* root" to count as a
/// cluster invite (prevents an attacker from self-signing a root +
/// credentials to redeem an account).
pub struct RedeemRequest<'a> {
    pub invite_bytes: &'a [u8],
    pub username: &'a str,
    pub device_x25519: [u8; 32],
    pub device_ed25519: [u8; 32],
    pub hostname: &'a str,
    pub expected_root_pub: [u8; 32],
    pub expected_cluster_id: [u8; 16],
    pub now_unix: u64,
}

/// Redemption product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemOutcome {
    pub username: String,
    pub device_id: [u8; 32],
    pub vip: [u8; 4],
}

/// Write-operation error.
#[derive(Debug)]
pub enum NetError {
    NotFound,
    InvalidState(String),
    /// Device already registered (same ed25519 ⇒ re-registration with the
    /// same DeviceId). A standalone variant (not an `InvalidState` string)
    /// —— the control-plane KeyBind re-register dispatch decides by variant,
    /// not by the `"already registered"` string contract (the same-shape
    /// mapping of flock-sync's `StateError::DeviceExists` lives in
    /// backend.rs).
    DeviceExists,
    IpExhausted,
    Internal(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::NotFound => write!(f, "netstate: not found"),
            NetError::InvalidState(m) => write!(f, "netstate: invalid state: {m}"),
            NetError::DeviceExists => write!(f, "netstate: device already registered"),
            NetError::IpExhausted => write!(f, "netstate: VIP pool exhausted"),
            NetError::Internal(m) => write!(f, "netstate: internal: {m}"),
        }
    }
}

// Note (review item 12 three-way dedup): the M2-era `pub trait NetState` was
// deleted —— multi-primary reads/writes go through `backend::NetBackend`
// (the real seam: Single = a synchronous direct call of this module's
// StateStore inherent methods; Sync = Raft commit/linearizable read); a
// single-implementation trait only had the ceremonial value of "aligning the
// two forms by trait shape" while forcing `NetState as _` indirection on
// callers. The methods all converged into the inherent `impl StateStore`
// below; the row types are re-exported from flock-sync proto.rs.

// ============================================================================
// Row encoding (fixed-length manual codec: the byte-level layout of the
// fields is the storage contract)
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
    let mut v = Vec::with_capacity(32 + row.owner.len() + row.hostname.len() + 96);
    put_str(&mut v, &row.owner);
    v.extend_from_slice(&row.device_x25519);
    v.extend_from_slice(&row.device_ed25519);
    v.extend_from_slice(&row.vip);
    v.push(row.status.code());
    put_u64(&mut v, row.since_epoch);
    // M7 fields: hostname (length-prefixed string) + expired_at (presence
    // flag + u64) + registered_at (the reaper's anchor —— appended fields
    // change the row layout: old-store rows fail to decode, acceptable in
    // the unreleased window, §7-M7.1).
    put_str(&mut v, &row.hostname);
    match row.expired_at {
        Some(t) => {
            v.push(1);
            put_u64(&mut v, t);
        }
        None => v.push(0),
    }
    put_u64(&mut v, row.registered_at);
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
    let hostname = r.str()?;
    let expired_at = match r.u8()? {
        0 => None,
        1 => Some(r.u64()?),
        _ => return None,
    };
    let registered_at = r.u64()?;
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
        hostname,
        expired_at,
        registered_at,
    })
}

fn encode_user(row: &UserRow) -> Vec<u8> {
    let mut v = Vec::with_capacity(96);
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
    // M8 three fields (§7-M8.3): admin/disabled/pw_bootstrap (presence flag
    // + 16B).
    v.push(u8::from(row.admin));
    v.push(u8::from(row.disabled));
    match row.pw_bootstrap {
        Some(t) => {
            v.push(1);
            v.extend_from_slice(&t);
        }
        None => v.push(0),
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
    // M8 three fields: **lenient decoding of pre-M8 old rows (the
    // three-field tail absent)** —— admin/disabled default false,
    // pw_bootstrap defaults None (a different surface from flock-sync's
    // postcard snapshot's "clean failure" discipline: the redb row encoding
    // is this module's own layout, a truncated old-store row tail is a legal
    // old shape, leniency preserves existing deployments; once the write
    // path touches a row it upgrades to the new layout).
    if r.done() {
        return Some(UserRow {
            opaque_record,
            opaque_profile,
            sr_sig_pubs,
            admin: false,
            disabled: false,
            pw_bootstrap: None,
        });
    }
    let admin = r.u8()? != 0;
    let disabled = r.u8()? != 0;
    let pw_bootstrap = match r.u8()? {
        0 => None,
        1 => Some(r.take(16)?.try_into().expect("16B")),
        _ => return None,
    };
    if !r.done() {
        return None;
    }
    Some(UserRow {
        opaque_record,
        opaque_profile,
        sr_sig_pubs,
        admin,
        disabled,
        pw_bootstrap,
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
// redb implementation
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

/// The redb single-machine state machine (single writer = the server
/// process; `Arc`-shared with the session/control/admin tasks).
pub struct StateStore {
    db: Database,
}

impl std::fmt::Debug for StateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateStore").finish_non_exhaustive()
    }
}

impl StateStore {
    /// Open/create the state store (creates an empty store when the file is
    /// absent).
    pub fn open(path: &Path) -> Result<Self, NetError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| NetError::Internal(format!("state dir {}: {e}", dir.display())))?;
        }
        let db = Database::create(path)
            .map_err(|e| NetError::Internal(format!("redb open {}: {e}", path.display())))?;
        // The state store holds the root key seed/OPRF key/OPAQUE records ⇒
        // tighten to 0600 right after creation (review item 1;
        // redb::Database::create has no permission parameter, only a
        // set_permissions afterwards —— no write occurs between first
        // creation and tightening (table initialization happens in the
        // transaction below; zero data inside the redb file's
        // loose-permission window)).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| NetError::Internal(format!("chmod 0600 {}: {e}", path.display())))?;
        }
        let txn = db
            .begin_write()
            .map_err(|e| NetError::Internal(format!("redb tx: {e}")))?;
        {
            let _ = txn.open_table(DEVICES).map_err(int_err)?;
            let _ = txn.open_table(USERS).map_err(int_err)?;
            let _ = txn.open_table(INVITES).map_err(int_err)?;
            let _ = txn.open_table(BIND_TOKENS).map_err(int_err)?;
            let _ = txn.open_table(VIP_POOL).map_err(int_err)?;
            let _ = txn.open_table(META).map_err(int_err)?;
        }
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(StateStore { db })
    }

    /// META read (server.rs's cluster identity material lives here).
    pub fn meta_get(&self, key: &str) -> Option<Vec<u8>> {
        let txn = self.db.begin_read().ok()?;
        let t = txn.open_table(META).ok()?;
        t.get(key).ok().flatten().map(|v| v.value().to_vec())
    }

    /// META write (one-time bootstrap write; read-only at runtime).
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

    /// Invite registration (the issuing side: persisted at mint time in the
    /// same instant as the InviteFile).
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

    /// VIP allocation (M7 two-tier: **the Expired return pool first** (the
    /// smallest key of `VIP_POOL`), falling back to the monotonic watermark
    /// when empty (advance-only —— the VIPs of revoked/disabled rows never
    /// enter the pool, §2.1); beyond [`VIP_LAST`] means exhausted).
    fn alloc_vip_tx(
        meta: &mut redb::Table<'_, &str, &[u8]>,
        pool: &mut redb::Table<'_, &[u8], ()>,
    ) -> Result<u32, RedeemError> {
        // The pool's smallest key (redb's ordered-iteration first key = the
        // smallest u32::from_be_bytes).
        let pooled: Option<[u8; 4]> = match pool.first() {
            Ok(Some(first)) => first.0.value().try_into().ok(),
            _ => None,
        };
        if let Some(key) = pooled {
            pool.remove(key.as_slice()).map_err(internal)?;
            return Ok(u32::from_be_bytes(key));
        }
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
            if row.status == DeviceStatus::Expired {
                // M7: Expired is an irreversible terminal state (the old VIP
                // may already belong to another device —— resurrection breaks
                // uniqueness).
                return Err(NetError::InvalidState("expired is terminal".into()));
            }
            if row.status != status {
                // Only "blocking" transitions (→ Disabled/Revoked) advance
                // the global revocation_epoch (§2.2); Enable (→ Active) is a
                // restoration and does not move the epoch —— otherwise it
                // would harmlessly void every in-flight ticket network-wide.
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

    /// M7: the expiry transition (submitted by the reaper) —— semantics
    /// share provenance with flock-sync's `apply_expire`.
    ///
    /// Row retained for audit + `expired_at` persisted + VIP returned to the
    /// pool + epoch advanced (session kills/ticket invalidation are consumed
    /// by the caller per the epoch semantics). Idempotent: already-Expired
    /// passes; Revoked is rejected (the IP is never reused).
    pub fn expire(&self, id: &DeviceId, now_unix: u64) -> Result<u64, NetError> {
        let txn = self.db.begin_write().map_err(int_err)?;
        let ret: Result<u64, NetError> = {
            let mut devices = txn.open_table(DEVICES).map_err(int_err)?;
            let mut meta = txn.open_table(META).map_err(int_err)?;
            let mut pool = txn.open_table(VIP_POOL).map_err(int_err)?;
            let raw = devices
                .get(id.0.as_slice())
                .map_err(int_err)?
                .ok_or(NetError::NotFound)?
                .value()
                .to_vec();
            let mut row = decode_device(&raw)
                .ok_or_else(|| NetError::Internal(format!("corrupt device row for {id}")))?;
            if row.status == DeviceStatus::Expired {
                return meta_u64(&meta, "epoch").map_err(int_err);
            }
            if row.status == DeviceStatus::Revoked {
                return Err(NetError::InvalidState("revoked is terminal".into()));
            }
            let epoch = meta_u64(&meta, "epoch").map_err(int_err)? + 1;
            meta.insert("epoch", epoch.to_be_bytes().as_slice())
                .map_err(int_err)?;
            row.since_epoch = epoch;
            row.status = DeviceStatus::Expired;
            row.expired_at = Some(now_unix);
            pool.insert(row.vip.as_slice(), ()).map_err(int_err)?;
            devices
                .insert(id.0.as_slice(), encode_device(&row).as_slice())
                .map_err(int_err)?;
            Ok(epoch)
        };
        let out = ret?;
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(out)
    }

    /// M7: hostname update (the re-register path; non-terminal rows only).
    pub fn set_hostname(&self, id: &DeviceId, hostname: &str) -> Result<DeviceRow, NetError> {
        let txn = self.db.begin_write().map_err(int_err)?;
        let ret: Result<DeviceRow, NetError> = {
            let mut devices = txn.open_table(DEVICES).map_err(int_err)?;
            let raw = devices
                .get(id.0.as_slice())
                .map_err(int_err)?
                .ok_or(NetError::NotFound)?
                .value()
                .to_vec();
            let mut row = decode_device(&raw)
                .ok_or_else(|| NetError::Internal(format!("corrupt device row for {id}")))?;
            if matches!(row.status, DeviceStatus::Revoked | DeviceStatus::Expired) {
                return Err(NetError::InvalidState("terminal state".into()));
            }
            row.hostname = flock_sync::normalize_hostname(hostname);
            devices
                .insert(id.0.as_slice(), encode_device(&row).as_slice())
                .map_err(int_err)?;
            Ok(row)
        };
        let out = ret?;
        txn.commit()
            .map_err(|e| NetError::Internal(format!("redb commit: {e}")))?;
        Ok(out)
    }

    /// The redemption's invite validation + account creation (one write
    /// transaction: atomicity = the local counterpart of M4 Raft's single
    /// commit).
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
            let mut pool = txn.open_table(VIP_POOL).map_err(internal)?;

            let raw = invites
                .get(invite_id.as_slice())
                .map_err(internal)?
                .ok_or(RedeemError::Unknown)?
                .value()
                .to_vec();
            let row = decode_invite(&raw)
                .ok_or_else(|| RedeemError::Internal("corrupt invite row".into()))?;
            // The one-time three verdicts (asserted one by one by the §7-M2
            // account-creation tests).
            match row.status {
                InviteStatus::Used => return Err(RedeemError::AlreadyUsed),
                InviteStatus::Revoked => return Err(RedeemError::InviteRevoked),
                InviteStatus::Valid => {}
            }
            // The expiry verdict follows the in-store row (the expiry
            // registered by the issuing side).
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
            // Create the user (when absent).
            if users.get(req.username).map_err(internal)?.is_some() {
                return Err(RedeemError::UserExists);
            }
            users
                .insert(req.username, encode_user(&UserRow::default()).as_slice())
                .map_err(internal)?;

            // VIP allocation (M7: the Expired return pool first, falling
            // back to the monotonic watermark when empty —— the §2.1 IP
            // reuse policy).
            let vip = Self::alloc_vip_tx(&mut meta, &mut pool)?.to_be_bytes();

            let dev_row = DeviceRow {
                owner: req.username.to_string(),
                device_x25519: req.device_x25519,
                device_ed25519: req.device_ed25519,
                vip,
                status: DeviceStatus::Active,
                since_epoch: 0,
                hostname: flock_sync::normalize_hostname(req.hostname),
                expired_at: None,
                // The redemption time is the registration time (the reaper's
                // anchor, §7-M7.5).
                registered_at: req.now_unix,
            };
            devices
                .insert(device_id.as_slice(), encode_device(&dev_row).as_slice())
                .map_err(internal)?;

            // Mark used (same transaction: no window between the dedup check
            // and the mark).
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

// ============================================================================
// The StateStore inherent read/write surface (the former `impl NetState for
// StateStore` —— converged into inherent methods after the trait deletion,
// review item 12; semantics/signatures unchanged)
// ============================================================================

impl StateStore {
    /// Register a device (M7 adds hostname —— empty string lands as
    /// "(unknown)"; the VIP allocation pool goes first).
    pub fn register_device(
        &self,
        owner: &str,
        x25519: [u8; 32],
        ed25519: [u8; 32],
        hostname: &str,
    ) -> Result<DeviceRow, NetError> {
        let device_id: [u8; 32] = Sha256::digest(ed25519).into();
        let txn = self.db.begin_write().map_err(int_err)?;
        let out = {
            let mut devices = txn.open_table(DEVICES).map_err(int_err)?;
            let mut users = txn.open_table(USERS).map_err(int_err)?;
            let mut meta = txn.open_table(META).map_err(int_err)?;
            let mut pool = txn.open_table(VIP_POOL).map_err(int_err)?;
            if devices
                .get(device_id.as_slice())
                .map_err(int_err)?
                .is_some()
            {
                return Err(NetError::DeviceExists);
            }
            if users.get(owner).map_err(int_err)?.is_none() {
                users
                    .insert(owner, encode_user(&UserRow::default()).as_slice())
                    .map_err(int_err)?;
            }
            let cur = Self::alloc_vip_tx(&mut meta, &mut pool).map_err(|e| match e {
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
                hostname: flock_sync::normalize_hostname(hostname),
                expired_at: None,
                // Registration time persisted on the row (the reaper's
                // anchor —— the retention period's starting point when
                // last_seen has no observation, §7-M7.5).
                registered_at: flock_protocol::trust::now_unix(),
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

    pub fn revoke(&self, id: &DeviceId) -> Result<u64, NetError> {
        self.set_device_status(id, DeviceStatus::Revoked)
            .map(|(_, epoch)| epoch)
    }

    pub fn disable(&self, id: &DeviceId) -> Result<u64, NetError> {
        self.set_device_status(id, DeviceStatus::Disabled)
            .map(|(_, epoch)| epoch)
    }

    pub fn enable(&self, id: &DeviceId) -> Result<(), NetError> {
        self.set_device_status(id, DeviceStatus::Active).map(|_| ())
    }

    pub fn lookup(&self, id: &DeviceId) -> LookupVerdict {
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
                        // A corrupt row is treated as untrusted (fail-closed,
                        // same shape as NotFound).
                        _ => LookupVerdict::NotFound,
                    }
                }
                DeviceStatus::Disabled | DeviceStatus::Revoked | DeviceStatus::Expired => {
                    LookupVerdict::Revoked {
                        since_epoch: row.since_epoch,
                    }
                }
            },
            None => LookupVerdict::NotFound,
        }
    }

    pub fn device_row(&self, id: &DeviceId) -> Option<DeviceRow> {
        let txn = self.db.begin_read().ok()?;
        let t = txn.open_table(DEVICES).ok()?;
        let raw = t.get(id.0.as_slice()).ok()??;
        decode_device(raw.value())
    }

    pub fn devices_of(&self, owner: &str) -> Vec<(DeviceId, DeviceRow)> {
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

    /// M7: all device rows (the registry snapshot for roster assembly —— a
    /// local read suffices, §7-M7.4).
    pub fn devices_all(&self) -> Vec<(DeviceId, DeviceRow)> {
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
            if let Some(row) = decode_device(e.1.value()) {
                out.push((DeviceId(idb), row));
            }
        }
        out
    }

    pub fn allocate_ip(&self) -> Result<Ipv4Addr, NetError> {
        let txn = self.db.begin_write().map_err(int_err)?;
        let out = {
            let mut meta = txn.open_table(META).map_err(int_err)?;
            let mut pool = txn.open_table(VIP_POOL).map_err(int_err)?;
            let cur = Self::alloc_vip_tx(&mut meta, &mut pool).map_err(|e| match e {
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

    pub fn redeem_invite(&self, req: RedeemRequest<'_>) -> Result<RedeemOutcome, RedeemError> {
        let device_id: [u8; 32] = Sha256::digest(req.device_ed25519).into();
        // Root signature/structure validation + this cluster's identity
        // pinned, ahead of any state touch.
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

    pub fn revoke_invite(&self, invite_id: &[u8; 16]) -> Result<(), NetError> {
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

    pub fn epoch(&self) -> u64 {
        self.meta_get("epoch")
            .and_then(|v| v.try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0)
    }

    pub fn set_password(&self, user: &str, record_b64: &str, profile: u16) -> Result<(), NetError> {
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

    pub fn password(&self, user: &str) -> Option<(String, u16)> {
        let txn = self.db.begin_read().ok()?;
        let t = txn.open_table(USERS).ok()?;
        let raw = t.get(user).ok()??;
        let row = decode_user(raw.value())?;
        row.opaque_record.map(|r| (r, row.opaque_profile))
    }

    pub fn add_user_sig_key(&self, user: &str, pub32: [u8; 32]) -> Result<(), NetError> {
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

    pub fn user_sig_pubs(&self, user: &str) -> Vec<VerifyingKey> {
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

    pub fn consume_bind_token(&self, token: &[u8; 16]) -> bool {
        let Ok(txn) = self.db.begin_write() else {
            return false;
        };
        {
            let Ok(mut t) = txn.open_table(BIND_TOKENS) else {
                return false;
            };
            if t.get(token.as_slice()).ok().flatten().is_some() {
                return false; // already consumed (verdict read, no commit)
            }
            if t.insert(token.as_slice(), ()).is_err() {
                return false;
            }
        }
        txn.commit().map(|_| true).unwrap_or(false)
    }

    // ------------------------------------------------------------------
    // M8 (§7-M8.3): Web admin-plane user operations (the single-server
    // direct-write arm; the Raft arm = the five SyncRequest writes, both
    // arms converged with the same semantics through backend::NetBackend)
    // ------------------------------------------------------------------

    /// User row (admin/disabled/pw_bootstrap included; absent ⇒ None).
    pub fn user_row(&self, user: &str) -> Option<UserRow> {
        let txn = self.db.begin_read().ok()?;
        let t = txn.open_table(USERS).ok()?;
        let raw = t.get(user).ok()??;
        decode_user(raw.value())
    }

    /// All user rows (`/api/users`·summary totals; username ordering is the
    /// caller's).
    pub fn users_all(&self) -> Vec<(String, UserRow)> {
        let Ok(txn) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(t) = txn.open_table(USERS) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let Ok(range) = t.iter() {
            for entry in range.flatten() {
                let (k, v) = (entry.0.value().to_string(), entry.1.value());
                if let Some(row) = decode_user(v) {
                    out.push((k, row));
                }
            }
        }
        out
    }

    /// Create a user (no password record, carrying the one-time bootstrap
    /// token); already exists ⇒ [`UserOpError::UserExists`] (same semantics
    /// as the Raft `CreateUser` —— the submitting side ignores it
    /// idempotently as needed).
    pub fn create_user(&self, username: &str, pw_bootstrap: [u8; 16]) -> Result<(), UserOpError> {
        let txn = self.db.begin_write().map_err(op_int)?;
        {
            let mut users = txn.open_table(USERS).map_err(op_int)?;
            if users.get(username).map_err(op_int)?.is_some() {
                return Err(UserOpError::UserExists);
            }
            let row = UserRow {
                pw_bootstrap: Some(pw_bootstrap),
                ..UserRow::default()
            };
            users
                .insert(username, encode_user(&row).as_slice())
                .map_err(op_int)?;
        }
        txn.commit().map_err(|e| op_int(e.to_string()))?;
        Ok(())
    }

    /// Persist the password record via the bootstrap token (atomic: token
    /// matches and record empty ⇒ persist the record + clear the token; the
    /// verdict order is verbatim-identical to the Raft
    /// `SetPasswordBootstrap` —— the token check precedes the record check,
    /// leaking no hint of an existing password).
    pub fn set_password_bootstrap(
        &self,
        user: &str,
        token: [u8; 16],
        record_b64: &str,
        profile: u16,
    ) -> Result<(), UserOpError> {
        let txn = self.db.begin_write().map_err(op_int)?;
        {
            let mut users = txn.open_table(USERS).map_err(op_int)?;
            let mut row = user_row_tx(&users, user)?;
            if row.pw_bootstrap != Some(token) {
                return Err(UserOpError::BadBootstrapToken);
            }
            if row.opaque_record.is_some() {
                return Err(UserOpError::PasswordExists);
            }
            row.opaque_record = Some(record_b64.to_string());
            row.opaque_profile = profile;
            row.pw_bootstrap = None;
            users
                .insert(user, encode_user(&row).as_slice())
                .map_err(op_int)?;
        }
        txn.commit().map_err(|e| op_int(e.to_string()))?;
        Ok(())
    }

    /// Administrator password reset: clear the record + set a new bootstrap
    /// token (the old password stops working immediately).
    pub fn reset_password(&self, user: &str, new_token: [u8; 16]) -> Result<(), UserOpError> {
        let txn = self.db.begin_write().map_err(op_int)?;
        {
            let mut users = txn.open_table(USERS).map_err(op_int)?;
            let mut row = user_row_tx(&users, user)?;
            row.opaque_record = None;
            row.opaque_profile = 0;
            row.pw_bootstrap = Some(new_token);
            users
                .insert(user, encode_user(&row).as_slice())
                .map_err(op_int)?;
        }
        txn.commit().map_err(|e| op_int(e.to_string()))?;
        Ok(())
    }

    /// Grant/revoke the Web admin role (the session-side cannot_demote_self
    /// adjudication lives at the webui handler layer).
    pub fn set_user_admin(&self, user: &str, admin: bool) -> Result<(), UserOpError> {
        let txn = self.db.begin_write().map_err(op_int)?;
        {
            let mut users = txn.open_table(USERS).map_err(op_int)?;
            let mut row = user_row_tx(&users, user)?;
            row.admin = admin;
            users
                .insert(user, encode_user(&row).as_slice())
                .map_err(op_int)?;
        }
        txn.commit().map_err(|e| op_int(e.to_string()))?;
        Ok(())
    }

    /// Disable/enable a user (blocks Web and control-flow login; does not
    /// retroactively drop established sessions).
    pub fn set_user_disabled(&self, user: &str, disabled: bool) -> Result<(), UserOpError> {
        let txn = self.db.begin_write().map_err(op_int)?;
        {
            let mut users = txn.open_table(USERS).map_err(op_int)?;
            let mut row = user_row_tx(&users, user)?;
            row.disabled = disabled;
            users
                .insert(user, encode_user(&row).as_slice())
                .map_err(op_int)?;
        }
        txn.commit().map_err(|e| op_int(e.to_string()))?;
        Ok(())
    }
}

/// The M8 user-operation error surface (both arms share the semantics;
/// webui/admin common).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserOpError {
    UserExists,
    PasswordExists,
    /// Token mismatched/already consumed (same semantics as flock-sync's
    /// `StateError::BadBootstrapToken`).
    BadBootstrapToken,
    NoSuchUser,
    Internal(String),
}

impl std::fmt::Display for UserOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserOpError::UserExists => write!(f, "username already exists"),
            UserOpError::PasswordExists => write!(f, "password already set"),
            UserOpError::BadBootstrapToken => write!(f, "bad or consumed bootstrap token"),
            UserOpError::NoSuchUser => write!(f, "no such user"),
            UserOpError::Internal(m) => write!(f, "internal: {m}"),
        }
    }
}

fn op_int(e: impl std::fmt::Display) -> UserOpError {
    UserOpError::Internal(format!("redb: {e}"))
}

fn user_row_tx(users: &redb::Table<'_, &str, &[u8]>, user: &str) -> Result<UserRow, UserOpError> {
    let raw = users
        .get(user)
        .map_err(op_int)?
        .ok_or(UserOpError::NoSuchUser)?
        .value()
        .to_vec();
    decode_user(&raw).ok_or_else(|| UserOpError::Internal("corrupt user row".into()))
}

/// The session::DeviceDirectory adapter (injected on the respond side, the
/// §3.5 lookup seam).
pub struct DirAdapter(pub Arc<StateStore>);

impl flock_protocol::session::DeviceDirectory for DirAdapter {
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict> {
        let v = self.0.lookup(id);
        Box::pin(async move { v })
    }
}

// ============================================================================
// Unit tests: the one-time invite three states / VIP pool discipline /
// disable does not delete
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use flock_protocol::session::{ClusterId, ServerEntry, ServerId};
    use flock_protocol::trust::InviteFile;
    use flock_protocol::{rand, sig::UserKey};

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

    /// Redemption request construction (identity = the fixture's
    /// root/cluster). `root_override` simulates an "other-signed" invite.
    fn req<'a>(
        invite: &'a [u8],
        username: &'a str,
        device_seed: u8,
        root: &SigningKey,
    ) -> RedeemRequest<'a> {
        req_h(invite, username, device_seed, root, "")
    }

    /// Redemption request construction with hostname (M7).
    fn req_h<'a>(
        invite: &'a [u8],
        username: &'a str,
        device_seed: u8,
        root: &SigningKey,
        hostname: &'a str,
    ) -> RedeemRequest<'a> {
        let (x, ed) = dev_keys(device_seed);
        RedeemRequest {
            invite_bytes: invite,
            username,
            device_x25519: x,
            device_ed25519: ed,
            hostname,
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
            "the first VIP = 100.64.0.2 (.1 reserved for the server)"
        );
        let id = DeviceId(out.device_id);
        let row = s.device_row(&id).expect("row");
        assert_eq!(row.owner, "alice");
        assert_eq!(row.status, DeviceStatus::Active);
        // A second redemption of the same invite_id is rejected.
        let err = s.redeem_invite(req(&bytes, "bob", 6, &root)).unwrap_err();
        assert_eq!(err, RedeemError::AlreadyUsed);
    }

    #[test]
    fn redeem_rejects_revoked_expired_unknown_and_forged() {
        let s = store();
        let root = SigningKey::from_bytes(&[3; 32]);
        // Rejected after revoke_invite.
        s.record_invite(&[2; 16], 999_999).unwrap();
        s.revoke_invite(&[2; 16]).unwrap();
        let bytes = invite_fixture(&root, 999_999, [2; 16]);
        assert_eq!(
            s.redeem_invite(req(&bytes, "u1", 1, &root)).unwrap_err(),
            RedeemError::InviteRevoked
        );
        // Expired rejected.
        s.record_invite(&[3; 16], 500).unwrap();
        let expired = invite_fixture(&root, 500, [3; 16]);
        assert_eq!(
            s.redeem_invite(req(&expired, "u2", 2, &root)).unwrap_err(),
            RedeemError::Expired {
                now_unix: 1000,
                expiry_unix: 500
            }
        );
        // Unregistered (no issuance record for this cluster) rejected.
        let unknown = invite_fixture(&root, 999_999, [4; 16]);
        assert_eq!(
            s.redeem_invite(req(&unknown, "u3", 3, &root)).unwrap_err(),
            RedeemError::Unknown
        );
        // Forged (issued under a different root —— even with the invite_id
        // registered in-store by someone else) rejected: this cluster's root
        // is pinned.
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
        let a = s.register_device("u", [1; 32], [1; 32], "").unwrap();
        let b = s.register_device("u", [2; 32], [2; 32], "").unwrap();
        let ip2 = u32::from_be_bytes(b.vip);
        let ip1 = u32::from_be_bytes(a.vip);
        assert!(ip2 > ip1, "monotonically increasing");
        // After revoking a, registering again: a's VIP is not reused (the
        // watermark only advances).
        let id_a = DeviceId(Sha256::digest([1u8; 32]).into());
        let epoch = s.revoke(&id_a).unwrap();
        assert!(epoch >= 1, "revoke advances the revocation_epoch");
        let c = s.register_device("u", [3; 32], [3; 32], "").unwrap();
        assert_eq!(u32::from_be_bytes(c.vip), ip2 + 1, "the IP is not reused");
        // Disable does not delete: the row remains, status Disabled, the VIP
        // not recycled; lookup gives the Revoked verdict.
        let id_b = DeviceId(Sha256::digest([2u8; 32]).into());
        let epoch2 = s.disable(&id_b).unwrap();
        assert!(epoch2 > epoch, "disable also advances the epoch");
        let row = s
            .device_row(&id_b)
            .expect("row retained (disable does not delete)");
        assert_eq!(row.status, DeviceStatus::Disabled);
        assert_eq!(row.vip, b.vip, "VIP not recycled");
        assert!(matches!(s.lookup(&id_b), LookupVerdict::Revoked { .. }));
        assert!(matches!(s.lookup(&id_a), LookupVerdict::Revoked { .. }));
        // Re-enable: Disabled → Active; the epoch does not regress.
        s.enable(&id_b).unwrap();
        assert_eq!(s.device_row(&id_b).unwrap().status, DeviceStatus::Active);
        assert_eq!(s.epoch(), epoch2, "enable does not move the epoch");
        // The Revoked terminal state is irreversible.
        assert!(s.enable(&id_a).is_err());
    }

    /// M7: expire releases the VIP back into the pool (a new device gets
    /// that VIP) + idempotence + terminal state + Expired ≠ Revoked
    /// (status/expired_at distinguishable) + the devices_all snapshot +
    /// hostname lands as "(unknown)".
    #[test]
    fn expire_releases_vip_and_reassigns_single_form() {
        let s = store();
        let a = s.register_device("u", [1; 32], [1; 32], "").unwrap();
        let _b = s.register_device("u", [2; 32], [2; 32], "host-b").unwrap();
        assert_eq!(
            a.hostname,
            flock_sync::HOSTNAME_UNKNOWN,
            "empty string ⇒ (unknown)"
        );
        let id_a = DeviceId(Sha256::digest([1u8; 32]).into());
        let e1 = s.expire(&id_a, 1_700_000_000).unwrap();
        assert!(e1 >= 1, "expire advances the epoch");
        let row = s.device_row(&id_a).unwrap();
        assert_eq!(row.status, DeviceStatus::Expired);
        assert_eq!(row.expired_at, Some(1_700_000_000));
        assert_eq!(row.vip, a.vip, "row retained (audit)");
        // Idempotent: a second expire does not move epoch/expired_at.
        assert_eq!(s.expire(&id_a, 1_800_000_000).unwrap(), e1);
        assert_eq!(s.device_row(&id_a).unwrap().expired_at, Some(1_700_000_000));
        // A new device gets the pool's smallest = a's VIP.
        let c = s.register_device("u", [3; 32], [3; 32], "").unwrap();
        assert_eq!(c.vip, a.vip, "in-pool VIP reassigned");
        // Terminal: enable/expire-after-revoke rejected.
        assert!(
            s.enable(&id_a).is_err(),
            "Expired terminal state irreversible"
        );
        assert!(
            s.set_hostname(&id_a, "x").is_err(),
            "terminal rows cannot change hostname"
        );
        // devices_all snapshot: three rows (the Expired row round-trips the
        // hostname/expired_at fields).
        let all = s.devices_all();
        assert_eq!(all.len(), 3);
        let expired = all
            .iter()
            .find(|(id, _)| *id == id_a)
            .map(|(_, r)| r.clone())
            .unwrap();
        assert_eq!(expired.status, DeviceStatus::Expired);
        // lookup: Expired blocks (the Revoked-verdict shape).
        assert!(matches!(s.lookup(&id_a), LookupVerdict::Revoked { .. }));
        // Revoked does not turn re-assignable via expire.
        let id_c = DeviceId(Sha256::digest([3u8; 32]).into());
        s.revoke(&id_c).unwrap();
        assert!(s.expire(&id_c, 9_999_999_999).is_err());
    }

    /// M7: set_hostname update (re-register semantics) + the redemption path
    /// persists the hostname.
    #[test]
    fn hostname_update_and_redeem_carries_hostname() {
        let s = store();
        let root = SigningKey::from_bytes(&[3; 32]);
        let bytes = invite_fixture(&root, 999_999, [7; 16]);
        s.record_invite(&[7; 16], 999_999).unwrap();
        let out = s
            .redeem_invite(req_h(&bytes, "harry", 6, &root, "  harry-pad  "))
            .expect("redeem");
        let id = DeviceId(out.device_id);
        assert_eq!(
            s.device_row(&id).unwrap().hostname,
            "harry-pad",
            "the redemption carries the hostname (trim normalization)"
        );
        // re-register update.
        let row = s.set_hostname(&id, "renamed").unwrap();
        assert_eq!(row.hostname, "renamed");
        assert_eq!(s.device_row(&id).unwrap().hostname, "renamed");
        // Unknown device rejected.
        assert!(s.set_hostname(&DeviceId([9; 32]), "x").is_err());
    }

    #[test]
    fn bind_token_single_use_and_user_keys() {
        let s = store();
        s.register_device("u", [1; 32], [1; 32], "").unwrap();
        let tok = [7u8; 16];
        assert!(s.consume_bind_token(&tok), "first consumption");
        assert!(!s.consume_bind_token(&tok), "second rejected");
        let key = UserKey::from_seed(&[9; 32]);
        let pub32 = *UserKey::from_pub_string(&key.pub_string())
            .unwrap()
            .as_bytes();
        s.add_user_sig_key("u", pub32).unwrap();
        assert_eq!(s.user_sig_pubs("u").len(), 1);
        assert_eq!(s.password("u"), None, "no password set");
        s.set_password("u", "rec", 0).unwrap();
        assert_eq!(s.password("u"), Some(("rec".into(), 0)));
        assert!(
            s.set_password("u", "rec2", 0).is_err(),
            "already set cannot be set again"
        );
    }

    // Review item 1: netstate.redb is tightened to 0600 at creation (unix
    // arm —— a state store holding the root key seed/OPRF key never sits on
    // loose permissions).
    #[cfg(unix)]
    #[test]
    fn netstate_redb_created_with_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("netstate.redb");
        let _s = StateStore::open(&path).expect("open");
        assert_eq!(
            std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
            0o600,
            "netstate.redb permissions 0600"
        );
        // Reopening (existing file) also keeps 0600. Drop the first handle
        // before opening again —— redb holds an exclusive lock on the same
        // file (flock semantics also apply to a second in-process handle,
        // "Database already open"), so the true meaning of "reopen" is a
        // reopen after the process exits. unix test surface: a Windows dev
        // machine does not compile this case; the exclusivity only shows up
        // in Linux containers/CI (exposed on the first container test run).
        drop(_s);
        let _s2 = StateStore::open(&path).expect("reopen");
        assert_eq!(
            std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
            0o600
        );
    }
    // ------------------------------------------------------------------
    // M8 (§7-M8.3): the user-operation semantics of the single-server
    // direct-write arm (same semantics as the five Raft writes —— verdict
    // order/error surface verbatim-identical; the Raft arm's semantics are
    // in flock-sync state::tests)
    // ------------------------------------------------------------------

    #[test]
    fn m8_user_ops_single_store_semantics() {
        let s = store();
        // Account creation: the token lands with the account; a duplicate
        // name is rejected without touching the original row.
        s.create_user("admin", [0xA1; 16]).unwrap();
        let row = s.user_row("admin").unwrap();
        assert_eq!(row.pw_bootstrap, Some([0xA1; 16]));
        assert!(!row.admin && !row.disabled && row.opaque_record.is_none());
        assert_eq!(
            s.create_user("admin", [0xB2; 16]),
            Err(UserOpError::UserExists)
        );
        assert_eq!(s.user_row("admin").unwrap().pw_bootstrap, Some([0xA1; 16]));

        // Bootstrap record persistence: wrong token ⇒ BadBootstrapToken
        // (leaks no hint of an existing password); correct ⇒ record
        // persisted + token cleared; replay ⇒ BadBootstrapToken.
        assert_eq!(
            s.set_password_bootstrap("admin", [0xB2; 16], "r", 0),
            Err(UserOpError::BadBootstrapToken)
        );
        s.set_password_bootstrap("admin", [0xA1; 16], "rec", 0)
            .unwrap();
        let row = s.user_row("admin").unwrap();
        assert_eq!(row.opaque_record.as_deref(), Some("rec"));
        assert_eq!(row.pw_bootstrap, None);
        assert_eq!(
            s.set_password_bootstrap("admin", [0xA1; 16], "r2", 0),
            Err(UserOpError::BadBootstrapToken),
            "token replay rejected"
        );

        // The four writes reject an unknown user alike.
        assert_eq!(
            s.set_password_bootstrap("ghost", [0; 16], "r", 0),
            Err(UserOpError::NoSuchUser)
        );
        assert_eq!(
            s.reset_password("ghost", [0; 16]),
            Err(UserOpError::NoSuchUser)
        );
        assert_eq!(
            s.set_user_admin("ghost", true),
            Err(UserOpError::NoSuchUser)
        );
        assert_eq!(
            s.set_user_disabled("ghost", true),
            Err(UserOpError::NoSuchUser)
        );

        // Reset: the old record stops working immediately + the new token
        // can land a new record.
        s.reset_password("admin", [0xC3; 16]).unwrap();
        assert!(s.user_row("admin").unwrap().opaque_record.is_none());
        s.set_password_bootstrap("admin", [0xC3; 16], "rec2", 0)
            .unwrap();
        assert_eq!(s.password("admin").unwrap().0, "rec2");

        // admin/disabled round trips; disabling does not clear the password
        // record.
        s.set_user_admin("admin", true).unwrap();
        assert!(s.user_row("admin").unwrap().admin);
        s.set_user_disabled("admin", true).unwrap();
        assert!(s.user_row("admin").unwrap().disabled);
        assert_eq!(
            s.user_row("admin").unwrap().opaque_record.as_deref(),
            Some("rec2"),
            "disable does not clear the password"
        );
        s.set_user_disabled("admin", false).unwrap();
        s.set_user_admin("admin", false).unwrap();

        // users_all: full round trip with the M8 fields.
        s.create_user("bob", [1; 16]).unwrap();
        let all = s.users_all();
        assert_eq!(all.len(), 2);
        assert!(all
            .iter()
            .any(|(u, r)| u == "bob" && r.pw_bootstrap == Some([1; 16])));
    }

    /// Lenient decoding of pre-M8 old rows (three-field tail truncated):
    /// admin/disabled default, token default —— existing deployments upgrade
    /// unbroken (once the write path touches a row it upgrades to the new
    /// layout).
    #[test]
    fn m8_legacy_user_row_decodes_lenient() {
        // Hand-build a pre-M8 encoding (byte-identical to encode_user's old
        // shape).
        let legacy = {
            let mut v = Vec::new();
            v.push(1);
            put_str(&mut v, "old-record");
            put_u16(&mut v, 0);
            put_u16(&mut v, 1);
            v.extend_from_slice(&[7u8; 32]);
            v
        };
        let row = decode_user(&legacy).expect("old row decodes leniently");
        assert_eq!(row.opaque_record.as_deref(), Some("old-record"));
        assert_eq!(row.sr_sig_pubs, vec![[7u8; 32]]);
        assert!(!row.admin && !row.disabled && row.pw_bootstrap.is_none());
        // Trailing garbage (an incomplete M8 tail) ⇒ None (no partial
        // decoding).
        let mut bad = legacy.clone();
        bad.push(1); // truncated after admin=1
        assert!(decode_user(&bad).is_none());
        // New-shape round trip.
        let row = UserRow {
            opaque_record: None,
            opaque_profile: 0,
            sr_sig_pubs: vec![],
            admin: true,
            disabled: true,
            pw_bootstrap: Some([9; 16]),
        };
        assert_eq!(decode_user(&encode_user(&row)).unwrap(), row);
    }
}
