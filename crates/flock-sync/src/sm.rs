//! openraft state machine adapter (RaftStateMachine v2) + apply callback hooks
//! + lag injection.
//!
//! Responsibilities (§2.2 revocation-propagation boundary):
//! - apply each Normal log entry → deterministic execution by
//!   [`NetStateData::apply`];
//! - blocking transitions (Revoke/Disable) ⇒ fire the [`crate::hooks`]
//!   kill-local-session hooks + broadcast the epoch watch (the record cache
//!   invalidates on it);
//! - Membership entries ⇒ maintain `last_membership` (the applied_state
//!   contract);
//! - snapshot = postcard(NetStateData) (persisted in a separate redb table;
//!   the table name is distinct from the log store's, avoiding redb
//!   write-transaction table-level conflicts).
//!
//! Shared surface: `SmCore` is held via `Arc` by [`crate::node`]/
//! [`crate::dir`] for local reads (the cache path); Raft holds
//! `RedbStateMachine` for serialized applies — the state itself sits behind an
//! `RwLock`, and the apply path holds no lock across awaits (hooks/timed
//! sends do not block).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use openraft::storage::RaftSnapshotBuilder;
use openraft::{
    BasicNode, Entry, EntryPayload, ErrorSubject, ErrorVerb, LogId, Snapshot, SnapshotMeta,
    StorageError, StoredMembership, ToStorageResult,
};
use redb::{Database, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::hooks::HookRegistry;
use crate::proto::SyncResponse;
use crate::raft_types::SyncConfig;
use crate::state::NetStateData;

/// SM-side snapshot persistence table (separate from the log-store tables:
/// redb concurrent write transactions avoid conflicts at table granularity).
pub const SMKV_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("flock_sync_sm");

/// Snapshot bundle (wire + persistence format).
#[derive(Serialize, Deserialize)]
struct SnapBundle {
    meta: SnapshotMeta<u64, BasicNode>,
    data: NetStateData,
}

/// Test-side apply lag injection (M4 §7: artificially stall a follower by 5s ⇒
/// apply-lag breaker cases). Once armed, every apply batch first sleeps the
/// configured duration — logs are still received as usual (storage append is
/// not delayed), heartbeats still flow (the network is not delayed); only the
/// state machine apply stalls.
#[derive(Debug)]
pub struct LagInjector {
    armed: AtomicBool,
    delay: RwLock<Duration>,
}

impl LagInjector {
    pub fn new() -> Arc<Self> {
        Arc::new(LagInjector {
            armed: AtomicBool::new(false),
            delay: RwLock::new(Duration::ZERO),
        })
    }

    /// Arm (delay = how long each apply batch stalls).
    pub fn arm(&self, delay: Duration) {
        *self.delay.write().expect("lag delay") = delay;
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Disarm.
    pub fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }

    pub fn armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }

    async fn maybe_delay(&self) {
        if self.armed() {
            let d = *self.delay.read().expect("lag delay");
            if d > Duration::ZERO {
                tokio::time::sleep(d).await;
            }
        }
    }
}

/// State machine shared core (read path + hooks + watch).
pub struct SmCore {
    db: Arc<Database>,
    data: RwLock<NetStateData>,
    /// The cluster root public key pinned by this node's config (a second
    /// line of defense for admin verification; after Bootstrap the in-state
    /// one is authoritative).
    pinned_root: Option<ed25519_dalek::VerifyingKey>,
    hooks: std::sync::Mutex<HookRegistry>,
    /// Highest applied log index (shared consumer: LagMonitor).
    applied_index: Arc<AtomicU64>,
    /// Broadcast of the current global revocation_epoch (record cache
    /// invalidation + ticket verification consumption).
    epoch_tx: watch::Sender<u64>,
    /// Test lag injection.
    pub lag: Arc<LagInjector>,
}

impl SmCore {
    /// Construct from an existing redb database and initial state
    /// (`pinned_root` = the locally pinned root, may be None).
    pub fn new(
        db: Arc<Database>,
        mut data: NetStateData,
        pinned_root: Option<ed25519_dalek::VerifyingKey>,
    ) -> Arc<Self> {
        // The VIP reverse-lookup index is derived data (not serialized):
        // rebuilt on entry from any source (empty DB / snapshot restore).
        data.reindex_vips();
        let epoch = data.epoch;
        let applied = data.last_applied.map(|l| l.index).unwrap_or(0);
        let (epoch_tx, _) = watch::channel(epoch);
        Arc::new(SmCore {
            db,
            data: RwLock::new(data),
            pinned_root,
            hooks: std::sync::Mutex::new(HookRegistry::new()),
            applied_index: Arc::new(AtomicU64::new(applied)),
            epoch_tx,
            lag: LagInjector::new(),
        })
    }

    /// Start on an empty database (no snapshot; Raft replay/catch-up fills it
    /// in).
    pub fn empty(db: Arc<Database>, pinned_root: Option<ed25519_dalek::VerifyingKey>) -> Arc<Self> {
        Self::new(db, NetStateData::new(), pinned_root)
    }

    /// Restore from the in-database snapshot (if present), otherwise empty
    /// state.
    pub fn restore_or_empty(
        db: Arc<Database>,
        pinned_root: Option<ed25519_dalek::VerifyingKey>,
    ) -> Arc<Self> {
        match read_snapshot(&db) {
            Some(bundle) => Self::new(db, bundle.data, pinned_root),
            None => Self::empty(db, pinned_root),
        }
    }

    /// Register an apply hook (injected at assembly; kills local sessions /
    /// rejects outstanding tickets).
    pub fn register_hook(&self, h: Arc<dyn crate::hooks::SyncHooks>) {
        self.hooks.lock().expect("sm hooks").add(h);
    }

    /// Shared handle to the hook registry (shared with LeaseTable etc.).
    pub fn shared_hooks(&self) -> HookRegistry {
        self.hooks.lock().expect("sm hooks").clone()
    }

    /// Local (not linearizable) read-view snapshot — cache/display paths
    /// only.
    pub fn with_data<R>(&self, f: impl FnOnce(&NetStateData) -> R) -> R {
        f(&self.data.read().expect("sm data"))
    }

    /// Current local epoch.
    pub fn epoch(&self) -> u64 {
        *self.epoch_tx.borrow()
    }

    /// Subscribe to the epoch watch.
    pub fn epoch_watch(&self) -> watch::Receiver<u64> {
        self.epoch_tx.subscribe()
    }

    /// Highest applied index.
    pub fn applied_index(&self) -> u64 {
        self.applied_index.load(Ordering::SeqCst)
    }

    /// Shared handle to the applied counter (consumed by LagMonitor).
    pub fn applied_counter(&self) -> Arc<AtomicU64> {
        self.applied_index.clone()
    }

    /// The ticket key root (inside Raft; present after Bootstrap). The
    /// cluster-shared OPRF key (b64; available after Bootstrap+SetOprf).
    pub fn oprf_b64(&self) -> Option<String> {
        self.with_data(|d| d.oprf_b64.clone())
    }

    pub fn ticket_root(&self) -> Option<[u8; 32]> {
        self.with_data(|d| d.ticket_root)
    }

    /// A device's registered VIP (for the forwarding plane's step-0 source
    /// binding check / route resolution).
    pub fn vip_of(&self, device: &[u8; 32]) -> Option<[u8; 4]> {
        self.with_data(|d| d.devices.get(device).map(|r| r.vip))
    }

    /// Reverse lookup of a device by VIP (destination-holder resolution; the
    /// per-packet forwarding hot path — `NetStateData`'s VIP index, O(log N);
    /// NetState stores only static registration info — no current location).
    pub fn device_by_vip(&self, vip: &[u8; 4]) -> Option<[u8; 32]> {
        self.with_data(|d| d.device_by_vip(vip))
    }

    /// Apply a batch of log entries (core transitions + hook firing + watch
    /// advancement).
    pub(crate) async fn apply_entries(&self, entries: &[Entry<SyncConfig>]) -> Vec<SyncResponse> {
        self.lag.maybe_delay().await;
        let mut out = Vec::with_capacity(entries.len());
        let mut new_epoch: Option<u64> = None;
        for e in entries {
            let idx = e.log_id.index;
            match &e.payload {
                // openraft contract: apply yields exactly one response per
                // entry (Blank/membership entries get a placeholder
                // response).
                EntryPayload::Blank => out.push(SyncResponse::Ok),
                EntryPayload::Normal(req) => {
                    let outcome = {
                        let mut d = self.data.write().expect("sm data");
                        d.last_applied = Some(e.log_id);
                        let pinned = self.pinned_root.as_ref();
                        d.apply(req, pinned)
                    };
                    if let Some(ev) = outcome.revoked {
                        self.hooks
                            .lock()
                            .expect("sm hooks")
                            .fire_revocation(ev, idx);
                        new_epoch = Some(ev.new_epoch);
                    }
                    out.push(outcome.resp);
                }
                EntryPayload::Membership(m) => {
                    let mut d = self.data.write().expect("sm data");
                    d.last_applied = Some(e.log_id);
                    d.last_membership = StoredMembership::new(Some(e.log_id), m.clone());
                    out.push(SyncResponse::Ok);
                }
            }
            self.applied_index.store(idx, Ordering::SeqCst);
        }
        if let Some(ep) = new_epoch {
            let _ = self.epoch_tx.send_if_modified(|cur| {
                if *cur < ep {
                    *cur = ep;
                    true
                } else {
                    false
                }
            });
        }
        out
    }

    /// Build a snapshot and persist it (retries to ride out sporadic write
    /// conflicts).
    fn build_and_persist_snapshot(&self) -> Snapshot<SyncConfig> {
        let (bundle, meta) = {
            let d = self.data.read().expect("sm data");
            let meta = SnapshotMeta {
                last_log_id: d.last_applied,
                last_membership: d.last_membership.clone(),
                snapshot_id: format!("flock-sync-{:016x}", rng_u64()),
            };
            (
                SnapBundle {
                    meta: meta.clone(),
                    data: d.clone(),
                },
                meta,
            )
        };
        let bytes = postcard::to_allocvec(&bundle).expect("sm snapshot serialize");
        persist_snapshot(&self.db, &bytes);
        Snapshot::<SyncConfig> {
            meta,
            snapshot: Box::new(std::io::Cursor::new(bytes)),
        }
    }
}

fn rng_u64() -> u64 {
    use rand::TryRngCore;
    let mut rng = rand::rng();
    rng.try_next_u64().expect("entropy")
}

fn persist_snapshot(db: &Arc<Database>, bytes: &[u8]) {
    for _ in 0..3 {
        let Ok(txn) = db.begin_write() else { continue };
        {
            let mut t = match txn.open_table(SMKV_TABLE) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if t.insert("snapshot", bytes).is_err() {
                continue;
            }
        }
        if txn.commit().is_ok() {
            return;
        }
    }
    // All three retries failed: not fatal (the logs are there, a restart
    // replays them — openraft startup replay semantics), but it must be
    // observable (a silent failure quietly falsifies the "a snapshot exists"
    // assumption — snapshot_and_purge decides based on it).
    eprintln!(
        "sm: snapshot persist failed after 3 attempts ({} bytes) — logs intact, restart will replay",
        bytes.len()
    );
}

fn read_snapshot(db: &Arc<Database>) -> Option<SnapBundle> {
    let txn = db.begin_read().ok()?;
    let t = txn.open_table(SMKV_TABLE).ok()?;
    let v = t.get("snapshot").ok()??;
    postcard::from_bytes(v.value()).ok()
}

/// openraft state machine handle (held by Raft; the core is Arc-shared with
/// the read path).
#[derive(Clone)]
pub struct RedbStateMachine {
    pub core: Arc<SmCore>,
}

impl RedbStateMachine {
    pub fn new(core: Arc<SmCore>) -> Self {
        RedbStateMachine { core }
    }
}

impl openraft::storage::RaftStateMachine<SyncConfig> for RedbStateMachine {
    type SnapshotBuilder = SmSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let d = self.core.data.read().expect("sm data");
        Ok((d.last_applied, d.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<SyncResponse>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<SyncConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<Entry<SyncConfig>> = entries.into_iter().collect();
        Ok(self.core.apply_entries(&entries).await)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        SmSnapshotBuilder {
            core: self.core.clone(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<std::io::Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(std::io::Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<std::io::Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let bytes = snapshot.into_inner();
        let bundle: SnapBundle = postcard::from_bytes(&bytes).map_err(|e| {
            let io_err = std::io::Error::other(format!("snapshot decode: {e}"));
            Err::<(), std::io::Error>(io_err)
                .sto_res(|| (ErrorSubject::Store, ErrorVerb::Read))
                .expect_err("Err")
        })?;
        // The snapshot data carries its own meta; align with the passed-in
        // meta (openraft contract).
        let mut data = bundle.data;
        data.last_applied = meta.last_log_id;
        data.last_membership = meta.last_membership.clone();
        // The index is derived data (not in the snapshot bytes) — rebuild it
        // when wholesale-replacing the state.
        data.reindex_vips();
        let epoch = data.epoch;
        let applied = meta.last_log_id.map(|l| l.index).unwrap_or(0);
        {
            let mut d = self.core.data.write().expect("sm data");
            *d = data;
        }
        self.core.applied_index.store(applied, Ordering::SeqCst);
        // Aligned with the apply path: monotonic advancement (send would
        // overwrite unconditionally — the anomalous shape of a snapshot epoch
        // below the current watch value must not roll observers back).
        let _ = self.core.epoch_tx.send_if_modified(|cur| {
            if *cur < epoch {
                *cur = epoch;
                true
            } else {
                false
            }
        });
        // Install is persist-on-arrival (the next restart restores straight
        // from the snapshot).
        let re_bundle = SnapBundle {
            meta: meta.clone(),
            data: self.core.data.read().expect("sm data").clone(),
        };
        let bytes = postcard::to_allocvec(&re_bundle).expect("sm snapshot serialize");
        persist_snapshot(&self.core.db, &bytes);
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<SyncConfig>>, StorageError<u64>> {
        Ok(read_snapshot(&self.core.db).map(|b| {
            let bytes = postcard::to_allocvec(&b).expect("sm snapshot serialize");
            Snapshot::<SyncConfig> {
                meta: b.meta,
                snapshot: Box::new(std::io::Cursor::new(bytes)),
            }
        }))
    }
}

/// Snapshot builder (called when Raft triggers compaction).
pub struct SmSnapshotBuilder {
    core: Arc<SmCore>,
}

impl RaftSnapshotBuilder<SyncConfig> for SmSnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<SyncConfig>, StorageError<u64>> {
        Ok(self.core.build_and_persist_snapshot())
    }
}

// ============================================================================
// Unit tests: apply hook firing + epoch watch + snapshot restore
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::HookRecorder;
    use crate::proto::SyncRequest;

    fn core() -> Arc<SmCore> {
        let dir = tempfile::tempdir().expect("tmp");
        let db = Database::create(dir.path().join("sm.redb")).expect("db");
        SmCore::empty(Arc::new(db), None)
    }

    #[tokio::test]
    async fn revocation_fires_hook_and_advances_epoch_watch() {
        let c = core();
        let rec = HookRecorder::new();
        c.register_hook(rec.clone());
        let root = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let entries = vec![
            entry(1, SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32])),
            entry(
                2,
                SyncRequest::RegisterDevice {
                    owner: "u".into(),
                    x25519: [1; 32],
                    ed25519: [1; 32],
                    hostname: String::new(),
                    registered_at_unix: 1_700_000_000,
                },
            ),
            entry(
                3,
                SyncRequest::Revoke {
                    device: sha(&[1; 32]),
                },
            ),
        ];
        let res = c.apply_entries(&entries).await;
        assert_eq!(res.len(), 3);
        assert_eq!(c.epoch(), 1, "epoch watch advanced");
        assert_eq!(c.applied_index(), 3);
        let revs = rec.revocations();
        assert_eq!(revs.len(), 1, "kill-session hook fired exactly once");
        assert_eq!(revs[0].device, sha(&[1; 32]));
        assert_eq!(revs[0].new_epoch, 1);
        assert_eq!(revs[0].log_index, 3);
    }

    #[tokio::test]
    async fn lag_injector_stalls_apply() {
        let c = core();
        c.lag.arm(Duration::from_millis(300));
        let root = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let t0 = std::time::Instant::now();
        let _ = c
            .apply_entries(&[entry(
                1,
                SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32]),
            )])
            .await;
        assert!(
            t0.elapsed() >= Duration::from_millis(300),
            "apply stalls once armed"
        );
        c.lag.disarm();
        let t1 = std::time::Instant::now();
        let _ = c.apply_entries(&[entry(2, SyncRequest::AllocateIp)]).await;
        assert!(
            t1.elapsed() < Duration::from_millis(200),
            "no stall after disarm"
        );
    }

    #[tokio::test]
    async fn snapshot_build_and_restore() {
        let dir = tempfile::tempdir().expect("tmp");
        let db = Arc::new(Database::create(dir.path().join("sm.redb")).expect("db"));
        let c = SmCore::empty(db.clone(), None);
        let root = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let _ = c
            .apply_entries(&[
                entry(1, SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32])),
                entry(
                    2,
                    SyncRequest::RegisterDevice {
                        owner: "u".into(),
                        x25519: [1; 32],
                        ed25519: [1; 32],
                        hostname: String::new(),
                        registered_at_unix: 1_700_000_000,
                    },
                ),
            ])
            .await;
        let snap = c.build_and_persist_snapshot();
        assert_eq!(snap.meta.last_log_id.map(|l| l.index), Some(2));
        // Hot-path index: resolvable right after registration (apply maintains
        // it incrementally).
        let dev: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest([1u8; 32]).into()
        };
        let vip = c.vip_of(&dev).expect("vip");
        assert_eq!(
            c.device_by_vip(&vip),
            Some(dev),
            "index resolvable right after apply"
        );
        // A fresh core restores from the in-database snapshot.
        let c2 = SmCore::restore_or_empty(db, None);
        assert_eq!(c2.epoch(), c.epoch());
        assert_eq!(c2.applied_index(), 2);
        assert!(c2.with_data(|d| d.devices.len() == 1));
        assert_eq!(
            c2.ticket_root(),
            Some([9; 32]),
            "ticket key root restored with the snapshot"
        );
        // The restore path rebuilds the index (the index is not serialized —
        // derived data).
        assert_eq!(
            c2.device_by_vip(&vip),
            Some(dev),
            "index rebuilt after snapshot restore"
        );
    }

    fn entry(idx: u64, req: SyncRequest) -> Entry<SyncConfig> {
        Entry {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), idx),
            payload: EntryPayload::Normal(req),
        }
    }

    fn sha(b: &[u8; 32]) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(b).into()
    }
}
