//! Multi-primary implementation of `session::DeviceDirectory` (§4 reads and
//! caching / §3.11 assembly injection): **device record cache +
//! revocation_epoch two-tier read + apply-lag circuit breaker**.
//!
//! - epoch unchanged and cache hit ⇒ answer locally (after a relay link
//!   failure, the N-client reconnect storm hits the local cache entirely when
//!   there are no revocations; the leader only absorbs genuine global-order
//!   changes — R18);
//! - epoch advanced (advances automatically as Raft log entries apply, no
//!   extra broadcast needed) ⇒ invalidate the cache;
//! - **breaker**: apply-lag > threshold (2s, the A6 timing budget) ⇒ disable
//!   the local cache path, degrade to linearizable reads (follower reads via
//!   leader; §4 stale-read boundary / R24).
//!
//! Stale-read boundary (honest disclosure): a revocation already committed by
//! the leader cannot block new handshakes before the follower applies it
//! locally; the window = how long the follower's log lags. The breaker blocks
//! "observed lag > 2s"; the 60s ticket TTL backstops cross-server replay.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use flock_protocol::session::{DeviceDirectory, DeviceId, LookupVerdict};
use futures::future::BoxFuture;
use tokio::sync::watch;

use crate::proto::{ReadQuery, ReadView, SyncError, VerdictW};
use crate::wire::LagMonitor;

/// Linearizable-read capability ([`crate::node::SyncNode`] implements it;
/// assembly/tests may also inject other sources).
pub trait LinearizableReader: Send + Sync + 'static {
    fn read(&self, q: ReadQuery) -> BoxFuture<'static, Result<ReadView, SyncError>>;
}

/// Directory read statistics (breaker/cache behavior made observable — used by
/// tests asserting "cache refused").
#[derive(Debug, Default, Clone, Copy)]
pub struct DirStats {
    pub cache_hits: u64,
    pub linearizable_reads: u64,
    pub breaker_degraded: u64,
}

/// Two-tier read directory (used boxed in an `Arc`; [`DirHandle`] provides the
/// DeviceDirectory seam).
pub struct SyncDirectory {
    reader: Arc<dyn LinearizableReader>,
    lag: Arc<LagMonitor>,
    epoch_rx: watch::Receiver<u64>,
    cache: Mutex<HashMap<[u8; 32], VerdictW>>,
    stats_cache_hits: AtomicU64,
    stats_linear: AtomicU64,
    stats_degraded: AtomicU64,
}

impl SyncDirectory {
    pub fn new(
        reader: Arc<dyn LinearizableReader>,
        lag: Arc<LagMonitor>,
        epoch_watch: watch::Receiver<u64>,
    ) -> Arc<Self> {
        Arc::new(SyncDirectory {
            reader,
            lag,
            epoch_rx: epoch_watch,
            cache: Mutex::new(HashMap::new()),
            stats_cache_hits: AtomicU64::new(0),
            stats_linear: AtomicU64::new(0),
            stats_degraded: AtomicU64::new(0),
        })
    }

    /// Read-statistics snapshot.
    pub fn stats(&self) -> DirStats {
        DirStats {
            cache_hits: self.stats_cache_hits.load(Ordering::Relaxed),
            linearizable_reads: self.stats_linear.load(Ordering::Relaxed),
            breaker_degraded: self.stats_degraded.load(Ordering::Relaxed),
        }
    }

    /// Directory lookup main path (async: a linearizable read is a network
    /// round trip — §1.3.3c seam contract).
    pub async fn lookup_async(&self, id: DeviceId) -> LookupVerdict {
        // Epoch change ⇒ invalidate the entire cache (advances automatically
        // with apply, no extra broadcast needed).
        {
            let mut rx = self.epoch_rx.clone();
            if rx.has_changed().unwrap_or(false) {
                rx.borrow_and_update();
                self.cache.lock().expect("dir cache").clear();
            }
        }
        let breaker = self.lag.breaker_open();
        if breaker {
            // Breaker: disable the local cache path, degrade to linearizable
            // reads (§4).
            self.stats_degraded.fetch_add(1, Ordering::Relaxed);
        } else if let Some(v) = self.cache.lock().expect("dir cache").get(&id.0).cloned() {
            self.stats_cache_hits.fetch_add(1, Ordering::Relaxed);
            return v.to_verdict();
        }
        self.stats_linear.fetch_add(1, Ordering::Relaxed);
        match self.reader.read(ReadQuery::Lookup(id.0)).await {
            Ok(ReadView::Verdict(v)) => {
                if !breaker {
                    // Do not write the cache while the breaker is open: avoids
                    // stale hits from "read, then immediately fall behind
                    // again".
                    self.cache
                        .lock()
                        .expect("dir cache")
                        .insert(id.0, v.clone());
                }
                v.to_verdict()
            }
            _ => {
                // Linearizable read failed (leader unreachable etc.) ⇒
                // fail-closed: NotFound shape (handshake refused). Never fall
                // back to the stale cache (§4 breaker semantics).
                LookupVerdict::NotFound
            }
        }
    }
}

/// DeviceDirectory seam handle (injection shape for session::respond).
#[derive(Clone)]
pub struct DirHandle(pub Arc<SyncDirectory>);

impl DeviceDirectory for DirHandle {
    fn lookup(&self, id: &DeviceId) -> BoxFuture<'static, LookupVerdict> {
        let dir = self.0.clone();
        let id = *id;
        Box::pin(async move { dir.lookup_async(id).await })
    }
}

// ============================================================================
// Unit tests: cache hit / epoch invalidation / breaker degradation /
// read-failure fail-closed
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct CountingReader {
        reads: AtomicU64,
        fail: AtomicBool,
    }

    impl LinearizableReader for CountingReader {
        fn read(&self, q: ReadQuery) -> BoxFuture<'static, Result<ReadView, SyncError>> {
            let r = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            let fail = self.fail.load(Ordering::SeqCst);
            Box::pin(async move {
                let _ = r;
                if fail {
                    return Err(SyncError::NoLeader);
                }
                let v = match q {
                    ReadQuery::Lookup(id) => ReadView::Verdict(VerdictW::Active {
                        x25519: id,
                        ed25519: [1; 32],
                    }),
                    _ => unreachable!(),
                };
                Ok(v)
            })
        }
    }

    fn monitor() -> Arc<LagMonitor> {
        // Silence limit = max(50ms, 200ms) = 200ms: this test group focuses on
        // the breaker-degradation path; querying immediately after construction
        // (silence ~0) keeps the silence dimension out of the picture.
        LagMonitor::new(
            Duration::from_millis(50),
            Duration::from_millis(200),
            Arc::new(AtomicU64::new(0)),
        )
    }

    #[tokio::test]
    async fn cache_hit_until_epoch_advances() {
        let reader = Arc::new(CountingReader {
            reads: AtomicU64::new(0),
            fail: AtomicBool::new(false),
        });
        let (tx, rx) = watch::channel(0u64);
        let dir = SyncDirectory::new(reader.clone(), monitor(), rx);
        let id = DeviceId([2; 32]);
        assert!(matches!(
            dir.lookup_async(id).await,
            LookupVerdict::Active(_)
        ));
        assert!(matches!(
            dir.lookup_async(id).await,
            LookupVerdict::Active(_)
        ));
        assert_eq!(
            reader.reads.load(Ordering::SeqCst),
            1,
            "second lookup hits the local cache"
        );
        // Epoch advanced ⇒ cache invalidated ⇒ linearizable read again.
        tx.send(1).expect("epoch advance");
        assert!(matches!(
            dir.lookup_async(id).await,
            LookupVerdict::Active(_)
        ));
        assert_eq!(
            reader.reads.load(Ordering::SeqCst),
            2,
            "cache invalidated after epoch advanced"
        );
        let stats = dir.stats();
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.linearizable_reads, 2);
    }

    #[tokio::test]
    async fn breaker_open_degrades_to_linearizable() {
        let reader = Arc::new(CountingReader {
            reads: AtomicU64::new(0),
            fail: AtomicBool::new(false),
        });
        let (_tx, rx) = watch::channel(0u64);
        let applied = Arc::new(AtomicU64::new(0));
        // Silence limit = max(30ms, 500ms) = 500ms > test window (60ms): the
        // breaker is triggered only by apply-lag.
        let lag = LagMonitor::new(
            Duration::from_millis(30),
            Duration::from_millis(500),
            applied.clone(),
        );
        let dir = SyncDirectory::new(reader.clone(), lag.clone(), rx);
        let id = DeviceId([3; 32]);
        assert!(matches!(
            dir.lookup_async(id).await,
            LookupVerdict::Active(_)
        ));
        assert_eq!(
            dir.stats().cache_hits,
            0,
            "first lookup must take the linearizable path"
        );
        // Lag persists past the threshold ⇒ breaker opens.
        lag.observe_leader_commit(5);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(lag.breaker_open());
        assert!(matches!(
            dir.lookup_async(id).await,
            LookupVerdict::Active(_)
        ));
        let stats = dir.stats();
        assert_eq!(stats.breaker_degraded, 1, "breaker path counted");
        assert_eq!(
            stats.cache_hits, 0,
            "no cache hits while the breaker is open"
        );
        // No cache writes while the breaker is open: after catching up and the
        // breaker closing, the read count contains no additional linearizable
        // reads (the cache still holds the entry written before the breaker —
        // with the epoch unchanged there is no reason to invalidate it), so the
        // linearizable-read count stays at 2.
        applied.store(5, Ordering::SeqCst);
        lag.observe_leader_commit(5);
        assert!(!lag.breaker_open());
        assert!(matches!(
            dir.lookup_async(id).await,
            LookupVerdict::Active(_)
        ));
        assert_eq!(
            reader.reads.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "no cache write while the breaker was open (no new linearizable reads)"
        );
    }

    #[tokio::test]
    async fn linearizable_failure_fails_closed() {
        let reader = Arc::new(CountingReader {
            reads: AtomicU64::new(0),
            fail: AtomicBool::new(true),
        });
        let (_tx, rx) = watch::channel(0u64);
        let dir = SyncDirectory::new(reader, monitor(), rx);
        let id = DeviceId([4; 32]);
        assert!(
            matches!(dir.lookup_async(id).await, LookupVerdict::NotFound),
            "fail-closed (handshake refused)"
        );
    }

    #[tokio::test]
    async fn dir_handle_boxes_future() {
        let reader = Arc::new(CountingReader {
            reads: AtomicU64::new(0),
            fail: AtomicBool::new(false),
        });
        let (_tx, rx) = watch::channel(0u64);
        let dir = SyncDirectory::new(reader, monitor(), rx);
        let handle = DirHandle(dir);
        let id = DeviceId([5; 32]);
        let v = handle.lookup(&id).await;
        assert!(matches!(v, LookupVerdict::Active(_)));
    }
}
