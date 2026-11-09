//! M8 webui traffic time series (docs/design.md §7-M8.5 —— in-memory ring
//! buffer, never enters Raft/gossip).
//!
//! per-VIP `VecDeque<(unix_minute, tx_bps, rx_bps)>`, capacity
//! `series_points` (default 120) × `series_interval_secs` (default 60) ⇒ a
//! 2-hour window. Sampling sources (one pass of the same task):
//! - single server = `TrafficMeter::stats(vip)` (the server itself goes
//!   through [`SERVER_TRAFFIC_KEY`]);
//! - multi-primary = `LeaseTable::peer_stats(device)` (the server itself goes
//!   through `server_self_device_id`; the VIP↔Device mapping comes from the
//!   local registry snapshot —— same view as the roster).
//!
//! Semantics (fixed by design): only Active rows are sampled (after a row
//! disappears (revoked/expired) the **series is retained until it naturally
//! rings out**); **restart zeroes it** (pure memory); a VIP with no samples
//! but on record returns empty points (not 404 —— the 404 decision is
//! "neither a series nor in the registry", carried by api.rs).

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::backend::NetBackend;
use crate::netstate::DeviceStatus;
use crate::server::ServerCore;

/// One sample point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplePoint {
    /// Bucket time (unix seconds; aligned to whole buckets of the interval).
    pub t: u64,
    pub tx_bps: u64,
    pub rx_bps: u64,
}

/// Ring-buffer set (per VIP).
pub struct Series {
    points: usize,
    interval_secs: u64,
    inner: Mutex<BTreeMap<[u8; 4], VecDeque<SamplePoint>>>,
}

impl Series {
    pub fn new(points: usize, interval_secs: u64) -> Self {
        Series {
            points: points.max(1),
            interval_secs: interval_secs.max(1),
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn interval_secs(&self) -> u64 {
        self.interval_secs
    }

    /// Series snapshot (old→new; the §M8.4 points array order).
    pub async fn snapshot(&self, vip: &[u8; 4]) -> Vec<SamplePoint> {
        self.inner
            .lock()
            .await
            .get(vip)
            .map(|q| q.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Whether any sample exists yet (the first arm of the 404 decision).
    pub async fn knows(&self, vip: &[u8; 4]) -> bool {
        self.inner
            .lock()
            .await
            .get(vip)
            .is_some_and(|q| !q.is_empty())
    }

    /// One sampling pass (injectable clock for tests; re-sampling within the
    /// same bucket = overwrite the last point —— idempotent).
    pub async fn sample_once(&self, core: &ServerCore, now_unix: u64) {
        let bucket = now_unix - (now_unix % self.interval_secs);
        let mut updates: Vec<([u8; 4], u64, u64)> = Vec::new();
        match &core.net {
            NetBackend::Single(store) => {
                for (_id, row) in store.devices_all() {
                    if row.status != DeviceStatus::Active {
                        continue;
                    }
                    if let Some((tx, rx, _)) = core.traffic.stats(&row.vip) {
                        updates.push((row.vip, tx, rx));
                    }
                }
                // The server itself (the single Server entry in single-server
                // form).
                if let Some((tx, rx, _)) = core.traffic.stats(crate::dataplane::SERVER_TRAFFIC_KEY)
                {
                    updates.push((core.cfg.vip.octets(), tx, rx));
                }
            }
            #[cfg(feature = "multi-primary")]
            NetBackend::Sync(s) => {
                let node = &s.node;
                let leases = node.lease();
                for (dev, row) in node.devices_snapshot() {
                    if row.status != DeviceStatus::Active {
                        continue;
                    }
                    if let Some(st) = leases.peer_stats(&dev) {
                        updates.push((row.vip, st.tx_ewma, st.rx_ewma));
                    }
                }
                for (node_id, entry) in node.server_keys_snapshot() {
                    if let Some(st) =
                        leases.peer_stats(&flock_sync::lease::server_self_device_id(node_id))
                    {
                        updates.push((entry.vip, st.tx_ewma, st.rx_ewma));
                    }
                }
            }
        }
        if updates.is_empty() {
            return;
        }
        let mut g = self.inner.lock().await;
        for (vip, tx, rx) in updates {
            let q = g.entry(vip).or_default();
            if q.back().is_some_and(|p| p.t == bucket) {
                q.pop_back(); // same-bucket overwrite (idempotent)
            }
            q.push_back(SamplePoint {
                t: bucket,
                tx_bps: tx,
                rx_bps: rx,
            });
            while q.len() > self.points {
                q.pop_front(); // ring out the oldest
            }
        }
    }

    /// Sampling loop (interval period; assembled in mod.rs).
    pub async fn sampler_loop(self: Arc<Self>, core: Arc<ServerCore>) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(self.interval_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let now = flock_protocol::trust::now_unix();
            self.sample_once(&core, now).await;
        }
    }
}

// ============================================================================
// Unit tests (§M8.9: fixed-point sampling with injected clock → ring-out cap
// 120 → a fresh instance is empty (restart semantics) → the series is retained
// after the row disappears)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use sha2::Digest as _;

    fn m8_cfg(state_dir: std::path::PathBuf) -> ServerConfig {
        ServerConfig {
            state_dir,
            bind: "127.0.0.1:9443".parse().unwrap(),
            mode: "direct".into(),
            advertise_endpoint: "127.0.0.1:9443".into(),
            extra_endpoints: vec![],
            dir_version: 1,
            ticket_ttl_secs: 60,
            peer_retention_days: 30,
            admin_bind: "127.0.0.1:9444".parse().unwrap(),
            max_sessions: 1024,
            tun_name: "tun0".into(),
            vip: "100.64.0.1".parse().unwrap(),
            frp: None,
            sync: None,
            webui: Default::default(),
        }
    }

    fn store_of(core: &ServerCore) -> Arc<crate::netstate::StateStore> {
        match &core.net {
            NetBackend::Single(s) => s.clone(),
            #[cfg(feature = "multi-primary")]
            _ => panic!("single"),
        }
    }

    /// Fixed-point sampling (injected clock) + ring-out cap + bucket
    /// alignment + same-bucket overwrite idempotence.
    #[tokio::test]
    async fn sampling_ring_and_bucket_alignment() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = ServerCore::open_or_init(m8_cfg(dir.path().to_path_buf())).unwrap();
        let store = store_of(&core);
        let row = store
            .register_device("alice", [1; 32], [1; 32], "box")
            .unwrap();
        // Feed traffic (two EWMA folds produce non-zero).
        core.traffic.note_tx(&row.vip, 8192);
        core.traffic.note_rx(&row.vip, 4096);

        let series = Series::new(4, 60);
        // Fold the EWMA to non-zero (1s window × 3 folds —— same technique as
        // the roster tests in control.rs).
        let mut ms = 1_000_000u64;
        for _ in 0..3 {
            core.traffic.note_tx(&row.vip, 8192);
            core.traffic.note_rx(&row.vip, 4096);
            ms += 1000;
            core.traffic.tick(ms);
        }
        // t=130: bucket = 120 (aligned to 60s).
        series.sample_once(&core, 130).await;
        let pts = series.snapshot(&row.vip).await;
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].t, 120, "bucket aligned to interval");
        assert!(pts[0].tx_bps > 0 && pts[0].rx_bps > 0);

        // Re-sample in the same bucket ⇒ overwrite (idempotent, not double
        // recorded).
        series.sample_once(&core, 175).await;
        assert_eq!(
            series.snapshot(&row.vip).await.len(),
            1,
            "same-bucket overwrite"
        );

        // After 4 buckets it rings out (capacity 4).
        for t in [180, 240, 300, 360] {
            series.sample_once(&core, t).await;
        }
        let pts = series.snapshot(&row.vip).await;
        assert_eq!(pts.len(), 4, "ring-out cap");
        assert_eq!(
            pts.first().unwrap().t,
            180,
            "the oldest (120) rang out —— 180..=360 remain"
        );
        assert!(pts.windows(2).all(|w| w[0].t < w[1].t), "old→new");

        // The server's own VIP is also on the sampling surface
        // (SERVER_TRAFFIC_KEY source; EWMA folded the same way).
        for _ in 0..3 {
            core.traffic
                .note_tx(crate::dataplane::SERVER_TRAFFIC_KEY, 4096);
            ms += 1000;
            core.traffic.tick(ms);
        }
        series.sample_once(&core, 370).await;
        let self_pts = series.snapshot(&core.cfg.vip.octets()).await;
        assert_eq!(self_pts.len(), 1);
        assert!(
            self_pts[0].tx_bps > 0,
            "the server itself goes through SERVER_TRAFFIC_KEY"
        );
    }

    /// After the row disappears (revoked) the series is retained until it
    /// naturally rings out —— non-Active rows leave the sampling surface.
    #[tokio::test]
    async fn series_retained_after_row_leaves_active() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = ServerCore::open_or_init(m8_cfg(dir.path().to_path_buf())).unwrap();
        let store = store_of(&core);
        let row = store
            .register_device("alice", [1; 32], [1; 32], "box")
            .unwrap();
        core.traffic.note_tx(&row.vip, 1024);
        let series = Series::new(8, 60);
        series.sample_once(&core, 60).await;
        assert_eq!(series.snapshot(&row.vip).await.len(), 1);

        // Revoke (the row is retained, the VIP is not recycled —— but it
        // leaves the sampling surface).
        let id = flock_protocol::session::DeviceId(sha2::Sha256::digest([1u8; 32]).into());
        store.revoke(&id).unwrap();
        series.sample_once(&core, 120).await;
        series.sample_once(&core, 180).await;
        let pts = series.snapshot(&row.vip).await;
        assert_eq!(
            pts.len(),
            1,
            "no appends after the row disappears (old point retained, not cleared): {pts:?}"
        );
        assert_eq!(
            pts[0].t, 60,
            "the old point is retained until natural ring-out"
        );
    }

    /// A fresh instance is empty (restart zeroes it —— pure memory; the
    /// registry is still there, so is the traffic meter ⇒ rebuilt on the first
    /// sample).
    #[tokio::test]
    async fn fresh_instance_empty_restart_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = ServerCore::open_or_init(m8_cfg(dir.path().to_path_buf())).unwrap();
        let store = store_of(&core);
        let row = store
            .register_device("alice", [1; 32], [1; 32], "box")
            .unwrap();
        core.traffic.note_tx(&row.vip, 512);
        let s1 = Series::new(120, 60);
        s1.sample_once(&core, 60).await;
        assert!(!s1.snapshot(&row.vip).await.is_empty());

        // "Restart": a brand-new Series (the chart starts from zero).
        let s2 = Series::new(120, 60);
        assert!(s2.snapshot(&row.vip).await.is_empty(), "restart zeroes");
        assert!(!s2.knows(&row.vip).await);
        // Rebuilt after the first sample (the deployment shape where the
        // registry + traffic meter survive).
        s2.sample_once(&core, 120).await;
        assert_eq!(s2.snapshot(&row.vip).await.len(), 1);
    }
}
