//! M8 webui 流量时间序列（docs/design.md §7-M8.5——内存环形缓冲，不进 Raft/gossip）。
//!
//! per-VIP `VecDeque<(unix_minute, tx_bps, rx_bps)>`，容量 `series_points`（缺省
//! 120）× `series_interval_secs`（缺省 60）⇒ 2 小时窗。采样源（同任务单趟）：
//! - 单服 = `TrafficMeter::stats(vip)`（服务器自身走 [`SERVER_TRAFFIC_KEY`]）；
//! - 多主 = `LeaseTable::peer_stats(device)`（服务器自身走 `server_self_device_id`；
//!   VIP↔Device 映射来自注册表本地快照——与名册同视图）。
//!
//! 语义（设计定死）：仅 Active 行参与采样（行消失（吊销/过期）后**序列保留至自然
//! 环出**）；**重启清零**（纯内存）；无样本但在册的 VIP 返回空 points（非 404——
//! 404 判定「既无序列也不在注册表」，api.rs 承担）。

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::backend::NetBackend;
use crate::netstate::DeviceStatus;
use crate::server::ServerCore;

/// 单点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplePoint {
    /// 桶时刻（unix 秒；对齐 interval 的整桶）。
    pub t: u64,
    pub tx_bps: u64,
    pub rx_bps: u64,
}

/// 环形缓冲集（per-VIP）。
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

    /// 序列快照（旧→新；§M8.4 points 数组序）。
    pub async fn snapshot(&self, vip: &[u8; 4]) -> Vec<SamplePoint> {
        self.inner
            .lock()
            .await
            .get(vip)
            .map(|q| q.iter().copied().collect())
            .unwrap_or_default()
    }

    /// 是否已有任何样本（404 判定的第一支）。
    pub async fn knows(&self, vip: &[u8; 4]) -> bool {
        self.inner
            .lock()
            .await
            .get(vip)
            .is_some_and(|q| !q.is_empty())
    }

    /// 采样单趟（注入时钟可测；同一桶内重复采样 = 覆盖末点——幂等）。
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
                // 服务器自身（单服形态唯一 Server 条目）。
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
                q.pop_back(); // 同桶覆盖（幂等）
            }
            q.push_back(SamplePoint {
                t: bucket,
                tx_bps: tx,
                rx_bps: rx,
            });
            while q.len() > self.points {
                q.pop_front(); // 环出最旧
            }
        }
    }

    /// 采样循环（interval 周期；装配于 mod.rs）。
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
// 单元测试（§M8.9：注入时钟定点采样 → 环出上限 120 → 新实例为空（重启语义）→
// 行消失后序列保留）
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
            _ => panic!("single"),
        }
    }

    /// 定点采样（注入时钟）+ 环出上限 + 桶对齐 + 同桶覆盖幂等。
    #[tokio::test]
    async fn sampling_ring_and_bucket_alignment() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = ServerCore::open_or_init(m8_cfg(dir.path().to_path_buf())).unwrap();
        let store = store_of(&core);
        let row = store
            .register_device("alice", [1; 32], [1; 32], "box")
            .unwrap();
        // 喂流量（EWMA 两折出非零）。
        core.traffic.note_tx(&row.vip, 8192);
        core.traffic.note_rx(&row.vip, 4096);

        let series = Series::new(4, 60);
        // EWMA 折叠出非零（1s 窗 × 3 折——与 control.rs 名册测试同手法）。
        let mut ms = 1_000_000u64;
        for _ in 0..3 {
            core.traffic.note_tx(&row.vip, 8192);
            core.traffic.note_rx(&row.vip, 4096);
            ms += 1000;
            core.traffic.tick(ms);
        }
        // t=130：桶 = 120（对齐 60s）。
        series.sample_once(&core, 130).await;
        let pts = series.snapshot(&row.vip).await;
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].t, 120, "桶对齐 interval");
        assert!(pts[0].tx_bps > 0 && pts[0].rx_bps > 0);

        // 同桶再采样 ⇒ 覆盖（幂等，不双记）。
        series.sample_once(&core, 175).await;
        assert_eq!(series.snapshot(&row.vip).await.len(), 1, "同桶覆盖");

        // 4 个桶后环出（容量 4）。
        for t in [180, 240, 300, 360] {
            series.sample_once(&core, t).await;
        }
        let pts = series.snapshot(&row.vip).await;
        assert_eq!(pts.len(), 4, "环出上限");
        assert_eq!(
            pts.first().unwrap().t,
            180,
            "最旧（120）被环出——留下 180..=360"
        );
        assert!(pts.windows(2).all(|w| w[0].t < w[1].t), "旧→新");

        // 服务器自身 VIP 也在采样面（SERVER_TRAFFIC_KEY 源；EWMA 折叠同手法）。
        for _ in 0..3 {
            core.traffic
                .note_tx(crate::dataplane::SERVER_TRAFFIC_KEY, 4096);
            ms += 1000;
            core.traffic.tick(ms);
        }
        series.sample_once(&core, 370).await;
        let self_pts = series.snapshot(&core.cfg.vip.octets()).await;
        assert_eq!(self_pts.len(), 1);
        assert!(self_pts[0].tx_bps > 0, "服务器自身走 SERVER_TRAFFIC_KEY");
    }

    /// 行消失（吊销）后序列保留至自然环出——非 Active 行不再进采样面。
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

        // 吊销（行保留、VIP 不回收——但退出采样面）。
        let id = flock_protocol::session::DeviceId(sha2::Sha256::digest([1u8; 32]).into());
        store.revoke(&id).unwrap();
        series.sample_once(&core, 120).await;
        series.sample_once(&core, 180).await;
        let pts = series.snapshot(&row.vip).await;
        assert_eq!(
            pts.len(),
            1,
            "行消失后不再追加（保留旧点，非清空）: {pts:?}"
        );
        assert_eq!(pts[0].t, 60, "旧点保留至自然环出");
    }

    /// 新实例为空（重启清零——纯内存；注册表仍在、流量计也在 ⇒ 首拍重建）。
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

        // 「重启」：全新 Series（曲线从零开始）。
        let s2 = Series::new(120, 60);
        assert!(s2.snapshot(&row.vip).await.is_empty(), "重启清零");
        assert!(!s2.knows(&row.vip).await);
        // 首拍后重建（注册表 + 流量计仍在的部署形态）。
        s2.sample_once(&core, 120).await;
        assert_eq!(s2.snapshot(&row.vip).await.len(), 1);
    }
}
