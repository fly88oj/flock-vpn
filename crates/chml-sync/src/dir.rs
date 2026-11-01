//! `session::DeviceDirectory` 的多主实现（§4 读与缓存 / §3.11 装配注入）：
//! **设备记录缓存 + revocation_epoch 两级读 + apply-lag 熔断**。
//!
//! - epoch 未变且缓存命中 ⇒ 本地答（中转断链后的 N 客户端重连风暴在无吊销时全部命中
//!   本地缓存，leader 只承接真正的全局序变化——R18）；
//! - epoch 前进（随 Raft 日志 apply 自动推进，无需额外广播）⇒ 失效缓存；
//! - **熔断**：apply-lag > 阈值（2s，A6 时序预算）⇒ 停用本地缓存路径、降级线性一致读
//!   （follower 经 leader 读；§4 陈旧读边界 / R24）。
//!
//! 陈旧读边界（诚实披露）：leader 已 commit 的吊销在 follower 本地 apply 之前挡不住
//! 新握手，窗口 = follower 日志落后时长；熔断把「观察到的落后 >2s」挡住，票据
//! TTL 60s 兜底跨服重放。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chml_protocol::session::{DeviceDirectory, DeviceId, LookupVerdict};
use futures::future::BoxFuture;
use tokio::sync::watch;

use crate::proto::{ReadQuery, ReadView, SyncError, VerdictW};
use crate::wire::LagMonitor;

/// 线性一致读能力（[`crate::node::SyncNode`] 实现；装配/测试也可注入别的源）。
pub trait LinearizableReader: Send + Sync + 'static {
    fn read(&self, q: ReadQuery) -> BoxFuture<'static, Result<ReadView, SyncError>>;
}

/// 目录读统计（熔断/缓存行为可观测——测试断言「拒用缓存」用）。
#[derive(Debug, Default, Clone, Copy)]
pub struct DirStats {
    pub cache_hits: u64,
    pub linearizable_reads: u64,
    pub breaker_degraded: u64,
}

/// 两级读目录（`Arc` 装箱后使用；[`DirHandle`] 提供 DeviceDirectory 接缝）。
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

    /// 读统计快照。
    pub fn stats(&self) -> DirStats {
        DirStats {
            cache_hits: self.stats_cache_hits.load(Ordering::Relaxed),
            linearizable_reads: self.stats_linear.load(Ordering::Relaxed),
            breaker_degraded: self.stats_degraded.load(Ordering::Relaxed),
        }
    }

    /// 目录查询主路径（async：线性一致读是网络往返——§1.3.3c 接缝契约）。
    pub async fn lookup_async(&self, id: DeviceId) -> LookupVerdict {
        // epoch 变化 ⇒ 缓存全量失效（随 apply 自动推进，无需额外广播）。
        {
            let mut rx = self.epoch_rx.clone();
            if rx.has_changed().unwrap_or(false) {
                rx.borrow_and_update();
                self.cache.lock().expect("dir cache").clear();
            }
        }
        let breaker = self.lag.breaker_open();
        if breaker {
            // 熔断：停用本地缓存路径、降级线性一致读（§4）。
            self.stats_degraded.fetch_add(1, Ordering::Relaxed);
        } else if let Some(v) = self.cache.lock().expect("dir cache").get(&id.0).cloned() {
            self.stats_cache_hits.fetch_add(1, Ordering::Relaxed);
            return v.to_verdict();
        }
        self.stats_linear.fetch_add(1, Ordering::Relaxed);
        match self.reader.read(ReadQuery::Lookup(id.0)).await {
            Ok(ReadView::Verdict(v)) => {
                if !breaker {
                    // 熔断期不写缓存：避免「读后立刻又落后」的陈旧命中。
                    self.cache
                        .lock()
                        .expect("dir cache")
                        .insert(id.0, v.clone());
                }
                v.to_verdict()
            }
            _ => {
                // 线性一致读失败（leader 不可达等）⇒ fail-closed：NotFound 外形（拒握手）。
                // 绝不回退用陈旧缓存（§4 熔断语义）。
                LookupVerdict::NotFound
            }
        }
    }

    /// 强制失效缓存（管理面/装配层用）。
    pub fn invalidate(&self) {
        self.cache.lock().expect("dir cache").clear();
    }
}

/// DeviceDirectory 接缝句柄（session::respond 注入形态）。
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
// 单元测试：缓存命中 / epoch 失效 / 熔断降级 / 读失败 fail-closed
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
        LagMonitor::new(Duration::from_millis(50), Arc::new(AtomicU64::new(0)))
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
        assert_eq!(reader.reads.load(Ordering::SeqCst), 1, "第二次命中本地缓存");
        // epoch 前进 ⇒ 缓存失效 ⇒ 再线性一致读。
        tx.send(1).expect("epoch advance");
        assert!(matches!(
            dir.lookup_async(id).await,
            LookupVerdict::Active(_)
        ));
        assert_eq!(
            reader.reads.load(Ordering::SeqCst),
            2,
            "epoch 前进后失效缓存"
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
        let lag = LagMonitor::new(Duration::from_millis(30), applied.clone());
        let dir = SyncDirectory::new(reader.clone(), lag.clone(), rx);
        let id = DeviceId([3; 32]);
        assert!(matches!(
            dir.lookup_async(id).await,
            LookupVerdict::Active(_)
        ));
        assert_eq!(dir.stats().cache_hits, 0, "首查必走线性一致读");
        // 落后持续超阈值 ⇒ 熔断。
        lag.observe_leader_commit(5);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(lag.breaker_open());
        assert!(matches!(
            dir.lookup_async(id).await,
            LookupVerdict::Active(_)
        ));
        let stats = dir.stats();
        assert_eq!(stats.breaker_degraded, 1, "熔断路径计数");
        assert_eq!(stats.cache_hits, 0, "熔断期不命中缓存");
        // 熔断期不做缓存写入：追平关闭熔断后，读计数不含新增线性一致读（缓存仍是
        // 熔断前写入的条目——epoch 未变即无失效理由），线性一致读计数停在 2。
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
            "熔断期未写缓存（无新增线性一致读）"
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
            "fail-closed（拒握手）"
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
