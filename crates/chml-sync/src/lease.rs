//! gossip 租约表（§3.10 `LeaseTable::{publish, observe}`；vpn-mesh §5.2）。
//!
//! **设备当前位置的唯一真相源 = 租约域**：每台服务器权威发布「连在我这的设备」，
//! 租约 TTL 30s；事件推送 ≤1s（publish 即时广播）+ 5s 反熵（全表摘要，装配的反熵循环
//! 调用 [`LeaseTable::anti_entropy_msg`]）。
//!
//! **冲突 = 新者胜 + 旧端踢会话**：term 单调（unix 毫秒 + 持有者 tie-break）；收到比本地
//! 更新的他机租约且本地持有时，触发 [`crate::hooks::SyncHooks::on_lease_evicted`]
//! （旧服务器踢出该设备会话——ZeroTer 撤销快速传播思路，vpn-mesh §5.2）。
//!
//! `location_query`（一次性跨服位置询问，fan-out ≤3）属跨服转发面（§2.2-4），与
//! ForwardEnvelope 同批落地；本模块先提供本地 `observe`（含 TTL 判定）。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::hooks::HookRegistry;
use crate::proto::NodeId;

/// 租约默认 TTL（§3.10：30s）。
pub const LEASE_TTL: Duration = Duration::from_secs(30);
/// 反熵周期（§3.10：5s）。
pub const ANTI_ENTROPY: Duration = Duration::from_secs(5);

/// gossip 线消息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipMsg {
    /// 单条租约事件推送（publish 即时广播，≤1s 语义）。
    Publish { device: [u8; 32], holder: NodeId, term_ms: u64 },
    /// 全表摘要（反熵；TTL 由收端以本机时钟重置）。
    Anti { entries: Vec<(Vec<u8>, NodeId, u64)> },
}

/// 单条租约。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub holder: NodeId,
    pub term_ms: u64,
    pub expires_at: Instant,
}

/// 本地租约表。
pub struct LeaseTable {
    me: NodeId,
    ttl: Duration,
    hooks: HookRegistry,
    st: Mutex<BTreeMap<[u8; 32], Lease>>,
}

impl LeaseTable {
    /// `hooks` 与状态机共用同一注册表（on_lease_evicted 与 on_revocation_applied 同源）。
    pub fn new(me: NodeId, ttl: Duration, hooks: HookRegistry) -> Arc<Self> {
        Arc::new(LeaseTable { me, ttl, hooks, st: Mutex::new(BTreeMap::new()) })
    }

    /// 本机节点号。
    pub fn me(&self) -> NodeId {
        self.me
    }

    /// 发布本机租约（新者胜）。返回被本机取代的旧持有者（若有——冲突场景的对端）。
    /// 远端传播由调用方（node 装配）广播 [`GossipMsg::Publish`]。
    pub fn publish(&self, device: &[u8; 32]) -> Option<NodeId> {
        let term = now_ms();
        let mut st = self.st.lock().expect("lease table");
        let prev = st.insert(
            *device,
            Lease { holder: self.me, term_ms: term, expires_at: Instant::now() + self.ttl },
        );
        prev.filter(|p| p.holder != self.me).map(|p| p.holder)
    }

    /// 收到远端 publish/反熵条目：合并（新者胜）；本地持有的租约被更新者取代 ⇒
    /// 触发踢出钩子（旧端踢会话）。
    pub fn merge_remote(&self, msg: GossipMsg) {
        let entries: Vec<([u8; 32], NodeId, u64)> = match msg {
            GossipMsg::Publish { device, holder, term_ms } => vec![(device, holder, term_ms)],
            GossipMsg::Anti { entries } => entries
                .into_iter()
                .filter_map(|(d, h, t)| <[u8; 32]>::try_from(d).ok().map(|d| (d, h, t)))
                .collect(),
        };
        let mut evicted = Vec::new();
        {
            let mut st = self.st.lock().expect("lease table");
            for (device, holder, term) in entries {
                let newer = match st.get(&device) {
                    Some(cur) => (term, holder) > (cur.term_ms, cur.holder),
                    None => true,
                };
                if newer {
                    // 本地持有且被他人更新者取代 ⇒ 旧端踢出（新者胜）。
                    if let Some(cur) = st.get(&device) {
                        if cur.holder == self.me && holder != self.me {
                            evicted.push(device);
                        }
                    }
                    st.insert(device, Lease { holder, term_ms: term, expires_at: Instant::now() + self.ttl });
                }
            }
        }
        for d in evicted {
            self.hooks.fire_lease_evict(&d);
        }
    }

    /// 查询设备当前归属（TTL 过期 ⇒ None；「设备当前位置唯一真相源」的本地视图）。
    pub fn observe(&self, device: &[u8; 32]) -> Option<Lease> {
        let mut st = self.st.lock().expect("lease table");
        match st.get(device).copied() {
            Some(l) if l.expires_at > Instant::now() => Some(l),
            Some(_) => {
                st.remove(device);
                None
            }
            None => None,
        }
    }

    /// 一次性跨服位置询问（§3.10 `location_query`：fan-out ≤3，不缓存不重试——
    /// 失败即丢包+ICMP，由上层恢复）。本地租约域命中即答（唯一真相源）；
    /// 否则经 [`LocateFanout`] 问互连服务器「谁在托管该设备」，取首个肯定回答。
    pub async fn location_query(&self, device: &[u8; 32], fanout: &dyn LocateFanout) -> Option<NodeId> {
        if let Some(l) = self.observe(device) {
            return Some(l.holder);
        }
        fanout.locate(device).await
    }

    /// 全表摘要（反熵消息体）。
    pub fn anti_entropy_msg(&self) -> GossipMsg {
        let st = self.st.lock().expect("lease table");
        GossipMsg::Anti {
            entries: st
                .iter()
                .filter(|(_, l)| l.expires_at > Instant::now())
                .map(|(d, l)| (d.to_vec(), l.holder, l.term_ms))
                .collect(),
        }
    }
}

/// 位置询问扇出接缝（node 装配注入 wire 实现：WireRpc::Locate，至多 3 台互连服务器）。
pub trait LocateFanout: Send + Sync + 'static {
    fn locate(&self, device: &[u8; 32]) -> BoxFuture<'static, Option<NodeId>>;
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ============================================================================
// 单元测试：新者胜 + 旧端踢出回调 + TTL
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::HookRecorder;

    fn table(me: NodeId) -> Arc<LeaseTable> {
        LeaseTable::new(me, Duration::from_secs(30), HookRegistry::new())
    }

    fn table_with_hooks(me: NodeId, rec: Arc<HookRecorder>) -> Arc<LeaseTable> {
        let hooks = HookRegistry::new();
        hooks.add(rec);
        LeaseTable::new(me, Duration::from_secs(30), hooks)
    }

    #[test]
    fn newer_wins_and_old_side_evicted() {
        let rec = HookRecorder::new();
        let t1 = table_with_hooks(1, rec.clone());
        t1.publish(&[7; 32]);
        assert_eq!(t1.observe(&[7; 32]).unwrap().holder, 1);
        // 节点 2 的更新租约到达节点 1 ⇒ 新者胜 + 节点 1 踢出回调。
        t1.merge_remote(GossipMsg::Publish { device: [7; 32], holder: 2, term_ms: now_ms() + 50 });
        assert_eq!(t1.observe(&[7; 32]).unwrap().holder, 2, "新者胜");
        assert_eq!(rec.evictions(), vec![[7u8; 32]], "旧端踢出回调触发");
        // 旧 term 再来 ⇒ 不回退。
        t1.merge_remote(GossipMsg::Publish { device: [7; 32], holder: 1, term_ms: 1 });
        assert_eq!(t1.observe(&[7; 32]).unwrap().holder, 2, "旧者不覆盖");
    }

    #[test]
    fn ttl_expiry_and_anti_entropy() {
        let rec = HookRecorder::new();
        let t1 = table_with_hooks(1, rec.clone());
        let t2 = table(2);
        t1.publish(&[1; 32]);
        t1.publish(&[2; 32]);
        // 反熵：t1 全表 → t2。
        let msg = t1.anti_entropy_msg();
        t2.merge_remote(msg);
        assert_eq!(t2.observe(&[1; 32]).unwrap().holder, 1);
        assert_eq!(t2.observe(&[2; 32]).unwrap().holder, 1);
        // TTL 过期 ⇒ observe None（短 TTL 表）。
        let t3 = LeaseTable::new(3, Duration::from_millis(20), HookRegistry::new());
        t3.publish(&[9; 32]);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(t3.observe(&[9; 32]), None, "TTL 过期即失效");
    }
}
