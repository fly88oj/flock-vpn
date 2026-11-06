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
//! M7（§7-M7.3）：租约条目携带 per-device **EWMA 流量**（`tx_ewma/rx_ewma`，bytes/s，
//! 设备视角）与 `last_seen_unix`——动态面搭租约便车（publish/反熵同步，不进 Raft）。
//! 持有者权威：只有本机持有的行由本机折叠 EWMA；远端行的值以持有者消息为准。
//!
//! `location_query`（一次性跨服位置询问，fan-out ≤3）属跨服转发面（§2.2-4），与
//! ForwardEnvelope 同批落地；本模块先提供本地 `observe`（含 TTL 判定）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// 本地会话租约续期周期（TTL/3——**长寿命会话必须周期重发布**：publish 只在建连时
/// 触发一次，无续期则 30s 后全网「忘记」仍在线的设备（M5 e2e 实测暴露——A1 的
/// 90s 字节透传把 A2 推过 TTL 窗，跨服转发全体退化为 NOT_HERE）。
pub const LEASE_REFRESH: Duration = Duration::from_secs(10);
/// M7：EWMA 更新周期（§7-M7.3——1s 折叠窗；node 装配的 tick 循环驱动）。
pub const EWMA_TICK: Duration = Duration::from_secs(1);
/// M7：EWMA α = 1/5 = 0.2（§7-M7.3）。
pub const EWMA_ALPHA_NUM: u64 = 1;
pub const EWMA_ALPHA_DEN: u64 = 5;

/// EWMA 折叠：`next = prev·(1−α) + rate·α`（整数算术：`(prev·(DEN−NUM) + rate·NUM)/DEN`）。
pub fn ewma_fold(prev: u64, rate: u64) -> u64 {
    (prev.saturating_mul(EWMA_ALPHA_DEN - EWMA_ALPHA_NUM) + rate.saturating_mul(EWMA_ALPHA_NUM))
        / EWMA_ALPHA_DEN
}

/// M7（§7-M7.3 修订）：离线衰减因子——TTL 已过期且本窗无累加的行每窗 ×4/5
/// （与 α 无关的独立常数：语义是「无累加证据时的指数遗忘」，非速率估计）。
pub const EWMA_OFFLINE_DECAY_NUM: u64 = 4;
pub const EWMA_OFFLINE_DECAY_DEN: u64 = 5;
/// 离线衰减地板：按窗衰减至低于该速率（B/s）即置 0——名册不再呈现离线非零流量。
pub const EWMA_OFFLINE_FLOOR_BPS: u64 = 8;

/// 离线衰减单步：`v × 4/5`，低于 [`EWMA_OFFLINE_FLOOR_BPS`] 置 0。
pub fn ewma_offline_decay(v: u64) -> u64 {
    let d = v.saturating_mul(EWMA_OFFLINE_DECAY_NUM) / EWMA_OFFLINE_DECAY_DEN;
    if d < EWMA_OFFLINE_FLOOR_BPS {
        0
    } else {
        d
    }
}

/// 服务器自身在租约域的合成设备键（M7：Server 名册条目的自发布/计数锚）。
/// node_id 大端居前 8B + 固定标记后缀——真实设备 id 是 sha256(ed25519)，结构化前缀
/// 碰撞概率可忽略；各服务器以该键自发布租约（携带自身 EWMA），全网名册可装配。
pub fn server_self_device_id(node_id: NodeId) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&node_id.to_be_bytes());
    id[8..].fill(0x5A);
    id
}

/// 反熵单条目（M7：带宽/last_seen 字段随表摘要同步——持有者权威值）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiEntry {
    pub device: Vec<u8>,
    pub holder: NodeId,
    pub term_ms: u64,
    pub tx_ewma: u64,
    pub rx_ewma: u64,
    pub last_seen_unix: u64,
}

/// gossip 线消息（M7：Publish/Anti 均携带 EWMA 与 last_seen）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipMsg {
    /// 单条租约事件推送（publish 即时广播，≤1s 语义）。
    Publish {
        device: [u8; 32],
        holder: NodeId,
        term_ms: u64,
        tx_ewma: u64,
        rx_ewma: u64,
        last_seen_unix: u64,
    },
    /// 全表摘要（反熵；TTL 由收端以本机时钟重置）。
    Anti { entries: Vec<AntiEntry> },
}

/// 单条租约。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub holder: NodeId,
    pub term_ms: u64,
    pub expires_at: Instant,
    /// M7：设备视角 EWMA（bytes/s）——持有者维护，随 publish/反熵传播。
    pub tx_ewma: u64,
    pub rx_ewma: u64,
    /// M7：最后在线时刻（unix 秒；TTL 过期后行保留——名册离线设备展示用）。
    pub last_seen_unix: u64,
}

/// 名册/回收器消费的本地租约视图统计（在线判定 + EWMA + last_seen）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLeaseStats {
    /// TTL 内（唯一真相源本地视图）。
    pub online: bool,
    pub last_seen_unix: u64,
    pub tx_ewma: u64,
    pub rx_ewma: u64,
}

/// 本机 per-device 字节累加器（EWMA 折叠源；持有者侧维护）。
#[derive(Debug, Clone, Copy, Default)]
struct TrafficAcc {
    tx: u64,
    rx: u64,
    last_fold_ms: u64,
}

/// 本地租约表。
pub struct LeaseTable {
    me: NodeId,
    ttl: Duration,
    hooks: HookRegistry,
    st: Mutex<BTreeMap<[u8; 32], Lease>>,
    /// 本机测量累加器（M7；只对「本机持有」的行折叠进 ewma——远端行以持有者消息为准）。
    acc: Mutex<BTreeMap<[u8; 32], TrafficAcc>>,
    /// 已见远端 term 水位（含被拒收的旧条目——任何到达即抬升）。
    ///
    /// 反「时钟偏移误踢」护栏：本地 publish/续期的 term 至少取 `floor + 1`——本机墙钟
    /// 可能落后于已见远端 term（偏移或远端时钟超前），直接用 `now` 会让本地真实在线的
    /// 设备在「新者胜」比较中输掉自己见过的远端旧条目（单向连通下反复被踢）。
    /// 残余依赖（诚实披露）：从未互通 term 的两节点间仍按各自墙钟定序——绝对时钟
    /// 偏移可让先到者暂时取胜，TTL 过期 + 反熵兜底收敛。
    term_floor: AtomicU64,
    /// 自创建起合并过的远端 gossip 消息数（含空反熵摘要——任何到达都证明互连/反熵
    /// 面已活）。回收器「视图就绪」闸门的信号（[`LeaseTable::reaper_view_ready`]）。
    remote_events: AtomicU64,
}

impl LeaseTable {
    /// `hooks` 与状态机共用同一注册表（on_lease_evicted 与 on_revocation_applied 同源）。
    pub fn new(me: NodeId, ttl: Duration, hooks: HookRegistry) -> Arc<Self> {
        Arc::new(LeaseTable {
            me,
            ttl,
            hooks,
            st: Mutex::new(BTreeMap::new()),
            acc: Mutex::new(BTreeMap::new()),
            term_floor: AtomicU64::new(0),
            remote_events: AtomicU64::new(0),
        })
    }

    /// 本机节点号。
    pub fn me(&self) -> NodeId {
        self.me
    }

    /// M7：计一笔设备流量（转发面投递成功点调用；持有者侧维护——跨服 FRWD 的 dst
    /// 计数发生在收端/持有端，origin 不计 dst，见 forward.rs 注记）。累入 acc 并抬升
    /// 本机持有行的 last_seen。
    pub fn note_tx(&self, device: &[u8; 32], bytes: u64) {
        self.note_traffic(device, bytes, 0);
    }

    pub fn note_rx(&self, device: &[u8; 32], bytes: u64) {
        self.note_traffic(device, 0, bytes);
    }

    fn note_traffic(&self, device: &[u8; 32], tx: u64, rx: u64) {
        {
            let mut acc = self.acc.lock().expect("lease acc");
            let e = acc.entry(*device).or_default();
            e.tx = e.tx.saturating_add(tx);
            e.rx = e.rx.saturating_add(rx);
        }
        // 本机持有的行：流量即活跃证据 ⇒ 抬 last_seen（远端行不动——持有者权威）。
        let now = now_unix();
        let mut st = self.st.lock().expect("lease table");
        if let Some(l) = st.get_mut(device) {
            if l.holder == self.me {
                l.last_seen_unix = l.last_seen_unix.max(now);
            }
        }
    }

    /// M7：EWMA 折叠（1s 窗；node 装配的 tick 循环调用，`now_ms` 显式注入可测）。
    /// 只折本机持有的行——acc 里的远端设备流量（如本机作为 FRWD 收端代计前的瞬态）
    /// 不覆写持有者发布的值。
    ///
    /// 离线衰减（§7-M7.3 修订）：TTL 已过期且**无本地累加器**（远端行/从未计流的本机
    /// 行——下方折叠循环触不到）的行按窗 ×4/5 衰减、<8B/s 置 0——名册不再呈现离线
    /// 非零流量。有累加器的行由折叠循环的零速率折叠（同 ×4/5 数学）自然衰减至 0。
    pub fn tick_ewma(&self, now_ms_val: u64) {
        let mut acc = self.acc.lock().expect("lease acc");
        let mut st = self.st.lock().expect("lease table");
        // ① 折叠：本机持有 + 有累加（既有逻辑）。
        for (dev, a) in acc.iter_mut() {
            if a.last_fold_ms == 0 {
                a.last_fold_ms = now_ms_val;
                continue;
            }
            let dt = now_ms_val.saturating_sub(a.last_fold_ms);
            if dt < EWMA_TICK.as_millis() as u64 {
                continue;
            }
            let Some(l) = st.get_mut(dev) else { continue };
            if l.holder != self.me {
                // 非本机持有：累加器留待持有权变化后重置（publish 重置 acc）。
                continue;
            }
            let secs = dt as f64 / 1000.0;
            let tx_rate = (a.tx as f64 / secs) as u64;
            let rx_rate = (a.rx as f64 / secs) as u64;
            l.tx_ewma = ewma_fold(l.tx_ewma, tx_rate);
            l.rx_ewma = ewma_fold(l.rx_ewma, rx_rate);
            a.tx = 0;
            a.rx = 0;
            a.last_fold_ms = now_ms_val;
        }
        // ② 离线衰减：TTL 过期且折叠循环触不到（无 acc 条目）的行。
        let now = Instant::now();
        for (dev, l) in st.iter_mut() {
            if l.expires_at > now {
                continue;
            }
            if acc.contains_key(dev) {
                continue;
            }
            l.tx_ewma = ewma_offline_decay(l.tx_ewma);
            l.rx_ewma = ewma_offline_decay(l.rx_ewma);
        }
    }

    /// 发布本机租约（新者胜）。返回被本机取代的旧持有者（若有——冲突场景的对端）。
    /// 远端传播由调用方（node 装配）广播 [`GossipMsg::Publish`]。
    ///
    /// term 至少取 `max(已见远端 term) + 1`（墙钟与本机取大）：本机时钟偏移（落后于
    /// 已见远端条目）不得让本地真实在线的设备在续期时输掉「新者胜」（见 `term_floor`）。
    /// M7：ewma 从既有行**继承**（续期不清零流量视图）；接管他机行（或全新发布）时
    /// 本机 acc 重置——旧累加器是旧持有者的测量，不作数。
    ///
    /// 锁纪律：st 与 acc 不嵌套（tick_ewma 以 acc→st 序嵌套——本函数先释 st 再碰 acc，
    /// 全表只有 tick 一处嵌套，无反向序）。
    pub fn publish(&self, device: &[u8; 32]) -> Option<NodeId> {
        let floor = self.term_floor.load(Ordering::SeqCst);
        let term = now_ms().max(floor.saturating_add(1));
        let prev = {
            let mut st = self.st.lock().expect("lease table");
            let prev = st.get(device).copied();
            st.insert(
                *device,
                Lease {
                    holder: self.me,
                    term_ms: term,
                    expires_at: Instant::now() + self.ttl,
                    tx_ewma: prev.map(|p| p.tx_ewma).unwrap_or(0),
                    rx_ewma: prev.map(|p| p.rx_ewma).unwrap_or(0),
                    last_seen_unix: now_unix(),
                },
            );
            prev
        };
        if prev.is_none_or(|p| p.holder != self.me) {
            self.acc.lock().expect("lease acc").remove(device);
        }
        prev.filter(|p| p.holder != self.me).map(|p| p.holder)
    }

    /// 收到远端 publish/反熵条目：合并（新者胜）；本地持有的租约被更新者取代 ⇒
    /// 触发踢出钩子（旧端踢会话）。
    ///
    /// 任何到达（含空反熵摘要）都计入 `remote_events`——「互连/反熵面已活」的证明，
    /// 回收器闸门据此判定重启后的租约视图是否已就绪（§7-M7.5）。
    pub fn merge_remote(&self, msg: GossipMsg) {
        self.remote_events.fetch_add(1, Ordering::SeqCst);
        let entries: Vec<AntiEntry> = match msg {
            GossipMsg::Publish {
                device,
                holder,
                term_ms,
                tx_ewma,
                rx_ewma,
                last_seen_unix,
            } => vec![AntiEntry {
                device: device.to_vec(),
                holder,
                term_ms,
                tx_ewma,
                rx_ewma,
                last_seen_unix,
            }],
            GossipMsg::Anti { entries } => entries,
        };
        let mut evicted = Vec::new();
        {
            let mut st = self.st.lock().expect("lease table");
            for e in entries {
                let Ok(device) = <[u8; 32]>::try_from(e.device) else {
                    continue;
                };
                let AntiEntry {
                    holder,
                    term_ms: term,
                    tx_ewma,
                    rx_ewma,
                    last_seen_unix,
                    ..
                } = e;
                // 任何到达的远端 term（含被拒收的旧条目）都抬升本地基准：
                // 下次本地 publish 至少 term+1（时钟偏移护栏，见 `term_floor`）。
                self.term_floor.fetch_max(term, Ordering::SeqCst);
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
                    st.insert(
                        device,
                        Lease {
                            holder,
                            term_ms: term,
                            expires_at: Instant::now() + self.ttl,
                            tx_ewma,
                            rx_ewma,
                            last_seen_unix,
                        },
                    );
                }
            }
        }
        for d in evicted {
            self.hooks.fire_lease_evict(&d);
        }
    }

    /// 查询设备当前归属（TTL 过期 ⇒ None；「设备当前位置唯一真相源」的本地视图）。
    /// M7：过期行**保留**（不再删除）——last_seen/EWMA 供名册离线设备展示；
    /// `live_len`/反熵仍按 TTL 过滤。
    pub fn observe(&self, device: &[u8; 32]) -> Option<Lease> {
        let st = self.st.lock().expect("lease table");
        match st.get(device).copied() {
            Some(l) if l.expires_at > Instant::now() => Some(l),
            _ => None,
        }
    }

    /// M7：名册/回收器视图（在线判定 + last_seen + EWMA；从未见过租约 ⇒ None）。
    pub fn peer_stats(&self, device: &[u8; 32]) -> Option<PeerLeaseStats> {
        let st = self.st.lock().expect("lease table");
        st.get(device).map(|l| PeerLeaseStats {
            online: l.expires_at > Instant::now(),
            last_seen_unix: l.last_seen_unix,
            tx_ewma: l.tx_ewma,
            rx_ewma: l.rx_ewma,
        })
    }

    /// 一次性跨服位置询问（§3.10 `location_query`：fan-out ≤3，不缓存不重试——
    /// 失败即丢包+ICMP，由上层恢复）。本地租约域命中即答（唯一真相源）；
    /// 否则经 [`LocateFanout`] 问互连服务器「谁在托管该设备」，取首个肯定回答。
    pub async fn location_query(
        &self,
        device: &[u8; 32],
        fanout: &dyn LocateFanout,
    ) -> Option<NodeId> {
        if let Some(l) = self.observe(device) {
            return Some(l.holder);
        }
        fanout.locate(device).await
    }

    /// 非过期租约条数（诊断/断言面：gossip 传播是否工作）。
    pub fn live_len(&self) -> usize {
        let st = self.st.lock().expect("lease table");
        st.iter()
            .filter(|(_, l)| l.expires_at > Instant::now())
            .count()
    }

    /// 表内总行数（**含 TTL 过期的保留行**——M7 过期不删，名册离线展示用）。
    pub fn total_rows(&self) -> usize {
        self.st.lock().expect("lease table").len()
    }

    /// 自创建起合并过的远端 gossip 消息数（含空摘要）。
    pub fn remote_events(&self) -> u64 {
        self.remote_events.load(Ordering::SeqCst)
    }

    /// M7 回收器「视图就绪」闸门（§7-M7.5，**最小可靠形态**）：表非空**且**自启动起
    /// 收到过至少一条远端 gossip ⇒ 本地租约视图足以支撑回收判定。
    ///
    /// 语义取舍（如实注明）：
    /// - 刚重启的节点租约表为空、且在收到首条远端事件（对端反熵摘要 ≤1 个周期 5s、
    ///   或本机首台设备建连 publish）之前，视图不可判 ⇒ 回收跳过——闭合「反熵回填与
    ///   回收首拍赛跑」窗口（该窗口内远端托管设备的租约行缺失，`last_seen=0` 会被
    ///   锚到 `registered_at`，长注册的在线设备可能被误终态化）。
    /// - 残余 1：闸门开启后首拍仍可能早于对端摘要回填（≤1 个反熵周期）——由回收周期
    ///   60s ≫ 5s 与「真离线设备才超锚窗」共同兜底；主修复是 registered_at 锚，
    ///   本闸门是纵深防御。
    /// - 残余 2：单节点 raft 集群（无对端）永无远端事件 ⇒ 闸门恒关、保留期不生效——
    ///   该形态不在部署面（§6.2 ≥2 台）；如需启用，接受此残留或补第 2 台服务器。
    pub fn reaper_view_ready(&self) -> bool {
        self.total_rows() > 0 && self.remote_events() > 0
    }

    /// 全表摘要（反熵消息体）。
    pub fn anti_entropy_msg(&self) -> GossipMsg {
        let st = self.st.lock().expect("lease table");
        GossipMsg::Anti {
            entries: st
                .iter()
                .filter(|(_, l)| l.expires_at > Instant::now())
                .map(|(d, l)| AntiEntry {
                    device: d.to_vec(),
                    holder: l.holder,
                    term_ms: l.term_ms,
                    tx_ewma: l.tx_ewma,
                    rx_ewma: l.rx_ewma,
                    last_seen_unix: l.last_seen_unix,
                })
                .collect(),
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
// TrafficMeter：单服形态的独立流量计（同 EWMA 数学，无 gossip；§7-M7.3）
// ============================================================================

/// 任意键（设备 VIP 字节 / 服务器自身键）的 per-key EWMA + last_seen 计量器。
/// 单服形态（无租约表）由 `PeerRouter` 双向计数喂入；多主形态走 `LeaseTable`。
pub struct TrafficMeter {
    st: Mutex<std::collections::HashMap<Vec<u8>, MeterEntry>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct MeterEntry {
    tx_acc: u64,
    rx_acc: u64,
    last_fold_ms: u64,
    tx_ewma: u64,
    rx_ewma: u64,
    last_seen_unix: u64,
}

impl TrafficMeter {
    pub fn new() -> Arc<Self> {
        Arc::new(TrafficMeter {
            st: Mutex::new(std::collections::HashMap::new()),
        })
    }

    pub fn note_tx(&self, key: &[u8], bytes: u64) {
        self.note(key, bytes, 0);
    }

    pub fn note_rx(&self, key: &[u8], bytes: u64) {
        self.note(key, 0, bytes);
    }

    fn note(&self, key: &[u8], tx: u64, rx: u64) {
        let now = now_unix();
        let mut st = self.st.lock().expect("traffic meter");
        let e = st.entry(key.to_vec()).or_default();
        e.tx_acc = e.tx_acc.saturating_add(tx);
        e.rx_acc = e.rx_acc.saturating_add(rx);
        e.last_seen_unix = e.last_seen_unix.max(now);
    }

    /// 1s 窗折叠（`now_ms` 显式注入可测）。
    pub fn tick(&self, now_ms_val: u64) {
        let mut st = self.st.lock().expect("traffic meter");
        for e in st.values_mut() {
            if e.last_fold_ms == 0 {
                e.last_fold_ms = now_ms_val;
                continue;
            }
            let dt = now_ms_val.saturating_sub(e.last_fold_ms);
            if dt < EWMA_TICK.as_millis() as u64 {
                continue;
            }
            let secs = dt as f64 / 1000.0;
            e.tx_ewma = ewma_fold(e.tx_ewma, (e.tx_acc as f64 / secs) as u64);
            e.rx_ewma = ewma_fold(e.rx_ewma, (e.rx_acc as f64 / secs) as u64);
            e.tx_acc = 0;
            e.rx_acc = 0;
            e.last_fold_ms = now_ms_val;
        }
    }

    /// 名册视图（无条目 ⇒ None——从未见过流量）。
    pub fn stats(&self, key: &[u8]) -> Option<(u64, u64, u64)> {
        let st = self.st.lock().expect("traffic meter");
        st.get(key)
            .map(|e| (e.tx_ewma, e.rx_ewma, e.last_seen_unix))
    }

    /// 是否有过任何观测（空表 = 自创建起从未计到任何流量——单服回收器的重启闸门
    /// 用，§7-M7.5：TrafficMeter 纯内存，重启即清空；空表且注册表非空 ⇒ 刚重启）。
    pub fn has_any(&self) -> bool {
        !self.st.lock().expect("traffic meter").is_empty()
    }
}

impl Default for TrafficMeter {
    fn default() -> Self {
        TrafficMeter {
            st: Mutex::new(std::collections::HashMap::new()),
        }
    }
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
        t1.merge_remote(GossipMsg::Publish {
            device: [7; 32],
            holder: 2,
            term_ms: now_ms() + 50,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
        assert_eq!(t1.observe(&[7; 32]).unwrap().holder, 2, "新者胜");
        assert_eq!(rec.evictions(), vec![[7u8; 32]], "旧端踢出回调触发");
        // 旧 term 再来 ⇒ 不回退。
        t1.merge_remote(GossipMsg::Publish {
            device: [7; 32],
            holder: 1,
            term_ms: 1,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
        assert_eq!(t1.observe(&[7; 32]).unwrap().holder, 2, "旧者不覆盖");
    }

    /// 续期周期守门：LEASE_REFRESH 必须显著短于 TTL（两次续期窗内不过期——
    /// M5 e2e 暴露的「长寿命会话租约蒸发」回归面）。
    #[test]
    fn refresh_period_is_well_within_ttl() {
        assert!(
            LEASE_REFRESH + LEASE_REFRESH < LEASE_TTL,
            "两个续期周期必须都在 TTL 内（缺一轮续期仍存活——10s 续期 × 30s TTL）"
        );
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

    /// 时钟偏移护栏：本地墙钟落后于已见远端 term（远端时钟超前 5s + 单向连通——本地
    /// 收得到远端）时，本地续期 term 仍越过已见远端 term ⇒「新者胜」不反转、本地在线
    /// 设备不被误踢。
    #[test]
    fn republish_beats_seen_remote_term_despite_clock_skew() {
        let t1 = table_with_hooks(1, HookRecorder::new());
        let t2 = table_with_hooks(2, HookRecorder::new());
        let dev = [0x5e; 32];
        // 节点 1 先持有（本地时钟正常）。
        t1.publish(&dev);
        let t1_term = t1.observe(&dev).unwrap().term_ms;
        // 节点 2 见到节点 1 的租约（抬升基准），随后设备移到节点 2 —— 但节点 2 墙钟
        // 落后（模拟：远端条目 term 超前本地 now 5s 到达）。
        let skewed_remote = now_ms() + 5_000;
        t2.merge_remote(GossipMsg::Publish {
            device: dev,
            holder: 3,
            term_ms: skewed_remote,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
        assert_eq!(t2.observe(&dev).unwrap().holder, 3, "超前的远端条目先入表");
        // 节点 2 本地续期（设备真实在节点 2）：term ≥ skewed_remote+1（越过已见远端）。
        t2.publish(&dev);
        let l2 = t2.observe(&dev).unwrap();
        assert_eq!(l2.holder, 2);
        assert!(
            l2.term_ms > skewed_remote,
            "本地续期 term 越过已见远端 term（不因时钟落后丢新者胜）"
        );
        assert!(l2.term_ms > t1_term);
        // 该续期到达节点 1 ⇒ 新者胜 + 旧端（节点 3 的视角对 1 而言即覆盖）+ 踢出钩子。
        t1.merge_remote(GossipMsg::Publish {
            device: dev,
            holder: 2,
            term_ms: l2.term_ms,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
        assert_eq!(t1.observe(&dev).unwrap().holder, 2, "续期传播后新者胜");
    }

    // ------------------------------------------------------------------
    // M7（§7-M7.3）：EWMA 收敛 / gossip 带宽字段往返 / last_seen 维护
    // ------------------------------------------------------------------

    /// EWMA 收敛：恒定速率（每秒 1000B）喂养 + 1s 折叠 ⇒ ewma 逼近 1000
    ///（α=0.2：20 折后残差 ≈ 1000·0.8²⁰ ≈ 1.2%，5% 容差充分）；中途单调非减。
    #[test]
    fn ewma_converges_under_constant_rate() {
        let t = table(1);
        let dev = [0x11; 32];
        t.publish(&dev);
        let mut ms = 1_000_000u64;
        let mut prev_ewma = 0u64;
        for _ in 0..20 {
            t.note_tx(&dev, 1000);
            ms += 1000;
            t.tick_ewma(ms);
            let ewma = t.peer_stats(&dev).unwrap().tx_ewma;
            assert!(
                ewma >= prev_ewma,
                "恒定速率下折叠单调非减（{prev_ewma}→{ewma}）"
            );
            prev_ewma = ewma;
        }
        let stats = t.peer_stats(&dev).unwrap();
        assert!(
            (stats.tx_ewma as i64 - 1000).abs() <= 50,
            "20 折后 ewma 收敛到 1000±5%: {}",
            stats.tx_ewma
        );
        assert_eq!(stats.rx_ewma, 0, "rx 未喂养 ⇒ 0");
        assert!(stats.online, "刚发布 ⇒ 在线");
    }

    /// gossip 带宽字段往返：持有者折叠出的 ewma/last_seen 经 Publish 与反熵两条通路
    /// 到达远端节点——线格式（postcard）往返 + peer_stats 取值一致。
    #[test]
    fn gossip_carries_bandwidth_fields_roundtrip() {
        let t1 = table(1);
        let t2 = table(2);
        let dev = [0x22; 32];
        t1.publish(&dev);
        // 喂 2 秒恒定速率并折叠。
        let mut ms = 5_000_000u64;
        for _ in 0..10 {
            t1.note_tx(&dev, 500);
            t1.note_rx(&dev, 300);
            ms += 1000;
            t1.tick_ewma(ms);
        }
        let s1 = t1.peer_stats(&dev).unwrap();
        assert!(s1.tx_ewma > 0 && s1.rx_ewma > 0, "持有者侧 ewma 非零");

        // Publish 通路：线格式往返（postcard 编解码）后合并到 t2。
        let l = t1.observe(&dev).unwrap();
        let msg = GossipMsg::Publish {
            device: dev,
            holder: 1,
            term_ms: l.term_ms,
            tx_ewma: s1.tx_ewma,
            rx_ewma: s1.rx_ewma,
            last_seen_unix: s1.last_seen_unix,
        };
        let wire = postcard::to_allocvec(&msg).expect("encode");
        let msg: GossipMsg = postcard::from_bytes(&wire).expect("decode");
        t2.merge_remote(msg);
        let s2 = t2.peer_stats(&dev).unwrap();
        assert_eq!(
            (s2.tx_ewma, s2.rx_ewma, s2.last_seen_unix),
            (s1.tx_ewma, s1.rx_ewma, s1.last_seen_unix),
            "Publish 通路带宽字段一致"
        );
        assert_eq!(t2.observe(&dev).unwrap().holder, 1);

        // 反熵通路：全表摘要（AntiEntry 线格式）→ 第三个节点。
        let t3 = table(3);
        let anti = t1.anti_entropy_msg();
        let wire = postcard::to_allocvec(&anti).expect("encode");
        let anti: GossipMsg = postcard::from_bytes(&wire).expect("decode");
        t3.merge_remote(anti);
        let s3 = t3.peer_stats(&dev).unwrap();
        assert_eq!(
            (s3.tx_ewma, s3.rx_ewma),
            (s1.tx_ewma, s1.rx_ewma),
            "反熵通路一致"
        );
        assert!(s3.online, "反熵携带的条目 TTL 由收端重置 ⇒ 在线");
    }

    /// last_seen 维护：流量计数抬升持有者行 last_seen；TTL 过期后行保留（observe None
    /// 但 peer_stats 仍给 last_seen/ewma——名册离线设备展示面）。
    #[test]
    fn last_seen_bumped_by_traffic_and_retained_after_expiry() {
        // 短 TTL 表（40ms）观察过期保留。
        let t = LeaseTable::new(9, Duration::from_millis(40), HookRegistry::new());
        let dev = [0x33; 32];
        t.publish(&dev);
        t.note_tx(&dev, 100);
        let before = t.peer_stats(&dev).unwrap().last_seen_unix;
        assert!(before > 0, "publish/note 已置 last_seen");
        // 过期：observe ⇒ None（在线判定收回），行保留 ⇒ peer_stats 仍在。
        std::thread::sleep(Duration::from_millis(80));
        assert!(t.observe(&dev).is_none(), "TTL 过期 ⇒ observe None");
        let s = t
            .peer_stats(&dev)
            .expect("行保留（M7：过期不删——名册 last_seen）");
        assert!(!s.online);
        assert_eq!(s.last_seen_unix, before);
        // 反熵/在线计数不再包含过期行。
        let anti = t.anti_entropy_msg();
        let GossipMsg::Anti { entries } = anti else {
            panic!()
        };
        assert!(entries.is_empty(), "过期行不进反熵摘要");
    }

    /// M7（§7-M7.3 修订）：TTL 过期后的离线衰减——**远端行**（无本地累加器，折叠
    /// 循环触不到）按窗 ×4/5 衰减、<8B/s 置 0（名册不再呈现离线非零流量）；收敛
    /// 单调非增且有限窗内到 0。本机累加行由零速率折叠（同数学）衰减。
    #[test]
    fn offline_ewma_decays_to_zero_after_ttl() {
        // 远端行：远端发布携带非零 ewma → TTL 过期（短表 40ms）→ 无 acc ⇒ 衰减支路。
        let t = LeaseTable::new(1, Duration::from_millis(40), HookRegistry::new());
        let remote = [0x55; 32];
        t.merge_remote(GossipMsg::Publish {
            device: remote,
            holder: 2,
            term_ms: now_ms() + 100,
            tx_ewma: 5_000,
            rx_ewma: 0,
            last_seen_unix: 100,
        });
        assert_eq!(t.peer_stats(&remote).unwrap().tx_ewma, 5_000);
        std::thread::sleep(Duration::from_millis(60)); // TTL 过期（observe None，行保留）
        assert!(t.observe(&remote).is_none());
        let mut ms = 8_000_000u64;
        let mut rounds = 0u32;
        let mut prev = t.peer_stats(&remote).unwrap().tx_ewma;
        while t.peer_stats(&remote).unwrap().tx_ewma > 0 {
            ms += 1000;
            t.tick_ewma(ms);
            rounds += 1;
            let cur = t.peer_stats(&remote).unwrap().tx_ewma;
            assert!(cur <= prev, "衰减单调非减变（{prev}→{cur}）");
            prev = cur;
            assert!(rounds < 100, "有限窗内收敛到 0（{} 轮后 {}）", rounds, cur);
        }
        assert_eq!(t.peer_stats(&remote).unwrap().rx_ewma, 0);

        // 本机持有 + 有累加的行：离线后由零速率折叠衰减（同 ×4/5 数学）——在线期先
        // 收敛出非零，断流过期后同样归 0。
        let t2 = LeaseTable::new(9, Duration::from_millis(40), HookRegistry::new());
        let local = [0x66; 32];
        t2.publish(&local);
        let mut ms2 = 9_000_000u64;
        for _ in 0..15 {
            t2.note_tx(&local, 1000);
            ms2 += 1000;
            t2.tick_ewma(ms2);
        }
        assert!(
            t2.peer_stats(&local).unwrap().tx_ewma > 100,
            "在线期收敛非零（{}）",
            t2.peer_stats(&local).unwrap().tx_ewma
        );
        std::thread::sleep(Duration::from_millis(60));
        let mut rounds = 0u32;
        while t2.peer_stats(&local).unwrap().tx_ewma > 0 {
            ms2 += 1000;
            t2.tick_ewma(ms2);
            rounds += 1;
            assert!(rounds < 100, "本机行有限窗收敛到 0");
        }
    }

    /// 服务器自身合成键：不同 node_id 不碰撞、与真实设备 id（sha256）结构可区分。
    #[test]
    fn server_self_device_id_distinct() {
        let a = server_self_device_id(1);
        let b = server_self_device_id(2);
        assert_ne!(a, b);
        assert_eq!(a, server_self_device_id(1));
        assert_eq!(&a[..8], &1u64.to_be_bytes());
        assert!(a[8..].iter().all(|&x| x == 0x5A), "固定标记后缀");
    }

    /// TrafficMeter（单服形态）：恒定速率收敛 + last_seen 抬升 + stats 键隔离。
    #[test]
    fn traffic_meter_converges_and_keys_isolated() {
        let m = TrafficMeter::new();
        let k1 = [100u8, 64, 0, 2];
        let k2 = [100u8, 64, 0, 3];
        let mut ms = 2_000_000u64;
        for _ in 0..15 {
            m.note_tx(&k1, 2000);
            ms += 1000;
            m.tick(ms);
        }
        m.note_rx(&k2, 777);
        let (tx1, rx1, ls1) = m.stats(&k1).expect("k1 有条目");
        assert!((tx1 as i64 - 2000).abs() <= 100, "k1 tx 收敛: {tx1}");
        assert_eq!(rx1, 0);
        assert!(ls1 > 0);
        let (tx2, rx2, _) = m.stats(&k2).expect("k2 有条目");
        assert_eq!((tx2, rx2), (0, 0), "k2 尚未折叠（无 tick 后喂入）");
        assert!(m.stats(&[9, 9, 9, 9]).is_none(), "未知键 ⇒ None");
    }
}
