//! 跨服转发承载（§2.2 数据面 ForwardEnvelope + §3.10 转发面，M4 第二部分）。
//!
//! 转发判定序（§2.2）：
//! 0. **源 VIP 绑定校验（第 0 步，先于一切转发逻辑）**：会话设备的每个出向 IP 包，
//!    源地址必须等于该设备的注册 VIP（会话 DeviceId ↔ src VIP 绑定；rp_filter 不覆盖
//!    用户态流——应用层每节点入向过滤）。失配 ⇒ 丢包 + 计数。ForwardEnvelope 的
//!    `src_dev` 与内层源地址**收端与发端各查一次**。
//! 1. 目标 VIP → 设备归属：查**本地租约表**（gossip）——设备当前位置的唯一真相源
//!    （NetState 只存静态注册信息）。
//! 2. 归属本机 ⇒ 直接投该会话的 PacketChannel（`PacketSink` 接缝）。
//! 3. 归属他机 ⇒ `ForwardEnvelope{ver, src_dev, dst_dev, origin_server, hop=1, payload}`
//!    经服务器互连 E2E 会话的专用 FRWD 流发出；收端：dst 在本地 ⇒ 投递；否则回
//!    `NOT_HERE`（**禁止二次转发**，hop=1 防环——hop 耗尽的再转发 ⇒ 丢 + 计数）。
//! 4. NOT_HERE ⇒ **一次性位置查询**（location_query，fan-out ≤3）重定向一次；
//!    仍失败 ⇒ **丢包 + 尽力发 ICMP unreachable**（不广播、不缓存重试）。
//!
//! # M7 per-device 字节计数（§7-M7.3「投递成功点计数」单点原则）
//!
//! 每笔流量恰由**一台服务器**计数（杜绝跨服双计）：
//! - **src 设备 tx**：由**接入服务器**（src 租约持有者）在 ingest 通过第 0 步源 VIP
//!   绑定校验后计一次（收进 mesh 即成功；dst 侧任何服务器都不计 src）；
//! - **dst 设备 rx**：由**投递成功的服务器**计——本机 sink 投递成功（同服路径）或
//!   ForwardEnvelope 收端本机投递成功（跨服路径，收端即 dst 的真实持有者）；
//!   NotHere/丢弃不计；跨服的 origin 服务器**不**计 dst（它只计 src tx）；
//! - **服务器自身**（`server_self_device_id(me)` 合成键）：dst = 本机 VIP 注内核
//!   成功 ⇒ rx；内核回程 `route_outbound` ⇒ tx（服务器自身条目只在自身计——
//!   其他服务器经 gossip 视图读）。

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::lease::{server_self_device_id, LeaseTable, LocateFanout};
use crate::proto::NodeId;
use crate::sm::SmCore;

/// ForwardEnvelope 版本。
pub const FORWARD_VER: u8 = 1;

/// 跨服转发信封（§2.2-3；经服务器互连会话的 FRWD 流承载——外层有服务器间加密）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardEnvelope {
    pub ver: u8,
    /// 内层 IP 包的声称发送设备（与内层源地址交叉校验，收发端各一次）。
    pub src_dev: [u8; 32],
    pub dst_dev: [u8; 32],
    /// 发起转发的服务器（NOT_HERE 回执目标）。
    pub origin_server: NodeId,
    /// 剩余跳数：1 = 首跳。收端只许本机投递/NOT_HERE；**禁止二次转发**（hop=1 防环）。
    pub hop: u8,
    /// 内层 IP 包（此段为明文——威胁模型见 §2.5）。
    pub payload: Vec<u8>,
}

/// 收端拒绝原因码。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    /// 版本不受支持。
    Version,
    /// hop 耗尽（防环：二次转发）。
    Hop,
    /// src_dev ↔ 内层源地址交叉校验失配。
    SrcBinding,
}

/// 转发结果（FRWD 流回执）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForwardOutcome {
    /// 已投递本机会话。
    Delivered,
    /// dst 不在本机（origin 据此走一次性 location_query）。
    NotHere,
    /// 收端拒绝（源绑定失配 / 环路 / 坏包）。
    Rejected(RejectReason),
}

/// 本地会话投递接缝（装配层映射 PacketChannel；测试用记录 sink）。
pub trait PacketSink: Send + Sync + 'static {
    fn deliver(&self, pkt: &[u8]) -> io::Result<()>;
}

/// 互连发送接缝（node 装配注入：WireRpc::Forward 经 E2E 会话）。
pub trait ForwardTransport: Send + Sync + 'static {
    fn send(
        &self,
        peer: NodeId,
        env: ForwardEnvelope,
    ) -> BoxFuture<'static, io::Result<ForwardOutcome>>;
}

/// 转发面计数（断言/告警面；§2.2-0「丢+计数+超限告警」）。
#[derive(Debug, Default, Clone, Copy)]
pub struct ForwardStats {
    /// 第 0 步源 VIP 绑定失配（丢 + 计数）。
    pub src_violations: u64,
    /// 收端 src_dev ↔ 内层源地址交叉校验失配（拒 + 计数）。
    pub src_mismatch_rejected: u64,
    /// hop 耗尽的二次转发（防环：丢 + 计数）。
    pub hop_dropped: u64,
    pub delivered_local: u64,
    /// 交付本机内核（dst = 本服务器自身 VIP——服务器也是 peer，§2.2）。
    pub delivered_kernel: u64,
    /// 本机内核发出（route_outbound：回程/本机协议栈流量进 mesh）。
    pub outbound_kernel: u64,
    pub forwarded: u64,
    pub not_here: u64,
    /// NOT_HERE 后经一次性 location_query 重定向成功。
    pub locate_redirected: u64,
    pub icmp_unreachable: u64,
    /// 重定向后仍失败 / 未知目标 ⇒ 丢包。
    pub dropped: u64,
}

/// 入向处理结果（ingest 返回；测试/装配断言用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestResult {
    /// 已投递本机目标会话。
    DeliveredLocal,
    /// 已跨服转发（含对端结果）。
    Forwarded(ForwardOutcome),
    /// 源 VIP 绑定失配 ⇒ 丢包（已计数）。
    SrcViolation,
    /// 丢弃（附尽力 ICMP unreachable，已计数）。
    DroppedIcmp,
    /// 丢弃（无 ICMP 收件人——源不在本机，尽力语义）。
    Dropped,
}

/// 转发引擎（每服务器一个；装配层把会话/租约表/互连注入）。
pub struct ForwardPlane {
    me: NodeId,
    sm: Arc<SmCore>,
    leases: Arc<LeaseTable>,
    transport: Mutex<Option<Arc<dyn ForwardTransport>>>,
    fanout: Mutex<Option<Arc<dyn LocateFanout>>>,
    sessions: Mutex<HashMap<[u8; 32], Arc<dyn PacketSink>>>,
    /// 本机内核接缝（服务器自身 VIP 的本机投递 + 回程路由，§2.2「服务端自身也是
    /// peer」）：`(自身 VIP, tun 写泵 sink)`——dst = 自身 VIP 的包进内核（ICMP 应答/
    /// iperf 绑定面）；内核读出的包经 [`ForwardPlane::route_outbound`] 回 mesh。
    local_peer: Mutex<Option<(Ipv4Addr, Arc<dyn PacketSink>)>>,
    stats: ForwardStatsAtomic,
}

#[derive(Default)]
struct ForwardStatsAtomic {
    src_violations: AtomicU64,
    src_mismatch_rejected: AtomicU64,
    hop_dropped: AtomicU64,
    delivered_local: AtomicU64,
    delivered_kernel: AtomicU64,
    outbound_kernel: AtomicU64,
    forwarded: AtomicU64,
    not_here: AtomicU64,
    locate_redirected: AtomicU64,
    icmp_unreachable: AtomicU64,
    dropped: AtomicU64,
}

impl ForwardPlane {
    pub fn new(me: NodeId, sm: Arc<SmCore>, leases: Arc<LeaseTable>) -> Arc<Self> {
        Arc::new(ForwardPlane {
            me,
            sm,
            leases,
            transport: Mutex::new(None),
            fanout: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            local_peer: Mutex::new(None),
            stats: ForwardStatsAtomic::default(),
        })
    }

    /// 注入互连发送与位置询问扇出（node 装配期）。
    pub fn set_transport(&self, t: Arc<dyn ForwardTransport>, f: Arc<dyn LocateFanout>) {
        *self.transport.lock().expect("fwd transport") = Some(t);
        *self.fanout.lock().expect("fwd fanout") = Some(f);
    }

    /// 本机节点号。
    pub fn me(&self) -> NodeId {
        self.me
    }

    /// 租约表引用（测试/装配诊断面）。
    pub fn leases(&self) -> &Arc<LeaseTable> {
        &self.leases
    }

    /// 本地在册会话设备集（租约续期循环用——长寿命会话的租约重发布，lease.rs）。
    pub fn local_devices(&self) -> Vec<[u8; 32]> {
        self.sessions
            .lock()
            .expect("fwd sessions")
            .keys()
            .copied()
            .collect()
    }

    /// 挂载/卸载本地设备会话（登录建立/断链拆除）。
    pub fn attach_session(&self, device: [u8; 32], sink: Arc<dyn PacketSink>) {
        self.sessions
            .lock()
            .expect("fwd sessions")
            .insert(device, sink);
    }

    pub fn detach_session(&self, device: &[u8; 32]) {
        self.sessions.lock().expect("fwd sessions").remove(device);
    }

    /// 计数快照。
    pub fn stats(&self) -> ForwardStats {
        ForwardStats {
            src_violations: self.stats.src_violations.load(Ordering::Relaxed),
            src_mismatch_rejected: self.stats.src_mismatch_rejected.load(Ordering::Relaxed),
            hop_dropped: self.stats.hop_dropped.load(Ordering::Relaxed),
            delivered_local: self.stats.delivered_local.load(Ordering::Relaxed),
            delivered_kernel: self.stats.delivered_kernel.load(Ordering::Relaxed),
            outbound_kernel: self.stats.outbound_kernel.load(Ordering::Relaxed),
            forwarded: self.stats.forwarded.load(Ordering::Relaxed),
            not_here: self.stats.not_here.load(Ordering::Relaxed),
            locate_redirected: self.stats.locate_redirected.load(Ordering::Relaxed),
            icmp_unreachable: self.stats.icmp_unreachable.load(Ordering::Relaxed),
            dropped: self.stats.dropped.load(Ordering::Relaxed),
        }
    }

    /// 挂载本机内核（服务器自身 peer 面）：`vip` = 本机 tun VIP；`sink` = tun 写泵
    /// （dst = 自身 VIP 的包注入内核）。装配层另起读泵消费 [`Self::route_outbound`]。
    pub fn set_local_peer(&self, vip: Ipv4Addr, sink: Arc<dyn PacketSink>) {
        *self.local_peer.lock().expect("fwd local peer") = Some((vip, sink));
    }

    /// 本机内核发出的包（ICMP 回程/本机协议栈流量）路由进 mesh：跳过第 0 步源绑定
    /// 校验（本机内核可信源 = 自身 VIP），按目标 VIP 走与 [`Self::ingest`] 相同的
    /// 判定序（本机会话投递 / ForwardEnvelope 跨服 / 一次性重定向 / 丢+ICMP——对端
    /// 设备不在本机时尽力语义，源为本机 ⇒ 无处送 ICMP，纯丢）。
    pub async fn route_outbound(&self, pkt: &[u8]) {
        self.stats.outbound_kernel.fetch_add(1, Ordering::Relaxed);
        // M7 计数点：服务器自身 tx（内核回程进 mesh——本机单点计）。
        self.leases
            .note_tx(&server_self_device_id(self.me), pkt.len() as u64);
        let Some(dst_vip) = ipv4_dst(pkt) else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        // dst = 自身 VIP：本机到本机（罕见；直接丢弃避免回环）。
        {
            let local = self.local_peer.lock().expect("fwd local peer").clone();
            if let Some((vip, _)) = local {
                if dst_vip == vip {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
        let dst_dev = match self.sm.device_by_vip(&dst_vip.octets()) {
            Some(d) => d,
            // 服务器段 VIP 回退映射（与 ingest 1b 同源；服务器间 mesh 流量——
            // §6.2 服务器段在设备表外）。
            None => match crate::proto::server_vip_node(&dst_vip.octets()) {
                Some(n) if n != self.me => server_self_device_id(n),
                _ => {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            },
        };
        // 源 = 本服务器 server-self 合成键（收端源绑定按 origin 的确定性 VIP 校验；
        // 失败路径 drop_with_icmp 找不到该键的会话 ⇒ 自然纯丢，内核出向尽力语义）。
        let src_dev = server_self_device_id(self.me);
        let _ = self.deliver_or_forward_fwd(&src_dev, dst_dev, pkt).await;
    }

    /// 设备注册 VIP（源绑定校验数据源 = NetState 强一致注册表）。
    pub fn vip_of(&self, device: &[u8; 32]) -> Option<Ipv4Addr> {
        self.sm.vip_of(device).map(Ipv4Addr::from)
    }

    /// **第 0 步：源 VIP 绑定校验**（会话设备 ↔ 包源地址；失配 ⇒ 丢 + 计数）。
    fn check_src_binding(&self, device: &[u8; 32], pkt: &[u8]) -> bool {
        let Some(expect) = self.vip_of(device) else {
            return false; // 无注册行（会话不应存在）⇒ 违例
        };
        match ipv4_src(pkt) {
            Some(src) => src == expect,
            None => false,
        }
    }

    /// 会话入向处理（§2.2 转发判定序 0→4）。`device` = 该会话的设备。
    pub async fn ingest(&self, device: &[u8; 32], pkt: &[u8]) -> IngestResult {
        // 0. 源 VIP 绑定校验——先于一切转发逻辑。
        if !self.check_src_binding(device, pkt) {
            self.stats.src_violations.fetch_add(1, Ordering::Relaxed);
            return IngestResult::SrcViolation;
        }
        // M7 计数点：src tx 在接入服务器（本机 = src 租约持有者）收进 mesh 时计一次
        //（绑定校验通过；dst 侧不重复计 src——单点原则，见模块文档）。
        self.leases.note_tx(device, pkt.len() as u64);
        // 1. 目标 VIP。
        let Some(dst_vip) = ipv4_dst(pkt) else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return IngestResult::Dropped;
        };
        // 1a. dst = 本服务器自身 VIP ⇒ 注入本机内核（服务器也是 peer，§2.2——A2/A4
        // 的 ping/iperf 本服路径）。
        {
            let local = self.local_peer.lock().expect("fwd local peer").clone();
            if let Some((vip, kernel)) = local {
                if dst_vip == vip {
                    if kernel.deliver(pkt).is_ok() {
                        self.stats.delivered_kernel.fetch_add(1, Ordering::Relaxed);
                        // M7 计数点：服务器自身 rx（本机 VIP 注内核成功——本机单点计）。
                        self.leases
                            .note_rx(&server_self_device_id(self.me), pkt.len() as u64);
                        return IngestResult::DeliveredLocal;
                    }
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return IngestResult::Dropped;
                }
            }
        }
        // 1b. 目标 VIP → 设备归属（设备注册表）。服务器段 VIP（§6.2 .1–.10）不在
        //     设备表——按确定性推导映射到对应服务器的 server-self 合成设备
        //     （§7-M8.2「任意服务器 VIP 可达」的跨服路径：ForwardEnvelope 到收端
        //     后投其内核，receive 侧）。本机服务器 VIP 已在 1a 兜住（local_peer
        //     未装配的窗口期按未注册目标处理——尽力 ICMP）。
        let dst_dev = match self.sm.device_by_vip(&dst_vip.octets()) {
            Some(dev) => dev,
            None => match crate::proto::server_vip_node(&dst_vip.octets()) {
                Some(n) if n != self.me => server_self_device_id(n),
                _ => return self.drop_with_icmp(device, pkt),
            },
        };
        self.deliver_or_forward_fwd(device, dst_dev, pkt).await
    }

    /// 判定序 2→4（本机投递 / 跨服 ForwardEnvelope / NOT_HERE→重定向 / 丢+ICMP）。
    /// 入向（ingest）与内核出向（route_outbound——src 无会话绑定，不送 ICMP）共用。
    async fn deliver_or_forward_fwd(
        &self,
        src_dev: &[u8; 32],
        dst_dev: [u8; 32],
        pkt: &[u8],
    ) -> IngestResult {
        // 2. 归属本机 ⇒ 直接投递。
        if let Some(sink) = self
            .sessions
            .lock()
            .expect("fwd sessions")
            .get(&dst_dev)
            .cloned()
        {
            if sink.deliver(pkt).is_ok() {
                self.stats.delivered_local.fetch_add(1, Ordering::Relaxed);
                // M7 计数点：dst rx（投递成功的服务器计——本机即 dst 持有者）。
                self.leases.note_rx(&dst_dev, pkt.len() as u64);
                return IngestResult::DeliveredLocal;
            }
        }
        // 3. 归属他机 ⇒ ForwardEnvelope（hop=1）跨服转发。
        match self.leases.observe(&dst_dev) {
            Some(lease) if lease.holder != self.me => {
                let env = ForwardEnvelope {
                    ver: FORWARD_VER,
                    src_dev: *src_dev,
                    dst_dev,
                    origin_server: self.me,
                    hop: 1,
                    payload: pkt.to_vec(),
                };
                let outcome = self.send_envelope(lease.holder, env).await;
                match outcome {
                    Ok(ForwardOutcome::Delivered) => {
                        self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                        IngestResult::Forwarded(ForwardOutcome::Delivered)
                    }
                    Ok(ForwardOutcome::NotHere) => {
                        // 4. 一次性 location_query 重定向；仍失败 ⇒ 丢 + ICMP。
                        self.stats.not_here.fetch_add(1, Ordering::Relaxed);
                        self.redirect_once(src_dev, dst_dev, pkt).await
                    }
                    Ok(ForwardOutcome::Rejected(_)) | Err(_) => {
                        self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        IngestResult::Dropped
                    }
                }
            }
            // 租约说本机但会话不在（刚断链）或无租约：一次性询问后丢。
            _ => {
                self.stats.not_here.fetch_add(1, Ordering::Relaxed);
                self.redirect_once(src_dev, dst_dev, pkt).await
            }
        }
    }

    /// NOT_HERE 容错：一次性位置询问（fan-out ≤3，不重试不缓存）→ 重定向一次。
    /// 注意：询问**只问对端**——本地租约正是刚失败的那个答案（陈旧即病因）。
    async fn redirect_once(
        &self,
        src_dev: &[u8; 32],
        dst_dev: [u8; 32],
        pkt: &[u8],
    ) -> IngestResult {
        let holder = {
            let fanout = self.fanout.lock().expect("fwd fanout").clone();
            match fanout {
                Some(f) => f.locate(&dst_dev).await,
                None => None,
            }
        };
        if let Some(holder) = holder.filter(|h| *h != self.me) {
            let env = ForwardEnvelope {
                ver: FORWARD_VER,
                src_dev: *src_dev,
                dst_dev,
                origin_server: self.me,
                hop: 1,
                payload: pkt.to_vec(),
            };
            if let Ok(ForwardOutcome::Delivered) = self.send_envelope(holder, env).await {
                self.stats.locate_redirected.fetch_add(1, Ordering::Relaxed);
                return IngestResult::Forwarded(ForwardOutcome::Delivered);
            }
        }
        self.drop_with_icmp(src_dev, pkt)
    }

    async fn send_envelope(
        &self,
        peer: NodeId,
        env: ForwardEnvelope,
    ) -> io::Result<ForwardOutcome> {
        let t = self.transport.lock().expect("fwd transport").clone();
        let Some(t) = t else {
            return Err(io::Error::other("forward transport not wired"));
        };
        t.send(peer, env).await
    }

    /// 丢包 + 尽力 ICMP unreachable（源设备在本机才送得出去；否则纯丢）。
    fn drop_with_icmp(&self, src_dev: &[u8; 32], pkt: &[u8]) -> IngestResult {
        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        let icmp = icmp_host_unreachable(pkt);
        let sink = self
            .sessions
            .lock()
            .expect("fwd sessions")
            .get(src_dev)
            .cloned();
        if let Some(sink) = sink {
            if sink.deliver(&icmp).is_ok() {
                self.stats.icmp_unreachable.fetch_add(1, Ordering::Relaxed);
                return IngestResult::DroppedIcmp;
            }
        }
        IngestResult::Dropped
    }

    /// **收端**：互连 FRWD 流收到 ForwardEnvelope。
    /// 校验序：ver → hop（防环：hop=0 的「二次转发」丢 + 计数）→ src_dev 交叉校验
    /// （收端各查一次）→ 本机投递 / NOT_HERE（禁止再转发）。
    pub fn receive(&self, env: ForwardEnvelope) -> ForwardOutcome {
        if env.ver != FORWARD_VER {
            self.stats.hop_dropped.fetch_add(1, Ordering::Relaxed);
            return ForwardOutcome::Rejected(RejectReason::Version);
        }
        if env.hop == 0 {
            // 防环：剩余跳数耗尽（构造出的二次转发）⇒ 丢 + 计数。
            self.stats.hop_dropped.fetch_add(1, Ordering::Relaxed);
            return ForwardOutcome::Rejected(RejectReason::Hop);
        }
        // 收端源绑定交叉校验：envelope.src_dev 的注册 VIP == 内层包源地址。
        // 例外面：src_dev = 发端服务器的 server-self 合成键（route_outbound 的
        // 服务器内核回程，非注册设备）⇒ 期望内层源 = 该服务器的确定性 VIP
        //（server_vip_of——服务器对自身内核流量背书，mesh 信任域内）。
        let ok = match self.vip_of(&env.src_dev) {
            Some(expect) => matches!(ipv4_src(&env.payload), Some(src) if src == expect),
            None if env.src_dev == server_self_device_id(env.origin_server) => {
                matches!(
                    (
                        crate::proto::server_vip_of(env.origin_server),
                        ipv4_src(&env.payload)
                    ),
                    (Some(expect), Some(src)) if Ipv4Addr::from(expect) == src
                )
            }
            None => false,
        };
        if !ok {
            self.stats
                .src_mismatch_rejected
                .fetch_add(1, Ordering::Relaxed);
            return ForwardOutcome::Rejected(RejectReason::SrcBinding);
        }
        // dst = 本服务器自身（server-self 合成设备无会话 sink）⇒ 注本机内核——
        // §7-M8.2「跨服则 ForwardEnvelope，收端投内核 fwd_delivered_kernel 路径」
        //（webui 于任意服务器 VIP 可达的跨服面；本机 VIP 未装配内核 ⇒ NOT_HERE）。
        if env.dst_dev == server_self_device_id(self.me) {
            let local = self.local_peer.lock().expect("fwd local peer").clone();
            if let Some((_, kernel)) = local {
                if kernel.deliver(&env.payload).is_ok() {
                    self.stats.delivered_kernel.fetch_add(1, Ordering::Relaxed);
                    // M7 计数点：跨服 dst rx 由收端（= dst 真实持有者）计——服务器
                    // 自身条目只在自身计（模块文档单点原则）。
                    self.leases.note_rx(&env.dst_dev, env.payload.len() as u64);
                    return ForwardOutcome::Delivered;
                }
            }
            return ForwardOutcome::NotHere;
        }
        // 本机投递或 NOT_HERE（hop 语义内禁止二次转发）。
        let sink = self
            .sessions
            .lock()
            .expect("fwd sessions")
            .get(&env.dst_dev)
            .cloned();
        match sink {
            Some(sink) if sink.deliver(&env.payload).is_ok() => {
                // M7 计数点：跨服 dst rx 由**收端**（= dst 的真实持有者）计——origin
                // 只计过 src tx，不双计（单点原则，模块文档）。
                self.leases.note_rx(&env.dst_dev, env.payload.len() as u64);
                ForwardOutcome::Delivered
            }
            _ => ForwardOutcome::NotHere,
        }
    }
}

// ============================================================================
// 最小 IPv4 解析与 ICMP unreachable 构造
// ============================================================================

/// 解析 IPv4 包源地址（20B 基本头；非 IPv4/截断 ⇒ None）。
pub fn ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    ipv4_header(pkt)?;
    (pkt.len() >= 20).then_some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

/// 解析 IPv4 包目标地址。
pub fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    ipv4_header(pkt)?;
    (pkt.len() >= 20).then_some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

fn ipv4_header(pkt: &[u8]) -> Option<usize> {
    if pkt.len() < 20 {
        return None;
    }
    let v = pkt[0] >> 4;
    if v != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    Some(ihl)
}

/// 构造 ICMPv4 host unreachable（type 3 / code 1）：RFC 792——原 IP 头 + 前 8 字节
/// 内嵌；发回原源（尽力：调用方投给源设备会话）。
pub fn icmp_host_unreachable(orig: &[u8]) -> Vec<u8> {
    let total_len = 20 + 8 + 28.min(orig.len());
    let mut pkt = vec![0u8; total_len];
    // IPv4 头：src = 原包 dst，dst = 原包 src（回给发送者）。
    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4] = 0x64; // id
    pkt[6] = 0x40; // DF
    pkt[8] = 64; // ttl
    pkt[9] = 0x01; // ICMP
    if orig.len() >= 20 {
        pkt[12..16].copy_from_slice(&orig[16..20]);
        pkt[16..20].copy_from_slice(&orig[12..16]);
    }
    let csum = ipv4_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    // ICMP：type=3 code=1 + unused 4B + 原包头 28B（IP 头 + 前 8B 载荷）。
    let icmp_off = 20;
    pkt[icmp_off] = 3;
    pkt[icmp_off + 1] = 1;
    let embedded = 28.min(orig.len());
    pkt[icmp_off + 8..icmp_off + 8 + embedded].copy_from_slice(&orig[..embedded]);
    let csum = icmp_checksum(&pkt[icmp_off..]);
    pkt[icmp_off + 2..icmp_off + 4].copy_from_slice(&csum.to_be_bytes());
    pkt
}

fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let chunks = bytes.as_chunks::<2>();
    for c in chunks.0 {
        sum = sum.wrapping_add(u16::from_be_bytes(*c) as u32);
    }
    if let Some(b) = chunks.1.first() {
        sum = sum.wrapping_add((*b as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn ipv4_checksum(hdr: &[u8]) -> u16 {
    ones_complement_sum(hdr)
}

fn icmp_checksum(body: &[u8]) -> u16 {
    ones_complement_sum(body)
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造最小 IPv4 包（20B 头 + payload）。
    fn ip4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 0x11; // UDP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..].copy_from_slice(payload);
        p
    }

    #[test]
    fn ipv4_parse() {
        let p = ip4(
            "100.64.0.2".parse().unwrap(),
            "100.64.0.3".parse().unwrap(),
            b"x",
        );
        assert_eq!(ipv4_src(&p).unwrap().to_string(), "100.64.0.2");
        assert_eq!(ipv4_dst(&p).unwrap().to_string(), "100.64.0.3");
        assert_eq!(ipv4_src(b"short"), None);
        let mut v6 = p.clone();
        v6[0] = 0x60;
        assert_eq!(ipv4_src(&v6), None, "非 IPv4 ⇒ 拒");
    }

    // —— M8b 跨服服务器 VIP 转发面测试具（§7-M8.2「任意服务器 VIP 可达」）——

    use crate::hooks::HookRegistry;
    use crate::lease::{GossipMsg, LeaseTable};
    use crate::sm::SmCore;
    use openraft::Entry;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    /// 捕获式 PacketSink（会话收件箱 / 内核注入泵共用）。
    struct CapSink(StdMutex<Vec<Vec<u8>>>);
    impl PacketSink for CapSink {
        fn deliver(&self, pkt: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().push(pkt.to_vec());
            Ok(())
        }
    }

    /// 捕获式互连（记录 (peer, envelope)，恒报 Delivered）。
    struct CapTransport(StdMutex<Vec<(NodeId, ForwardEnvelope)>>);
    impl ForwardTransport for CapTransport {
        fn send(
            &self,
            peer: NodeId,
            env: ForwardEnvelope,
        ) -> BoxFuture<'static, io::Result<ForwardOutcome>> {
            self.0.lock().unwrap().push((peer, env));
            Box::pin(async { Ok(ForwardOutcome::Delivered) })
        }
    }

    struct NoFanout;
    impl crate::lease::LocateFanout for NoFanout {
        fn locate(&self, _device: &[u8; 32]) -> BoxFuture<'static, Option<NodeId>> {
            Box::pin(async { None })
        }
    }

    fn entry_of(idx: u64, req: crate::proto::SyncRequest) -> Entry<crate::raft_types::SyncConfig> {
        Entry {
            log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), idx),
            payload: openraft::EntryPayload::Normal(req),
        }
    }

    /// node 1 上的转发面（含注册设备 dev=sha(ed25519=[1;32]) @ vip 100.64.0.11，
    /// 会话 sink 已挂）。
    async fn plane_with_device() -> (Arc<ForwardPlane>, [u8; 32], Arc<CapSink>, Arc<CapTransport>) {
        let dir = tempfile::tempdir().expect("tmp");
        let db = redb::Database::create(dir.path().join("fwd.redb")).expect("db");
        let sm = SmCore::empty(Arc::new(db), None);
        let root = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let dev: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest([1u8; 32]).into()
        };
        sm.apply_entries(&[
            entry_of(
                1,
                crate::proto::SyncRequest::bootstrap_signed(&root, [7; 16], [9; 32]),
            ),
            entry_of(
                2,
                crate::proto::SyncRequest::RegisterDevice {
                    owner: "u".into(),
                    x25519: [2; 32],
                    ed25519: [1; 32],
                    hostname: "t".into(),
                    registered_at_unix: 1,
                },
            ),
        ])
        .await;
        let leases = LeaseTable::new(1, Duration::from_secs(60), HookRegistry::new());
        let plane = ForwardPlane::new(1, sm, leases);
        let sess = Arc::new(CapSink(StdMutex::new(Vec::new())));
        plane.attach_session(dev, sess.clone());
        let t = Arc::new(CapTransport(StdMutex::new(Vec::new())));
        plane.set_transport(t.clone(), Arc::new(NoFanout));
        (plane, dev, sess, t)
    }

    /// ingest：dst = 远端服务器 VIP（100.64.0.2，非设备表行）⇒ 服务器段回退映射 →
    /// ForwardEnvelope(dst_dev=server_self(2)) 发往 node 2。
    #[tokio::test]
    async fn ingest_to_remote_server_vip_forwards_to_self_device() {
        let (plane, dev, _sess, t) = plane_with_device().await;
        // node 2 的 server-self 租约（gossip 视图）。
        plane.leases().merge_remote(GossipMsg::Publish {
            device: server_self_device_id(2),
            holder: 2,
            term_ms: 1,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 1,
        });
        let pkt = ip4(
            "100.64.0.11".parse().unwrap(),
            "100.64.0.2".parse().unwrap(),
            b"req",
        );
        let r = plane.ingest(&dev, &pkt).await;
        assert!(
            matches!(r, IngestResult::Forwarded(ForwardOutcome::Delivered)),
            "{r:?}"
        );
        let sent = t.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let (peer, env) = &sent[0];
        assert_eq!(*peer, 2, "发往 node 2（lease holder）");
        assert_eq!(env.dst_dev, server_self_device_id(2));
        assert_eq!(env.src_dev, dev);
        assert_eq!(env.origin_server, 1);
        assert_eq!(env.hop, 1, "hop=1（禁止二次转发）");
    }

    /// ingest：dst = 未注册的非服务器段 VIP ⇒ 丢 + 尽力 ICMP（回退映射不越界）。
    #[tokio::test]
    async fn ingest_to_unknown_device_vip_still_icmp() {
        let (plane, dev, sess, _t) = plane_with_device().await;
        let pkt = ip4(
            "100.64.0.11".parse().unwrap(),
            "100.64.0.99".parse().unwrap(),
            b"x",
        );
        let r = plane.ingest(&dev, &pkt).await;
        assert!(matches!(r, IngestResult::DroppedIcmp), "{r:?}");
        assert_eq!(sess.0.lock().unwrap().len(), 1, "尽力 ICMP 回源会话");
    }

    /// receive：dst_dev = 本服务器 server-self ⇒ 注本机内核（delivered_kernel）。
    #[tokio::test]
    async fn receive_for_server_self_delivers_to_kernel() {
        let (plane, dev, _sess, _t) = plane_with_device().await;
        let kern = Arc::new(CapSink(StdMutex::new(Vec::new())));
        plane.set_local_peer("100.64.0.1".parse().unwrap(), kern.clone());
        let pkt = ip4(
            "100.64.0.11".parse().unwrap(),
            "100.64.0.1".parse().unwrap(),
            b"req",
        );
        let env = ForwardEnvelope {
            ver: FORWARD_VER,
            src_dev: dev,
            dst_dev: server_self_device_id(1),
            origin_server: 2,
            hop: 1,
            payload: pkt,
        };
        assert!(matches!(plane.receive(env), ForwardOutcome::Delivered));
        assert_eq!(kern.0.lock().unwrap().len(), 1, "包入本机内核写泵");
        assert_eq!(plane.stats().delivered_kernel, 1);
    }

    /// receive：dst_dev = 本服务器 server-self 但源绑定失配（内层 src ≠ 注册 VIP）
    /// ⇒ Rejected（server-self 投内核不放松第 0 步校验）。
    #[tokio::test]
    async fn receive_for_server_self_bad_src_rejected() {
        let (plane, dev, _sess, _t) = plane_with_device().await;
        let kern = Arc::new(CapSink(StdMutex::new(Vec::new())));
        plane.set_local_peer("100.64.0.1".parse().unwrap(), kern.clone());
        let pkt = ip4(
            "100.64.0.12".parse().unwrap(), // ≠ dev 注册 VIP .11
            "100.64.0.1".parse().unwrap(),
            b"x",
        );
        let env = ForwardEnvelope {
            ver: FORWARD_VER,
            src_dev: dev,
            dst_dev: server_self_device_id(1),
            origin_server: 2,
            hop: 1,
            payload: pkt,
        };
        assert!(matches!(
            plane.receive(env),
            ForwardOutcome::Rejected(RejectReason::SrcBinding)
        ));
        assert!(kern.0.lock().unwrap().is_empty(), "未触内核");
    }

    /// route_outbound：本机内核 → 远端服务器 VIP（服务器间 mesh 流量面，回退映射）。
    #[tokio::test]
    async fn outbound_to_remote_server_vip_forwards() {
        let (plane, _dev, _sess, t) = plane_with_device().await;
        plane.leases().merge_remote(GossipMsg::Publish {
            device: server_self_device_id(2),
            holder: 2,
            term_ms: 1,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 1,
        });
        let pkt = ip4(
            "100.64.0.1".parse().unwrap(),
            "100.64.0.2".parse().unwrap(),
            b"srv",
        );
        plane.route_outbound(&pkt).await;
        let sent = t.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, 2);
        assert_eq!(sent[0].1.dst_dev, server_self_device_id(2));
        assert_eq!(
            sent[0].1.src_dev,
            server_self_device_id(1),
            "服务器内核回程的源 = 本机 server-self 合成键（收端可校验）"
        );
        assert_eq!(sent[0].1.origin_server, 1);
    }

    /// receive：src_dev = 发端服务器 server-self（内核回程面）、dst = 本机会话设备
    /// ⇒ 源绑定按 origin 的确定性 VIP 校验通过并投会话。
    #[tokio::test]
    async fn receive_from_remote_server_kernel_delivers_to_session() {
        let (plane, dev, sess, _t) = plane_with_device().await;
        let pkt = ip4(
            "100.64.0.2".parse().unwrap(), // node 2 的确定性服务器 VIP
            "100.64.0.11".parse().unwrap(),
            b"reply",
        );
        let env = ForwardEnvelope {
            ver: FORWARD_VER,
            src_dev: server_self_device_id(2),
            dst_dev: dev,
            origin_server: 2,
            hop: 1,
            payload: pkt,
        };
        assert!(matches!(plane.receive(env), ForwardOutcome::Delivered));
        assert_eq!(sess.0.lock().unwrap().len(), 1, "回程包入客户端会话");
    }

    /// receive：server-self 源但内层 src ≠ 该服务器确定性 VIP ⇒ Rejected（回程面
    /// 不放松源绑定）。
    #[tokio::test]
    async fn receive_from_server_kernel_bad_src_rejected() {
        let (plane, dev, _sess, _t) = plane_with_device().await;
        let pkt = ip4(
            "100.64.0.3".parse().unwrap(), // ≠ node 2 的 .2
            "100.64.0.11".parse().unwrap(),
            b"x",
        );
        let env = ForwardEnvelope {
            ver: FORWARD_VER,
            src_dev: server_self_device_id(2),
            dst_dev: dev,
            origin_server: 2,
            hop: 1,
            payload: pkt,
        };
        assert!(matches!(
            plane.receive(env),
            ForwardOutcome::Rejected(RejectReason::SrcBinding)
        ));
    }

    /// server_vip_of / server_vip_node 往返（段内/段外界点）。
    #[test]
    fn server_vip_roundtrip() {
        for n in 1u64..=10 {
            let v = crate::proto::server_vip_of(n).unwrap();
            assert_eq!(crate::proto::server_vip_node(&v), Some(n));
        }
        assert_eq!(crate::proto::server_vip_of(0), None);
        assert_eq!(crate::proto::server_vip_of(11), None);
        assert_eq!(
            crate::proto::server_vip_node(&[100, 64, 0, 11]),
            None,
            "设备段"
        );
        assert_eq!(crate::proto::server_vip_node(&[100, 64, 0, 0]), None);
        assert_eq!(
            crate::proto::server_vip_node(&[100, 64, 1, 2]),
            None,
            "段外第三字节"
        );
    }

    #[test]
    fn icmp_shape() {
        let orig = ip4(
            "100.64.0.2".parse().unwrap(),
            "100.64.0.9".parse().unwrap(),
            &[7u8; 32],
        );
        let icmp = icmp_host_unreachable(&orig);
        assert_eq!(icmp[20], 3, "type = destination unreachable");
        assert_eq!(icmp[21], 1, "code = host unreachable");
        // 内嵌原头 28B：IP 头 20 + 前 8B 载荷。
        assert_eq!(&icmp[28..48], &orig[..20]);
        assert_eq!(&icmp[48..56], &orig[20..28]);
        // 回给原源：ICMP 的 IP dst = 原源 .2。
        assert_eq!(icmp[16], 100);
        // 校验和非零（够格的「尽力」包）。
        assert!(icmp[22] != 0 || icmp[23] != 0);
    }
}
