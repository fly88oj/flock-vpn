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

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::lease::{LeaseTable, LocateFanout};
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
    fn send(&self, peer: NodeId, env: ForwardEnvelope) -> BoxFuture<'static, io::Result<ForwardOutcome>>;
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
    stats: ForwardStatsAtomic,
}

#[derive(Default)]
struct ForwardStatsAtomic {
    src_violations: AtomicU64,
    src_mismatch_rejected: AtomicU64,
    hop_dropped: AtomicU64,
    delivered_local: AtomicU64,
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

    /// 挂载/卸载本地设备会话（登录建立/断链拆除）。
    pub fn attach_session(&self, device: [u8; 32], sink: Arc<dyn PacketSink>) {
        self.sessions.lock().expect("fwd sessions").insert(device, sink);
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
            forwarded: self.stats.forwarded.load(Ordering::Relaxed),
            not_here: self.stats.not_here.load(Ordering::Relaxed),
            locate_redirected: self.stats.locate_redirected.load(Ordering::Relaxed),
            icmp_unreachable: self.stats.icmp_unreachable.load(Ordering::Relaxed),
            dropped: self.stats.dropped.load(Ordering::Relaxed),
        }
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
        // 1. 目标 VIP → 设备归属。
        let Some(dst_vip) = ipv4_dst(pkt) else {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return IngestResult::Dropped;
        };
        let Some(dst_dev) = self.sm.device_by_vip(&dst_vip.octets()) else {
            // 未注册目标：丢 + 尽力 ICMP。
            return self.drop_with_icmp(device, pkt);
        };
        // 2. 归属本机 ⇒ 直接投递。
        if let Some(sink) = self.sessions.lock().expect("fwd sessions").get(&dst_dev).cloned() {
            if sink.deliver(pkt).is_ok() {
                self.stats.delivered_local.fetch_add(1, Ordering::Relaxed);
                return IngestResult::DeliveredLocal;
            }
        }
        // 3. 归属他机 ⇒ ForwardEnvelope（hop=1）跨服转发。
        match self.leases.observe(&dst_dev) {
            Some(lease) if lease.holder != self.me => {
                let env = ForwardEnvelope {
                    ver: FORWARD_VER,
                    src_dev: *device,
                    dst_dev,
                    origin_server: self.me,
                    hop: 1,
                    payload: pkt.to_vec(),
                };
                let outcome = self.send_envelope(lease.holder, env).await;
                match outcome {
                    Ok(ForwardOutcome::Delivered) => {
                        self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                        return IngestResult::Forwarded(ForwardOutcome::Delivered);
                    }
                    Ok(ForwardOutcome::NotHere) => {
                        // 4. 一次性 location_query 重定向；仍失败 ⇒ 丢 + ICMP。
                        self.stats.not_here.fetch_add(1, Ordering::Relaxed);
                        return self.redirect_once(device, dst_dev, pkt).await;
                    }
                    Ok(ForwardOutcome::Rejected(_)) | Err(_) => {
                        self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        return IngestResult::Dropped;
                    }
                }
            }
            // 租约说本机但会话不在（刚断链）或无租约：一次性询问后丢。
            _ => {
                self.stats.not_here.fetch_add(1, Ordering::Relaxed);
                return self.redirect_once(device, dst_dev, pkt).await;
            }
        }
    }

    /// NOT_HERE 容错：一次性位置询问（fan-out ≤3，不重试不缓存）→ 重定向一次。
    /// 注意：询问**只问对端**——本地租约正是刚失败的那个答案（陈旧即病因）。
    async fn redirect_once(&self, src_dev: &[u8; 32], dst_dev: [u8; 32], pkt: &[u8]) -> IngestResult {
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

    async fn send_envelope(&self, peer: NodeId, env: ForwardEnvelope) -> io::Result<ForwardOutcome> {
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
        let sink = self.sessions.lock().expect("fwd sessions").get(src_dev).cloned();
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
        let ok = match self.vip_of(&env.src_dev) {
            Some(expect) => matches!(ipv4_src(&env.payload), Some(src) if src == expect),
            None => false,
        };
        if !ok {
            self.stats.src_mismatch_rejected.fetch_add(1, Ordering::Relaxed);
            return ForwardOutcome::Rejected(RejectReason::SrcBinding);
        }
        // 本机投递或 NOT_HERE（hop 语义内禁止二次转发）。
        let sink = self.sessions.lock().expect("fwd sessions").get(&env.dst_dev).cloned();
        match sink {
            Some(sink) if sink.deliver(&env.payload).is_ok() => ForwardOutcome::Delivered,
            _ => ForwardOutcome::NotHere,
        }
    }
}

// ============================================================================
// 最小 IPv4 解析与 ICMP unreachable 构造
// ============================================================================

/// 解析 IPv4 包源地址（20B 基本头；非 IPv4/截断 ⇒ None）。
pub fn ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    let h = ipv4_header(pkt)?;
    Some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
        .filter(|_| h >= 20)
}

/// 解析 IPv4 包目标地址。
pub fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    let h = ipv4_header(pkt)?;
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
        .filter(|_| h >= 20)
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
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([c[0], c[1]]) as u32);
    }
    if let Some(b) = chunks.remainder().first() {
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
        let p = ip4("100.64.0.2".parse().unwrap(), "100.64.0.3".parse().unwrap(), b"x");
        assert_eq!(ipv4_src(&p).unwrap().to_string(), "100.64.0.2");
        assert_eq!(ipv4_dst(&p).unwrap().to_string(), "100.64.0.3");
        assert_eq!(ipv4_src(b"short"), None);
        let mut v6 = p.clone();
        v6[0] = 0x60;
        assert_eq!(ipv4_src(&v6), None, "非 IPv4 ⇒ 拒");
    }

    #[test]
    fn icmp_shape() {
        let orig = ip4("100.64.0.2".parse().unwrap(), "100.64.0.9".parse().unwrap(), &[7u8; 32]);
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
