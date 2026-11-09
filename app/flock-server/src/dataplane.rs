//! 服务器侧数据面（docs/design.md §2.2/§3.11，M3「数据面打通」的服务端半边）。
//!
//! 服务端自身也是 peer：tun（VIP [`SERVER_VIP`] = 100.64.0.1，MTU 1280）+ 路由
//! （`100.64.0.0/16` 指向 tun + rp_filter=1，与客户端同一 [`route`] 适配器）。
//! 会话内分派：**首条 yamux 流 = 控制流**（M2 语义不变），余流按 [`PacketChannel`]
//! 进数据面。每条包通道：
//!
//! 1. **第 0 步源 VIP 绑定校验**（§2.2/R22）：包源地址必须等于该会话设备的注册 VIP；
//!    失配 ⇒ 丢包 + 计数（rp_filter 只作用于内核入向，用户态流必须应用层过滤）；
//! 2. 经 tun 写泵注入内核（dst = 服务器 VIP 的包由本机协议栈应答——A2 ping 路径）；
//! 3. 内核回程（tun 读泵）按目标 VIP 路由到对应会话的包通道（单服形态的租约表对应物；
//!    跨服 ForwardEnvelope 转发面属 M4 `flock-sync`，§2.2 第 3 步）。
//!
//! 无 tun 环境（宿主单测、无 NET_ADMIN 的部署）：[`PeerRouter::open`] 记日志并降级
//! 「控制流-only」——包通道优雅 FIN，客户端观察通道 EOF（M2 行为保持）。
//!
//! # 取消安全与会话登记（关键不变量）
//!
//! - 入站帧化同客户端契约（见 `flock_client::dataplane` 模块文档）：select! 内
//!   直接 await 帧化 recv 会丢帧——本侧以 `poll_fn` + 单次 `poll_read` + 持久
//!   [`FrameBuf`] 驱动；
//! - 同 VIP 重注册（设备重连，§2.4 漫游模型）：[`SessionIndex`] 以**代际**守卫——
//!   旧会话退出只注销自己的登记，不得删除新会话的（否则该设备下行黑洞）。

use std::net::Ipv4Addr;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use flock_client::dataplane::{FrameBuf, READ_CHUNK};
use flock_protocol::mux::{send_packet, PacketChannel, Stream};
use futures::io::AsyncRead as _;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
use flock_client::route::{self, RoutePlan};
use flock_client::tun::TunIo;
#[cfg(target_os = "linux")]
use flock_client::tun::TunSpec;

/// 服务器自身 VIP（§2.2「服务端自身也是 peer，VIP 100.64.0.1」；netstate 分配从 .2 起）。
pub const SERVER_VIP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);

/// M7：单服形态流量计里「服务器自身」条目的键（设备条目以 VIP 4B 为键）。
pub const SERVER_TRAFFIC_KEY: &[u8] = b"flock-server-self";

// 数据通道**不设**空闲超时（评审项 8 分层修正——M5 e2e 回归根因）。
//
// 会话层 PING/PONG 走记录层（整条连接），不产生 yamux 流帧：一条健康但无业务流量
// 的数据通道**必然**长期零帧。若在本层按「3×keepalive 无流帧」关闭通道，空闲客户端
// 每 30s 被拆一次数据通道，而客户端把数据通道 EOF 视为会话终止（connector::supervise
// 整链重连 + 端点轮换），引发「lease evicted (device moved)」风暴——e2e 实测 30 次
// idle-close / 35 次驱逐，钉死端点拓扑全毁（A2/A6/A7/A10/A11/A14 连锁 FAIL）。
//
// 死链检测的所有权在正确的层：记录层 3×keepalive 无入站记录 ⇒ DeadLink 拆整条会话
// （A9 语义，含 yamux 通道 FIN）；对端整机死机/NAT 过期由接受连接时设置的 TCP
// keepalive（评审项 8）让内核报错拆链；半开握手由 respond 外包握手预算拦截。通道
// 循环对这三条终止路径都经 EOF/错误自然退出，无需也不应再有第二把空闲刀。

/// 源 VIP 校验失配累计（断言/告警面；§2.2「丢包 + 计数」）。
pub fn src_vip_mismatches() -> u64 {
    SRC_MISMATCH.load(Ordering::Relaxed)
}

/// 因 per-session 源 VIP 失配达限被拆的会话通道数（评审项 10 的 admin stats 面）。
pub fn src_vip_mismatch_kills() -> u64 {
    SRC_MISMATCH_KILLS.load(Ordering::Relaxed)
}

static SRC_MISMATCH: AtomicU64 = AtomicU64::new(0);
static SRC_MISMATCH_KILLS: AtomicU64 = AtomicU64::new(0);

/// per-session 源 VIP 失配上限（评审项 10）：达限即拆该会话通道（客户端观察通道
/// EOF → 退避重连；持续伪造源的会话不再永久存活于「丢包+计数」的静默兜底）。
const SRC_MISMATCH_SESSION_LIMIT: u32 = 100;

/// 每会话源 VIP 失配计数器（serve_stream 内联使用；拆出便于上限语义单测）。
#[derive(Default)]
struct SrcMismatchCounter {
    count: u32,
}

impl SrcMismatchCounter {
    /// 记一次失配（全局计数同步累加）。返回 true ⇒ 达 [`SRC_MISMATCH_SESSION_LIMIT`]，
    /// 调用方应拆会话通道。
    fn on_mismatch(&mut self) -> bool {
        self.count += 1;
        SRC_MISMATCH.fetch_add(1, Ordering::Relaxed);
        if self.count >= SRC_MISMATCH_SESSION_LIMIT {
            SRC_MISMATCH_KILLS.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

/// IPv4 包源/目标地址（版本/IHL 校验后取 12..16 / 16..20）。非 IPv4/太短 ⇒ None。
fn ipv4_src_dst(pkt: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let src: [u8; 4] = pkt[12..16].try_into().ok()?;
    let dst: [u8; 4] = pkt[16..20].try_into().ok()?;
    Some((src, dst))
}

/// 目标 VIP → 会话出站通道索引（**代际守卫**）。
///
/// 同 VIP 重注册（设备断线重连）以 insert 覆盖旧通道——旧会话循环随其发送端被
/// drop 而退出，退出时只允许注销**自己那一代**（[`SessionIndex::unregister`] 带
/// 代次比对）：否则旧退出会把新会话的登记一并删除，该设备下行从此黑洞（直到
/// 客户端再一次重连）。
/// VIP →（出站通道，登记代次）。
type SessionMap = std::collections::HashMap<[u8; 4], (mpsc::Sender<Vec<u8>>, u64)>;

struct SessionIndex {
    map: Mutex<SessionMap>,
    next_gen: AtomicU64,
}

impl SessionIndex {
    fn new() -> Self {
        SessionIndex {
            map: Mutex::new(std::collections::HashMap::new()),
            next_gen: AtomicU64::new(0),
        }
    }

    /// 登记（同 VIP 覆盖旧通道），返回本代代次（注销凭证）。
    fn register(&self, vip: [u8; 4], tx: mpsc::Sender<Vec<u8>>) -> u64 {
        let gen = self.next_gen.fetch_add(1, Ordering::Relaxed) + 1;
        self.map
            .lock()
            .expect("router poisoned")
            .insert(vip, (tx, gen));
        gen
    }

    /// 当前登记的出站通道（内核回程路由用）。调用面 = Linux 编译面的
    /// `with_kernel_router_task` + 测试档（`outbound_sender`/SessionIndex 单测）——
    /// 非 Linux 的非测试编译面无调用方，cfg 到位即免 allow（dead_code 按平台面
    /// 独立分析，Windows 开发机看不到 Linux 调用点）。
    #[cfg(any(test, target_os = "linux"))]
    fn get(&self, vip: &[u8; 4]) -> Option<mpsc::Sender<Vec<u8>>> {
        self.map
            .lock()
            .expect("router poisoned")
            .get(vip)
            .map(|(tx, _)| tx.clone())
    }

    /// 注销**仅当**当前登记仍是 `gen` 这一代（同 VIP 已被新会话覆盖 ⇒ 不动新登记）。
    fn unregister(&self, vip: &[u8; 4], gen: u64) {
        let mut g = self.map.lock().expect("router poisoned");
        if g.get(vip).map(|(_, cur)| *cur == gen).unwrap_or(false) {
            g.remove(vip);
        }
    }
}

/// 单服数据面路由器（VIP → 会话包通道）。
pub struct PeerRouter {
    /// TUN 设备句柄（**存活持有**：接口与路由随句柄存续——不被读取即其全部用途，
    /// 纯 RAII 语义；Linux 真实装配路径写入 Some，非 Linux 降级路径恒 None，任何
    /// 平台的编译面都不存在读取点）。allow(dead_code) 须无条件覆盖全部平台：
    /// dead_code 恰在 Linux 编译面触发（有写入无读取），该 unix 编译面 Windows
    /// 开发机不可见。
    #[allow(dead_code)]
    tun: Option<Arc<TunIo>>,
    /// 目标 VIP → 该会话出站通道（内核回程 → 对端；代际守卫见 [`SessionIndex`]）。
    sessions: SessionIndex,
    /// 内核注入通道（tun 写泵；无 tun ⇒ None = 控制流-only 降级）。
    kernel_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// M7：per-VIP 流量计（EWMA/last_seen——名册单服形态数据源；计数点同 §7-M7.3
    /// 单点原则：入站（源校验通过）= 该设备 tx，出站下发 = 该设备 rx；dst = 服务器
    /// VIP 的入站 = 服务器 rx，内核回程路由 = 服务器 tx）。
    traffic: Mutex<Option<Arc<flock_sync::lease::TrafficMeter>>>,
    /// 本机服务器 VIP（M7：入站 dst 判服务器 rx 用；测试装配缺省 None）。
    server_vip: Option<Ipv4Addr>,
}

impl PeerRouter {
    /// 打开 tun + 路由并装配路由器；任一步失败记日志并降级控制流-only
    /// （M2 宿主测试/无 NET_ADMIN 部署路径）。async：路由配置走 rtnetlink/tokio。
    ///
    /// `vip` = 本机 tun VIP（单服缺省 [`SERVER_VIP`]；多主形态每台各配，§6.2）。
    ///
    /// 非 Linux 平台不装配真设备（Windows wintun 运行路径按 §7-M3 留待 M5 真机手工
    /// 验证——宿主 `cargo test` 不得触碰宿主驱动；macOS 未验证同 §7-M3）。
    pub async fn open(tun_name: &str, vip: Ipv4Addr) -> Arc<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun_name, vip);
            eprintln!(
                "flock-server: 数据面仅 Linux 装配（Windows 真机 M5 手工清单/macOS 未验证）——控制流-only 模式"
            );
            Self::none()
        }
        #[cfg(target_os = "linux")]
        {
            match open_tun_with_route(tun_name, vip).await {
                Ok(tun) => {
                    let sess = tun.session();
                    let kernel_tx = sess.tx.clone();
                    PeerRouter {
                        tun: Some(Arc::new(tun)),
                        sessions: SessionIndex::new(),
                        kernel_tx: Some(kernel_tx),
                        traffic: Mutex::new(None),
                        server_vip: Some(vip),
                    }
                    .with_kernel_router_task(sess, vip)
                }
                Err(()) => Arc::new(PeerRouter {
                    tun: None,
                    sessions: SessionIndex::new(),
                    kernel_tx: None,
                    traffic: Mutex::new(None),
                    server_vip: Some(vip),
                }),
            }
        }
    }

    /// 多主形态的 tun 装配（§2.2「服务端自身也是 peer」+ §6.2 M5 批次）：开 tun + 路由
    /// 后**不**起单服内核路由任务——会话面由 flock-sync 转发面承担
    /// （[`crate::sync::wire_local_peer`]：dst=自身 VIP 注入内核；内核回程读泵 →
    /// `SyncNode::route_outbound`）。
    ///
    /// 返回 `(tun 句柄, 会话)`；失败 ⇒ None（控制流-only 降级，同单服语义）。
    pub async fn open_tun_session(
        tun_name: &str,
        vip: Ipv4Addr,
    ) -> Option<(Arc<TunIo>, flock_client::tun::TunSession)> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun_name, vip);
            eprintln!("flock-server: 数据面仅 Linux 装配——多主形态控制流-only 模式");
            None
        }
        #[cfg(target_os = "linux")]
        {
            match open_tun_with_route(tun_name, vip).await {
                Ok(tun) => {
                    let sess = tun.session();
                    Some((Arc::new(tun), sess))
                }
                Err(()) => None,
            }
        }
    }

    /// M7：注入流量计（run() 装配期；serve_stream/内核路由任务据此计数）。
    pub fn set_traffic_meter(&self, meter: Arc<flock_sync::lease::TrafficMeter>) {
        *self.traffic.lock().expect("router traffic") = Some(meter);
    }

    fn traffic_of(&self) -> Option<Arc<flock_sync::lease::TrafficMeter>> {
        self.traffic.lock().expect("router traffic").clone()
    }

    /// 内核回程路由任务：tun 读泵产出 → 按目标 VIP 分发到会话出站通道
    /// （无对应会话 ⇒ 丢弃——M4 前不做 ICMP unreachable/跨服转发，§2.2 容错策略）。
    /// M7：内核回程 = 服务器自身 tx（计数点，§7-M7.3）。
    #[cfg(target_os = "linux")]
    fn with_kernel_router_task(
        self: PeerRouter,
        mut sess: flock_client::tun::TunSession,
        self_vip: Ipv4Addr,
    ) -> Arc<Self> {
        let arc = Arc::new(self);
        let router = arc.clone();
        tokio::spawn(async move {
            //（TunSession 整体移入：rx 供路由；tx 存续使写泵常驻——服务端数据面不拆。）
            while let Some(pkt) = sess.rx.recv().await {
                let Some((src, dst)) = ipv4_src_dst(&pkt) else {
                    continue;
                };
                if src == self_vip.octets() {
                    if let Some(m) = router.traffic_of() {
                        m.note_tx(SERVER_TRAFFIC_KEY, pkt.len() as u64);
                    }
                }
                if let Some(tx) = router.sessions.get(&dst) {
                    let _ = tx.send(pkt).await;
                }
            }
        });
        arc
    }

    /// 显式无数据面（测试装配）。
    pub fn none() -> Arc<Self> {
        Arc::new(PeerRouter {
            tun: None,
            sessions: SessionIndex::new(),
            kernel_tx: None,
            traffic: Mutex::new(None),
            server_vip: None,
        })
    }

    /// 测试装配：注入内核通道（无真 tun；宿主集成测试驱动 serve_stream 用）。
    #[cfg(test)]
    pub(crate) fn with_kernel_tx(kernel_tx: mpsc::Sender<Vec<u8>>) -> Arc<Self> {
        Arc::new(PeerRouter {
            tun: None,
            sessions: SessionIndex::new(),
            kernel_tx: Some(kernel_tx),
            traffic: Mutex::new(None),
            server_vip: None,
        })
    }

    /// 当前登记的出站通道（测试直驱用——非测试面内核回程走
    /// [`SessionIndex::get`]（with_kernel_router_task 内联），本方法无生产调用方，
    /// Linux 编译面曾以 cfg_attr allow 掩盖其 unused，实为纯测试档）。
    #[cfg(test)]
    fn outbound_sender(&self, vip: &[u8; 4]) -> Option<mpsc::Sender<Vec<u8>>> {
        self.sessions.get(vip)
    }

    /// 数据面是否在位（部署诊断/断言）。
    pub fn is_up(&self) -> bool {
        self.kernel_tx.is_some()
    }

    /// 会话包通道服务：登记出站通道（目标 VIP，代际守卫）+ 入站第 0 步源 VIP 校验
    /// + 内核注入 + 出站回程下发。
    ///
    /// 返回 = 通道结束（EOF/错误/内核通道拆/被新会话取代——同 VIP 重注册覆盖发送端
    /// ⇒ 本侧 out_rx 收 None）。
    ///
    /// 取消安全结构见模块文档（入站 poll_fn + 单次 poll_read + 持久 FrameBuf 帧化，
    /// 不用 select! 直接 await 帧化 recv；出站整帧写在分支体内完成）。
    pub async fn serve_stream(self: &Arc<Self>, vip: [u8; 4], stream: Stream) {
        let Some(kernel_tx) = self.kernel_tx.clone() else {
            // 无数据面降级：优雅 FIN（客户端观察通道 EOF，控制流不受影响）。
            let mut ch = PacketChannel::from_stream(stream);
            let _ = ch.finish().await;
            return;
        };
        let mut stream = stream;
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);
        let gen = self.sessions.register(vip, out_tx);
        let mut src_mismatch = SrcMismatchCounter::default();
        let mut frames = FrameBuf::new();
        let mut chunk = vec![0u8; READ_CHUNK];
        'tunnel: loop {
            // 已缓冲完整帧：第 0 步源 VIP 校验（§2.2）→ 内核注入 / 失配丢+计数。
            while let Some(pkt) = frames.take_frame() {
                match ipv4_src_dst(&pkt) {
                    Some((src, dst)) if src == vip => {
                        // M7 计数点（§7-M7.3 单点原则）：入站收进 mesh = 该设备 tx；
                        // dst = 服务器自身 VIP ⇒ 服务器 rx（本机单点计）。
                        if let Some(m) = self.traffic_of() {
                            m.note_tx(&vip, pkt.len() as u64);
                            if Some(dst) == self.server_vip.map(|v| v.octets()) {
                                m.note_rx(SERVER_TRAFFIC_KEY, pkt.len() as u64);
                            }
                        }
                        if kernel_tx.send(pkt).await.is_err() {
                            self.sessions.unregister(&vip, gen); // tun 写泵已拆
                            return;
                        }
                    }
                    // 失配/非 IPv4：丢包 + 计数（R22：不静默放行）。评审项 10：per-session
                    // 失配计数 ≥100 即拆该会话通道（持续源伪造不再仅靠计数告警兜底）。
                    _ => {
                        if src_mismatch.on_mismatch() {
                            eprintln!(
                                "flock-server: 源 VIP 失配 {} 次 ≥ {}——拆会话通道 vip={vip:?}",
                                src_mismatch.count, SRC_MISMATCH_SESSION_LIMIT
                            );
                            break 'tunnel;
                        }
                    }
                }
            }
            // 单步等待（无跨 poll 状态：out_rx.poll_recv + 单次 poll_read）。不设空闲
            // 超时——死链所有权在记录层 DeadLink/TCP keepalive（见 STREAM 注记块）；
            // 空闲但健康的通道（无业务流量）必须长存，否则空闲客户端被周期性拆链。
            let step = std::future::poll_fn(|cx| {
                match out_rx.poll_recv(cx) {
                    Poll::Ready(out) => return Poll::Ready(Step::Outbound(out)),
                    Poll::Pending => {}
                }
                match pin!(&mut stream).poll_read(cx, &mut chunk) {
                    Poll::Ready(Ok(0)) => Poll::Ready(Step::InEof),
                    Poll::Ready(Ok(n)) => Poll::Ready(Step::InBytes(n)),
                    Poll::Ready(Err(_)) => Poll::Ready(Step::InErr),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            match step {
                Step::Outbound(Some(pkt)) => {
                    // M7 计数点：出站下发成功前计数（投递面——写失败即通道拆，该包
                    // 未送达；EWMA 语义按「计入即发送」足够精确，失败路径罕见）。
                    if let Some(m) = self.traffic_of() {
                        m.note_rx(&vip, pkt.len() as u64);
                    }
                    if send_packet(&mut stream, &pkt).await.is_err() {
                        break; // 通道拆（客户端会话结束）
                    }
                }
                Step::Outbound(None) => break, // 被 newer 代覆盖（同 VIP 重注册）
                Step::InBytes(n) => frames.extend(&chunk[..n]),
                Step::InErr => break, // 通道 EOF/错误
                Step::InEof => {
                    if frames.has_partial() {
                        break; // 半帧截断违约，按通道错误收场
                    }
                    break; // 对端 FIN：通道自然结束
                }
            }
        }
        // 代际守卫注销：同 VIP 已被新会话覆盖时不删新登记（bug 修复点——此前无条件
        // remove 会把新会话的出站通道一并删除，该设备下行黑洞）。
        self.sessions.unregister(&vip, gen);
    }
}

/// poll_fn 单步产物（无跨 poll 状态）。
enum Step {
    Outbound(Option<Vec<u8>>),
    InBytes(usize),
    InErr,
    InEof,
}

/// Linux：开 tun + 配路由（`100.64.0.0/16 → tun + 本机 VIP + rp_filter=1`）。
/// 失败记日志并返回 Err（调用方降级控制流-only）。
#[cfg(target_os = "linux")]
async fn open_tun_with_route(tun_name: &str, vip: Ipv4Addr) -> Result<TunIo, ()> {
    let spec = TunSpec {
        name: tun_name.into(),
        mtu: flock_client::tun::MTU,
    };
    match TunIo::open(&spec) {
        Ok(tun) => {
            let ifname = tun.name().to_string();
            match route::apply(&RoutePlan::new(&ifname, vip)).await {
                Ok(()) => {
                    eprintln!(
                        "flock-server: dataplane up: tun {} vip {vip} route {}/{} + rp_filter=1",
                        tun.name(),
                        route::VIP_POOL.0,
                        route::VIP_POOL.1
                    );
                    Ok(tun)
                }
                Err(e) => {
                    eprintln!("flock-server: 路由配置失败（控制流-only 模式）: {e}");
                    Err(())
                }
            }
        }
        Err(e) => {
            eprintln!(
                "flock-server: tun 打开失败（控制流-only 模式；容器需 --cap-add NET_ADMIN --device /dev/net/tun）: {e}"
            );
            Err(())
        }
    }
}

// ============================================================================
// 多主转发面（feature `multi-primary`；§2.2 判定序 + §3.10 ForwardPlane）
// ============================================================================

/// 本地会话投递 sink：ForwardPlane 的本机投递 → 会话出站通道（写泵下发到对端）。
#[cfg(feature = "multi-primary")]
struct ChannelSink(mpsc::Sender<Vec<u8>>);

#[cfg(feature = "multi-primary")]
impl flock_sync::PacketSink for ChannelSink {
    fn deliver(&self, pkt: &[u8]) -> std::io::Result<()> {
        self.0.try_send(pkt.to_vec()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("session outbound full: {e}"),
            )
        })
    }
}

/// 多主形态的会话包通道服务（与 [`PeerRouter::serve_stream`] 同构的取消安全结构）。
///
/// - 入站：帧化读出 → [`flock_sync::SyncNode::ingest_packet`]（内部完成 §2.2 判定序：
///   **第 0 步源 VIP 绑定校验** → 租约定位 → 本机投递 / ForwardEnvelope 跨服转发 /
///   NOT_HERE → 一次性 location_query → 仍失败丢包+尽力 ICMP）；
/// - 出站：ForwardPlane 本机投递（sink → out_rx）→ 整帧下发；
/// - 生命周期：attach/detach_session（租约域登记）+ 代际语义由 ForwardPlane 的
///   sessions 表承担（同设备新流覆盖旧 sink）。
#[cfg(feature = "multi-primary")]
pub async fn serve_stream_sync(node: Arc<flock_sync::SyncNode>, device: [u8; 32], stream: Stream) {
    let mut stream = stream;
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);
    node.attach_session(device, Arc::new(ChannelSink(out_tx)));
    let mut frames = FrameBuf::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        // 已缓冲完整帧 → 转发面（判定序在 ForwardPlane::ingest 内）。
        while let Some(pkt) = frames.take_frame() {
            let _ = node.ingest_packet(&device, &pkt).await;
        }
        // 单步等待（无跨 poll 状态）。不设空闲超时——死链所有权在记录层 DeadLink/
        // TCP keepalive（见 STREAM 注记块）；空闲但健康的通道必须长存（同 serve_stream）。
        let step = std::future::poll_fn(|cx| {
            match out_rx.poll_recv(cx) {
                Poll::Ready(out) => return Poll::Ready(Step::Outbound(out)),
                Poll::Pending => {}
            }
            match pin!(&mut stream).poll_read(cx, &mut chunk) {
                Poll::Ready(Ok(0)) => Poll::Ready(Step::InEof),
                Poll::Ready(Ok(n)) => Poll::Ready(Step::InBytes(n)),
                Poll::Ready(Err(_)) => Poll::Ready(Step::InErr),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        match step {
            Step::Outbound(Some(pkt)) => {
                if send_packet(&mut stream, &pkt).await.is_err() {
                    break;
                }
            }
            Step::Outbound(None) => break,
            Step::InBytes(n) => frames.extend(&chunk[..n]),
            Step::InErr => break,
            Step::InEof => break,
        }
    }
    node.detach_session(&device);
}

// ============================================================================
// 单元测试（宿主：纯函数面；tun/路由真路径由 deploy/m3_assert.sh 容器实跑）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// SRC_MISMATCH/SRC_MISMATCH_KILLS 是进程级静态——触达它们的服务端 e2e 测试
    /// 间以此锁串行（否则并行测试互踩彼此的精确计数断言）。tokio Mutex（LazyLock
    /// 物化——new 非 const）：异步测试持锁跨 await 点（测试全程互斥；std Mutex
    /// 跨 await 持有属 clippy 禁形），同步单元测试经 try_lock/阻塞获取同锁串行。
    static MISMATCH_COUNTER_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    #[test]
    fn ipv4_src_dst_parses_and_rejects() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // IPv4, IHL 5
        pkt[12..16].copy_from_slice(&[100, 64, 0, 2]);
        pkt[16..20].copy_from_slice(&[100, 64, 0, 1]);
        let (src, dst) = ipv4_src_dst(&pkt).unwrap();
        assert_eq!(src, [100, 64, 0, 2]);
        assert_eq!(dst, [100, 64, 0, 1]);
        assert!(ipv4_src_dst(&pkt[..19]).is_none(), "太短 ⇒ None");
        pkt[0] = 0x65; // 版本 6
        assert!(ipv4_src_dst(&pkt).is_none(), "非 IPv4 ⇒ None");
    }

    #[test]
    fn none_router_reports_down() {
        // 降级路径标志位（FIN 语义的端到端行为由 m3 容器反向覆盖：有 tun ⇒ is_up）。
        let router = PeerRouter::none();
        assert!(!router.is_up());
    }

    /// 评审项 10：per-session 源 VIP 失配上限——前 99 次仅丢包+全局计数，第
    /// [`SRC_MISMATCH_SESSION_LIMIT`] 次返回拆链信号并累计 kills。
    #[test]
    fn src_mismatch_counter_kills_at_limit() {
        let _g = futures::executor::block_on(MISMATCH_COUNTER_LOCK.lock());
        let mism_before = src_vip_mismatches();
        let kills_before = src_vip_mismatch_kills();
        let mut c = SrcMismatchCounter::default();
        for i in 1..SRC_MISMATCH_SESSION_LIMIT {
            assert!(!c.on_mismatch(), "第 {i} 次不拆");
        }
        assert_eq!(src_vip_mismatch_kills(), kills_before, "未达限不计数拆链");
        assert!(
            c.on_mismatch(),
            "第 {} 次达限 ⇒ 拆",
            SRC_MISMATCH_SESSION_LIMIT
        );
        assert_eq!(
            src_vip_mismatches(),
            mism_before + SRC_MISMATCH_SESSION_LIMIT as u64,
            "全局失配计数逐次累加"
        );
        assert_eq!(src_vip_mismatch_kills(), kills_before + 1, "拆链计数 +1");
    }

    /// 回归（bug：serve_stream 退出无条件 remove）：同 VIP 重注册后，旧代会话退出
    /// 只注销自己——新登记必须存活（否则该设备下行黑洞到下一次重连）。
    #[test]
    fn session_index_old_generation_exit_keeps_new_registration() {
        let idx = SessionIndex::new();
        let vip = [100u8, 64, 0, 2];
        let (tx_a, rx_a) = mpsc::channel::<Vec<u8>>(4);
        let (tx_b, mut rx_b) = mpsc::channel::<Vec<u8>>(4);
        let gen_a = idx.register(vip, tx_a);
        let gen_b = idx.register(vip, tx_b); // 设备重连：覆盖 A 的发送端
        assert_ne!(gen_a, gen_b);
        assert_eq!(
            idx.map.lock().unwrap().len(),
            1,
            "同 VIP 单登记（新覆盖旧）"
        );
        // A 的发送端被覆盖 ⇒ drop ⇒ A 的 out_rx 将观察到 None（旧循环退出路径）。
        drop(rx_a); //（接收端随旧会话任务结束）
                    // 旧代注销：不得删除 B 的登记。
        idx.unregister(&vip, gen_a);
        assert!(idx.get(&vip).is_some(), "旧代退出不得删除新登记");
        // 新代通道可用。
        let cur = idx.get(&vip).expect("B 在册");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            cur.send(vec![1, 2, 3]).await.unwrap();
            assert_eq!(rx_b.recv().await.unwrap(), vec![1, 2, 3]);
        });
        // 新代注销后清空。
        idx.unregister(&vip, gen_b);
        assert!(idx.get(&vip).is_none());
        assert_eq!(idx.map.lock().unwrap().len(), 0);
    }

    /// serve_stream 端到端（宿主，真会话/记录层/复用器 + 注入内核通道）：
    /// ① 入站：合法 src VIP 包进内核、失配包丢+计数（§2.2 第 0 步）；
    /// ② 出站：内核回程 → 包通道下发；
    /// ③ 重注册竞态（回归 bug：退出无条件 remove）：同 VIP 新流接管后，旧流退出
    ///    不得删除新登记——新流下行必须照常（旧代码下该设备下行黑洞）。
    #[tokio::test]
    async fn serve_stream_inbound_check_outbound_and_reregistration_race() {
        let _g = MISMATCH_COUNTER_LOCK.lock().await;
        use flock_protocol::session::{
            respond, ClusterId, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, ServerId,
            ServerIdentity, TunnelConfig,
        };
        use flock_protocol::trust::ClusterDirectory;
        use std::time::Duration;

        // respond 侧材料 + 已注册设备（与客户端测试 harness 同构）。
        let root = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let identity = ServerIdentity::enroll(&root, ClusterId([7; 16]), ServerId([1; 16]), "t:1");
        let directory =
            ClusterDirectory::issue(&root, identity.cluster_id, 1, vec![identity.entry.clone()]);
        let device = DeviceStaticKeys::generate();
        let mut dir = InMemoryDirectory::new();
        dir.register(DeviceRecord {
            device_x25519: device.x25519_public(),
            device_ed25519: device.ed25519_public(),
        });
        let pin = flock_protocol::session::ServerPin {
            cluster_id: directory.cluster_id,
            cluster_root_pub: root.verifying_key(),
            entry: directory.servers[0].clone(),
        };

        let (a, b) = tokio::io::duplex(256 * 1024);
        let identity_srv = identity;
        let (stream_tx, mut stream_rx) = mpsc::channel::<Stream>(8);
        let srv = tokio::spawn(async move {
            let t = respond(b, &identity_srv, dir, TunnelConfig::default())
                .await
                .expect("respond");
            while let Some(s) = t.accept_stream().await {
                if stream_tx.send(s).await.is_err() {
                    break;
                }
            }
        });
        let tunnel = flock_protocol::session::initiate(a, &device, &pin, TunnelConfig::default())
            .await
            .expect("initiate");

        let (kernel_tx, mut kernel_rx) = mpsc::channel::<Vec<u8>>(64);
        let router = PeerRouter::with_kernel_tx(kernel_tx);
        let vip = [100u8, 64, 0, 2];

        let ip_pkt = |src: [u8; 4], tag: u8| -> Vec<u8> {
            let mut p = vec![0x45u8, 0, 0, tag];
            p.resize(20, 0);
            p[12..16].copy_from_slice(&src);
            p[16..20].copy_from_slice(&[100, 64, 0, 1]);
            p
        };
        let mism_before = src_vip_mismatches();

        // 控制占位 + 通道 1（惰性 SYN：首数据帧触发服务端 accept 产出流）。
        let _hold = tunnel
            .open_stream(flock_protocol::mux::Prio::Control)
            .await
            .unwrap();
        let mut ch1 = tunnel.open_packet_channel().await.unwrap();
        ch1.send(&ip_pkt(vip, 1)).await.unwrap();
        let s1 = tokio::time::timeout(Duration::from_secs(5), stream_rx.recv())
            .await
            .expect("stream1 materialize")
            .unwrap();
        let r1 = router.clone();
        let t1 = tokio::spawn(async move { r1.serve_stream(vip, s1).await });
        // ① 合法 src VIP ⇒ 进内核。
        let got = tokio::time::timeout(Duration::from_secs(5), kernel_rx.recv())
            .await
            .expect("kernel recv")
            .unwrap();
        assert_eq!(got, ip_pkt(vip, 1), "合法 src VIP 包注入内核");
        // ① 失配 src ⇒ 丢 + 计数（不进内核）。
        ch1.send(&ip_pkt([9, 9, 9, 9], 2)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(src_vip_mismatches(), mism_before + 1, "失配包丢+计数");
        assert!(kernel_rx.try_recv().is_err(), "失配包不进内核");
        // ② 出站：当前登记（代 1）下发。
        router
            .outbound_sender(&vip)
            .expect("登记存在")
            .send(ip_pkt(vip, 3))
            .await
            .unwrap();
        let down = tokio::time::timeout(Duration::from_secs(5), ch1.recv())
            .await
            .expect("ch1 下行")
            .unwrap();
        assert_eq!(down, ip_pkt(vip, 3));

        // ③ 同 VIP 重注册：通道 2 接管（覆盖代 1 发送端 ⇒ t1 退出并注销旧代）。
        let mut ch2 = tunnel.open_packet_channel().await.unwrap();
        ch2.send(&ip_pkt(vip, 4)).await.unwrap();
        let s2 = tokio::time::timeout(Duration::from_secs(5), stream_rx.recv())
            .await
            .expect("stream2 materialize")
            .unwrap();
        let r2 = router.clone();
        let t2 = tokio::spawn(async move { r2.serve_stream(vip, s2).await });
        let got = tokio::time::timeout(Duration::from_secs(5), kernel_rx.recv())
            .await
            .expect("kernel recv ch2")
            .unwrap();
        assert_eq!(got, ip_pkt(vip, 4), "新通道入站照常");
        // 等 t1 退出（其发送端被覆盖 → out_rx None → unregister(旧代)）。
        let _ = tokio::time::timeout(Duration::from_secs(5), t1).await;
        // 关键断言：新登记未被旧退出删除；新通道下行照常（旧代码在此黑洞）。
        let sender2 = router
            .outbound_sender(&vip)
            .expect("新登记存活（旧退出不得删除）");
        sender2.send(ip_pkt(vip, 5)).await.unwrap();
        let down2 = tokio::time::timeout(Duration::from_secs(5), ch2.recv())
            .await
            .expect("ch2 下行（重注册后不被黑洞）")
            .unwrap();
        assert_eq!(down2, ip_pkt(vip, 5));

        let _ = tokio::time::timeout(Duration::from_secs(3), t2).await;
        drop(srv);
    }

    /// 评审项 10：per-session 源 VIP 失配达限（100）⇒ 拆会话通道（客户端观察通道
    /// EOF）+ kills 计数递增——持续伪造源的会话不再永久存活于「丢包+计数」兜底。
    #[tokio::test]
    async fn serve_stream_killed_after_100_src_vip_mismatches() {
        let _g = MISMATCH_COUNTER_LOCK.lock().await;
        use flock_protocol::session::{
            respond, ClusterId, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, ServerId,
            ServerIdentity, TunnelConfig,
        };
        use flock_protocol::trust::ClusterDirectory;
        use std::time::Duration;

        let root = flock_protocol::ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let identity = ServerIdentity::enroll(&root, ClusterId([7; 16]), ServerId([1; 16]), "t:1");
        let directory =
            ClusterDirectory::issue(&root, identity.cluster_id, 1, vec![identity.entry.clone()]);
        let device = DeviceStaticKeys::generate();
        let mut dir = InMemoryDirectory::new();
        dir.register(DeviceRecord {
            device_x25519: device.x25519_public(),
            device_ed25519: device.ed25519_public(),
        });
        let pin = flock_protocol::session::ServerPin {
            cluster_id: directory.cluster_id,
            cluster_root_pub: root.verifying_key(),
            entry: directory.servers[0].clone(),
        };

        let (a, b) = tokio::io::duplex(256 * 1024);
        let (stream_tx, mut stream_rx) = mpsc::channel::<Stream>(8);
        let srv = tokio::spawn(async move {
            let t = respond(b, &identity, dir, TunnelConfig::default())
                .await
                .expect("respond");
            while let Some(s) = t.accept_stream().await {
                if stream_tx.send(s).await.is_err() {
                    break;
                }
            }
        });
        let tunnel = flock_protocol::session::initiate(a, &device, &pin, TunnelConfig::default())
            .await
            .expect("initiate");

        let (kernel_tx, _kernel_rx) = mpsc::channel::<Vec<u8>>(64);
        let router = PeerRouter::with_kernel_tx(kernel_tx);
        let vip = [100u8, 64, 0, 2];
        let kills_before = src_vip_mismatch_kills();

        // 控制占位 + 数据通道物化（惰性 SYN：首帧触发服务端 accept）。物化用**合法**
        // src VIP 包（不进失配计数）。
        let _hold = tunnel
            .open_stream(flock_protocol::mux::Prio::Control)
            .await
            .unwrap();
        let mut ch = tunnel.open_packet_channel().await.unwrap();
        let ip_pkt = |src: [u8; 4], tag: u8| -> Vec<u8> {
            let mut p = vec![0x45u8, 0, 0, tag];
            p.resize(20, 0);
            p[12..16].copy_from_slice(&src);
            p[16..20].copy_from_slice(&[100, 64, 0, 1]);
            p
        };
        ch.send(&ip_pkt(vip, 1)).await.unwrap();
        let s = tokio::time::timeout(Duration::from_secs(5), stream_rx.recv())
            .await
            .expect("stream materialize")
            .unwrap();
        let r = router.clone();
        let task = tokio::spawn(async move { r.serve_stream(vip, s).await });

        // 连发 100 个失配包：第 100 个达限 ⇒ 服务端拆通道（客户端 recv 观察 EOF/错误；
        // 拆链后残余 send 报 WriteZero 即停止发送——拆链本身即是目标）。
        let bad = ip_pkt([9, 9, 9, 9], 2);
        for _ in 0..SRC_MISMATCH_SESSION_LIMIT {
            if ch.send(&bad).await.is_err() {
                break; // 通道已被服务端拆除（早于发满 100 个——计数在服务端侧已先行）
            }
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let closed = tokio::time::timeout_at(deadline.into(), async {
            loop {
                if ch.recv().await.is_err() {
                    break true; // 通道关闭（EOF/错误）= 服务端拆链的客户端观察
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(closed, "失配达限后客户端通道必须观察到关闭");
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert_eq!(src_vip_mismatch_kills(), kills_before + 1, "拆链计数 +1");
        drop(srv);
    }
}
