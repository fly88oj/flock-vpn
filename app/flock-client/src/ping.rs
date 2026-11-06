//! peers 延迟探测（M7 §7-M7.7）：对 online 且非自身的 VIP 并发 ICMP echo 探测。
//!
//! **选型（socket2 + 自研薄层，非成熟 ping crate）**：
//! - 探测路径必须「经 tun」——raw ICMP socket 发往 VIP 时由内核路由表决定出接口
//!   （`100.64.0.0/16 → tun0` 已由 route 装配），对端 VIP 的回包同理进 tun；用
//!   datagram ICMP（Linux `ping` 的 SOCK_DGRAM 档）不可控且 macOS/Windows 无此形态，
//!   raw 是三平台唯一一致档。
//! - daemon 是特权服务（Windows 服务/SYSTEM、Unix root），raw 权限天然在位
//!   （Windows raw ICMP 需管理员、Linux 需 CAP_NET_RAW、macOS 需 root）。
//! - 自研面 ~200 行且全部可控：ICMP echo 组包/校验和（三平台一致——Windows/macOS
//!   内核不代算 ICMP 校验和，统一自算；Linux 自算值同样正确）、回复按
//!   `(源地址, id, seq)` 匹配、超时明确；socket2（三平台同一 API 面，已在依赖树）
//!   建套接字后转 std UdpSocket 再入 tokio（与命名管道 IPC 同调度域）。
//! - 代价（如实声明）：Windows/macOS 真机实测列 `docs/manual/service-install.md`
//!   清单（容器 Linux 路径由 m7 实测覆盖；三平台编译面进门禁）。
//!
//! 探测参数（§7-M7.7）：每目标 3 探针、2s 超时/探针、**取中位**（偶数个成功值取
//! 上中位——保守侧：两值中取较大者），目标间并发。

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 单探针超时（§7-M7.7：2s/探针）。
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// 每目标探针数。
pub const PROBE_COUNT: u32 = 3;

/// 探针抽象（生产 raw ICMP；测试 mock 注入回环/超时/中位脚本）。
pub trait Pinger: Send + Sync {
    /// 一次 ICMP echo 往返（None = 超时/失败）。
    fn rtt(
        &self,
        target: Ipv4Addr,
        seq: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Option<Duration>> + Send + '_>>;
}

/// 每目标探测：3 探针（顺序——同目标探针彼此独立收敛）→ 成功值排序取中位
/// （偶数取上中位）→ `Some(ms)`；全超时 ⇒ None。
pub async fn probe_latency(p: &dyn Pinger, target: Ipv4Addr) -> Option<u32> {
    probe_latency_with(p, target, PROBE_COUNT, PROBE_TIMEOUT).await
}

/// [`probe_latency`] 的参数注入档（测试面）。
pub async fn probe_latency_with(
    p: &dyn Pinger,
    target: Ipv4Addr,
    probes: u32,
    timeout: Duration,
) -> Option<u32> {
    let mut got: Vec<u128> = Vec::new();
    for i in 0..probes {
        if let Some(d) = p.rtt(target, i as u16, timeout).await {
            got.push(d.as_millis());
        }
    }
    if got.is_empty() {
        return None;
    }
    got.sort_unstable();
    Some(got[got.len() / 2] as u32)
}

// ============================================================================
// raw ICMP 实现（socket2 → std UdpSocket → tokio；单套接字 + 回复分发任务）
// ============================================================================

/// 回复等待者表：`(源 VIP, seq) → 唤醒通道`。
type Waiters = Arc<Mutex<HashMap<(Ipv4Addr, u16), tokio::sync::oneshot::Sender<()>>>>;

/// raw ICMP 探测器（单套接字复用；id = 进程派生——同机多 daemon 不互扰）。
///
/// seq 由调用方给（[`probe_latency_with`] 以 `0..probes` 序）；评审项 8 删除了
/// 无人接线的 `next_seq` 全局序号。残余影响（如实声明）：同目标跨轮次（>5s 名册
/// 缓存过期后的两次探测）复用相同 seq 值，上一轮迟到的回包可唤醒本轮等待者——
/// 回复仍按 `(源, id, seq)` 匹配（不同目标隔离），且 3 探针取中位下单样本污染
/// 至多抬高/压低一个采样、中位稳定，不致误判在线性。
pub struct RawIcmpPinger {
    id: u16,
    socket: Arc<tokio::net::UdpSocket>,
    waiters: Waiters,
}

impl RawIcmpPinger {
    /// 建 raw ICMP 套接字（特权要求见模块文档；失败 ⇒ 调用方降级为「无延迟」档）。
    pub fn new() -> io::Result<Self> {
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        sock.set_nonblocking(true)?;
        // raw socket 句柄按 UdpSocket 语义走 send_to/recv_from（平台同构；Windows 侧
        // SOCK_RAW 的 sendto/recvfrom 语义一致）。
        let std_sock = std::net::UdpSocket::from(sock);
        let socket = Arc::new(tokio::net::UdpSocket::from_std(std_sock)?);
        let waiters: Waiters = Arc::new(Mutex::new(HashMap::new()));
        let id = (std::process::id() as u16) & 0x7fff | 0x8000;
        // 回复分发：单接收任务按 (源, id, seq) 唤醒等待者（id 进闭包——同进程同值）。
        let rx_socket = socket.clone();
        let rx_waiters = waiters.clone();
        let my_id = id;
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                match rx_socket.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        let SocketAddr::V4(v4) = addr else { continue };
                        let Some((id, seq)) = parse_echo_reply(&buf[..n]) else {
                            continue;
                        };
                        if id != my_id {
                            continue;
                        }
                        if let Some(tx) = rx_waiters
                            .lock()
                            .expect("ping waiters")
                            .remove(&(*v4.ip(), seq))
                        {
                            let _ = tx.send(());
                        }
                    }
                    Err(_) => return, // 套接字关闭（daemon 拆除）
                }
            }
        });
        Ok(RawIcmpPinger {
            id,
            socket,
            waiters,
        })
    }
}

impl Pinger for RawIcmpPinger {
    fn rtt(
        &self,
        target: Ipv4Addr,
        seq: u16,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Option<Duration>> + Send + '_>> {
        let socket = self.socket.clone();
        let waiters = self.waiters.clone();
        let id = self.id;
        Box::pin(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            waiters
                .lock()
                .expect("ping waiters")
                .insert((target, seq), tx);
            let t0 = std::time::Instant::now();
            let echo = build_echo(id, seq);
            let sent = match socket.send_to(&echo, SocketAddr::from((target, 0))).await {
                Ok(n) => n == echo.len(),
                Err(_) => false,
            };
            if !sent {
                waiters.lock().expect("ping waiters").remove(&(target, seq));
                return None;
            }
            tokio::select! {
                r = rx => match r {
                    Ok(()) => Some(t0.elapsed()),
                    Err(_) => None,
                },
                _ = tokio::time::sleep(timeout) => {
                    waiters.lock().expect("ping waiters").remove(&(target, seq));
                    None
                }
            }
        })
    }
}

/// ICMP echo request（type 8 + id + seq + 32B 模式载荷 + 校验和——三平台一致自算）。
fn build_echo(id: u16, seq: u16) -> [u8; 40] {
    let mut m = [0u8; 40];
    m[0] = 8; // Echo Request
    m[4..6].copy_from_slice(&id.to_be_bytes());
    m[6..8].copy_from_slice(&seq.to_be_bytes());
    for (i, b) in m[8..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let ck = icmp_checksum(&m);
    m[2..4].copy_from_slice(&ck.to_be_bytes());
    m
}

/// RFC 1071 校验和（16 位反码和的反码）。
fn icmp_checksum(msg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in msg.as_chunks::<2>().0 {
        sum += u16::from_be_bytes(*c) as u32;
    }
    if msg.len() % 2 == 1 {
        sum += (*msg.last().expect("len 奇数必有尾字节") as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 解析 ICMP echo reply（raw 接收面含 IP 头——三平台一致）→ (id, seq)。
fn parse_echo_reply(pkt: &[u8]) -> Option<(u16, u16)> {
    if pkt.len() < 28 {
        return None; // 20B IP + 8B ICMP 头下限
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let icmp = &pkt[ihl..];
    if icmp[0] != 0 {
        return None; // 仅 Echo Reply（0）；请求副本/错误报文不匹配
    }
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    Some((id, seq))
}

// ============================================================================
// 单元测试（mock 回环/超时/中位 + 解析/校验和纯函数 + 特权自门槛 raw 实测）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 脚本化 mock（按调用次序弹射结果——回环/超时/中位分支复用）。
    struct MockPinger {
        script: Mutex<std::collections::VecDeque<Option<Duration>>>,
    }

    impl MockPinger {
        fn new(script: &[Option<Duration>]) -> Self {
            MockPinger {
                script: Mutex::new(script.iter().copied().collect()),
            }
        }
    }

    impl Pinger for MockPinger {
        fn rtt(
            &self,
            _target: Ipv4Addr,
            _seq: u16,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = Option<Duration>> + Send + '_>> {
            let next = self.script.lock().unwrap().pop_front();
            Box::pin(async move { next.flatten() })
        }
    }

    /// 回环：全部成功 ⇒ 中位 = 成功值的中位数。
    #[tokio::test]
    async fn probe_median_of_three_successes() {
        let p = MockPinger::new(&[
            Some(Duration::from_millis(30)),
            Some(Duration::from_millis(10)),
            Some(Duration::from_millis(200)),
        ]);
        let got =
            probe_latency_with(&p, "100.64.0.2".parse().unwrap(), 3, Duration::from_secs(1)).await;
        assert_eq!(got, Some(30), "3 值中位 = 30ms");
    }

    /// 超时：全 None ⇒ None（离线/不可达列「—」的数据源）。
    #[tokio::test]
    async fn probe_all_timeout_is_none() {
        let p = MockPinger::new(&[None, None, None]);
        let got = probe_latency_with(
            &p,
            "100.64.0.3".parse().unwrap(),
            3,
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(got, None);
    }

    /// 部分成功：[10, 超时, 30] ⇒ 成功值 [10,30] 的上中位 = 30（偶数取大——保守侧）。
    #[tokio::test]
    async fn probe_partial_success_takes_upper_median() {
        let p = MockPinger::new(&[
            Some(Duration::from_millis(10)),
            None,
            Some(Duration::from_millis(30)),
        ]);
        let got =
            probe_latency_with(&p, "100.64.0.4".parse().unwrap(), 3, Duration::from_secs(1)).await;
        assert_eq!(got, Some(30), "偶数个成功值取上中位");
    }

    /// 校验和 + 解析纯函数：组包自校验（校验和字段覆盖下重算得 0）。
    #[test]
    fn echo_checksum_and_parse_roundtrip() {
        let echo = build_echo(0x1234, 7);
        assert_eq!(echo[0], 8);
        assert_eq!(u16::from_be_bytes([echo[4], echo[5]]), 0x1234);
        assert_eq!(u16::from_be_bytes([echo[6], echo[7]]), 7);
        // 回包（IP 头 20B + Echo Reply——type 改 0 后按协议重算校验和）解析。
        let mut pkt = [0u8; 60];
        pkt[0] = 0x45; // v4, IHL 5
        pkt[2..4].copy_from_slice(&60u16.to_be_bytes());
        pkt[20..60].copy_from_slice(&echo);
        pkt[20] = 0; // type = Echo Reply
        pkt[22..24].copy_from_slice(&[0, 0]); // 清零后重算
        let ck = icmp_checksum(&pkt[20..]);
        pkt[22..24].copy_from_slice(&ck.to_be_bytes());
        // 校验和自洽：对含校验和的整包重算 ⇒ 0（含 padding 与载荷）。
        assert_eq!(icmp_checksum(&pkt[20..]), 0, "校验和覆盖后重算为 0");
        assert_eq!(parse_echo_reply(&pkt), Some((0x1234, 7)));
        // 非 echo reply（如目的不可达 type 3）不匹配。
        pkt[20] = 3;
        assert_eq!(parse_echo_reply(&pkt), None);
        // 截断/坏版本拒。
        assert_eq!(parse_echo_reply(&pkt[..10]), None);
        let mut v6 = pkt;
        v6[0] = 0x60;
        assert_eq!(parse_echo_reply(&v6), None);
    }

    /// raw 实测（特权自门槛）：raw 套接字创建失败（非管理员/无 CAP_NET_RAW）⇒ 记录
    /// 跳过；创建成功 ⇒ loopback 三探针中位非 None（校验和/收发/匹配全链路真验证）。
    #[tokio::test]
    async fn raw_icmp_loopback_when_privileged() {
        let p = match RawIcmpPinger::new() {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("跳过：无 raw 套接字权限（容器内 root / 管理员会话跑全链路）");
                return;
            }
            Err(e) => panic!("raw 套接字创建意外失败: {e}"),
        };
        let got =
            probe_latency_with(&p, "127.0.0.1".parse().unwrap(), 3, Duration::from_secs(1)).await;
        assert!(got.is_some(), "loopback echo 应可达（特权形态）");
    }
}
