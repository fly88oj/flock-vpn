//! 数据面（docs/design.md §2.3 / §3.12）：IP 包 ↔ [`PacketChannel`]。
//!
//! 客户端侧桥：TUN 读泵产出的包 → 上行帧；下行帧 → TUN 写泵。任一侧错误/EOF ⇒
//! 返回（会话结束，接入器退避重连，[`supervise`]）。
//!
//! # 取消安全结构（关键不变量）
//!
//! 包通道帧化（`[u16 len][pkt]`）是**两次 read_exact**——绝不可作为 select! 的臂
//! future：对臂胜出时半途 future 被丢弃，已消费的帧头/帧体字节随之丢失，下行帧流
//! 永久失步（垃圾包写入 tun；回归测试
//! `bridge_survives_split_downstream_frames_with_interleaved_upstream` 的红形态）。
//! 因此读侧不用 select：`futures::poll_fn` 内做**单次** `poll_read`（裸读无跨 poll
//! 状态——让位零损失）+ 持久接收缓冲完成帧化；流只在 poll_fn 的一次 poll 期间被
//! 借用，上行写（整帧 [`send_packet`] 至完成）在 poll_fn 返回后另行借用。

use std::io;
use std::pin::pin;
use std::task::Poll;

use flock_protocol::mux::{send_packet, PacketChannel};
use futures::io::AsyncRead as _;

use crate::tun::TunSession;

/// 读块大小（≤ 单帧上限；帧在持久缓冲内重组，读块无需整帧）。
///
/// pub：服务器侧 dataplane（`flock-server`，§2.2「服务端自身也是 peer」）共用
/// 同一取消安全帧化形态。
pub const READ_CHUNK: usize = 4096;

/// 下行帧化缓冲：`[u16 len][pkt]` 持续累积，能取整帧即取（取消安全的帧化半途
/// 状态容器——字节一旦入缓冲不再丢失）。
pub struct FrameBuf {
    buf: Vec<u8>,
}

impl Default for FrameBuf {
    fn default() -> Self {
        FrameBuf::new()
    }
}

impl FrameBuf {
    pub fn new() -> Self {
        FrameBuf {
            buf: Vec::with_capacity(2048),
        }
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// 取出一个完整帧（不足整帧 ⇒ None）。
    pub fn take_frame(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 2 {
            return None;
        }
        let len = u16::from_le_bytes([self.buf[0], self.buf[1]]) as usize;
        if self.buf.len() < 2 + len {
            return None;
        }
        let pkt = self.buf.drain(..2 + len).as_slice()[2..].to_vec();
        Some(pkt)
    }

    pub fn has_partial(&self) -> bool {
        !self.buf.is_empty()
    }
}

/// poll_fn 单步产物（两路 poll 均无跨 poll 状态）。
enum Step {
    Upstream(Option<Vec<u8>>),
    DownBytes(usize),
    DownErr(io::Error),
    DownEof,
}

/// 桥接循环：tun ↔ packet channel（首个错误即返回；取消安全结构见模块文档）。
pub async fn bridge(sess: &mut TunSession, ch: PacketChannel) -> io::Result<()> {
    let mut stream = ch.into_stream();
    let mut frames = FrameBuf::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        // 已缓冲的完整帧全部落地（EOF 判定前排空，保「FIN 且无残包」语义）。
        while let Some(pkt) = frames.take_frame() {
            if sess.tx.send(pkt).await.is_err() {
                return Err(io::Error::other("tun: 写泵已退出"));
            }
        }
        // 单步等待：上行包到 / 下行字节到 / 下行读错。本 poll_fn future 即便被上层
        // 让位也不丢字节（无跨 poll 状态；`poll_recv` 与单次 `poll_read` 均安全）。
        let step = std::future::poll_fn(|cx| {
            match sess.rx.poll_recv(cx) {
                Poll::Ready(up) => return Poll::Ready(Step::Upstream(up)),
                Poll::Pending => {}
            }
            match pin!(&mut stream).poll_read(cx, &mut chunk) {
                Poll::Ready(Ok(0)) => Poll::Ready(Step::DownEof),
                Poll::Ready(Ok(n)) => Poll::Ready(Step::DownBytes(n)),
                Poll::Ready(Err(e)) => Poll::Ready(Step::DownErr(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        match step {
            Step::Upstream(Some(pkt)) => send_packet(&mut stream, &pkt).await?,
            Step::Upstream(None) => return Err(io::Error::other("tun: 读泵已退出")),
            Step::DownBytes(n) => frames.extend(&chunk[..n]),
            Step::DownErr(e) => return Err(e),
            Step::DownEof => {
                // 对端 FIN：仅当无残包才算通道自然结束（残包 = 半帧截断违约）。
                if frames.has_partial() {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                return Err(io::Error::other("packet: 对端 FIN（通道结束）"));
            }
        }
    }
}
// ============================================================================
// 集成测试（宿主可跑：mock tun + TCP/duplex 上的真握手/记录层/复用器）
// ============================================================================

/// 测试对端工具（connector 守护循环测试共用）。
#[cfg(test)]
pub(crate) mod testutil {
    use std::sync::Arc;

    use flock_protocol::ed25519_dalek::SigningKey;
    use flock_protocol::session::{
        respond, ClusterId, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, ServerId,
        ServerIdentity, TunnelConfig,
    };
    use flock_protocol::trust::ClusterDirectory;
    use flock_protocol::{mux::PacketChannel, rand};

    /// respond 侧真材料 + 设备注册表 + 每流回显 + 会话级 kill 开关。
    /// `chunked = true`：每个回显帧拆成「帧头 → 250ms 间隔 → 帧体」两段下发——
    /// 构造下游帧半途状态，逼出 select 循环内 PacketChannel::recv 的取消不安全
    /// （半途 future 被丢弃 ⇒ 已消费字节丢失、帧流失步）。
    pub(crate) struct EchoPeer {
        pub identity: ServerIdentity,
        pub directory: ClusterDirectory,
        pub root: SigningKey,
        pub chunked: bool,
        devices: std::sync::Mutex<InMemoryDirectory>,
        conns: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    }

    impl EchoPeer {
        pub(crate) fn new(endpoint: &str) -> Self {
            Self::with_mode(endpoint, false)
        }

        pub(crate) fn with_mode(endpoint: &str, chunked: bool) -> Self {
            let root = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
            let identity =
                ServerIdentity::enroll(&root, ClusterId([7; 16]), ServerId([1; 16]), endpoint);
            let directory = ClusterDirectory::issue(
                &root,
                identity.cluster_id,
                1,
                vec![identity.entry.clone()],
            );
            EchoPeer {
                identity,
                directory,
                root,
                chunked,
                devices: std::sync::Mutex::new(InMemoryDirectory::new()),
                conns: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// 设备入注册表（Active）。
        pub(crate) fn register(&self, device: &DeviceStaticKeys) {
            self.devices.lock().unwrap().register(DeviceRecord {
                device_x25519: device.x25519_public(),
                device_ed25519: device.ed25519_public(),
            });
        }

        /// accept 循环：每入连 respond → 每条流按 PacketChannel 回显
        /// （客户端首流为控制流占位：无字节 ⇒ 回显任务静默等待，行为等价）。
        pub(crate) async fn serve(self: Arc<Self>, listener: tokio::net::TcpListener) {
            loop {
                let Ok((io, _)) = listener.accept().await else {
                    return;
                };
                let conn_peer = self.clone();
                let h =
                    tokio::spawn(async move {
                        let dir = conn_peer.devices.lock().unwrap().clone();
                        let tunnel =
                            match respond(io, &conn_peer.identity, dir, TunnelConfig::default())
                                .await
                            {
                                Ok(t) => t,
                                Err(_) => return,
                            };
                        while let Some(stream) = tunnel.accept_stream().await {
                            let chunked = conn_peer.chunked;
                            let mut ch = PacketChannel::from_stream(stream);
                            tokio::spawn(async move {
                                while let Ok(pkt) = ch.recv().await {
                                    if chunked {
                                        // 拆帧回显：先发帧头，250ms 后发帧体。
                                        let mut s = ch.into_stream();
                                        if s.write_all(&(pkt.len() as u16).to_le_bytes())
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                        tokio::time::sleep(std::time::Duration::from_millis(250))
                                            .await;
                                        if s.write_all(&pkt).await.is_err() {
                                            break;
                                        }
                                        ch = PacketChannel::from_stream(s);
                                    } else if ch.send(&pkt).await.is_err() {
                                        break;
                                    }
                                }
                            });
                        }
                    });
                self.conns.lock().unwrap().push(h);
            }
        }

        /// 杀死全部已建立会话（模拟服务器侧拆链；监听继续 ⇒ 客户端应可重连）。
        pub(crate) fn kill_sessions(&self) {
            let mut g = self.conns.lock().unwrap();
            for h in g.iter() {
                h.abort();
            }
            g.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use flock_protocol::session::{
        respond, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, TunnelConfig,
    };

    use super::testutil::EchoPeer;
    use super::*;
    use crate::tun::{MockTunDevice, TunDevice as _, TunIo, TunSpec};

    /// 端到端：mock tun 包 → 客户端隧道（TCP 真路径）→ 对端回显 → 回到 mock 写侧。
    #[tokio::test]
    async fn bridge_carries_packets_both_directions_over_real_session() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = listener.local_addr().unwrap().to_string();
        let peer = Arc::new(EchoPeer::new(&ep));
        let peer_dir = peer.clone();
        tokio::spawn(async move { peer_dir.serve(listener).await });

        let device = DeviceStaticKeys::generate();
        peer.register(&device);
        let pin = flock_protocol::session::ServerPin {
            cluster_id: peer.directory.cluster_id,
            cluster_root_pub: peer.root.verifying_key(),
            entry: peer.directory.servers[0].clone(),
        };

        // 隧道 + 首流控制占位 + 包通道（与 supervise 的排序契约一致）。
        let io = tokio::net::TcpStream::connect(&ep).await.unwrap();
        let tunnel = flock_protocol::session::initiate(io, &device, &pin, TunnelConfig::default())
            .await
            .expect("1-RTT initiate");
        let _control_hold = tunnel
            .open_stream(flock_protocol::mux::Prio::Control)
            .await
            .unwrap();
        let ch = tunnel.open_packet_channel().await.unwrap();

        // mock tun + 桥任务。
        let mock = Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = TunIo::from_arc(mock.clone());
        let mut sess = tun.session();
        let bridged = tokio::spawn(async move { bridge(&mut sess, ch).await });

        // 内核 → 隧道 → 回显 → 写侧。
        mock.inject(b"\x45\x00\x00\x14echo-me");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            mock.written(),
            vec![b"\x45\x00\x00\x14echo-me".to_vec()],
            "包经隧道往返（mock 写侧收到回显）"
        );

        // 批量（帧化保边界：100 包逐包回显，不粘连；首包 echo 已在写侧——base 计入）。
        let base = mock.written().len();
        for i in 0..100u16 {
            let mut pkt = vec![0x45u8, (i >> 8) as u8, i as u8];
            pkt.extend_from_slice(&i.to_le_bytes());
            mock.inject(&pkt);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while mock.written().len() < base + 100 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(mock.written().len(), base + 100, "100 包全回显");
        assert_eq!(mock.written()[base + 99], {
            let mut pkt = vec![0x45u8, 0, 99];
            pkt.extend_from_slice(&99u16.to_le_bytes());
            pkt
        });

        // 会话拆 ⇒ bridge 返回（通道 EOF）。
        tunnel.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(3), bridged).await;
        tun.shutdown();
    }

    /// 回归（取消安全）：对端把每个回显帧拆成「帧头 → 250ms → 帧体」，并在间隔期
    /// 持续注入上行包——若 bridge 在 select! 内直接 await PacketChannel::recv（帧化
    /// = 两次 read_exact），上行臂胜出会丢弃半途 future：已消费的帧头/帧体字节丢失，
    /// 下行帧流永久失步（垃圾包/丢包写入 tun）。专职读任务形态下必须逐字节完整往返。
    #[tokio::test]
    async fn bridge_survives_split_downstream_frames_with_interleaved_upstream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ep = listener.local_addr().unwrap().to_string();
        let peer = Arc::new(EchoPeer::with_mode(&ep, true));
        let peer_serve = peer.clone();
        tokio::spawn(async move { peer_serve.serve(listener).await });

        let device = DeviceStaticKeys::generate();
        peer.register(&device);
        let pin = flock_protocol::session::ServerPin {
            cluster_id: peer.directory.cluster_id,
            cluster_root_pub: peer.root.verifying_key(),
            entry: peer.directory.servers[0].clone(),
        };
        let io = tokio::net::TcpStream::connect(&ep).await.unwrap();
        let tunnel = flock_protocol::session::initiate(io, &device, &pin, TunnelConfig::default())
            .await
            .expect("1-RTT initiate");
        let _control_hold = tunnel
            .open_stream(flock_protocol::mux::Prio::Control)
            .await
            .unwrap();
        let ch = tunnel.open_packet_channel().await.unwrap();

        let mock = Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = TunIo::from_arc(mock.clone());
        let mut sess = tun.session();
        let bridged = tokio::spawn(async move { bridge(&mut sess, ch).await });

        // 载荷可辨识（序号在字节 3），断言逐字节完整且顺序不乱。
        let pkt_i = |i: u8| -> Vec<u8> {
            let mut v = vec![0x45u8, 0x00, 0x14, i];
            v.extend_from_slice(&[0xA5; 12]);
            v
        };
        // 注入序列：偶数步在对端拆帧窗口内（帧头已到、帧体未到）追加注入下一包，
        // 在半途帧上制造 select 臂切换压力（正是取消不安全缺陷的触发形态）。
        let mut expected: Vec<Vec<u8>> = Vec::new();
        let mut i = 0u8;
        while (i as usize) < 10 {
            mock.inject(&pkt_i(i));
            expected.push(pkt_i(i));
            if i.is_multiple_of(2) && (i as usize) + 1 < 10 {
                tokio::time::sleep(Duration::from_millis(120)).await;
                mock.inject(&pkt_i(i + 1));
                expected.push(pkt_i(i + 1));
                i += 2;
            } else {
                i += 1;
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while mock.written().len() < expected.len() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let got = mock.written();
        assert_eq!(
            got.len(),
            expected.len(),
            "全部回显（无丢失/无重复）：{got:?}"
        );
        assert_eq!(got, expected, "逐包逐字节完整且有序（下行帧流无失步）");

        tunnel.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(3), bridged).await;
        tun.shutdown();
    }

    /// duplex 冒烟：记录层/复用器最小路径（跳过 TCP）。
    #[tokio::test]
    async fn session_duplex_smoke() {
        let peer = EchoPeer::new("127.0.0.1:9443");
        let device = DeviceStaticKeys::generate();
        peer.register(&device);
        let pin = flock_protocol::session::ServerPin {
            cluster_id: peer.directory.cluster_id,
            cluster_root_pub: peer.root.verifying_key(),
            entry: peer.directory.servers[0].clone(),
        };
        let (a, b) = tokio::io::duplex(64 * 1024);
        let identity = peer.identity;
        let device_srv = DeviceStaticKeys::from_bytes(&device.to_bytes());
        let server_side = tokio::spawn(async move {
            let mut registered = InMemoryDirectory::new();
            registered.register(DeviceRecord {
                device_x25519: device_srv.x25519_public(),
                device_ed25519: device_srv.ed25519_public(),
            });
            let t = match respond(b, &identity, registered, TunnelConfig::default()).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[duplex-smoke] respond failed: {e}");
                    return;
                }
            };
            // 注：yamux SYN 惰性（首帧携带）——控制流占位无数据 ⇒ 首个被接受的流
            // 即包通道（与 M1 session_mux 的 PacketChannel 测试同语义）。
            let Some(s) = t.accept_stream().await else {
                return;
            };
            let mut ch = PacketChannel::from_stream(s);
            while let Ok(p) = ch.recv().await {
                if ch.send(&p).await.is_err() {
                    break;
                }
            }
        });
        let tunnel = tokio::time::timeout(
            Duration::from_secs(5),
            flock_protocol::session::initiate(a, &device, &pin, TunnelConfig::default()),
        )
        .await;
        let tunnel = match tunnel {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => panic!("duplex 上 1-RTT 握手失败: {e}"),
            Err(_) => panic!("duplex initiate 5s 超时"),
        };
        let _hold = t_open_hold(&tunnel).await;
        let mut ch = tunnel.open_packet_channel().await.unwrap();
        ch.send(b"\x45\x00\x00\x03abc").await.unwrap();
        let back = tokio::time::timeout(Duration::from_secs(3), ch.recv())
            .await
            .expect("回显超时")
            .unwrap();
        assert_eq!(back, b"\x45\x00\x00\x03abc");
        // 控制流占位被客户端持有 ⇒ 服务端回显循环不结束——有界等待后收尾。
        let _ = tokio::time::timeout(Duration::from_secs(2), server_side).await;
    }

    /// 控制流占位打开（首流排序契约；返回持有句柄防止过早 Drop）。
    async fn t_open_hold(tunnel: &flock_protocol::session::Tunnel) -> flock_protocol::mux::Stream {
        tunnel
            .open_stream(flock_protocol::mux::Prio::Control)
            .await
            .expect("control stream")
    }
}
