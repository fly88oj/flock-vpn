//! 数据面（docs/design.md §2.3 / §3.12）：IP 包 ↔ [`PacketChannel`]。
//!
//! 客户端侧桥：TUN 读泵产出的包 → `PacketChannel::send`；`PacketChannel::recv` →
//! TUN 写泵。任一侧错误/EOF ⇒ 返回（会话结束，接入器退避重连，[`supervise`]）。
//! （服务器侧的多会话路由在 `chmlvpn-server::dataplane`，同一 [`TunIo`] 底座。）

use std::io;

use chml_protocol::mux::PacketChannel;

use crate::tun::TunSession;

/// 桥接循环：tun ↔ packet channel（双向 select；首个错误即返回）。
pub async fn bridge(sess: &mut TunSession, ch: &mut PacketChannel) -> io::Result<()> {
    loop {
        tokio::select! {
            // 内核 → 隧道
            pkt = sess.rx.recv() => {
                match pkt {
                    Some(p) => ch.send(&p).await?,
                    None => return Err(io::Error::other("tun: 读泵已退出")),
                }
            }
            // 隧道 → 内核
            pkt = ch.recv() => {
                let p = pkt?;
                sess.tx.send(p).await.map_err(|_| io::Error::other("tun: 写泵已退出"))?;
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

    use chml_protocol::ed25519_dalek::SigningKey;
    use chml_protocol::session::{
        respond, ClusterId, DeviceRecord, DeviceStaticKeys, InMemoryDirectory, ServerId,
        ServerIdentity, TunnelConfig,
    };
    use chml_protocol::trust::ClusterDirectory;
    use chml_protocol::{rand, mux::PacketChannel};

    /// respond 侧真材料 + 设备注册表 + 每流回显 + 会话级 kill 开关。
    pub(crate) struct EchoPeer {
        pub identity: ServerIdentity,
        pub directory: ClusterDirectory,
        pub root: SigningKey,
        devices: std::sync::Mutex<InMemoryDirectory>,
        conns: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    }

    impl EchoPeer {
        pub(crate) fn new(endpoint: &str) -> Self {
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
                let Ok((io, _)) = listener.accept().await else { return };
                let conn_peer = self.clone();
                let h = tokio::spawn(async move {
                    let dir = conn_peer.devices.lock().unwrap().clone();
                    let tunnel =
                        match respond(io, &conn_peer.identity, dir, TunnelConfig::default()).await {
                            Ok(t) => t,
                            Err(_) => return,
                        };
                    while let Some(stream) = tunnel.accept_stream().await {
                        let mut ch = PacketChannel::from_stream(stream);
                        tokio::spawn(async move {
                            while let Ok(pkt) = ch.recv().await {
                                if ch.send(&pkt).await.is_err() {
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

    use chml_protocol::session::{
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
        let pin = chml_protocol::session::ServerPin {
            cluster_id: peer.directory.cluster_id,
            cluster_root_pub: peer.root.verifying_key(),
            entry: peer.directory.servers[0].clone(),
        };

        // 隧道 + 首流控制占位 + 包通道（与 supervise 的排序契约一致）。
        let io = tokio::net::TcpStream::connect(&ep).await.unwrap();
        let tunnel = chml_protocol::session::initiate(io, &device, &pin, TunnelConfig::default())
            .await
            .expect("1-RTT initiate");
        let _control_hold = tunnel.open_stream(chml_protocol::mux::Prio::Control).await.unwrap();
        let mut ch = tunnel.open_packet_channel().await.unwrap();

        // mock tun + 桥任务。
        let mock = Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let tun = TunIo::from_arc(mock.clone());
        let mut sess = tun.session();
        let bridged = tokio::spawn(async move { bridge(&mut sess, &mut ch).await });

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

    /// duplex 冒烟：记录层/复用器最小路径（跳过 TCP）。
    #[tokio::test]
    async fn session_duplex_smoke() {
        let peer = EchoPeer::new("127.0.0.1:9443");
        let device = DeviceStaticKeys::generate();
        peer.register(&device);
        let pin = chml_protocol::session::ServerPin {
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
            let Some(s) = t.accept_stream().await else { return };
            let mut ch = PacketChannel::from_stream(s);
            while let Ok(p) = ch.recv().await {
                if ch.send(&p).await.is_err() {
                    break;
                }
            }
        });
        let tunnel = tokio::time::timeout(
            Duration::from_secs(5),
            chml_protocol::session::initiate(a, &device, &pin, TunnelConfig::default()),
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
    async fn t_open_hold(
        tunnel: &chml_protocol::session::Tunnel,
    ) -> chml_protocol::mux::Stream {
        tunnel
            .open_stream(chml_protocol::mux::Prio::Control)
            .await
            .expect("control stream")
    }
}
