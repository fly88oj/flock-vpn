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
//!    跨服 ForwardEnvelope 转发面属 M4 `chml-sync`，§2.2 第 3 步）。
//!
//! 无 tun 环境（宿主单测、无 NET_ADMIN 的部署）：[`PeerRouter::open`] 记日志并降级
//! 「控制流-only」——包通道优雅 FIN，客户端观察通道 EOF（M2 行为保持）。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chml_protocol::mux::{PacketChannel, Stream};
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
use chmlvpn_client::route::{self, RoutePlan};
use chmlvpn_client::tun::TunIo;
#[cfg(target_os = "linux")]
use chmlvpn_client::tun::TunSpec;

/// 服务器自身 VIP（§2.2「服务端自身也是 peer，VIP 100.64.0.1」；netstate 分配从 .2 起）。
pub const SERVER_VIP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);

/// 源 VIP 校验失配累计（断言/告警面；§2.2「丢包 + 计数」）。
pub fn src_vip_mismatches() -> u64 {
    SRC_MISMATCH.load(Ordering::Relaxed)
}

static SRC_MISMATCH: AtomicU64 = AtomicU64::new(0);

/// IPv4 包源/目标地址（版本/IHL 校验后取 12..16 / 16..20）。非 IPv4/太短 ⇒ None。
fn ipv4_src_dst(pkt: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let src: [u8; 4] = pkt[12..16].try_into().ok()?;
    let dst: [u8; 4] = pkt[16..20].try_into().ok()?;
    Some((src, dst))
}

/// 单服数据面路由器（VIP → 会话包通道）。
pub struct PeerRouter {
    /// TUN 设备句柄（**存活持有**：接口与路由随句柄存续；非 Linux 装配路径不写入）。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    tun: Option<Arc<TunIo>>,
    /// 目标 VIP → 该会话出站通道（内核回程 → 对端）。
    sessions: Mutex<HashMap<[u8; 4], mpsc::Sender<Vec<u8>>>>,
    /// 内核注入通道（tun 写泵；无 tun ⇒ None = 控制流-only 降级）。
    kernel_tx: Option<mpsc::Sender<Vec<u8>>>,
}

impl PeerRouter {
    /// 打开 tun + 路由并装配路由器；任一步失败记日志并降级控制流-only
    /// （M2 宿主测试/无 NET_ADMIN 部署路径）。async：路由配置走 rtnetlink/tokio。
    ///
    /// 非 Linux 平台不装配真设备（Windows wintun 运行路径按 §7-M3 留待 M5 真机手工
    /// 验证——宿主 `cargo test` 不得触碰宿主驱动；macOS 未验证同 §7-M3）。
    pub async fn open(tun_name: &str) -> Arc<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = tun_name;
            eprintln!(
                "chmlvpn-server: 数据面仅 Linux 装配（Windows 真机 M5 手工清单/macOS 未验证）——控制流-only 模式"
            );
            Self::none()
        }
        #[cfg(target_os = "linux")]
        {
            let spec = TunSpec { name: tun_name.into(), mtu: chmlvpn_client::tun::MTU };
            let opened = match TunIo::open(&spec) {
                Ok(tun) => {
                    let ifname = tun.name().to_string();
                    match route::apply(&RoutePlan::new(&ifname, SERVER_VIP)).await {
                        Ok(()) => Ok(tun),
                        Err(e) => {
                            eprintln!("chmlvpn-server: 路由配置失败（控制流-only 模式）: {e}");
                            Err(())
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "chmlvpn-server: tun 打开失败（控制流-only 模式；容器需 --cap-add NET_ADMIN --device /dev/net/tun）: {e}"
                    );
                    Err(())
                }
            };
            match opened {
                Ok(tun) => {
                    let mut sess = tun.session();
                    let kernel_tx = sess.tx.clone();
                    eprintln!(
                        "chmlvpn-server: dataplane up: tun {} vip {SERVER_VIP} route {}/{} + rp_filter=1",
                        tun.name(),
                        route::VIP_POOL.0,
                        route::VIP_POOL.1
                    );
                    PeerRouter {
                        tun: Some(Arc::new(tun)),
                        sessions: Mutex::new(HashMap::new()),
                        kernel_tx: Some(kernel_tx),
                    }
                    .with_kernel_router_task(sess)
                }
                Err(()) => Arc::new(PeerRouter {
                    tun: None,
                    sessions: Mutex::new(HashMap::new()),
                    kernel_tx: None,
                }),
            }
        }
    }

    /// 内核回程路由任务：tun 读泵产出 → 按目标 VIP 分发到会话出站通道
    /// （无对应会话 ⇒ 丢弃——M4 前不做 ICMP unreachable/跨服转发，§2.2 容错策略）。
    #[cfg(target_os = "linux")]
    fn with_kernel_router_task(
        self: PeerRouter,
        mut sess: chmlvpn_client::tun::TunSession,
    ) -> Arc<Self> {
        let arc = Arc::new(self);
        let router = arc.clone();
        tokio::spawn(async move {
            //（TunSession 整体移入：rx 供路由；tx 存续使写泵常驻——服务端数据面不拆。）
            while let Some(pkt) = sess.rx.recv().await {
                let Some((_, dst)) = ipv4_src_dst(&pkt) else { continue };
                let target = router.sessions.lock().expect("router poisoned").get(&dst).cloned();
                if let Some(tx) = target {
                    let _ = tx.send(pkt).await;
                }
            }
        });
        arc
    }

    /// 显式无数据面（测试装配）。
    pub fn none() -> Arc<Self> {
        Arc::new(PeerRouter { tun: None, sessions: Mutex::new(HashMap::new()), kernel_tx: None })
    }

    /// 数据面是否在位（部署诊断/断言）。
    pub fn is_up(&self) -> bool {
        self.kernel_tx.is_some()
    }

    /// 会话包通道服务：登记出站通道（目标 VIP）+ 入站第 0 步源 VIP 校验 + 内核注入。
    /// 返回 = 通道结束（EOF/错误/内核通道拆）。
    pub async fn serve_stream(self: &Arc<Self>, vip: [u8; 4], stream: Stream) {
        let Some(kernel_tx) = self.kernel_tx.clone() else {
            // 无数据面降级：优雅 FIN（客户端观察通道 EOF，控制流不受影响）。
            let mut ch = PacketChannel::from_stream(stream);
            let _ = ch.finish().await;
            return;
        };
        let mut ch = PacketChannel::from_stream(stream);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);
        self.sessions.lock().expect("router poisoned").insert(vip, out_tx);
        // 单任务双向（PacketChannel 收/发均需 &mut——select 内串行化）：
        // 入站：包通道 → 源 VIP 校验（第 0 步，§2.2）→ 内核注入；
        // 出站：内核回程（router 任务分发）→ 包通道。
        loop {
            tokio::select! {
                out = out_rx.recv() => match out {
                    Some(pkt) => {
                        if ch.send(&pkt).await.is_err() {
                            break; // 通道拆（客户端会话结束）
                        }
                    }
                    None => break, // 出站登记已被移除
                },
                inc = ch.recv() => match inc {
                    Ok(pkt) => match ipv4_src_dst(&pkt) {
                        Some((src, _)) if src == vip => {
                            if kernel_tx.send(pkt).await.is_err() {
                                break; // tun 写泵已拆
                            }
                        }
                        // 失配/非 IPv4：丢包 + 计数（R22：不静默放行也不断链——计数供告警面）。
                        _ => {
                            SRC_MISMATCH.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    Err(_) => break, // 通道 EOF/错误
                },
            }
        }
        self.sessions.lock().expect("router poisoned").remove(&vip);
    }
}

// ============================================================================
// 单元测试（宿主：纯函数面；tun/路由真路径由 deploy/m3_assert.sh 容器实跑）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(src_vip_mismatches(), 0);
    }
}
