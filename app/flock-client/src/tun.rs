//! TUN 设备接缝（docs/design.md §2.3 / §3.12，VPN-14）。
//!
//! [`TunDevice`] = 客户端对 TUN 的全部认知面：`open/read/write/close` 四方法
//! （§3.12 接口）。平台适配器：
//!
//! - **tun-rs 原生适配器**（Linux/Windows/macOS，cfg 门控）：`DeviceBuilder` 创建
//!   （name + MTU 1280），Unix 上设非阻塞（读泵轮询模型，见 [`TunIo`]）；
//! - **Android/iOS fd 注入接缝**（仅注释，不装配）：两平台无 native 等价 API，fd 必须
//!   由上层框架注入（vpn-mesh §1.1）——
//!   - Android：`VpnService.Builder().establish().getFd()` 取 fd 后
//!     `tun_rs::SyncDevice::from_fd(fd)`（unsafe：fd 所有权移交）；本 crate 的
//!     [`TunDevice::open`] 不覆盖此路径，留给上层装配（tun-rs 2.8 内置该示例）；
//!   - iOS：`NEPacketTunnelProvider.packetFlow` 的 `socket.fileDescriptor` 取 fd，
//!     同 `from_fd`。两平台路由由 `VpnService.Builder` /
//!     `NEPacketTunnelProvider` 参数承担（§2.3），不走本 crate 的 route 模块。
//!
//! [`MockTunDevice`]：宿主单测用（§7-M3「tun 单测用 mock TunDevice——主机无容器
//! NET_ADMIN 环境」）——读空队列返回 `WouldBlock` 模拟非阻塞内核面。
//!
//! [`TunIo`]/[`TunSession`]：把同步 [`TunDevice`] 桥成 tokio 异步面（两条阻塞线程 +
//! 有界通道）。TUN 设备跨重连**常驻**（接口在，路由才在）；每条隧道会话取一个
//! [`TunSession`]，会话结束即拆线程、设备不动。

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

/// 部署形态 MTU = 1280（§2.1：Tailscale 同款、IPv6 下限，vpn-mesh §3.2）。
pub const MTU: u16 = 1280;

/// TUN 创建参数。
#[derive(Debug, Clone)]
pub struct TunSpec {
    /// 接口名（Linux ≤15 字符；缺省 "tun0"——§6.3 A3 断言按 `ip link show tun0`）。
    pub name: String,
    /// MTU（缺省 [`MTU`]）。
    pub mtu: u16,
}

impl Default for TunSpec {
    fn default() -> Self {
        TunSpec { name: "tun0".into(), mtu: MTU }
    }
}

/// TUN 设备接缝（§3.12：open/read/write/close）。
///
/// `read/write` 取 `&self`：真实 TUN fd 全双工且 read/write 互不阻塞（tun-rs 的
/// `recv/send` 均为 `&self`），读/写两线程可共享一个 `Arc<dyn TunDevice>` 而无锁竞争。
pub trait TunDevice: Send + Sync + 'static {
    /// 打开设备（平台适配器装配点）。
    fn open(spec: &TunSpec) -> io::Result<Self>
    where
        Self: Sized;
    /// 读一个 IP 包进 buf；返回读到的字节数。无包 ⇒ `ErrorKind::WouldBlock`
    /// （Linux 非阻塞语义；Mock 对齐）。
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// 写一个 IP 包。
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    /// 关闭设备（此后 read/write 报错）。
    fn close(&self) -> io::Result<()>;
    /// 接口名（路由配置/日志用）。
    fn name(&self) -> String;
}

/// 装配平台适配器（宿主/容器统一入口；无适配器平台返回明确错误而非 panic）。
pub fn open(spec: &TunSpec) -> io::Result<Box<dyn TunDevice>> {
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        TunRsDevice::open(spec).map(|d| Box::new(d) as Box<dyn TunDevice>)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        // Android/iOS：fd 注入接缝（模块文档）——由上层框架持有 fd 构造，不走 open。
        let _ = spec;
        Err(io::Error::other(
            "tun: 平台无原生适配器（Android/iOS 走 fd 注入接缝，§2.3/§3.12）",
        ))
    }
}

// ============================================================================
// tun-rs 原生适配器（Linux/Windows/macOS）
// ============================================================================

/// tun-rs 2.8 适配器（§2.3 选型：平台矩阵最全、活跃度最高，vpn-mesh §1.2）。
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub struct TunRsDevice {
    dev: tun_rs::SyncDevice,
    name: String,
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
impl TunDevice for TunRsDevice {
    fn open(spec: &TunSpec) -> io::Result<Self> {
        let dev = tun_rs::DeviceBuilder::new()
            .name(spec.name.clone())
            .mtu(spec.mtu)
            .build_sync()
            .map_err(|e| io::Error::other(format!("tun-rs create {}: {e}", spec.name)))?;
        // Unix：读泵 = 非阻塞轮询模型（见 TunIo 文档），显式设非阻塞。
        // Windows（wintun）运行路径留待 M5 真机手工验证（§7-M3 清单）。
        #[cfg(unix)]
        dev.set_nonblocking(true)
            .map_err(|e| io::Error::other(format!("tun nonblocking: {e}")))?;
        Ok(TunRsDevice { dev, name: spec.name.clone() })
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.recv(buf)
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.dev.send(buf)
    }

    fn close(&self) -> io::Result<()> {
        // tun-rs 无显式 close（fd 随 Drop 关）；置 down 即拆接口。
        self.dev.enabled(false).map_err(|e| io::Error::other(format!("tun down: {e}")))
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}

// ============================================================================
// Mock（宿主单测）
// ============================================================================

/// 内存 TUN：`inject` 模拟内核→本机包（读侧），`written` 收集本机→内核包（写侧）。
///
/// 读语义与 Linux 适配器对齐：空队列 ⇒ `WouldBlock`（`TunIo` 读泵的轮询路径在宿主
/// 单测中被真实走到）。
#[derive(Debug, Default)]
pub struct MockTunDevice {
    to_read: std::sync::Mutex<VecDeque<Vec<u8>>>,
    written: std::sync::Mutex<Vec<Vec<u8>>>,
    closed: AtomicBool,
    spec: std::sync::Mutex<Option<TunSpec>>,
}

impl MockTunDevice {
    /// 注入一个「内核发出」的包（读侧可见）。
    pub fn inject(&self, pkt: &[u8]) {
        self.to_read.lock().expect("mock tun poisoned").push_back(pkt.to_vec());
    }

    /// 本机写入的全部包（写侧记录）。
    pub fn written(&self) -> Vec<Vec<u8>> {
        self.written.lock().expect("mock tun poisoned").clone()
    }

    /// 打开时的 spec（断言 open 参数用）。
    pub fn spec(&self) -> Option<TunSpec> {
        self.spec.lock().expect("mock tun poisoned").clone()
    }
}

impl TunDevice for MockTunDevice {
    fn open(spec: &TunSpec) -> io::Result<Self> {
        let m = MockTunDevice::default();
        *m.spec.lock().expect("mock tun poisoned") = Some(spec.clone());
        Ok(m)
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }
        let mut q = self.to_read.lock().expect("mock tun poisoned");
        match q.pop_front() {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }
        self.written.lock().expect("mock tun poisoned").push(buf.to_vec());
        Ok(buf.len())
    }

    fn close(&self) -> io::Result<()> {
        self.closed.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn name(&self) -> String {
        self.spec
            .lock()
            .expect("mock tun poisoned")
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "mock0".into())
    }
}

// ============================================================================
// TunIo：同步设备 → tokio 异步桥
// ============================================================================

/// 读泵轮询间隔（非阻塞 read 的 WouldBlock 空转节流；1280B@100Mbps ≈ 万包/s，
/// 5ms 粒度批量排空对 A4 吞吐无感）。
const POLL: Duration = Duration::from_millis(5);
/// 单通道在途包数（背压：TUN 读快于会话写时阻塞读泵而非丢包/膨胀）。
const CHAN_CAP: usize = 1024;

/// 常驻 TUN 异步句柄：设备跨会话存活；每会话 [`TunIo::session`] 取一对通道。
pub struct TunIo {
    dev: Arc<dyn TunDevice>,
    stop: AtomicBool,
    name: String,
}

impl std::fmt::Debug for TunIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunIo").field("name", &self.name).finish_non_exhaustive()
    }
}

impl TunIo {
    /// 打开真设备并装配（`tun::open` + [`TunIo::from_arc`]）。
    pub fn open(spec: &TunSpec) -> io::Result<Self> {
        Ok(Self::from_arc(Arc::from(open(spec)?)))
    }

    /// 由共享设备装配（测试持 `Arc<MockTunDevice>` 双句柄时用）。
    pub fn from_arc(dev: Arc<dyn TunDevice>) -> Self {
        let name = dev.name();
        TunIo { dev, stop: AtomicBool::new(false), name }
    }

    /// 接口名。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 内部设备引用（mock 注入/诊断）。
    pub fn device(&self) -> &Arc<dyn TunDevice> {
        &self.dev
    }

    /// 起一条会话通道：spawns 读泵（设备→rx）与写泵（tx→设备）两条阻塞线程。
    /// 返回值 drop ⇒ 两泵在一个轮询周期内退出（设备保持打开，供下一会话复用）。
    pub fn session(&self) -> TunSession {
        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        // 会话级停止位（TunSession::drop 置位；无流量也能及时退出读泵轮询）。
        // 全局停机走 shutdown 的设备 close：读/写随 Err 退出。
        let session_stop = Arc::new(AtomicBool::new(false));
        {
            let dev = self.dev.clone();
            let stop = session_stop.clone();
            std::thread::Builder::new()
                .name("tun-read".into())
                .spawn(move || loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut buf = vec![0u8; 65535];
                    match dev.read(&mut buf) {
                        Ok(0) => {}
                        Ok(n) => {
                            buf.truncate(n);
                            if read_tx.blocking_send(buf).is_err() {
                                break; // 会话通道已拆
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(POLL);
                        }
                        Err(_) => break, // 设备关闭/故障
                    }
                })
                .expect("spawn tun-read");
        }
        {
            let dev = self.dev.clone();
            std::thread::Builder::new()
                .name("tun-write".into())
                .spawn(move || {
                    while let Some(pkt) = write_rx.blocking_recv() {
                        match dev.write(&pkt) {
                            Ok(_) => {}
                            // 非阻塞 fd 写侧 EAGAIN（设备队列瞬满）：小睡重试，不判死。
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(POLL);
                            }
                            Err(_) => break,
                        }
                    }
                })
                .expect("spawn tun-write");
        }
        TunSession { rx: read_rx, tx: write_tx, stop: session_stop }
    }

    /// 全局停机：关设备（读/写泵随设备报错退出；进程退出路径）。
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.dev.close();
    }
}

/// 会话通道：`rx` = 设备读出的包（内核→隧道），`tx` = 待写入设备的包（隧道→内核）。
pub struct TunSession {
    pub rx: mpsc::Receiver<Vec<u8>>,
    pub tx: mpsc::Sender<Vec<u8>>,
    stop: Arc<AtomicBool>,
}

impl Drop for TunSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

// ============================================================================
// 单元测试（宿主：mock 面；真设备路径由 deploy/m3_assert.sh 在容器实跑）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_open_read_write_close_semantics() {
        let dev = MockTunDevice::open(&TunSpec { name: "tun0".into(), mtu: MTU }).unwrap();
        let mut buf = [0u8; 2048];
        // 读空队列 ⇒ WouldBlock（对齐 Linux 非阻塞语义）。
        assert_eq!(
            dev.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "空队列 ⇒ WouldBlock"
        );
        assert_eq!(dev.name(), "tun0");
        assert_eq!(dev.spec().unwrap().mtu, MTU, "MTU 1280 进 spec（§2.1）");
        // 注入 → 读到；写 → 记录。
        dev.inject(b"\x45\x00\x00\x14abc");
        let n = dev.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"\x45\x00\x00\x14abc");
        dev.write(b"\x45\x00\x00\x08").unwrap();
        assert_eq!(dev.written(), vec![b"\x45\x00\x00\x08".to_vec()]);
        // close 后读写皆拒。
        dev.close().unwrap();
        assert_eq!(
            dev.read(&mut buf).err().map(|e| e.kind()),
            Some(io::ErrorKind::NotConnected)
        );
        assert_eq!(
            dev.write(b"x").err().map(|e| e.kind()),
            Some(io::ErrorKind::NotConnected)
        );
    }

    #[tokio::test]
    async fn tun_session_pumps_both_directions_and_stops_on_drop() {
        let mock = Arc::new(MockTunDevice::open(&TunSpec::default()).unwrap());
        let io = TunIo::from_arc(mock.clone());
        let mut s1 = io.session();
        // 读泵：注入一个包 ⇒ rx 可收（≤ 轮询间隔+裕量）。
        mock.inject(b"\x45\x00\x00\x14ping");
        let pkt = tokio::time::timeout(Duration::from_secs(2), s1.rx.recv())
            .await
            .expect("5ms 轮询内应收到注入包")
            .expect("读泵存活");
        assert_eq!(pkt, b"\x45\x00\x00\x14ping");
        // 写泵：tx 发包 ⇒ mock written 可见。
        s1.tx.send(b"\x45\x00\x00\x15pong".to_vec()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(mock.written(), vec![b"\x45\x00\x00\x15pong".to_vec()]);
        // 会话拆除（drop）⇒ 新会话通道照常（设备常驻跨会话；旧泵随会话停位退出）。
        drop(s1);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let s2 = io.session();
        s2.tx.send(b"\x45\x00\x00\x16next".to_vec()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(mock.written().len(), 2, "新会话复用同一设备");
        // 全局停机：设备关闭 ⇒ 后续读写拒。
        io.shutdown();
        let mut buf = [0u8; 64];
        assert!(mock.read(&mut buf).is_err(), "shutdown 后设备读拒");
        assert!(mock.write(b"x").is_err(), "shutdown 后设备写拒");
    }
}
