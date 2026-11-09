//! TUN device seam (docs/design.md §2.3 / §3.12, VPN-14).
//!
//! [`TunDevice`] = the client's entire knowledge surface of a TUN: four
//! methods `open/read/write/close` (§3.12 interface). Platform adapters:
//!
//! - **tun-rs native adapter** (Linux/Windows/macOS, cfg-gated): created via
//!   `DeviceBuilder` (name + MTU 1280), non-blocking on Unix (read-pump
//!   polling model, see [`TunIo`]);
//! - **Android/iOS fd-injection seam** (comments only, not assembled): the
//!   two platforms have no native equivalent API; the fd must be injected by
//!   the upper framework (vpn-mesh §1.1) —
//!   - Android: after `VpnService.Builder().establish().getFd()` yields the
//!     fd, `tun_rs::SyncDevice::from_fd(fd)` (unsafe: fd ownership
//!     transferred); [`TunDevice::open`] in this crate does not cover this
//!     path — left for upper-layer assembly (tun-rs 2.8 ships that example);
//!   - iOS: take the fd from `NEPacketTunnelProvider.packetFlow`'s
//!     `socket.fileDescriptor`, same `from_fd`. Routing on both platforms is
//!     handled by `VpnService.Builder` / `NEPacketTunnelProvider` parameters
//!     (§2.3), not by this crate's route module.
//!
//! [`MockTunDevice`]: for host unit tests (§7-M3 "tun unit tests use a mock
//! TunDevice — hosts lack the container NET_ADMIN environment") — an empty
//! read queue returns `WouldBlock` to mimic the non-blocking kernel surface.
//!
//! [`TunIo`]/[`TunSession`]: bridge the synchronous [`TunDevice`] into a
//! tokio async surface (two blocking threads + bounded channels). The TUN
//! device is **resident** across reconnects (only while the interface exists
//! do the routes); each tunnel session takes one [`TunSession`], and when
//! the session ends its threads are torn down while the device stays.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

/// Deployment-form MTU = 1280 (§2.1: same as Tailscale, IPv6 floor, vpn-mesh
/// §3.2).
pub const MTU: u16 = 1280;

/// TUN creation parameters.
#[derive(Debug, Clone)]
pub struct TunSpec {
    /// Interface name (Linux ≤15 chars; default "tun0" — the §6.3 A3
    /// assertion targets `ip link show tun0`).
    pub name: String,
    /// MTU (default [`MTU`]).
    pub mtu: u16,
}

impl Default for TunSpec {
    fn default() -> Self {
        TunSpec {
            name: "tun0".into(),
            mtu: MTU,
        }
    }
}

/// TUN device seam (§3.12: open/read/write/close).
///
/// `read/write` take `&self`: a real TUN fd is full-duplex and read/write do
/// not block each other (tun-rs's `recv/send` are both `&self`), so the
/// read/write threads can share one `Arc<dyn TunDevice>` without lock
/// contention.
pub trait TunDevice: Send + Sync + 'static {
    /// Open the device (platform adapter assembly point).
    fn open(spec: &TunSpec) -> io::Result<Self>
    where
        Self: Sized;
    /// Read one IP packet into buf; returns the byte count read. No packet ⇒
    /// `ErrorKind::WouldBlock` (Linux non-blocking semantics; the Mock is
    /// aligned).
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Write one IP packet.
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    /// Close the device (read/write error afterwards).
    fn close(&self) -> io::Result<()>;
    /// Interface name (for route configuration/logging).
    fn name(&self) -> String;
}

/// Assemble the platform adapter (unified host/container entry point;
/// platforms without an adapter get an explicit error rather than a panic).
pub fn open(spec: &TunSpec) -> io::Result<Box<dyn TunDevice>> {
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        TunRsDevice::open(spec).map(|d| Box::new(d) as Box<dyn TunDevice>)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        // Android/iOS: fd-injection seam (module docs) — constructed by the
        // upper framework holding the fd, not via open.
        let _ = spec;
        Err(io::Error::other(
            "tun: no native adapter on this platform (Android/iOS go through the fd-injection \
             seam, §2.3/§3.12)",
        ))
    }
}

// ============================================================================
// tun-rs native adapter (Linux/Windows/macOS)
// ============================================================================

/// tun-rs 2.8 adapter (§2.3 selection: fullest platform matrix, highest
/// activity, vpn-mesh §1.2).
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
        // Unix: read pump = non-blocking polling model (see the TunIo docs);
        // set non-blocking explicitly.
        // The Windows (wintun) runtime path is pending M5 real-machine manual
        // verification (§7-M3 checklist).
        #[cfg(unix)]
        dev.set_nonblocking(true)
            .map_err(|e| io::Error::other(format!("tun nonblocking: {e}")))?;
        Ok(TunRsDevice {
            dev,
            name: spec.name.clone(),
        })
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Windows (wintun): tun-rs's recv is **blocking** semantics (no
        // cross-platform non-blocking switch; set_nonblocking is unix-only) —
        // a blocking read would leave the read-pump thread stuck inside recv,
        // and TunSession::drop's stop flag would never be checked when there
        // is no traffic (breaking the both-pumps-exit promise, see
        // TunIo::session). Switch to try_recv polling (an API tun-rs provides
        // on Windows only): no packet ⇒ WouldBlock, throttled by the read
        // pump's POLL interval. Unix keeps the non-blocking recv
        // (set_nonblocking was applied at open).
        #[cfg(windows)]
        {
            self.dev.try_recv(buf)
        }
        #[cfg(not(windows))]
        {
            self.dev.recv(buf)
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.dev.send(buf)
    }

    fn close(&self) -> io::Result<()> {
        // tun-rs has no explicit close (the fd closes with Drop); setting
        // down tears down the interface.
        self.dev
            .enabled(false)
            .map_err(|e| io::Error::other(format!("tun down: {e}")))
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}

// ============================================================================
// Mock (host unit tests)
// ============================================================================

/// In-memory TUN: `inject` simulates kernel→local packets (read side),
/// `written` collects local→kernel packets (write side).
///
/// Read semantics align with the Linux adapter: empty queue ⇒ `WouldBlock`
/// (the poll path of the [`TunIo`] read pump is genuinely exercised in host
/// unit tests).
#[derive(Debug, Default)]
pub struct MockTunDevice {
    to_read: std::sync::Mutex<VecDeque<Vec<u8>>>,
    written: std::sync::Mutex<Vec<Vec<u8>>>,
    closed: AtomicBool,
    spec: std::sync::Mutex<Option<TunSpec>>,
}

impl MockTunDevice {
    /// Inject a "kernel-sent" packet (visible on the read side).
    pub fn inject(&self, pkt: &[u8]) {
        self.to_read
            .lock()
            .expect("mock tun poisoned")
            .push_back(pkt.to_vec());
    }

    /// All packets written by the local side (write-side record).
    pub fn written(&self) -> Vec<Vec<u8>> {
        self.written.lock().expect("mock tun poisoned").clone()
    }

    /// The spec at open time (for asserting open parameters).
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
        self.written
            .lock()
            .expect("mock tun poisoned")
            .push(buf.to_vec());
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
// TunIo: sync device → tokio async bridge
// ============================================================================

/// Read-pump poll interval (throttles WouldBlock spinning of the
/// non-blocking read; 1280B@100Mbps ≈ 10k packets/s, draining in batches at
/// a 5ms granularity is imperceptible for A4 throughput).
const POLL: Duration = Duration::from_millis(5);
/// In-flight packets per channel (backpressure: when TUN reads faster than
/// the session writes, block the read pump rather than dropping packets or
/// ballooning).
const CHAN_CAP: usize = 1024;
/// Read-pump buffer (reused in a loop): allocated once at the IP packet
/// ceiling — trimming to MTU+margin would silently truncate on a deployment
/// MTU change or an unusually large packet; reuse removes the "64KiB
/// allocation per packet" (delivery copies are allocated at the exact
/// length).
const READ_BUF_LEN: usize = 65535;

/// Resident TUN async handle: the device survives across sessions; each
/// session takes one pair of channels from [`TunIo::session`].
pub struct TunIo {
    dev: Arc<dyn TunDevice>,
    name: String,
}

impl std::fmt::Debug for TunIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunIo")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl TunIo {
    /// Open the real device and assemble (`tun::open` +
    /// [`TunIo::from_arc`]).
    pub fn open(spec: &TunSpec) -> io::Result<Self> {
        Ok(Self::from_arc(Arc::from(open(spec)?)))
    }

    /// Assemble from a shared device (for tests holding an
    /// `Arc<MockTunDevice>` dual-handle).
    pub fn from_arc(dev: Arc<dyn TunDevice>) -> Self {
        let name = dev.name();
        TunIo { dev, name }
    }

    /// Interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Internal device reference (mock injection/diagnostics).
    pub fn device(&self) -> &Arc<dyn TunDevice> {
        &self.dev
    }

    /// Start one session channel: spawns a read pump (device→rx) and a write
    /// pump (tx→device), two blocking threads. Dropping the return value ⇒
    /// both pumps exit within one poll period (the device stays open for the
    /// next session to reuse).
    pub fn session(&self) -> TunSession {
        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
        // Session-level stop flag (set by TunSession::drop; lets the read
        // pump exit its polling loop promptly even with no traffic).
        // Global shutdown goes through shutdown's device close: reads/writes
        // exit with Err.
        let session_stop = Arc::new(AtomicBool::new(false));
        {
            let dev = self.dev.clone();
            let stop = session_stop.clone();
            std::thread::Builder::new()
                .name("tun-read".into())
                .spawn(move || {
                    // Read buffer reused in a loop (READ_BUF_LEN note): no
                    // fresh 64KiB per packet; delivery copies are allocated
                    // at the exact read length.
                    let mut buf = vec![0u8; READ_BUF_LEN];
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        match dev.read(&mut buf) {
                            // Ok(0): a zero-length read meaning "no data for
                            // now" on the device side — throttle by the poll
                            // interval; must not be converted naively
                            // (otherwise 100% CPU spin with no packets).
                            Ok(0) => std::thread::sleep(POLL),
                            Ok(n) => {
                                if read_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                    break; // session channel torn down
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(POLL);
                            }
                            Err(_) => break, // device closed/failure
                        }
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
                            // Write-side EAGAIN on a non-blocking fd
                            // (device queue momentarily full): brief sleep
                            // and retry, not fatal.
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(POLL);
                            }
                            Err(_) => break,
                        }
                    }
                })
                .expect("spawn tun-write");
        }
        TunSession {
            rx: read_rx,
            tx: write_tx,
            stop: session_stop,
        }
    }

    /// Global shutdown: close the device (read/write pumps exit on the
    /// device erroring; the process-exit path).
    pub fn shutdown(&self) {
        let _ = self.dev.close();
    }
}

/// Session channel: `rx` = packets read from the device (kernel→tunnel),
/// `tx` = packets to write to the device (tunnel→kernel).
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
// Unit tests (host: mock surface; the real-device path is exercised by
// deploy/m3_assert.sh in a container)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_open_read_write_close_semantics() {
        let dev = MockTunDevice::open(&TunSpec {
            name: "tun0".into(),
            mtu: MTU,
        })
        .unwrap();
        let mut buf = [0u8; 2048];
        // Empty queue read ⇒ WouldBlock (aligned with Linux non-blocking
        // semantics).
        assert_eq!(
            dev.read(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "empty queue ⇒ WouldBlock"
        );
        assert_eq!(dev.name(), "tun0");
        assert_eq!(
            dev.spec().unwrap().mtu,
            MTU,
            "MTU 1280 lands in the spec (§2.1)"
        );
        // Inject → read; write → recorded.
        dev.inject(b"\x45\x00\x00\x14abc");
        let n = dev.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"\x45\x00\x00\x14abc");
        dev.write(b"\x45\x00\x00\x08").unwrap();
        assert_eq!(dev.written(), vec![b"\x45\x00\x00\x08".to_vec()]);
        // After close, both read and write are rejected.
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
        // Read pump: inject one packet ⇒ receivable on rx (≤ poll interval +
        // margin).
        mock.inject(b"\x45\x00\x00\x14ping");
        let pkt = tokio::time::timeout(Duration::from_secs(2), s1.rx.recv())
            .await
            .expect("injected packet should arrive within the 5ms poll cadence")
            .expect("read pump alive");
        assert_eq!(pkt, b"\x45\x00\x00\x14ping");
        // Write pump: send a packet on tx ⇒ visible in mock written.
        s1.tx.send(b"\x45\x00\x00\x15pong".to_vec()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(mock.written(), vec![b"\x45\x00\x00\x15pong".to_vec()]);
        // Session teardown (drop) ⇒ a fresh session channel works as usual
        // (device resident across sessions; the old pumps exit on the stop
        // flag).
        drop(s1);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let s2 = io.session();
        s2.tx.send(b"\x45\x00\x00\x16next".to_vec()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            mock.written().len(),
            2,
            "new session reuses the same device"
        );
        // Global shutdown: device closed ⇒ subsequent reads/writes rejected.
        io.shutdown();
        let mut buf = [0u8; 64];
        assert!(
            mock.read(&mut buf).is_err(),
            "device read rejected after shutdown"
        );
        assert!(
            mock.write(b"x").is_err(),
            "device write rejected after shutdown"
        );
    }
}
