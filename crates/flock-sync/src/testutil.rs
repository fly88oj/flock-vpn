//! Test support (`--features test-util`; not in the default build).
//!
//! - [`MemoryFabric`]: in-process interconnect fabric — `dial` creates a
//!   duplex pair and delivers the peer's end to its accept queue (simulating
//!   a TCP dial; node kill = accept queue torn down + dial refused);
//! - bidirectional delay bridge: between the two duplex pairs, each direction
//!   sleeps `delay` ⇒ RTT = 2×delay (§7-M4 injects 100ms for calibration);
//! - [`MemoryFabric::cut`]: single-node failure injection (for the kill
//!   leader case).

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flock_protocol::session::ServerId;
use futures::future::BoxFuture;
use futures::FutureExt;
use tokio::io::DuplexStream;
use tokio::sync::mpsc;

use crate::wire::{Fabric, PeerIo};

/// One-way pump: read `r` → sleep `delay` → write `w` (a line-propagation
/// delay model).
async fn pump(
    mut r: tokio::io::ReadHalf<DuplexStream>,
    mut w: tokio::io::WriteHalf<DuplexStream>,
    delay: Duration,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                tokio::time::sleep(delay).await;
                if w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                let _ = w.flush().await;
            }
        }
    }
}

/// Bidirectional delay bridge: `x ↔ y`, each direction sleeps `delay` before
/// forwarding; **either side closing (EOF) ⇒ both directions torn down**
/// (emulating the FIN propagation of a TCP one-sided close — otherwise the
/// peer never sees EOF and a bad handshake would hang forever). Returns both
/// pumps' AbortHandles (registered into the NodeSlot at both ends — `cut` can
/// sever established connections, emulating a full partition: merely refusing
/// new dials is not enough to disconnect cached sessions).
fn spawn_bridge(
    x: DuplexStream,
    y: DuplexStream,
    delay: Duration,
) -> [tokio::task::AbortHandle; 2] {
    let (xr, xw) = tokio::io::split(x);
    let (yr, yw) = tokio::io::split(y);
    let mut x2y = tokio::spawn(pump(xr, yw, delay));
    let mut y2x = tokio::spawn(pump(yr, xw, delay));
    let handles = [x2y.abort_handle(), y2x.abort_handle()];
    tokio::spawn(async move {
        tokio::select! {
            _ = &mut x2y => { y2x.abort(); }
            _ = &mut y2x => { x2y.abort(); }
        }
    });
    handles
}

/// Node access slot (public visibility carries the FabricRegistry type
/// alias).
pub struct NodeSlot {
    tx: mpsc::Sender<PeerIo>,
    alive: bool,
    /// Established bridges with this node as an endpoint (the dialer and the
    /// dialed each register one copy) — all severed on `cut`.
    bridges: Vec<[tokio::task::AbortHandle; 2]>,
}

/// Node registry (shared by all nodes).
pub type FabricRegistry = Arc<Mutex<BTreeMap<[u8; 16], NodeSlot>>>;

/// In-process interconnect fabric (one instance per node).
pub struct MemoryFabric {
    me: ServerId,
    reg: FabricRegistry,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<PeerIo>>>,
    delay: Duration,
    buf: usize,
}

impl MemoryFabric {
    /// Empty registry.
    pub fn registry() -> FabricRegistry {
        Arc::new(Mutex::new(BTreeMap::new()))
    }

    /// Build a node's fabric and register it. `delay` = one-way propagation
    /// delay (RTT = 2×delay); `buf` = duplex buffer.
    pub fn new(me: ServerId, reg: &FabricRegistry, delay: Duration, buf: usize) -> Arc<Self> {
        let (tx, rx) = mpsc::channel::<PeerIo>(64);
        reg.lock().expect("fabric reg").insert(
            me.0,
            NodeSlot {
                tx,
                alive: true,
                bridges: Vec::new(),
            },
        );
        Arc::new(MemoryFabric {
            me,
            reg: reg.clone(),
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
            delay,
            buf,
        })
    }

    /// Take a node offline (full-partition shape: dial refused + **sever
    /// established bridges** — cached E2E sessions die with the connections,
    /// observation streams vanish; the in-flight accept queue is retained
    /// until drained — for the kill leader case).
    pub fn cut(reg: &FabricRegistry, id: &ServerId) {
        if let Some(slot) = reg.lock().expect("fabric reg").get_mut(&id.0) {
            slot.alive = false;
            for pair in slot.bridges.drain(..) {
                for h in pair {
                    h.abort();
                }
            }
        }
    }

    /// Bring a node back.
    pub fn uncut(reg: &FabricRegistry, id: &ServerId) {
        if let Some(slot) = reg.lock().expect("fabric reg").get_mut(&id.0) {
            slot.alive = true;
        }
    }

    /// The local identity.
    pub fn id(&self) -> &ServerId {
        &self.me
    }
}

impl Fabric for MemoryFabric {
    fn dial(&self, target: &ServerId) -> BoxFuture<'static, io::Result<PeerIo>> {
        let reg = self.reg.clone();
        let me = self.me;
        let target = *target;
        let delay = self.delay;
        let buf = self.buf;
        async move {
            // Two duplexes + delay bridge: the dialer holds d1a, the acceptor
            // gets d2a, and d1b↔d2b are bridged.
            let (dial_io, d1b) = tokio::io::duplex(buf);
            let (acc_io, d2b) = tokio::io::duplex(buf);
            let handles = spawn_bridge(d1b, d2b, delay);
            let tx = {
                let mut reg = reg.lock().expect("fabric reg");
                let tx = {
                    // This end was cut too ⇒ outbound is refused as well
                    // (full partition = bidirectional blocking — a cut node
                    // neither receives connections nor dials out; one-way
                    // allowance would falsify the fail-closed assertions).
                    let self_alive = reg.get(&me.0).is_some_and(|s| s.alive);
                    let slot = reg.get_mut(&target.0).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::ConnectionRefused, "no such node")
                    })?;
                    if !slot.alive || !self_alive {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "node down",
                        ));
                    }
                    slot.tx.clone()
                };
                // Register the bridge at both ends (severed when either end
                // is cut — full-partition semantics).
                let mine_copy = [handles[0].clone(), handles[1].clone()];
                if let Some(slot) = reg.get_mut(&target.0) {
                    slot.bridges.push(handles);
                }
                if let Some(mine) = reg.get_mut(&me.0) {
                    mine.bridges.push(mine_copy);
                }
                tx
            };
            tx.send(Box::new(acc_io) as PeerIo).await.map_err(|_| {
                io::Error::new(io::ErrorKind::ConnectionRefused, "accept queue gone")
            })?;
            Ok(Box::new(dial_io) as PeerIo)
        }
        .boxed()
    }

    fn accept(&self) -> BoxFuture<'static, io::Result<PeerIo>> {
        let rx = self.rx.clone();
        async move {
            // tokio Mutex: the guard can be held across an await (a single
            // serve_loop consumer, no contention).
            let mut rx = rx.lock().await;
            // The closed shape = NotConnected (wire::is_fabric_closed's
            // conventional signal: registry gone / all dialers torn down —
            // serve_loop exits on it instead of retrying on a transient
            // error).
            rx.recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "fabric closed"))
        }
        .boxed()
    }
}
