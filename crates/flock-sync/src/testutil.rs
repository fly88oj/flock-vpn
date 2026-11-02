//! 测试支撑（`--features test-util`；不入默认构建）。
//!
//! - [`MemoryFabric`]：进程内互连织物——`dial` 造 duplex 对投递到对端 accept 队列
//!   （模拟 TCP 拨号；节点 kill = accept 队列拆除 + dial 拒绝）；
//! - 双向延迟桥：两对 duplex 之间每方向 sleep `delay` ⇒ RTT = 2×delay（§7-M4 注入
//!   100ms 校准）；
//! - [`MemoryFabric::cut`]：单节点故障注入（kill leader 用例）。

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

/// 单向泵：读 `r` → sleep `delay` → 写 `w`（线路传播延迟模型）。
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

/// 双向延迟桥：`x ↔ y` 每方向 sleep `delay` 再转发；**任一侧关闭（EOF）⇒ 双向拆除**
/// （仿真 TCP 单侧 close 的 FIN 传播——否则对端永远等不到 EOF，坏握手会挂死）。
/// 返回两泵的 AbortHandle（登记进两端 NodeSlot——`cut` 时可斩断已建立的连接，
/// 仿真完全分区：仅拒新拨号不足以让缓存会话失联）。
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

/// 节点接入槽（公开可见性承载 FabricRegistry 类型别名）。
pub struct NodeSlot {
    tx: mpsc::Sender<PeerIo>,
    alive: bool,
    /// 本节点为端点的已建立桥（拨号方与被拨方各登记一份）——`cut` 时全部斩断。
    bridges: Vec<[tokio::task::AbortHandle; 2]>,
}

/// 节点注册表（全部节点共享）。
pub type FabricRegistry = Arc<Mutex<BTreeMap<[u8; 16], NodeSlot>>>;

/// 进程内互连织物（每节点一个实例）。
pub struct MemoryFabric {
    me: ServerId,
    reg: FabricRegistry,
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<PeerIo>>>,
    delay: Duration,
    buf: usize,
}

impl MemoryFabric {
    /// 空注册表。
    pub fn registry() -> FabricRegistry {
        Arc::new(Mutex::new(BTreeMap::new()))
    }

    /// 建节点织物并注册。`delay` = 单向传播延迟（RTT = 2×delay）；`buf` = duplex 缓冲。
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

    /// 节点下线（完全分区形态：dial 拒绝 + **斩断已建立的桥**——缓存 E2E 会话随连接
    /// 消亡，观察流消失；在途 accept 队列保留至耗尽——kill leader 用例）。
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

    /// 节点恢复。
    pub fn uncut(reg: &FabricRegistry, id: &ServerId) {
        if let Some(slot) = reg.lock().expect("fabric reg").get_mut(&id.0) {
            slot.alive = true;
        }
    }

    /// 本机身份。
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
            // 双 duplex + 延迟桥：dialer 持 d1a、acceptor 得 d2a，桥接 d1b↔d2b。
            let (dial_io, d1b) = tokio::io::duplex(buf);
            let (acc_io, d2b) = tokio::io::duplex(buf);
            let handles = spawn_bridge(d1b, d2b, delay);
            let tx = {
                let mut reg = reg.lock().expect("fabric reg");
                let tx = {
                    // 本端也被切断 ⇒ 出向同样拒（完全分区 = 双向阻断——被切节点既收不到
                    // 入连也拨不出去，单向放行会让 fail-closed 断言失真）。
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
                // 桥登记进两端（cut 任一端即斩断——完全分区语义）。
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
            // tokio Mutex：guard 可跨 await（单 serve_loop 消费者，无争用）。
            let mut rx = rx.lock().await;
            // 关闭形态 = NotConnected（wire::is_fabric_closed 的约定信号：
            // 注册表消亡/全部拨号端拆除——serve_loop 据此退出而非按瞬时错误重试）。
            rx.recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "fabric closed"))
        }
        .boxed()
    }
}
