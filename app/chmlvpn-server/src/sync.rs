//! 多主运行装配（feature `multi-primary`；docs/design.md §2.2/§3.11/§6.2 M5 批次）。
//!
//! 单服形态见 [`crate::server::run`]；本模块把 §3.10 的 [`chml_sync::SyncNode`] 接到
//! **真实进程/容器部署**：
//!
//! 1. **入群捆绑**：`state_dir/bundle.bin`（`enroll` 子命令产物；缺失 ⇒ 等待——容器
//!    编排里 init-cluster → 分发 → enroll 先于起服完成，等待语义让 `compose up`
//!    一次全起不崩循环）；
//! 2. **TCP 织物**：[`chml_sync::TcpFabric`] 绑 `sync.raft_bind`（§6.2 srvmesh 内联
//!    网），对端表来自 `sync.raft_peers`；
//! 3. **装配**：`SyncNodeBuilder`（voters = 根签目录全体节点）→ `ServerCore::open_sync`
//!    （等 Bootstrap+SetOprf 在本节点 apply——运维侧 `cluster-bootstrap` 提交，等待
//!    窗口 600s 覆盖编排序）；
//! 4. **服务器自身 peer 面**：开 tun（`cfg.vip`）→ `set_local_peer`（dst=自身 VIP 的
//!    包注入内核）+ 内核回程读泵（`route_outbound` 回 mesh，§2.2 判定序）；
//! 5. 监听/admin 与单服 [`crate::server::run`] 同构（Direct 缺省 / Frp 托管）。

use std::sync::Arc;

use flock_protocol::session::ServerIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use crate::config::{ListenerMode, ServerConfig};
use crate::server::{run, ServerCore};

/// 捆绑等待窗口（编排序：init-cluster → enroll 可能在 up 之后数十秒）。
const BUNDLE_WAIT: std::time::Duration = std::time::Duration::from_secs(600);
/// Bootstrap/SetOprf 等待窗口（open_sync 内 15s × 重试覆盖运维侧 cluster-bootstrap）。
const CLUSTER_READY_WAIT: std::time::Duration = std::time::Duration::from_secs(600);

/// raft 形态起服（`server.toml [sync] mode = "raft"`；§3.11 M5 批次接入）。
/// 返回形态与 [`crate::server::run`] 同构。
pub async fn run_raft(
    cfg: ServerConfig,
    mode: ListenerMode,
) -> Result<
    (
        crate::server::RunningListener,
        JoinHandle<std::io::Result<()>>,
        JoinHandle<()>,
    ),
    String,
> {
    let sync = cfg
        .sync
        .as_ref()
        .filter(|s| s.mode == "raft")
        .ok_or("run_raft 需要 [sync] mode = \"raft\"")?;
    let bundle_path = sync
        .bundle
        .clone()
        .unwrap_or_else(|| cfg.state_dir.join("bundle.bin"));

    // 1. 等入群捆绑（enroll 产物）。
    let bytes = wait_bundle(&bundle_path).await?;

    // 2. TCP 织物（srvmesh 直接互连；对端表 = sync.raft_peers）。
    let mut peers = std::collections::BTreeMap::new();
    for entry in &sync.raft_peers {
        let (id, addr) = chml_sync::tcp::parse_peer_entry(entry)?;
        peers.insert(id, addr);
    }
    let fabric =
        chml_sync::TcpFabric::bind(sync.raft_bind, peers)
            .await
            .map_err(|e| format!("raft fabric bind {}: {e}", sync.raft_bind))?;
    eprintln!(
        "chmlvpn-server: raft fabric listening on {}",
        fabric.local_addr().map(|a| a.to_string()).unwrap_or_default()
    );

    // 3. 装配 SyncNode（voters = 根签目录全体；同配置多节点并发 initialize 安全）。
    let bundle = verify_bundle(&bytes)?;
    let ident = Arc::new(bundle.identity()?);
    let directory = bundle.directory()?;
    let voters: Vec<u64> = directory
        .servers
        .iter()
        .map(|e| chml_sync::node::node_id_of(&e.server_id))
        .collect();
    let node = Arc::new(
        chml_sync::SyncNodeBuilder::new(
            chml_sync::SyncSettings::default(),
            ident.clone(),
            directory,
            fabric,
            cfg.state_dir.join("sync.redb"),
        )
        .voters(&voters)
        .build()
        .await
        .map_err(|e| format!("sync node: {e}"))?,
    );

    // 优雅停机（A7/A5 的 docker stop = SIGTERM）：先 Raft shutdown（停复制/清队在途
    // 写）再退出——redb 提交本身是事务持久的，此举进一步收敛在途写窗口。
    {
        let n = node.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            eprintln!("chmlvpn-server: 信号退出——Raft 优雅停机");
            let _ = n.shutdown().await;
            std::process::exit(0);
        });
    }

    // 4. 集群引导端点（**先于**就绪等待绑定，§4-1 编排序）：Bootstrap/SetOprf 的根签
    //    提交通道——admin 端点(9444)随 ServerCore 在 Bootstrap apply 后才起，而提交
    //    本身必须先能进来（鸡蛋序解法：专用通道直达 node.write）。端口 = admin + 1。
    let boot_bind = bootstrap_bind_of(cfg.admin_bind);
    serve_bootstrap_ep(node.clone(), boot_bind)
        .await
        .map_err(|e| format!("bootstrap endpoint bind {boot_bind}: {e}"))?;
    eprintln!("chmlvpn-server: cluster bootstrap endpoint on {boot_bind}（根签提交直达 Raft）");

    // 5. ServerCore（等 Bootstrap+SetOprf apply；运维侧 cluster-bootstrap 先行/后行皆可）。
    let core = wait_cluster_ready(cfg.clone(), ident, node.clone()).await?;

    // 6. 服务器自身 peer 面：tun + 本机投递/回程（§2.2）。
    wire_local_peer(&core, &node).await;

    // 7. 监听 + admin（与单服 run 同构）。router 预置 ⇒ run() 不再二次开同名 tun。
    core.set_router(crate::dataplane::PeerRouter::none());
    run(core, mode).await
}

/// admin 端口 +1（集群引导专用通道缺省位；9444 → 9445）。
fn bootstrap_bind_of(admin: std::net::SocketAddr) -> std::net::SocketAddr {
    let mut a = admin;
    a.set_port(admin.port() + 1);
    a
}

/// 集群引导端点：只接受 [`crate::admin::AdminRequest::SignedWrite`]（Bootstrap/SetOprf/
/// RecordInvite——签名验证在状态机内）与 `Stats`，直达 `SyncNode::write`。进程生命周期
/// 常驻（与 admin 并存；CLI `cluster-bootstrap`/`cluster-invite` 在 admin 未起时回退到它）。
async fn serve_bootstrap_ep(
    node: Arc<chml_sync::SyncNode>,
    bind: std::net::SocketAddr,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    Ok(tokio::spawn(async move {
        loop {
            let Ok((mut io, _)) = listener.accept().await else {
                return;
            };
            let node = node.clone();
            tokio::spawn(async move {
                let _ = handle_bootstrap_conn(&node, &mut io).await;
            });
        }
    }))
}

async fn handle_bootstrap_conn(
    node: &Arc<chml_sync::SyncNode>,
    io: &mut tokio::net::TcpStream,
) -> std::io::Result<()> {
    // 帧协议与 admin.rs 相同（[u32 LE len][postcard AdminRequest]）。
    let mut hdr = [0u8; 4];
    io.read_exact(&mut hdr).await?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > 256 * 1024 {
        return Err(std::io::Error::other("bootstrap frame length"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    let req: crate::admin::AdminRequest =
        postcard::from_bytes(&buf).map_err(|e| std::io::Error::other(e.to_string()))?;
    let resp = match req {
        crate::admin::AdminRequest::SignedWrite { req } => {
            match node.write(req).await {
                Ok(r) => crate::admin::AdminResponse::WriteReceipt { text: format!("{r:?}") },
                Err(e) => crate::admin::AdminResponse::Err { msg: e.to_string() },
            }
        }
        crate::admin::AdminRequest::Stats => {
            // 就绪前面：leader/epoch（本机视图）——编排查活用。
            let mut lines = Vec::new();
            lines.push(format!("node_id={}", node.id()));
            let leader = node
                .current_leader()
                .await
                .map(|l| l.to_string())
                .unwrap_or_default();
            lines.push(format!("leader={leader}"));
            lines.push(format!("epoch={}", node.local_epoch()));
            crate::admin::AdminResponse::StatsText { lines }
        }
        other => crate::admin::AdminResponse::Err {
            msg: format!("bootstrap endpoint 不受理该请求（{other:?} 面）"),
        },
    };
    let out = postcard::to_allocvec(&resp).map_err(|e| std::io::Error::other(e.to_string()))?;
    io.write_all(&(out.len() as u32).to_le_bytes()).await?;
    io.write_all(&out).await?;
    io.flush().await
}

/// 等待捆绑文件出现（enroll 先于/后于起服皆可）。
async fn wait_bundle(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let deadline = std::time::Instant::now() + BUNDLE_WAIT;
    loop {
        match std::fs::read(path) {
            Ok(b) => return Ok(b),
            Err(_) if std::time::Instant::now() < deadline => {
                eprintln!(
                    "chmlvpn-server: 等待入群捆绑 {}（enroll 后自动继续；剩余 {:?}）",
                    path.display(),
                    deadline.saturating_duration_since(std::time::Instant::now())
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => return Err(format!("读 {}: {e}", path.display())),
        }
    }
}

/// ServerCore（等集群就绪：Bootstrap 的票据根 + SetOprf 在本节点 apply）。
async fn wait_cluster_ready(
    cfg: ServerConfig,
    ident: Arc<ServerIdentity>,
    node: Arc<chml_sync::SyncNode>,
) -> Result<Arc<ServerCore>, String> {
    let deadline = std::time::Instant::now() + CLUSTER_READY_WAIT;
    loop {
        match ServerCore::open_sync(cfg.clone(), ident.clone(), node.clone()).await {
            Ok(core) => return Ok(core),
            Err(e) if std::time::Instant::now() < deadline => {
                eprintln!("chmlvpn-server: 集群未就绪（{e}）——2s 后重试");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => {
                return Err(format!("集群 600s 内未就绪（Bootstrap/SetOprf 未 apply）: {e}"))
            }
        }
    }
}

/// 服务器自身 peer 面（§2.2）：
/// - `set_local_peer`：dst = 自身 VIP 的入向包 → tun 写泵（A2 ping / A4 iperf）；
/// - 回程读泵：tun 产出（ICMP 回程/本机协议栈流量）→ `SyncNode::route_outbound`。
///
/// 无 tun（无 NET_ADMIN 部署）⇒ 记日志跳过（控制流-only；转发面设备↔设备不受影响）。
pub async fn wire_local_peer(core: &Arc<ServerCore>, node: &Arc<chml_sync::SyncNode>) {
    let vip = core.cfg.vip;
    match crate::dataplane::PeerRouter::open_tun_session(&core.cfg.tun_name, vip).await {
        Some((tun, sess)) => {
            let kernel_tx = sess.tx.clone();
            node.set_local_peer(vip, Arc::new(KernelSink(kernel_tx)));
            let node = node.clone();
            tokio::spawn(async move {
                let mut sess = sess;
                while let Some(pkt) = sess.rx.recv().await {
                    node.route_outbound(&pkt).await;
                }
            });
            // 设备句柄存活持有（接口随句柄存续）。
            std::mem::forget(tun);
            eprintln!("chmlvpn-server: local peer wired vip={vip}（dst=本机 VIP 入内核 + 回程进 mesh）");
        }
        None => {
            eprintln!("chmlvpn-server: 无 tun——本机 VIP 投递降级（跨服转发面不受影响）")
        }
    }
}

/// tun 写泵 sink（ForwardPlane 本机投递接缝）。
struct KernelSink(tokio::sync::mpsc::Sender<Vec<u8>>);

impl chml_sync::PacketSink for KernelSink {
    fn deliver(&self, pkt: &[u8]) -> std::io::Result<()> {
        self.0.try_send(pkt.to_vec()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("kernel write pump full: {e}"),
            )
        })
    }
}

fn verify_bundle(bytes: &[u8]) -> Result<crate::bundle::NodeBundle, String> {
    let b = crate::bundle::NodeBundle::from_bytes(bytes).ok_or("捆绑文件解码失败")?;
    b.verify().map(|_| b)
}
