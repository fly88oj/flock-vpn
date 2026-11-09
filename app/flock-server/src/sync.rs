//! Multi-primary runtime assembly (feature `multi-primary`; docs/design.md
//! §2.2/§3.11/§6.2 M5 batch).
//!
//! The single-server form is [`crate::server::run`]; this module wires the
//! §3.10 [`flock_sync::SyncNode`] into **real process/container deployments**:
//!
//! 1. **Enrollment bundle**: `state_dir/bundle.bin` (the `enroll`
//!    subcommand's product; missing ⇒ wait —— in container orchestration,
//!    init-cluster → distribute → enroll completes before startup, and the
//!    wait semantics let `compose up` start everything at once without
//!    crash-looping);
//! 2. **TCP fabric**: [`flock_sync::TcpFabric`] bound to `sync.raft_bind`
//!    (the §6.2 srvmesh inline network), the peer table from
//!    `sync.raft_peers`;
//! 3. **Assembly**: `SyncNodeBuilder` (voters = all nodes of the root-signed
//!    directory) → `ServerCore::open_sync` (waits for Bootstrap+SetOprf to
//!    apply on this node —— submitted operations-side by
//!    `cluster-bootstrap`; the 600s wait window covers the layout order);
//! 4. **The server's own peer surface**: open the tun (`cfg.vip`) →
//!    `set_local_peer` (packets with dst = own VIP injected into the
//!    kernel) + the kernel return-path read pump (`route_outbound` back
//!    into the mesh, the §2.2 decision order);
//! 5. Listener/admin is isomorphic to the single-server
//!    [`crate::server::run`] (Direct default / Frp managed).

use std::sync::Arc;

use flock_protocol::session::ServerIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use crate::config::{ListenerMode, ServerConfig};
use crate::server::{run, ServerCore};

/// Bundle wait window (layout order: init-cluster → enroll may be tens of
/// seconds after up).
const BUNDLE_WAIT: std::time::Duration = std::time::Duration::from_secs(600);
/// Bootstrap/SetOprf wait window (15s retries inside open_sync cover the
/// operations-side cluster-bootstrap).
const CLUSTER_READY_WAIT: std::time::Duration = std::time::Duration::from_secs(600);

/// Start the server in raft form (`server.toml [sync] mode = "raft"`; the
/// §3.11 M5 batch hookup). The returned shape is isomorphic to
/// [`crate::server::run`].
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
        .ok_or("run_raft requires [sync] mode = \"raft\"")?;
    let bundle_path = sync
        .bundle
        .clone()
        .unwrap_or_else(|| cfg.state_dir.join("bundle.bin"));

    // 1. Wait for the enrollment bundle (the enroll product).
    let bytes = wait_bundle(&bundle_path).await?;

    // 2. TCP fabric (direct srvmesh interconnect; peer table =
    //    sync.raft_peers).
    let mut peers = std::collections::BTreeMap::new();
    for entry in &sync.raft_peers {
        let (id, addr) = flock_sync::tcp::parse_peer_entry(entry)?;
        peers.insert(id, addr);
    }
    let fabric = flock_sync::TcpFabric::bind(sync.raft_bind, peers)
        .await
        .map_err(|e| format!("raft fabric bind {}: {e}", sync.raft_bind))?;
    eprintln!(
        "flock-server: raft fabric listening on {}",
        fabric
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );

    // 3. Assemble the SyncNode (voters = the whole root-signed directory;
    //    concurrent initialize from multiple nodes with the same config is
    //    safe).
    let bundle = verify_bundle(&bytes)?;
    let ident = Arc::new(bundle.identity()?);
    let directory = bundle.directory()?;
    let voters: Vec<u64> = directory
        .servers
        .iter()
        .map(|e| flock_sync::node::node_id_of(&e.server_id))
        .collect();
    let node = Arc::new(
        flock_sync::SyncNodeBuilder::new(
            flock_sync::SyncSettings::default(),
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

    // Graceful shutdown (A7/A5's docker stop = SIGTERM): Raft shutdown first
    // (stop replication, drain in-flight writes) then exit —— redb commits
    // are already transactionally durable; this further narrows the
    // in-flight write window.
    {
        let n = node.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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
            eprintln!("flock-server: signal exit - Raft graceful shutdown");
            let _ = n.shutdown().await;
            std::process::exit(0);
        });
    }

    // 4. Cluster bootstrap endpoint (bound **before** the ready wait, the
    //    §4-1 layout order): the submission channel for root-signed
    //    Bootstrap/SetOprf —— the admin endpoint (9444) starts with
    //    ServerCore only after Bootstrap applies, yet the submission itself
    //    must be able to arrive first (the chicken-and-egg solution: a
    //    dedicated channel straight to node.write). Port = admin + 1.
    let boot_bind = bootstrap_bind_of(cfg.admin_bind);
    serve_bootstrap_ep(node.clone(), boot_bind)
        .await
        .map_err(|e| format!("bootstrap endpoint bind {boot_bind}: {e}"))?;
    eprintln!("flock-server: cluster bootstrap endpoint on {boot_bind} (root-signed submissions straight to Raft)");

    // 5. ServerCore (waits for Bootstrap+SetOprf to apply; the operations-side
    //    cluster-bootstrap may come before or after).
    let core = wait_cluster_ready(cfg.clone(), ident, node.clone()).await?;

    // 6. The server's own peer surface: tun + local delivery/return path
    //    (§2.2).
    wire_local_peer(&core, &node).await;

    // 7. Listener + admin (isomorphic to the single-server run). The router
    //    is pre-set ⇒ run() does not open a same-named tun a second time.
    core.set_router(crate::dataplane::PeerRouter::none());
    run(core, mode).await
}

/// Admin port + 1 (the default slot of the dedicated cluster-bootstrap
/// channel; 9444 → 9445).
fn bootstrap_bind_of(admin: std::net::SocketAddr) -> std::net::SocketAddr {
    let mut a = admin;
    a.set_port(admin.port() + 1);
    a
}

/// Cluster bootstrap endpoint: accepts only
/// [`crate::admin::AdminRequest::SignedWrite`] (Bootstrap/SetOprf/
/// RecordInvite —— signature verification inside the state machine) and
/// `Stats`, going straight to `SyncNode::write`. Lives for the process
/// lifetime (coexisting with admin; the CLI `cluster-bootstrap`/
/// `cluster-invite` fall back to it while admin is not up).
async fn serve_bootstrap_ep(
    node: Arc<flock_sync::SyncNode>,
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
    node: &Arc<flock_sync::SyncNode>,
    io: &mut tokio::net::TcpStream,
) -> std::io::Result<()> {
    // Same framing protocol as admin.rs ([u32 LE len][postcard
    // AdminRequest]).
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
        crate::admin::AdminRequest::SignedWrite { req } => match node.write(req).await {
            Ok(r) => crate::admin::AdminResponse::WriteReceipt {
                text: format!("{r:?}"),
            },
            Err(e) => crate::admin::AdminResponse::Err { msg: e.to_string() },
        },
        crate::admin::AdminRequest::Stats => {
            // Pre-ready surface: leader/epoch (local view) —— for layout
            // liveness probing.
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
            msg: format!("bootstrap endpoint does not accept this request ({other:?} surface)"),
        },
    };
    let out = postcard::to_allocvec(&resp).map_err(|e| std::io::Error::other(e.to_string()))?;
    io.write_all(&(out.len() as u32).to_le_bytes()).await?;
    io.write_all(&out).await?;
    io.flush().await
}

/// Wait for the bundle file to appear (enroll may precede or follow
/// startup).
async fn wait_bundle(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let deadline = std::time::Instant::now() + BUNDLE_WAIT;
    loop {
        match std::fs::read(path) {
            Ok(b) => return Ok(b),
            Err(_) if std::time::Instant::now() < deadline => {
                eprintln!(
                    "flock-server: waiting for enrollment bundle {} (continues automatically after enroll; {:?} left)",
                    path.display(),
                    deadline.saturating_duration_since(std::time::Instant::now())
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        }
    }
}

/// ServerCore (waits for cluster readiness: Bootstrap + this server's OPRF
/// wrap applied on this node).
///
/// Only transient errors are retried (prefixed by
/// [`crate::server::SYNC_NOT_READY_PREFIX`] —— the wrap has not replicated
/// yet); permanent errors (review item 2: a wrap unsealing failure = this
/// node's hybrid private key does not match the wrap, retrying is pointless)
/// propagate immediately.
async fn wait_cluster_ready(
    cfg: ServerConfig,
    ident: Arc<ServerIdentity>,
    node: Arc<flock_sync::SyncNode>,
) -> Result<Arc<ServerCore>, String> {
    let deadline = std::time::Instant::now() + CLUSTER_READY_WAIT;
    loop {
        match ServerCore::open_sync(cfg.clone(), ident.clone(), node.clone()).await {
            Ok(core) => return Ok(core),
            Err(e)
                if e.starts_with(crate::server::SYNC_NOT_READY_PREFIX)
                    && std::time::Instant::now() < deadline =>
            {
                eprintln!("flock-server: {e} - retrying in 2s");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) if e.starts_with(crate::server::SYNC_NOT_READY_PREFIX) => {
                return Err(format!(
                    "cluster not ready within 600s (Bootstrap/local OPRF wrap not applied): {e}"
                ))
            }
            Err(e) => return Err(e), // permanent error (unsealing failure etc.) - propagate now
        }
    }
}

/// The server's own peer surface (§2.2):
/// - `set_local_peer`: inbound packets with dst = own VIP → the tun write
///   pump (A2 ping / A4 iperf);
/// - return-path read pump: tun output (ICMP returns / local stack traffic)
///   → `SyncNode::route_outbound`.
///
/// No tun (a deployment without NET_ADMIN) ⇒ log and skip (control-flow
/// only; the device↔device forwarding surface is unaffected).
pub async fn wire_local_peer(core: &Arc<ServerCore>, node: &Arc<flock_sync::SyncNode>) {
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
            // The device handle is kept alive (the interface lives with the
            // handle).
            std::mem::forget(tun);
            eprintln!(
                "flock-server: local peer wired vip={vip} (dst=local VIP into kernel + return path into mesh)"
            );
        }
        None => {
            eprintln!("flock-server: no tun - local VIP delivery degraded (cross-server forwarding unaffected)")
        }
    }
}

/// The tun write-pump sink (the ForwardPlane local-delivery seam).
struct KernelSink(tokio::sync::mpsc::Sender<Vec<u8>>);

impl flock_sync::PacketSink for KernelSink {
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
    let b = crate::bundle::NodeBundle::from_bytes(bytes).ok_or("bundle file failed to decode")?;
    b.verify().map(|_| b)
}
