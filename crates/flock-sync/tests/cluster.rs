//! tests/cluster: 3-node in-memory cluster (injected RTT 100ms), eight
//! assertions (docs/design.md §7-M4, this batch's completion gate).
//!
//! 1. Write on any node → linearizable read on any node, visible ≤2s
//!    (including the revocation record);
//! 2. kill leader → re-election ≤15s with no lost commits;
//! 3. same device dual-server lease conflict → newest wins + old-side
//!    eviction callback;
//! 4. register→revoke→register, IP never reused;
//! 5. server_keys→rewrap round trip (envelope v2 wrapping → state machine
//!    persistence → the target server unwraps);
//! 6. after a revoke commits, each node's apply callback advances the epoch +
//!    kill-session hook ≤2s;
//! 7. **apply-lag breaker** — inject a revocation while a follower lags 5s ⇒
//!    the cache is refused (degraded linearizable read) and new handshakes
//!    are rejected (§4 stale-read boundary / R24); 7b. **full partition** —
//!    after the cut (including established sessions) the revocation is still
//!    blocked (heartbeat-silence breaker + fail-closed); after rejoining and
//!    catching up it becomes visible;
//! 8. the ticket key root is inside Raft: A signs, B verifies; after a
//!    revocation it is invalid network-wide (epoch).
//!
//! RTT injection = 50ms per-direction line delay (§7-M4 100ms calibration);
//! node failure = MemoryFabric::cut.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use flock_protocol::session::{ClusterId, DeviceId, LookupVerdict, ServerId, ServerIdentity};
use flock_protocol::trust::ClusterDirectory;
use sha2::{Digest, Sha256};

use flock_sync::hooks::HookRecorder;
use flock_sync::proto::{
    AdminAck, NodeId, ReadQuery, ReadView, ServerKeyEntry, StateError, SyncRequest, SyncResponse,
    VerdictW,
};
use flock_sync::testutil::{FabricRegistry, MemoryFabric};
use flock_sync::ticket::TicketError;
use flock_sync::{SyncNode, SyncNodeBuilder, SyncSettings};

/// 50ms per direction ⇒ RTT 100ms.
const RTT_HALF: Duration = Duration::from_millis(50);
const NODES: [u64; 3] = [1, 2, 3];

/// NodeId ↔ ServerId (same mapping as flock_sync::wire::sid_of).
fn sid(n: NodeId) -> ServerId {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&n.to_be_bytes());
    ServerId(b)
}

fn dev_id(ed: &[u8; 32]) -> DeviceId {
    DeviceId(Sha256::digest(ed).into())
}

async fn must_write(node: &SyncNode, req: SyncRequest) -> SyncResponse {
    node.write(req).await.expect("write")
}

/// 3-node test cluster (shared root key / root-signed directory / fabric
/// registry).
struct Cluster {
    root: SigningKey,
    nodes: Vec<SyncNode>,
    recorders: Vec<Arc<HookRecorder>>,
    reg: FabricRegistry,
    idents: Vec<Arc<ServerIdentity>>,
    _tmp: tempfile::TempDir,
}

impl Cluster {
    async fn new() -> Cluster {
        Cluster::new_tuned(|_| {}).await
    }

    /// Build with tuning (the full-partition negative case shortens the
    /// write/read forwarding budget — the fail-closed assertion doesn't drag
    /// out to the full 12s).
    async fn new_tuned(tune: impl FnOnce(&mut SyncSettings)) -> Cluster {
        let root = SigningKey::from_bytes(&[7u8; 32]);
        let cluster_id = ClusterId([9u8; 16]);
        let reg = MemoryFabric::registry();
        let tmp = tempfile::tempdir().expect("tmpdir");
        let mut settings = SyncSettings::default();
        tune(&mut settings);

        // Root-signed directory (the public part of the enrollment
        // credentials — the material source of mutual interconnect
        // authentication).
        let mut idents = Vec::new();
        let mut entries = Vec::new();
        for &n in &NODES {
            let ident = Arc::new(ServerIdentity::enroll(
                &root,
                cluster_id,
                sid(n),
                &format!("node-{n}.test:9443"),
            ));
            entries.push(ident.entry.clone());
            idents.push(ident);
        }
        let directory = ClusterDirectory::issue(&root, cluster_id, 1, entries);

        let mut nodes = Vec::new();
        let mut recorders = Vec::new();
        for (i, ident) in idents.iter().enumerate() {
            let fabric = MemoryFabric::new(ident.server_id, &reg, RTT_HALF, 2 * 1024 * 1024);
            let rec = HookRecorder::new();
            let node = SyncNodeBuilder::new(
                settings.clone(),
                ident.clone(),
                directory.clone(),
                fabric,
                tmp.path().join(format!("node{}.redb", NODES[i])),
            )
            .voters(&NODES)
            .hook(rec.clone())
            .build()
            .await
            .expect("node build");
            nodes.push(node);
            recorders.push(rec);
        }
        Cluster {
            root,
            nodes,
            recorders,
            reg,
            idents,
            _tmp: tmp,
        }
    }

    /// Wait for a leader to appear and return **its own** index (≤15s) —
    /// "some node knows the leader" ≠ the leader itself.
    async fn leader(&self) -> (usize, NodeId) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            for n in &self.nodes {
                if let Some(l) = n.current_leader().await {
                    if l == n.id()
                        && matches!(
                            n.raft().metrics().borrow().state,
                            openraft::ServerState::Leader
                        )
                    {
                        let idx = self
                            .nodes
                            .iter()
                            .position(|x| x.id() == l)
                            .expect("leader in nodes");
                        return (idx, l);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("no leader elected within 15s");
    }
}

/// Bootstrap the cluster identity (the ticket key root goes into Raft).
async fn bootstrap(cluster: &Cluster, node_idx: usize) {
    let resp = must_write(
        &cluster.nodes[node_idx],
        SyncRequest::bootstrap_signed(&cluster.root, [9; 16], [42; 32]),
    )
    .await;
    assert!(matches!(resp, SyncResponse::Ok), "bootstrap: {resp:?}");
}

// ============================================================================
// 1. Write on any node → linearizable read on any node ≤2s (including the
//    revocation record)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_any_read_any_linearizable_within_2s() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, _) = cluster.leader().await;
    // Pick non-leader nodes for both the writer and the reader (write
    // forwarding + read forwarding paths).
    let writer = (leader_idx + 1) % 3;
    let reader = (leader_idx + 2) % 3;

    let t0 = Instant::now();
    let resp = must_write(
        &cluster.nodes[writer],
        SyncRequest::RegisterDevice {
            owner: "alice".into(),
            x25519: [1; 32],
            ed25519: [1; 32],
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(row) = resp else {
        panic!()
    };
    let id = dev_id(&[1; 32]);
    let v = cluster.nodes[reader]
        .read_linearizable(ReadQuery::Lookup(id.0))
        .await
        .expect("read");
    let elapsed = t0.elapsed();
    assert!(
        matches!(v, ReadView::Verdict(VerdictW::Active { .. })),
        "visible via a linearizable read on any node: {v:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(2),
        "write→read ≤2s (actual {:?})",
        elapsed
    );
    assert_eq!(
        row.vip,
        flock_sync::VIP_FIRST.to_be_bytes(),
        "first VIP = 100.64.0.11 (.1–.10 reserved for servers, §6.2)"
    );

    // The revocation record is likewise linearizably visible ≤2s.
    let t1 = Instant::now();
    must_write(&cluster.nodes[writer], SyncRequest::Revoke { device: id.0 }).await;
    let v = cluster.nodes[reader]
        .read_linearizable(ReadQuery::Lookup(id.0))
        .await
        .expect("read");
    assert!(
        matches!(v, ReadView::Verdict(VerdictW::Revoked { .. })),
        "revocation record linearizably visible: {v:?}"
    );
    assert!(
        t1.elapsed() <= Duration::from_secs(2),
        "revocation write→read ≤2s (actual {:?})",
        t1.elapsed()
    );
}

// ============================================================================
// 2. kill leader → re-election ≤15s with no lost commits
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_leader_reelects_within_15s_no_lost_writes() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, leader_id) = cluster.leader().await;

    // First write 5 confirmed commits (via a non-leader node — the write
    // forwarding path).
    for i in 0..5u8 {
        let resp = must_write(
            &cluster.nodes[(leader_idx + 1) % 3],
            SyncRequest::RegisterDevice {
                owner: format!("u{i}"),
                x25519: [i; 32],
                ed25519: [i + 1; 32],
                hostname: String::new(),
                registered_at_unix: 1_700_000_000,
            },
        )
        .await;
        assert!(matches!(resp, SyncResponse::Device(_)));
    }

    // kill leader: Raft shutdown + fabric cut (dial refused).
    cluster.nodes[leader_idx]
        .shutdown()
        .await
        .expect("leader shutdown");
    MemoryFabric::cut(&cluster.reg, &sid(leader_id));

    // Re-election ≤15s (election timeout 1.5~3s + RTT 100ms).
    let t0 = Instant::now();
    let mut new_leader = None;
    while Instant::now() - t0 < Duration::from_secs(15) {
        for (i, n) in cluster.nodes.iter().enumerate() {
            if i == leader_idx {
                continue;
            }
            if let Some(l) = n.current_leader().await {
                if l != leader_id {
                    new_leader = Some((i, l));
                }
            }
        }
        if new_leader.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (_ni, _nl) = new_leader.expect("re-elected within 15s");
    assert!(
        t0.elapsed() <= Duration::from_secs(15),
        "re-election {:?}",
        t0.elapsed()
    );

    // No lost commits: a linearizable read via a surviving follower (read
    // forwarding) = all 5 devices on the books.
    let survivor = (leader_idx + 1) % 3;
    let view = cluster.nodes[survivor]
        .read_linearizable(ReadQuery::State)
        .await
        .expect("read");
    let ReadView::State(st) = view else { panic!() };
    assert_eq!(st.devices, 5, "no lost commits (5 registered)");

    // The new leader keeps accepting writes.
    let resp = must_write(
        &cluster.nodes[survivor],
        SyncRequest::RegisterDevice {
            owner: "post".into(),
            x25519: [9; 32],
            ed25519: [9; 32],
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    assert!(
        matches!(resp, SyncResponse::Device(_)),
        "the new leader accepts writes: {resp:?}"
    );
}

// ============================================================================
// 3. Same device dual-server lease conflict → newest wins + old-side eviction
//    callback
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_conflict_newer_wins_old_side_evicted() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let _ = cluster.leader().await;
    let device = [0xab; 32];

    // Node 1 publishes first (the device is connected to node 1).
    cluster.nodes[0].publish_lease(&device).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        cluster.nodes[1].lease().observe(&device).unwrap().holder,
        1,
        "the lease propagated to node 2"
    );

    // Node 2 publishes a newer lease for the same device ⇒ newest wins +
    // node 1's eviction callback (event push ≤1s + anti-entropy backstop).
    let t0 = Instant::now();
    cluster.nodes[1].publish_lease(&device).await;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if cluster.recorders[0].evictions().contains(&device) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        cluster.recorders[0].evictions().contains(&device),
        "old side (node 1) eviction callback fired (actual {:?})",
        cluster.recorders[0].evictions()
    );
    assert!(
        t0.elapsed() <= Duration::from_secs(3),
        "eviction callback ≤3s (actual {:?})",
        t0.elapsed()
    );
    // Newest wins: observe on every node consistently points to node 2.
    for n in &cluster.nodes {
        assert_eq!(
            n.lease().observe(&device).unwrap().holder,
            2,
            "newest wins (node {})",
            n.id()
        );
    }
}

// ============================================================================
// 4. register→revoke→register, IP never reused
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_revoke_register_ip_never_reused() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, _) = cluster.leader().await;
    let writer = (leader_idx + 1) % 3;

    let a = must_write(
        &cluster.nodes[writer],
        SyncRequest::RegisterDevice {
            owner: "u".into(),
            x25519: [1; 32],
            ed25519: [1; 32],
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(a) = a else { panic!() };
    let id_a = dev_id(&[1; 32]);
    must_write(
        &cluster.nodes[writer],
        SyncRequest::Revoke { device: id_a.0 },
    )
    .await;

    let b = must_write(
        &cluster.nodes[writer],
        SyncRequest::RegisterDevice {
            owner: "u".into(),
            x25519: [2; 32],
            ed25519: [2; 32],
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(b) = b else { panic!() };
    let (ia, ib) = (u32::from_be_bytes(a.vip), u32::from_be_bytes(b.vip));
    assert!(
        ib > ia,
        "IP not reused: the watermark only moves forward ({ia} → {ib})"
    );
    // Re-registering the same device rejected (disable does not delete: the
    // Revoked terminal row is retained).
    let again = cluster.nodes[writer]
        .write(SyncRequest::RegisterDevice {
            owner: "u".into(),
            x25519: [1; 32],
            ed25519: [1; 32],
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        })
        .await
        .expect("write ok");
    assert!(
        matches!(again, SyncResponse::Error(StateError::DeviceExists)),
        "{again:?}"
    );
}

// ============================================================================
// 5. server_keys→rewrap round trip (an OPAQUE-like secret → envelope v2 →
//    state machine → the target server unwraps)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_keys_rewrap_roundtrip() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, _) = cluster.leader().await;
    let writer = (leader_idx + 2) % 3;

    // The target server = node 2 (the wrapping target = the hybrid public key
    // inside its enrollment credential).
    let target_entry = &cluster.idents[1].entry;
    let entries = vec![ServerKeyEntry {
        server_id: 2,
        identity_pub: *target_entry.identity_pub.as_bytes(),
        hybrid_pub: target_entry.static_hybrid_pub.to_bytes().to_vec(),
        vip: [100, 64, 0, 2],
    }];

    // No root signature (foreign-signed) ⇒ state-machine rejection (a
    // compromised in-register server holds no root key and cannot trigger a
    // rewrap).
    let forged_root = SigningKey::from_bytes(&[8u8; 32]);
    let bad = cluster.nodes[writer]
        .write(SyncRequest::server_keys_signed(
            &forged_root,
            entries.clone(),
        ))
        .await
        .expect("write ok");
    assert!(
        matches!(bad, SyncResponse::Error(StateError::BadRootSignature)),
        "foreign-signed server_keys rejected: {bad:?}"
    );
    let bad_rw = cluster.nodes[writer]
        .write(SyncRequest::rewrap_signed(&forged_root, 2, vec![1, 2, 3]))
        .await
        .expect("write ok");
    assert!(
        matches!(bad_rw, SyncResponse::Error(StateError::BadRootSignature)),
        "foreign-signed rewrap rejected: {bad_rw:?}"
    );

    // Root-signed server_keys lands.
    let resp = must_write(
        &cluster.nodes[writer],
        SyncRequest::server_keys_signed(&cluster.root, entries),
    )
    .await;
    assert!(
        matches!(resp, SyncResponse::ServerKeys { servers: 1 }),
        "{resp:?}"
    );

    // The OPAQUE-like secret → envelope v2 wrapped to node 2's hybrid public
    // key → root-signed rewrap committed.
    let secret = b"opaque-oprf-key-material-32-bytes!!!";
    let mut wrapped = Vec::new();
    flock_protocol::envelope::seal_v2(&target_entry.static_hybrid_pub, &secret[..], &mut wrapped)
        .expect("seal");
    let resp = must_write(
        &cluster.nodes[writer],
        SyncRequest::rewrap_signed(&cluster.root, 2, wrapped.clone()),
    )
    .await;
    let SyncResponse::Admin(AdminAck::Rewrap {
        server_id: 2,
        bytes,
    }) = resp
    else {
        panic!()
    };
    assert_eq!(
        bytes,
        wrapped.len(),
        "OPRF key copy count +1 observable (wrapped byte count recorded)"
    );

    // Node 2 linearizably reads out the wrapped copy and unwraps it with its
    // own static hybrid private key → the original secret.
    let view = cluster.nodes[1]
        .read_linearizable(ReadQuery::Wrap(2))
        .await
        .expect("read");
    let ReadView::Wrap(Some(got)) = view else {
        panic!("wrap landed: {view:?}")
    };
    assert_eq!(got, wrapped, "the wrapped copy landed verbatim");
    let mut opened = Vec::new();
    flock_protocol::envelope::open_v2(&cluster.idents[1].static_hybrid, &got[..], &mut opened)
        .expect("open");
    assert_eq!(
        opened, secret,
        "rewrap round trip: the target server unwraps the original secret"
    );
}

// ============================================================================
// 6. After a revoke commits, each node's apply callback advances the epoch +
//    kill-session hook ≤2s
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_apply_callback_epoch_and_kill_hook_within_2s() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, _) = cluster.leader().await;
    let writer = (leader_idx + 1) % 3;

    let resp = must_write(
        &cluster.nodes[writer],
        SyncRequest::RegisterDevice {
            owner: "bob".into(),
            x25519: [3; 32],
            ed25519: [3; 32],
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(_) = resp else {
        panic!()
    };
    let id = dev_id(&[3; 32]);

    // A ticket issued before the revocation (epoch = 0) — for the
    // outstanding-ticket rejection assertion.
    let pre_ticket = cluster.nodes[writer]
        .issue_ticket(id.0, 1_000)
        .expect("ticket");

    // Commit→apply budget: the clock starts when the write response returns
    // (the commit point observable by the client). Taking it before the write
    // lets write-path latency (leader forwarding + follower dial races during
    // cluster warm-up) eat into the 2s budget although commit→apply itself
    // was fast — a startup-race flake, not a product budget violation.
    let resp = must_write(&cluster.nodes[writer], SyncRequest::Revoke { device: id.0 }).await;
    let t_commit = Instant::now();
    let SyncResponse::Epoch(new_epoch) = resp else {
        panic!()
    };
    assert!(new_epoch >= 1, "the revocation advanced revocation_epoch");

    // Apply callback on every node (including followers) ≤2s: epoch advanced
    // + kill-session hook fired.
    for (i, rec) in cluster.recorders.iter().enumerate() {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let events: Vec<_> = rec
                .revocations()
                .into_iter()
                .filter(|e| e.device == id.0)
                .collect();
            if let Some(ev) = events.last() {
                assert_eq!(
                    ev.new_epoch,
                    new_epoch,
                    "node {} epoch advanced consistently",
                    i + 1
                );
                break;
            }
            assert!(
                Instant::now() <= deadline,
                "node {} did not fire the kill-session hook within 2s (events {:?})",
                i + 1,
                rec.revocations()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            t_commit.elapsed() <= Duration::from_secs(2),
            "node {} callback ≤2s (actual {:?})",
            i + 1,
            t_commit.elapsed()
        );
    }
    // The ticket's epoch is invalidated with it (the ticket-side data surface
    // of outstanding-ticket rejection: a ticket issued before the revocation
    // ⇒ StaleEpoch).
    assert!(matches!(
        cluster.nodes[writer].verify_ticket(&pre_ticket, &id.0, 1_001),
        Err(TicketError::StaleEpoch { .. })
    ));
    let _ = new_epoch;
}

// ============================================================================
// 7. apply-lag breaker: inject a revocation while a follower lags 5s ⇒ cache
//    refused + new handshakes rejected
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_lag_breaker_rejects_cache_and_new_handshake() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, _) = cluster.leader().await;
    let writer = (leader_idx + 1) % 3;
    let lagger_idx = (leader_idx + 2) % 3;
    let lagger = &cluster.nodes[lagger_idx];

    // The device key uses a real Ed25519 public key ([4;32] is an illegal
    // point ⇒ to_verdict fails closed).
    let dev = SigningKey::from_bytes(&[4u8; 32]);
    let dev_pub = *dev.verifying_key().as_bytes();
    let resp = must_write(
        &cluster.nodes[writer],
        SyncRequest::RegisterDevice {
            owner: "carol".into(),
            x25519: [4; 32],
            ed25519: dev_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(_) = resp else {
        panic!()
    };
    let id = dev_id(&dev_pub);

    // Warm the cache: after one successful lookup, the device is Active in
    // the lagging follower's cache.
    let v = lagger.dir().lookup_async(id).await;
    assert!(
        matches!(v, LookupVerdict::Active(_)),
        "warm-up: lookup gives Active ({v:?})"
    );
    let v = lagger.dir().lookup_async(id).await;
    assert!(matches!(v, LookupVerdict::Active(_)));

    // Artificially make the follower lag 5s: apply stalls (network and log
    // flow as usual).
    lagger.sm().lag.arm(Duration::from_secs(5));
    tokio::time::sleep(Duration::from_millis(300)).await;

    // During that window, inject a revocation (committed by the leader +
    // healthy followers; the lagging follower falls behind).
    must_write(&cluster.nodes[writer], SyncRequest::Revoke { device: id.0 }).await;

    // Breaker: observing leader_commit > applied persisting >2s ⇒ opens.
    let deadline = Instant::now() + Duration::from_secs(4);
    while !lagger.breaker_open() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(lagger.breaker_open(), "apply-lag >2s ⇒ breaker opens");

    // Cache refused: that follower's directory lookup takes the degraded
    // linearizable path (forwarded to the leader) ⇒ Revoked. "New handshakes
    // rejected" — session::respond consumes the same directory verdict;
    // Revoked ⇒ DeviceRejected.
    let stats_before = lagger.dir().stats();
    let t_lookup = Instant::now();
    let v = lagger.dir().lookup_async(id).await;
    let stats_after = lagger.dir().stats();
    assert!(
        matches!(v, LookupVerdict::Revoked { .. }),
        "degraded linearizable read ⇒ revocation visible (new handshakes rejected): {v:?}"
    );
    assert!(
        stats_after.breaker_degraded > stats_before.breaker_degraded,
        "breaker-path count advanced (before={:?} after={:?})",
        stats_before,
        stats_after
    );
    assert!(
        stats_after.cache_hits == stats_before.cache_hits,
        "local cache refused while the breaker is open (cache_hits does not advance)"
    );
    assert!(
        t_lookup.elapsed() <= Duration::from_secs(2),
        "degraded read within budget"
    );

    // Control: the healthy follower (not lagging) is unaffected by the
    // breaker — after the epoch advances the cache invalidates, and it also
    // reports Revoked.
    let v2 = cluster.nodes[writer].dir().lookup_async(id).await;
    assert!(matches!(v2, LookupVerdict::Revoked { .. }));

    // After catching up the breaker recovers (the apply stall ends ⇒ applied
    // catches up to leader_commit).
    lagger.sm().lag.disarm();
    let deadline = Instant::now() + Duration::from_secs(8);
    while lagger.breaker_open() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!lagger.breaker_open(), "breaker recovers after catching up");
    assert_eq!(
        lagger.local_epoch(),
        1,
        "the lagging node eventually applies (epoch advanced)"
    );
}

// ============================================================================
// 7b. Full-partition negative case: after the cut the revocation is still
//     blocked, the cache refused (heartbeat-silence dimension)
// ============================================================================

/// During a full partition (cut = refuse new dials + sever established E2E
/// session bridges — the observation stream vanishes), a revocation committed
/// on the leader side must not slip through the cut node's local cache:
/// silence beyond max(lag_threshold, election_timeout) ⇒ breaker opens ⇒
/// cache refused; under the partition a linearizable read is unreachable ⇒
/// fail-closed (NotFound ⇒ handshake refused, never falling back to a stale
/// Active). Backdating semantics on partition recovery: the first frame after
/// recovery still finds it open (pending backdated); once apply catches up it
/// closes and the revocation becomes visible.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_partition_breaker_blocks_revoked_cache_until_rejoin() {
    let cluster = Cluster::new_tuned(|s| s.forward_deadline = Duration::from_secs(3)).await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, _) = cluster.leader().await;
    let writer = (leader_idx + 1) % 3;
    let cut_idx = (leader_idx + 2) % 3;
    let cut_node = &cluster.nodes[cut_idx];
    let cut_id = cut_node.id();

    // Register a device (real Ed25519 public key) and warm the cache on the
    // follower about to be cut (Active).
    let dev = SigningKey::from_bytes(&[6u8; 32]);
    let dev_pub = *dev.verifying_key().as_bytes();
    let resp = must_write(
        &cluster.nodes[writer],
        SyncRequest::RegisterDevice {
            owner: "eve".into(),
            x25519: [6; 32],
            ed25519: dev_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    assert!(matches!(resp, SyncResponse::Device(_)));
    let id = dev_id(&dev_pub);
    let v = cut_node.dir().lookup_async(id).await;
    assert!(matches!(v, LookupVerdict::Active(_)), "warm-up: {v:?}");
    let v = cut_node.dir().lookup_async(id).await;
    assert!(matches!(v, LookupVerdict::Active(_)), "cache hit: {v:?}");
    assert!(cut_node.dir().stats().cache_hits >= 1);

    // —— Full partition: cut the follower (new dials refused + established
    //     session bridges severed) ——
    MemoryFabric::cut(&cluster.reg, &sid(cut_id));

    // During the partition the other two nodes (still quorate) commit a
    // revocation.
    must_write(&cluster.nodes[writer], SyncRequest::Revoke { device: id.0 }).await;

    // Heartbeat silence > max(2s, 3s) ⇒ breaker opens (this covers the blind
    // spot where leader_commit frozen == applied).
    let deadline = Instant::now() + Duration::from_secs(8);
    while !cut_node.breaker_open() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        cut_node.breaker_open(),
        "full partition (no observation at all) ⇒ silence breaker"
    );

    // The revocation is still blocked: cache refused (cache_hits does not
    // advance) + linearizable read unreachable under the partition ⇒
    // fail-closed (NotFound ⇒ handshake refused — never letting a stale
    // Active through).
    let before = cut_node.dir().stats();
    let v = cut_node.dir().lookup_async(id).await;
    let after = cut_node.dir().stats();
    assert!(
        matches!(v, LookupVerdict::NotFound),
        "the partitioned node fails closed (not a stale Active): {v:?}"
    );
    assert_eq!(
        after.cache_hits, before.cache_hits,
        "local cache refused while the breaker is open"
    );
    assert!(
        after.breaker_degraded > before.breaker_degraded,
        "breaker-path count advanced"
    );

    // —— Partition recovery: uncut (severed connections must re-dial — the
    //     interconnect rebuilds automatically) ——
    MemoryFabric::uncut(&cluster.reg, &sid(cut_id));
    // Backdating semantics: recovery's first frame observes leader_commit >>
    // applied ⇒ still open immediately; once apply catches up it closes.
    let deadline = Instant::now() + Duration::from_secs(12);
    while cut_node.breaker_open() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !cut_node.breaker_open(),
        "breaker closes after recovery catch-up"
    );
    // Caught up ⇒ epoch advanced ⇒ cache invalidated ⇒ the linearizable read
    // returns Revoked (the revocation finally visible).
    let v = cut_node.dir().lookup_async(id).await;
    assert!(
        matches!(v, LookupVerdict::Revoked { .. }),
        "revocation visible after recovery: {v:?}"
    );
    assert_eq!(cut_node.local_epoch(), 1, "the cut node eventually applies");
}

// ============================================================================
// 8. The ticket key root is inside Raft: A signs, B verifies; after a
//    revocation invalid network-wide (epoch)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ticket_root_in_raft_cross_node_and_epoch_invalidation() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, _) = cluster.leader().await;
    let writer = (leader_idx + 1) % 3;

    let resp = must_write(
        &cluster.nodes[writer],
        SyncRequest::RegisterDevice {
            owner: "dave".into(),
            x25519: [5; 32],
            ed25519: [5; 32],
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(_) = resp else {
        panic!()
    };
    let id = dev_id(&[5; 32]).0;

    // A (the writer) issues; after waiting for Bootstrap/registration to
    // apply network-wide (≤3s), A/B/C can all verify — the ticket key root is
    // replicated inside Raft state; any server can verify.
    let ticket = cluster.nodes[writer]
        .issue_ticket(id, 1_000)
        .expect("ticket");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let all_ok = cluster
            .nodes
            .iter()
            .all(|n| n.verify_ticket(&ticket, &id, 1_001).is_ok());
        if all_ok {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ticket verifiable network-wide within 3s (root replication)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The revocation advances the epoch ⇒ the old ticket invalid network-wide
    // (StaleEpoch — outstanding-ticket rejection).
    must_write(&cluster.nodes[writer], SyncRequest::Revoke { device: id }).await;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let all_stale = cluster.nodes.iter().all(|n| {
            matches!(
                n.verify_ticket(&ticket, &id, 1_002),
                Err(TicketError::StaleEpoch { .. })
            )
        });
        if all_stale {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ticket invalid network-wide within 3s (epoch propagation)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
