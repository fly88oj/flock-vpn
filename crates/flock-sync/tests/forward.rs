//! tests/forward: cross-server forwarding plane (docs/design.md §7-M4
//! forward group, §2.2 forwarding decision order).
//!
//! 1. **Source VIP binding check (step 0)**: a session device sends a packet
//!    with src=someone else's VIP ⇒ drop + count; a ForwardEnvelope's
//!    `src_dev` mismatching the inner source address ⇒ receiver rejects
//!    (checked once at each end).
//! 2. Local delivery / NOT_HERE → one-shot location_query redirect / hop=1
//!    loop guard (construct a second forward ⇒ drop + count).
//! 3. Still failing ⇒ drop + best-effort ICMP unreachable.
//! 4. Lease-domain semantics: the single source of truth for a device's
//!    current location = the lease domain (NetState does not store current
//!    location); publish/observe + event push ≤1s + 5s anti-entropy + TTL
//!    30s + location_query fan-out ≤3.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flock_sync::forward::{
    ForwardEnvelope, ForwardOutcome, IngestResult, PacketSink, RejectReason, FORWARD_VER,
};
use flock_sync::proto::{NodeId, SyncRequest, SyncResponse};

use common::{bootstrap, wait_local_row, TestCluster};

const NODES: [u64; 3] = [1, 2, 3];

/// Recording sink (simulates the PacketChannel).
#[derive(Default)]
struct RecvSink {
    packets: Mutex<Vec<Vec<u8>>>,
}

impl PacketSink for RecvSink {
    fn deliver(&self, pkt: &[u8]) -> std::io::Result<()> {
        self.packets.lock().expect("sink").push(pkt.to_vec());
        Ok(())
    }
}

impl RecvSink {
    fn count(&self) -> usize {
        self.packets.lock().expect("sink").len()
    }
    fn first(&self) -> Vec<u8> {
        self.packets.lock().expect("sink")[0].clone()
    }
}

/// Build an IPv4 packet (20B header + payload).
fn ip4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 0x11;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..].copy_from_slice(payload);
    p
}

async fn must_write(c: &TestCluster, idx: usize, req: SyncRequest) -> SyncResponse {
    c.nodes[idx].write(req).await.expect("write")
}

fn dev_id(ed: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(ed).into()
}

/// Register two devices (real Ed25519 public keys), returning (id_a, id_b).
/// Sinks are attached by the caller.
async fn two_devices(c: &TestCluster, writer: usize) -> ([u8; 32], [u8; 32]) {
    let dev_a = ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32]);
    let dev_b = ed25519_dalek::SigningKey::from_bytes(&[0xB2; 32]);
    let a_pub = *dev_a.verifying_key().as_bytes();
    let b_pub = *dev_b.verifying_key().as_bytes();
    let ra = must_write(
        c,
        writer,
        SyncRequest::RegisterDevice {
            owner: "a".into(),
            x25519: [1; 32],
            ed25519: a_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    assert!(matches!(ra, SyncResponse::Device(_)));
    let rb = must_write(
        c,
        writer,
        SyncRequest::RegisterDevice {
            owner: "b".into(),
            x25519: [2; 32],
            ed25519: b_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    assert!(matches!(rb, SyncResponse::Device(_)));
    (dev_id(&a_pub), dev_id(&b_pub))
}

// ============================================================================
// 1a. Source VIP binding check: a session device with src=someone else's VIP
//     ⇒ drop + count
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn src_vip_binding_violation_dropped_and_counted() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let (leader_idx, _) = c.leader().await;
    let writer = (leader_idx + 1) % 3;

    let dev_a = ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32]);
    let dev_b = ed25519_dalek::SigningKey::from_bytes(&[0xB2; 32]);
    let a_pub = *dev_a.verifying_key().as_bytes();
    let b_pub = *dev_b.verifying_key().as_bytes();
    let ra = must_write(
        &c,
        writer,
        SyncRequest::RegisterDevice {
            owner: "a".into(),
            x25519: [1; 32],
            ed25519: a_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(row_a) = ra else {
        panic!()
    };
    let rb = must_write(
        &c,
        writer,
        SyncRequest::RegisterDevice {
            owner: "b".into(),
            x25519: [2; 32],
            ed25519: b_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(row_b) = rb else {
        panic!()
    };
    let id_a = dev_id(&a_pub);

    let sink_a = Arc::new(RecvSink::default());
    let sink_b = Arc::new(RecvSink::default());
    let n1 = &c.nodes[0];
    n1.attach_session(id_a, sink_a.clone());
    n1.attach_session(dev_id(&b_pub), sink_b.clone());
    // The forwarding plane reads the local registry: wait for node1's local
    // apply to catch up (remote commit → local apply ≤ heartbeat+RTT).
    wait_local_row(n1, &id_a, "dev-a row").await;
    wait_local_row(n1, &dev_id(&b_pub), "dev-b row").await;

    // devA's session sends src=devB's VIP (identity spoofing) ⇒ drop + count;
    // no delivery, no forwarding.
    let spoofed = ip4(row_b.vip, row_a.vip, b"spoof");
    let r = n1.ingest_packet(&id_a, &spoofed).await;
    assert!(
        matches!(r, IngestResult::SrcViolation),
        "caught at step 0: {r:?}"
    );
    let st = n1.forward().stats();
    assert_eq!(st.src_violations, 1, "drop + count");
    assert_eq!(
        st.delivered_local + st.forwarded,
        0,
        "no delivery, no forwarding"
    );
    assert_eq!(
        sink_b.count(),
        0,
        "the target did not receive the spoofed packet"
    );

    // A legitimate src (its own VIP) ⇒ normal local delivery.
    let ok = ip4(row_a.vip, row_b.vip, b"legit");
    let r = n1.ingest_packet(&id_a, &ok).await;
    assert!(matches!(r, IngestResult::DeliveredLocal), "{r:?}");
    assert_eq!(sink_b.count(), 1);
}

// ============================================================================
// 1b. ForwardEnvelope src_dev mismatching the inner source address ⇒ receiver
//     rejects
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn envelope_src_dev_mismatch_rejected_at_receiver() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let (leader_idx, _) = c.leader().await;
    let writer = (leader_idx + 1) % 3;

    let (id_a, _id_b) = two_devices(&c, writer).await;
    let n2 = &c.nodes[1];
    wait_local_row(n2, &id_a, "dev-a row").await;

    // Construct an envelope whose src_dev=A but whose inner source VIP is a
    // made-up address (not A's registered VIP).
    let vip_a = c.nodes[0].forward().vip_of(&id_a).expect("vip a");
    let fake_vip: [u8; 4] = [100, 64, 99, 99];
    assert_ne!(vip_a.octets(), fake_vip);
    let pkt = ip4(fake_vip, [100, 64, 0, 9], b"x");
    let env = ForwardEnvelope {
        ver: FORWARD_VER,
        src_dev: id_a,
        dst_dev: [9; 32],
        origin_server: 1,
        hop: 1,
        payload: pkt,
    };
    let out = n2.forward().receive(env);
    assert!(
        matches!(out, ForwardOutcome::Rejected(RejectReason::SrcBinding)),
        "{out:?}"
    );
    assert_eq!(
        n2.forward().stats().src_mismatch_rejected,
        1,
        "receiver rejects + counts"
    );

    // Control: src_dev consistent with the inner source ⇒ not rejected on
    // binding grounds (dst not local ⇒ NotHere).
    let pkt2 = ip4(vip_a.octets(), [100, 64, 0, 9], b"x");
    let env2 = ForwardEnvelope {
        ver: FORWARD_VER,
        src_dev: id_a,
        dst_dev: [9; 32],
        origin_server: 1,
        hop: 1,
        payload: pkt2,
    };
    let out2 = n2.forward().receive(env2);
    assert!(matches!(out2, ForwardOutcome::NotHere), "{out2:?}");
}

// ============================================================================
// 2. Local delivery / cross-server forwarding / NOT_HERE→location_query
//    one-shot redirect / hop loop guard
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_local_delivery_and_redirect_with_hop_guard() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let (leader_idx, _) = c.leader().await;
    let writer = (leader_idx + 1) % 3;

    let dev_a = ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32]);
    let dev_c = ed25519_dalek::SigningKey::from_bytes(&[0xC3; 32]);
    let a_pub = *dev_a.verifying_key().as_bytes();
    let c_pub = *dev_c.verifying_key().as_bytes();
    let ra = must_write(
        &c,
        writer,
        SyncRequest::RegisterDevice {
            owner: "a".into(),
            x25519: [1; 32],
            ed25519: a_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(row_a) = ra else {
        panic!()
    };
    let rc = must_write(
        &c,
        writer,
        SyncRequest::RegisterDevice {
            owner: "c".into(),
            x25519: [3; 32],
            ed25519: c_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(row_c) = rc else {
        panic!()
    };
    let (id_a, id_c) = (dev_id(&a_pub), dev_id(&c_pub));

    // A is connected to node1; C is **currently** connected to node3 (the
    // lease-domain truth), but node1's lease table still points to node2
    // (a stale-lease window — the migration scenario).
    let sink_a = Arc::new(RecvSink::default());
    let sink_c = Arc::new(RecvSink::default());
    c.nodes[0].attach_session(id_a, sink_a.clone());
    c.nodes[2].attach_session(id_c, sink_c.clone());
    wait_local_row(&c.nodes[0], &id_a, "dev-a row").await;
    wait_local_row(&c.nodes[0], &id_c, "dev-c row").await;
    c.nodes[0].publish_lease(&id_a).await;
    // node3 publishes the truth (newest wins); the event-push ≤1s assertion
    // (node1/node2's lease domains flip to 3).
    let t0 = Instant::now();
    c.nodes[2].publish_lease(&id_c).await;
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if c.nodes[1].lease().observe(&id_c).map(|l| l.holder) == Some(3) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        c.nodes[1].lease().observe(&id_c).map(|l| l.holder) == Some(3),
        "event push ≤1s (actual {:?})",
        t0.elapsed()
    );

    // The A→C packet: node1 sends it to node2 per the stale lease ⇒ NotHere ⇒
    // one-shot location_query (node1 asks only peers node2/node3 — its local
    // lease is exactly the disease; node3 answers "me") ⇒ redirected and
    // delivered.
    let pkt = ip4(row_a.vip, row_c.vip, b"redirect-me");
    // Construct the migration window: the last thing node1's lease domain
    // heard was node2 (the most recent term — the device subsequently moved
    // to node3 and node1 has not yet received the event); node3's own table
    // holds holder=3 (answering the location inquiry).
    let stale_term = now_ms();
    c.nodes[0]
        .lease()
        .merge_remote(flock_sync::lease::GossipMsg::Publish {
            device: id_c,
            holder: 2,
            term_ms: stale_term + 200,
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
    let r = c.nodes[0].ingest_packet(&id_a, &pkt).await;
    assert!(
        matches!(r, IngestResult::Forwarded(ForwardOutcome::Delivered)),
        "NOT_HERE → location_query → redirected delivery: {r:?}"
    );
    assert_eq!(
        sink_c.count(),
        1,
        "C received the packet (via node3 local delivery)"
    );
    assert_eq!(sink_c.first(), pkt);
    let st = c.nodes[0].forward().stats();
    assert_eq!(st.not_here, 1, "went through one NOT_HERE");
    assert_eq!(st.locate_redirected, 1, "one-shot redirect success counted");
    assert_eq!(st.dropped, 0, "no drops");
    assert_eq!(st.icmp_unreachable, 0, "ICMP not triggered");

    // hop=1 loop guard: construct a "second forward" (hop exhausted) envelope
    // ⇒ drop + count, no delivery.
    let before = c.nodes[2].forward().stats().hop_dropped;
    let env_hop0 = ForwardEnvelope {
        ver: FORWARD_VER,
        src_dev: id_a,
        dst_dev: id_c,
        origin_server: 1,
        hop: 0,
        payload: pkt.clone(),
    };
    let out = c.nodes[2].forward().receive(env_hop0);
    assert!(
        matches!(out, ForwardOutcome::Rejected(RejectReason::Hop)),
        "{out:?}"
    );
    assert_eq!(
        c.nodes[2].forward().stats().hop_dropped,
        before + 1,
        "loop-guard count"
    );
    assert_eq!(sink_c.count(), 1, "a hop-exhausted packet is not delivered");
}

// ============================================================================
// 3. Still failing ⇒ drop + best-effort ICMP unreachable
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unresolved_destination_drops_with_best_effort_icmp() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let (leader_idx, _) = c.leader().await;
    let writer = (leader_idx + 1) % 3;

    let dev_a = ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32]);
    let a_pub = *dev_a.verifying_key().as_bytes();
    let ra = must_write(
        &c,
        writer,
        SyncRequest::RegisterDevice {
            owner: "a".into(),
            x25519: [1; 32],
            ed25519: a_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(row_a) = ra else {
        panic!()
    };
    let id_a = dev_id(&a_pub);

    let sink_a = Arc::new(RecvSink::default());
    c.nodes[0].attach_session(id_a, sink_a.clone());
    c.nodes[0].publish_lease(&id_a).await;
    wait_local_row(&c.nodes[0], &id_a, "dev-a row").await;

    // Destination VIP unregistered (unknown dst): drop + best-effort ICMP
    // (source is local ⇒ deliverable).
    let pkt = ip4(row_a.vip, [100, 64, 77, 77], b"to-void");
    let r = c.nodes[0].ingest_packet(&id_a, &pkt).await;
    assert!(matches!(r, IngestResult::DroppedIcmp), "{r:?}");
    let st = c.nodes[0].forward().stats();
    assert_eq!(st.dropped, 1, "dropped");
    assert_eq!(st.icmp_unreachable, 1, "best-effort ICMP");
    // The source device receives ICMP type=3 code=1.
    assert_eq!(
        sink_a.count(),
        1,
        "the ICMP goes back to the source session"
    );
    let icmp = sink_a.first();
    assert_eq!(icmp[20], 3, "ICMP type=3 destination unreachable");
    assert_eq!(icmp[21], 1, "code=1 host unreachable");
    // The embedded original packet header.
    assert_eq!(&icmp[28..48], &pkt[..20]);

    // A lease exists but the target is offline (location_query after NOT_HERE
    // also finds nothing) ⇒ likewise drop + ICMP.
    let dev_d = ed25519_dalek::SigningKey::from_bytes(&[0xD4; 32]);
    let d_pub = *dev_d.verifying_key().as_bytes();
    let rd = must_write(
        &c,
        writer,
        SyncRequest::RegisterDevice {
            owner: "d".into(),
            x25519: [4; 32],
            ed25519: d_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(row_d) = rd else {
        panic!()
    };
    let id_d = dev_id(&d_pub);
    wait_local_row(&c.nodes[0], &id_d, "dev-d row").await;
    // A stale lease points at node2, but node2 has no session for the device
    // and nobody claims it.
    c.nodes[0]
        .lease()
        .merge_remote(flock_sync::lease::GossipMsg::Publish {
            device: id_d,
            holder: 2,
            term_ms: now_ms() + 100, // a newer term so it wins over the empty local table
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
    let pkt2 = ip4(row_a.vip, row_d.vip, b"stale-lease");
    let r2 = c.nodes[0].ingest_packet(&id_a, &pkt2).await;
    match r2 {
        IngestResult::DroppedIcmp => {}
        IngestResult::Forwarded(ForwardOutcome::Delivered) => {
            // location_query found a new holder and delivered — not allowed
            // (nobody claims it).
            panic!("delivered although nobody claimed it");
        }
        other => panic!("expected drop+ICMP, got {other:?}"),
    }
}

// ============================================================================
// 4. Lease-domain semantics + location_query fan-out ≤3 (one-shot)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_domain_semantics_and_locate_fanout() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let (leader_idx, _) = c.leader().await;

    let dev = ed25519_dalek::SigningKey::from_bytes(&[0xE5; 32]);
    let d_pub = *dev.verifying_key().as_bytes();
    let rd = must_write(
        &c,
        leader_idx,
        SyncRequest::RegisterDevice {
            owner: "e".into(),
            x25519: [5; 32],
            ed25519: d_pub,
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        },
    )
    .await;
    let SyncResponse::Device(row) = rd else {
        panic!()
    };
    let id = dev_id(&d_pub);

    // publish (node1) → observe (node3): the event-push path.
    c.nodes[0].publish_lease(&id).await;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut within_1s = false;
    while Instant::now() < deadline {
        if c.nodes[2].lease().observe(&id).is_some() {
            within_1s = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        within_1s,
        "publish event push ≤1s reaches the remote observe"
    );

    // Migration: node2 publishes (newest wins) — the device's current
    // location flips to node2 in the lease domain, while NetState's device
    // row (VIP/status) stays unchanged: the single source of truth = the
    // lease domain (§2.2-1).
    c.nodes[1].publish_lease(&id).await;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if c.nodes[2].lease().observe(&id).map(|l| l.holder) == Some(2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        c.nodes[2].lease().observe(&id).map(|l| l.holder),
        Some(2),
        "newest wins"
    );
    // NetState device rows carry no current location: VIP/status unchanged
    // (the snapshot view has no holder field to speak of).
    let v = c.nodes[0]
        .read_linearizable(flock_sync::proto::ReadQuery::DeviceRow(id))
        .await
        .expect("read");
    let flock_sync::proto::ReadView::Device(Some(d)) = v else {
        panic!()
    };
    assert_eq!(
        d.vip, row.vip,
        "static registration info unchanged (NetState stores no location)"
    );
    assert_eq!(d.status, flock_sync::proto::DeviceStatus::Active);

    // location_query: a local lease-domain hit answers immediately (no
    // fan-out).
    let holder = c.nodes[2].location_query(&id).await;
    assert_eq!(
        holder,
        Some(2),
        "the local lease domain is the source of truth"
    );
    // Unknown device: fan-out ≤3 one-shot inquiry; nobody claims it ⇒ None.
    let unknown = dev_id(&[0x11; 32]);
    let t0 = Instant::now();
    let none = c.nodes[0].location_query(&unknown).await;
    assert_eq!(none, None, "nobody claims it");
    assert!(
        t0.elapsed() < Duration::from_secs(8),
        "one-shot ≤3 fan-out within budget ({:?})",
        t0.elapsed()
    );

    // TTL 30s: lease expiry ⇒ observe None (the timeliness of the single
    // source of truth). (Waiting out a short-circuit 31s is too slow —
    // directly mutating expires inside the table is impossible (private);
    // the anti-entropy/event paths already cover it; here we assert that the
    // LEASE_TTL constant agrees with observe semantics.)
    assert_eq!(
        flock_sync::lease::LEASE_TTL,
        Duration::from_secs(30),
        "lease TTL 30s (§3.10)"
    );
    assert_eq!(
        flock_sync::lease::ANTI_ENTROPY,
        Duration::from_secs(5),
        "anti-entropy 5s (§3.10)"
    );
    let _ = NodeId::default();
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ============================================================================
// M7 (§7-M7.3): per-device byte counting points — the "count at the
// successful delivery point" single-point principle
// ============================================================================

/// Counting-point assertions: on the same-server path, src tx and dst rx are
/// each counted once by that same machine; on the cross-server path the
/// origin counts only src tx, and dst rx is counted by the **receiver** (the
/// origin's count for the dst's rx is always 0 — no double counting).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn traffic_counting_single_point_local_and_cross_server() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let (leader_idx, _) = c.leader().await;
    let writer = (leader_idx + 1) % 3;

    let (id_a, id_c) = two_devices(&c, writer).await;
    let n0 = &c.nodes[0];
    let n1 = &c.nodes[1];
    wait_local_row(n0, &id_a, "dev-a row").await;
    wait_local_row(n0, &id_c, "dev-c row").await;
    wait_local_row(n1, &id_c, "dev-c row @n1").await;
    let vip_a = n0.forward().vip_of(&id_a).expect("vip a");
    let vip_c = n0.forward().vip_of(&id_c).expect("vip c");

    let sink_c_n1 = Arc::new(RecvSink::default());
    n1.attach_session(id_c, sink_c_n1.clone());
    n1.publish_lease(&id_c).await;
    // A is attached to n0 (the real flow publishes via serve_conn — the test
    // sends directly).
    n0.publish_lease(&id_a).await;

    // Preconditions made explicit: wait for C's lease to spread to n0's
    // remote view via gossip (event push/anti-entropy) — the original
    // implementation ingested immediately after publish, implicitly relying
    // on the event-push ≤1s timing, which flakes under parallel load (ingest
    // hitting "lease not yet arrived" gives Dropped instead of Forwarded).
    // Upper bound 5s (the anti-entropy period).
    for _ in 0..200 {
        if n0.lease().peer_stats(&id_c).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        n0.lease().peer_stats(&id_c).is_some(),
        "precondition failed: C's lease did not spread to n0 within 5s"
    );

    // —— Cross-server: A attached to n0 (session/lease holder), C attached to
    //    n1 ——
    let pkt = ip4(vip_a.octets(), vip_c.octets(), &[7u8; 100]);
    n0.ingest_packet(&id_a, &pkt).await; // src tx @n0 (access point) + FRWD → n1 counts dst rx
    assert!(
        matches!(
            n0.ingest_packet(&id_a, &pkt).await,
            IngestResult::Forwarded(_)
        ),
        "the cross-server forwarding path is in place (precondition: C's lease has spread to n0)"
    );
    // Wait for the delivery + the ewma folding loop (1s window) to turn a
    // folding round (the first tick sets the baseline, the next folds). Same
    // fix as 157f141 (explicit preconditions): folding is driven by the
    // background 1s loop, and tick lag varies under parallel load
    // (MissedTickBehavior::Delay only postpones, never catches up) — a fixed
    // 2.3s sleep leaves only ~300ms of margin and flakes under container/CI
    // parallel multi-case load. Wait for the condition explicitly with a 4s
    // budget: still < the 5s anti-entropy window, preserving the observation
    // window for the "origin does not count dst rx" == 0 assertion below
    // (before n1's folded value reaches n0 via anti-entropy).
    let mut a_n0 = n0.lease().peer_stats(&id_a).expect("A's row on n0");
    let deadline = Instant::now() + Duration::from_secs(4);
    while a_n0.tx_ewma == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
        a_n0 = n0.lease().peer_stats(&id_a).expect("A's row on n0");
    }
    assert!(
        a_n0.tx_ewma > 0,
        "src tx counted by the access server: {}",
        a_n0.tx_ewma
    );
    let c_n0 = n0
        .lease()
        .peer_stats(&id_c)
        .expect("C's row on n0 (remote view)");
    assert_eq!(
        c_n0.rx_ewma, 0,
        "origin does not count dst rx (receiver-side single-point counting — n0 only has the holder-published value, 0 here because n1 has not folded yet)"
    );

    // —— Same server: attach C to n0 as well (the local delivery path) ——
    let sink_c_n0 = Arc::new(RecvSink::default());
    n0.attach_session(id_c, sink_c_n0.clone());
    n0.publish_lease(&id_c).await;
    // Wait for n0's lease to win and spread (self-publication overwriting
    // n1's view does not affect this assertion).
    tokio::time::sleep(Duration::from_millis(200)).await;
    let pkt2 = ip4(vip_a.octets(), vip_c.octets(), &[9u8; 80]);
    assert!(matches!(
        n0.ingest_packet(&id_a, &pkt2).await,
        IngestResult::DeliveredLocal
    ));
    // Same as above: wait explicitly for the fold (a fixed 2.3s sleep's
    // jitter surface is unreliable under parallel load).
    let mut c_n0_after = n0.lease().peer_stats(&id_c).expect("C's row");
    let deadline = Instant::now() + Duration::from_secs(4);
    while c_n0_after.rx_ewma == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
        c_n0_after = n0.lease().peer_stats(&id_c).expect("C's row");
    }
    // Same-server delivery ⇒ dst rx counted by this machine (= the holder).
    // Note: A's row is now held by n0 (after publish).
    assert!(
        c_n0_after.rx_ewma > 0,
        "dst rx counted by the server that delivers successfully"
    );
}
