//! tests/admission: cluster admission and rewrap authorization
//! (docs/design.md §7-M4 admission group).
//!
//! 1. **Nodes without enrollment credentials / with forged credentials are
//!    rejected at the server-server handshake layer** — no snapshot, no Raft
//!    (§4-2: the openraft network adapter rides only on authenticated
//!    sessions; R19 red line — a fake node able to request snapshots and
//!    re-wraps would open a network-wide offline dictionary surface for
//!    passwords).
//! 2. **Learner joins → snapshot sync → add_voter (root key signature) →
//!    promoted to voter** (the §4-3 authorization path is pinned down: a
//!    learner only receives the replication stream; becoming a voter requires
//!    passing state-machine signature verification).
//! 3. **rewrap without a root signature ⇒ state-machine rejection; with the
//!    signature ⇒ the new server's hybrid public key enters the wrapping
//!    set** (the OPRF key copy count +1 is observable; a single compromised
//!    in-register server holds no root key and cannot trigger it).

mod common;

use std::time::{Duration, Instant};

use common::{bootstrap, sid, TestCluster};
use flock_protocol::session::{DeviceStaticKeys, ServerEntry, ServerPin, TunnelConfig};
use flock_protocol::trust::ClusterDirectory;
use flock_sync::wire::Fabric;

use flock_sync::proto::{
    AdminAck, NodeId, ReadQuery, ReadView, ServerKeyEntry, StateError, SyncRequest, SyncResponse,
};
use flock_sync::ticket::TicketIssuer;

const NODES: [u64; 3] = [1, 2, 3];

// ============================================================================
// 1. No credentials / forged credentials ⇒ rejected at the server-server
//    handshake layer
// ============================================================================

/// Dial a real server and initiate a session with "credential-free rogue
/// device material". `pin` decides the claimed target (only a real entry can
/// get through the KEM — an attacker can obtain the public material).
async fn rogue_handshake(
    c: &TestCluster,
    target: NodeId,
    pin_root: &ed25519_dalek::SigningKey,
    claimed_entry: ServerEntry,
) -> Result<flock_protocol::session::Tunnel, flock_protocol::session::SessionError> {
    let fabric =
        flock_sync::testutil::MemoryFabric::new(sid(0xABCD), &c.reg, common::RTT_HALF, 1024 * 1024);
    let io = fabric.dial(&sid(target)).await.expect("dial");
    let rogue = DeviceStaticKeys::generate();
    let pin = ServerPin {
        cluster_id: c.fx.cluster_id,
        cluster_root_pub: pin_root.verifying_key(),
        entry: claimed_entry,
    };
    flock_protocol::session::initiate(io, &rogue, &pin, TunnelConfig::default()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rogue_without_credential_rejected_at_handshake() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let _ = c.leader().await;

    // No credentials: a rogue holding random device keys initiates toward a
    // real entry (assemblable from public material) — the answer-side
    // PeerDirectory only accepts identities inside the root-signed directory
    // ⇒ rejected at the handshake layer. To the initiator this appears as an
    // opaque connection termination (flock-protocol's timing-alignment
    // design: DeviceRejected does not leak the specific reason).
    let target = c.node_of(2);
    let before = target.rejected_handshakes();
    let _ = rogue_handshake(&c, 2, &c.fx.root, target.entry().clone())
        .await
        .expect_err("a credential-free rogue must be rejected");
    // The answer side indeed rejected at the handshake layer (the count
    // advanced) — no session ⇒ cannot enter the dispatcher ⇒ no snapshot and
    // no Raft (§4-2).
    assert!(
        target.rejected_handshakes() > before,
        "answer-side handshake rejection count advanced (before={before}, after={})",
        target.rejected_handshakes()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rogue_with_forged_root_rejected_at_handshake() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let _ = c.leader().await;

    // Forged credentials: the rogue self-signs a root/credential set (a root
    // signed by someone else) — even with the claimed target entry being real
    // (the KEM can succeed), its "device identity" is not in this cluster's
    // root-signed directory ⇒ the answer side rejects at the handshake layer.
    let forged_root = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
    let target = c.node_of(3);
    let before = target.rejected_handshakes();
    let _ = rogue_handshake(&c, 3, &forged_root, target.entry().clone())
        .await
        .expect_err("a rogue with a foreign-signed root must be rejected");
    assert!(
        target.rejected_handshakes() > before,
        "answer-side handshake rejection count advanced"
    );
}

// ============================================================================
// 2. learner → snapshot sync → add_voter (root-signed) → promotion
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn learner_snapshot_add_voter_promotion() {
    let mut c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let (leader_idx, _) = c.leader().await;

    // Pre-seeded state: 2 devices + 1 revocation (epoch=1) — the snapshot
    // must carry all of it.
    for i in 1u8..=2 {
        let resp = c.nodes[(leader_idx + 1) % 3]
            .write(SyncRequest::RegisterDevice {
                owner: format!("u{i}"),
                x25519: [i; 32],
                ed25519: [i; 32],
                hostname: String::new(),
                registered_at_unix: 1_700_000_000,
            })
            .await
            .expect("register");
        assert!(matches!(resp, SyncResponse::Device(_)));
    }
    let dev1: [u8; 32] = sha(&[1u8; 32]);
    let resp = c.nodes[(leader_idx + 1) % 3]
        .write(SyncRequest::Revoke { device: dev1 })
        .await
        .expect("revoke");
    assert!(matches!(resp, SyncResponse::Epoch(1)));
    let expect_state = c.nodes[leader_idx]
        .read_linearizable(ReadQuery::State)
        .await
        .expect("leader state");
    let ReadView::State(ref st) = expect_state else {
        panic!()
    };

    // —— Admission pipeline (§4-3) ——
    // (a) Operations uses the root key to issue the new node's enrollment
    //     credential + a new directory (dir_version=2).
    let n4 = c.fx.enroll(4);
    let dir_v2 = c.fx.directory(
        2,
        &[
            c.idents[0].clone(),
            c.idents[1].clone(),
            c.idents[2].clone(),
            n4.clone(),
        ],
    );
    // (b) The existing nodes install the new directory (root verification +
    //     interconnect mapping hot update — only then can the leader dial the
    //     new node).
    for n in &c.nodes {
        n.install_directory(&dir_v2).expect("install dir v2");
    }
    // A directory signed by a different root ⇒ rejected (admission material
    // cannot be injected under a foreign signature).
    let other_root = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);
    let forged_dir =
        ClusterDirectory::issue(&other_root, c.fx.cluster_id, 3, vec![n4.entry.clone()]);
    assert!(
        c.nodes[0].install_directory(&forged_dir).is_err(),
        "foreign-signed directory rejected"
    );

    // dir_pull serve: what is distributed is the root-signed v2 directory
    // (the client's PinStore::record_directory can land it directly: root
    // verification + monotonic version); since=2 ⇒ no new content (304
    // semantics).
    let resp = c.nodes[0].directory().dir_pull_response(0);
    assert_eq!(resp.version, 2);
    let served = ClusterDirectory::from_bytes(&resp.bytes.expect("full dir")).expect("parse");
    assert!(
        served.verify(&c.fx.root.verifying_key()),
        "root-signed directory"
    );
    assert_eq!(served.servers.len(), 4);
    assert!(
        c.nodes[0].directory().dir_pull_response(2).bytes.is_none(),
        "304"
    );

    // (c) The new node joins as a learner (no initialize — not an initial
    //     member).
    let n4_idx = c.build_node(&n4, &dir_v2, None).await;

    // (d) The leader compacts the log (trigger snapshot + purge) ⇒ the
    //     learner can only take the snapshot-sync path.
    c.nodes[leader_idx]
        .snapshot_and_purge()
        .await
        .expect("snapshot+purge");

    // (e) add_learner (blocking: waits for replication/snapshot catch-up).
    c.nodes[leader_idx]
        .add_learner(4)
        .await
        .expect("add learner");

    // Snapshot-sync assertion: the learner's state machine received the full
    // state (devices/epoch/ticket root), and its log is empty (after the
    // purge only a snapshot can carry this state).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = c.nodes[n4_idx]
            .read_linearizable(ReadQuery::State)
            .await
            .expect("learner read");
        let ReadView::State(g) = got else { panic!() };
        if g.devices == 2
            && g.epoch == 1
            && g.ticket_root_present
            && g.last_applied.unwrap_or(0) > 0
        {
            assert_eq!(g.revoked, 1, "revocation record travels with the snapshot");
            assert_eq!(g.config_version, st.config_version);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "learner snapshot sync timed out (state={:?})",
            g
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The learner can read but cannot write (client_write forwards to the
    // leader — a non-voter does not vote; here we assert it is not yet in the
    // voters set).
    {
        let v = c.nodes[leader_idx]
            .read_linearizable(ReadQuery::State)
            .await
            .expect("state");
        let ReadView::State(g) = v else { panic!() };
        assert!(
            !g.voters.contains(&4),
            "node4 is not a voter before promotion"
        );
    }

    // (f) add_voter without a root signature ⇒ state-machine rejection + no
    //     promotion.
    let forged_root = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
    let bad = c.nodes[leader_idx]
        .add_voter_signed(&forged_root, 4)
        .await
        .expect("write ok");
    assert!(
        matches!(bad, SyncResponse::Error(StateError::BadRootSignature)),
        "foreign-signed add_voter rejected: {bad:?}"
    );
    {
        let v = c.nodes[leader_idx]
            .read_linearizable(ReadQuery::State)
            .await
            .expect("state");
        let ReadView::State(g) = v else { panic!() };
        assert!(
            !g.voters.contains(&4),
            "the rejection path does not promote"
        );
    }

    // (g) add_voter with a root signature ⇒ the state machine records it +
    //     openraft promotes (joint consensus).
    let ok = c.nodes[leader_idx]
        .add_voter_signed(&c.fx.root, 4)
        .await
        .expect("add voter");
    assert!(
        matches!(ok, SyncResponse::Admin(AdminAck::AddVoter { node_id: 4 })),
        "{ok:?}"
    );
    // Membership convergence: voters in metrics network-wide contain 4.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let m = c.nodes[n4_idx]
            .raft()
            .metrics()
            .borrow()
            .membership_config
            .clone();
        if m.membership().voter_ids().any(|v| v == 4) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "voter promotion did not converge"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // After promotion node4 can serve writes (any-node-write semantics) and
    // they are visible network-wide.
    let resp = c.nodes[n4_idx]
        .write(SyncRequest::RegisterDevice {
            owner: "n4".into(),
            x25519: [7; 32],
            ed25519: [7; 32],
            hostname: String::new(),
            registered_at_unix: 1_700_000_000,
        })
        .await
        .expect("voter write");
    assert!(matches!(resp, SyncResponse::Device(_)));
    let v = c.nodes[0]
        .read_linearizable(ReadQuery::State)
        .await
        .expect("read");
    let ReadView::State(g) = v else { panic!() };
    assert_eq!(g.devices, 3, "node4's write is visible network-wide");
}

// ============================================================================
// 3. rewrap ± root signature (the OPRF key copy count +1 is observable)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rewrap_requires_root_and_targets_new_server() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let (leader_idx, _) = c.leader().await;
    let writer = (leader_idx + 2) % 3;

    // The new server node4 enters the directory (the post-admission shape —
    // this test only exercises the rewrap authorization surface; no need to
    // enter Raft).
    let n4 = c.fx.enroll(4);
    let dir_v2 = c.fx.directory(
        2,
        &[
            c.idents[0].clone(),
            c.idents[1].clone(),
            c.idents[2].clone(),
            n4.clone(),
        ],
    );
    for n in &c.nodes {
        n.install_directory(&dir_v2).expect("install");
    }

    // No root signature ⇒ state-machine rejection (a compromised in-register
    // server holds no root key and cannot trigger a rewrap).
    let forged = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
    let bad = c.nodes[writer]
        .write(SyncRequest::rewrap_signed(&forged, 4, vec![1; 16]))
        .await
        .expect("write ok");
    assert!(
        matches!(bad, SyncResponse::Error(StateError::BadRootSignature)),
        "{bad:?}"
    );
    // Even with a root signature, rejected before server_keys is registered
    // (the wrapping target must be on the books — server_keys first, then
    // rewrap).
    let bad2 = c.nodes[writer]
        .write(SyncRequest::rewrap_signed(&c.fx.root, 4, vec![1; 16]))
        .await
        .expect("write ok");
    assert!(
        matches!(bad2, SyncResponse::Error(StateError::NotFound(_))),
        "{bad2:?}"
    );

    // server_keys (root-signed) registers the full set of hybrid public keys
    // (including the new server — node4 only entered the directory, not
    // Raft).
    let mut entries: Vec<ServerKeyEntry> = [1u64, 2, 3]
        .into_iter()
        .map(|n| {
            let e = c.node_of(n).entry().clone();
            ServerKeyEntry {
                server_id: n,
                identity_pub: *e.identity_pub.as_bytes(),
                hybrid_pub: e.static_hybrid_pub.to_bytes().to_vec(),
                vip: [100, 64, 0, n as u8],
            }
        })
        .collect();
    entries.push(ServerKeyEntry {
        server_id: 4,
        identity_pub: *n4.entry.identity_pub.as_bytes(),
        hybrid_pub: n4.entry.static_hybrid_pub.to_bytes().to_vec(),
        vip: [100, 64, 0, 4],
    });
    let resp = c.nodes[writer]
        .write(SyncRequest::server_keys_signed(&c.fx.root, entries))
        .await
        .expect("server_keys");
    assert!(
        matches!(resp, SyncResponse::ServerKeys { servers: 4 }),
        "{resp:?}"
    );

    // With the root signature ⇒ the wrapped copy +1 is observable (a node4
    // entry appears in the wraps set).
    let secret = b"opaque-oprf-key-material-32-bytes!!!";
    let mut wrapped = Vec::new();
    flock_protocol::envelope::seal_v2(&n4.entry.static_hybrid_pub, &secret[..], &mut wrapped)
        .expect("seal");
    let before = {
        let v = c.nodes[writer]
            .read_linearizable(ReadQuery::State)
            .await
            .expect("state");
        let ReadView::State(g) = v else { panic!() };
        g.wraps.len()
    };
    let resp = c.nodes[writer]
        .write(SyncRequest::rewrap_signed(&c.fx.root, 4, wrapped.clone()))
        .await
        .expect("rewrap");
    assert!(
        matches!(
            resp,
            SyncResponse::Admin(AdminAck::Rewrap { server_id: 4, .. })
        ),
        "{resp:?}"
    );
    let after = {
        let v = c.nodes[writer]
            .read_linearizable(ReadQuery::State)
            .await
            .expect("state");
        let ReadView::State(g) = v else { panic!() };
        g.wraps.clone()
    };
    assert_eq!(after.len(), before + 1, "OPRF key copy count +1 observable");
    assert!(
        after.iter().any(|(sid, _)| *sid == 4),
        "node4 enters the wrapping set"
    );

    // The new server can fetch and unwrap the copy with its own private key
    // (it genuinely received the OPRF key copy). node4 is not inside this
    // test cluster's process — verified locally with its identity material
    // (envelope v2 round trip).
    let mut opened = Vec::new();
    flock_protocol::envelope::open_v2(&n4.static_hybrid, &wrapped[..], &mut opened).expect("open");
    assert_eq!(opened, secret);

    // The ticket root is consistent across nodes (TicketIssuer already
    // landed with part one — re-proved here that a new-directory node can
    // verify).
    let t = c.nodes[writer]
        .issue_ticket(dev_id_of(&[8; 32]), 1_000)
        .expect("ticket");
    assert!(c.nodes[0]
        .verify_ticket(&t, &dev_id_of(&[8; 32]), 1_001)
        .is_ok());
    let _ = TicketIssuer::from_root(&[42; 32]); // key-root derivation determinism
}

fn sha(b: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(b).into()
}

fn dev_id_of(b: &[u8; 32]) -> [u8; 32] {
    sha(b)
}
