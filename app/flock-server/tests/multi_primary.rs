//! Multi-primary assembly integration tests (docs/design.md §2.2/§3.11 M4
//! batch; feature `multi-primary`).
//!
//! In-process 3-node in-memory cluster (`flock_sync::testutil::
//! MemoryFabric`, RTT 2×5ms):
//!
//! 1. **Full control plane**: redeem (Raft commit) → 1-RTT first
//!    connection (the **two-level-read directory**: respond injects
//!    `SyncNode::device_directory`) → OPAQUE login (anchor + **the
//!    Raft-shared OPRF**) → ticket = **the Raft key root**
//!    (`TicketWire::Sync`) → key-bind → SR-SIG1 TicketRenew;
//! 2. **Cross-server forwarding plane**: two clients ping each other
//!    through two servers —— server-A's packet channel → ForwardEnvelope
//!    (FRWD over the interconnect E2E session) → server-B delivery (the
//!    §2.2 decision order: step-0 source VIP check → lease location →
//!    cross-server forwarding);
//! 3. **Revocation propagation bound (A6 ≤5s)**: revoke submitted on the
//!    server-B side → the other server's (A's) new handshake rejected
//!    within ≤5s, and A's existing session killed by the apply callback
//!    (§2.2 (a)(b)(c)).

#![cfg(feature = "multi-primary")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use flock_protocol::mux::Prio;
use flock_protocol::pake::server_setup_new;
use flock_protocol::session::{
    initiate, DeviceId, DeviceStaticKeys, ServerEntry, ServerId, ServerPin, Tunnel, TunnelConfig,
};
use flock_protocol::sig::UserKey;
use flock_protocol::trust::{InviteFile, PinStore, PinVerdict};
use flock_protocol::{ed25519_dalek, rand};
use flock_server::config::ServerConfig;
use flock_server::netstate::RedeemRequest;
use flock_server::server::ServerCore;
use flock_server::ticket::TicketWire;
use flock_sync::hooks::HookRecorder;
use flock_sync::proto::{NodeId, SyncRequest};
use flock_sync::testutil::MemoryFabric;
use flock_sync::{SyncNode, SyncNodeBuilder, SyncSettings};

/// RTT = 2×5ms (the in-memory fabric; the 100ms calibration tier of §7-M4
/// belongs to flock-sync's own tests).
const FABRIC_DELAY: Duration = Duration::from_millis(5);
/// The A6 timing budget (§2.2: revocation propagation ≤5s in a healthy
/// cluster).
const A6_BUDGET: Duration = Duration::from_secs(5);

fn sid(n: NodeId) -> ServerId {
    flock_sync::wire::sid_of(n)
}

// ============================================================================
// Assembly: a 3-node cluster + the dual server stacks
// ============================================================================

struct Node3 {
    root: ed25519_dalek::SigningKey,
    cluster_id: flock_protocol::session::ClusterId,
    nodes: Vec<Arc<SyncNode>>,
    idents: Vec<Arc<flock_protocol::session::ServerIdentity>>,
    directory: flock_protocol::trust::ClusterDirectory,
    #[allow(dead_code)] // the observation surface kept (apply hook recorders)
    recorders: Vec<Arc<HookRecorder>>,
    _tmp: tempfile::TempDir,
}

async fn build_cluster() -> Node3 {
    let c3 = build_cluster_bare().await;
    // Per-server OPRF sealing (review item 2): ServerKeys root-signed
    // registers every server's hybrid public key → one envelope v2-sealed
    // Rewrap per server —— the state machine stores only wraps, no more
    // plaintext SetOprf (the §2.4 cross-node login semantics unchanged).
    let oprf_b64 = server_setup_new(&mut rand::rngs::OsRng);
    let leader = wait_leader(&c3.nodes).await;
    submit_wrapped_oprf(&leader, &c3.root, &c3.idents, &oprf_b64).await;
    // The sealed store is unreadable as plaintext (wire-format assertion):
    // the network-wide plaintext OPRF field is empty; the state summary has
    // only wraps (one per each of the 3 servers).
    for n in &c3.nodes {
        assert!(
            n.oprf_b64().is_none(),
            "the plaintext OPRF must not enter Raft state"
        );
    }
    let view = c3.nodes[0]
        .read_linearizable(flock_sync::proto::ReadQuery::State)
        .await
        .expect("state view");
    let flock_sync::proto::ReadView::State(v) = view else {
        panic!("state view shape: {view:?}")
    };
    assert_eq!(v.wraps.len(), 3, "one seal (rewrap) per server");
    c3
}

/// Assemble the 3-node cluster up to Bootstrap (the OPRF wrap submission's
/// subset is the caller's decision —— the review-item-2 cases of "no wrap
/// ⇒ the server fails / after rewrap it can unseal").
async fn build_cluster_bare() -> Node3 {
    let root = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let cluster_id = flock_protocol::session::ClusterId(rand::random());
    let voters: Vec<NodeId> = vec![1, 2, 3];
    let idents: Vec<Arc<flock_protocol::session::ServerIdentity>> = voters
        .iter()
        .map(|n| {
            Arc::new(flock_protocol::session::ServerIdentity::enroll(
                &root,
                cluster_id,
                sid(*n),
                &format!("node-{n}.test:9443"),
            ))
        })
        .collect();
    let entries: Vec<ServerEntry> = idents.iter().map(|i| i.entry.clone()).collect();
    let directory = flock_protocol::trust::ClusterDirectory::issue(&root, cluster_id, 1, entries);

    let reg = MemoryFabric::registry();
    let tmp = tempfile::tempdir().expect("tmpdir");
    let mut nodes = Vec::new();
    let mut recorders = Vec::new();
    for (i, ident) in idents.iter().enumerate() {
        let rec = HookRecorder::new();
        let fabric = MemoryFabric::new(ident.server_id, &reg, FABRIC_DELAY, 2 * 1024 * 1024);
        let node = SyncNodeBuilder::new(
            SyncSettings::default(),
            ident.clone(),
            directory.clone(),
            fabric,
            tmp.path().join(format!("db-{}.redb", i)),
        )
        .voters(&voters)
        .hook(rec.clone())
        .build()
        .await
        .expect("node build");
        nodes.push(Arc::new(node));
        recorders.push(rec);
    }

    // Bootstrap (the ticket root enters Raft, §4).
    let leader = wait_leader(&nodes).await;
    let ticket_root: [u8; 32] = rand::random();
    let boot = leader
        .write(SyncRequest::bootstrap_signed(
            &root,
            cluster_id.0,
            ticket_root,
        ))
        .await
        .expect("bootstrap");
    assert!(
        matches!(boot, flock_sync::proto::SyncResponse::Ok),
        "bootstrap: {boot:?}"
    );

    Node3 {
        root,
        cluster_id,
        nodes,
        idents,
        directory,
        recorders,
        _tmp: tmp,
    }
}

/// ServerKeys + per-server Rewrap submission (shared by build_cluster and
/// the rewrap-top-up test). Asserts: the state summary contains only wraps
/// (one per each of the 3 servers) and the network-wide plaintext oprf
/// field is empty (review item 2's "the sealed store is unreadable as
/// plaintext" wire-format assertion).
async fn submit_wrapped_oprf(
    leader: &Arc<SyncNode>,
    root: &ed25519_dalek::SigningKey,
    idents: &[Arc<flock_protocol::session::ServerIdentity>],
    oprf_b64: &str,
) {
    let entries: Vec<flock_sync::proto::ServerKeyEntry> = idents
        .iter()
        .map(|i| {
            let node_id = flock_sync::node::node_id_of(&i.server_id);
            flock_sync::proto::ServerKeyEntry {
                server_id: node_id,
                identity_pub: *i.identity.verifying_key().as_bytes(),
                hybrid_pub: i.static_hybrid.public().to_bytes().to_vec(),
                vip: flock_sync::proto::server_vip_of(node_id).expect("node 1..=10"),
            }
        })
        .collect();
    let resp = leader
        .write(SyncRequest::server_keys_signed(root, entries))
        .await
        .expect("server keys");
    assert!(
        matches!(
            resp,
            flock_sync::proto::SyncResponse::ServerKeys { servers } if servers == idents.len()
        ),
        "server_keys: {resp:?}"
    );
    for ident in idents {
        let node_id = flock_sync::node::node_id_of(&ident.server_id);
        let wrapped = flock_server::server::seal_oprf_wrap(oprf_b64, &ident.static_hybrid.public())
            .expect("seal");
        let resp = leader
            .write(SyncRequest::rewrap_signed(root, node_id, wrapped))
            .await
            .expect("rewrap");
        assert!(
            matches!(
                resp,
                flock_sync::proto::SyncResponse::Admin(flock_sync::proto::AdminAck::Rewrap { .. })
            ),
            "rewrap: {resp:?}"
        );
    }
}

async fn wait_leader(nodes: &[Arc<SyncNode>]) -> Arc<SyncNode> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        for n in nodes {
            if let Some(l) = n.current_leader().await {
                if l == n.id() {
                    return n.clone();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no leader elected within 15s");
}

/// A server stack (respond/control flow/forwarding plane) hung onto a raft
/// node.
struct SyncServer {
    core: Arc<ServerCore>,
    #[allow(dead_code)] // endpoint consumed via pin_for
    endpoint: String,
}

async fn serve_on(c3: &Node3, idx: usize, extra_endpoints: Vec<String>) -> SyncServer {
    let tmp = tempfile::tempdir().expect("tmp");
    let state_dir = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = l.local_addr().unwrap().to_string();
    // VIP = this node's deterministically derived value (server_vip_of ——
    // required by open_sync's consistency assertion; the old configs
    // hard-coding .1 for nodes 2/3 were the "registered VIP ≠ actually
    // configured VIP" misaligned shape).
    let node_id = flock_sync::node::node_id_of(&c3.idents[idx].server_id);
    let vip =
        std::net::Ipv4Addr::from(flock_sync::proto::server_vip_of(node_id).expect("node 1..=10"));
    let cfg = sync_server_cfg(state_dir, endpoint.clone(), extra_endpoints, vip);
    let core = ServerCore::open_sync(cfg, c3.idents[idx].clone(), c3.nodes[idx].clone())
        .await
        .expect("open_sync");
    tokio::spawn(core.clone().serve_listener(l));
    SyncServer { core, endpoint }
}

/// The ServerConfig shared by serve_on / the direct open_sync tests
/// (assembly goes through open_sync, not the config-file path).
fn sync_server_cfg(
    state_dir: std::path::PathBuf,
    advertise_endpoint: String,
    extra_endpoints: Vec<String>,
    vip: std::net::Ipv4Addr,
) -> ServerConfig {
    ServerConfig {
        state_dir,
        bind: "127.0.0.1:9443".parse().unwrap(),
        mode: "direct".into(),
        advertise_endpoint,
        extra_endpoints,
        dir_version: 1,
        ticket_ttl_secs: 60,
        peer_retention_days: 30,
        admin_bind: "127.0.0.1:0".parse().unwrap(),
        max_sessions: 1024,
        tun_name: "tun0".into(),
        vip,
        frp: None,
        sync: None,
        webui: flock_server::config::WebUiSection {
            enabled: false,
            ..Default::default()
        },
    }
}

/// The client pin: the root-signed directory entry as the identity anchor,
/// **with the dial address swapped for the TCP listen port** (the
/// directory's `node-N.test:9443` is the interconnect fabric endpoint; the
/// access endpoint and this test's dial port share the machine but not the
/// position —— I1's signature anchor is identity_pub, the endpoint string
/// never enters the signed surface).
fn pin_for(c3: &Node3, server_idx: usize, dial: &str) -> ServerPin {
    let mut entry = c3.directory.servers[server_idx].clone();
    entry.relay_endpoint = dial.to_string();
    ServerPin {
        cluster_id: c3.cluster_id,
        cluster_root_pub: c3.root.verifying_key(),
        entry,
    }
}

async fn connect(device: &DeviceStaticKeys, pin: &ServerPin) -> Tunnel {
    let io = tokio::net::TcpStream::connect(&pin.entry.relay_endpoint)
        .await
        .expect("tcp");
    initiate(io, device, pin, TunnelConfig::default())
        .await
        .expect("1-RTT initiate (the two-level-read directory passes it)")
}

// ============================================================================
// The client control-flow driver (reusing the server crate's protocol
// surface; only the subset this test needs)
// ============================================================================

mod cli {
    use super::*;
    use flock_protocol::sig as sr_sig;
    use flock_server::control::{recv_ctrl_msg, send_ctrl_msg, CtrlRequest, CtrlResponse};

    pub struct Ctrl {
        pub tunnel: Tunnel,
        stream: flock_protocol::mux::Stream,
    }

    impl Ctrl {
        pub async fn open(tunnel: Tunnel) -> Self {
            let stream = tunnel
                .open_stream(Prio::Control)
                .await
                .expect("ctrl stream");
            Ctrl { tunnel, stream }
        }

        pub async fn req(&mut self, r: CtrlRequest) -> CtrlResponse {
            send_ctrl_msg(&mut self.stream, &r).await.expect("send");
            recv_ctrl_msg(&mut self.stream).await.expect("recv")
        }

        /// Set the password (PwBegin/PwCommit —— the replication-form
        /// SetPassword).
        pub async fn set_password(&mut self, user: &str, pw: &str) -> CtrlResponse {
            let mut rng = rand::rngs::OsRng;
            let (state, m1) = flock_protocol::pake::reg_start(&mut rng, pw, user).unwrap();
            let resp = self
                .req(CtrlRequest::PwBegin {
                    user: user.into(),
                    m1_b64: m1,
                })
                .await;
            let CtrlResponse::PwChallenge { m2_b64 } = resp else {
                panic!("pw begin shape: {resp:?}")
            };
            let record =
                flock_protocol::pake::reg_finish(&mut rng, state, pw, user, &m2_b64).unwrap();
            self.req(CtrlRequest::PwCommit {
                record_b64: record,
                profile: 0,
            })
            .await
        }

        /// OPAQUE login (anchor verification) → (ticket, bind_token).
        pub async fn login(
            &mut self,
            user: &str,
            pw: &str,
            pin: &ServerPin,
        ) -> Result<(TicketWire, [u8; 16]), String> {
            let mut rng = rand::rngs::OsRng;
            let (state, ke1) = flock_protocol::pake::login_start(&mut rng, pw, user).unwrap();
            let resp = self
                .req(CtrlRequest::LoginBegin {
                    user: user.into(),
                    ke1_b64: ke1,
                })
                .await;
            let CtrlResponse::LoginChallenge {
                ke2_b64,
                bind_token,
                anchor_sig,
            } = resp
            else {
                return Err(format!("login begin shape: {resp:?}"));
            };
            let ke3 = flock_server::control::client_login_finish_anchored(
                state,
                pw,
                user,
                &ke2_b64,
                flock_server::control::AnchorLoginExpectation {
                    server_id: pin.entry.server_id.0,
                    identity_pub: pin.entry.identity_pub,
                    bind_token,
                    anchor_sig,
                },
            )
            .map_err(|e| format!("anchor: {e}"))?;
            match self.req(CtrlRequest::LoginFinish { ke3_b64: ke3 }).await {
                CtrlResponse::LoginOk { ticket, .. } => Ok((ticket, bind_token)),
                CtrlResponse::Err { code, msg } => Err(format!("{code:?}: {msg}")),
                other => Err(format!("login ok: {other:?}")),
            }
        }

        /// key-bind (device public keys + the SR-SIG1 public key; ticket +
        /// one-time bind_token + device signature).
        pub async fn key_bind(
            &mut self,
            ticket: &TicketWire,
            bind_token: [u8; 16],
            user: &str,
            cluster_id: &[u8; 16],
            dev: &DeviceStaticKeys,
            sr: &UserKey,
        ) -> CtrlResponse {
            use ed25519_dalek::Signer as _;
            let device = flock_server::control::DevicePubs {
                x25519: dev.x25519_public().to_bytes(),
                ed25519: *dev.ed25519_public().as_bytes(),
                hostname: String::new(),
            };
            let sr_pub = *sr_sig::UserKey::from_pub_string(&sr.pub_string())
                .unwrap()
                .as_bytes();
            let canon = flock_server::control::keybind_canonical(
                cluster_id,
                user,
                &bind_token,
                &device,
                &sr_pub,
            );
            let seed = dev.to_bytes();
            let sk = ed25519_dalek::SigningKey::from_bytes(seed[32..64].try_into().unwrap());
            self.req(CtrlRequest::KeyBind {
                ticket: ticket.clone(),
                bind_token,
                device,
                sr_sig_pub: sr_pub,
                device_sig: sk.sign(&canon).to_bytes().to_vec(),
            })
            .await
        }

        pub async fn ticket_renew(
            &mut self,
            ticket: Option<TicketWire>,
            user: &str,
            sr: &UserKey,
        ) -> CtrlResponse {
            let auth = sr_auth(user, sr);
            self.req(CtrlRequest::TicketRenew { ticket, auth }).await
        }
    }

    /// The SR-SIG1 authorization header (the §1.3.2 seven fields).
    fn sr_auth(user: &str, key: &UserKey) -> flock_server::control::SrAuth {
        let now = flock_protocol::trust::now_unix() as i64;
        let nonce = sr_sig::nonce_hex();
        flock_server::control::SrAuth {
            header: sr_sig::sign_prehashed(
                user,
                key,
                flock_server::control::CTRL_METHOD,
                flock_server::control::PATH_TICKET_RENEW,
                &sr_sig::sha256_hex(b""),
                now,
                &nonce,
            ),
        }
    }
}

// ============================================================================
// IP/ICMP construction (data-plane payloads)
// ============================================================================

/// IPv4 + ICMP echo (type=8/0; checksum left 0 —— the forwarding plane only
/// validates the source/destination address fields).
fn icmp_echo(src: [u8; 4], dst: [u8; 4], echo_type: u8, id: u16, seq: u16) -> Vec<u8> {
    let total_len = 20u16 + 8 + 8;
    let mut p = vec![0u8; total_len as usize];
    p[0] = 0x45; // IPv4 IHL=5
    p[2..4].copy_from_slice(&total_len.to_be_bytes());
    p[4..6].copy_from_slice(&id.to_be_bytes()); // identification reused
    p[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    p[8] = 64; // TTL
    p[9] = 1; // ICMP
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20] = echo_type; // 8=echo request / 0=reply
    p[22..24].copy_from_slice(&id.to_be_bytes());
    p[24..26].copy_from_slice(&seq.to_be_bytes());
    p
}

fn pkt_src_dst(pkt: &[u8]) -> ([u8; 4], [u8; 4]) {
    (
        pkt[12..16].try_into().unwrap(),
        pkt[16..20].try_into().unwrap(),
    )
}

// ============================================================================
// The main tests
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_node_cluster_forward_and_revocation() {
    let c3 = build_cluster().await;

    // —— The dual server stacks (server-1 / server-2; server-3 only runs
    //    Raft arbitration) ——
    let s1 = serve_on(&c3, 0, vec![]).await;
    let s2 = serve_on(&c3, 1, vec![]).await;

    // —— Account creation (Raft commit: redeem initiated on the server-2
    //    side, readable on the server-1 side) ——
    let invite_id: [u8; 16] = rand::random();
    let expiry = flock_protocol::trust::now_unix() + 3600;
    c3.nodes[0]
        .write(SyncRequest::RecordInvite {
            invite_id,
            expiry_unix: expiry,
        })
        .await
        .expect("record invite");
    // The invite file = root-key issuance (the operations side; §1.3.3f
    // invite generation = the root-key context).
    let invite = InviteFile::issue(
        &c3.root,
        c3.cluster_id,
        c3.directory.dir_version,
        c3.directory.servers.clone(),
        expiry,
        invite_id,
    );
    let invite_bytes = invite.to_bytes();

    let dev_a = DeviceStaticKeys::generate();
    let dev_b = DeviceStaticKeys::generate();
    let vip_of = |dev: &DeviceStaticKeys| DeviceId::from_ed25519(&dev.ed25519_public()).0;
    let out_a = s2
        .core
        .net
        .redeem_invite(RedeemRequest {
            invite_bytes: &invite_bytes,
            username: "mp-a",
            device_x25519: dev_a.x25519_public().to_bytes(),
            device_ed25519: *dev_a.ed25519_public().as_bytes(),
            hostname: "",
            expected_root_pub: *c3.root.verifying_key().as_bytes(),
            expected_cluster_id: c3.cluster_id.0,
            now_unix: flock_protocol::trust::now_unix(),
        })
        .await
        .expect("redeem A (via server-2, Raft commit)");
    assert_eq!(out_a.device_id, vip_of(&dev_a));
    // Redeem B on the server-1 side (the same Raft state —— any node is
    // equivalent).
    let out_b = s1
        .core
        .net
        .redeem_invite(RedeemRequest {
            invite_bytes: &invite_bytes, // a second redemption of the same invite must be rejected (assertion below)
            username: "mp-b",
            device_x25519: dev_b.x25519_public().to_bytes(),
            device_ed25519: *dev_b.ed25519_public().as_bytes(),
            hostname: "",
            expected_root_pub: *c3.root.verifying_key().as_bytes(),
            expected_cluster_id: c3.cluster_id.0,
            now_unix: flock_protocol::trust::now_unix(),
        })
        .await;
    assert!(
        matches!(out_b, Err(flock_server::netstate::RedeemError::AlreadyUsed)),
        "a second redemption of the same invite_id rejected (dedup inside the Raft state machine): {out_b:?}"
    );
    // B's own invite.
    let invite2_id: [u8; 16] = rand::random();
    c3.nodes[1]
        .write(SyncRequest::RecordInvite {
            invite_id: invite2_id,
            expiry_unix: flock_protocol::trust::now_unix() + 3600,
        })
        .await
        .expect("record invite 2");
    let invite2 = InviteFile::issue(
        &c3.root,
        c3.cluster_id,
        c3.directory.dir_version,
        c3.directory.servers.clone(),
        flock_protocol::trust::now_unix() + 3600,
        invite2_id,
    );
    let out_b = s1
        .core
        .net
        .redeem_invite(RedeemRequest {
            invite_bytes: &invite2.to_bytes(),
            username: "mp-b",
            device_x25519: dev_b.x25519_public().to_bytes(),
            device_ed25519: *dev_b.ed25519_public().as_bytes(),
            hostname: "",
            expected_root_pub: *c3.root.verifying_key().as_bytes(),
            expected_cluster_id: c3.cluster_id.0,
            now_unix: flock_protocol::trust::now_unix(),
        })
        .await
        .expect("redeem B (via server-1)");
    let vip_a = out_a.vip;
    let vip_b = out_b.vip;
    assert_ne!(vip_a, vip_b);

    // —— 1-RTT first connections (respond injects the two-level-read
    //    directory; through different servers) ——
    let pin1 = pin_for(&c3, 0, &s1.endpoint);
    let pin2 = pin_for(&c3, 1, &s2.endpoint);
    let ta = connect(&dev_a, &pin1).await;
    let tb = connect(&dev_b, &pin2).await;
    let mut ca = cli::Ctrl::open(ta).await;
    let cb = cli::Ctrl::open(tb).await;

    // —— The control plane (Raft replication: password/ticket/binding) ——
    assert!(
        matches!(
            ca.set_password("mp-a", "pw").await,
            flock_server::control::CtrlResponse::Ok
        ),
        "password set (SetPassword replicated; shared OPRF)"
    );
    let (ticket_a, bind_a) = ca
        .login("mp-a", "pw", &pin1)
        .await
        .expect("login (shared OPRF + the Raft ticket root)");
    assert!(
        matches!(ticket_a, TicketWire::Sync(_)),
        "the multi-primary form's ticket = issued by the Raft key root (TicketWire::Sync)"
    );
    // key-bind: register device B' (this test need not connect it again) +
    // the SR-SIG1 public key (for TicketRenew verification).
    let sr_key = UserKey::generate();
    let dev_aux = DeviceStaticKeys::generate();
    match ca
        .key_bind(
            &ticket_a,
            bind_a,
            "mp-a",
            &c3.cluster_id.0,
            &dev_aux,
            &sr_key,
        )
        .await
    {
        flock_server::control::CtrlResponse::KeyBound { .. } => {}
        other => panic!("key bind: {other:?}"),
    }
    // The SR-SIG1 state change (Sync ticket + nonce accounting; verified on
    // server-1).
    match ca
        .ticket_renew(Some(ticket_a.clone()), "mp-a", &sr_key)
        .await
    {
        flock_server::control::CtrlResponse::TicketRenewed { ticket } => {
            assert!(
                matches!(ticket, TicketWire::Sync(_)),
                "the renewed ticket is still Raft-rooted"
            );
        }
        other => panic!("ticket renew (SR-SIG1 + Sync ticket): {other:?}"),
    }

    // —— Data plane: two clients ping each other through two servers (the
    //    ForwardEnvelope path) ——
    let mut cha = ca
        .tunnel
        .open_packet_channel()
        .await
        .expect("A packet channel");
    let mut chb = cb
        .tunnel
        .open_packet_channel()
        .await
        .expect("B packet channel");

    // Note: the mux's SYN flushes lazily with the first data frame (same
    // note as the M3 dataplane tests) —— send one packet each way first so
    // both servers' packet channels materialize + attach_session, then
    // assert the cross-server path.
    let fwd1_before = c3.nodes[0].forward().stats().forwarded;
    let fwd2_before = c3.nodes[1].forward().stats().forwarded;

    // Lazy-SYN materialization order: B sends one packet first
    // (materializing B's channel + the n2 attach; at this moment A's
    // channel is unmaterialized ⇒ n2, per the real fault-tolerance
    // semantics, does NOT_HERE→locate→still no session→drop+ICMP —— the
    // honest behavior for an "idle destination", not asserted), then A
    // sends one packet (materializing A's side + the n1 attach); the
    // bidirectional assertions follow.
    let warmup = icmp_echo(vip_b, vip_a, 8, 0xb000, 0);
    chb.send(&warmup)
        .await
        .expect("B materialization packet (warmup)");
    tokio::time::sleep(Duration::from_millis(400)).await; // attach + lease diffusion

    // A → B (server-1 → server-2 FRWD).
    let req_ab = icmp_echo(vip_a, vip_b, 8, 0xa001, 1);
    cha.send(&req_ab).await.expect("A sends echo request");
    let got_ab = tokio::time::timeout(A6_BUDGET, chb.recv())
        .await
        .expect("B receives A's request within 5s")
        .expect("recv");
    assert_eq!(
        pkt_src_dst(&got_ab),
        (vip_a, vip_b),
        "A→B source/destination VIPs preserved across forwarding"
    );

    // B → A (server-2 → server-1 FRWD).
    let req_ba = icmp_echo(vip_b, vip_a, 8, 0xb001, 1);
    chb.send(&req_ba).await.expect("B sends echo request");
    let got_ba = tokio::time::timeout(A6_BUDGET, cha.recv()).await;
    let got_ba = match got_ba {
        Ok(r) => r.expect("recv"),
        Err(_) => {
            let a_dev = vip_of(&dev_a);
            let f1 = c3.nodes[0].forward().stats();
            let f2 = c3.nodes[1].forward().stats();
            eprintln!(
                "DIAG-B n1={{fwd:{} local:{} nothere:{} drop:{} srcv:{} loc:{} icmp:{} mism:{}}} n2={{fwd:{} local:{} nothere:{} drop:{} srcv:{} loc:{} mism:{}}} leaseA@n1={:?} leaseA@n2={:?}",
                f1.forwarded, f1.delivered_local, f1.not_here, f1.dropped, f1.src_violations, f1.locate_redirected, f1.icmp_unreachable, f1.src_mismatch_rejected,
                f2.forwarded, f2.delivered_local, f2.not_here, f2.dropped, f2.src_violations, f2.locate_redirected, f2.src_mismatch_rejected,
                c3.nodes[0].lease().observe(&a_dev),
                c3.nodes[1].lease().observe(&a_dev),
            );
            panic!("A did not receive B's request within 5s (B→A FRWD failed)");
        }
    };
    assert_eq!(
        pkt_src_dst(&got_ba),
        (vip_b, vip_a),
        "B→A source/destination VIPs preserved across forwarding"
    );

    // Both directional FRWD counts incremented (the empirical proof of the
    // §2.2 step-3 cross-server forwarding).
    let f1 = c3.nodes[0].forward().stats();
    let f2 = c3.nodes[1].forward().stats();
    assert!(
        f1.forwarded > fwd1_before,
        "server-1's cross-server forwarding count incremented (→{})",
        f1.forwarded
    );
    assert!(
        f2.forwarded > fwd2_before,
        "server-2's cross-server forwarding count incremented (→{})",
        f2.forwarded
    );

    // The two-level-read directory has actually served handshakes (cache
    // hits or linearizable reads non-zero).
    let ds1 = c3.nodes[0].dir().stats();
    assert!(
        ds1.cache_hits + ds1.linearizable_reads > 0,
        "SyncDirectory served respond queries (cache={} linear={})",
        ds1.cache_hits,
        ds1.linearizable_reads
    );

    // —— Revocation propagation bound (A6 ≤5s; the §2.2 apply callback) ——
    let t0 = Instant::now();
    s2.core
        .net
        .revoke(&DeviceId(vip_of(&dev_a)))
        .await
        .expect("revoke submitted via server-2 (Raft)");

    // The other server's (server-1's) new handshake rejected within ≤5s.
    let mut rejected_at: Option<Duration> = None;
    while t0.elapsed() < A6_BUDGET {
        let io = tokio::net::TcpStream::connect(&pin1.entry.relay_endpoint)
            .await
            .unwrap();
        if initiate(io, &dev_a, &pin1, TunnelConfig::default())
            .await
            .is_err()
        {
            rejected_at = Some(t0.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let dt = rejected_at.expect("the other server must reject new handshakes within 5s (A6)");
    assert!(dt <= A6_BUDGET, "new-handshake rejection took {dt:?} ≤ 5s");

    // The existing session is killed (apply callback → SyncHooks →
    // LiveSessions.kill).
    let deadline = Instant::now() + A6_BUDGET;
    while c3.nodes[0].local_epoch() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        c3.nodes[0].local_epoch() >= 1,
        "the revocation_epoch has advanced (applied)"
    );
    assert_eq!(
        s1.core.sessions.online(&vip_of(&dev_a)),
        0,
        "A's session on server-1 is killed"
    );

    // Control: the unrevoked B can still connect (the rejection is causally
    // tied to the revocation).
    let io = tokio::net::TcpStream::connect(&pin2.entry.relay_endpoint)
        .await
        .unwrap();
    initiate(io, &dev_b, &pin2, TunnelConfig::default())
        .await
        .expect("B can still connect (control)");

    // Pin-chain integrity (the root trust chain shared by the TOFU surface
    // and this test).
    let pins_dir = tempfile::tempdir().unwrap();
    let mut pins = PinStore::new();
    pins.pin(&c3.cluster_id, &c3.root.verifying_key());
    pins.save(&pins_dir.path().join("pins.bin")).unwrap();
    assert_eq!(
        PinStore::load(&pins_dir.path().join("pins.bin"))
            .unwrap()
            .verify_pinned(&c3.cluster_id, &c3.root.verifying_key()),
        PinVerdict::Match
    );
}

// ============================================================================
// Review item 2: the readiness semantics of per-server OPRF sealing (no
// wrap ⇒ explicit failure / after rewrap the new server can unseal)
// ============================================================================

/// ① Seal only for nodes 1/2: node 3's `open_sync` fails explicitly within
///    a short window (the error names "OPRF wrap", of the transient class
///    —— sync.rs's ready retry recognizes only that class);
/// ② After topping up node 3's rewrap: `open_sync` succeeds (the local
///    hybrid sk unseals into memory —— OPAQUE available, core.oprf being
///    the unsealed product).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oprf_wrap_missing_server_fails_then_rewrap_enables() {
    let c3 = build_cluster_bare().await;
    let oprf_b64 = server_setup_new(&mut rand::rngs::OsRng);
    let leader = wait_leader(&c3.nodes).await;
    // Seal only nodes 1/2 (idents[0]/[1] —— nodes 1/2; node 3 without a
    // wrap).
    submit_wrapped_oprf(&leader, &c3.root, &c3.idents[..2], &oprf_b64).await;

    let tmp = tempfile::tempdir().expect("tmp");
    let state_dir = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let cfg = sync_server_cfg(
        state_dir,
        "node-3.test:9443".into(),
        vec![],
        std::net::Ipv4Addr::from(flock_sync::proto::server_vip_of(3).expect("node 3")),
    );

    // ① A server without a matching wrap: explicit failure after a short
    //    window (300ms) —— the error names the missing OPRF wrap.
    let err = match ServerCore::open_sync_with_wait(
        cfg.clone(),
        c3.idents[2].clone(),
        c3.nodes[2].clone(),
        Duration::from_millis(300),
    )
    .await
    {
        Err(e) => e,
        Ok(_) => panic!("node 3 without a wrap ⇒ open_sync must fail explicitly"),
    };
    assert!(
        err.contains("OPRF wrap"),
        "the error must name the missing OPRF wrap (diagnosable): {err}"
    );
    assert!(
        err.starts_with(flock_server::server::SYNC_NOT_READY_PREFIX),
        "no wrap yet is transient (the ready-retry semantics): {err}"
    );
    // Control: node 1, which has a wrap, succeeds within the same window.
    let tmp1 = tempfile::tempdir().expect("tmp");
    let cfg1 = sync_server_cfg(
        tmp1.path().to_path_buf(),
        "node-1.test:9443".into(),
        vec![],
        std::net::Ipv4Addr::from(flock_sync::proto::server_vip_of(1).expect("node 1")),
    );
    std::mem::forget(tmp1);
    ServerCore::open_sync_with_wait(
        cfg1,
        c3.idents[0].clone(),
        c3.nodes[0].clone(),
        Duration::from_secs(5),
    )
    .await
    .expect("node 1 has a wrap ⇒ open_sync succeeds");

    // ② After rewrap the new server can unseal: new-server admission = a
    // full ServerKeys re-registration (root-signed, including node 3's
    // hybrid public key —— the state machine's server_keys has
    // whole-replacement semantics) → topping up node 3's seal (root-signed
    // Rewrap) → open_sync succeeds.
    let node3_id = flock_sync::node::node_id_of(&c3.idents[2].server_id);
    let entries: Vec<flock_sync::proto::ServerKeyEntry> = c3
        .idents
        .iter()
        .map(|i| {
            let node_id = flock_sync::node::node_id_of(&i.server_id);
            flock_sync::proto::ServerKeyEntry {
                server_id: node_id,
                identity_pub: *i.identity.verifying_key().as_bytes(),
                hybrid_pub: i.static_hybrid.public().to_bytes().to_vec(),
                vip: flock_sync::proto::server_vip_of(node_id).expect("node 1..=10"),
            }
        })
        .collect();
    let resp = leader
        .write(SyncRequest::server_keys_signed(&c3.root, entries))
        .await
        .expect("server keys full");
    assert!(
        matches!(
            resp,
            flock_sync::proto::SyncResponse::ServerKeys { servers: 3 }
        ),
        "server_keys full: {resp:?}"
    );
    let wrapped =
        flock_server::server::seal_oprf_wrap(&oprf_b64, &c3.idents[2].static_hybrid.public())
            .expect("seal");
    let resp = leader
        .write(SyncRequest::rewrap_signed(&c3.root, node3_id, wrapped))
        .await
        .expect("rewrap node3");
    assert!(
        matches!(
            resp,
            flock_sync::proto::SyncResponse::Admin(flock_sync::proto::AdminAck::Rewrap { .. })
        ),
        "rewrap: {resp:?}"
    );
    let core = ServerCore::open_sync_with_wait(
        cfg,
        c3.idents[2].clone(),
        c3.nodes[2].clone(),
        Duration::from_secs(5),
    )
    .await
    .expect("after the rewrap top-up, node 3 can unseal (OPAQUE available)");
    // Unsealing semantic loop closure: the login path uses exactly this
    // OPRF (the server-side setup of PwBegin/Login).
    let _ = &core.oprf;
}

// ============================================================================
// M7 (§7-M7.6): with two clients cross-server, the roster assembles
// identically on either server (including non-zero ewma)
// ============================================================================

/// Assertion surface:
/// - **structural fields strictly equal** (vip/hostname/owner/kind/online)
///   —— the registry snapshot and the lease-domain view agree across the
///   two servers;
/// - **ewma/last_seen compared with tolerance** (non-zero + both-side
///   difference < 15s) —— the two servers' local views come from
///   anti-entropy snapshots at different moments (5s period); byte
///   equality is neither achievable nor necessary (declared as-is);
/// - a fake traffic pump (A→B sustained ~2s): A's tx and B's rx non-zero
///   in the rosters of **both servers** (holder folding + gossip
///   propagation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roster_consistent_across_servers_with_traffic_pump() {
    let c3 = build_cluster().await;
    let s1 = serve_on(&c3, 0, vec![]).await;
    let s2 = serve_on(&c3, 1, vec![]).await;

    // Account creation (hostname reported through redeem —— empirical proof
    // of the field's chain).
    let inv_a = m7_invite(&c3, rand::random()).await;
    let dev_a = DeviceStaticKeys::generate();
    let out_a = s1
        .core
        .net
        .redeem_invite(RedeemRequest {
            invite_bytes: &inv_a.to_bytes(),
            username: "roster-a",
            device_x25519: dev_a.x25519_public().to_bytes(),
            device_ed25519: *dev_a.ed25519_public().as_bytes(),
            hostname: "roster-a-pad",
            expected_root_pub: *c3.root.verifying_key().as_bytes(),
            expected_cluster_id: c3.cluster_id.0,
            now_unix: flock_protocol::trust::now_unix(),
        })
        .await
        .expect("redeem A");
    let inv_b = m7_invite(&c3, rand::random()).await;
    let dev_b = DeviceStaticKeys::generate();
    let out_b = s2
        .core
        .net
        .redeem_invite(RedeemRequest {
            invite_bytes: &inv_b.to_bytes(),
            username: "roster-b",
            device_x25519: dev_b.x25519_public().to_bytes(),
            device_ed25519: *dev_b.ed25519_public().as_bytes(),
            hostname: "roster-b-pad",
            expected_root_pub: *c3.root.verifying_key().as_bytes(),
            expected_cluster_id: c3.cluster_id.0,
            now_unix: flock_protocol::trust::now_unix(),
        })
        .await
        .expect("redeem B");

    // Connect (A→server-1, B→server-2) + packet channels.
    let pin1 = pin_for(&c3, 0, &s1.endpoint);
    let pin2 = pin_for(&c3, 1, &s2.endpoint);
    let ta = connect(&dev_a, &pin1).await;
    let tb = connect(&dev_b, &pin2).await;
    let ca = cli::Ctrl::open(ta).await;
    let cb = cli::Ctrl::open(tb).await;
    let mut cha = ca
        .tunnel
        .open_packet_channel()
        .await
        .expect("A packet channel");
    let mut chb = cb
        .tunnel
        .open_packet_channel()
        .await
        .expect("B packet channel");

    // Channel materialization (lazy SYN: one packet each way first).
    let warm_b = icmp_echo(out_b.vip, out_a.vip, 8, 0xb000, 0);
    chb.send(&warm_b).await.expect("B warmup");
    let warm_a = icmp_echo(out_a.vip, out_b.vip, 8, 0xa000, 0);
    cha.send(&warm_a).await.expect("A warmup");
    tokio::time::sleep(Duration::from_millis(400)).await;

    // The fake traffic pump: A→B sustained ~2s (one 1200B packet per 20ms
    // ⇒ on the order of ~60KB/s —— enough for non-zero EWMA).
    let pump = icmp_echo(out_a.vip, out_b.vip, 8, 0xa001, 1);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut sent = 0u64;
    while Instant::now() < deadline {
        if cha.send(&pump).await.is_err() {
            break;
        }
        sent += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(sent > 10, "pumped {sent} packets");

    // Wait for anti-entropy (5s) + the folding window (1s) to propagate:
    // the ewma goes through holder folding → publish/anti-entropy to the
    // peer.
    tokio::time::sleep(Duration::from_secs(7)).await;

    // Assemble on both sides.
    let r1 = flock_server::control::assemble_roster(&s1.core).await;
    let r2 = flock_server::control::assemble_roster(&s2.core).await;

    // Structural fields strictly equal.
    let shape = |r: &[flock_server::control::PeerInfo]| {
        r.iter()
            .map(|p| (p.vip, p.hostname.clone(), p.owner.clone(), p.kind, p.online))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        shape(&r1),
        shape(&r2),
        "either server assembles identically (structural fields strictly equal)"
    );
    // 3 Servers + 2 Devices.
    assert_eq!(r1.len(), 5, "{r1:?}");
    assert_eq!(
        r1.iter()
            .filter(|p| p.kind == flock_server::control::PeerKind::Server)
            .count(),
        3,
        "all three servers on record"
    );
    let devices: Vec<_> = r1
        .iter()
        .filter(|p| p.kind == flock_server::control::PeerKind::Device)
        .collect();
    assert!(devices.iter().all(|p| p.online), "both clients online");

    // ewma non-zero (both sides): A's tx (counted on the access side), B's
    // rx (counted on the receiving side).
    for (roster, tag) in [(&r1, "s1"), (&r2, "s2")] {
        let a = roster.iter().find(|p| p.vip == out_a.vip).expect("A entry");
        assert!(
            a.tx_bps > 0,
            "{tag}: A's tx ewma non-zero (holder folding + propagation): {}",
            a.tx_bps
        );
        let b = roster.iter().find(|p| p.vip == out_b.vip).expect("B entry");
        assert!(
            b.rx_bps > 0,
            "{tag}: B's rx ewma non-zero (receiving-side counting + propagation): {}",
            b.rx_bps
        );
        assert!(a.last_seen_unix > 0 && b.last_seen_unix > 0);
    }
    // last_seen tolerance (< 15s): the two views come from different
    // anti-entropy moments.
    let ls = |r: &[flock_server::control::PeerInfo], vip: [u8; 4]| {
        r.iter().find(|p| p.vip == vip).unwrap().last_seen_unix
    };
    for vip in [out_a.vip, out_b.vip] {
        assert!(
            ls(&r1, vip).abs_diff(ls(&r2, vip)) < 15,
            "last_seen both-side difference < 15s (tolerance for anti-entropy snapshot time skew)"
        );
    }
    // hostname reported through redeem reaches the roster.
    assert!(r1
        .iter()
        .any(|p| p.vip == out_a.vip && p.hostname == "roster-a-pad"));
    assert!(r1
        .iter()
        .any(|p| p.vip == out_b.vip && p.hostname == "roster-b-pad"));
}

// ============================================================================
// server_vip_of consistency (the multi-primary form): open_sync's VIP
// assertion
// ============================================================================

/// Node 1's deterministic server VIP = 100.64.0.1: a misaligned config (.9)
/// ⇒ refuses to start and the error **names the expected value** and is a
/// permanent error (not the SYNC_NOT_READY prefix —— the ready-retry loop
//  does not swallow it); the matching value starts fine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_sync_rejects_vip_mismatch_with_expected_value() {
    let c3 = build_cluster().await;
    let tmp = tempfile::tempdir().expect("tmp");
    let state_dir = tmp.path().to_path_buf();
    std::mem::forget(tmp);

    // Misaligned (node 1 should be .1, configured .9): explicit failure +
    // the expected value + a permanent error (returned immediately within a
    // short window, not waiting for the wrap).
    let mut cfg = sync_server_cfg(
        state_dir.clone(),
        "node-1.test:9443".into(),
        vec![],
        "100.64.0.9".parse().unwrap(),
    );
    let t0 = std::time::Instant::now();
    let err = match ServerCore::open_sync_with_wait(
        cfg.clone(),
        c3.idents[0].clone(),
        c3.nodes[0].clone(),
        std::time::Duration::from_secs(5),
    )
    .await
    {
        Err(e) => e,
        Ok(_) => panic!("a vip mismatch must refuse to start"),
    };
    assert!(
        err.contains("100.64.0.1"),
        "the error gives the expected value (deterministic derivation): {err}"
    );
    assert!(
        !err.starts_with(flock_server::server::SYNC_NOT_READY_PREFIX),
        "a configuration error is permanent (not swallowed by the ready retry): {err}"
    );
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(2),
        "the assertion precedes the wrap wait (immediate rejection)"
    );

    // Matching (.1 = server_vip_of(node 1)) ⇒ starts normally (the wraps
    // were already persisted by build_cluster).
    cfg.vip = "100.64.0.1".parse().unwrap();
    ServerCore::open_sync_with_wait(
        cfg,
        c3.idents[0].clone(),
        c3.nodes[0].clone(),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("the derived value matches ⇒ startable");
}

// ============================================================================
// M7 (§7-M7.5): the reaper —— the registered_at anchor + the lease
// view-ready gate (the multi-primary form)
// ============================================================================

/// Assertion surface (a single-node raft cluster = no peers ⇒ never any
/// remote lease events —— the gate's two states can be driven precisely):
/// - **gate closed** (no remote events in the lease table): even with
///   dev_idle's registered_at anchor past the window (40d > the 30d
///   retention period), it is **not reaped** —— inside the post-restart
///   "anti-entropy backfill ≤5s racing the reaper's first pass" window,
///   remotely-hosted devices' lease rows are missing, and terminalizing
///   them by mistake would harm the whole network (including online
///   devices —— invite consumed = bricked);
/// - **gate open** (injecting one remote gossip = anti-entropy backfill
///   complete): dev_idle (never online and anchor past the window) is
///   reaped; dev_online with a lease observation (registered_at likewise
///   40d ago, last_seen = now) untouched —— the observation takes priority
///   over the stale anchor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reaper_anchor_and_lease_gate_multi_primary() {
    use flock_sync::lease::GossipMsg;

    // Single-node cluster assembly (root-signed identity + self-signed
    // directory + an in-memory fabric with only this node).
    let root = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let cluster_id = flock_protocol::session::ClusterId(rand::random());
    let ident = Arc::new(flock_protocol::session::ServerIdentity::enroll(
        &root,
        cluster_id,
        sid(1),
        "node-1.test:9443",
    ));
    let directory = flock_protocol::trust::ClusterDirectory::issue(
        &root,
        cluster_id,
        1,
        vec![ident.entry.clone()],
    );
    let reg = MemoryFabric::registry();
    let fabric = MemoryFabric::new(ident.server_id, &reg, FABRIC_DELAY, 2 * 1024 * 1024);
    let tmp = tempfile::tempdir().expect("tmpdir");
    let node = Arc::new(
        SyncNodeBuilder::new(
            SyncSettings::default(),
            ident.clone(),
            directory,
            fabric,
            tmp.path().join("db-1.redb"),
        )
        .voters(&[1])
        .build()
        .await
        .expect("node build"),
    );
    // Bootstrap + ServerKeys + the local Rewrap (open_sync's readiness
    // precondition).
    let leader = wait_leader(std::slice::from_ref(&node)).await;
    let oprf_b64 = server_setup_new(&mut rand::rngs::OsRng);
    submit_wrapped_oprf(&leader, &root, std::slice::from_ref(&ident), &oprf_b64).await;

    let tmp2 = tempfile::tempdir().expect("tmpdir");
    let cfg = sync_server_cfg(
        tmp2.path().to_path_buf(),
        "node-1.test:9443".into(),
        vec![],
        std::net::Ipv4Addr::from(flock_sync::proto::server_vip_of(1).expect("node 1")),
    );
    std::mem::forget(tmp2);
    let core = ServerCore::open_sync(cfg, ident.clone(), node.clone())
        .await
        .expect("open_sync");

    // Two devices: registered_at likewise 40 days ago (injected by the
    // submitting side —— apply is deterministic); dev_online additionally
    // has a local lease observation (publish ⇒ last_seen = now).
    let now = flock_protocol::trust::now_unix();
    let t_old = now.saturating_sub(40 * 86_400);
    let vk_of = |seed: u8| {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_owned()
    };
    for seed in 1u8..=2 {
        let resp = node
            .write(SyncRequest::RegisterDevice {
                owner: format!("u{seed}"),
                x25519: [seed; 32],
                ed25519: *vk_of(seed).as_bytes(),
                hostname: String::new(),
                registered_at_unix: t_old,
            })
            .await
            .expect("register");
        assert!(
            matches!(resp, flock_sync::proto::SyncResponse::Device(_)),
            "register: {resp:?}"
        );
    }
    let dev_online = DeviceId::from_ed25519(&vk_of(1));
    let dev_idle = DeviceId::from_ed25519(&vk_of(2));
    node.publish_lease(&dev_online.0).await;
    let row_status = |dev: &DeviceId| {
        node.devices_snapshot()
            .iter()
            .find(|(id, _)| DeviceId(*id) == *dev)
            .map(|(_, r)| r.status)
            .expect("row")
    };
    let day = 86_400u64;

    // ① Gate closed (the table has rows but zero remote events since
    //    startup): even the anchor-past-window dev_idle is not reaped.
    assert!(
        !node.lease().reaper_view_ready(),
        "single node without peers ⇒ the gate is closed"
    );
    let expired = flock_server::server::reap_once(&core, 30, now + day).await;
    assert!(
        expired.is_empty(),
        "view not ready ⇒ the whole pass skipped: {expired:?}"
    );
    assert_eq!(
        row_status(&dev_idle),
        flock_sync::proto::DeviceStatus::Active
    );
    assert_eq!(
        row_status(&dev_online),
        flock_sync::proto::DeviceStatus::Active
    );

    // ② Gate open (injecting one remote gossip = anti-entropy backfill
    //    complete): dev_idle (never online and anchor 41d > 30d) reaped;
    //    dev_online (observation 1d < 30d) untouched.
    node.lease()
        .merge_remote(GossipMsg::Anti { entries: vec![] });
    assert!(node.lease().reaper_view_ready());
    let expired = flock_server::server::reap_once(&core, 30, now + day).await;
    assert_eq!(
        expired,
        vec![dev_idle],
        "only the never-online anchor-past-window one is reaped"
    );
    assert_eq!(
        row_status(&dev_idle),
        flock_sync::proto::DeviceStatus::Expired
    );
    assert_eq!(
        row_status(&dev_online),
        flock_sync::proto::DeviceStatus::Active,
        "the lease observation (1d) takes priority over the stale anchor (41d)"
    );
    // Idempotent: another pass in the same window ⇒ an empty pass.
    let expired = flock_server::server::reap_once(&core, 30, now + day).await;
    assert!(expired.is_empty(), "idempotent");
}

/// The invite fixture of the M7 roster tests (registration + root-signed
/// issuance).
async fn m7_invite(c3: &Node3, id: [u8; 16]) -> InviteFile {
    let expiry = flock_protocol::trust::now_unix() + 3600;
    c3.nodes[0]
        .write(SyncRequest::RecordInvite {
            invite_id: id,
            expiry_unix: expiry,
        })
        .await
        .expect("record invite");
    InviteFile::issue(
        &c3.root,
        c3.cluster_id,
        c3.directory.dir_version,
        c3.directory.servers.clone(),
        expiry,
        id,
    )
}

// ============================================================================
// M8 webui (the multi-primary form): the registry verdict for remote
// server VIPs in dashboard/series
// ============================================================================

/// Green review item 7 (series vip_in_registry includes remote server
/// VIPs): Series resets on restart ⇒ before the first sample after a
/// restart knows()=false —— a series query for a remote server VIP must
/// hit the registry arm (the server_keys local view) and return empty
/// points rather than 404; a VIP on no registry surface still 404s.
#[tokio::test]
async fn webui_series_remote_server_vip_known_before_first_sample() {
    let c3 = build_cluster().await;
    // Node 0's ServerCore (Sync backend; server_keys already root-signed
    // and registered by build_cluster).
    let server_a = serve_on(&c3, 0, vec![]).await;
    let state = std::sync::Arc::new(flock_server::webui::api::WebState::new(
        server_a.core.clone(),
    ));

    // A login-tier session (dispatch reads back the UserRow —— review item
    // 6 semantics; issued directly through the session table).
    server_a
        .core
        .net
        .create_user("probe", [0xAB; 16])
        .await
        .expect("create_user");
    server_a
        .core
        .net
        .set_user_admin("probe", true)
        .await
        .expect("set_user_admin");
    let now = flock_protocol::trust::now_unix();
    use flock_server::webui::session::Origin;
    let sid = state
        .sessions
        .issue("probe", true, Origin::Loopback, now, 3600);

    // The remote (node 2) server's VIP = server_vip_of's deterministic
    // derivation.
    let node2 = flock_sync::node::node_id_of(&c3.idents[2].server_id);
    let vip2 = flock_sync::proto::server_vip_of(node2).expect("node 1..=10");
    let vip_str = format!("{}.{}.{}.{}", vip2[0], vip2[1], vip2[2], vip2[3]);
    let remote: std::net::SocketAddr = "127.0.0.1:40000".parse().unwrap();

    // DBG: the server_keys local view and the decision inputs.
    let mk_req = |query: String| flock_server::webui::http::Request {
        method: "GET".into(),
        path: "/api/dashboard/series".into(),
        query,
        headers: vec![("Cookie".into(), format!("flock_session={sid}"))],
        body: vec![],
    };
    // The remote server VIP: no samples (a fresh Series —— the restart
    // semantics) but on record ⇒ 200 empty points.
    let resp = state
        .dispatch(mk_req(format!("vip={vip_str}")), remote)
        .await;
    assert_eq!(
        resp.status, 200,
        "the remote server VIP hits the registry arm (not 404)"
    );
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(
        body["points"].as_array().map(Vec::len),
        Some(0),
        "empty points before the first sample after restart"
    );
    // A VIP on no registry surface ⇒ 404.
    let resp = state
        .dispatch(mk_req("vip=100.64.0.99".into()), remote)
        .await;
    assert_eq!(resp.status, 404, "an unregistered VIP still 404s");
}
