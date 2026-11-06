//! 多主装配集成测试（docs/design.md §2.2/§3.11 M4 批次；feature `multi-primary`）。
//!
//! 进程内 3 节点内存集群（`flock_sync::testutil::MemoryFabric`，RTT 2×5ms）：
//!
//! 1. **全链控制面**：redeem（Raft 提交）→ 1-RTT 首连（**两级读目录**：respond 注入
//!    `SyncNode::device_directory`）→ OPAQUE 登录（anchor + **Raft 内共享 OPRF**）→
//!    票据 = **Raft 密钥根**（`TicketWire::Sync`）→ key-bind → SR-SIG1 TicketRenew；
//! 2. **跨服转发面**：双客户端经两台服务器互 ping——server-A 的包通道 → ForwardEnvelope
//!    （FRWD 经互连 E2E 会话）→ server-B 投递（§2.2 判定序：第 0 步源 VIP 校验 →
//!    租约定位 → 跨服转发）；
//! 3. **吊销传播界（A6 ≤5s）**：在 server-B 侧提交 revoke → 另一台服务器（A）的新握手
//!    被拒 ≤5s，且 A 的既有会话被 apply 回调杀掉（§2.2 (a)(b)(c)）。

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

/// RTT = 2×5ms（内存织物；§7-M4 的 100ms 校准档属 flock-sync 自身测试）。
const FABRIC_DELAY: Duration = Duration::from_millis(5);
/// A6 时序预算（§2.2：健康集群吊销传播 ≤5s）。
const A6_BUDGET: Duration = Duration::from_secs(5);

fn sid(n: NodeId) -> ServerId {
    flock_sync::wire::sid_of(n)
}

// ============================================================================
// 装配：3 节点集群 + 双服务器栈
// ============================================================================

struct Node3 {
    root: ed25519_dalek::SigningKey,
    cluster_id: flock_protocol::session::ClusterId,
    nodes: Vec<Arc<SyncNode>>,
    idents: Vec<Arc<flock_protocol::session::ServerIdentity>>,
    directory: flock_protocol::trust::ClusterDirectory,
    #[allow(dead_code)] // 保留观察面（apply 钩子记录器）
    recorders: Vec<Arc<HookRecorder>>,
    _tmp: tempfile::TempDir,
}

async fn build_cluster() -> Node3 {
    let c3 = build_cluster_bare().await;
    // OPRF 逐服务器封装（评审项 2）：ServerKeys 根签登记各服务器混合公钥 → 每台
    // envelope v2 seal 一份 Rewrap——状态机只存 wraps，不再明文 SetOprf（§2.4 跨
    // 节点登录语义不变）。
    let oprf_b64 = server_setup_new(&mut rand::rngs::OsRng);
    let leader = wait_leader(&c3.nodes).await;
    submit_wrapped_oprf(&leader, &c3.root, &c3.idents, &oprf_b64).await;
    // 密封存储不可读出明文（线格式断言）：全网明文 OPRF 字段为空；状态摘要只有
    // wraps（3 台各一份）。
    for n in &c3.nodes {
        assert!(n.oprf_b64().is_none(), "明文 OPRF 不得入 Raft 状态");
    }
    let view = c3.nodes[0]
        .read_linearizable(flock_sync::proto::ReadQuery::State)
        .await
        .expect("state view");
    let flock_sync::proto::ReadView::State(v) = view else {
        panic!("state view shape: {view:?}")
    };
    assert_eq!(v.wraps.len(), 3, "每台服务器一份封装（rewrap）");
    c3
}

/// 3 节点集群装配到 Bootstrap 为止（OPRF 封装提交由调用方决定子集——评审项 2 的
/// 「无 wrap 服务器失败 / rewrap 后可解封」用例）。
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

    // Bootstrap（票据根进 Raft，§4）。
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

/// ServerKeys + 逐服务器 Rewrap 提交（build_cluster 与 rewrap 补交测试共用）。
/// 断言：状态摘要只含 wraps（3 台各一份）且全网明文 oprf 字段为空（评审项 2 的
/// 「密封存储不可读出明文」在线格式断言）。
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
    panic!("15s 内未选出 leader");
}

/// 服务器栈（respond/控制流/转发面）挂到 raft 节点。
struct SyncServer {
    core: Arc<ServerCore>,
    #[allow(dead_code)] // endpoint 经 pin_for 消费
    endpoint: String,
}

async fn serve_on(c3: &Node3, idx: usize, extra_endpoints: Vec<String>) -> SyncServer {
    let tmp = tempfile::tempdir().expect("tmp");
    let state_dir = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = l.local_addr().unwrap().to_string();
    // VIP = 本机 node_id 的确定性推导值（server_vip_of——open_sync 的一致性断言要求；
    // 旧配置全部硬编码 .1 对 node 2/3 是「登记 VIP ≠ 实配 VIP」的错位形态）。
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

/// serve_on / open_sync 直测共用的 ServerConfig（装配经 open_sync，不走配置文件路径）。
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
    }
}

/// 客户端 pin：以根签目录条目为身份锚，**拨号地址换成 TCP 监听口**（目录内
/// `node-N.test:9443` 是互连织物端点；接入端点与本测试拨号口同机不同位——
/// I1 签名锚是 identity_pub，端点串不进签名面）。
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
        .expect("1-RTT initiate（两级读目录放行）")
}

// ============================================================================
// 客户端控制流驱动（复用 server crate 的协议面；仅本测试所需子集）
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

        /// 设置口令（PwBegin/PwCommit——复制形态 SetPassword）。
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

        /// OPAQUE 登录（anchor 验签）→ (票据, bind_token)。
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

        /// key-bind（设备公钥 + SR-SIG1 公钥；票据 + bind_token 一次性 + 设备签名）。
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

    /// SR-SIG1 授权头（§1.3.2 七字段）。
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
// IP/ICMP 构造（数据面载荷）
// ============================================================================

/// IPv4 + ICMP echo（type=8/0；校验和填 0——转发面只校验源/目标地址字段）。
fn icmp_echo(src: [u8; 4], dst: [u8; 4], echo_type: u8, id: u16, seq: u16) -> Vec<u8> {
    let total_len = 20u16 + 8 + 8;
    let mut p = vec![0u8; total_len as usize];
    p[0] = 0x45; // IPv4 IHL=5
    p[2..4].copy_from_slice(&total_len.to_be_bytes());
    p[4..6].copy_from_slice(&id.to_be_bytes()); // identification 复用
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
// 主测试
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_node_cluster_forward_and_revocation() {
    let c3 = build_cluster().await;

    // —— 双服务器栈（server-1 / server-2；server-3 只跑 Raft 仲裁）——
    let s1 = serve_on(&c3, 0, vec![]).await;
    let s2 = serve_on(&c3, 1, vec![]).await;

    // —— 开户（Raft 提交：redeem 在 server-2 侧发起，server-1 侧可读）——
    let invite_id: [u8; 16] = rand::random();
    let expiry = flock_protocol::trust::now_unix() + 3600;
    c3.nodes[0]
        .write(SyncRequest::RecordInvite {
            invite_id,
            expiry_unix: expiry,
        })
        .await
        .expect("record invite");
    // 邀请文件 = 根密钥签发（运维侧；§1.3.3f 邀请生成 = 根密钥语境）。
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
        .expect("redeem A（经 server-2，Raft 提交）");
    assert_eq!(out_a.device_id, vip_of(&dev_a));
    // server-1 侧兑换 B（同一 Raft 状态——任意节点等价）。
    let out_b = s1
        .core
        .net
        .redeem_invite(RedeemRequest {
            invite_bytes: &invite_bytes, // 同 invite 二次兑换必拒（下方断言）
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
        "同 invite_id 二次兑换拒（Raft 状态机内查重）：{out_b:?}"
    );
    // B 的独立邀请。
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
        .expect("redeem B（经 server-1）");
    let vip_a = out_a.vip;
    let vip_b = out_b.vip;
    assert_ne!(vip_a, vip_b);

    // —— 1-RTT 首连（respond 注入两级读目录；经不同服务器）——
    let pin1 = pin_for(&c3, 0, &s1.endpoint);
    let pin2 = pin_for(&c3, 1, &s2.endpoint);
    let ta = connect(&dev_a, &pin1).await;
    let tb = connect(&dev_b, &pin2).await;
    let mut ca = cli::Ctrl::open(ta).await;
    let cb = cli::Ctrl::open(tb).await;

    // —— 控制面（Raft 复制：口令/票据/绑定）——
    assert!(
        matches!(
            ca.set_password("mp-a", "pw").await,
            flock_server::control::CtrlResponse::Ok
        ),
        "口令设置（SetPassword 复制；共享 OPRF）"
    );
    let (ticket_a, bind_a) = ca
        .login("mp-a", "pw", &pin1)
        .await
        .expect("登录（共享 OPRF + Raft 票据根）");
    assert!(
        matches!(ticket_a, TicketWire::Sync(_)),
        "多主形态票据 = Raft 密钥根签发（TicketWire::Sync）"
    );
    // key-bind：登记设备 B'（本测试不必再连）+ SR-SIG1 公钥（供 TicketRenew 验签）。
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
    // SR-SIG1 状态变更（Sync 票据 + nonce 记账；在 server-1 上验证）。
    match ca
        .ticket_renew(Some(ticket_a.clone()), "mp-a", &sr_key)
        .await
    {
        flock_server::control::CtrlResponse::TicketRenewed { ticket } => {
            assert!(
                matches!(ticket, TicketWire::Sync(_)),
                "换发票据仍为 Raft 根"
            );
        }
        other => panic!("ticket renew（SR-SIG1 + Sync 票据）: {other:?}"),
    }

    // —— 数据面：双客户端经两台服务器互 ping（ForwardEnvelope 路径）——
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

    // 注：mux 的 SYN 惰性随首数据帧 flush（M3 dataplane 测试同注记）——双向各先发一包，
    // 使两侧服务器的包通道都物化 + attach_session，再断言跨服路径。
    let fwd1_before = c3.nodes[0].forward().stats().forwarded;
    let fwd2_before = c3.nodes[1].forward().stats().forwarded;

    // 惰性 SYN 的物化序：B 先发一包（物化 B 侧通道 + n2 attach；此刻 A 侧通道未物化
    // ⇒ n2 按真实容错语义 NOT_HERE→locate→仍无会话→丢+ICMP——这是「目标空闲」的
    // 诚实行为，不作断言），随后 A 发一包（物化 A 侧 + n1 attach），此后双向断言。
    let warmup = icmp_echo(vip_b, vip_a, 8, 0xb000, 0);
    chb.send(&warmup).await.expect("B 物化包（warmup）");
    tokio::time::sleep(Duration::from_millis(400)).await; // attach + 租约扩散

    // A → B（server-1 → server-2 的 FRWD）。
    let req_ab = icmp_echo(vip_a, vip_b, 8, 0xa001, 1);
    cha.send(&req_ab).await.expect("A 发 echo request");
    let got_ab = tokio::time::timeout(A6_BUDGET, chb.recv())
        .await
        .expect("B 5s 内收到 A 的请求")
        .expect("recv");
    assert_eq!(
        pkt_src_dst(&got_ab),
        (vip_a, vip_b),
        "A→B 源/目标 VIP 经转发保持"
    );

    // B → A（server-2 → server-1 的 FRWD）。
    let req_ba = icmp_echo(vip_b, vip_a, 8, 0xb001, 1);
    chb.send(&req_ba).await.expect("B 发 echo request");
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
            panic!("A 5s 内未收到 B 的请求（B→A FRWD 失败）");
        }
    };
    assert_eq!(
        pkt_src_dst(&got_ba),
        (vip_b, vip_a),
        "B→A 源/目标 VIP 经转发保持"
    );

    // 双向 FRWD 计数均递增（§2.2 第 3 步跨服转发的实证）。
    let f1 = c3.nodes[0].forward().stats();
    let f2 = c3.nodes[1].forward().stats();
    assert!(
        f1.forwarded > fwd1_before,
        "server-1 跨服转发计数递增（→{}）",
        f1.forwarded
    );
    assert!(
        f2.forwarded > fwd2_before,
        "server-2 跨服转发计数递增（→{}）",
        f2.forwarded
    );

    // 两级读目录已实际服务握手（缓存命中或线性一致读非零）。
    let ds1 = c3.nodes[0].dir().stats();
    assert!(
        ds1.cache_hits + ds1.linearizable_reads > 0,
        "SyncDirectory 服务过 respond 查询（cache={} linear={}）",
        ds1.cache_hits,
        ds1.linearizable_reads
    );

    // —— 吊销传播界（A6 ≤5s；§2.2 apply 回调）——
    let t0 = Instant::now();
    s2.core
        .net
        .revoke(&DeviceId(vip_of(&dev_a)))
        .await
        .expect("revoke 经 server-2 提交（Raft）");

    // 另一台服务器（server-1）的新握手 ≤5s 被拒。
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
    let dt = rejected_at.expect("5s 内另一台服务器必须拒新握手（A6）");
    assert!(dt <= A6_BUDGET, "拒新握手耗时 {dt:?} ≤ 5s");

    // 既有会话被杀（apply 回调 → SyncHooks → LiveSessions.kill）。
    let deadline = Instant::now() + A6_BUDGET;
    while c3.nodes[0].local_epoch() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        c3.nodes[0].local_epoch() >= 1,
        "revocation_epoch 已推进（apply）"
    );
    assert_eq!(
        s1.core.sessions.online(&vip_of(&dev_a)),
        0,
        "server-1 上 A 的会话被杀"
    );

    // 对照：未吊销的 B 仍可连（拒绝与吊销因果绑定）。
    let io = tokio::net::TcpStream::connect(&pin2.entry.relay_endpoint)
        .await
        .unwrap();
    initiate(io, &dev_b, &pin2, TunnelConfig::default())
        .await
        .expect("B 仍可接入（对照）");

    // 钉扎链路完整性（TOFU 面与本测试共用的根信任链）。
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
// 评审项 2：OPRF 逐服务器封装的就绪语义（无 wrap 明确失败 / rewrap 后新服务器可解封）
// ============================================================================

/// ① 只给节点 1/2 封装：节点 3 的 `open_sync` 在短窗内明确失败（错误点名「OPRF 封装」，
///    属 transient 类——sync.rs 的就绪重试只认该类）；
/// ② 补交节点 3 的 rewrap 后：`open_sync` 成功（本机 hybrid sk 解封进内存——OPAQUE
///    可用，core.oprf 即解封产物）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oprf_wrap_missing_server_fails_then_rewrap_enables() {
    let c3 = build_cluster_bare().await;
    let oprf_b64 = server_setup_new(&mut rand::rngs::OsRng);
    let leader = wait_leader(&c3.nodes).await;
    // 只封装节点 1/2（idents[0]/[1]——node 1/2；节点 3 无 wrap）。
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

    // ① 无对应 wrap 的服务器：短窗（300ms）后明确失败——错误点名 OPRF 封装缺失。
    let err = match ServerCore::open_sync_with_wait(
        cfg.clone(),
        c3.idents[2].clone(),
        c3.nodes[2].clone(),
        Duration::from_millis(300),
    )
    .await
    {
        Err(e) => e,
        Ok(_) => panic!("节点 3 无 wrap ⇒ open_sync 必须明确失败"),
    };
    assert!(
        err.contains("OPRF 封装"),
        "错误需点名 OPRF 封装缺失（可诊断）: {err}"
    );
    assert!(
        err.starts_with(flock_server::server::SYNC_NOT_READY_PREFIX),
        "未达封装属 transient（就绪重试语义）: {err}"
    );
    // 对照：有 wrap 的节点 1 同窗成功。
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
    .expect("节点 1 有 wrap ⇒ open_sync 成功");

    // ② rewrap 后新服务器可解封：新服务器准入 = ServerKeys 全量重登（根签，含节点 3
    // 的混合公钥——状态机 server_keys 是整体替换语义）→ 补交节点 3 的封装（根签
    // Rewrap）→ open_sync 成功。
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
    .expect("rewrap 补交后节点 3 可解封（OPAQUE 可用）");
    // 解封语义闭环：登录路径用的就是这个 OPRF（PwBegin/Login 的服务端 setup）。
    let _ = &core.oprf;
}

// ============================================================================
// M7（§7-M7.6）：双客户端跨服时 roster 在任一服务器装配一致（含 ewma 非零）
// ============================================================================

/// 断言面：
/// - **结构字段严格相等**（vip/hostname/owner/kind/online）——注册表快照与租约域
///   视图在两台服务器上一致；
/// - **ewma/last_seen 容差比较**（非零 + 双侧差 < 15s）——两服务器的本地视图来自
///   不同时刻的反熵快照（5s 周期），逐字节相等不可实现也不必要（如实声明）；
/// - 假流量泵（A→B 持续 ~2s）：A 的 tx 与 B 的 rx 在**两台服务器**的名册里都非零
///   （持有者折叠 + gossip 传播）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roster_consistent_across_servers_with_traffic_pump() {
    let c3 = build_cluster().await;
    let s1 = serve_on(&c3, 0, vec![]).await;
    let s2 = serve_on(&c3, 1, vec![]).await;

    // 开户（hostname 经 redeem 上报——字段链路实证）。
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

    // 接入（A→server-1、B→server-2）+ 包通道。
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

    // 通道物化（惰性 SYN：双向各先发一包）。
    let warm_b = icmp_echo(out_b.vip, out_a.vip, 8, 0xb000, 0);
    chb.send(&warm_b).await.expect("B warmup");
    let warm_a = icmp_echo(out_a.vip, out_b.vip, 8, 0xa000, 0);
    cha.send(&warm_a).await.expect("A warmup");
    tokio::time::sleep(Duration::from_millis(400)).await;

    // 假流量泵：A→B 持续 ~2s（每 20ms 一包 1200B ⇒ ~60KB/s 量级——EWMA 非零充分）。
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
    assert!(sent > 10, "泵出 {sent} 包");

    // 等反熵（5s）+ 折叠窗（1s）传播：ewma 经持有者折叠 → publish/反熵到对端。
    tokio::time::sleep(Duration::from_secs(7)).await;

    // 双侧装配。
    let r1 = flock_server::control::assemble_roster(&s1.core).await;
    let r2 = flock_server::control::assemble_roster(&s2.core).await;

    // 结构字段严格相等。
    let shape = |r: &[flock_server::control::PeerInfo]| {
        r.iter()
            .map(|p| (p.vip, p.hostname.clone(), p.owner.clone(), p.kind, p.online))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        shape(&r1),
        shape(&r2),
        "任一服务器装配一致（结构字段严格相等）"
    );
    // 3 Server + 2 Device。
    assert_eq!(r1.len(), 5, "{r1:?}");
    assert_eq!(
        r1.iter()
            .filter(|p| p.kind == flock_server::control::PeerKind::Server)
            .count(),
        3,
        "三台服务器各自在册"
    );
    let devices: Vec<_> = r1
        .iter()
        .filter(|p| p.kind == flock_server::control::PeerKind::Device)
        .collect();
    assert!(devices.iter().all(|p| p.online), "双客户端在线");

    // ewma 非零（双侧）：A 的 tx（接入侧计）、B 的 rx（收端计）。
    for (roster, tag) in [(&r1, "s1"), (&r2, "s2")] {
        let a = roster.iter().find(|p| p.vip == out_a.vip).expect("A 条目");
        assert!(
            a.tx_bps > 0,
            "{tag}: A 的 tx ewma 非零（持有者折叠 + 传播）: {}",
            a.tx_bps
        );
        let b = roster.iter().find(|p| p.vip == out_b.vip).expect("B 条目");
        assert!(
            b.rx_bps > 0,
            "{tag}: B 的 rx ewma 非零（收端计数 + 传播）: {}",
            b.rx_bps
        );
        assert!(a.last_seen_unix > 0 && b.last_seen_unix > 0);
    }
    // last_seen 容差（< 15s）：两视图来自不同反熵时刻。
    let ls = |r: &[flock_server::control::PeerInfo], vip: [u8; 4]| {
        r.iter().find(|p| p.vip == vip).unwrap().last_seen_unix
    };
    for vip in [out_a.vip, out_b.vip] {
        assert!(
            ls(&r1, vip).abs_diff(ls(&r2, vip)) < 15,
            "last_seen 双侧差 < 15s（反熵快照时差容差）"
        );
    }
    // hostname 经 redeem 上报进名册。
    assert!(r1
        .iter()
        .any(|p| p.vip == out_a.vip && p.hostname == "roster-a-pad"));
    assert!(r1
        .iter()
        .any(|p| p.vip == out_b.vip && p.hostname == "roster-b-pad"));
}

// ============================================================================
// server_vip_of 一致性（多主形态）：open_sync 的 VIP 断言
// ============================================================================

/// node 1 的确定性服务器 VIP = 100.64.0.1：配置错位（.9）⇒ 拒起且错误**给出期望值**、
/// 属永久错误（非 SYNC_NOT_READY 前缀——就绪重试循环不吞它）；匹配值可起。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_sync_rejects_vip_mismatch_with_expected_value() {
    let c3 = build_cluster().await;
    let tmp = tempfile::tempdir().expect("tmp");
    let state_dir = tmp.path().to_path_buf();
    std::mem::forget(tmp);

    // 错配（node 1 应为 .1，配了 .9）：明确失败 + 期望值 + 永久错误（短窗内立即返回，
    // 不等 wrap）。
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
        Ok(_) => panic!("vip 错配必须拒起"),
    };
    assert!(
        err.contains("100.64.0.1"),
        "错误给出期望值（确定性推导）: {err}"
    );
    assert!(
        !err.starts_with(flock_server::server::SYNC_NOT_READY_PREFIX),
        "配置错误是永久错误（不被就绪重试吞掉）: {err}"
    );
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(2),
        "断言先于 wrap 等待（立即拒）"
    );

    // 匹配（.1 = server_vip_of(node 1)）⇒ 正常起（wraps 已在 build_cluster 落库）。
    cfg.vip = "100.64.0.1".parse().unwrap();
    ServerCore::open_sync_with_wait(
        cfg,
        c3.idents[0].clone(),
        c3.nodes[0].clone(),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("推导值匹配 ⇒ 可起");
}

// ============================================================================
// M7（§7-M7.5）：回收器——registered_at 锚 + 租约视图就绪闸门（多主形态）
// ============================================================================

/// 断言面（单节点 raft 集群 = 无对端 ⇒ 永无远端租约事件——闸门两态可精确驱动）：
/// - **闸门关**（租约表无远端事件）：即使 dev_idle 的 registered_at 锚已超窗（40d >
///   30d 保留期）也**不回收**——重启后「反熵回填 ≤5s 与回收首拍赛跑」窗口内，远端
///   托管设备的租约行缺失，误终态化会殃及全网（含在线设备——邀请已消费即砖死）；
/// - **闸门开**（注入一条远端 gossip = 反熵回填完成）：从未在线且锚超窗的 dev_idle
///   被回收；有租约观测的 dev_online（registered_at 同为 40d 前、last_seen = 当前）
///   不动——观测值优先于陈旧锚。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reaper_anchor_and_lease_gate_multi_primary() {
    use flock_sync::lease::GossipMsg;

    // 单节点集群装配（root 签身份 + 自签目录 + 内存织物仅本机）。
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
    // Bootstrap + ServerKeys + 本机 Rewrap（open_sync 就绪前置）。
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

    // 两台设备：registered_at 同为 40 天前（提交方注入——apply 确定性）；dev_online
    // 另有本机租约观测（publish ⇒ last_seen = 当前）。
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

    // ① 闸门关（表有行但自启动起零远端事件）：锚超窗的 dev_idle 也不回收。
    assert!(!node.lease().reaper_view_ready(), "单节点无对端 ⇒ 闸门关");
    let expired = flock_server::server::reap_once(&core, 30, now + day).await;
    assert!(expired.is_empty(), "视图未就绪 ⇒ 跳过整趟: {expired:?}");
    assert_eq!(
        row_status(&dev_idle),
        flock_sync::proto::DeviceStatus::Active
    );
    assert_eq!(
        row_status(&dev_online),
        flock_sync::proto::DeviceStatus::Active
    );

    // ② 闸门开（注入一条远端 gossip = 反熵回填完成）：dev_idle（从未在线且锚 41d >
    // 30d）回收；dev_online（观测 1d < 30d）不动。
    node.lease()
        .merge_remote(GossipMsg::Anti { entries: vec![] });
    assert!(node.lease().reaper_view_ready());
    let expired = flock_server::server::reap_once(&core, 30, now + day).await;
    assert_eq!(expired, vec![dev_idle], "仅锚超窗且从未在线者回收");
    assert_eq!(
        row_status(&dev_idle),
        flock_sync::proto::DeviceStatus::Expired
    );
    assert_eq!(
        row_status(&dev_online),
        flock_sync::proto::DeviceStatus::Active,
        "租约观测（1d）优先于陈旧锚（41d）"
    );
    // 幂等：同窗再跑 ⇒ 空趟。
    let expired = flock_server::server::reap_once(&core, 30, now + day).await;
    assert!(expired.is_empty(), "幂等");
}

/// M7 roster 测试的邀请 fixture（登记 + 根签签发）。
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
