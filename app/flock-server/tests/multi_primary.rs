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

    // Bootstrap（票据根进 Raft，§4）+ SetOprf（共享 OPRF——跨节点登录，§2.4）。
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
    let oprf_b64 = server_setup_new(&mut rand::rngs::OsRng);
    let oprf_op = flock_sync::proto::AdminOp::Rewrap {
        server_id: 0,
        wrapped: oprf_b64.as_bytes().to_vec(),
    };
    let _ = oprf_op; // （SetOprf 走独立构造，非 AdminOp——见下）
    let set_oprf = SyncRequest::SetOprf(flock_sync::proto::RootSigned {
        op: oprf_b64.clone(),
        sig: {
            use ed25519_dalek::Signer as _;
            let mut canon = b"flock-sync/set-oprf/v1".to_vec();
            canon.extend_from_slice(&(oprf_b64.len() as u32).to_le_bytes());
            canon.extend_from_slice(oprf_b64.as_bytes());
            root.sign(&canon).to_bytes()
        },
    });
    let resp = leader.write(set_oprf).await.expect("set oprf");
    assert!(
        matches!(resp, flock_sync::proto::SyncResponse::Ok),
        "set_oprf: {resp:?}"
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
    let cfg = ServerConfig {
        state_dir,
        bind: "127.0.0.1:9443".parse().unwrap(),
        mode: "direct".into(),
        advertise_endpoint: endpoint.clone(),
        extra_endpoints,
        dir_version: 1,
        ticket_ttl_secs: 60,
        admin_bind: "127.0.0.1:0".parse().unwrap(),
        max_sessions: 1024,
        tun_name: "tun0".into(),
        vip: "100.64.0.1".parse().unwrap(),
        frp: None,
        sync: None, // 装配经 open_sync（进程内），不走配置文件路径
    };
    let core = ServerCore::open_sync(cfg, c3.idents[idx].clone(), c3.nodes[idx].clone())
        .await
        .expect("open_sync");
    tokio::spawn(core.clone().serve_listener(l));
    SyncServer { core, endpoint }
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
    while c3.nodes[0].sm().epoch() == 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        c3.nodes[0].sm().epoch() >= 1,
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
