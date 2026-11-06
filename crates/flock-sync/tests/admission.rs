//! tests/admission：集群准入与 rewrap 授权（docs/design.md §7-M4 admission 组）。
//!
//! 1. **无入群凭证/伪造凭证的节点在服务器-服务器握手层被拒**——拿不到快照也进不了
//!    Raft（§4-2：openraft 网络适配器只挂在认证会话之上；R19 红线——伪节点可索要
//!    快照与 re-wrap 即打开全网口令离线字典面）。
//! 2. **learner 加入 → 快照同步 → add_voter（根密钥签名）→ 提升为 voter**（§4-3
//!    授权路径定死：learner 只能收到复制流，成为 voter 必须状态机验签通过）。
//! 3. **rewrap 无根签名 ⇒ 状态机拒绝；有签名 ⇒ 新服务器混合公钥进入封装集**
//!    （OPRF key 副本数 +1 可观测；被入侵的单台在册服务器没有根密钥，无法触发）。

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
// 1. 无凭证/伪造凭证 ⇒ 服务器-服务器握手层被拒
// ============================================================================

/// 拨号一个真实服务器并以「无凭证 rogue 设备材料」发起会话。
/// `pin` 决定声称的目标（真 entry 才能走通 KEM——攻击者可拿到公开材料）。
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

    // 无凭证：rogue 持随机设备密钥，对真 entry（公开材料可拼出）发起——
    // 应答侧 PeerDirectory 只认根签目录内的身份 ⇒ 握手层拒。对发起端表现为不透明的
    // 连接终止（flock-protocol 的时序对齐设计：DeviceRejected 不外泄具体原因）。
    let target = c.node_of(2);
    let before = target.rejected_handshakes();
    let _ = rogue_handshake(&c, 2, &c.fx.root, target.entry().clone())
        .await
        .expect_err("无凭证 rogue 必被拒");
    // 应答端确实在握手层拒绝（计数前进）——拿不到会话 ⇒ 进不了分发器 ⇒
    // 拿不到快照也进不了 Raft（§4-2）。
    assert!(
        target.rejected_handshakes() > before,
        "应答侧握手拒绝计数前进（before={before}, after={}）",
        target.rejected_handshakes()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rogue_with_forged_root_rejected_at_handshake() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let _ = c.leader().await;

    // 伪造凭证：rogue 自签一套根/凭证（他签 root）——即便声称的目标 entry 为真
    // （KEM 可走通），其「设备身份」不在本集群根签目录内 ⇒ 应答侧握手层拒。
    let forged_root = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
    let target = c.node_of(3);
    let before = target.rejected_handshakes();
    let _ = rogue_handshake(&c, 3, &forged_root, target.entry().clone())
        .await
        .expect_err("他签根的 rogue 必被拒");
    assert!(
        target.rejected_handshakes() > before,
        "应答侧握手拒绝计数前进"
    );
}

// ============================================================================
// 2. learner → 快照同步 → add_voter（根签）→ 提升
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn learner_snapshot_add_voter_promotion() {
    let mut c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let (leader_idx, _) = c.leader().await;

    // 预置状态：2 台设备 + 1 次吊销（epoch=1）——快照必须完整携带。
    for i in 1u8..=2 {
        let resp = c.nodes[(leader_idx + 1) % 3]
            .write(SyncRequest::RegisterDevice {
                owner: format!("u{i}"),
                x25519: [i; 32],
                ed25519: [i; 32],
                hostname: String::new(),
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

    // —— 准入流水（§4-3）——
    // (a) 运维用根密钥签发新节点入群凭证 + 新目录（dir_version=2）。
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
    // (b) 现有节点 install 新目录（根验签 + 互连映射热更新——leader 才能拨新节点）。
    for n in &c.nodes {
        n.install_directory(&dir_v2).expect("install dir v2");
    }
    // 换根签名的目录 ⇒ 拒（准入材料不可被他签注入）。
    let other_root = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);
    let forged_dir =
        ClusterDirectory::issue(&other_root, c.fx.cluster_id, 3, vec![n4.entry.clone()]);
    assert!(
        c.nodes[0].install_directory(&forged_dir).is_err(),
        "他签目录拒"
    );

    // dir_pull serve：下发的是根签 v2 目录（客户端 PinStore::record_directory 可直接
    // 落地：根验签 + 版本单调）；since=2 ⇒ 无新内容（304 语义）。
    let resp = c.nodes[0].directory().dir_pull_response(0);
    assert_eq!(resp.version, 2);
    let served = ClusterDirectory::from_bytes(&resp.bytes.expect("full dir")).expect("parse");
    assert!(served.verify(&c.fx.root.verifying_key()), "根签目录");
    assert_eq!(served.servers.len(), 4);
    assert!(
        c.nodes[0].directory().dir_pull_response(2).bytes.is_none(),
        "304"
    );

    // (c) 新节点以 learner 加入（不做 initialize——不是初始成员）。
    let n4_idx = c.build_node(&n4, &dir_v2, None).await;

    // (d) leader 压实日志（触发快照 + purge）⇒ learner 只能走快照同步路径。
    c.nodes[leader_idx]
        .snapshot_and_purge()
        .await
        .expect("snapshot+purge");

    // (e) add_learner（blocking：等复制/快照追平）。
    c.nodes[leader_idx]
        .add_learner(4)
        .await
        .expect("add learner");

    // 快照同步断言：learner 的状态机拿到完整状态（设备/epoch/票据根），
    // 且其日志为空（purge 后仅快照可携带这些状态）。
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
            assert_eq!(g.revoked, 1, "吊销记录随快照");
            assert_eq!(g.config_version, st.config_version);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "learner 快照同步超时（state={:?}）",
            g
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // learner 可读但不可写（client_write 转发 leader——非 voter 不参与表决；此处断言
    // 其尚不在 voters 集内）。
    {
        let v = c.nodes[leader_idx]
            .read_linearizable(ReadQuery::State)
            .await
            .expect("state");
        let ReadView::State(g) = v else { panic!() };
        assert!(!g.voters.contains(&4), "提升前 node4 不是 voter");
    }

    // (f) add_voter 无根签名 ⇒ 状态机拒绝 + 不提升。
    let forged_root = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
    let bad = c.nodes[leader_idx]
        .add_voter_signed(&forged_root, 4)
        .await
        .expect("write ok");
    assert!(
        matches!(bad, SyncResponse::Error(StateError::BadRootSignature)),
        "他签 add_voter 拒: {bad:?}"
    );
    {
        let v = c.nodes[leader_idx]
            .read_linearizable(ReadQuery::State)
            .await
            .expect("state");
        let ReadView::State(g) = v else { panic!() };
        assert!(!g.voters.contains(&4), "拒绝路径不提升");
    }

    // (g) add_voter 有根签名 ⇒ 状态机记录 + openraft 提升（joint 共识）。
    let ok = c.nodes[leader_idx]
        .add_voter_signed(&c.fx.root, 4)
        .await
        .expect("add voter");
    assert!(
        matches!(ok, SyncResponse::Admin(AdminAck::AddVoter { node_id: 4 })),
        "{ok:?}"
    );
    // 成员收敛：全网 metrics 的 voters 含 4。
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
        assert!(Instant::now() < deadline, "voter 提升未收敛");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 提升后 node4 可承载写（任意节点写语义）且全网可见。
    let resp = c.nodes[n4_idx]
        .write(SyncRequest::RegisterDevice {
            owner: "n4".into(),
            x25519: [7; 32],
            ed25519: [7; 32],
            hostname: String::new(),
        })
        .await
        .expect("voter 写");
    assert!(matches!(resp, SyncResponse::Device(_)));
    let v = c.nodes[0]
        .read_linearizable(ReadQuery::State)
        .await
        .expect("read");
    let ReadView::State(g) = v else { panic!() };
    assert_eq!(g.devices, 3, "node4 的写全网可见");
}

// ============================================================================
// 3. rewrap ±根签名（OPRF key 副本数 +1 可观测）
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rewrap_requires_root_and_targets_new_server() {
    let c = TestCluster::new(&NODES).await;
    bootstrap(&c, 0).await;
    let (leader_idx, _) = c.leader().await;
    let writer = (leader_idx + 2) % 3;

    // 新服务器 node4 入目录（准入后形态——此处只测 rewrap 授权面，无需进 Raft）。
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

    // 无根签名 ⇒ 状态机拒绝（被入侵的在册服务器没有根密钥，无法触发 rewrap）。
    let forged = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
    let bad = c.nodes[writer]
        .write(SyncRequest::rewrap_signed(&forged, 4, vec![1; 16]))
        .await
        .expect("write ok");
    assert!(
        matches!(bad, SyncResponse::Error(StateError::BadRootSignature)),
        "{bad:?}"
    );
    // 未登记 server_keys 前即便根签也拒（封装目标必须在册——先 server_keys 后 rewrap）。
    let bad2 = c.nodes[writer]
        .write(SyncRequest::rewrap_signed(&c.fx.root, 4, vec![1; 16]))
        .await
        .expect("write ok");
    assert!(
        matches!(bad2, SyncResponse::Error(StateError::NotFound(_))),
        "{bad2:?}"
    );

    // server_keys（根签）登记全套混合公钥（含新服务器——node4 仅入目录，未进 Raft）。
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

    // 有根签名 ⇒ 封装副本 +1 可观测（wraps 集内出现 node4 条目）。
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
    assert_eq!(after.len(), before + 1, "OPRF key 副本数 +1 可观测");
    assert!(after.iter().any(|(sid, _)| *sid == 4), "node4 进入封装集");

    // 新服务器能取出并以自己的私钥开封（真实拿到 OPRF key 副本）。
    // node4 不在本测试集群进程内——用其身份材料在本地验证（envelope v2 往返）。
    let mut opened = Vec::new();
    flock_protocol::envelope::open_v2(&n4.static_hybrid, &wrapped[..], &mut opened).expect("open");
    assert_eq!(opened, secret);

    // 票据根跨节点一致（TicketIssuer 已随第一部分落地——此处复证新目录节点可验）。
    let t = c.nodes[writer]
        .issue_ticket(dev_id_of(&[8; 32]), 1_000)
        .expect("ticket");
    assert!(c.nodes[0]
        .verify_ticket(&t, &dev_id_of(&[8; 32]), 1_001)
        .is_ok());
    let _ = TicketIssuer::from_root(&[42; 32]); // 密钥根派生确定性
}

fn sha(b: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(b).into()
}

fn dev_id_of(b: &[u8; 32]) -> [u8; 32] {
    sha(b)
}
