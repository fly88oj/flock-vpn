//! tests/cluster：3 节点内存集群（注入 RTT 100ms）八项断言（docs/design.md §7-M4，
//! 本批次 ask 的完成门禁）。
//!
//! 1. 任意节点写 → 任意节点线性一致读 ≤2s 可见（含吊销记录）；
//! 2. kill leader → 重选举 ≤15s 且无丢提交；
//! 3. 同设备双服务端租约冲突 → 新者胜 + 旧端踢出回调；
//! 4. register→revoke→register IP 不复用；
//! 5. server_keys→rewrap 往返（envelope v2 封装 → 状态机落库 → 目标服务器开封）；
//! 6. revoke 提交后各节点 apply 回调 epoch 前进 + 杀会话钩子 ≤2s；
//! 7. **apply-lag 熔断**——follower 落后 5s 期间注入吊销 ⇒ 拒用缓存（降级线性一致读）
//!    且新握手被拒（§4 陈旧读边界 / R24）；
//! 8. 票据密钥根在 Raft 内：A 签 B 验，吊销后全网失效（epoch）。
//!
//! RTT 注入 = 每方向 50ms 线路延迟（§7-M4 100ms 校准）；节点故障 = MemoryFabric::cut。

use std::sync::Arc;
use std::time::{Duration, Instant};

use flock_protocol::session::{ClusterId, DeviceId, LookupVerdict, ServerId, ServerIdentity};
use flock_protocol::trust::ClusterDirectory;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use chml_sync::hooks::HookRecorder;
use chml_sync::proto::{
    AdminAck, NodeId, ReadQuery, ReadView, ServerKeyEntry, StateError, SyncRequest, SyncResponse,
    VerdictW,
};
use chml_sync::testutil::{FabricRegistry, MemoryFabric};
use chml_sync::ticket::TicketError;
use chml_sync::{SyncNode, SyncNodeBuilder, SyncSettings};

/// 每方向 50ms ⇒ RTT 100ms。
const RTT_HALF: Duration = Duration::from_millis(50);
const NODES: [u64; 3] = [1, 2, 3];

/// NodeId ↔ ServerId（与 chml_sync::wire::sid_of 同映射）。
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

/// 3 节点测试集群（共享根密钥/根签目录/织物注册表）。
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
        let root = SigningKey::from_bytes(&[7u8; 32]);
        let cluster_id = ClusterId([9u8; 16]);
        let reg = MemoryFabric::registry();
        let tmp = tempfile::tempdir().expect("tmpdir");

        // 根签目录（入群凭证公开部分——互连双向认证的材料源）。
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
                SyncSettings::default(),
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

    /// 等 leader 出现并返回**其自身**下标（≤15s）——「任一节点知道 leader」≠ leader 本体。
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
        panic!("15s 内未选出 leader");
    }
}

/// 引导集群身份（票据密钥根进 Raft）。
async fn bootstrap(cluster: &Cluster, node_idx: usize) {
    let resp = must_write(
        &cluster.nodes[node_idx],
        SyncRequest::bootstrap_signed(&cluster.root, [9; 16], [42; 32]),
    )
    .await;
    assert!(matches!(resp, SyncResponse::Ok), "bootstrap: {resp:?}");
}

// ============================================================================
// 1. 任意节点写 → 任意节点线性一致读 ≤2s（含吊销记录）
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_any_read_any_linearizable_within_2s() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, _) = cluster.leader().await;
    // 写入者/读取者都选非 leader 节点（写转发 + 读转发路径）。
    let writer = (leader_idx + 1) % 3;
    let reader = (leader_idx + 2) % 3;

    let t0 = Instant::now();
    let resp = must_write(
        &cluster.nodes[writer],
        SyncRequest::RegisterDevice {
            owner: "alice".into(),
            x25519: [1; 32],
            ed25519: [1; 32],
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
        "任意节点线性一致读可见: {v:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(2),
        "写→读 ≤2s（实际 {:?}）",
        elapsed
    );
    assert_eq!(
        row.vip,
        chml_sync::VIP_FIRST.to_be_bytes(),
        "首 VIP = 100.64.0.11（.1–.10 保留给服务器，§6.2）"
    );

    // 吊销记录同样 ≤2s 线性一致可见。
    let t1 = Instant::now();
    must_write(&cluster.nodes[writer], SyncRequest::Revoke { device: id.0 }).await;
    let v = cluster.nodes[reader]
        .read_linearizable(ReadQuery::Lookup(id.0))
        .await
        .expect("read");
    assert!(
        matches!(v, ReadView::Verdict(VerdictW::Revoked { .. })),
        "吊销记录线性一致可见: {v:?}"
    );
    assert!(
        t1.elapsed() <= Duration::from_secs(2),
        "吊销写→读 ≤2s（实际 {:?}）",
        t1.elapsed()
    );
}

// ============================================================================
// 2. kill leader → 重选举 ≤15s 且无丢提交
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_leader_reelects_within_15s_no_lost_writes() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, leader_id) = cluster.leader().await;

    // 先写 5 条已确认提交（经非 leader 节点——写转发路径）。
    for i in 0..5u8 {
        let resp = must_write(
            &cluster.nodes[(leader_idx + 1) % 3],
            SyncRequest::RegisterDevice {
                owner: format!("u{i}"),
                x25519: [i; 32],
                ed25519: [i + 1; 32],
            },
        )
        .await;
        assert!(matches!(resp, SyncResponse::Device(_)));
    }

    // kill leader：Raft 停机 + 织物切除（dial 拒绝）。
    cluster.nodes[leader_idx]
        .shutdown()
        .await
        .expect("leader shutdown");
    MemoryFabric::cut(&cluster.reg, &sid(leader_id));

    // 重选举 ≤15s（选举超时 1.5~3s + RTT 100ms）。
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
    let (_ni, _nl) = new_leader.expect("15s 内重选举");
    assert!(
        t0.elapsed() <= Duration::from_secs(15),
        "重选举 {:?}",
        t0.elapsed()
    );

    // 无丢提交：经幸存 follower 线性一致读（读转发）= 全部 5 台设备在册。
    let survivor = (leader_idx + 1) % 3;
    let view = cluster.nodes[survivor]
        .read_linearizable(ReadQuery::State)
        .await
        .expect("read");
    let ReadView::State(st) = view else { panic!() };
    assert_eq!(st.devices, 5, "无丢提交（5 台在册）");

    // 新 leader 继续可写。
    let resp = must_write(
        &cluster.nodes[survivor],
        SyncRequest::RegisterDevice {
            owner: "post".into(),
            x25519: [9; 32],
            ed25519: [9; 32],
        },
    )
    .await;
    assert!(
        matches!(resp, SyncResponse::Device(_)),
        "新 leader 可写: {resp:?}"
    );
}

// ============================================================================
// 3. 同设备双服务端租约冲突 → 新者胜 + 旧端踢出回调
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_conflict_newer_wins_old_side_evicted() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let _ = cluster.leader().await;
    let device = [0xab; 32];

    // 节点 1 先发布（设备连在节点 1）。
    cluster.nodes[0].publish_lease(&device).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        cluster.nodes[1].lease().observe(&device).unwrap().holder,
        1,
        "租约传播到节点 2"
    );

    // 节点 2 发布同设备更新租约 ⇒ 新者胜 + 节点 1 踢出回调（事件推送 ≤1s + 反熵兜底）。
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
        "旧端（节点 1）踢出回调触发（实际 {:?}）",
        cluster.recorders[0].evictions()
    );
    assert!(
        t0.elapsed() <= Duration::from_secs(3),
        "踢出回调 ≤3s（实际 {:?}）",
        t0.elapsed()
    );
    // 新者胜：各节点 observe 一致指向节点 2。
    for n in &cluster.nodes {
        assert_eq!(
            n.lease().observe(&device).unwrap().holder,
            2,
            "新者胜（节点 {}）",
            n.id()
        );
    }
}

// ============================================================================
// 4. register→revoke→register IP 不复用
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
        },
    )
    .await;
    let SyncResponse::Device(b) = b else { panic!() };
    let (ia, ib) = (u32::from_be_bytes(a.vip), u32::from_be_bytes(b.vip));
    assert!(ib > ia, "IP 不复用：水位线只进不退（{ia} → {ib}）");
    // 同设备重注册拒（禁用不删除：Revoked 终态行保留）。
    let again = cluster.nodes[writer]
        .write(SyncRequest::RegisterDevice {
            owner: "u".into(),
            x25519: [1; 32],
            ed25519: [1; 32],
        })
        .await
        .expect("write ok");
    assert!(
        matches!(again, SyncResponse::Error(StateError::DeviceExists)),
        "{again:?}"
    );
}

// ============================================================================
// 5. server_keys→rewrap 往返（OPRF 类秘密 → envelope v2 → 状态机 → 目标服务器开封）
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_keys_rewrap_roundtrip() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, _) = cluster.leader().await;
    let writer = (leader_idx + 2) % 3;

    // 目标服务器 = 节点 2（封装目标 = 其入群凭证内的混合公钥）。
    let target_entry = &cluster.idents[1].entry;
    let entries = vec![ServerKeyEntry {
        server_id: 2,
        identity_pub: *target_entry.identity_pub.as_bytes(),
        hybrid_pub: target_entry.static_hybrid_pub.to_bytes().to_vec(),
    }];

    // 无根签名（他签）⇒ 状态机拒绝（被入侵的在册服务器没有根密钥，无法触发 rewrap）。
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
        "他签 server_keys 拒: {bad:?}"
    );
    let bad_rw = cluster.nodes[writer]
        .write(SyncRequest::rewrap_signed(&forged_root, 2, vec![1, 2, 3]))
        .await
        .expect("write ok");
    assert!(
        matches!(bad_rw, SyncResponse::Error(StateError::BadRootSignature)),
        "他签 rewrap 拒: {bad_rw:?}"
    );

    // 根签 server_keys 落库。
    let resp = must_write(
        &cluster.nodes[writer],
        SyncRequest::server_keys_signed(&cluster.root, entries),
    )
    .await;
    assert!(
        matches!(resp, SyncResponse::ServerKeys { servers: 1 }),
        "{resp:?}"
    );

    // OPRF 类秘密 → envelope v2 封装到节点 2 的混合公钥 → 根签 rewrap 提交。
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
        "OPRF key 副本数 +1 可观测（封装字节数入账）"
    );

    // 节点 2 线性一致读取出封装副本，以自己的静态混合私钥开封 → 原秘密。
    let view = cluster.nodes[1]
        .read_linearizable(ReadQuery::Wrap(2))
        .await
        .expect("read");
    let ReadView::Wrap(Some(got)) = view else {
        panic!("wrap 落库: {view:?}")
    };
    assert_eq!(got, wrapped, "封装副本原样落库");
    let mut opened = Vec::new();
    flock_protocol::envelope::open_v2(&cluster.idents[1].static_hybrid, &got[..], &mut opened)
        .expect("open");
    assert_eq!(opened, secret, "rewrap 往返：目标服务器开封得到原秘密");
}

// ============================================================================
// 6. revoke 提交后各节点 apply 回调 epoch 前进 + 杀会话钩子 ≤2s
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
        },
    )
    .await;
    let SyncResponse::Device(_) = resp else {
        panic!()
    };
    let id = dev_id(&[3; 32]);

    // 吊销前签发的票据（epoch = 0）——清拒票据断言用。
    let pre_ticket = cluster.nodes[writer]
        .issue_ticket(id.0, 1_000)
        .expect("ticket");

    let t_commit = Instant::now();
    let resp = must_write(&cluster.nodes[writer], SyncRequest::Revoke { device: id.0 }).await;
    let SyncResponse::Epoch(new_epoch) = resp else {
        panic!()
    };
    assert!(new_epoch >= 1, "吊销推进 revocation_epoch");

    // 各节点（含 follower）apply 回调 ≤2s：epoch 前进 + 杀会话钩子触发。
    for (i, rec) in cluster.recorders.iter().enumerate() {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let events: Vec<_> = rec
                .revocations()
                .into_iter()
                .filter(|e| e.device == id.0)
                .collect();
            if let Some(ev) = events.last() {
                assert_eq!(ev.new_epoch, new_epoch, "节点 {} epoch 前进一致", i + 1);
                break;
            }
            assert!(
                Instant::now() <= deadline,
                "节点 {} 2s 内未触发杀会话钩子（事件 {:?}）",
                i + 1,
                rec.revocations()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            t_commit.elapsed() <= Duration::from_secs(2),
            "节点 {} 回调 ≤2s（实际 {:?}）",
            i + 1,
            t_commit.elapsed()
        );
    }
    // 票据 epoch 随之失效（清拒票据的本地侧数据面：吊销前签的票 ⇒ StaleEpoch）。
    assert!(matches!(
        cluster.nodes[writer].verify_ticket(&pre_ticket, &id.0, 1_001),
        Err(TicketError::StaleEpoch { .. })
    ));
    let _ = new_epoch;
}

// ============================================================================
// 7. apply-lag 熔断：follower 落后 5s 期间注入吊销 ⇒ 拒用缓存 + 新握手被拒
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_lag_breaker_rejects_cache_and_new_handshake() {
    let cluster = Cluster::new().await;
    bootstrap(&cluster, 0).await;
    let (leader_idx, _) = cluster.leader().await;
    let writer = (leader_idx + 1) % 3;
    let lagger_idx = (leader_idx + 2) % 3;
    let lagger = &cluster.nodes[lagger_idx];

    // 设备密钥用真实 Ed25519 公钥（[4;32] 非法点 ⇒ to_verdict fail-closed）。
    let dev = SigningKey::from_bytes(&[4u8; 32]);
    let dev_pub = *dev.verifying_key().as_bytes();
    let resp = must_write(
        &cluster.nodes[writer],
        SyncRequest::RegisterDevice {
            owner: "carol".into(),
            x25519: [4; 32],
            ed25519: dev_pub,
        },
    )
    .await;
    let SyncResponse::Device(_) = resp else {
        panic!()
    };
    let id = dev_id(&dev_pub);

    // 预热缓存：一次成功查询后该设备在 lagging follower 缓存中为 Active。
    let v = lagger.dir().lookup_async(id).await;
    assert!(
        matches!(v, LookupVerdict::Active(_)),
        "预热：查询给 Active（{v:?}）"
    );
    let v = lagger.dir().lookup_async(id).await;
    assert!(matches!(v, LookupVerdict::Active(_)));

    // 人为让 follower 落后 5s：apply 停摆（网络与日志照常）。
    lagger.sm().lag.arm(Duration::from_secs(5));
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 期间注入吊销（leader + 健康 follower 提交；lagging follower 落后）。
    must_write(&cluster.nodes[writer], SyncRequest::Revoke { device: id.0 }).await;

    // 熔断：观察到 leader_commit > applied 持续 >2s ⇒ 打开。
    let deadline = Instant::now() + Duration::from_secs(4);
    while !lagger.breaker_open() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(lagger.breaker_open(), "apply-lag >2s ⇒ 熔断打开");

    // 拒用缓存：该 follower 的目录查询走降级线性一致读（转发 leader）⇒ Revoked。
    // 「新握手被拒」——session::respond 消费同一目录判定，Revoked ⇒ DeviceRejected。
    let stats_before = lagger.dir().stats();
    let t_lookup = Instant::now();
    let v = lagger.dir().lookup_async(id).await;
    let stats_after = lagger.dir().stats();
    assert!(
        matches!(v, LookupVerdict::Revoked { .. }),
        "降级线性一致读 ⇒ 吊销可见（新握手被拒）: {v:?}"
    );
    assert!(
        stats_after.breaker_degraded > stats_before.breaker_degraded,
        "熔断路径计数前进（before={:?} after={:?}）",
        stats_before,
        stats_after
    );
    assert!(
        stats_after.cache_hits == stats_before.cache_hits,
        "熔断期拒用本地缓存（cache_hits 不前进）"
    );
    assert!(
        t_lookup.elapsed() <= Duration::from_secs(2),
        "降级读在预算内"
    );

    // 对照：健康 follower（未滞后）不受熔断影响——epoch 前进后缓存失效，同样给 Revoked。
    let v2 = cluster.nodes[writer].dir().lookup_async(id).await;
    assert!(matches!(v2, LookupVerdict::Revoked { .. }));

    // 追平后熔断恢复（apply 停摆结束 ⇒ applied 追上 leader_commit）。
    lagger.sm().lag.disarm();
    let deadline = Instant::now() + Duration::from_secs(8);
    while lagger.breaker_open() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!lagger.breaker_open(), "追平后熔断恢复");
    assert_eq!(lagger.local_epoch(), 1, "滞后节点最终 apply（epoch 前进）");
}

// ============================================================================
// 8. 票据密钥根在 Raft：A 签 B 验；吊销后全网失效（epoch）
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
        },
    )
    .await;
    let SyncResponse::Device(_) = resp else {
        panic!()
    };
    let id = dev_id(&[5; 32]).0;

    // A（writer）签发；等 Bootstrap/注册在全网 apply（≤3s）后 A/B/C 全部可验——
    // 票据密钥根在 Raft 状态内复制，任何服务器都验得。
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
        assert!(Instant::now() < deadline, "3s 内全网可验票据（根复制）");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 吊销推进 epoch ⇒ 旧票据全网失效（StaleEpoch——清拒票据）。
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
        assert!(Instant::now() < deadline, "3s 内全网票据失效（epoch 传播）");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
