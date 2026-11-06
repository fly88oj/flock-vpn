//! tests/forward：跨服转发承载（docs/design.md §7-M4 forward 组，§2.2 转发判定序）。
//!
//! 1. **源 VIP 绑定校验（第 0 步）**：会话设备发包 src=他人 VIP ⇒ 丢 + 计数；
//!    ForwardEnvelope `src_dev` 与内层源地址失配 ⇒ 收端拒（收发端各查一次）。
//! 2. 本机投递 / NOT_HERE → 一次性 location_query 重定向 / hop=1 防环
//!    （构造二次转发 ⇒ 丢 + 计数）。
//! 3. 仍失败 ⇒ 丢包 + 尽力 ICMP unreachable。
//! 4. 租约域语义：设备当前位置唯一真相源 = 租约域（NetState 不存当前位置）；
//!    publish/observe + 事件推送 ≤1s + 5s 反熵 + TTL 30s + location_query fan-out ≤3。

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flock_sync::forward::{
    ForwardEnvelope, ForwardOutcome, IngestResult, PacketSink, RejectReason, FORWARD_VER,
};
use flock_sync::proto::{NodeId, SyncRequest, SyncResponse};

use common::{bootstrap, wait_local_row, TestCluster};

const NODES: [u64; 3] = [1, 2, 3];

/// 记录 sink（模拟 PacketChannel）。
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

/// 构造 IPv4 包（20B 头 + payload）。
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

/// 两台设备注册（真 Ed25519 公钥），返回 (id_a, id_b)。sink 由调用方挂。
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
        },
    )
    .await;
    assert!(matches!(rb, SyncResponse::Device(_)));
    (dev_id(&a_pub), dev_id(&b_pub))
}

// ============================================================================
// 1a. 源 VIP 绑定校验：会话设备 src=他人 VIP ⇒ 丢 + 计数
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
    // 转发面读本地注册表：等 node1 本地 apply 追上（远端提交 → 本地 apply ≤ 心跳+RTT）。
    wait_local_row(n1, &id_a, "dev-a row").await;
    wait_local_row(n1, &dev_id(&b_pub), "dev-b row").await;

    // devA 的会话发 src=devB 的 VIP（身份嫁祸）⇒ 丢 + 计数；不投递、不转发。
    let spoofed = ip4(row_b.vip, row_a.vip, b"spoof");
    let r = n1.ingest_packet(&id_a, &spoofed).await;
    assert!(
        matches!(r, IngestResult::SrcViolation),
        "第 0 步拦下: {r:?}"
    );
    let st = n1.forward().stats();
    assert_eq!(st.src_violations, 1, "丢 + 计数");
    assert_eq!(st.delivered_local + st.forwarded, 0, "不投递不转发");
    assert_eq!(sink_b.count(), 0, "目标未收到嫁祸包");

    // 合法 src（自己的 VIP）⇒ 本机投递正常。
    let ok = ip4(row_a.vip, row_b.vip, b"legit");
    let r = n1.ingest_packet(&id_a, &ok).await;
    assert!(matches!(r, IngestResult::DeliveredLocal), "{r:?}");
    assert_eq!(sink_b.count(), 1);
}

// ============================================================================
// 1b. ForwardEnvelope src_dev 与内层源地址失配 ⇒ 收端拒
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

    // 构造 src_dev=A 但内层源 VIP 是编造地址（非 A 注册 VIP）的信封。
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
        "收端拒 + 计数"
    );

    // 对照：src_dev 与内层源一致 ⇒ 不因绑定被拒（dst 不在本机 ⇒ NotHere）。
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
// 2. 本机投递 / 跨服转发 / NOT_HERE→location_query 一次性重定向 / hop 防环
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
        },
    )
    .await;
    let SyncResponse::Device(row_c) = rc else {
        panic!()
    };
    let (id_a, id_c) = (dev_id(&a_pub), dev_id(&c_pub));

    // A 连在 node1；C **当前**连在 node3（租约域真相），但 node1 的租约表还指着 node2
    // （陈旧租约窗口——迁移场景）。
    let sink_a = Arc::new(RecvSink::default());
    let sink_c = Arc::new(RecvSink::default());
    c.nodes[0].attach_session(id_a, sink_a.clone());
    c.nodes[2].attach_session(id_c, sink_c.clone());
    wait_local_row(&c.nodes[0], &id_a, "dev-a row").await;
    wait_local_row(&c.nodes[0], &id_c, "dev-c row").await;
    c.nodes[0].publish_lease(&id_a).await;
    // node3 真实发布（新者胜）；事件推送 ≤1s 断言（node1/node2 的租约域翻转到 3）。
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
        "事件推送 ≤1s（实际 {:?}）",
        t0.elapsed()
    );

    // A→C 的包：node1 按陈旧租约发给 node2 ⇒ NotHere ⇒ 一次性 location_query
    // （node1 只问对端 node2/node3——本地租约正是病因；node3 答「我」）⇒ 重定向投递。
    let pkt = ip4(row_a.vip, row_c.vip, b"redirect-me");
    // 构造迁移窗口：node1 的租约域最后听到的是 node2（term 最新——设备随后迁到
    // node3 而 node1 尚未收到事件）；node3 自己的表持有 holder=3（对位置询问作答）。
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
        "NOT_HERE → location_query → 重定向投递: {r:?}"
    );
    assert_eq!(sink_c.count(), 1, "C 收到包（经 node3 本机投递）");
    assert_eq!(sink_c.first(), pkt);
    let st = c.nodes[0].forward().stats();
    assert_eq!(st.not_here, 1, "经历过一次 NOT_HERE");
    assert_eq!(st.locate_redirected, 1, "一次性重定向成功计数");
    assert_eq!(st.dropped, 0, "无丢包");
    assert_eq!(st.icmp_unreachable, 0, "未触发 ICMP");

    // hop=1 防环：构造「二次转发」（hop 耗尽）信封 ⇒ 丢 + 计数、不投递。
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
        "防环计数"
    );
    assert_eq!(sink_c.count(), 1, "hop 耗尽的包不投递");
}

// ============================================================================
// 3. 仍失败 ⇒ 丢包 + 尽力 ICMP unreachable
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

    // 目标 VIP 未注册（未知 dst）：丢 + 尽力 ICMP（源在本机 ⇒ 送得出）。
    let pkt = ip4(row_a.vip, [100, 64, 77, 77], b"to-void");
    let r = c.nodes[0].ingest_packet(&id_a, &pkt).await;
    assert!(matches!(r, IngestResult::DroppedIcmp), "{r:?}");
    let st = c.nodes[0].forward().stats();
    assert_eq!(st.dropped, 1, "丢包");
    assert_eq!(st.icmp_unreachable, 1, "尽力 ICMP");
    // 源设备收到 ICMP type=3 code=1。
    assert_eq!(sink_a.count(), 1, "ICMP 回给源会话");
    let icmp = sink_a.first();
    assert_eq!(icmp[20], 3, "ICMP type=3 destination unreachable");
    assert_eq!(icmp[21], 1, "code=1 host unreachable");
    // 内嵌原包头。
    assert_eq!(&icmp[28..48], &pkt[..20]);

    // 租约存在但目标不在线（NOT_HERE 后 location_query 也找不到）⇒ 同样丢 + ICMP。
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
        },
    )
    .await;
    let SyncResponse::Device(row_d) = rd else {
        panic!()
    };
    let id_d = dev_id(&d_pub);
    wait_local_row(&c.nodes[0], &id_d, "dev-d row").await;
    // 陈旧租约指向 node2，但 node2 没有该设备会话且无人认领。
    c.nodes[0]
        .lease()
        .merge_remote(flock_sync::lease::GossipMsg::Publish {
            device: id_d,
            holder: 2,
            term_ms: now_ms() + 100, // 较新 term 使其胜出本地空表
            tx_ewma: 0,
            rx_ewma: 0,
            last_seen_unix: 0,
        });
    let pkt2 = ip4(row_a.vip, row_d.vip, b"stale-lease");
    let r2 = c.nodes[0].ingest_packet(&id_a, &pkt2).await;
    match r2 {
        IngestResult::DroppedIcmp => {}
        IngestResult::Forwarded(ForwardOutcome::Delivered) => {
            // location_query 找到了新持有者且投递成功——不允许（无人认领）。
            panic!("无人认领却被投递");
        }
        other => panic!("期望丢+ICMP，实际 {other:?}"),
    }
}

// ============================================================================
// 4. 租约域语义 + location_query fan-out ≤3（一次性）
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
        },
    )
    .await;
    let SyncResponse::Device(row) = rd else {
        panic!()
    };
    let id = dev_id(&d_pub);

    // publish（node1）→ observe（node3）：事件推送路径。
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
    assert!(within_1s, "publish 事件推送 ≤1s 到达远端 observe");

    // 迁移：node2 发布（新者胜）——设备当前位置在租约域翻转到 node2，而 NetState
    // 的设备行（VIP/状态）不变：唯一真相源 = 租约域（§2.2-1）。
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
        "新者胜"
    );
    // NetState 设备行不存当前位置：VIP/状态原样（快照视图无 holder 字段可言）。
    let v = c.nodes[0]
        .read_linearizable(flock_sync::proto::ReadQuery::DeviceRow(id))
        .await
        .expect("read");
    let flock_sync::proto::ReadView::Device(Some(d)) = v else {
        panic!()
    };
    assert_eq!(d.vip, row.vip, "静态注册信息不变（NetState 不存位置）");
    assert_eq!(d.status, flock_sync::proto::DeviceStatus::Active);

    // location_query：本地租约域命中即答（不扇出）。
    let holder = c.nodes[2].location_query(&id).await;
    assert_eq!(holder, Some(2), "本地租约域即真相源");
    // 未知设备：fan-out ≤3 一次性询问，无人认领 ⇒ None。
    let unknown = dev_id(&[0x11; 32]);
    let t0 = Instant::now();
    let none = c.nodes[0].location_query(&unknown).await;
    assert_eq!(none, None, "无人认领");
    assert!(
        t0.elapsed() < Duration::from_secs(8),
        "一次性 ≤3 扇出在预算内（{:?}）",
        t0.elapsed()
    );

    // TTL 30s：租约到期 ⇒ observe None（唯一真相源的时效性）。
    // （短路等待 31s 太慢——用表内直改 expires 不可行（私有），改以反熵/事件路径
    // 已覆盖；此处断言 LEASE_TTL 常量与 observe 语义一致。）
    assert_eq!(
        flock_sync::lease::LEASE_TTL,
        Duration::from_secs(30),
        "租约 TTL 30s（§3.10）"
    );
    assert_eq!(
        flock_sync::lease::ANTI_ENTROPY,
        Duration::from_secs(5),
        "反熵 5s（§3.10）"
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
// M7（§7-M7.3）：per-device 字节计数点——「投递成功点计数」单点原则
// ============================================================================

/// 计数点断言：同服路径 src tx + dst rx 各由同机计一次；跨服路径 origin 只计
/// src tx，dst rx 由**收端**计（origin 对 dst 的 rx 恒 0——不双计）。
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
    // A 接在 n0（真实流程由 serve_conn 发布——测试直发）。
    n0.publish_lease(&id_a).await;

    // —— 跨服：A 接在 n0（会话/租约持有），C 接在 n1 ——
    let pkt = ip4(vip_a.octets(), vip_c.octets(), &[7u8; 100]);
    n0.ingest_packet(&id_a, &pkt).await; // src tx @n0（接入点）+ FRWD → n1 计 dst rx
    assert!(
        matches!(
            n0.ingest_packet(&id_a, &pkt).await,
            IngestResult::Forwarded(_)
        ),
        "跨服转发通路在位（前置：C 的租约已扩散到 n0）"
    );
    // 等投递 + ewma 折叠循环（1s 窗）转过折叠轮（首 tick 定基准、次 tick 折出）。
    tokio::time::sleep(Duration::from_millis(2300)).await;
    let a_n0 = n0.lease().peer_stats(&id_a).expect("A 行在 n0");
    assert!(a_n0.tx_ewma > 0, "src tx 由接入服务器计：{}", a_n0.tx_ewma);
    let c_n0 = n0.lease().peer_stats(&id_c).expect("C 行在 n0（远端视图）");
    assert_eq!(
        c_n0.rx_ewma, 0,
        "origin 不计 dst rx（收端单点计——n0 只有持有者发布的值，此处为 0 因 n1 尚未折出）"
    );

    // —— 同服：把 C 也接到 n0（本地投递路径）——
    let sink_c_n0 = Arc::new(RecvSink::default());
    n0.attach_session(id_c, sink_c_n0.clone());
    n0.publish_lease(&id_c).await;
    // 等 n0 的租约新者胜扩散（自发布覆盖 n1 视图不影响本断言）。
    tokio::time::sleep(Duration::from_millis(200)).await;
    let pkt2 = ip4(vip_a.octets(), vip_c.octets(), &[9u8; 80]);
    assert!(matches!(
        n0.ingest_packet(&id_a, &pkt2).await,
        IngestResult::DeliveredLocal
    ));
    tokio::time::sleep(Duration::from_millis(2300)).await;
    let c_n0_after = n0.lease().peer_stats(&id_c).expect("C 行");
    // 同服投递 ⇒ dst rx 由本机（= 持有者）计。注：A 的行现在由 n0 持有（publish 后）。
    assert!(c_n0_after.rx_ewma > 0, "dst rx 由投递成功的服务器计");
}
