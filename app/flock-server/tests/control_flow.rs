//! M2 全链 in-process 集成（docs/design.md §7-M2 完成标准的非容器部分；容器实跑见
//! tests/smoke.rs）。
//!
//! 覆盖：
//! 1. `full_chain_*`：邀请 → 1-RTT 首连 → OPAQUE 登录（anchor 验签 + 篡改拒绝）→ 票据 →
//!    key-bind（设备签名）→ 设备 B 入注册表（1-RTT 可连）→ SR-SIG1 验签 → 票据契约
//!    （无票据/坏票据顺序/nonce 不入账/重放/时间窗）→ 吊销 → 杀会话 + 握手被拒 +
//!    低 epoch 票据失效；
//! 2. `tofu_*`：TOFU 首连 I0→R0 → 根指纹确认 → 钉扎落盘 → 二连 1-RTT → dir_pull →
//!    换端点（第二暴露口）仍 1-RTT；
//! 3. `ticket_expiry_*`：短 TTL 真实时钟下的过期票据三态。

mod common;

use common::{connect, pin_from_invite, pin_with_root, CtrlClient, TestServer};
use flock_protocol::pake::login_start;
use flock_protocol::rand;
use flock_protocol::session::{
    fingerprint_ed25519, initiate, initiate_tofu, DeviceId, DeviceStaticKeys, ServerPin,
    SessionError, TunnelConfig,
};
use flock_protocol::sig as sr_sig;
use flock_protocol::sig::UserKey;
use flock_protocol::trust::{confirm_tofu_and_pin, InviteFile, PinStore, PinVerdict};
use flock_server::control::{client_login_finish_anchored, CtrlError, CtrlResponse, DeviceOp};

fn now() -> i64 {
    flock_protocol::trust::now_unix() as i64
}

fn dev_id(d: &DeviceStaticKeys) -> [u8; 32] {
    DeviceId::from_ed25519(&d.ed25519_public()).0
}

fn expect_err(resp: CtrlResponse) -> CtrlError {
    match resp {
        CtrlResponse::Err { code, .. } => code,
        other => panic!("期望 Err，得 {other:?}"),
    }
}

// ============================================================================
// 1. 全链
// ============================================================================

#[tokio::test]
async fn full_chain_invite_login_keybind_srsig1_revoke() {
    let srv = TestServer::start(60).await;

    // —— 邀请（根签 v3，含全套服务器材料/双端点）——
    let invite_bytes = srv.mint_invite(3600).await;
    let invite = InviteFile::from_bytes(&invite_bytes).expect("invite parse");
    assert!(invite.verify_against(&srv.core.identity.root_pub), "根验签");
    assert_eq!(invite.directory.servers.len(), 2, "目录含主端点+第二暴露口");
    let pin = pin_from_invite(&invite, 0);

    // —— 开户：兑换邀请（建用户/设备 + VIP）——
    let dev_a = DeviceStaticKeys::generate();
    let vip_a = srv.redeem(&invite_bytes, "alice", &dev_a).await;
    assert_eq!(
        vip_a,
        [100, 64, 0, 2],
        "首个 VIP = 100.64.0.2（.1 留给服务器）"
    );

    // —— 1-RTT 首连（initiate = 已钉扎形态，单往返）——
    let tunnel_a = connect(&dev_a, &pin).await;
    let mut a = CtrlClient::open(tunnel_a).await.expect("ctrl open");
    let (cid, sid) = a.hello().await;
    assert_eq!(cid, srv.core.identity.cluster_id.0);
    assert_eq!(sid, srv.core.identity.server_id.0);

    // —— OPAQUE 注册（设置口令；授权 = 会话设备 owner）——
    assert!(matches!(
        a.set_password("alice", "pw-123").await,
        CtrlResponse::Ok
    ));

    // —— anchor 负路径：篡改 anchor_sig ⇒ 客户端 login_finish_anchored 拒绝 ——
    {
        let mut rng = rand::rngs::OsRng;
        let (state, ke1) = login_start(&mut rng, "pw-123", "alice").unwrap();
        match a
            .req(flock_server::control::CtrlRequest::LoginBegin {
                user: "alice".into(),
                ke1_b64: ke1,
            })
            .await
            .unwrap()
        {
            CtrlResponse::LoginChallenge {
                ke2_b64,
                bind_token,
                anchor_sig,
            } => {
                let mut tampered = anchor_sig;
                tampered[0] ^= 0x01;
                assert!(
                    client_login_finish_anchored(
                        state,
                        "pw-123",
                        "alice",
                        &ke2_b64,
                        flock_server::control::AnchorLoginExpectation {
                            server_id: pin.entry.server_id.0,
                            identity_pub: pin.entry.identity_pub,
                            bind_token,
                            anchor_sig: tampered,
                        },
                    )
                    .is_err(),
                    "篡改 anchor 签名 ⇒ 客户端拒绝（ke3 不产生）"
                );
            }
            other => panic!("login challenge: {other:?}"),
        }
    }

    // —— OPAQUE 登录（anchor 验签通过）→ 票据 ——
    let (ticket_a, bind_token) = a
        .login_anchored("alice", "pw-123", &pin)
        .await
        .expect("login");
    match &ticket_a {
        flock_server::ticket::TicketWire::Local(t) => {
            assert_eq!(t.user, "alice");
            assert_eq!(t.device, dev_id(&dev_a).to_vec(), "票据绑定会话设备");
        }
        other => panic!("单服形态票据应为 Local：{other:?}"),
    }

    // —— key-bind：设备 B 公钥登记（票据 + bind_token 一次性 + 设备签名）——
    let dev_b = DeviceStaticKeys::generate();
    let sr_key = UserKey::generate();
    match a
        .key_bind(&ticket_a, bind_token, "alice", &cid, &dev_b, &sr_key)
        .await
    {
        CtrlResponse::KeyBound { device_id, vip } => {
            assert_eq!(device_id, dev_id(&dev_b), "返回设备 B 的 DeviceId");
            assert_eq!(vip, [100, 64, 0, 3], "VIP 单调分配");
        }
        other => panic!("key bind: {other:?}"),
    }
    // bind_token 一次性：同 token 二次 bind 拒。
    let dev_c = DeviceStaticKeys::generate();
    match a
        .key_bind(&ticket_a, bind_token, "alice", &cid, &dev_c, &sr_key)
        .await
    {
        resp @ CtrlResponse::KeyBound { .. } => panic!("bind_token 二次消费未拒: {resp:?}"),
        resp => assert_eq!(expect_err(resp), CtrlError::BindTokenUsed),
    }

    // —— 设备 B 入注册表：1-RTT 可连 + 目录拉取 ——
    let tunnel_b = connect(&dev_b, &pin).await;
    let mut b = CtrlClient::open(tunnel_b).await.expect("ctrl open B");
    b.hello().await;
    let dir = b.dir_pull().await;
    assert!(dir.verify(&srv.core.identity.root_pub), "dir_pull 根验签");
    assert_eq!(dir.servers[0].relay_endpoint, srv.primary);
    assert_eq!(dir.servers[1].relay_endpoint, srv.alt);

    // —— SR-SIG1 请求验签通过（TicketRenew 状态变更）——
    let ts = now();
    let auth1 = CtrlClient::sr_auth(
        "alice",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        ts,
        &sr_sig::nonce_hex(),
    );
    assert!(matches!(
        a.ticket_renew(Some(ticket_a.clone()), auth1).await,
        CtrlResponse::TicketRenewed { .. }
    ));

    // —— 票据契约三态 + 顺序 ——
    // (a) 无票据 ⇒ TicketMissing。
    let auth2 = CtrlClient::sr_auth(
        "alice",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        now(),
        &sr_sig::nonce_hex(),
    );
    assert_eq!(
        expect_err(a.ticket_renew(None, auth2).await),
        CtrlError::TicketMissing
    );

    // (b) 契约顺序：坏票据 + 全新 nonce ⇒ TicketBad；同 nonce 持有效票据 ⇒ 过（未入账证明）。
    // 篡改覆盖字段 ⇒ 签名失效（TicketWire::Local 的 exp 进 canonical 字节）。
    let mut bad_ticket = ticket_a.clone();
    if let flock_server::ticket::TicketWire::Local(t) = &mut bad_ticket {
        t.exp += 100;
    }
    let n3 = sr_sig::nonce_hex();
    let auth3 = CtrlClient::sr_auth(
        "alice",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        ts,
        &n3,
    );
    assert_eq!(
        expect_err(a.ticket_renew(Some(bad_ticket), auth3.clone()).await),
        CtrlError::TicketBad,
        "坏票据被拒"
    );
    assert!(
        matches!(
            a.ticket_renew(Some(ticket_a.clone()), auth3.clone()).await,
            CtrlResponse::TicketRenewed { .. }
        ),
        "同一 nonce 持有效票据通过 ⇒ 先前拒绝未入账"
    );
    // (c) nonce 重放 ⇒ NonceReplay。
    assert_eq!(
        expect_err(a.ticket_renew(Some(ticket_a.clone()), auth3).await),
        CtrlError::NonceReplay
    );
    // (d) 时间窗外 ⇒ SigStale。
    let stale = CtrlClient::sr_auth(
        "alice",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        ts - 400,
        &sr_sig::nonce_hex(),
    );
    assert_eq!(
        expect_err(a.ticket_renew(Some(ticket_a.clone()), stale).await),
        CtrlError::SigStale
    );
    // (e) 签名坏（换 key）⇒ SigBad，且 nonce 不入账（同 nonce 随后可用好 key 过）。
    let other_key = UserKey::generate();
    let n5 = sr_sig::nonce_hex();
    let wrong_key = CtrlClient::sr_auth(
        "alice",
        &other_key,
        CtrlClient::path_ticket_renew(),
        b"",
        now(),
        &n5,
    );
    assert_eq!(
        expect_err(a.ticket_renew(Some(ticket_a.clone()), wrong_key).await),
        CtrlError::SigBad
    );
    let right_key = CtrlClient::sr_auth(
        "alice",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        now(),
        &n5,
    );
    assert!(
        matches!(
            a.ticket_renew(Some(ticket_a.clone()), right_key).await,
            CtrlResponse::TicketRenewed { .. }
        ),
        "签名失败未入账"
    );

    // —— 吊销（B 的登录态发起；A 被吊销）——
    let (ticket_b, _) = b
        .login_anchored("alice", "pw-123", &pin)
        .await
        .expect("B login");
    let body = postcard::to_allocvec(&DeviceOp::Revoke {
        device: dev_id(&dev_a),
    })
    .unwrap();
    let revoke_auth = CtrlClient::sr_auth(
        "alice",
        &sr_key,
        CtrlClient::path_device_op(),
        &body,
        now(),
        &sr_sig::nonce_hex(),
    );
    assert!(matches!(
        b.device_op(
            Some(ticket_b.clone()),
            revoke_auth,
            DeviceOp::Revoke {
                device: dev_id(&dev_a)
            }
        )
        .await,
        CtrlResponse::Ok
    ));

    // A 的本地会话被杀（§2.2）：其后续控制请求以 IO 失败收场。
    {
        let mut a2 = a;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            a2.req(flock_server::control::CtrlRequest::DirPull { since_version: 0 }),
        )
        .await;
        assert!(r.is_err() || r.unwrap().is_err(), "吊销后 A 的会话被拆");
    }

    // 低 epoch 票据：吊销推进 epoch ⇒ B 的旧票据失效。
    let list_body = postcard::to_allocvec(&DeviceOp::List).unwrap();
    let stale_ticket_auth = CtrlClient::sr_auth(
        "alice",
        &sr_key,
        CtrlClient::path_device_op(),
        &list_body,
        now(),
        &sr_sig::nonce_hex(),
    );
    assert_eq!(
        expect_err(
            b.device_op(Some(ticket_b), stale_ticket_auth, DeviceOp::List)
                .await
        ),
        CtrlError::TicketBad,
        "票据 epoch < 当前 epoch ⇒ 拒"
    );

    // 吊销后握手被拒：respond 侧 Revoked ⇒ 同一不透明 DeviceRejected 且**不回 R1**（防
    // 在线枚举，§3.5 时序对齐）⇒ 客户端观察为连接失败（EOF），而非可区分的错误码。
    let io = tokio::net::TcpStream::connect(&pin.entry.relay_endpoint)
        .await
        .unwrap();
    let err = initiate(io, &dev_a, &pin, TunnelConfig::default())
        .await
        .expect_err("revoked device handshake must fail");
    assert!(
        matches!(err, SessionError::DeviceRejected | SessionError::Io(_)),
        "got {err:?}"
    );
    // 对照：未吊销的设备 B 同刻仍可 1-RTT 连接（拒绝与吊销因果绑定，而非服务挂了）。
    let io_b = tokio::net::TcpStream::connect(&pin.entry.relay_endpoint)
        .await
        .unwrap();
    initiate(io_b, &dev_b, &pin, TunnelConfig::default())
        .await
        .expect("active device still connects");
}

// ============================================================================
// 2. TOFU 首连 → 钉扎 → 二连 1-RTT → dir_pull → 换端点仍 1-RTT
// ============================================================================

#[tokio::test]
async fn tofu_bootstrap_pin_second_connect_and_endpoint_switch() {
    let srv = TestServer::start(60).await;
    // TOFU 设备经管理面预置（TOFU 解决的是**信任**引导，不是账号开通，§1.3.3f）。
    let dev = DeviceStaticKeys::generate();
    srv.device_add("tofu-user", &dev).await;

    // —— 首连 I0→R0（无邀请/无钉扎）——
    let io = tokio::net::TcpStream::connect(&srv.primary).await.unwrap();
    let boot = initiate_tofu(
        io,
        DeviceStaticKeys::from_bytes(&dev.to_bytes()),
        TunnelConfig::default(),
    )
    .await
    .expect("tofu bootstrap");
    // 根指纹 = 服务器根公钥指纹（确认回调的展示本体）。
    assert_eq!(
        boot.root_fingerprint(),
        fingerprint_ed25519(&srv.core.identity.root_pub),
        "R0 携入群凭证链与集群根公钥"
    );
    let cluster_id = boot.cluster_id();
    let root_pub = *boot.root_pub();
    let entry0 = boot.server_entry().clone();
    assert_eq!(entry0.relay_endpoint, srv.primary);

    // —— 根指纹确认（回调）+ 钉扎落盘 ——
    let pins_path = srv.state_dir.join("pins.bin");
    let mut pins = PinStore::new();
    let t1 = confirm_tofu_and_pin(boot, &mut pins)
        .await
        .expect("confirm tofu");
    pins.save(&pins_path).expect("pin store save");
    let loaded = PinStore::load(&pins_path).expect("pin store load");
    assert_eq!(
        loaded.verify_pinned(&cluster_id, &root_pub),
        PinVerdict::Match,
        "钉扎集群根公钥落盘"
    );
    let mut c1 = CtrlClient::open(t1).await.unwrap();
    c1.hello().await; // TOFU 会话功能正常

    // —— 二连 1-RTT：已钉扎（initiate 形态，I0 不再出现）——
    let pin1 = ServerPin {
        cluster_id,
        cluster_root_pub: root_pub,
        entry: entry0,
    };
    let t2 = connect(&dev, &pin1).await;
    let mut c2 = CtrlClient::open(t2).await.unwrap();
    c2.hello().await;

    // —— dir_pull：根签目录 → 钉扎存储登记 → 换端点（第二暴露口）仍 1-RTT ——
    let dir = c2.dir_pull().await;
    assert!(dir.verify(&root_pub));
    pins.record_directory(&root_pub, &dir).expect("record dir");
    assert_eq!(dir.servers.len(), 2);
    let pin2 = pin_with_root(&dir, 1, root_pub);
    assert_eq!(pin2.entry.relay_endpoint, srv.alt, "端点 #2 = 第二暴露口");
    let t3 = connect(&dev, &pin2).await;
    let mut c3 = CtrlClient::open(t3).await.unwrap();
    c3.hello().await; // 换端点仍 1-RTT 且会话功能正常
}

// ============================================================================
// 3. 过期票据（真实时钟短 TTL）
// ============================================================================

#[tokio::test]
async fn ticket_expiry_rejected_after_ttl() {
    let srv = TestServer::start(2).await; // TTL 2s（部署可调，缺省 60 = §2.2 硬顶）
    let invite_bytes = srv.mint_invite(3600).await;
    let invite = InviteFile::from_bytes(&invite_bytes).unwrap();
    let pin = pin_from_invite(&invite, 0);
    let dev = DeviceStaticKeys::generate();
    srv.redeem(&invite_bytes, "bob", &dev).await;

    let t = connect(&dev, &pin).await;
    let mut c = CtrlClient::open(t).await.unwrap();
    assert!(matches!(
        c.set_password("bob", "pw").await,
        CtrlResponse::Ok
    ));
    let (ticket1, _) = c.login_anchored("bob", "pw", &pin).await.expect("login 1");

    // key-bind 登记 SR-SIG1 用户公钥（需要 bind_token ⇒ 再登录一次）。
    let sr_key = UserKey::generate();
    let (ticket2, bind_token) = c.login_anchored("bob", "pw", &pin).await.expect("login 2");
    match c
        .key_bind(
            &ticket2,
            bind_token,
            "bob",
            &srv.core.identity.cluster_id.0,
            &DeviceStaticKeys::generate(),
            &sr_key,
        )
        .await
    {
        CtrlResponse::KeyBound { .. } => {}
        other => panic!("key bind: {other:?}"),
    }
    // TTL 内续签：通过。
    let auth_ok = CtrlClient::sr_auth(
        "bob",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        now(),
        &sr_sig::nonce_hex(),
    );
    assert!(matches!(
        c.ticket_renew(Some(ticket2.clone()), auth_ok).await,
        CtrlResponse::TicketRenewed { .. }
    ));
    // 等 TTL 过期：签名层新鲜的同一操作 ⇒ TicketBad（过期，§2.2 等效重放窗 = min(±300s, TTL)）。
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let auth_late = CtrlClient::sr_auth(
        "bob",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        now(),
        &sr_sig::nonce_hex(),
    );
    assert_eq!(
        expect_err(c.ticket_renew(Some(ticket2), auth_late).await),
        CtrlError::TicketBad,
        "票据 TTL 到期 ⇒ 状态变更被拒"
    );
    // 旧票据（第一次登录的）同样过期。
    let auth_old = CtrlClient::sr_auth(
        "bob",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        now(),
        &sr_sig::nonce_hex(),
    );
    assert_eq!(
        expect_err(c.ticket_renew(Some(ticket1), auth_old).await),
        CtrlError::TicketBad
    );
}
