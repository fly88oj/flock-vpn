//! M2 冒烟（#[ignore]，宿主对容器实跑；docs/design.md §7-M2 完成标准）。
//!
//! 用法（测试名即 harness 参数——libtest 过滤器选端点 profile）：
//!
//! ```text
//! docker compose -f deploy/m2.yml        up -d --build   # 先起 frp 中转变体（需 prepare）
//! cargo test -p chmlvpn-server --test smoke -- --ignored relay
//!
//! docker compose -f deploy/m2-direct.yml up -d --build   # 直连变体（零 frp，免 prepare）
//! cargo test -p chmlvpn-server --test smoke -- --ignored direct
//! ```
//!
//! 断言集与 in-process `tests/control_flow.rs` 完全同源（同一 CtrlClient 驱动），差异仅在：
//! 端点 = 宿主映射口；管理面 = 容器内 CLI（`docker compose exec`）而非进程内调用。
//!
//! 环境变量：`CHML_SMOKE_HOST`（默认 127.0.0.1；远程 docker host 时改指）。
//!
//! TOFU 残余风险声明（§3.8，不可静默）：TOFU 不防首登在线 MITM；组织场景走邀请强路径。

mod common;

use chml_protocol::pake::login_start;
use chml_protocol::rand;
use chml_protocol::session::{
    initiate, initiate_tofu, DeviceStaticKeys, ServerPin, SessionError, TunnelConfig,
};
use chml_protocol::sig as sr_sig;
use chml_protocol::sig::UserKey;
use chml_protocol::trust::{confirm_tofu_and_pin, InviteFile, PinStore, PinVerdict};
use chmlvpn_server::control::{client_login_finish_anchored, CtrlError, CtrlResponse, DeviceOp};
use common::{connect, pin_from_invite, pin_with_root, CtrlClient};

const DEPLOY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy");

#[derive(Clone, Copy, PartialEq)]
enum Profile {
    Relay,
    Direct,
}

impl Profile {
    fn compose(self) -> &'static str {
        match self {
            Profile::Relay => "m2.yml",
            Profile::Direct => "m2-direct.yml",
        }
    }

    /// 宿主侧端点（目录内条目 = 同一映射口；端点 #2 = 第二暴露口，§7-M2 换端点模拟）。
    fn endpoints(self) -> (String, String) {
        let host = std::env::var("CHML_SMOKE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        match self {
            Profile::Relay => (format!("{host}:27500"), format!("{host}:27501")),
            Profile::Direct => (format!("{host}:9443"), format!("{host}:9444")),
        }
    }
}

// ============================================================================
// docker 辅助
// ============================================================================

fn compose_path(file: &str) -> std::path::PathBuf {
    std::path::Path::new(DEPLOY).join(file)
}

/// `docker compose -f <file> exec -T server <args...>`（stdout 捕获；非零退出 = panic）。
fn compose_exec(profile: Profile, args: &[&str]) -> String {
    let out = std::process::Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_path(profile.compose()))
        .args(["exec", "-T", "server"])
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("docker 调用失败（Docker Desktop 是否在跑？）：{e}"));
    assert!(
        out.status.success(),
        "docker compose exec {:?} 失败：{}{}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// `docker compose exec` 允许失败（pgrep 无命中退出码 1 = 期望结果）。
fn compose_exec_status(profile: Profile, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_path(profile.compose()))
        .args(["exec", "-T", "server"])
        .args(args)
        .output()
        .expect("docker 调用失败");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn cli(profile: Profile, sub: &[&str]) -> String {
    let mut args = vec!["--config", "/etc/chmlvpn/server.toml"];
    args.extend_from_slice(sub);
    compose_exec(profile, &args)
}

async fn wait_tcp(addr: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "端点 {addr} 90s 内未就绪"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

fn now() -> i64 {
    chml_protocol::trust::now_unix() as i64
}

fn expect_err(resp: CtrlResponse) -> CtrlError {
    match resp {
        CtrlResponse::Err { code, .. } => code,
        other => panic!("期望 Err，得 {other:?}"),
    }
}

fn dev_id(d: &DeviceStaticKeys) -> [u8; 32] {
    chml_protocol::session::DeviceId::from_ed25519(&d.ed25519_public()).0
}

// ============================================================================
// 全链（邀请 → 1-RTT → OPAQUE 登录 → key-bind → 注册表 → SR-SIG1 → 吊销）
// ============================================================================

async fn smoke_full_chain(profile: Profile) {
    let (ep1, _ep2) = profile.endpoints();
    wait_tcp(&ep1).await;

    // 邀请（容器内 CLI 签发；admin 端点 = 进程内单写者入口）。
    let invite_b64 = cli(profile, &["invite", "--ttl-secs", "3600"])
        .trim()
        .to_string();
    assert!(!invite_b64.is_empty(), "invite 输出非空");
    let invite_bytes = common_b64d(&invite_b64);
    let invite = InviteFile::from_bytes(&invite_bytes).expect("invite parse");
    assert_eq!(invite.directory.servers.len(), 2, "目录含双端点");
    let pin = pin_from_invite(&invite, 0);

    // 开户：兑换邀请（CLI redeem：建用户/设备 + VIP）。
    let dev_a = DeviceStaticKeys::generate();
    let out = cli(
        profile,
        &[
            "redeem",
            "--user",
            "smoke-alice",
            "--invite-b64",
            &invite_b64,
            "--device-x",
            &common_b64(&dev_a.x25519_public().to_bytes()),
            "--device-ed",
            &common_b64(dev_a.ed25519_public().as_bytes()),
        ],
    );
    assert!(
        out.contains("vip=100.64.0.2"),
        "首个 VIP = 100.64.0.2：{out}"
    );
    // 同 invite_id 二次兑换拒（邀请一次性，容器内实证）。
    let dev_x = DeviceStaticKeys::generate();
    let dup = cli_status(
        profile,
        &[
            "redeem",
            "--user",
            "smoke-dup",
            "--invite-b64",
            &invite_b64,
            "--device-x",
            &common_b64(&dev_x.x25519_public().to_bytes()),
            "--device-ed",
            &common_b64(dev_x.ed25519_public().as_bytes()),
        ],
    );
    assert!(!dup.0, "二次兑换必须失败：{}", dup.1);

    // 1-RTT 首连（经中转/直连的宿主映射口——协议层同构）。
    let tunnel_a = connect(&dev_a, &pin).await;
    let mut a = CtrlClient::open(tunnel_a).await.expect("ctrl open");
    a.hello().await;
    assert!(matches!(
        a.set_password("smoke-alice", "pw").await,
        CtrlResponse::Ok
    ));

    // anchor 负路径（容器路径同样生效）：篡改 anchor_sig ⇒ 客户端拒绝。
    {
        let mut rng = rand::rngs::OsRng;
        let (state, ke1) = login_start(&mut rng, "pw", "smoke-alice").unwrap();
        match a
            .req(chmlvpn_server::control::CtrlRequest::LoginBegin {
                user: "smoke-alice".into(),
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
                let mut t = anchor_sig;
                t[0] ^= 0x01;
                assert!(
                    client_login_finish_anchored(
                        state,
                        "pw",
                        "smoke-alice",
                        &ke2_b64,
                        chmlvpn_server::control::AnchorLoginExpectation {
                            server_id: pin.entry.server_id.0,
                            identity_pub: pin.entry.identity_pub,
                            bind_token,
                            anchor_sig: t,
                        },
                    )
                    .is_err(),
                    "篡改 anchor ⇒ 拒"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    // OPAQUE 登录（anchor）→ 票据（部署 TTL 6s，见 deploy/server-*.toml）。
    let (ticket_a, bind_token) = a
        .login_anchored("smoke-alice", "pw", &pin)
        .await
        .expect("login");

    // key-bind：设备 B 公钥登记。
    let dev_b = DeviceStaticKeys::generate();
    let sr_key = UserKey::generate();
    match a
        .key_bind(
            &ticket_a,
            bind_token,
            "smoke-alice",
            &invite.directory.cluster_id.0,
            &dev_b,
            &sr_key,
        )
        .await
    {
        CtrlResponse::KeyBound { device_id, vip } => {
            assert_eq!(device_id, dev_id(&dev_b));
            assert_eq!(vip, [100, 64, 0, 3], "VIP 单调");
        }
        other => panic!("key bind: {other:?}"),
    }

    // 设备 B 入注册表：1-RTT 可连 + dir_pull。
    let tunnel_b = connect(&dev_b, &pin).await;
    let mut b = CtrlClient::open(tunnel_b).await.expect("ctrl open B");
    b.hello().await;
    let dir = b.dir_pull().await;
    assert!(dir.verify(&invite.cluster_root_pub), "dir_pull 根验签");

    // SR-SIG1 验签通过。
    let auth = CtrlClient::sr_auth(
        "smoke-alice",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        now(),
        &sr_sig::nonce_hex(),
    );
    assert!(matches!(
        a.ticket_renew(Some(ticket_a.clone()), auth).await,
        CtrlResponse::TicketRenewed { .. }
    ));

    // 票据三态：
    // (1) 无票据。
    let no_tkt = CtrlClient::sr_auth(
        "smoke-alice",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        now(),
        &sr_sig::nonce_hex(),
    );
    assert_eq!(
        expect_err(a.ticket_renew(None, no_tkt).await),
        CtrlError::TicketMissing
    );
    // (2) 坏票据 + 全新 nonce ⇒ 拒；同 nonce 好票据 ⇒ 过（顺序契约的端到端实证）。
    let mut bad = ticket_a.clone();
    bad.epoch += 1;
    let n = sr_sig::nonce_hex();
    let auth_n = CtrlClient::sr_auth(
        "smoke-alice",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        now(),
        &n,
    );
    assert_eq!(
        expect_err(a.ticket_renew(Some(bad), auth_n.clone()).await),
        CtrlError::TicketBad
    );
    assert!(matches!(
        a.ticket_renew(Some(ticket_a.clone()), auth_n).await,
        CtrlResponse::TicketRenewed { .. }
    ));
    // (3) 过期票据（部署 TTL 6s）。
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;
    let late = CtrlClient::sr_auth(
        "smoke-alice",
        &sr_key,
        CtrlClient::path_ticket_renew(),
        b"",
        now(),
        &sr_sig::nonce_hex(),
    );
    assert_eq!(
        expect_err(a.ticket_renew(Some(ticket_a.clone()), late).await),
        CtrlError::TicketBad
    );

    // 吊销后握手被拒（重新登录拿新票据——旧票据已因 (3) 过期）。
    let (ticket2, _) = a
        .login_anchored("smoke-alice", "pw", &pin)
        .await
        .expect("re-login");
    let (ticket_b, _) = b
        .login_anchored("smoke-alice", "pw", &pin)
        .await
        .expect("B login");
    let body = postcard::to_allocvec(&DeviceOp::Revoke {
        device: dev_id(&dev_a),
    })
    .unwrap();
    let rv = CtrlClient::sr_auth(
        "smoke-alice",
        &sr_key,
        CtrlClient::path_device_op(),
        &body,
        now(),
        &sr_sig::nonce_hex(),
    );
    assert!(matches!(
        b.device_op(
            Some(ticket_b.clone()),
            rv,
            DeviceOp::Revoke {
                device: dev_id(&dev_a)
            }
        )
        .await,
        CtrlResponse::Ok
    ));
    // 低 epoch 票据：吊销推进 epoch ⇒ B 的旧票据失效。
    let lb = postcard::to_allocvec(&DeviceOp::List).unwrap();
    let stale = CtrlClient::sr_auth(
        "smoke-alice",
        &sr_key,
        CtrlClient::path_device_op(),
        &lb,
        now(),
        &sr_sig::nonce_hex(),
    );
    assert_eq!(
        expect_err(b.device_op(Some(ticket_b), stale, DeviceOp::List).await),
        CtrlError::TicketBad
    );
    let _ = ticket2;

    // A 重连被拒（respond Revoked ⇒ 客户端观察为连接失败，§3.5 防枚举）。
    let io = tokio::net::TcpStream::connect(&pin.entry.relay_endpoint)
        .await
        .unwrap();
    let err = initiate(io, &dev_a, &pin, TunnelConfig::default())
        .await
        .expect_err("吊销后握手必拒");
    assert!(
        matches!(err, SessionError::DeviceRejected | SessionError::Io(_)),
        "got {err:?}"
    );
    // 对照：B 仍可连。
    let io_b = tokio::net::TcpStream::connect(&pin.entry.relay_endpoint)
        .await
        .unwrap();
    initiate(io_b, &dev_b, &pin, TunnelConfig::default())
        .await
        .expect("B 仍可连");
}

fn common_b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)
}

fn common_b64d(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s.trim())
        .expect("b64")
}

fn cli_status(profile: Profile, sub: &[&str]) -> (bool, String) {
    let mut args = vec!["--config", "/etc/chmlvpn/server.toml"];
    args.extend_from_slice(sub);
    compose_exec_status(profile, &args)
}

// ============================================================================
// TOFU（I0→R0 → 指纹确认 → 钉扎落盘 → 二连 1-RTT → dir_pull → 换端点仍 1-RTT）
// ============================================================================

async fn smoke_tofu(profile: Profile) {
    let (ep1, ep2) = profile.endpoints();
    wait_tcp(&ep1).await;

    // TOFU 设备管理面预置（TOFU 解决信任引导，非账号开通）。
    let dev = DeviceStaticKeys::generate();
    let out = cli(
        profile,
        &[
            "device-add",
            "--user",
            "smoke-tofu",
            "--device-x",
            &common_b64(&dev.x25519_public().to_bytes()),
            "--device-ed",
            &common_b64(dev.ed25519_public().as_bytes()),
        ],
    );
    assert!(out.contains("vip=100.64."), "device-add：{out}");

    // 首连 I0→R0（客户端无邀请/无钉扎）。
    let io = tokio::net::TcpStream::connect(&ep1).await.unwrap();
    let boot = initiate_tofu(
        io,
        DeviceStaticKeys::from_bytes(&dev.to_bytes()),
        TunnelConfig::default(),
    )
    .await
    .expect("tofu bootstrap");
    let fingerprint = boot.root_fingerprint();
    assert!(!fingerprint.as_bytes().iter().all(|&b| b == 0));
    let cluster_id = boot.cluster_id();
    let root_pub = *boot.root_pub();
    let entry0 = boot.server_entry().clone();
    assert_eq!(entry0.relay_endpoint, ep1);

    // 根指纹确认 + 钉扎落盘（宿主临时目录）。
    let pins_dir = tempfile::tempdir().unwrap();
    let pins_path = pins_dir.path().join("pins.bin");
    let mut pins = PinStore::new();
    let t1 = confirm_tofu_and_pin(boot, &mut pins)
        .await
        .expect("confirm");
    pins.save(&pins_path).unwrap();
    assert_eq!(
        PinStore::load(&pins_path)
            .unwrap()
            .verify_pinned(&cluster_id, &root_pub),
        PinVerdict::Match,
        "钉扎落盘"
    );
    let mut c1 = CtrlClient::open(t1).await.unwrap();
    c1.hello().await;

    // 二连 1-RTT（已钉扎形态）。
    let pin1 = ServerPin {
        cluster_id,
        cluster_root_pub: root_pub,
        entry: entry0,
    };
    let t2 = connect(&dev, &pin1).await;
    let mut c2 = CtrlClient::open(t2).await.unwrap();
    c2.hello().await;

    // dir_pull → 换端点（第二暴露口）仍 1-RTT。
    let dir = c2.dir_pull().await;
    assert!(dir.verify(&root_pub));
    pins.record_directory(&root_pub, &dir).unwrap();
    let pin2 = pin_with_root(&dir, 1, root_pub);
    assert_eq!(pin2.entry.relay_endpoint, ep2);
    let t3 = connect(&dev, &pin2).await;
    let mut c3 = CtrlClient::open(t3).await.unwrap();
    c3.hello().await;
}

// ============================================================================
// 入口（测试名 = harness profile 过滤器）
// ============================================================================

#[ignore = "对容器实跑：先 docker compose up（见文件头）；cargo test -- --ignored relay|direct"]
#[tokio::test]
async fn relay_full_chain() {
    smoke_full_chain(Profile::Relay).await;
}

#[ignore = "对容器实跑：见文件头"]
#[tokio::test]
async fn relay_tofu_dirpull_endpoint_switch() {
    smoke_tofu(Profile::Relay).await;
}

#[ignore = "对容器实跑：见文件头"]
#[tokio::test]
async fn relay_frpc_supervisor_process_running() {
    let (ep1, _) = Profile::Relay.endpoints();
    wait_tcp(&ep1).await;
    // Frp 模式运行时证明：frpc 子进程在 server 容器内由 Supervisor 托管运行。
    let (ok, out) = compose_exec_status(Profile::Relay, &["pgrep", "-f", "frpc"]);
    assert!(ok, "frpc 进程应在运行（Supervisor 托管）：{out}");
}

#[ignore = "对容器实跑：见文件头"]
#[tokio::test]
async fn direct_full_chain() {
    smoke_full_chain(Profile::Direct).await;
}

#[ignore = "对容器实跑：见文件头"]
#[tokio::test]
async fn direct_tofu_dirpull_endpoint_switch() {
    smoke_tofu(Profile::Direct).await;
}

#[ignore = "对容器实跑：见文件头（§7-M2：Direct 形态容器内 pgrep -f frp 无进程）"]
#[tokio::test]
async fn direct_no_frp_process_in_container() {
    let (ep1, _) = Profile::Direct.endpoints();
    wait_tcp(&ep1).await;
    // Direct 代码路径零 frp 逻辑的运行时证明（§7-M2）：容器内无任何 frp 进程。
    let (ok, out) = compose_exec_status(Profile::Direct, &["pgrep", "-f", "frp"]);
    assert!(!ok, "Direct 容器内不得出现 frp 进程：{out}");
}
