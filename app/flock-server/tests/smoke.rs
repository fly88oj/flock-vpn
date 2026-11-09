//! M2 smoke tests (#[ignore], host runs against containers; docs/design.md
//! §7-M2 completion criteria).
//!
//! Usage (the test name is the harness argument —— the libtest filter
//! selects the endpoint profile):
//!
//! ```text
//! docker compose -f deploy/m2.yml        up -d --build   # start the frp relay variant first (needs prepare)
//! cargo test -p flock-server --test smoke -- --ignored relay
//!
//! docker compose -f deploy/m2-direct.yml up -d --build   # the direct variant (zero frp, no prepare)
//! cargo test -p flock-server --test smoke -- --ignored direct
//! ```
//!
//! The assertion set shares its provenance entirely with the in-process
//! `tests/control_flow.rs` (the same CtrlClient driver); the only
//! differences: endpoints = host-mapped ports; the management surface =
//! the in-container CLI (`docker compose exec`) instead of in-process
//! calls.
//!
//! Environment variable: `FLOCK_SMOKE_HOST` (default 127.0.0.1; repoint
//! for a remote docker host).
//!
//! TOFU residual-risk statement (§3.8, not to be silenced): TOFU does not
//! defend against an online MITM on first login; organizational scenarios
//! take the invite strong path.

mod common;

use common::{connect, pin_from_invite, pin_with_root, CtrlClient};
use flock_protocol::pake::login_start;
use flock_protocol::rand;
use flock_protocol::session::{
    initiate, initiate_tofu, DeviceStaticKeys, ServerPin, SessionError, TunnelConfig,
};
use flock_protocol::sig as sr_sig;
use flock_protocol::sig::UserKey;
use flock_protocol::trust::{confirm_tofu_and_pin, InviteFile, PinStore, PinVerdict};
use flock_server::control::{client_login_finish_anchored, CtrlError, CtrlResponse, DeviceOp};

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

    /// Host-side endpoints (the directory entries = the same mapped port;
    /// endpoint #2 = the second exposure opening, the §7-M2
    /// endpoint-switching simulation).
    fn endpoints(self) -> (String, String) {
        let host = std::env::var("FLOCK_SMOKE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        match self {
            Profile::Relay => (format!("{host}:27500"), format!("{host}:27501")),
            Profile::Direct => (format!("{host}:9443"), format!("{host}:9444")),
        }
    }
}

// ============================================================================
// docker helpers
// ============================================================================

fn compose_path(file: &str) -> std::path::PathBuf {
    std::path::Path::new(DEPLOY).join(file)
}

/// `docker compose -f <file> exec -T server <args...>` (stdout captured; a
/// non-zero exit = panic).
fn compose_exec(profile: Profile, args: &[&str]) -> String {
    let out = std::process::Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_path(profile.compose()))
        .args(["exec", "-T", "server"])
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("docker invocation failed (is Docker Desktop running?): {e}"));
    assert!(
        out.status.success(),
        "docker compose exec {:?} failed: {}{}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// `docker compose exec` where failure is allowed (pgrep's exit code 1 on
/// no match = the expected outcome).
fn compose_exec_status(profile: Profile, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_path(profile.compose()))
        .args(["exec", "-T", "server"])
        .args(args)
        .output()
        .expect("docker invocation failed");
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
    let mut args = vec![
        "/usr/local/bin/flock-server",
        "--config",
        "/etc/flock/server.toml",
    ];
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
            "endpoint {addr} not ready within 90s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// A username unique per run (named volumes keep state across runs ⇒ the
/// smoke must be re-entrant: account creation against the same store).
fn uname(base: &str) -> String {
    use flock_protocol::rand::RngCore as _;
    let mut rng = flock_protocol::rand::rng();
    let mut b = [0u8; 3];
    rng.fill_bytes(&mut b);
    format!("{base}-{}", hex::encode(b))
}

/// Parse `vip=a.b.c.d` out of CLI output.
fn parse_vip(out: &str) -> Option<u32> {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("vip="))
        .and_then(|v| v.parse::<std::net::Ipv4Addr>().ok())
        .map(u32::from)
}

/// The VIP must fall inside the 100.64.0.0/10 pool (RFC 6598, §2.1; from
/// .1 reserved for the server).
fn assert_vip_in_pool(vip: u32) {
    let lo = u32::from_be_bytes([100, 64, 0, 0]);
    let hi = u32::from_be_bytes([100, 127, 255, 255]);
    assert!(
        (lo..=hi).contains(&vip),
        "VIP {vip} not in the 100.64.0.0/10 pool"
    );
}

fn now() -> i64 {
    flock_protocol::trust::now_unix() as i64
}

fn expect_err(resp: CtrlResponse) -> CtrlError {
    match resp {
        CtrlResponse::Err { code, .. } => code,
        other => panic!("expected Err, got {other:?}"),
    }
}

fn dev_id(d: &DeviceStaticKeys) -> [u8; 32] {
    flock_protocol::session::DeviceId::from_ed25519(&d.ed25519_public()).0
}

// ============================================================================
// The full chain (invite → 1-RTT → OPAQUE login → key-bind → registry →
// SR-SIG1 → revocation)
// ============================================================================

async fn smoke_full_chain(profile: Profile) {
    let (ep1, _ep2) = profile.endpoints();
    wait_tcp(&ep1).await;

    let user = uname("smoke-alice");
    // Invite (minted by the in-container CLI; the admin endpoint = the
    // in-process single-writer entry).
    let invite_b64 = cli(profile, &["invite", "--ttl-secs", "3600"])
        .trim()
        .to_string();
    assert!(!invite_b64.is_empty(), "invite output non-empty");
    let invite_bytes = common_b64d(&invite_b64);
    let invite = InviteFile::from_bytes(&invite_bytes).expect("invite parse");
    assert_eq!(
        invite.directory.servers.len(),
        2,
        "the directory holds both endpoints"
    );
    let pin = pin_from_invite(&invite, 0);

    // Account creation: redeem the invite (CLI redeem: user/device + VIP).
    let dev_a = DeviceStaticKeys::generate();
    let out = cli(
        profile,
        &[
            "redeem",
            "--user",
            &user,
            "--invite-b64",
            &invite_b64,
            "--device-x",
            &common_b64(&dev_a.x25519_public().to_bytes()),
            "--device-ed",
            &common_b64(dev_a.ed25519_public().as_bytes()),
        ],
    );
    // The VIP is inside the 100.64.0.0/10 pool (named volumes keep
    // allocations across runs ⇒ assert pool membership, not an absolute
    // value; "the IP is not reused" is carried by the monotonicity
    // assertion of the key-bind below).
    let vip_a = parse_vip(&out).expect("redeem outputs vip=");
    assert_vip_in_pool(vip_a);
    // A second redemption of the same invite_id is rejected (the one-time
    // invite, proven in-container).
    let dev_x = DeviceStaticKeys::generate();
    let dup = cli_status(
        profile,
        &[
            "redeem",
            "--user",
            &uname("smoke-dup"),
            "--invite-b64",
            &invite_b64,
            "--device-x",
            &common_b64(&dev_x.x25519_public().to_bytes()),
            "--device-ed",
            &common_b64(dev_x.ed25519_public().as_bytes()),
        ],
    );
    assert!(!dup.0, "the second redemption must fail: {}", dup.1);

    // 1-RTT first connection (through the relay/direct host-mapped port ——
    // protocol-level isomorphic).
    let tunnel_a = connect(&dev_a, &pin).await;
    let mut a = CtrlClient::open(tunnel_a).await.expect("ctrl open");
    a.hello().await;
    assert!(matches!(
        a.set_password(&user, "pw").await,
        CtrlResponse::Ok
    ));

    // anchor negative path (equally effective on the container path):
    // tampered anchor_sig ⇒ the client rejects.
    {
        let mut rng = rand::rngs::OsRng;
        let (state, ke1) = login_start(&mut rng, "pw", &user).unwrap();
        match a
            .req(flock_server::control::CtrlRequest::LoginBegin {
                user: user.clone(),
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
                        &user,
                        &ke2_b64,
                        flock_server::control::AnchorLoginExpectation {
                            server_id: pin.entry.server_id.0,
                            identity_pub: pin.entry.identity_pub,
                            bind_token,
                            anchor_sig: t,
                        },
                    )
                    .is_err(),
                    "tampered anchor ⇒ rejected"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    // OPAQUE login (anchor) → ticket (the deployment TTL is 6s, see
    // deploy/server-*.toml).
    let (ticket_a, bind_token) = a.login_anchored(&user, "pw", &pin).await.expect("login");

    // key-bind: device B's public keys registered.
    let dev_b = DeviceStaticKeys::generate();
    let sr_key = UserKey::generate();
    match a
        .key_bind(
            &ticket_a,
            bind_token,
            &user,
            &invite.directory.cluster_id.0,
            &dev_b,
            &sr_key,
        )
        .await
    {
        CtrlResponse::KeyBound { device_id, vip } => {
            assert_eq!(device_id, dev_id(&dev_b));
            let vip_b = u32::from_be_bytes(vip);
            assert!(
                vip_b > vip_a,
                "VIP monotonic, not reused: {vip_b} > {vip_a}"
            );
            assert_vip_in_pool(vip_b);
        }
        other => panic!("key bind: {other:?}"),
    }

    // Device B enters the registry: 1-RTT connectable + dir_pull.
    let tunnel_b = connect(&dev_b, &pin).await;
    let mut b = CtrlClient::open(tunnel_b).await.expect("ctrl open B");
    b.hello().await;
    let dir = b.dir_pull().await;
    assert!(
        dir.verify(&invite.cluster_root_pub),
        "dir_pull root signature check"
    );

    // SR-SIG1 verification passes.
    let auth = CtrlClient::sr_auth(
        &user,
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

    // The three ticket states:
    // (1) No ticket.
    let no_tkt = CtrlClient::sr_auth(
        &user,
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
    // (2) Bad ticket + fresh nonce ⇒ rejected; the same nonce with a good
    //     ticket ⇒ passes (the end-to-end proof of the order contract).
    let mut bad = ticket_a.clone();
    if let flock_server::ticket::TicketWire::Local(t) = &mut bad {
        t.exp += 100;
    }
    let n = sr_sig::nonce_hex();
    let auth_n = CtrlClient::sr_auth(
        &user,
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
    // (3) Expired ticket (the deployment TTL is 6s).
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;
    let late = CtrlClient::sr_auth(
        &user,
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

    // After revocation the handshake is rejected (log in again for a fresh
    // ticket —— the old one already expired in (3)).
    let (ticket2, _) = a.login_anchored(&user, "pw", &pin).await.expect("re-login");
    let (ticket_b, _) = b.login_anchored(&user, "pw", &pin).await.expect("B login");
    let body = postcard::to_allocvec(&DeviceOp::Revoke {
        device: dev_id(&dev_a),
    })
    .unwrap();
    let rv = CtrlClient::sr_auth(
        &user,
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
    // Low-epoch ticket: the revocation advanced the epoch ⇒ B's old ticket
    // is void.
    let lb = postcard::to_allocvec(&DeviceOp::List).unwrap();
    let stale = CtrlClient::sr_auth(
        &user,
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

    // A's reconnect is rejected (respond Revoked ⇒ the client observes a
    // connection failure, §3.5 anti-enumeration).
    let io = tokio::net::TcpStream::connect(&pin.entry.relay_endpoint)
        .await
        .unwrap();
    let err = initiate(io, &dev_a, &pin, TunnelConfig::default())
        .await
        .expect_err("the handshake must be rejected after revocation");
    assert!(
        matches!(err, SessionError::DeviceRejected | SessionError::Io(_)),
        "got {err:?}"
    );
    // Control: B can still connect.
    let io_b = tokio::net::TcpStream::connect(&pin.entry.relay_endpoint)
        .await
        .unwrap();
    initiate(io_b, &dev_b, &pin, TunnelConfig::default())
        .await
        .expect("B can still connect");
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
    let mut args = vec![
        "/usr/local/bin/flock-server",
        "--config",
        "/etc/flock/server.toml",
    ];
    args.extend_from_slice(sub);
    compose_exec_status(profile, &args)
}

// ============================================================================
// TOFU (I0→R0 → fingerprint confirmation → pin persisted → second
// connection 1-RTT → dir_pull → still 1-RTT after switching endpoints)
// ============================================================================

async fn smoke_tofu(profile: Profile) {
    let (ep1, ep2) = profile.endpoints();
    wait_tcp(&ep1).await;

    // The TOFU device's management-side pre-provisioning (TOFU solves
    // trust bootstrapping, not account creation).
    let dev = DeviceStaticKeys::generate();
    let tofu_user = uname("smoke-tofu");
    let out = cli(
        profile,
        &[
            "device-add",
            "--user",
            &tofu_user,
            "--device-x",
            &common_b64(&dev.x25519_public().to_bytes()),
            "--device-ed",
            &common_b64(dev.ed25519_public().as_bytes()),
        ],
    );
    assert!(out.contains("vip=100.64."), "device-add: {out}");

    // First connection I0→R0 (the client has no invite/no pin).
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

    // Root fingerprint confirmation + pin persisted (a host temp
    // directory).
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
        "pin persisted"
    );
    let mut c1 = CtrlClient::open(t1).await.unwrap();
    c1.hello().await;

    // Second connection 1-RTT (the pinned form).
    let pin1 = ServerPin {
        cluster_id,
        cluster_root_pub: root_pub,
        entry: entry0,
    };
    let t2 = connect(&dev, &pin1).await;
    let mut c2 = CtrlClient::open(t2).await.unwrap();
    c2.hello().await;

    // dir_pull → still 1-RTT after switching endpoints (the second
    // exposure opening).
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
// Entries (the test names = the harness profile filters)
// ============================================================================

#[ignore = "runs against containers: docker compose up first (see the file header); cargo test -- --ignored relay|direct"]
#[tokio::test]
async fn relay_full_chain() {
    smoke_full_chain(Profile::Relay).await;
}

#[ignore = "runs against containers: see the file header"]
#[tokio::test]
async fn relay_tofu_dirpull_endpoint_switch() {
    smoke_tofu(Profile::Relay).await;
}

#[ignore = "runs against containers: see the file header"]
#[tokio::test]
async fn relay_frpc_supervisor_process_running() {
    let (ep1, _) = Profile::Relay.endpoints();
    wait_tcp(&ep1).await;
    // Frp-mode runtime proof: the frpc subprocess runs Supervisor-managed
    // inside the server container.
    let (ok, out) = compose_exec_status(Profile::Relay, &["pgrep", "-f", "frpc"]);
    assert!(
        ok,
        "the frpc process should be running (Supervisor-managed): {out}"
    );
}

#[ignore = "runs against containers: see the file header"]
#[tokio::test]
async fn direct_full_chain() {
    smoke_full_chain(Profile::Direct).await;
}

#[ignore = "runs against containers: see the file header"]
#[tokio::test]
async fn direct_tofu_dirpull_endpoint_switch() {
    smoke_tofu(Profile::Direct).await;
}

#[ignore = "runs against containers: see the file header (§7-M2: the Direct-form container has no `pgrep -f frp` process)"]
#[tokio::test]
async fn direct_no_frp_process_in_container() {
    let (ep1, _) = Profile::Direct.endpoints();
    wait_tcp(&ep1).await;
    // Runtime proof that the Direct code path has zero frp logic (§7-M2):
    // no frp process inside the container.
    let (ok, out) = compose_exec_status(Profile::Direct, &["pgrep", "-f", "frp"]);
    assert!(
        !ok,
        "no frp process may appear in the Direct container: {out}"
    );
}
