//! M2 full-chain in-process integration (the non-container part of the
//! docs/design.md §7-M2 completion criteria; real container runs are in
//! tests/smoke.rs).
//!
//! Coverage:
//! 1. `full_chain_*`: invite → 1-RTT first connection → OPAQUE login
//!    (anchor verification + tamper rejection) → ticket → key-bind (device
//!    signature) → device B enters the registry (1-RTT connectable) →
//!    SR-SIG1 verification → the ticket contract (no ticket/bad-ticket
//!    ordering/nonce not recorded/replay/time window) → revocation →
//!    session kill + handshake rejected + low-epoch ticket void;
//! 2. `tofu_*`: TOFU first connection I0→R0 → root fingerprint
//!    confirmation → pin persisted → second connection 1-RTT → dir_pull →
//!    still 1-RTT after switching endpoints (the second exposure opening);
//! 3. `ticket_expiry_*`: the expired-ticket three states under a short-TTL
//!    real clock.

mod common;

use common::{connect, pin_from_invite, pin_with_root, CtrlClient, TestServer};
use flock_protocol::pake::login_start;
use flock_protocol::rand;
use flock_protocol::session::{
    fingerprint_ed25519, initiate, initiate_tofu, DeviceId, DeviceStaticKeys, LookupVerdict,
    ServerPin, SessionError, TunnelConfig,
};
use flock_protocol::sig as sr_sig;
use flock_protocol::sig::UserKey;
use flock_protocol::trust::{confirm_tofu_and_pin, InviteFile, PinStore, PinVerdict};
use flock_server::control::{client_login_finish_anchored, CtrlError, CtrlResponse, DeviceOp};

// ============================================================================
// 4. The revoke-register race (review item 5)
// ============================================================================

/// Timeline: respond's lookup passes (Active) → revoke arrives before the
/// register → the second directory verdict after the register is not
/// Active ⇒ serve_conn tears down the connection (the millisecond window
/// closed).
///
/// Note: there is no externally controllable await point between lookup and
/// register inside the server process (after R1 is sent it reaches the
/// register synchronously), so pure black-box testing cannot pin that
/// interleave from outside —— this test drives the real store lookup and
/// the real admission path step by step per the review's described timeline
/// (`post_register_admission` is the very method serve_conn calls after
/// register); all three steps land on real components.
#[tokio::test]
async fn revoke_between_handshake_lookup_and_register_closes_session() {
    let srv = TestServer::start(60).await;
    let invite_bytes = srv.mint_invite(3600).await;
    let invite = InviteFile::from_bytes(&invite_bytes).unwrap();
    let pin = pin_from_invite(&invite, 0);
    let dev = DeviceStaticKeys::generate();
    srv.redeem(&invite_bytes, "race-user", &dev).await;
    let did = DeviceId(dev_id(&dev));

    // Step 1: respond's lookup (Active passes —— the first half of the race
    // window).
    assert!(
        matches!(srv.core.net.lookup(&did).await, LookupVerdict::Active(_)),
        "first half of the race window: the device is Active at lookup"
    );

    // Step 2: revoke arrives before the register (the kill broadcast misses
    // —— no session registered yet).
    srv.core.net.revoke(&did).await.expect("revoke");
    assert_eq!(
        srv.core.sessions.online(&did.0),
        0,
        "no session on record yet"
    );

    // Step 3: the second admission after the register (serve_conn's race
    // backstop) ⇒ not Active ⇒ the connection is torn down.
    assert!(
        !srv.core.post_register_admission(&did).await,
        "not Active after register ⇒ serve_conn tears down the connection (window closed)"
    );

    // End-to-end control: this device's new handshake is rejected at the
    // lookup step (Revoked gets no R1).
    let io = tokio::net::TcpStream::connect(&pin.entry.relay_endpoint)
        .await
        .unwrap();
    let err = initiate(io, &dev, &pin, TunnelConfig::default())
        .await
        .expect_err("revoked device must not complete handshake");
    assert!(matches!(
        err,
        SessionError::DeviceRejected | SessionError::Io(_)
    ));

    // The admission semantics are consistent with the registry state
    // (control device): Disable ⇒ admission rejected; Enable
    // (Disabled→Active reversible; Revoked terminal, irreversible) ⇒
    // admission restored and passing.
    let dev2 = DeviceStaticKeys::generate();
    srv.device_add("race-user", &dev2).await;
    let did2 = DeviceId(dev_id(&dev2));
    srv.core.net.disable(&did2).await.expect("disable");
    assert!(
        !srv.core.post_register_admission(&did2).await,
        "admission rejected after disable (teardown semantics same as revocation)"
    );
    srv.core.net.enable(&did2).await.expect("enable");
    assert!(
        srv.core.post_register_admission(&did2).await,
        "restored to Active ⇒ admission passes"
    );
}

fn now() -> i64 {
    flock_protocol::trust::now_unix() as i64
}

fn dev_id(d: &DeviceStaticKeys) -> [u8; 32] {
    DeviceId::from_ed25519(&d.ed25519_public()).0
}

fn expect_err(resp: CtrlResponse) -> CtrlError {
    match resp {
        CtrlResponse::Err { code, .. } => code,
        other => panic!("expected Err, got {other:?}"),
    }
}

// ============================================================================
// 1. The full chain
// ============================================================================

#[tokio::test]
async fn full_chain_invite_login_keybind_srsig1_revoke() {
    let srv = TestServer::start(60).await;

    // —— Invite (root-signed v3, carrying the full server material/both
    //    endpoints) ——
    let invite_bytes = srv.mint_invite(3600).await;
    let invite = InviteFile::from_bytes(&invite_bytes).expect("invite parse");
    assert!(
        invite.verify_against(&srv.core.identity.root_pub),
        "root signature check"
    );
    assert_eq!(
        invite.directory.servers.len(),
        2,
        "the directory holds the primary endpoint + the second exposure opening"
    );
    let pin = pin_from_invite(&invite, 0);

    // —— Account creation: redeem the invite (user/device + VIP) ——
    let dev_a = DeviceStaticKeys::generate();
    let vip_a = srv.redeem(&invite_bytes, "alice", &dev_a).await;
    assert_eq!(
        vip_a,
        [100, 64, 0, 2],
        "the first VIP = 100.64.0.2 (.1 reserved for the server)"
    );

    // —— 1-RTT first connection (initiate = the pinned form, one round
    //    trip) ——
    let tunnel_a = connect(&dev_a, &pin).await;
    let mut a = CtrlClient::open(tunnel_a).await.expect("ctrl open");
    let (cid, sid) = a.hello().await;
    assert_eq!(cid, srv.core.identity.cluster_id.0);
    assert_eq!(sid, srv.core.identity.server_id.0);

    // —— OPAQUE registration (set password; authorization = the session
    //    device's owner) ——
    assert!(matches!(
        a.set_password("alice", "pw-123").await,
        CtrlResponse::Ok
    ));

    // —— anchor negative path: tampered anchor_sig ⇒ the client's
    //    login_finish_anchored rejects ——
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
                    "tampered anchor signature ⇒ the client rejects (no ke3 produced)"
                );
            }
            other => panic!("login challenge: {other:?}"),
        }
    }

    // —— OPAQUE login (anchor verification passes) → ticket ——
    let (ticket_a, bind_token) = a
        .login_anchored("alice", "pw-123", &pin)
        .await
        .expect("login");
    match &ticket_a {
        flock_server::ticket::TicketWire::Local(t) => {
            assert_eq!(t.user, "alice");
            assert_eq!(
                t.device,
                dev_id(&dev_a).to_vec(),
                "the ticket binds the session device"
            );
        }
        other => panic!("the single-server form's ticket should be Local: {other:?}"),
    }

    // —— key-bind: device B's public keys registered (ticket + one-time
    //    bind_token + device signature) ——
    let dev_b = DeviceStaticKeys::generate();
    let sr_key = UserKey::generate();
    match a
        .key_bind(&ticket_a, bind_token, "alice", &cid, &dev_b, &sr_key)
        .await
    {
        CtrlResponse::KeyBound { device_id, vip } => {
            assert_eq!(device_id, dev_id(&dev_b), "device B's DeviceId returned");
            assert_eq!(vip, [100, 64, 0, 3], "VIP allocated monotonically");
        }
        other => panic!("key bind: {other:?}"),
    }
    // bind_token one-time: a second bind with the same token rejected.
    let dev_c = DeviceStaticKeys::generate();
    match a
        .key_bind(&ticket_a, bind_token, "alice", &cid, &dev_c, &sr_key)
        .await
    {
        resp @ CtrlResponse::KeyBound { .. } => {
            panic!("the bind_token's second consumption was not rejected: {resp:?}")
        }
        resp => assert_eq!(expect_err(resp), CtrlError::BindTokenUsed),
    }

    // —— Device B enters the registry: 1-RTT connectable + directory pull ——
    let tunnel_b = connect(&dev_b, &pin).await;
    let mut b = CtrlClient::open(tunnel_b).await.expect("ctrl open B");
    b.hello().await;
    let dir = b.dir_pull().await;
    assert!(
        dir.verify(&srv.core.identity.root_pub),
        "dir_pull root signature check"
    );
    assert_eq!(dir.servers[0].relay_endpoint, srv.primary);
    assert_eq!(dir.servers[1].relay_endpoint, srv.alt);

    // —— SR-SIG1 request verification passes (the TicketRenew state
    //    change) ——
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

    // —— The ticket contract's three states + ordering ——
    // (a) No ticket ⇒ TicketMissing.
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

    // (b) Contract order: bad ticket + fresh nonce ⇒ TicketBad; the same
    //     nonce with a valid ticket ⇒ passes (proof it was not recorded).
    //     Tampering a covered field ⇒ the signature fails (TicketWire::
    //     Local's exp goes into the canonical bytes).
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
        "the bad ticket is rejected"
    );
    assert!(
        matches!(
            a.ticket_renew(Some(ticket_a.clone()), auth3.clone()).await,
            CtrlResponse::TicketRenewed { .. }
        ),
        "the same nonce passes with a valid ticket ⇒ the earlier rejection was not recorded"
    );
    // (c) Nonce replay ⇒ NonceReplay.
    assert_eq!(
        expect_err(a.ticket_renew(Some(ticket_a.clone()), auth3).await),
        CtrlError::NonceReplay
    );
    // (d) Outside the time window ⇒ SigStale.
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
    // (e) Bad signature (swapped key) ⇒ SigBad, and the nonce is not
    //     recorded (the same nonce passes later with the good key).
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
        "the signature failure was not recorded"
    );

    // —— Revocation (initiated from B's logged-in state; A is revoked) ——
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

    // A's local session is killed (§2.2): its subsequent control requests
    // end in IO failure.
    {
        let mut a2 = a;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            a2.req(flock_server::control::CtrlRequest::DirPull { since_version: 0 }),
        )
        .await;
        assert!(
            r.is_err() || r.unwrap().is_err(),
            "A's session is torn down after revocation"
        );
    }

    // Low-epoch ticket: the revocation advanced the epoch ⇒ B's old ticket
    // is void.
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
        "ticket epoch < current epoch ⇒ rejected"
    );

    // Handshake rejected after revocation: respond-side Revoked ⇒ the same
    // opaque DeviceRejected and **no R1 returned** (anti-online-enumeration,
    // §3.5 timing alignment) ⇒ the client observes a connection failure
    // (EOF), not a distinguishable error code.
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
    // Control: the unrevoked device B still connects 1-RTT at the same
    // instant (the rejection is causally tied to the revocation, not a dead
    // server).
    let io_b = tokio::net::TcpStream::connect(&pin.entry.relay_endpoint)
        .await
        .unwrap();
    initiate(io_b, &dev_b, &pin, TunnelConfig::default())
        .await
        .expect("active device still connects");
}

// ============================================================================
// 2. TOFU first connection → pin → second connection 1-RTT → dir_pull →
//    still 1-RTT after switching endpoints
// ============================================================================

#[tokio::test]
async fn tofu_bootstrap_pin_second_connect_and_endpoint_switch() {
    let srv = TestServer::start(60).await;
    // The TOFU device pre-provisioned via the management surface (TOFU
    // solves **trust** bootstrapping, not account creation, §1.3.3f).
    let dev = DeviceStaticKeys::generate();
    srv.device_add("tofu-user", &dev).await;

    // —— First connection I0→R0 (no invite/no pin) ——
    let io = tokio::net::TcpStream::connect(&srv.primary).await.unwrap();
    let boot = initiate_tofu(
        io,
        DeviceStaticKeys::from_bytes(&dev.to_bytes()),
        TunnelConfig::default(),
    )
    .await
    .expect("tofu bootstrap");
    // The root fingerprint = the server root public key's fingerprint (the
    // presentation subject of the confirmation callback).
    assert_eq!(
        boot.root_fingerprint(),
        fingerprint_ed25519(&srv.core.identity.root_pub),
        "R0 carries the enrollment credential chain and the cluster root public key"
    );
    let cluster_id = boot.cluster_id();
    let root_pub = *boot.root_pub();
    let entry0 = boot.server_entry().clone();
    assert_eq!(entry0.relay_endpoint, srv.primary);

    // —— Root fingerprint confirmation (callback) + pin persisted ——
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
        "the pinned cluster root public key persisted"
    );
    let mut c1 = CtrlClient::open(t1).await.unwrap();
    c1.hello().await; // the TOFU session works

    // —— Second connection 1-RTT: already pinned (the initiate form, I0
    //    no longer appears) ——
    let pin1 = ServerPin {
        cluster_id,
        cluster_root_pub: root_pub,
        entry: entry0,
    };
    let t2 = connect(&dev, &pin1).await;
    let mut c2 = CtrlClient::open(t2).await.unwrap();
    c2.hello().await;

    // —— dir_pull: the root-signed directory → pin-store registration →
    //    still 1-RTT after switching endpoints (the second exposure
    //    opening) ——
    let dir = c2.dir_pull().await;
    assert!(dir.verify(&root_pub));
    pins.record_directory(&root_pub, &dir).expect("record dir");
    assert_eq!(dir.servers.len(), 2);
    let pin2 = pin_with_root(&dir, 1, root_pub);
    assert_eq!(
        pin2.entry.relay_endpoint, srv.alt,
        "endpoint #2 = the second exposure opening"
    );
    let t3 = connect(&dev, &pin2).await;
    let mut c3 = CtrlClient::open(t3).await.unwrap();
    c3.hello().await; // still 1-RTT after switching endpoints, session works
}

// ============================================================================
// 3. Expired tickets (a short-TTL real clock)
// ============================================================================

#[tokio::test]
async fn ticket_expiry_rejected_after_ttl() {
    let srv = TestServer::start(2).await; // TTL 2s (deployments may lower it; the default 60 = the §2.2 hard cap)
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

    // key-bind registers the SR-SIG1 user public key (needs a bind_token ⇒
    // log in once more).
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
    // Renewal within the TTL: passes.
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
    // Wait past the TTL: the same operation with a fresh signature layer ⇒
    // TicketBad (expired, §2.2 equivalent replay window = min(±300s,
    // TTL)).
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
        "the ticket TTL expiring ⇒ the state change is rejected"
    );
    // The old ticket (from the first login) is likewise expired.
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
