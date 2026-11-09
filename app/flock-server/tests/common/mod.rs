//! In-process test assembly (shared by the `tests/control_flow.rs` full
//! chain and `tests/listener_mode.rs`).
//!
//! - [`TestServer`]: dual listeners (primary endpoint + a second exposure
//!   opening = the "still 1-RTT after switching endpoints" simulation,
//!   §7-M2), `ServerCore::serve_listener` hung directly (the assembly
//!   dispatch of `run()` is covered by `tests/listener_mode.rs`); the
//!   management surface (invite minting/redemption/registration) calls
//!   `ServerCore`/`NetState` directly —— the out-of-process admin TCP
//!   endpoint path is covered by `tests/smoke.rs` via the in-container CLI.
//! - [`CtrlClient`]: the control-flow client driver (the first yamux
//!   stream, postcard frames) —— OPAQUE registration/login (anchor
//!   verification)/key-bind (device signature)/SR-SIG1/DirPull wrapped step
//!   by step; tests assert intermediate products as needed.

#![allow(dead_code)]

use std::sync::Arc;

use flock_protocol::ed25519_dalek;
use flock_protocol::ed25519_dalek::Signer as _;
use flock_protocol::mux::Prio;
use flock_protocol::pake::{login_start, reg_finish, reg_start};
use flock_protocol::rand;
use flock_protocol::session::{initiate, DeviceStaticKeys, ServerPin, Tunnel, TunnelConfig};
use flock_protocol::sig as sr_sig;
use flock_protocol::sig::{self, UserKey};
use flock_protocol::trust::{ClusterDirectory, InviteFile};
use flock_server::config::ServerConfig;
use flock_server::control::{
    client_login_finish_anchored, keybind_canonical, recv_ctrl_msg, send_ctrl_msg, CtrlRequest,
    CtrlResponse, DeviceOp, DevicePubs, SrAuth, CTRL_METHOD, CTRL_PROTO_VERSION, PATH_DEVICE_OP,
    PATH_REDEEM_INVITE, PATH_TICKET_RENEW,
};
use flock_server::netstate::RedeemRequest;
use flock_server::server::ServerCore;
use flock_server::ticket::TicketWire;

pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

/// A control-flow client already connected to a tunnel.
pub struct CtrlClient {
    pub tunnel: Tunnel,
    stream: flock_protocol::mux::Stream,
}

impl CtrlClient {
    pub async fn open(tunnel: Tunnel) -> std::io::Result<Self> {
        let stream = tunnel.open_stream(Prio::Control).await?;
        Ok(CtrlClient { tunnel, stream })
    }

    pub async fn req(&mut self, req: CtrlRequest) -> std::io::Result<CtrlResponse> {
        send_ctrl_msg(&mut self.stream, &req).await?;
        recv_ctrl_msg(&mut self.stream).await
    }

    pub async fn hello(&mut self) -> ([u8; 16], [u8; 16]) {
        match self
            .req(CtrlRequest::Hello {
                ver: CTRL_PROTO_VERSION,
            })
            .await
            .unwrap()
        {
            CtrlResponse::Hello {
                cluster_id,
                server_id,
                ..
            } => (cluster_id, server_id),
            other => panic!("hello: {other:?}"),
        }
    }

    pub async fn set_password(&mut self, user: &str, pw: &str) -> CtrlResponse {
        let mut rng = rand::rngs::OsRng;
        let (state, m1) = reg_start(&mut rng, pw, user).expect("reg start");
        let m2 = match self
            .req(CtrlRequest::PwBegin {
                user: user.into(),
                m1_b64: m1,
            })
            .await
            .unwrap()
        {
            CtrlResponse::PwChallenge { m2_b64 } => m2_b64,
            other => panic!("pw begin: {other:?}"),
        };
        let record = reg_finish(&mut rng, state, pw, user, &m2).expect("reg finish");
        self.req(CtrlRequest::PwCommit {
            record_b64: record,
            profile: 0,
        })
        .await
        .unwrap()
    }

    /// OPAQUE login (anchor: the client verifies the server's signature
    /// against the pinned identity). Success returns (ticket, bind_token);
    /// business errors are carried as strings (for negative-path
    /// assertions).
    pub async fn login_anchored(
        &mut self,
        user: &str,
        pw: &str,
        pin: &ServerPin,
    ) -> Result<(TicketWire, [u8; 16]), String> {
        let mut rng = rand::rngs::OsRng;
        let (state, ke1) = login_start(&mut rng, pw, user).expect("login start");
        let (ke2, bind_token, anchor_sig) = match self
            .req(CtrlRequest::LoginBegin {
                user: user.into(),
                ke1_b64: ke1,
            })
            .await
            .unwrap()
        {
            CtrlResponse::LoginChallenge {
                ke2_b64,
                bind_token,
                anchor_sig,
            } => (ke2_b64, bind_token, anchor_sig),
            CtrlResponse::Err { code, msg } => return Err(format!("{code:?}: {msg}")),
            other => return Err(format!("login challenge: {other:?}")),
        };
        let ke3 = client_login_finish_anchored(
            state,
            pw,
            user,
            &ke2,
            flock_server::control::AnchorLoginExpectation {
                server_id: pin.entry.server_id.0,
                identity_pub: pin.entry.identity_pub,
                bind_token,
                anchor_sig,
            },
        )
        .map_err(|e| format!("anchor login finish: {e}"))?;
        match self
            .req(CtrlRequest::LoginFinish { ke3_b64: ke3 })
            .await
            .unwrap()
        {
            CtrlResponse::LoginOk { ticket, .. } => Ok((ticket, bind_token)),
            CtrlResponse::Err { code, msg } => Err(format!("{code:?}: {msg}")),
            other => Err(format!("login ok: {other:?}")),
        }
    }

    /// key-bind: register device B's static public keys + the user's
    /// SR-SIG1 public key (the device signature = proof of possession).
    pub async fn key_bind(
        &mut self,
        ticket: &TicketWire,
        bind_token: [u8; 16],
        user: &str,
        cluster_id: &[u8; 16],
        device_b: &DeviceStaticKeys,
        sr_key: &UserKey,
    ) -> CtrlResponse {
        let device = DevicePubs {
            x25519: device_b.x25519_public().to_bytes(),
            ed25519: *device_b.ed25519_public().as_bytes(),
            hostname: String::new(),
        };
        let sr_pub = *sr_sig::UserKey::from_pub_string(&sr_key.pub_string())
            .unwrap()
            .as_bytes();
        let canonical = keybind_canonical(cluster_id, user, &bind_token, &device, &sr_pub);
        let seed = device_b.to_bytes();
        let sk = ed25519_dalek::SigningKey::from_bytes(seed[32..64].try_into().unwrap());
        let device_sig = sk.sign(&canonical).to_bytes().to_vec();
        self.req(CtrlRequest::KeyBind {
            ticket: ticket.clone(),
            bind_token,
            device,
            sr_sig_pub: sr_pub,
            device_sig,
        })
        .await
        .unwrap()
    }

    /// SR-SIG1 authorization-header construction (the canonical seven
    /// fields, §1.3.2 wire format unchanged).
    pub fn sr_auth(
        user: &str,
        key: &UserKey,
        path: &str,
        body: &[u8],
        ts: i64,
        nonce: &str,
    ) -> SrAuth {
        SrAuth {
            header: sig::sign_prehashed(
                user,
                key,
                CTRL_METHOD,
                path,
                &sig::sha256_hex(body),
                ts,
                nonce,
            ),
        }
    }

    pub fn path_ticket_renew() -> &'static str {
        PATH_TICKET_RENEW
    }

    pub fn path_device_op() -> &'static str {
        PATH_DEVICE_OP
    }

    pub fn path_redeem() -> &'static str {
        PATH_REDEEM_INVITE
    }

    pub async fn ticket_renew(&mut self, ticket: Option<TicketWire>, auth: SrAuth) -> CtrlResponse {
        self.req(CtrlRequest::TicketRenew { ticket, auth })
            .await
            .unwrap()
    }

    pub async fn device_op(
        &mut self,
        ticket: Option<TicketWire>,
        auth: SrAuth,
        op: DeviceOp,
    ) -> CtrlResponse {
        self.req(CtrlRequest::DeviceOp { ticket, auth, op })
            .await
            .unwrap()
    }

    pub async fn redeem(
        &mut self,
        ticket: Option<TicketWire>,
        auth: SrAuth,
        invite_bytes: &[u8],
        username: &str,
        device: &DeviceStaticKeys,
    ) -> CtrlResponse {
        self.req(CtrlRequest::RedeemInvite {
            ticket,
            auth,
            invite_b64: b64(invite_bytes),
            username: username.into(),
            device: DevicePubs {
                x25519: device.x25519_public().to_bytes(),
                ed25519: *device.ed25519_public().as_bytes(),
                hostname: String::new(),
            },
        })
        .await
        .unwrap()
    }

    pub async fn dir_pull(&mut self) -> ClusterDirectory {
        match self
            .req(CtrlRequest::DirPull { since_version: 0 })
            .await
            .unwrap()
        {
            CtrlResponse::Directory { bytes, .. } => {
                ClusterDirectory::from_bytes(&bytes).expect("dir decode")
            }
            other => panic!("dir pull: {other:?}"),
        }
    }
}

/// An already-pinned 1-RTT connection (an invite file or a pinned directory
/// entry).
pub async fn connect(device: &DeviceStaticKeys, pin: &ServerPin) -> Tunnel {
    let io = tokio::net::TcpStream::connect(&pin.entry.relay_endpoint)
        .await
        .expect("tcp");
    initiate(io, device, pin, TunnelConfig::default())
        .await
        .expect("1-RTT initiate")
}

/// Build the target endpoint pin from an invite file (idx = the directory
/// entry index).
pub fn pin_from_invite(invite: &InviteFile, idx: usize) -> ServerPin {
    ServerPin {
        cluster_id: invite.directory.cluster_id,
        cluster_root_pub: invite.cluster_root_pub,
        entry: invite.directory.servers[idx].clone(),
    }
}

/// Build the target endpoint pin from a root-signed directory + the pinned
/// root public key (the endpoint-switching path after dir_pull).
pub fn pin_with_root(
    dir: &ClusterDirectory,
    idx: usize,
    root_pub: ed25519_dalek::VerifyingKey,
) -> ServerPin {
    ServerPin {
        cluster_id: dir.cluster_id,
        cluster_root_pub: root_pub,
        entry: dir.servers[idx].clone(),
    }
}

// ============================================================================
// TestServer (in-process, dual endpoints)
// ============================================================================

pub struct TestServer {
    pub core: Arc<ServerCore>,
    pub primary: String,
    pub alt: String,
    pub state_dir: std::path::PathBuf,
    _tasks: Vec<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl TestServer {
    /// `ticket_ttl_secs` injected (a small TTL for exercising the
    /// expired-ticket path; the formal default 60 = the §2.2 hard cap).
    pub async fn start(ticket_ttl_secs: u64) -> TestServer {
        let dir = tempfile::tempdir().expect("tmp");
        let state_dir = dir.path().to_path_buf();
        // Keep the tempdir alive until process end (leaking the directory
        // beats tearing down the state store early).
        std::mem::forget(dir);
        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary = l1.local_addr().unwrap().to_string();
        let alt = l2.local_addr().unwrap().to_string();

        let cfg = ServerConfig {
            state_dir: state_dir.clone(),
            bind: "127.0.0.1:9443".parse().unwrap(),
            mode: "direct".into(),
            advertise_endpoint: primary.clone(),
            extra_endpoints: vec![alt.clone()],
            dir_version: 1,
            ticket_ttl_secs,
            peer_retention_days: 30,
            admin_bind: "127.0.0.1:0".parse().unwrap(),
            max_sessions: 1024,
            tun_name: "tun0".into(),
            vip: "100.64.0.1".parse().unwrap(),
            frp: None,
            sync: None,
            webui: flock_server::config::WebUiSection {
                enabled: false,
                ..Default::default()
            },
        };
        let (core, created) = ServerCore::open_or_init(cfg).expect("core");
        assert!(created, "a fresh state store");
        let tasks = vec![
            tokio::spawn(core.clone().serve_listener(l1)),
            tokio::spawn(core.clone().serve_listener(l2)),
        ];
        TestServer {
            core,
            primary,
            alt,
            state_dir,
            _tasks: tasks,
        }
    }

    /// Management-surface invite minting (single-server form: the root key
    /// is in-store).
    pub async fn mint_invite(&self, ttl_secs: u64) -> Vec<u8> {
        self.core.mint_invite(ttl_secs).await.expect("mint")
    }

    /// Management-surface device registration (the server-side
    /// pre-provisioning of the TOFU flow).
    pub async fn device_add(&self, user: &str, device: &DeviceStaticKeys) -> [u8; 4] {
        self.core
            .net
            .register_device(
                user,
                device.x25519_public().to_bytes(),
                *device.ed25519_public().as_bytes(),
                "",
            )
            .await
            .expect("device add")
            .vip
    }

    /// Management-surface invite redemption (account creation: user/device
    /// + VIP).
    pub async fn redeem(&self, invite: &[u8], user: &str, device: &DeviceStaticKeys) -> [u8; 4] {
        self.core
            .net
            .redeem_invite(RedeemRequest {
                invite_bytes: invite,
                username: user,
                device_x25519: device.x25519_public().to_bytes(),
                device_ed25519: *device.ed25519_public().as_bytes(),
                hostname: "",
                expected_root_pub: *self.core.identity.root_pub.as_bytes(),
                expected_cluster_id: self.core.identity.cluster_id.0,
                now_unix: flock_protocol::trust::now_unix(),
            })
            .await
            .expect("redeem")
            .vip
    }
}
