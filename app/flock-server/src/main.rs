//! flock-server process entry (docs/design.md §3.11: `--config server.toml`
//! / `init-cluster` / operations subcommands).
//!
//! Subcommands:
//! - (default `run`): start the server —— assembled per `listener.mode`
//!   (Direct default / Frp relay managed);
//! - `init-cluster`: bootstrap the state store (cluster root/identity/static
//!   hybrid/OPRF/ticket-root seeds; errors if already initialized);
//! - `invite [--ttl-secs N]`: mint an invite (admin endpoint → v3 invite file
//!   b64 to stdout);
//! - `redeem --user U --invite-b64 B --device-x B --device-ed B`: redeem an
//!   invite to create an account (admin endpoint);
//! - `device-add --user U --device-x B --device-ed B`: register a device
//!   directly (TOFU pre-provisioning; admin endpoint);
//! - `revoke --device HEX32B`: revoke a device (admin endpoint).
//!
//! `enroll` (multi-server join) is M4 scope (the §4 admission pipeline), not
//! provided in this milestone —— declared as-is.

use std::path::PathBuf;

use flock_server::admin::{client, AdminRequest, AdminResponse};
use flock_server::config::ServerConfig;
use flock_server::control::DevicePubs;

const USAGE: &str = "\
flock-server [--config <server.toml>] [<subcommand>]

Subcommands:
  (run)                          start the server (default; listener.mode = direct default / frp;
                                 with [sync] mode=raft takes the multi-primary assembly - TCP fabric + SyncNode)
  init-cluster [--voters N --out DIR [--endpoints e1,e2,...]]
                                 single server: bootstrap the state store; --voters: generate
                                 multi-primary cluster material (root key root.seed + per-voter
                                 enrollment bundle node-i.bundle; endpoints = each voter's
                                 client-visible access endpoint, section 6.2)
  enroll --bundle FILE           load and verify the node bundle (root-signed directory +
                                 enrollment credential), persist into the state directory
  cluster-bootstrap --root-seed FILE
                                 multi-primary ops: root-key-signed Bootstrap (ticket root) +
                                 SetOprf (shared OPRF), submitted via the local admin endpoint
                                 (idempotent, re-runnable)
  cluster-invite --root-seed FILE --bundle FILE [--ttl-secs N]
                                 multi-primary ops: sign a v3 invite with the root key
                                 (directory taken from the bundle) -> stdout b64
  stats                          runtime status snapshot (epoch/leader/forwarding counters/online sessions)
  invite [--ttl-secs N]          mint an invite -> single-line b64 on stdout (single-server form)
  redeem --user U --invite-b64 B --device-x B32 --device-ed B32
                                 redeem an invite to create an account (user/device + VIP assignment)
  device-add --user U --device-x B32 --device-ed B32
                                 register a device directly (TOFU pre-provisioning)
  revoke --device HEX64          revoke a device (advance revocation_epoch + kill sessions)
  web-admin-add <username>       M8 Web UI first-admin bootstrap (password twice on stdin;
                                 native OPAQUE registration; prefers the admin endpoint;
                                 server not running => single-server direct write /
                                 multi-primary errors with explicit guidance)
";

fn main() {
    let code = match run_cli() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("flock-server: {e}");
            2
        }
    };
    std::process::exit(code);
}

struct Cli {
    config: PathBuf,
    cmd: Cmd,
}

enum Cmd {
    Run,
    InitCluster {
        voters: Option<usize>,
        out: Option<String>,
        endpoints: Option<String>,
    },
    Enroll {
        bundle: String,
    },
    ClusterBootstrap {
        root_seed: String,
    },
    ClusterInvite {
        root_seed: String,
        bundle: String,
        ttl_secs: u64,
    },
    Stats,
    Invite {
        ttl_secs: u64,
    },
    Redeem {
        invite_b64: String,
        username: String,
        device: DevicePubs,
    },
    DeviceAdd {
        username: String,
        device: DevicePubs,
    },
    Revoke {
        device: [u8; 32],
    },
    /// M8: Web UI first-admin bootstrap (§7-M8.3 —— password twice on stdin +
    /// native OPAQUE registration).
    WebAdminAdd {
        user: String,
    },
}

fn parse_args() -> Result<Cli, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut config = PathBuf::from("server.toml");
    // Global flags peeled off first; the rest parsed as positional
    // arguments/subcommand flags.
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--config" => {
                i += 1;
                config = PathBuf::from(raw.get(i).ok_or("--config value")?.clone());
            }
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    let mut it = rest.into_iter().peekable();
    let cmd = match it.peek().map(|s| s.as_str()) {
        None | Some("run") => Cmd::Run,
        Some("init-cluster") => {
            it.next();
            let (mut voters, mut out, mut endpoints) = (None, None, None);
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} value"))?;
                match k.as_str() {
                    "--voters" => {
                        voters = Some(v.parse().map_err(|e| format!("voters: {e}"))?);
                    }
                    "--out" => out = Some(v),
                    "--endpoints" => endpoints = Some(v),
                    other => return Err(format!("init-cluster: unknown argument {other:?}")),
                }
            }
            if voters.is_some() && out.is_none() {
                return Err("init-cluster --voters requires --out DIR".into());
            }
            if let Some(n) = voters {
                let eps = endpoints
                    .as_deref()
                    .map(|s| s.split(',').count())
                    .unwrap_or(0);
                if eps != n {
                    return Err(format!(
                        "init-cluster --endpoints must match --voters count ({eps} != {n}; comma-separated, in voter order)"
                    ));
                }
            }
            Cmd::InitCluster {
                voters,
                out,
                endpoints,
            }
        }
        Some("enroll") => {
            it.next();
            let mut bundle = None;
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} value"))?;
                match k.as_str() {
                    "--bundle" => bundle = Some(v),
                    other => return Err(format!("enroll: unknown argument {other:?}")),
                }
            }
            Cmd::Enroll {
                bundle: bundle.ok_or("enroll requires --bundle FILE")?,
            }
        }
        Some("cluster-bootstrap") => {
            it.next();
            let mut root_seed = None;
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} value"))?;
                match k.as_str() {
                    "--root-seed" => root_seed = Some(v),
                    other => return Err(format!("cluster-bootstrap: unknown argument {other:?}")),
                }
            }
            Cmd::ClusterBootstrap {
                root_seed: root_seed.ok_or("cluster-bootstrap requires --root-seed FILE")?,
            }
        }
        Some("cluster-invite") => {
            it.next();
            let (mut root_seed, mut bundle, mut ttl_secs) = (None, None, 7 * 24 * 3600);
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} value"))?;
                match k.as_str() {
                    "--root-seed" => root_seed = Some(v),
                    "--bundle" => bundle = Some(v),
                    "--ttl-secs" => ttl_secs = v.parse().map_err(|e| format!("ttl: {e}"))?,
                    other => return Err(format!("cluster-invite: unknown argument {other:?}")),
                }
            }
            Cmd::ClusterInvite {
                root_seed: root_seed.ok_or("cluster-invite requires --root-seed FILE")?,
                bundle: bundle.ok_or("cluster-invite requires --bundle FILE")?,
                ttl_secs,
            }
        }
        Some("stats") => {
            it.next();
            Cmd::Stats
        }
        Some("invite") => {
            it.next();
            let mut ttl_secs = 7 * 24 * 3600;
            while let Some(k) = it.next() {
                match k.as_str() {
                    "--ttl-secs" => {
                        let v = it.next().ok_or("--ttl-secs value")?;
                        ttl_secs = v.parse().map_err(|e| format!("ttl: {e}"))?;
                    }
                    other => return Err(format!("invite: unknown argument {other:?}")),
                }
            }
            Cmd::Invite { ttl_secs }
        }
        Some("redeem") => {
            it.next();
            let (mut invite_b64, mut username, mut dx, mut de) = (None, None, None, None);
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} value"))?;
                match k.as_str() {
                    "--invite-b64" => invite_b64 = Some(v),
                    "--user" => username = Some(v),
                    "--device-x" => dx = Some(v),
                    "--device-ed" => de = Some(v),
                    other => return Err(format!("redeem: unknown argument {other:?}")),
                }
            }
            Cmd::Redeem {
                invite_b64: invite_b64.ok_or("redeem requires --invite-b64")?,
                username: username.ok_or("redeem requires --user")?,
                device: DevicePubs {
                    x25519: b32(&dx.ok_or("redeem requires --device-x")?)?,
                    ed25519: b32(&de.ok_or("redeem requires --device-ed")?)?,
                    hostname: String::new(),
                },
            }
        }
        Some("device-add") => {
            it.next();
            let (mut username, mut dx, mut de) = (None, None, None);
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} value"))?;
                match k.as_str() {
                    "--user" => username = Some(v),
                    "--device-x" => dx = Some(v),
                    "--device-ed" => de = Some(v),
                    other => return Err(format!("device-add: unknown argument {other:?}")),
                }
            }
            Cmd::DeviceAdd {
                username: username.ok_or("device-add requires --user")?,
                device: DevicePubs {
                    x25519: b32(&dx.ok_or("device-add requires --device-x")?)?,
                    ed25519: b32(&de.ok_or("device-add requires --device-ed")?)?,
                    hostname: String::new(),
                },
            }
        }
        Some("revoke") => {
            it.next();
            let mut device = None;
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} value"))?;
                match k.as_str() {
                    "--device" => device = Some(hex32(&v)?),
                    other => return Err(format!("revoke: unknown argument {other:?}")),
                }
            }
            Cmd::Revoke {
                device: device.ok_or("revoke requires --device")?,
            }
        }
        Some("web-admin-add") => {
            it.next();
            let user = it.next().ok_or("web-admin-add requires <username>")?;
            Cmd::WebAdminAdd { user }
        }
        Some(other) => return Err(format!("unknown subcommand {other:?}\n\n{USAGE}")),
    };
    Ok(Cli { config, cmd })
}

fn b32(b64s: &str) -> Result<[u8; 32], String> {
    use base64::Engine as _;
    let t = b64s.trim();
    let v = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(t))
        .map_err(|e| format!("b64: {e}"))?;
    v.try_into()
        .map_err(|v: Vec<u8>| format!("expected 32B, got {}B", v.len()))
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim()).map_err(|e| format!("hex: {e}"))?;
    v.try_into()
        .map_err(|v: Vec<u8>| format!("expected 64 hex (32B), got {}B", v.len()))
}

/// root.seed (init-cluster product, hex 32B) → the root signing key (the
/// material kept offline on the operations side).
#[cfg_attr(not(feature = "multi-primary"), allow(dead_code))]
fn load_root_seed(path: &str) -> Result<flock_protocol::ed25519_dalek::SigningKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let bytes = hex::decode(text.trim()).map_err(|e| format!("root.seed hex: {e}"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("root.seed expects 64 hex (32B), got {}B", v.len()))?;
    Ok(flock_protocol::ed25519_dalek::SigningKey::from_bytes(&seed))
}

/// `web-admin-add <username>`: M8 Web UI first-admin bootstrap (§7-M8.3).
///
/// Flow: password twice on stdin (the tty echoes —— a local-trust-domain
/// trade-off, same semantics as `flock-client login`) → native OPAQUE
/// registration (reg_start → admin endpoint m1→m2 → reg_finish → WebPwCommit
/// (the token is generated by this process and carried in the message)).
/// Server running ⇒ via the admin endpoint (multi-primary also goes through
/// it —— writes go over Raft); server not running ⇒ single-server can write
/// the state store directly (the fallback precedent of Cmd::Invite);
/// **multi-primary must submit through a running service (Raft), otherwise
/// an explicit error with guidance**.
async fn cmd_web_admin_add(cfg: ServerConfig, user: String) -> Result<(), String> {
    use std::io::BufRead as _;
    // Username constraints identical to the Web API (§M8.4).
    let valid = |u: &str| {
        !u.is_empty()
            && u.len() <= 32
            && u.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
    };
    if !valid(&user) {
        return Err(format!(
            "username {user:?} is invalid (1..=32B, [A-Za-z0-9_.-], same as the Web API)"
        ));
    }
    // Password twice on stdin.
    let mut lines = std::io::stdin().lock().lines();
    let mut read_pw = |prompt: &str| -> Result<String, String> {
        eprint!("{prompt}");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        lines
            .next()
            .transpose()
            .map_err(|e| format!("stdin: {e}"))?
            .ok_or_else(|| "stdin EOF (two password lines required)".to_string())
    };
    let pw = read_pw("Password (the local tty echoes, same trade-off as flock-client login): ")?;
    let pw2 = read_pw("Enter again: ")?;
    if pw.is_empty() {
        return Err("password is empty".into());
    }
    if pw != pw2 {
        return Err("the two passwords do not match".into());
    }
    // First step of native OPAQUE registration (in-process).
    let mut rng = flock_protocol::rand::rngs::OsRng;
    let (cstate, m1_b64) = flock_protocol::pake::reg_start(&mut rng, &pw, &user)
        .map_err(|e| format!("OPAQUE reg_start: {e}"))?;

    // Server running ⇒ admin endpoint (multi-primary writes go over Raft);
    // not running ⇒ single-server direct write.
    let admin_up = tokio::net::TcpStream::connect(cfg.admin_bind).await.is_ok();
    let token: [u8; 16] = flock_protocol::rand::random();
    if admin_up {
        // ① m1 → m2 (a target that already has a password is rejected here).
        let m2_b64 = match client(
            cfg.admin_bind,
            AdminRequest::WebPwBegin {
                user: user.clone(),
                m1_b64,
            },
        )
        .await
        .map_err(|e| format!("admin endpoint ({}): {e}", cfg.admin_bind))?
        {
            AdminResponse::WebPwM2 { m2_b64 } => m2_b64,
            AdminResponse::Err { msg } => return Err(msg),
            other => return Err(format!("unexpected admin response shape: {other:?}")),
        };
        // ② reg_finish → record.
        let record_b64 = flock_protocol::pake::reg_finish(&mut rng, cstate, &pw, &user, &m2_b64)
            .map_err(|e| format!("OPAQUE reg_finish: {e}"))?;
        // ③ Commit (token carried in the message; admin=true —— first-admin
        //    bootstrap).
        match client(
            cfg.admin_bind,
            AdminRequest::WebPwCommit {
                user: user.clone(),
                token,
                record_b64,
                profile: 0,
                admin: true,
            },
        )
        .await?
        {
            AdminResponse::WebPwDone { username } => {
                println!("web admin ready: {username} (admin=true; the Web UI login password is the input above)");
                Ok(())
            }
            AdminResponse::Err { msg } => Err(msg),
            other => Err(format!("unexpected admin response shape: {other:?}")),
        }
    } else {
        // Server not running: multi-primary must go through a running service
        // (Raft) —— explicit error with guidance.
        let raft = cfg.sync.as_ref().is_some_and(|s| s.mode == "raft");
        if raft {
            return Err(
                "web-admin-add in multi-primary ([sync] mode=raft) form must be submitted through a running service (writes go over Raft) - start flock-server first, then run this command"
                    .into(),
            );
        }
        // Single-server direct write (the fallback precedent of Cmd::Invite:
        // probe before opening redb —— if the server is running, the database
        // lock is held).
        let (core, created) = flock_server::server::ServerCore::open_or_init(cfg)?;
        if created {
            eprintln!(
                "note: bootstrapped a new state store (use init-cluster first in production)"
            );
        }
        // Target already has a password ⇒ reject (same semantics as the admin
        // endpoint).
        if core
            .net
            .user_row(&user)
            .await
            .is_some_and(|r| r.opaque_record.is_some())
        {
            return Err(format!(
                "user {user} already has a password - web-admin-add is for first-time setup only; reset existing passwords via the Web UI (admin /api/users/{user}/reset-password)"
            ));
        }
        // The OPAQUE m2 is generated by this process's OPRF (same store, same
        // key) —— the direct-write path has the same registration semantics
        // as the server.
        let m2_b64 = flock_protocol::pake::server_reg_start(&core.oprf, &m1_b64, &user)
            .map_err(|e| format!("OPAQUE server_reg_start: {e}"))?;
        let record_b64 = flock_protocol::pake::reg_finish(&mut rng, cstate, &pw, &user, &m2_b64)
            .map_err(|e| format!("OPAQUE reg_finish: {e}"))?;
        flock_server::admin::web_pw_commit(&core, &user, token, &record_b64, 0, true).await?;
        println!("web admin ready: {user} (admin=true; single-server direct write; the Web UI login password is the input above)");
        Ok(())
    }
}

fn run_cli() -> Result<(), String> {
    let cli = parse_args()?;
    let cfg = ServerConfig::load(&cli.config)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async move {
        match cli.cmd {
            Cmd::InitCluster {
                voters,
                out,
                endpoints,
            } => {
                if let (Some(n), Some(out)) = (voters, out) {
                    // Multi-primary cluster material (§4-1): root key +
                    // per-voter enrollment credentials + root-signed
                    // directory. endpoints = each voter's client-visible
                    // access endpoint (§6.2: a Direct dial address or an Frp
                    // relay user port) —— directory entries and enrollment
                    // credentials signed by the same root.
                    let eps: Vec<String> = match &endpoints {
                        Some(s) => s.split(',').map(|e| e.trim().to_string()).collect(),
                        None => (0..n).map(|i| format!("node-{i}:9443")).collect(),
                    };
                    let m = flock_server::bundle::ClusterMaterial::generate(n, None, |i| {
                        eps[i].clone()
                    });
                    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
                    // Root key seed: exactly one copy (kept offline by ops;
                    // bundles contain only root_pub —— the §4-3 red line).
                    // Written 0600 (review item 1: secret files are tightened
                    // at creation, no "write then tighten" window).
                    flock_server::write_private_file(
                        &std::path::Path::new(&out).join("root.seed"),
                        hex::encode(m.root.to_bytes()).as_bytes(),
                    )
                    .map_err(|e| e.to_string())?;
                    for i in 0..n {
                        let path = std::path::Path::new(&out).join(format!("node-{i}.bundle"));
                        // Bundles contain the node identity/hybrid seeds ⇒
                        // also persisted as 0600 secret files.
                        flock_server::write_private_file(&path, &m.bundle(i).to_bytes())
                            .map_err(|e| format!("{}: {e}", path.display()))?;
                    }
                    println!("cluster_id={}", hex::encode(m.cluster_id.0));
                    println!("voters={n}");
                    println!("endpoints={}", eps.join(","));
                    println!("out={out} (keep root.seed secret; distribute node-*.bundle to each node + enroll)");
                    return Ok(());
                }
                let (core, created) = flock_server::server::ServerCore::open_or_init(cfg)?;
                if !created {
                    return Err("state store already initialized (init-cluster is first-time only)".into());
                }
                println!("cluster_id={}", hex::encode(core.identity.cluster_id.0));
                println!("server_id={}", hex::encode(core.identity.server_id.0));
                Ok(())
            }
            Cmd::Enroll { bundle } => {
                let bytes = std::fs::read(&bundle).map_err(|e| format!("read {bundle}: {e}"))?;
                let b = flock_server::bundle::NodeBundle::from_bytes(&bytes)
                    .ok_or("bundle file failed to decode")?;
                let cid = b.verify()?;
                let ident = b.identity()?;
                let dst = cfg.state_dir.join("bundle.bin");
                // The bundle contains the node identity/hybrid seeds ⇒
                // persisted 0600 (review item 1).
                flock_server::write_private_file(&dst, &bytes).map_err(|e| e.to_string())?;
                println!("cluster_id={}", hex::encode(cid.0));
                println!("server_id={}", hex::encode(ident.server_id.0));
                println!("bundle={}", dst.display());
                // Note: the inter-process fabric of the raft form (TCP/relay
                // Fabric) arrives with the §6/§7-M5 deployment batches; the
                // in-process assembly path is in tests/multi_primary.rs.
                Ok(())
            }
            Cmd::ClusterBootstrap { root_seed } => {
                // Multi-primary ops (§4-1/§4-3): root-key side submits
                // Bootstrap (ticket root) + SetOprf (shared OPRF). Signing
                // happens in this process (the operations entry point of the
                // offline root.seed-keeping semantics); submission goes
                // through the local admin endpoint (SignedWrite pass-through;
                // idempotent and re-runnable —— the state machine allows
                // same-value replays).
                #[cfg(not(feature = "multi-primary"))]
                {
                    let _ = root_seed;
                    Err("cluster-bootstrap requires a multi-primary build".into())
                }
                #[cfg(feature = "multi-primary")]
                {
                    let root = load_root_seed(&root_seed)?;
                    // Ticket key root: 32B random (shared network-wide after
                    // submission; Bootstrap is idempotent ⇒ re-running does
                    // not change the root).
                    let ticket_root: [u8; 32] = flock_protocol::rand::random();
                    // cluster_id of this node's ServerIdentity (bundle.bin;
                    // the bundle and the root key share provenance).
                    let cfg2 = cfg.clone();
                    let bundle_path = cfg2
                        .sync
                        .as_ref()
                        .and_then(|s| s.bundle.clone())
                        .unwrap_or_else(|| cfg2.state_dir.join("bundle.bin"));
                    let bytes = std::fs::read(&bundle_path)
                        .map_err(|e| format!("read {}: {e}", bundle_path.display()))?;
                    let bundle = flock_server::bundle::NodeBundle::from_bytes(&bytes)
                        .ok_or("bundle file failed to decode")?;
                    let cluster_id = bundle.verify()?;
                    let dir = bundle.directory()?;
                    let boot = flock_sync::proto::SyncRequest::bootstrap_signed(
                        &root,
                        cluster_id.0,
                        ticket_root,
                    );
                    // OPRF key (generated in this process): **sealed and
                    // submitted per server** (review item 2: design §2.4
                    // "encrypt-sealed to each server's hybrid public key" ——
                    // no more plaintext SetOprf into Raft state).
                    // ① ServerKeys (root-signed): register every on-record
                    //    server's hybrid public key (the precondition for
                    //    rewrap).
                    // ② AdminOp::Rewrap (root-signed): seal one copy per
                    //    server with envelope v2 —— the state machine stores
                    //    only wraps; each server unseals with its own hybrid
                    //    sk at startup.
                    let oprf_b64 = flock_protocol::pake::server_setup_new(
                        &mut flock_protocol::rand::rngs::OsRng,
                    );
                    let entries: Result<Vec<flock_sync::proto::ServerKeyEntry>, String> = dir
                        .servers
                        .iter()
                        .map(|e| {
                            let node_id = flock_sync::node::node_id_of(&e.server_id);
                            Ok(flock_sync::proto::ServerKeyEntry {
                                server_id: node_id,
                                identity_pub: *e.identity_pub.as_bytes(),
                                hybrid_pub: e.static_hybrid_pub.to_bytes().to_vec(),
                                // M7: deterministic derivation of the server
                                // mesh VIP (§6.2 server segment .1–.10; the
                                // roster Server-entry data source).
                                vip: flock_sync::proto::server_vip_of(node_id)
                                    .ok_or("server node number outside the reserved VIP segment (1..=10)")?,
                            })
                        })
                        .collect();
                    let entries = entries?;
                    let n_servers = entries.len();
                    let server_keys =
                        flock_sync::proto::SyncRequest::server_keys_signed(&root, entries);
                    let rewrap_reqs: Result<Vec<flock_sync::proto::SyncRequest>, String> = dir
                        .servers
                        .iter()
                        .map(|e| {
                            let node_id = flock_sync::node::node_id_of(&e.server_id);
                            flock_server::server::seal_oprf_wrap(&oprf_b64, &e.static_hybrid_pub)
                                .map(|wrapped| {
                                    flock_sync::proto::SyncRequest::rewrap_signed(
                                        &root, node_id, wrapped,
                                    )
                                })
                                .map_err(|err| format!("seal OPRF wrap (node {node_id}): {err}"))
                        })
                        .collect();
                    let rewrap_reqs = rewrap_reqs?;
                    let mut reqs = Vec::with_capacity(2 + n_servers);
                    reqs.push(boot);
                    reqs.push(server_keys);
                    reqs.extend(rewrap_reqs);
                    for req in reqs {
                        // Prefer admin (once ready); when not ready (Bootstrap
                        // not yet applied ⇒ admin not started) fall back to
                        // the cluster bootstrap endpoint (admin port + 1, the
                        // §6.2 layout order).
                        let resp = match client(
                            cfg.admin_bind,
                            AdminRequest::SignedWrite { req: req.clone() },
                        )
                        .await
                        {
                            Ok(r) => r,
                            Err(_) => {
                                let mut boot_bind = cfg.admin_bind;
                                boot_bind.set_port(cfg.admin_bind.port() + 1);
                                client(boot_bind, AdminRequest::SignedWrite { req }).await?
                            }
                        };
                        match resp {
                            AdminResponse::WriteReceipt { text } => {
                                // AlreadyBootstrapped = idempotent re-run
                                // (previously submitted) —— not an error.
                                if text.contains("AlreadyBootstrapped") {
                                    println!("{text} (idempotent: already bootstrapped)");
                                } else {
                                    println!("{text}");
                                }
                            }
                            AdminResponse::Err { msg } => {
                                if msg.contains("AlreadyBootstrapped") {
                                    println!("{msg} (idempotent: already bootstrapped)");
                                } else {
                                    return Err(format!("cluster-bootstrap submission rejected: {msg}"));
                                }
                            }
                            _ => return Err("unexpected admin response shape".into()),
                        }
                    }
                    println!(
                        "cluster-bootstrap ok (ticket_root + ServerKeys + per-server OPRF \
                         sealing for {n_servers} servers submitted; the state machine stores only \
                         wraps; idempotent and re-runnable)"
                    );
                    Ok(())
                }
            }
            Cmd::ClusterInvite {
                root_seed,
                bundle,
                ttl_secs,
            } => {
                // Multi-primary ops: an invite = a root-key-signed v3 file
                // (servers hold no root key ⇒ the multi-primary form rejects
                // `invite`; this command does "RecordInvite + issuance" on
                // the operations side).
                #[cfg(not(feature = "multi-primary"))]
                {
                    let _ = (root_seed, bundle, ttl_secs);
                    Err("cluster-invite requires a multi-primary build".into())
                }
                #[cfg(feature = "multi-primary")]
                {
                    let root = load_root_seed(&root_seed)?;
                    let bytes = std::fs::read(&bundle).map_err(|e| format!("read {bundle}: {e}"))?;
                    let b = flock_server::bundle::NodeBundle::from_bytes(&bytes)
                        .ok_or("bundle file failed to decode")?;
                    let cluster_id = b.verify()?;
                    let dir = b.directory()?;
                    let invite_id: [u8; 16] = flock_protocol::rand::random();
                    let expiry = flock_protocol::trust::now_unix() + ttl_secs;
                    let record = flock_sync::proto::SyncRequest::RecordInvite {
                        invite_id,
                        expiry_unix: expiry,
                    };
                    // Prefer admin; when not ready fall back to the cluster
                    // bootstrap endpoint (same as cluster-bootstrap).
                    let resp =
                        match client(cfg.admin_bind, AdminRequest::SignedWrite { req: record })
                            .await
                        {
                            Ok(r) => r,
                            Err(_) => {
                                let mut boot_bind = cfg.admin_bind;
                                boot_bind.set_port(cfg.admin_bind.port() + 1);
                                client(
                                    boot_bind,
                                    AdminRequest::SignedWrite {
                                        req: flock_sync::proto::SyncRequest::RecordInvite {
                                            invite_id,
                                            expiry_unix: expiry,
                                        },
                                    },
                                )
                                .await?
                            }
                        };
                    match resp {
                        AdminResponse::WriteReceipt { text } => println!("{text}"),
                        AdminResponse::Err { msg } => {
                            return Err(format!("RecordInvite rejected: {msg}"));
                        }
                        _ => return Err("unexpected admin response shape".into()),
                    }
                    let inv = flock_protocol::trust::InviteFile::issue(
                        &root,
                        cluster_id,
                        dir.dir_version,
                        dir.servers.clone(),
                        expiry,
                        invite_id,
                    );
                    use base64::Engine as _;
                    println!(
                        "{}",
                        base64::engine::general_purpose::STANDARD_NO_PAD.encode(inv.to_bytes())
                    );
                    Ok(())
                }
            }
            Cmd::Stats => match client(cfg.admin_bind, AdminRequest::Stats).await? {
                AdminResponse::StatsText { lines } => {
                    for l in lines {
                        println!("{l}");
                    }
                    Ok(())
                }
                AdminResponse::Err { msg } => Err(msg),
                _ => Err("unexpected admin response shape".into()),
            },
            Cmd::Invite { ttl_secs } => {
                // Server running ⇒ probe admin first (the single writer) ——
                // the probe must precede any redb open: a running service
                // holds the database lock, and an open_or_init first would
                // fail with "Database already open".
                if tokio::net::TcpStream::connect(cfg.admin_bind).await.is_ok() {
                    match client(cfg.admin_bind, AdminRequest::Invite { ttl_secs }).await? {
                        AdminResponse::Invite { invite_b64 } => {
                            println!("{invite_b64}");
                            Ok(())
                        }
                        AdminResponse::Err { msg } => Err(msg),
                        _ => Err("unexpected admin response shape".into()),
                    }
                } else {
                    // Server not running: this process writes directly (a
                    // fresh state store is bootstrapped when uninitialized ——
                    // the fallback path for a first issuance).
                    let (core, created) =
                        flock_server::server::ServerCore::open_or_init(cfg.clone())?;
                    if created {
                        eprintln!("note: bootstrapped a new state store (prefer init-cluster)");
                    }
                    let bytes = core.mint_invite(ttl_secs).await?;
                    use base64::Engine as _;
                    println!(
                        "{}",
                        base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
                    );
                    Ok(())
                }
            }
            Cmd::Redeem {
                invite_b64,
                username,
                device,
            } => {
                let resp = client(
                    cfg.admin_bind,
                    AdminRequest::Redeem {
                        invite_b64,
                        username,
                        device,
                    },
                )
                .await?;
                match resp {
                    AdminResponse::Redeemed { device_id, vip } => {
                        println!("device_id={}", hex::encode(device_id));
                        println!("vip={}.{}.{}.{}", vip[0], vip[1], vip[2], vip[3]);
                        Ok(())
                    }
                    AdminResponse::Err { msg } => Err(msg),
                    _ => Err("unexpected admin response shape".into()),
                }
            }
            Cmd::DeviceAdd { username, device } => {
                let resp =
                    client(cfg.admin_bind, AdminRequest::DeviceAdd { username, device }).await?;
                match resp {
                    AdminResponse::DeviceAdded { device_id, vip } => {
                        println!("device_id={}", hex::encode(device_id));
                        println!("vip={}.{}.{}.{}", vip[0], vip[1], vip[2], vip[3]);
                        Ok(())
                    }
                    AdminResponse::Err { msg } => Err(msg),
                    _ => Err("unexpected admin response shape".into()),
                }
            }
            Cmd::Revoke { device } => {
                let resp = client(cfg.admin_bind, AdminRequest::Revoke { device }).await?;
                match resp {
                    AdminResponse::Revoked { epoch } => {
                        println!("epoch={epoch}");
                        Ok(())
                    }
                    AdminResponse::Err { msg } => Err(msg),
                    _ => Err("unexpected admin response shape".into()),
                }
            }
            Cmd::WebAdminAdd { user } => cmd_web_admin_add(cfg, user).await,
            Cmd::Run => {
                let mode = cfg.listener_mode()?;
                // Multi-primary form (§6.2 M5 batch): TCP fabric + SyncNode +
                // the server's own peer surface; the single-server path
                // (default) unchanged.
                #[cfg(feature = "multi-primary")]
                if let Some(sync) = &cfg.sync {
                    if sync.mode == "raft" {
                        let (running, task, _admin) =
                            flock_server::sync::run_raft(cfg, mode).await?;
                        eprintln!(
                            "flock-server: listening on {} (mode: {}, sync: raft)",
                            running.local_addr(),
                            match running {
                                flock_server::server::RunningListener::Direct { .. } => "direct",
                                flock_server::server::RunningListener::Frp { .. } => "frp",
                            }
                        );
                        return match task.await {
                            Ok(Ok(())) => Ok(()),
                            Ok(Err(e)) => Err(e.to_string()),
                            Err(e) => Err(e.to_string()),
                        };
                    }
                }
                #[cfg(not(feature = "multi-primary"))]
                if let Some(sync) = &cfg.sync {
                    if sync.mode == "raft" {
                        return Err(
                            "server.toml [sync] mode = \"raft\" requires a multi-primary build\n\
                             (image build with --features multi-primary; single-server deployments use the default [sync] single)"
                                .into(),
                        );
                    }
                }
                let (core, created) = flock_server::server::ServerCore::open_or_init(cfg)?;
                if created {
                    eprintln!("note: state store not initialized at startup - bootstrapped (use init-cluster first in production)");
                }
                let (running, task, _admin) = flock_server::server::run(core, mode).await?;
                eprintln!(
                    "flock-server: listening on {} (mode: {})",
                    running.local_addr(),
                    match running {
                        flock_server::server::RunningListener::Direct { .. } => "direct",
                        flock_server::server::RunningListener::Frp { .. } => "frp",
                    }
                );
                match task.await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
        }
    })
}
