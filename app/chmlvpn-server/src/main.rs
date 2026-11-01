//! chmlvpn-server 进程入口（docs/design.md §3.11：`--config server.toml` / `init-cluster`
//! / 运维子命令）。
//!
//! 子命令：
//! - （缺省 `run`）：起服——按 `listener.mode` 装配（Direct 缺省 / Frp 中转托管）；
//! - `init-cluster`：引导状态库（集群根/身份/静态混合/OPRF/票据根种子；已初始化则报错）；
//! - `invite [--ttl-secs N]`：签发邀请（admin 端点 → v3 邀请文件 b64 到 stdout）；
//! - `redeem --user U --invite-b64 B --device-x B --device-ed B`：兑换邀请开户（admin 端点）；
//! - `device-add --user U --device-x B --device-ed B`：直接注册设备（TOFU 预置；admin 端点）；
//! - `revoke --device HEX32B`：吊销设备（admin 端点）。
//!
//! `enroll`（多服入群）为 M4 范围（§4 准入流水），本里程碑不提供——如实声明。

use std::path::PathBuf;

use chmlvpn_server::admin::{client, AdminRequest, AdminResponse};
use chmlvpn_server::config::ServerConfig;
use chmlvpn_server::control::DevicePubs;

const USAGE: &str = "\
chmlvpn-server [--config <server.toml>] [<subcommand>]

子命令：
  (run)                          起服（缺省；listener.mode = direct 缺省 / frp；
                                 [sync] mode=raft 时走多主装配——TCP 织物 + SyncNode）
  init-cluster [--voters N --out DIR [--endpoints e1,e2,…]]
                                 单服：引导状态库；--voters：生成多主集群材料
                                 （根密钥 root.seed + 各 voter 入群捆绑 node-i.bundle；
                                 endpoints = 各 voter 的客户端可见接入端点，§6.2）
  enroll --bundle FILE           装载并验证节点捆绑（根签目录+入群凭证），落状态目录
  cluster-bootstrap --root-seed FILE
                                 多主运维：根密钥签 Bootstrap（票据根）+ SetOprf（共享
                                 OPRF），经本机 admin 端点提交（幂等可重跑）
  cluster-invite --root-seed FILE --bundle FILE [--ttl-secs N]
                                 多主运维：以根密钥签 v3 邀请（目录取自捆绑）→ stdout b64
  stats                          运行状态快照（epoch/leader/转发计数/在线会话）
  invite [--ttl-secs N]          签发邀请 → stdout 单行 b64（单服形态）
  redeem --user U --invite-b64 B --device-x B32 --device-ed B32
                                 兑换邀请开户（建用户/设备 + 分 VIP）
  device-add --user U --device-x B32 --device-ed B32
                                 直接注册设备（TOFU 预置）
  revoke --device HEX64          吊销设备（推进 revocation_epoch + 杀会话）
";

fn main() {
    let code = match run_cli() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("chmlvpn-server: {e}");
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
}

fn parse_args() -> Result<Cli, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut config = PathBuf::from("server.toml");
    // 全局旗标先行剥离；其余按位置参数/子命令旗标解析。
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--config" => {
                i += 1;
                config = PathBuf::from(raw.get(i).ok_or("--config 值")?.clone());
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
                let v = it.next().ok_or(format!("{k} 值"))?;
                match k.as_str() {
                    "--voters" => {
                        voters = Some(v.parse().map_err(|e| format!("voters: {e}"))?);
                    }
                    "--out" => out = Some(v),
                    "--endpoints" => endpoints = Some(v),
                    other => return Err(format!("init-cluster: 未知参数 {other:?}")),
                }
            }
            if voters.is_some() && out.is_none() {
                return Err("init-cluster --voters 需要 --out DIR".into());
            }
            if let Some(n) = voters {
                let eps = endpoints.as_deref().map(|s| s.split(',').count()).unwrap_or(0);
                if eps != n {
                    return Err(format!(
                        "init-cluster --endpoints 需与 --voters 同数（{eps} != {n}；逗号分隔，按 voter 序）"
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
                let v = it.next().ok_or(format!("{k} 值"))?;
                match k.as_str() {
                    "--bundle" => bundle = Some(v),
                    other => return Err(format!("enroll: 未知参数 {other:?}")),
                }
            }
            Cmd::Enroll {
                bundle: bundle.ok_or("enroll 需要 --bundle FILE")?,
            }
        }
        Some("cluster-bootstrap") => {
            it.next();
            let mut root_seed = None;
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} 值"))?;
                match k.as_str() {
                    "--root-seed" => root_seed = Some(v),
                    other => return Err(format!("cluster-bootstrap: 未知参数 {other:?}")),
                }
            }
            Cmd::ClusterBootstrap {
                root_seed: root_seed.ok_or("cluster-bootstrap 需要 --root-seed FILE")?,
            }
        }
        Some("cluster-invite") => {
            it.next();
            let (mut root_seed, mut bundle, mut ttl_secs) = (None, None, 7 * 24 * 3600);
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} 值"))?;
                match k.as_str() {
                    "--root-seed" => root_seed = Some(v),
                    "--bundle" => bundle = Some(v),
                    "--ttl-secs" => {
                        ttl_secs = v.parse().map_err(|e| format!("ttl: {e}"))?
                    }
                    other => return Err(format!("cluster-invite: 未知参数 {other:?}")),
                }
            }
            Cmd::ClusterInvite {
                root_seed: root_seed.ok_or("cluster-invite 需要 --root-seed FILE")?,
                bundle: bundle.ok_or("cluster-invite 需要 --bundle FILE")?,
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
                        let v = it.next().ok_or("--ttl-secs 值")?;
                        ttl_secs = v.parse().map_err(|e| format!("ttl: {e}"))?;
                    }
                    other => return Err(format!("invite: 未知参数 {other:?}")),
                }
            }
            Cmd::Invite { ttl_secs }
        }
        Some("redeem") => {
            it.next();
            let (mut invite_b64, mut username, mut dx, mut de) = (None, None, None, None);
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} 值"))?;
                match k.as_str() {
                    "--invite-b64" => invite_b64 = Some(v),
                    "--user" => username = Some(v),
                    "--device-x" => dx = Some(v),
                    "--device-ed" => de = Some(v),
                    other => return Err(format!("redeem: 未知参数 {other:?}")),
                }
            }
            Cmd::Redeem {
                invite_b64: invite_b64.ok_or("redeem 需要 --invite-b64")?,
                username: username.ok_or("redeem 需要 --user")?,
                device: DevicePubs {
                    x25519: b32(&dx.ok_or("redeem 需要 --device-x")?)?,
                    ed25519: b32(&de.ok_or("redeem 需要 --device-ed")?)?,
                },
            }
        }
        Some("device-add") => {
            it.next();
            let (mut username, mut dx, mut de) = (None, None, None);
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} 值"))?;
                match k.as_str() {
                    "--user" => username = Some(v),
                    "--device-x" => dx = Some(v),
                    "--device-ed" => de = Some(v),
                    other => return Err(format!("device-add: 未知参数 {other:?}")),
                }
            }
            Cmd::DeviceAdd {
                username: username.ok_or("device-add 需要 --user")?,
                device: DevicePubs {
                    x25519: b32(&dx.ok_or("device-add 需要 --device-x")?)?,
                    ed25519: b32(&de.ok_or("device-add 需要 --device-ed")?)?,
                },
            }
        }
        Some("revoke") => {
            it.next();
            let mut device = None;
            while let Some(k) = it.next() {
                let v = it.next().ok_or(format!("{k} 值"))?;
                match k.as_str() {
                    "--device" => device = Some(hex32(&v)?),
                    other => return Err(format!("revoke: 未知参数 {other:?}")),
                }
            }
            Cmd::Revoke {
                device: device.ok_or("revoke 需要 --device")?,
            }
        }
        Some(other) => return Err(format!("未知子命令 {other:?}\n\n{USAGE}")),
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
        .map_err(|v: Vec<u8>| format!("期望 32B，得 {}B", v.len()))
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim()).map_err(|e| format!("hex: {e}"))?;
    v.try_into()
        .map_err(|v: Vec<u8>| format!("期望 64 hex（32B），得 {}B", v.len()))
}

/// root.seed（init-cluster 产物，hex 32B）→ 根签名钥（运维侧离线保管的物化）。
#[cfg_attr(not(feature = "multi-primary"), allow(dead_code))]
fn load_root_seed(path: &str) -> Result<chml_protocol::ed25519_dalek::SigningKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("读 {path}: {e}"))?;
    let bytes = hex::decode(text.trim()).map_err(|e| format!("root.seed hex: {e}"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("root.seed 期望 64 hex（32B），得 {}B", v.len()))?;
    Ok(chml_protocol::ed25519_dalek::SigningKey::from_bytes(&seed))
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
                    // 多主集群材料（§4-1）：根密钥 + 各 voter 入群凭证 + 根签目录。
                    // endpoints = 各 voter 的客户端可见接入端点（§6.2：Direct 直连地址
                    // 或 Frp 中转用户口）——目录条目与入群凭证同根签名。
                    let eps: Vec<String> = match &endpoints {
                        Some(s) => s.split(',').map(|e| e.trim().to_string()).collect(),
                        None => (0..n).map(|i| format!("node-{i}:9443")).collect(),
                    };
                    let m = chmlvpn_server::bundle::ClusterMaterial::generate(n, None, |i| {
                        eps[i].clone()
                    });
                    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
                    // 根密钥种子：仅此一份（运维离线保管；bundle 只含 root_pub——§4-3 红线）。
                    std::fs::write(
                        std::path::Path::new(&out).join("root.seed"),
                        hex::encode(m.root.to_bytes()),
                    )
                    .map_err(|e| e.to_string())?;
                    for i in 0..n {
                        let path = std::path::Path::new(&out).join(format!("node-{i}.bundle"));
                        std::fs::write(&path, m.bundle(i).to_bytes())
                            .map_err(|e| format!("{}: {e}", path.display()))?;
                    }
                    println!("cluster_id={}", hex::encode(m.cluster_id.0));
                    println!("voters={n}");
                    println!(
                        "endpoints={}",
                        eps.join(",")
                    );
                    println!("out={out}（root.seed 保密；node-*.bundle 分发各机 + enroll）");
                    return Ok(());
                }
                let (core, created) = chmlvpn_server::server::ServerCore::open_or_init(cfg)?;
                if !created {
                    return Err("状态库已初始化（init-cluster 仅首次）".into());
                }
                println!("cluster_id={}", hex::encode(core.identity.cluster_id.0));
                println!("server_id={}", hex::encode(core.identity.server_id.0));
                Ok(())
            }
            Cmd::Enroll { bundle } => {
                let bytes = std::fs::read(&bundle).map_err(|e| format!("read {bundle}: {e}"))?;
                let b = chmlvpn_server::bundle::NodeBundle::from_bytes(&bytes)
                    .ok_or("捆绑文件解码失败")?;
                let cid = b.verify()?;
                let ident = b.identity()?;
                let dst = cfg.state_dir.join("bundle.bin");
                std::fs::create_dir_all(&cfg.state_dir).map_err(|e| e.to_string())?;
                std::fs::write(&dst, &bytes).map_err(|e| e.to_string())?;
                println!("cluster_id={}", hex::encode(cid.0));
                println!("server_id={}", hex::encode(ident.server_id.0));
                println!("bundle={}", dst.display());
                // 注：raft 形态的进程间织物（TCP/中转 Fabric）随 §6/§7-M5 部署批次接入；
                // 进程内装配路径见 tests/multi_primary.rs。
                Ok(())
            }
            Cmd::ClusterBootstrap { root_seed } => {
                // 多主运维（§4-1/§4-3）：根密钥侧提交 Bootstrap（票据根）+ SetOprf（共享
                // OPRF）。签名在本进程内做（root.seed 离线保管语义的运维入口），提交经
                // 本机 admin 端点（SignedWrite 透传；幂等可重跑——状态机同值重放放行）。
                #[cfg(not(feature = "multi-primary"))]
                {
                    let _ = root_seed;
                    return Err("cluster-bootstrap 需要 multi-primary 构建档".into());
                }
                #[cfg(feature = "multi-primary")]
                {
                    use chml_protocol::ed25519_dalek::{Signature, Signer, Verifier};
                    let root = load_root_seed(&root_seed)?;
                    // 票据密钥根：32B 随机（提交后全网共享；Bootstrap 幂等 ⇒ 重跑不换根）。
                    let ticket_root: [u8; 32] = chml_protocol::rand::random();
                    // 本机 ServerIdentity 的 cluster_id（bundle.bin；捆绑与根密钥同源）。
                    let cfg2 = cfg.clone();
                    let bundle_path = cfg2
                        .sync
                        .as_ref()
                        .and_then(|s| s.bundle.clone())
                        .unwrap_or_else(|| cfg2.state_dir.join("bundle.bin"));
                    let bytes = std::fs::read(&bundle_path)
                        .map_err(|e| format!("读 {}: {e}", bundle_path.display()))?;
                    let bundle = chmlvpn_server::bundle::NodeBundle::from_bytes(&bytes)
                        .ok_or("捆绑文件解码失败")?;
                    let cluster_id = bundle.verify()?;
                    let boot = chml_sync::proto::SyncRequest::bootstrap_signed(
                        &root,
                        cluster_id.0,
                        ticket_root,
                    );
                    // SetOprf：共享 OPRF key（本进程生成；根签后全网可验——§2.4）。
                    let oprf_b64 = chml_protocol::pake::server_setup_new(&mut chml_protocol::rand::rngs::OsRng);
                    let l_oprf: &[u8] = b"chml-sync/set-oprf/v1";
                    let mut canon = Vec::with_capacity(l_oprf.len() + 4 + oprf_b64.len());
                    canon.extend_from_slice(l_oprf);
                    canon.extend_from_slice(&(oprf_b64.len() as u32).to_le_bytes());
                    canon.extend_from_slice(oprf_b64.as_bytes());
                    let set_oprf = chml_sync::proto::SyncRequest::SetOprf(chml_sync::proto::RootSigned {
                        op: oprf_b64,
                        sig: root.sign(&canon).to_bytes(),
                    });
                    // 自验（root_pub 对 canonical 验签——防端点错配直接提交废签名）。
                    let root_pub = root.verifying_key();
                    if let chml_sync::proto::SyncRequest::SetOprf(rs) = &set_oprf {
                        debug_assert!(root_pub.verify(&canon, &Signature::from_bytes(&rs.sig)).is_ok());
                    }
                    for req in [boot, set_oprf] {
                        // admin（就绪后）优先；未就绪（Bootstrap 尚未 apply ⇒ admin 未起）
                        // 回退到集群引导端点（admin 端口 +1，§6.2 编排序）。
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
                                // AlreadyBootstrapped = 幂等重跑（此前已提交过）——非错误。
                                if text.contains("AlreadyBootstrapped") {
                                    println!("{text}（幂等：此前已引导）");
                                } else {
                                    println!("{text}");
                                }
                            }
                            AdminResponse::Err { msg } => {
                                if msg.contains("AlreadyBootstrapped") {
                                    println!("{msg}（幂等：此前已引导）");
                                } else {
                                    return Err(format!("cluster-bootstrap 提交被拒: {msg}"));
                                }
                            }
                            _ => return Err("admin 响应形态不符".into()),
                        }
                    }
                    println!("cluster-bootstrap ok（ticket_root+oprf 已提交；幂等可重跑）");
                    Ok(())
                }
            }
            Cmd::ClusterInvite {
                root_seed,
                bundle,
                ttl_secs,
            } => {
                // 多主运维：邀请 = 根密钥签 v3 文件（服务器不持根密钥 ⇒ 多主形态
                // `invite` 拒；本命令在运维侧完成「RecordInvite + 签发」）。
                #[cfg(not(feature = "multi-primary"))]
                {
                    let _ = (root_seed, bundle, ttl_secs);
                    return Err("cluster-invite 需要 multi-primary 构建档".into());
                }
                #[cfg(feature = "multi-primary")]
                {
                    let root = load_root_seed(&root_seed)?;
                    let bytes =
                        std::fs::read(&bundle).map_err(|e| format!("读 {bundle}: {e}"))?;
                    let b = chmlvpn_server::bundle::NodeBundle::from_bytes(&bytes)
                        .ok_or("捆绑文件解码失败")?;
                    let cluster_id = b.verify()?;
                    let dir = b.directory()?;
                    let invite_id: [u8; 16] = chml_protocol::rand::random();
                    let expiry = chml_protocol::trust::now_unix() + ttl_secs;
                    let record = chml_sync::proto::SyncRequest::RecordInvite {
                        invite_id,
                        expiry_unix: expiry,
                    };
                    // admin 优先；未就绪回退集群引导端点（同 cluster-bootstrap）。
                    let resp = match client(cfg.admin_bind, AdminRequest::SignedWrite { req: record }).await {
                        Ok(r) => r,
                        Err(_) => {
                            let mut boot_bind = cfg.admin_bind;
                            boot_bind.set_port(cfg.admin_bind.port() + 1);
                            client(boot_bind, AdminRequest::SignedWrite { req: chml_sync::proto::SyncRequest::RecordInvite { invite_id, expiry_unix: expiry } }).await?
                        }
                    };
                    match resp {
                        AdminResponse::WriteReceipt { text } => println!("{text}"),
                        AdminResponse::Err { msg } => {
                            return Err(format!("RecordInvite 被拒: {msg}"));
                        }
                        _ => return Err("admin 响应形态不符".into()),
                    }
                    let inv = chml_protocol::trust::InviteFile::issue(
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
                _ => Err("admin 响应形态不符".into()),
            },
            Cmd::Invite { ttl_secs } => {
                // 服务在跑 ⇒ 先探 admin（单写者）——探测必须先于任何 redb 打开：
                // 运行中的服务持库锁，先 open_or_init 会以「Database already open」失败。
                if tokio::net::TcpStream::connect(cfg.admin_bind).await.is_ok() {
                    match client(cfg.admin_bind, AdminRequest::Invite { ttl_secs }).await? {
                        AdminResponse::Invite { invite_b64 } => {
                            println!("{invite_b64}");
                            Ok(())
                        }
                        AdminResponse::Err { msg } => Err(msg),
                        _ => Err("admin 响应形态不符".into()),
                    }
                } else {
                    // 服务未跑：本进程直写（状态库未初始化时先引导——首次签发的兜底路径）。
                    let (core, created) =
                        chmlvpn_server::server::ServerCore::open_or_init(cfg.clone())?;
                    if created {
                        eprintln!("note: 已引导新状态库（建议改用 init-cluster）");
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
                    _ => Err("admin 响应形态不符".into()),
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
                    _ => Err("admin 响应形态不符".into()),
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
                    _ => Err("admin 响应形态不符".into()),
                }
            }
            Cmd::Run => {
                let mode = cfg.listener_mode()?;
                // 多主形态（§6.2 M5 批次）：TCP 织物 + SyncNode + 服务器自身 peer 面；
                // 单服路径（缺省）不变。
                #[cfg(feature = "multi-primary")]
                if let Some(sync) = &cfg.sync {
                    if sync.mode == "raft" {
                        let (running, task, _admin) =
                            chmlvpn_server::sync::run_raft(cfg, mode).await?;
                        eprintln!(
                            "chmlvpn-server: listening on {} (mode: {}, sync: raft)",
                            running.local_addr(),
                            match running {
                                chmlvpn_server::server::RunningListener::Direct { .. } => "direct",
                                chmlvpn_server::server::RunningListener::Frp { .. } => "frp",
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
                            "server.toml [sync] mode = \"raft\" 需要 multi-primary 构建档\n\
                             （镜像构建 --features multi-primary；单服部署用缺省 [sync] single）"
                                .into(),
                        );
                    }
                }
                let (core, created) = chmlvpn_server::server::ServerCore::open_or_init(cfg)?;
                if created {
                    eprintln!("note: 状态库未初始化即起服——已引导（生产请先 init-cluster）");
                }
                let (running, task, _admin) = chmlvpn_server::server::run(core, mode).await?;
                eprintln!(
                    "chmlvpn-server: listening on {} (mode: {})",
                    running.local_addr(),
                    match running {
                        chmlvpn_server::server::RunningListener::Direct { .. } => "direct",
                        chmlvpn_server::server::RunningListener::Frp { .. } => "frp",
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
