//! ListenerMode assembly tests (docs/design.md §2.1/§3.11: Direct defaults
//! to zero frp logic; Frp takes the flock-frpc Supervisor's real product
//! path).
//!
//! - `direct_mode_*`: a Direct-mode server start ⇒ the listen handle is
//!   `RunningListener::Direct`; the state directory holds no frp
//!   config/managed drop points (the runtime proof that the Supervisor was
//!   never instantiated —— its only side effects are the run directory and
//!   the managed config copy, see flock-frpc supervisor.rs).
//! - `frp_mode_*`: the Frp assembly really takes over (the embedded TOML
//!   persisted + the Supervisor spawn); a missing/non-executable frpc
//!   binary ⇒ startup fails fast (the R9 matrix and spawn validation are
//!   enforced inside flock-frpc).

mod common;

use flock_server::config::{FrpRelayPlan, ListenerMode, ServerConfig};
use flock_server::server::{self, RunningListener, ServerCore};

fn cfg_for(mode: &str, state_dir: &std::path::Path) -> ServerConfig {
    ServerConfig {
        state_dir: state_dir.to_path_buf(),
        bind: "127.0.0.1:0".parse().unwrap(),
        mode: mode.into(),
        advertise_endpoint: "127.0.0.1:9443".into(),
        extra_endpoints: vec![],
        dir_version: 1,
        ticket_ttl_secs: 60,
        peer_retention_days: 30,
        admin_bind: "127.0.0.1:0".parse().unwrap(),
        max_sessions: 1024,
        sync: None,
        webui: flock_server::config::WebUiSection {
            enabled: false,
            ..Default::default()
        },
        tun_name: "tun0".into(),
        vip: "100.64.0.1".parse().unwrap(),
        frp: Some(flock_server::config::FrpSection {
            flavor: "original".into(),
            original_toml: "serverAddr = \"frps\"\nserverPort = 7000\n".into(),
            chmlfrp_ini: None,
            user_token_auto: None,
            frpc_bin: state_dir.join("fake-frpc"),
            run_base: Some(state_dir.join("frpc-run")),
        }),
    }
}

/// Whether any entry inside the directory tree has a name matching the
/// predicate.
fn any_entry(root: &std::path::Path, pred: &dyn Fn(&str) -> bool) -> bool {
    fn walk(p: &std::path::Path, pred: &dyn Fn(&str) -> bool) -> bool {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if pred(&name) {
                    return true;
                }
                if e.path().is_dir() && walk(&e.path(), pred) {
                    return true;
                }
            }
        }
        false
    }
    walk(root, pred)
}

#[tokio::test]
async fn direct_mode_starts_without_any_frp_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg_for("direct", dir.path());
    let (core, created) = ServerCore::open_or_init(cfg.clone()).unwrap();
    assert!(created);
    let (running, task, admin) = server::run(core, cfg.listener_mode().unwrap())
        .await
        .unwrap();
    assert!(
        matches!(running, RunningListener::Direct { .. }),
        "a Direct-mode start ⇒ the Direct variant (no ManagedRelay)"
    );
    // Runtime proof: no frp config generated, no Supervisor run directory
    // (flock-frpc zero-instantiated in this process).
    assert!(
        !any_entry(dir.path(), &|n| n.starts_with("frpc") || n.contains("frp")),
        "the state directory must show no frp drop points"
    );
    assert!(!dir.path().join("frpc-run").exists());
    // The session surface works (a Direct end-to-end smoke).
    let addr = running.local_addr();
    let mut io = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    // Send an I0 (TOFU bootstrap): the Direct listener runs
    // session::respond normally (the handshake will be rejected because the
    // device is not in the directory —— expected behavior; this only proves
    // the byte surface reaches the server and gets processed).
    io.write_all(&[5, 0, 1, 1, 0x01]).await.unwrap();
    let mut buf = [0u8; 16];
    let _ = io.read(&mut buf).await;
    task.abort();
    admin.abort();
}

#[tokio::test]
async fn frp_mode_engages_supervisor_and_fails_fast_without_binary() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg_for("frp", dir.path());
    // Binary placeholder: present but not executable ⇒ the Supervisor spawn
    // fails fast (proving the assembly really takes over).
    std::fs::write(dir.path().join("fake-frpc"), b"not an elf").unwrap();
    let (core, _) = ServerCore::open_or_init(cfg.clone()).unwrap();
    let err = match server::run(core, cfg.listener_mode().unwrap()).await {
        Ok(_) => panic!("a non-executable frpc ⇒ startup must fail"),
        Err(e) => e,
    };
    assert!(
        err.contains("frpc"),
        "the error should come from the frpc supervisor: {err}"
    );
    // The embedded TOML was persisted along the Original registration path
    // (§7-M2 "the server embeds frpc").
    let embedded = dir
        .path()
        .join("frpc-run")
        .join("embedded")
        .join("frpc.toml");
    let text = std::fs::read_to_string(&embedded).expect("embedded frpc.toml");
    assert!(
        text.contains("serverAddr"),
        "the embedded TOML is persisted"
    );
}

/// Review item 14: ChmlFrp assembly wiring —— config parsing → RelaySpec
/// construction.
/// ① `[frp] flavor = "chmlfrp"` + the panel-exported ini path ⇒ the default
///    ChmlFrpMode::ConfigFile;
/// ② An explicit `[frp.user_token_auto]` opt-in ⇒ UserTokenAuto mode (the
///    ini may be omitted);
/// ③ Original compatibility unbroken (default flavor + original_toml).
#[tokio::test]
async fn chmlfrp_config_parses_to_relay_spec() {
    // ① The default ConfigFile mode.
    let cfg: ServerConfig = toml::from_str(
        r#"
        state_dir = "/tmp/s"
        advertise_endpoint = "127.0.0.1:27500"
        mode = "frp"
        [frp]
        flavor = "chmlfrp"
        chmlfrp_ini = "/etc/flock/chmlfrp-panel.ini"
    "#,
    )
    .unwrap();
    let ListenerMode::Frp { plan, .. } = cfg.listener_mode().unwrap() else {
        panic!("frp mode")
    };
    let FrpRelayPlan::ChmlFrp {
        ini,
        user_token_auto,
    } = &plan.relay
    else {
        panic!("chmlfrp relay plan: {:?}", plan.relay)
    };
    assert_eq!(
        ini.as_deref(),
        Some("/etc/flock/chmlfrp-panel.ini".as_ref())
    );
    assert!(user_token_auto.is_none(), "the default ConfigFile mode");
    assert!(
        matches!(
            flock_server::frp::chmlfrp_spec_for_test(ini, user_token_auto),
            flock_frpc::RelaySpec::ChmlFrp {
                mode: flock_frpc::ChmlFrpMode::ConfigFile(_),
            }
        ),
        "RelaySpec::ChmlFrp + ConfigFile"
    );

    // ② An explicit UserTokenAuto opt-in.
    let cfg2: ServerConfig = toml::from_str(
        r#"
        state_dir = "/tmp/s"
        advertise_endpoint = "127.0.0.1:27500"
        mode = "frp"
        [frp]
        flavor = "chmlfrp"
        [frp.user_token_auto]
        usertoken = "tok-1"
        tunnel_id = 42
    "#,
    )
    .unwrap();
    let ListenerMode::Frp { plan, .. } = cfg2.listener_mode().unwrap() else {
        panic!("frp mode 2")
    };
    let FrpRelayPlan::ChmlFrp {
        ini,
        user_token_auto,
    } = &plan.relay
    else {
        panic!("chmlfrp relay plan 2")
    };
    assert!(ini.is_none(), "UserTokenAuto mode may omit the ini");
    let uta = user_token_auto.as_ref().expect("opt-in parsed");
    assert_eq!(uta.usertoken, "tok-1");
    assert_eq!(uta.tunnel_id, 42);
    let spec = flock_server::frp::chmlfrp_spec_for_test(ini, user_token_auto);
    match &spec {
        flock_frpc::RelaySpec::ChmlFrp {
            mode:
                flock_frpc::ChmlFrpMode::UserTokenAuto {
                    usertoken,
                    tunnel_id,
                },
        } => {
            assert_eq!(usertoken, "tok-1");
            assert_eq!(*tunnel_id, 42);
        }
        other => panic!("RelaySpec::ChmlFrp + UserTokenAuto: {other:?}"),
    }

    // ③ Original compatibility unbroken (the default flavor is original).
    let cfg3: ServerConfig = toml::from_str(
        r#"
        state_dir = "/tmp/s"
        advertise_endpoint = "127.0.0.1:27500"
        mode = "frp"
        [frp]
        original_toml = """
serverAddr = "frps"
serverPort = 7000
"""
    "#,
    )
    .unwrap();
    let ListenerMode::Frp { plan, .. } = cfg3.listener_mode().unwrap() else {
        panic!("frp mode 3")
    };
    assert!(
        matches!(
            &plan.relay,
            flock_server::config::FrpRelayPlan::Original { toml } if toml.contains("serverAddr")
        ),
        "Original compatibility unbroken (default flavor)"
    );
    // Validation negative path: chmlfrp with neither an ini nor an opt-in ⇒
    // rejected.
    let cfg4: ServerConfig = toml::from_str(
        r#"
        state_dir = "/tmp/s"
        advertise_endpoint = "127.0.0.1:27500"
        mode = "frp"
        [frp]
        flavor = "chmlfrp"
    "#,
    )
    .unwrap();
    let err = cfg4.listener_mode().unwrap_err();
    assert!(
        err.contains("chmlfrp_ini"),
        "the missing-config error is diagnosable: {err}"
    );
}

/// Review item 7: the concurrent session cap —— with `max_sessions = 1`,
/// the second inbound connection is politely closed right after acceptance
/// (the peer observes FIN) and the over-limit counter increments; the
/// permit-holding first connection is unaffected (the silent connection
/// stays pending).
#[tokio::test]
async fn session_cap_politely_closes_excess_connection() {
    use tokio::io::AsyncReadExt as _;

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = cfg_for("direct", dir.path());
    cfg.max_sessions = 1;
    let (core, _) = ServerCore::open_or_init(cfg).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let task = tokio::spawn(core.clone().serve_listener(l));

    let before = flock_server::server::sessions_overlimit();
    // First connection: a silent TCP connection (no I0) —— holds the single
    // permit (respond pends waiting for the first frame).
    let mut c1 = tokio::net::TcpStream::connect(addr).await.unwrap();
    // Second connection: over the limit ⇒ politely closed right after
    // acceptance (the read side observes EOF).
    let mut c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 8];
    let t = tokio::time::timeout(std::time::Duration::from_secs(3), c2.read(&mut buf)).await;
    match t {
        Ok(Ok(0)) | Ok(Err(_)) => {} // EOF/error = the observable face of the polite close
        Ok(Ok(n)) => panic!("an over-limit connection must carry no data (read {n}B)"),
        Err(_) => panic!("the over-limit connection did not observe closure within 3s"),
    }
    // The counter increments.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while flock_server::server::sessions_overlimit() < before + 1
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        flock_server::server::sessions_overlimit(),
        before + 1,
        "over-limit close count +1"
    );
    // The first connection is unaffected: still pending on the server (no
    // EOF on the read side within 1s).
    let still = tokio::time::timeout(std::time::Duration::from_secs(1), c1.read(&mut buf)).await;
    assert!(
        still.is_err(),
        "the permit-holding first connection must not be closed"
    );
    task.abort();
}

/// Review item 8: the handshake timeout is a class of rejection —— a
/// silent connection (sending no I0/I1) is closed by the server after the
/// 10s budget (the read side observes EOF), no longer holding a session
/// permit indefinitely.
#[tokio::test]
async fn silent_connection_closed_by_handshake_timeout() {
    use tokio::io::AsyncReadExt as _;

    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg_for("direct", dir.path());
    let (core, _) = ServerCore::open_or_init(cfg).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let task = tokio::spawn(core.serve_listener(l));

    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 8];
    // 10s budget + margin: EOF should arrive within (10s, 15s] (earlier
    // than 10s = closed before waiting out the budget; later = no
    // timeout).
    let t0 = std::time::Instant::now();
    let n = tokio::time::timeout(std::time::Duration::from_secs(15), c.read(&mut buf))
        .await
        .expect("closure must be observed within 15s")
        .expect("read");
    assert_eq!(n, 0, "EOF (polite close)");
    let dt = t0.elapsed();
    assert!(
        dt >= std::time::Duration::from_secs(10),
        "closure no earlier than the handshake budget ({dt:?})"
    );
    task.abort();
}
