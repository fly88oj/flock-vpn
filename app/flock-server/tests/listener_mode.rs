//! ListenerMode 装配测试（docs/design.md §2.1/§3.11：Direct 缺省零 frp 逻辑；Frp 走
//! flock-frpc Supervisor 真实产品路径）。
//!
//! - `direct_mode_*`：Direct 起服 ⇒ 监听句柄为 `RunningListener::Direct`；状态目录无任何
//!   frp 配置/托管落点（Supervisor 未实例化的运行时证明——其唯一副作用是 run 目录与
//!   托管配置副本，见 flock-frpc supervisor.rs）。
//! - `frp_mode_*`：Frp 装配确实接管（内嵌 TOML 落盘 + Supervisor spawn）；frpc 二进制
//!   缺失/不可执行 ⇒ 启动失败fail-fast（R9 矩阵与 spawn 校验在 flock-frpc 内执行）。

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

/// 目录树内是否存在名字匹配谓词的条目。
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
        "Direct 起服 ⇒ Direct 变体（无 ManagedRelay）"
    );
    // 运行时证明：无 frp 配置生成、无 Supervisor run 目录（flock-frpc 在本进程零实例化）。
    assert!(
        !any_entry(dir.path(), &|n| n.starts_with("frpc") || n.contains("frp")),
        "状态目录不应出现任何 frp 落点"
    );
    assert!(!dir.path().join("frpc-run").exists());
    // 会话面可用（Direct 端到端冒烟）。
    let addr = running.local_addr();
    let mut io = tokio::net::TcpStream::connect(addr).await.expect("connect");
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    // 发一个 I0（TOFU 引导）：Direct 监听上正常走 session::respond（握手会因设备不在
    // 目录被拒——预期行为；此处只证明字节面到达服务器并被处理）。
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
    // 二进制占位：存在但不可执行 ⇒ Supervisor spawn fail-fast（证明装配确实接管）。
    std::fs::write(dir.path().join("fake-frpc"), b"not an elf").unwrap();
    let (core, _) = ServerCore::open_or_init(cfg.clone()).unwrap();
    let err = match server::run(core, cfg.listener_mode().unwrap()).await {
        Ok(_) => panic!("frpc 不可执行 ⇒ 启动应失败"),
        Err(e) => e,
    };
    assert!(err.contains("frpc"), "错误应来自 frpc supervisor: {err}");
    // 内嵌 TOML 已按 Original 注册路径落盘（§7-M2「server 内嵌 frpc」）。
    let embedded = dir
        .path()
        .join("frpc-run")
        .join("embedded")
        .join("frpc.toml");
    let text = std::fs::read_to_string(&embedded).expect("embedded frpc.toml");
    assert!(text.contains("serverAddr"), "内嵌 TOML 落盘");
}

/// 评审项 14：ChmlFrp 装配接线——配置解析 → RelaySpec 构造。
/// ① `[frp] flavor = "chmlfrp"` + 面板导出 ini 路径 ⇒ 缺省 ChmlFrpMode::ConfigFile；
/// ② 显式 `[frp.user_token_auto]` opt-in ⇒ UserTokenAuto 模式（ini 可省）；
/// ③ Original 兼容不破（flavor 缺省 + original_toml）。
#[tokio::test]
async fn chmlfrp_config_parses_to_relay_spec() {
    // ① 缺省 ConfigFile 模式。
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
    assert!(user_token_auto.is_none(), "缺省 ConfigFile 模式");
    assert!(
        matches!(
            flock_server::frp::chmlfrp_spec_for_test(ini, user_token_auto),
            flock_frpc::RelaySpec::ChmlFrp {
                mode: flock_frpc::ChmlFrpMode::ConfigFile(_),
            }
        ),
        "RelaySpec::ChmlFrp + ConfigFile"
    );

    // ② UserTokenAuto 显式 opt-in。
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
    assert!(ini.is_none(), "UserTokenAuto 模式 ini 可省");
    let uta = user_token_auto.as_ref().expect("opt-in 解析");
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

    // ③ Original 兼容不破（flavor 缺省即 original）。
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
        "Original 兼容不破（缺省 flavor）"
    );
    // 校验负路径：chmlfrp 无 ini 且无 opt-in ⇒ 拒。
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
    assert!(err.contains("chmlfrp_ini"), "缺配置错误可诊断: {err}");
}

/// 评审项 7：并发会话上限——`max_sessions = 1` 时第二条入连被接受后立即礼貌关闭
/// （对端观察到 FIN），且超限计数递增；持许可的首连不受影响（静默连接保持挂起）。
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
    // 首连：静默 TCP（无 I0）——占住唯一许可（respond 挂起等待首帧）。
    let mut c1 = tokio::net::TcpStream::connect(addr).await.unwrap();
    // 第二连：超限 ⇒ 接受后立即礼貌关闭（读侧观察到 EOF）。
    let mut c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 8];
    let t = tokio::time::timeout(std::time::Duration::from_secs(3), c2.read(&mut buf)).await;
    match t {
        Ok(Ok(0)) | Ok(Err(_)) => {} // EOF/错误 = 礼貌关闭的观察面
        Ok(Ok(n)) => panic!("超限连接不应有数据（读到 {n}B）"),
        Err(_) => panic!("3s 内超限连接未观察到关闭"),
    }
    // 计数递增。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while flock_server::server::sessions_overlimit() < before + 1
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        flock_server::server::sessions_overlimit(),
        before + 1,
        "超限关闭计数 +1"
    );
    // 首连不受影响：仍在服务端挂起（读侧 1s 内无 EOF）。
    let still = tokio::time::timeout(std::time::Duration::from_secs(1), c1.read(&mut buf)).await;
    assert!(still.is_err(), "持许可的首连不应被关闭");
    task.abort();
}

/// 评审项 8：握手超时归类拒绝——沉默连接（不发 I0/I1）在 10s 预算后被服务端关闭
/// （读侧观察到 EOF），不再无限占住会话许可。
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
    // 10s 预算 + 余量：EOF 应在 (10s, 15s] 内到达（早于 10s = 未等预算即关，迟到 = 无超时）。
    let t0 = std::time::Instant::now();
    let n = tokio::time::timeout(std::time::Duration::from_secs(15), c.read(&mut buf))
        .await
        .expect("15s 内必须观察到关闭")
        .expect("read");
    assert_eq!(n, 0, "EOF（礼貌关闭）");
    let dt = t0.elapsed();
    assert!(
        dt >= std::time::Duration::from_secs(10),
        "关闭不早于握手预算（{dt:?}）"
    );
    task.abort();
}
