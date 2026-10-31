//! ListenerMode 装配测试（docs/design.md §2.1/§3.11：Direct 缺省零 frp 逻辑；Frp 走
//! chml-frpc Supervisor 真实产品路径）。
//!
//! - `direct_mode_*`：Direct 起服 ⇒ 监听句柄为 `RunningListener::Direct`；状态目录无任何
//!   frp 配置/托管落点（Supervisor 未实例化的运行时证明——其唯一副作用是 run 目录与
//!   托管配置副本，见 chml-frpc supervisor.rs）。
//! - `frp_mode_*`：Frp 装配确实接管（内嵌 TOML 落盘 + Supervisor spawn）；frpc 二进制
//!   缺失/不可执行 ⇒ 启动失败fail-fast（R9 矩阵与 spawn 校验在 chml-frpc 内执行）。

mod common;

use chmlvpn_server::config::ServerConfig;
use chmlvpn_server::server::{self, RunningListener, ServerCore};

fn cfg_for(mode: &str, state_dir: &std::path::Path) -> ServerConfig {
    ServerConfig {
        state_dir: state_dir.to_path_buf(),
        bind: "127.0.0.1:0".parse().unwrap(),
        mode: mode.into(),
        advertise_endpoint: "127.0.0.1:9443".into(),
        extra_endpoints: vec![],
        dir_version: 1,
        ticket_ttl_secs: 60,
        admin_bind: "127.0.0.1:0".parse().unwrap(),
        frp: Some(chmlvpn_server::config::FrpSection {
            original_toml: "serverAddr = \"frps\"\nserverPort = 7000\n".into(),
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
    // 运行时证明：无 frp 配置生成、无 Supervisor run 目录（chml-frpc 在本进程零实例化）。
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
