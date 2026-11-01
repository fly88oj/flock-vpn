//! 进程守护测试（§7-M2 完成标准；frp-compat §2.3/§4-R6）。
//!
//! 用假进程桩（`src/bin/frpc_stub.rs`，经 `CARGO_BIN_EXE_frpc_stub` 调用）单测：
//!
//! - **3 退→3 拉**：ChmlFrp frpc「三次重连失败即退出进程」的魔改行为由守护循环兜住——
//!   桩反复自退，断言拉起次数与指数退避下界（每轮退避 ≥ initial×2^n，调度只会更晚
//!   不会更早 ⇒ 下界断言稳定）；
//! - **停止语义**：`stop()` 杀当前子进程、落 `Stopped{Manual}`、此后不再拉起；
//! - **重启额度**：`max_restarts` 耗尽 → `Stopped{RestartsExhausted}`；
//! - **健康探测**：本地隧道口 + frpc admin（serve 桩的 HTTP 200 面）；
//! - **argv 刻画**：`-c`（ConfigFile/Original）与 `-u/-p`（UserTokenAuto）到达子进程；
//! - **R12 端到端**：托管副本的 proxy 节与面板输入逐字节一致、admin 只进 `[common]`。
//!
//! 桩行为由测试配置文件尾部的 `[stub]` 节选择（`mode`/`lifetime_ms`），marker 落
//! 托管 run_dir（每路中继唯一）。

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use flock_frpc::config::{parse_ini, AdminCommon};
use flock_frpc::probe::ProbeResult;
use flock_frpc::supervisor::{HealthPolicy, RestartPolicy, SupervisorConfig};
use flock_frpc::{
    ChmlFrpMode, FrpcBinaries, FrpcBinary, ManagedRelay, RelayFlavor, RelayPhase, RelaySpec,
    StopReason, Supervisor, CHMLFRP_PINNED_VERSION, ORIGINAL_PINNED_VERSION,
};

const STUB: &str = env!("CARGO_BIN_EXE_frpc_stub");
const GOLDEN_INI: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/chmlfrp_panel.frpc.ini"
);
const GOLDEN_TOML: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/original.frpc.toml"
);

// 退避节奏（毫秒级，压总时长；断言只依赖下界——调度延迟只会放大间隔不会缩小）
const INITIAL_MS: u64 = 80;
const MULTIPLIER: u64 = 2;
const STUB_LIFETIME_MS: u64 = 20;

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "flock-frpc-test-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 面板 ini 样本 + `[stub]` 行为节（追加在新节里，proxy 节本身不动）。
fn panel_ini_with_stub(dir: &Path, stub: &str) -> PathBuf {
    let ini = dir.join("frpc.ini");
    let golden = std::fs::read_to_string(GOLDEN_INI)
        .unwrap()
        .replace("\r\n", "\n");
    std::fs::write(&ini, format!("{golden}\n[stub]\n{stub}\n")).unwrap();
    ini
}

fn fast_restart_policy() -> RestartPolicy {
    RestartPolicy {
        initial: Duration::from_millis(INITIAL_MS),
        multiplier: MULTIPLIER as f64,
        max: Duration::from_secs(1),
        max_restarts: None,
    }
}

fn stub_bins() -> FrpcBinaries {
    FrpcBinaries {
        chmlfrp: FrpcBinary {
            path: PathBuf::from(STUB),
            flavor: RelayFlavor::ChmlFrp,
            decl_version: CHMLFRP_PINNED_VERSION.to_string(),
        },
        original: FrpcBinary {
            path: PathBuf::from(STUB),
            flavor: RelayFlavor::Original,
            decl_version: ORIGINAL_PINNED_VERSION.to_string(),
        },
    }
}

fn supervisor(tag: &str, restart: RestartPolicy, health: HealthPolicy) -> Supervisor {
    let mut cfg = SupervisorConfig::new(stub_bins());
    cfg.restart = restart;
    cfg.health = health;
    cfg.run_base = test_dir(tag);
    Supervisor::new(cfg)
}

/// marker 事件行：`(kind, unix_ms, extra)`——extra 为该行剩余全部
/// （argv 行的参数串、serve 行的监听地址）。
fn read_marker(path: &Path) -> Vec<(String, u128, String)> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let mut parts = l.splitn(3, ' ');
            let kind = parts.next()?.trim().to_string();
            if kind.is_empty() {
                return None;
            }
            let ms: u128 = parts.next()?.trim().parse().ok()?;
            let extra = parts.next().unwrap_or("").trim().to_string();
            Some((kind, ms, extra))
        })
        .collect()
}

/// 轮询直到累计重启 ≥ want，返回 run_dir（marker 落点）。
async fn wait_until_restarts(relay: &ManagedRelay, want: u32, timeout: Duration) -> PathBuf {
    let deadline = Instant::now() + timeout;
    loop {
        let status = relay.health();
        if let RelayPhase::Stopped { reason } = &status.phase {
            panic!("中继提前停止: {reason:?}（restarts={}）", status.restarts);
        }
        if status.restarts >= want {
            return status.run_dir;
        }
        if Instant::now() > deadline {
            panic!(
                "等待 restarts>={want} 超时（当前 {:?}, restarts={}）；logs: {:?}",
                status.phase,
                status.restarts,
                relay.logs()
            );
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

/// **核心用例：3 退 → 3 拉 + 指数退避下界**。
///
/// ChmlFrp frpc 三次重连退出（魔改）后由守护拉起：桩崩 3 次以上，marker 记录 4+ 次
/// start；连续 start 间隔分别 ≥ lifetime+initial、lifetime+initial×2、lifetime+initial×4
/// （退避 sleep 是下界，进程调度只增不减 ⇒ 下界断言稳定），且末轮间隔显著大于首轮
/// （指数增长的直接证据）。
#[tokio::test]
async fn three_crashes_pull_three_restarts_with_exponential_backoff() {
    common::prewarm_stub();
    let dir = test_dir("crash3");
    let ini = panel_ini_with_stub(&dir, "mode = crash\nlifetime_ms = 20");
    let sup = supervisor("crash3", fast_restart_policy(), HealthPolicy::default());
    let relay = sup
        .start(RelaySpec::ChmlFrp {
            mode: ChmlFrpMode::ConfigFile(ini),
        })
        .await
        .expect("假桩规格应可启动");
    let run_dir = wait_until_restarts(&relay, 3, Duration::from_secs(20)).await;
    // 宽限窗：restarts 在 spawn 返回瞬间记账，而第 4 个桩进程写 marker 需几毫秒——
    // 立即 stop() 会把它杀在落笔前。200ms 足够留痕，又短于第 4 次退出后的下一轮
    // 退避（80×2³=640ms），不会引入第 5 次 start。
    tokio::time::sleep(Duration::from_millis(200)).await;
    let status = relay.stop().await.expect("stop 收尾");
    assert_eq!(
        status.phase,
        RelayPhase::Stopped {
            reason: StopReason::Manual
        }
    );
    // 魔改退出形态：非零退出码（ChmlFrp 三次重连后 os.Exit(1) 的模拟面）
    assert!(matches!(&status.last_exit, Some(e) if !e.success));

    let marker = run_dir.join("stub-marker.log");
    // 拉起计数：start 事件 = 首次 + ≥3 次重启
    let starts: Vec<u128> = read_marker(&marker)
        .into_iter()
        .filter(|(kind, _, _)| kind == "start")
        .map(|(_, ms, _)| ms)
        .collect();
    assert!(
        starts.len() >= 4,
        "3 退应至少 3 拉起（共 4 次 start），实际 {}",
        starts.len()
    );

    // 指数退避下界：间隔_i ≥ stub 存活 + initial × multiplier^i
    let mut prev = starts[0];
    for (i, &t) in starts.iter().skip(1).take(3).enumerate() {
        let lower = STUB_LIFETIME_MS + INITIAL_MS * MULTIPLIER.pow(i as u32);
        let interval = (t - prev) as u64;
        assert!(
            interval >= lower,
            "第 {} 次重启间隔 {interval}ms 低于退避下界 {lower}ms",
            i + 1
        );
        prev = t;
    }
    // 增长证据：第 3 间隔 ≈ 4×第 1 间隔（容 25% 调度松弛仍应显著更大）
    let i1 = (starts[1] - starts[0]) as u64;
    let i3 = (starts[3] - starts[2]) as u64;
    assert!(i3 * 4 >= i1 * 10, "退避未见指数增长: i1={i1}ms i3={i3}ms");
}

/// 停止语义：运行中的子进程被杀、落 `Stopped{Manual}`、之后不再有 start 事件。
#[tokio::test]
async fn stop_kills_running_child_and_no_respawn() {
    common::prewarm_stub();
    let dir = test_dir("stop");
    let _ini = panel_ini_with_stub(&dir, "mode = run");

    let sup = supervisor("stop", fast_restart_policy(), HealthPolicy::default());
    let relay = sup
        .start(RelaySpec::ChmlFrp {
            mode: ChmlFrpMode::UserTokenAuto {
                usertoken: "tok".into(),
                tunnel_id: 42,
            },
        })
        .await
        .expect("run 桩应可启动");

    // 等 Running（stub 长驻），确认仅 1 次 start
    let run_dir = {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let s = relay.health();
            if matches!(s.phase, RelayPhase::Running { .. }) {
                break s.run_dir;
            }
            assert!(Instant::now() < deadline, "未进入 Running: {:?}", s.phase);
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let marker = run_dir.join("stub-marker.log");
    let starts = || {
        read_marker(&marker)
            .iter()
            .filter(|(k, _, _)| k == "start")
            .count()
    };
    assert_eq!(starts(), 1);

    let status = relay.stop().await.expect("stop 收尾");
    assert_eq!(
        status.phase,
        RelayPhase::Stopped {
            reason: StopReason::Manual
        }
    );

    // 停止后不再拉起（等待窗 > 退避 initial）
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(starts(), 1, "stop 后不得再拉起");
}

/// 重启额度：`max_restarts=2` → 首 + 2 拉后停 `Stopped{RestartsExhausted}`。
#[tokio::test]
async fn max_restarts_exhaustion_stops_relay() {
    common::prewarm_stub();
    let dir = test_dir("exhaust");
    let ini = panel_ini_with_stub(&dir, "mode = crash\nlifetime_ms = 10");

    let mut policy = fast_restart_policy();
    policy.initial = Duration::from_millis(40);
    policy.max_restarts = Some(2);
    let sup = supervisor("exhaust", policy, HealthPolicy::default());
    let relay = sup
        .start(RelaySpec::ChmlFrp {
            mode: ChmlFrpMode::ConfigFile(ini),
        })
        .await
        .expect("启动");

    let deadline = Instant::now() + Duration::from_secs(20);
    let run_dir = loop {
        let s = relay.health();
        if let RelayPhase::Stopped {
            reason: StopReason::RestartsExhausted,
        } = s.phase
        {
            break s.run_dir;
        }
        assert!(Instant::now() < deadline, "未在额度内停机: {:?}", s.phase);
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    // 恰好 3 次 start（首 + 2 拉起），等待窗内不再增
    tokio::time::sleep(Duration::from_millis(250)).await;
    let marker = run_dir.join("stub-marker.log");
    let starts = read_marker(&marker)
        .into_iter()
        .filter(|(k, _, _)| k == "start")
        .count();
    assert_eq!(starts, 3, "max_restarts=2 应恰好拉起 2 次");
    relay.stop().await.expect("已停的 relay stop 仍应幂等收尾");
}

/// 健康探测：admin（serve 桩 200）+ 本地隧道口（显式不可达口）双路报告；
/// 同时验证 R12 端到端：托管副本 proxy 节与面板输入逐字节一致、admin 只进 `[common]`。
#[tokio::test]
async fn health_probe_admin_ok_local_tunnel_err_and_r12_managed_copy() {
    common::prewarm_stub();
    let dir = test_dir("probe");
    let serve_marker = dir.join("serve-marker.log");
    let ini = panel_ini_with_stub(&dir, "mode = run");

    // serve 桩：模拟「frpc admin 监听」（HTTP 200），先起、从 marker 读实际端口
    let mut serve = tokio::process::Command::new(STUB)
        .args([
            "serve",
            "--marker",
            serve_marker.to_str().unwrap(),
            "--addr",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("serve 桩启动");
    let admin_port = wait_for_serve_port(&serve_marker);

    let health = HealthPolicy {
        probe_interval: Duration::from_millis(60),
        probe_timeout: Duration::from_secs(1),
        inject_admin: Some(AdminCommon {
            addr: "127.0.0.1".parse().unwrap(),
            port: admin_port,
            user: "probe".into(),
            password: "probe-pw".into(),
        }),
        // 本地隧道口显式指向必然拒绝的口（golden 样本的 local 22 在部分机器真有 sshd，
        // 显式不可达口保断言确定性）；admin 走注入的 serve 桩。
        probe_local_tunnel: Some("127.0.0.1:1".parse().unwrap()),
    };

    let sup = supervisor("probe", fast_restart_policy(), health);
    let relay = sup
        .start(RelaySpec::ChmlFrp {
            mode: ChmlFrpMode::ConfigFile(ini.clone()),
        })
        .await
        .expect("run 桩应可启动");

    // 探测报告：admin Ok、local_tunnel Err
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        let s = relay.health();
        if let Some(rep) = &s.probe {
            if matches!(rep.admin, Some(ProbeResult::Ok)) && rep.local_tunnel.is_some() {
                break s;
            }
        }
        assert!(
            Instant::now() < deadline,
            "探测报告未就绪: {:?} logs={:?}",
            s.probe,
            relay.logs()
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    };
    let rep = status.probe.expect("已确认就绪");
    assert_eq!(rep.admin, Some(ProbeResult::Ok), "admin 应探测到 serve 桩");
    assert!(
        matches!(rep.local_tunnel, Some(ProbeResult::Err(_))),
        "本地隧道口（127.0.0.1:1）应失败: {:?}",
        rep.local_tunnel
    );
    assert!(!rep.all_ok(), "存在失败路时 all_ok 应为 false");

    // —— R12 端到端：托管副本 ——
    let run_dir = status.run_dir;
    let managed = std::fs::read_to_string(run_dir.join("frpc.ini")).expect("托管副本在位");
    let panel = std::fs::read_to_string(&ini).unwrap();
    let norm = |s: String| s.replace("\r\n", "\n");
    let (managed, panel) = (norm(managed), norm(panel));
    // proxy 节（[ssh] 起至尾，含 [stub] 行为节）逐字节一致
    let tail_panel = &panel[panel.find("[ssh]").unwrap()..];
    let tail_managed = &managed[managed.find("[ssh]").unwrap()..];
    assert_eq!(
        tail_panel, tail_managed,
        "R12：托管副本 proxy 节必须与面板输入逐字节一致"
    );
    let parsed = parse_ini(&managed).unwrap();
    assert_eq!(
        parsed.get("common", "admin_port"),
        Some(admin_port.to_string().as_str())
    );
    assert_eq!(parsed.get("common", "admin_user"), Some("probe"));
    // 面板原字段不动
    assert_eq!(parsed.get("common", "server_port"), Some("7000"));

    // argv：ConfigFile 模式 = -c <run_dir>/frpc.ini（托管副本）
    let argv = argv_lines(&run_dir.join("stub-marker.log"));
    let managed_path = run_dir.join("frpc.ini");
    assert!(
        argv.iter()
            .any(|a| a.contains("-c") && a.contains(managed_path.to_str().unwrap())),
        "-c 应指向托管副本: {argv:?}"
    );

    relay.stop().await.expect("stop 收尾");
    let _ = serve.kill().await;
}

/// UserTokenAuto：argv 到达形态 = `-u <usertoken> -p <tunnel_id>`（魔改 CLI 契约）。
#[tokio::test]
async fn user_token_auto_argv_shape() {
    common::prewarm_stub();
    let dir = test_dir("userauto");
    let _ini = panel_ini_with_stub(&dir, "mode = run");

    let sup = supervisor("userauto", fast_restart_policy(), HealthPolicy::default());
    let relay = sup
        .start(RelaySpec::ChmlFrp {
            mode: ChmlFrpMode::UserTokenAuto {
                usertoken: "ut-测试-token".into(),
                tunnel_id: 77,
            },
        })
        .await
        .expect("启动");
    tokio::time::sleep(Duration::from_millis(250)).await;

    let run_dir = relay.health().run_dir;
    let argv = argv_lines(&run_dir.join("stub-marker.log"));
    assert!(
        argv.iter().any(|a| a.contains("-u ut-测试-token -p 77")),
        "-u/-p 应按魔改 CLI 契约下发: {argv:?}"
    );
    relay.stop().await.expect("stop 收尾");
}

/// Original 栈：`-c <调用方 TOML>` 且**不改写**原文件（内容逐字节不变）。
#[tokio::test]
async fn original_spec_uses_caller_toml_verbatim() {
    common::prewarm_stub();
    let dir = test_dir("original");
    let toml = dir.join("frpc.toml");
    let golden = std::fs::read_to_string(GOLDEN_TOML)
        .unwrap()
        .replace("\r\n", "\n");
    std::fs::write(&toml, format!("{golden}\n[stub]\nmode = \"run\"\n")).unwrap();
    let before = std::fs::read(&toml).unwrap();

    let sup = supervisor("original", fast_restart_policy(), HealthPolicy::default());
    let relay = sup
        .start(RelaySpec::Original { toml: toml.clone() })
        .await
        .expect("启动");
    tokio::time::sleep(Duration::from_millis(250)).await;

    let run_dir = relay.health().run_dir;
    let argv = argv_lines(&run_dir.join("stub-marker.log"));
    assert!(
        argv.iter()
            .any(|a| a.contains("-c") && a.contains(toml.to_str().unwrap())),
        "-c 应指向调用方 TOML: {argv:?}"
    );
    let after = std::fs::read(&toml).unwrap();
    assert_eq!(before, after, "调用方 TOML 绝不改写");
    relay.stop().await.expect("stop 收尾");
}

/// `RestartPolicy::delay_for` 的纯函数面：指数增长 + 封顶。
#[test]
fn restart_policy_delay_curve() {
    let p = RestartPolicy {
        initial: Duration::from_millis(100),
        multiplier: 2.0,
        max: Duration::from_millis(350),
        max_restarts: None,
    };
    assert_eq!(p.delay_for(1), Duration::from_millis(100));
    assert_eq!(p.delay_for(2), Duration::from_millis(200));
    assert_eq!(
        p.delay_for(3),
        Duration::from_millis(350),
        "封顶生效（400→350）"
    );
    assert_eq!(p.delay_for(9), Duration::from_millis(350));
}

// ---------------------------------------------------------------------------

fn wait_for_serve_port(marker: &Path) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let events = read_marker(marker);
        if let Some((_, _, addr)) = events.iter().find(|(k, _, _)| k == "serve") {
            return addr.rsplit(':').next().unwrap().parse().unwrap();
        }
        assert!(Instant::now() < deadline, "serve 桩未上报监听地址");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn argv_lines(marker: &Path) -> Vec<String> {
    read_marker(marker)
        .into_iter()
        .filter(|(k, _, _)| k == "argv")
        .map(|(_, _, extra)| extra)
        .collect()
}
