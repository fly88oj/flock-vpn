//! R9 版本矩阵锁测试（frp-compat §4-R9；docs/design.md §3.9 实现要点）。
//!
//! 矩阵：ChmlFrp 节点 ⇔ ChmlFrp frpc（`ChmlFrp-0.51.2_251023`）、自建节点 ⇔ 同代原版
//! frpc（`0.71.1`），**禁交叉**。机理（frp-compat §1.3 源码级证实）：ChmlFrp 基于
//! v0.51.2（无控制面加密）与原版 ≥v0.53.0（登录后强制 AES-128-CFB，token 派生 key）
//! 两代控制面互不兼容，双向均挂 ⇒ 「4 组合只有对角线成功」在此固化（CI 矩阵冒烟的
//! 单测形态；端到端 R1 冒烟留 M5）。
//!
//! 进程级核对（`--version` 实测 ↔ 声明）也在本组：矩阵的「声明面」由
//! `FrpcBinary::decl_version` 承担，声明面与二进制实测不符在启动期即拒。

mod common;

use std::path::PathBuf;

use flock_frpc::supervisor::SupervisorConfig;
use flock_frpc::{
    check_version_matrix, ChmlFrpMode, FrpcBinaries, FrpcBinary, FrpcError, RelayFlavor,
    RelayPhase, RelaySpec, StopReason, Supervisor, CHMLFRP_PINNED_VERSION, ORIGINAL_PINNED_VERSION,
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

fn bin(flavor: RelayFlavor, decl_version: &str) -> FrpcBinary {
    FrpcBinary {
        path: PathBuf::from(STUB),
        flavor,
        decl_version: decl_version.to_string(),
    }
}

fn chmlfrp_spec() -> RelaySpec {
    RelaySpec::ChmlFrp {
        mode: ChmlFrpMode::ConfigFile(PathBuf::from(GOLDEN_INI)),
    }
}

fn original_spec() -> RelaySpec {
    RelaySpec::Original {
        toml: PathBuf::from(GOLDEN_TOML),
    }
}

fn temp_run_base(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "flock-frpc-test-matrix-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 纯函数面：4 组合只有对角线过（R9 矩阵冒烟的单测固化）。
#[test]
fn matrix_diagonal_only() {
    let chmlfrp_bin = bin(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION);
    let original_bin = bin(RelayFlavor::Original, ORIGINAL_PINNED_VERSION);

    // 对角线 ✅
    check_version_matrix(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION, &chmlfrp_bin)
        .expect("ChmlFrp 节点 ⇔ ChmlFrp frpc 应放行");
    check_version_matrix(
        RelayFlavor::Original,
        ORIGINAL_PINNED_VERSION,
        &original_bin,
    )
    .expect("自建节点 ⇔ 同代原版 frpc 应放行");

    // 交叉 ❌（双向）
    let err = check_version_matrix(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION, &original_bin)
        .expect_err("ChmlFrp 规格 × 原版 frpc 必须被拒");
    assert!(
        matches!(err, FrpcError::Matrix(_)),
        "交叉配对应报 Matrix 错: {err}"
    );
    let err = check_version_matrix(RelayFlavor::Original, ORIGINAL_PINNED_VERSION, &chmlfrp_bin)
        .expect_err("原版规格 × ChmlFrp frpc 必须被拒");
    assert!(
        matches!(err, FrpcError::Matrix(_)),
        "交叉配应对报 Matrix 错: {err}"
    );
}

/// 定版纪律：栈代正确但版本非定版 → 拒（防「同代但漂移」的静默升级）。
#[test]
fn matrix_rejects_unpinned_versions() {
    let drifted = bin(RelayFlavor::ChmlFrp, "ChmlFrp-0.51.3_260101");
    assert!(check_version_matrix(RelayFlavor::ChmlFrp, "ChmlFrp-0.51.3_260101", &drifted).is_err());

    let drifted = bin(RelayFlavor::Original, "0.72.0");
    assert!(check_version_matrix(RelayFlavor::Original, "0.72.0", &drifted).is_err());
}

/// 交叉栈下 `start()` 必须失败且返回 Matrix 错（而非 spawn 后才挂）。
async fn start_expect_matrix_error(sup: &Supervisor, spec: RelaySpec) {
    match sup.start(spec).await {
        Err(e) => assert!(matches!(e, FrpcError::Matrix(_)), "应为 Matrix 错: {e}"),
        Ok(relay) => {
            let _ = relay.stop().await;
            panic!("交叉栈必须在 start 层被拒")
        }
    }
}

/// RelaySpec 校验层接线：`Supervisor::start` 按声明的二进制表执行同一矩阵检查。
#[tokio::test]
async fn supervisor_start_enforces_matrix_on_cross_stack() {
    // 交叉栈用例不会走到 spawn（start 即拒），但同进程其它用例需要热路径——统一预热。
    common::prewarm_stub();
    // ChmlFrp 规格，但 chmlfrp 槽位挂的是原版声明的二进制 → start 即拒（不 spawn）
    let bins = FrpcBinaries {
        chmlfrp: bin(RelayFlavor::Original, ORIGINAL_PINNED_VERSION),
        original: bin(RelayFlavor::Original, ORIGINAL_PINNED_VERSION),
    };
    let sup = Supervisor::new(SupervisorConfig::new(bins));
    start_expect_matrix_error(&sup, chmlfrp_spec()).await;

    // 原版规格 × ChmlFrp 声明二进制 → 同拒
    let bins = FrpcBinaries {
        chmlfrp: bin(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION),
        original: bin(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION),
    };
    let sup = Supervisor::new(SupervisorConfig::new(bins));
    start_expect_matrix_error(&sup, original_spec()).await;
}

/// 非定版声明（栈代正确、版本漂移）在 start 层同样被拒。
#[tokio::test]
async fn supervisor_start_rejects_unpinned_decl() {
    let bins = FrpcBinaries {
        chmlfrp: bin(RelayFlavor::ChmlFrp, "ChmlFrp-0.52.0_000000"),
        original: bin(RelayFlavor::Original, ORIGINAL_PINNED_VERSION),
    };
    let sup = Supervisor::new(SupervisorConfig::new(bins));
    start_expect_matrix_error(&sup, chmlfrp_spec()).await;
}

/// `--version` 实测核对：声明与二进制实际打印不一致 → 拒（抓「路径挂错二进制」）。
#[tokio::test]
async fn version_probe_cross_checks_declared_version() {
    common::prewarm_stub();
    // 桩的 --version 打印环境变量 FRPC_STUB_VERSION（本测试进程设置一次，子进程继承；
    // 其它测试不触发 --version 路径，无环境串扰）。
    std::env::set_var("FRPC_STUB_VERSION", CHMLFRP_PINNED_VERSION);

    let ok = bin(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION);
    let probed = ok.probe_version().await.expect("--version 探测成功");
    assert_eq!(probed, CHMLFRP_PINNED_VERSION);
    ok.verify_declared().await.expect("实测=声明=定版 → 放行");

    // 实测 ChmlFrp 定版串、声明成 0.71.1 → 拒（版本漂移）
    let drifted = bin(RelayFlavor::ChmlFrp, ORIGINAL_PINNED_VERSION);
    let err = drifted
        .verify_declared()
        .await
        .expect_err("声明与实测不一致必须被拒");
    assert!(matches!(err, FrpcError::Matrix(_)), "{err}");

    // verify_version_at_start=true：核对通过则正常起（stub 忽略 -c 自退，验证点在
    // start() 不因核对失败而拒、且核对通过路径可用）
    let bins = FrpcBinaries {
        chmlfrp: bin(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION),
        original: bin(RelayFlavor::Original, ORIGINAL_PINNED_VERSION),
    };
    let mut cfg = SupervisorConfig::new(bins);
    cfg.verify_version_at_start = true;
    cfg.run_base = temp_run_base("version-ok");
    let sup = Supervisor::new(cfg);
    let relay = sup.start(chmlfrp_spec()).await.expect("核对通过应正常启动");
    let status = relay.stop().await.expect("stop 收尾");
    assert_eq!(
        status.phase,
        RelayPhase::Stopped {
            reason: StopReason::Manual
        }
    );

    // 声明漂移 + 启动期核对 → start 即拒
    let bins = FrpcBinaries {
        chmlfrp: bin(RelayFlavor::ChmlFrp, "ChmlFrp-0.51.3_260101"),
        original: bin(RelayFlavor::Original, ORIGINAL_PINNED_VERSION),
    };
    let mut cfg = SupervisorConfig::new(bins);
    cfg.verify_version_at_start = true;
    cfg.run_base = temp_run_base("version-drift");
    let sup = Supervisor::new(cfg);
    start_expect_matrix_error(&sup, chmlfrp_spec()).await;
}
