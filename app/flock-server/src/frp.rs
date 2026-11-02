//! Frp 模式装配（docs/design.md §2.1/§3.9/§5）。
//!
//! **本模块是 flock-server 唯一触碰 flock-frpc 类型的地方**（§3.11：仅 Frp 模式装配，
//! Direct 分支无 flock-frpc 类型引用——Direct 代码路径在 `server.rs` 的 accept/会话/控制流，
//! 不经过本文件）。职责：把 config 层 [`FrpPlan`]（自有类型）翻译成
//! `RelaySpec::Original{toml}` + `Supervisor`，并把内嵌 TOML 落到 run 目录。

use std::net::SocketAddr;
use std::path::Path;

use flock_frpc::supervisor::{Supervisor, SupervisorConfig};
use flock_frpc::{
    FrpcBinaries, FrpcBinary, ManagedRelay, RelayFlavor, RelaySpec, CHMLFRP_PINNED_VERSION,
    ORIGINAL_PINNED_VERSION,
};
use tokio::net::TcpListener;

use crate::config::FrpPlan;

/// Frp 模式的运行时句柄（包装 flock-frpc 类型；Drop 即托管拆除）。
pub struct Managed {
    relay: ManagedRelay,
}

impl Managed {
    /// 托管健康快照（诊断面）。
    pub fn health(&self) -> flock_frpc::RelayStatus {
        self.relay.health()
    }

    /// 显式停止（Drop 亦会停——`kill_on_drop` 语义由 flock-frpc 保证）。
    pub async fn stop(self) {
        let _ = self.relay.stop().await;
    }
}

/// Frp 模式启动：bind 本地监听 + 内嵌 TOML 落盘 + Supervisor 托管原版 frpc。
///
/// 内嵌 TOML 写到 `run_base/embedded/frpc.toml`（Supervisor 对该文件只读，§3.9）。
pub async fn start(plan: FrpPlan, bind: SocketAddr) -> Result<(TcpListener, Managed), String> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("frp listener bind {bind}: {e}"))?;

    std::fs::create_dir_all(&plan.run_base)
        .map_err(|e| format!("frp run dir {}: {e}", plan.run_base.display()))?;
    let toml_path = plan.run_base.join("embedded").join("frpc.toml");
    // frpc.toml 可含服务端 token/凭证 ⇒ 0600 落盘（评审项 1；创建即收紧）。
    crate::write_private_file(&toml_path, plan.original_toml.as_bytes())
        .map_err(|e| format!("write {}: {e}", toml_path.display()))?;

    // 双栈声明（flock-frpc 的 FrpcBinaries 需两栈齐备；Original 路径只校验 original 侧，
    // chmlfrp 槽位在此模式恒不触碰——见 flock-frpc spec.rs validate_spec 的 match 分派）。
    let bins = FrpcBinaries {
        original: FrpcBinary {
            path: plan.frpc_bin.clone(),
            flavor: RelayFlavor::Original,
            decl_version: ORIGINAL_PINNED_VERSION.to_string(),
        },
        chmlfrp: FrpcBinary {
            path: plan.run_base.join("chmlfrpc-unused"),
            flavor: RelayFlavor::ChmlFrp,
            decl_version: CHMLFRP_PINNED_VERSION.to_string(),
        },
    };
    let mut cfg = SupervisorConfig::new(bins);
    cfg.run_base = plan.run_base.clone();
    let supervisor = Supervisor::new(cfg);
    let relay = supervisor
        .start(RelaySpec::Original { toml: toml_path })
        .await
        .map_err(|e| format!("frpc supervisor: {e}"))?;
    Ok((listener, Managed { relay }))
}

/// Frp 模式启动期自检（测试用：Supervisor 确实接管、run 目录已生成）。
pub fn run_dir_exists(run_base: &Path) -> bool {
    run_base.is_dir()
}
