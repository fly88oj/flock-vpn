//! Frp 模式装配（docs/design.md §2.1/§3.9/§5）。
//!
//! **本模块是 flock-server 唯一触碰 flock-frpc 类型的地方**（§3.11：仅 Frp 模式装配，
//! Direct 分支无 flock-frpc 类型引用——Direct 代码路径在 `server.rs` 的 accept/会话/控制流，
//! 不经过本文件）。职责：把 config 层 [`FrpPlan`]（自有类型）翻译成
//! `RelaySpec::Original{toml}` + `Supervisor`，并把内嵌 TOML 落到 run 目录。

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use flock_frpc::supervisor::{RelayPhase, Supervisor, SupervisorConfig};
use flock_frpc::{
    FrpcBinaries, FrpcBinary, ManagedRelay, RelayFlavor, RelaySpec, CHMLFRP_PINNED_VERSION,
    ORIGINAL_PINNED_VERSION,
};
use tokio::net::TcpListener;

use crate::config::FrpPlan;

/// 健康监控轮询间隔（评审项 11：低频 10s——对齐会话层 keepalive 节奏；RelayStatus
/// 读取是内存快照，无子进程开销）。
const HEALTH_POLL: Duration = Duration::from_secs(10);

/// 健康事件计数（admin stats 消费面）。
static RELAY_UNHEALTHY_EVENTS: AtomicU64 = AtomicU64::new(0);
static RELAY_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// 健康监控事件计数快照 `(unhealthy_events, recoveries)`（admin stats）。
pub fn relay_health_events() -> (u64, u64) {
    (
        RELAY_UNHEALTHY_EVENTS.load(Ordering::Relaxed),
        RELAY_RECOVERIES.load(Ordering::Relaxed),
    )
}

/// phase ⇒ 健康判定（Running = 健康；Starting/Backoff/Stopped = 不健康）。
fn phase_healthy(phase: &RelayPhase) -> bool {
    matches!(phase, RelayPhase::Running { .. })
}

/// Frp 模式的运行时句柄（包装 flock-frpc 类型；Drop 即托管拆除）。
pub struct Managed {
    relay: ManagedRelay,
}

impl Managed {
    /// 托管健康快照（诊断面）。
    pub fn health(&self) -> flock_frpc::RelayStatus {
        self.relay.health()
    }

    /// 低频健康监控（评审项 11）：每 [`HEALTH_POLL`] 轮询一次 [`Managed::health`]，
    /// 健康态迁移（健康→不健康 / 不健康→健康）eprintln 留痕并计数——不健康事件
    /// 与恢复均进 admin stats（[`relay_health_events`]）。任务随 Arc<Managed> 存亡。
    pub fn spawn_health_monitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let managed = self.clone();
        tokio::spawn(async move {
            let mut prev: Option<bool> = None;
            let mut tick = tokio::time::interval(HEALTH_POLL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let st = managed.health();
                let healthy = phase_healthy(&st.phase);
                match (prev, healthy) {
                    (Some(false), true) => {
                        RELAY_RECOVERIES.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "flock-server: frp relay 恢复（phase={:?} restarts={}）",
                            st.phase, st.restarts
                        );
                    }
                    (Some(true), false) => {
                        RELAY_UNHEALTHY_EVENTS.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "flock-server: frp relay 不健康（phase={:?} failures={} last_exit={:?}）",
                            st.phase, st.failures, st.last_exit
                        );
                    }
                    _ => {}
                }
                prev = Some(healthy);
            }
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 评审项 11：phase ⇒ 健康判定——Running 健康；Starting/Backoff/Stopped 不健康
    /// （Supervisor 的退避重试期按不健康上报，admin stats/日志面据此告警）。
    #[test]
    fn phase_health_classification() {
        use std::time::Duration as D;
        assert!(phase_healthy(&RelayPhase::Running { pid: 42 }));
        assert!(!phase_healthy(&RelayPhase::Starting));
        assert!(!phase_healthy(&RelayPhase::Backoff {
            restarts: 3,
            next_restart_in: D::from_secs(2),
        }));
        assert!(!phase_healthy(&RelayPhase::Stopped {
            reason: flock_frpc::StopReason::Manual,
        }));
    }
}
