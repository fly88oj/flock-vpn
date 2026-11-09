//! Frp-mode assembly (docs/design.md §2.1/§3.9/§5).
//!
//! **This module is the only place flock-server touches flock-frpc types**
//! (§3.11: Frp-mode assembly only; the Direct branch has no flock-frpc type
//! references —— the Direct code path is the accept/session/control-flow in
//! `server.rs` and never passes through this file). Responsibilities:
//! translate the config-layer [`FrpPlan`] (an own type) into
//! `RelaySpec::Original{toml}` + `Supervisor`, and persist the embedded TOML
//! into the run directory.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use flock_frpc::supervisor::{RelayPhase, Supervisor, SupervisorConfig};
use flock_frpc::{
    ChmlFrpMode, FrpcBinaries, FrpcBinary, ManagedRelay, RelayFlavor, RelaySpec,
    CHMLFRP_PINNED_VERSION, ORIGINAL_PINNED_VERSION,
};
use tokio::net::TcpListener;

use crate::config::FrpPlan;

/// Health-monitor polling interval (review item 11: low-frequency 10s ——
/// aligned with the session-layer keepalive cadence; RelayStatus reads are
/// in-memory snapshots with no subprocess cost).
const HEALTH_POLL: Duration = Duration::from_secs(10);

/// Health event counters (the admin stats consumption surface).
static RELAY_UNHEALTHY_EVENTS: AtomicU64 = AtomicU64::new(0);
static RELAY_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the health-monitor event counters `(unhealthy_events,
/// recoveries)` (admin stats).
pub fn relay_health_events() -> (u64, u64) {
    (
        RELAY_UNHEALTHY_EVENTS.load(Ordering::Relaxed),
        RELAY_RECOVERIES.load(Ordering::Relaxed),
    )
}

/// phase ⇒ health verdict (Running = healthy; Starting/Backoff/Stopped =
/// unhealthy).
fn phase_healthy(phase: &RelayPhase) -> bool {
    matches!(phase, RelayPhase::Running { .. })
}

/// The Frp-mode runtime handle (wrapping the flock-frpc types; Drop tears
/// the management down).
pub struct Managed {
    relay: ManagedRelay,
}

impl Managed {
    /// Managed health snapshot (diagnostics surface).
    pub fn health(&self) -> flock_frpc::RelayStatus {
        self.relay.health()
    }

    /// Low-frequency health monitoring (review item 11): poll
    /// [`Managed::health`] every [`HEALTH_POLL`]; health-state transitions
    /// (healthy→unhealthy / unhealthy→healthy) leave an eprintln trail and
    /// count —— unhealthy events and recoveries both feed admin stats
    /// ([`relay_health_events`]). The task lives and dies with the
    /// Arc<Managed>.
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
                            "flock-server: frp relay recovered (phase={:?} restarts={})",
                            st.phase, st.restarts
                        );
                    }
                    (Some(true), false) => {
                        RELAY_UNHEALTHY_EVENTS.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "flock-server: frp relay unhealthy (phase={:?} failures={} last_exit={:?})",
                            st.phase, st.failures, st.last_exit
                        );
                    }
                    _ => {}
                }
                prev = Some(healthy);
            }
        })
    }

    /// Explicit stop (Drop also stops —— the `kill_on_drop` semantics are
    /// guaranteed by flock-frpc).
    pub async fn stop(self) {
        let _ = self.relay.stop().await;
    }
}

/// Test exposure surface of [`chmlfrp_spec_of`] (the "config parsing →
/// RelaySpec construction" assertions of tests/listener_mode, review item
/// 14).
pub fn chmlfrp_spec_for_test(
    ini: &Option<std::path::PathBuf>,
    user_token_auto: &Option<crate::config::UserTokenAuto>,
) -> RelaySpec {
    chmlfrp_spec_of(ini, user_token_auto)
}

/// Config-layer ChmlFrp parameters → flock-frpc `RelaySpec::ChmlFrp` (review
/// item 14: ChmlFrp assembly wiring; a pure function —— the test assertion
/// surface). Defaults to `ConfigFile(ini)`; only an explicit
/// `user_token_auto` opt-in takes the `UserTokenAuto` path (the R20 risk is
/// documented upstream in flock-frpc).
fn chmlfrp_spec_of(
    ini: &Option<std::path::PathBuf>,
    user_token_auto: &Option<crate::config::UserTokenAuto>,
) -> RelaySpec {
    RelaySpec::ChmlFrp {
        mode: match user_token_auto {
            None => ChmlFrpMode::ConfigFile(
                ini.clone()
                    .expect("config layer already validated: chmlfrp_ini is required when user_token_auto is absent"),
            ),
            Some(uta) => ChmlFrpMode::UserTokenAuto {
                usertoken: uta.usertoken.clone(),
                tunnel_id: uta.tunnel_id,
            },
        },
    }
}

/// Frp-mode startup: bind the local listener + (for Original) persist the
/// embedded TOML + Supervisor-managed frpc of the corresponding stack
/// generation (review item 14: Original / ChmlFrp dual-generation dispatch).
///
/// The embedded TOML is written to `run_base/embedded/frpc.toml` (the
/// Supervisor only reads that file, §3.9).
pub async fn start(plan: FrpPlan, bind: SocketAddr) -> Result<(TcpListener, Managed), String> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("frp listener bind {bind}: {e}"))?;

    std::fs::create_dir_all(&plan.run_base)
        .map_err(|e| format!("frp run dir {}: {e}", plan.run_base.display()))?;
    // Dual-stack declaration (flock-frpc's FrpcBinaries requires both
    // generations present; only the generation matching plan.relay is
    // validated/used, the other slot is never touched —— see the match
    // dispatch in flock-frpc spec.rs validate_spec).
    let (spec, bins) = match &plan.relay {
        crate::config::FrpRelayPlan::Original { toml } => {
            let toml_path = plan.run_base.join("embedded").join("frpc.toml");
            // frpc.toml may contain server tokens/credentials ⇒ persisted
            // 0600 (review item 1; tightened at creation).
            crate::write_private_file(&toml_path, toml.as_bytes())
                .map_err(|e| format!("write {}: {e}", toml_path.display()))?;
            (
                RelaySpec::Original { toml: toml_path },
                FrpcBinaries {
                    original: FrpcBinary {
                        path: plan.frpc_bin.clone(),
                        flavor: RelayFlavor::Original,
                        decl_version: ORIGINAL_PINNED_VERSION.to_string(),
                    },
                    chmlfrp: unused_bin(&plan.run_base, RelayFlavor::ChmlFrp),
                },
            )
        }
        crate::config::FrpRelayPlan::ChmlFrp {
            ini,
            user_token_auto,
        } => (
            chmlfrp_spec_of(ini, user_token_auto),
            FrpcBinaries {
                original: unused_bin(&plan.run_base, RelayFlavor::Original),
                chmlfrp: FrpcBinary {
                    path: plan.frpc_bin.clone(),
                    flavor: RelayFlavor::ChmlFrp,
                    decl_version: CHMLFRP_PINNED_VERSION.to_string(),
                },
            },
        ),
    };
    let mut cfg = SupervisorConfig::new(bins);
    cfg.run_base = plan.run_base.clone();
    let supervisor = Supervisor::new(cfg);
    let relay = supervisor
        .start(spec)
        .await
        .map_err(|e| format!("frpc supervisor: {e}"))?;
    Ok((listener, Managed { relay }))
}

/// Placeholder binary declaration for the unused generation (that slot
/// participates in neither validation nor startup —— the R9 matrix dispatches
/// by spec).
fn unused_bin(run_base: &Path, flavor: RelayFlavor) -> FrpcBinary {
    FrpcBinary {
        path: run_base.join(match flavor {
            RelayFlavor::ChmlFrp => "chmlfrpc-unused",
            RelayFlavor::Original => "frpc-unused",
        }),
        flavor,
        decl_version: flavor.pinned_version().to_string(),
    }
}

// (Review item 15: the zero-reference dead item run_dir_exists was deleted ——
// startup-time self-checks are carried by the "run directory / embedded TOML
// persisted" assertions in tests/listener_mode.rs; the `Managed` wrapper
// stays: review item 11's health monitoring goes through its health().)

#[cfg(test)]
mod tests {
    use super::*;

    /// Review item 11: phase ⇒ health verdict —— Running healthy;
    /// Starting/Backoff/Stopped unhealthy (the Supervisor's backoff-retry
    /// period reports unhealthy, so admin stats/log surfaces can alert on
    /// it).
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
