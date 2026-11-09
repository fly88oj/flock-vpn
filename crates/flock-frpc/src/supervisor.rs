//! Process supervision (docs/design.md §3.9 implementation notes / §7-M2;
//! frp-compat §2.3, §4-R6).
//!
//! ChmlFrp frpc has a modded behavior of "after the control connection
//! drops, reconnect 3 times at 5s/10s/20s, and if still failing, **exit the
//! process**" (the original does infinite exponential backoff; the
//! frp-compat §2.3 diff table) ⇒ the supervision layer must watch for exits
//! and pull the process back up. This module = the monitor-restart loop
//! (exponential backoff) + the state machine ([`RelayPhase`]) + periodic
//! health probing ([`crate::probe`], targets derived read-only from the
//! config).
//!
//! Deep-module contract: callers see only `Supervisor::start(spec) ->
//! ManagedRelay` and `ManagedRelay::health()/stop()`; argv assembly, the
//! config copy, admin injection, and the log ring buffer are all kept inside.
//! The fake process stub (`src/bin/frpc_stub.rs`) supports the "3 exits → 3
//! restarts" unit tests (§7-M2 completion criteria).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::watch;

use crate::config::{self, AdminCommon};
use crate::probe::{run_probes, ProbeReport, ProbeTargets};
use crate::spec::{
    validate_spec, ChmlFrpMode, FrpcBinaries, FrpcBinary, FrpcError, RelayFlavor, RelaySpec,
};

const LOG_RING_CAP: usize = 512;

/// Restart backoff policy (exponential: `initial × multiplier^(n-1)`, capped
/// at `max`).
///
/// ChmlFrp frpc exits only after its own reconnect attempts are exhausted
/// (5+10+20=35s), so the `initial` here (default 1s) stacks on top of the
/// modded wait; `max_restarts = None` = supervise forever (the tunnel is the
/// server's lifeline).
///
/// `max` doubles as the **stability window**: a subprocess that survives
/// longer than `max` in one stretch counts as a successful epoch and the
/// failure count resets (mirroring the flock-client connector's
/// `Backoff::reset` "success resets" semantics) — otherwise, after a
/// long-running server has a few sporadic crashes, every restart pays the
/// capped `max` (default 60s) blackout.
#[derive(Clone, Debug)]
pub struct RestartPolicy {
    pub initial: Duration,
    pub multiplier: f64,
    pub max: Duration,
    pub max_restarts: Option<u32>,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            multiplier: 2.0,
            max: Duration::from_secs(60),
            max_restarts: None,
        }
    }
}

impl RestartPolicy {
    /// Backoff duration after the `restarts`-th exit (restarts ≥ 1).
    pub fn delay_for(&self, restarts: u32) -> Duration {
        let exp = (restarts.saturating_sub(1)) as f64;
        let factor = self.multiplier.powf(exp);
        let ms = (self.initial.as_millis() as f64 * factor).round() as u64;
        self.max.min(Duration::from_millis(ms))
    }
}

/// Health probing policy.
#[derive(Clone, Debug)]
pub struct HealthPolicy {
    /// Probe interval (default 5s).
    pub probe_interval: Duration,
    /// Single-probe timeout (default 2s).
    pub probe_timeout: Duration,
    /// ChmlFrp `ConfigFile` mode: inject the four admin keys into the
    /// supervised copy's `[common]` (within the R12 red line: proxy sections
    /// pass through byte for byte), making the admin probe usable.
    pub inject_admin: Option<AdminCommon>,
    /// Explicitly specify the local tunnel port probe address (overrides
    /// what is derived from the config; in UserTokenAuto mode the config is
    /// opaque to the supervision layer, so it can only be given explicitly).
    pub probe_local_tunnel: Option<SocketAddr>,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(2),
            inject_admin: None,
            probe_local_tunnel: None,
        }
    }
}

/// Supervisor construction parameters.
#[derive(Clone, Debug)]
pub struct SupervisorConfig {
    /// The dual-stack pinned binary table (the R9 matrix check target).
    pub bins: FrpcBinaries,
    /// Restart backoff policy.
    pub restart: RestartPolicy,
    /// Health probing policy.
    pub health: HealthPolicy,
    /// Per-relay run-directory base (where the supervised config copy/logs
    /// land; default is the system temp directory).
    pub run_base: PathBuf,
}

impl SupervisorConfig {
    pub fn new(bins: FrpcBinaries) -> Self {
        Self {
            bins,
            restart: RestartPolicy::default(),
            health: HealthPolicy::default(),
            run_base: std::env::temp_dir().join("flock-frpc"),
        }
    }
}

/// Relay lifecycle phase (the backbone of the `health()` snapshot).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayPhase {
    /// Subprocess spawned; stable running not yet observed.
    Starting,
    /// Subprocess running.
    Running { pid: u32 },
    /// Subprocess exited; backing off before the next restart.
    Backoff {
        restarts: u32,
        next_restart_in: Duration,
    },
    /// Terminal (manual stop / restart budget exhausted).
    Stopped { reason: StopReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// `stop()` called (including the Drop signal).
    Manual,
    /// `max_restarts` exhausted.
    RestartsExhausted,
}

/// A record of one subprocess exit.
#[derive(Clone, Debug)]
pub struct ExitRecord {
    pub code: Option<i32>,
    pub success: bool,
    pub at: Instant,
}

/// The full return of `ManagedRelay::health()`.
#[derive(Clone, Debug)]
pub struct RelayStatus {
    pub flavor: RelayFlavor,
    pub phase: RelayPhase,
    /// Cumulative restart count (= restarts − 1).
    pub restarts: u32,
    /// The current backoff-exponent input (both real exits and failed-restart
    /// retries count; resets after running stably longer than
    /// [`RestartPolicy::max`] — a diagnostics surface; backoff durations are
    /// driven by it).
    pub failures: u32,
    /// The most recent subprocess exit.
    pub last_exit: Option<ExitRecord>,
    /// The most recent health probe round (None when unconfigured / before
    /// the first round completes).
    pub probe: Option<ProbeReport>,
    /// The supervised directory of this relay (the config copy).
    pub run_dir: PathBuf,
}

struct Inner {
    flavor: RelayFlavor,
    run_dir: PathBuf,
    state: Mutex<StateSnap>,
    shutdown_tx: watch::Sender<bool>,
}

#[derive(Default)]
struct StateSnap {
    phase: Option<RelayPhase>,
    restarts: u32,
    failures: u32,
    last_exit: Option<ExitRecord>,
    probe: Option<ProbeReport>,
    logs: VecDeque<String>,
}

impl Inner {
    fn set_phase(&self, phase: RelayPhase) {
        self.state.lock().unwrap().phase = Some(phase);
    }

    fn push_log(&self, line: String) {
        let mut st = self.state.lock().unwrap();
        if st.logs.len() == LOG_RING_CAP {
            st.logs.pop_front();
        }
        st.logs.push_back(line);
    }
}

/// The supervisor: pulls up and supervises one frpc per [`RelaySpec`] (the
/// §3.9 interface).
pub struct Supervisor {
    cfg: SupervisorConfig,
    relay_seq: AtomicU64,
}

impl Supervisor {
    pub fn new(cfg: SupervisorConfig) -> Self {
        Self {
            cfg,
            relay_seq: AtomicU64::new(0),
        }
    }

    /// Validate the spec (including the R9 matrix lock) → prepare the
    /// supervised config → first spawn → start the supervision/probe tasks.
    ///
    /// A first-spawn failure (binary missing etc.) returns `Err` immediately;
    /// later exits are handled by the supervision loop per the backoff
    /// policy.
    pub async fn start(&self, spec: RelaySpec) -> Result<ManagedRelay, FrpcError> {
        let validated = validate_spec(&spec, &self.cfg.bins)?;

        if !validated.bin.path.is_file() {
            return Err(FrpcError::Spawn(format!(
                "frpc binary does not exist: {}",
                validated.bin.path.display()
            )));
        }

        let run_dir = self.alloc_run_dir(validated.bin.flavor);
        std::fs::create_dir_all(&run_dir)?;
        let plan = self.prepare_plan(&validated.spec, &run_dir)?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let inner = Arc::new(Inner {
            flavor: validated.bin.flavor,
            run_dir: run_dir.clone(),
            state: Mutex::new(StateSnap {
                phase: Some(RelayPhase::Starting),
                ..StateSnap::default()
            }),
            shutdown_tx,
        });

        // First spawn (fail-fast; later exits go through the supervision
        // loop).
        let mut child = spawn_child(&plan)?;
        inner.set_phase(RelayPhase::Running {
            pid: child.id().unwrap_or(0),
        });
        let logs = child_pipes_to_ring(&mut child, &inner);

        let has_probe_targets = plan.targets.admin.is_some() || plan.targets.local_tunnel.is_some();
        let probe_targets = plan.targets.clone();
        let task = tokio::spawn(supervise_loop(
            Arc::clone(&inner),
            plan,
            Some(child),
            logs,
            self.cfg.restart.clone(),
            shutdown_rx.clone(),
        ));

        let prober = if has_probe_targets {
            Some(tokio::spawn(probe_loop(
                Arc::clone(&inner),
                probe_targets,
                self.cfg.health.clone(),
                shutdown_rx,
            )))
        } else {
            None
        };

        Ok(ManagedRelay {
            inner,
            task: Some(task),
            prober,
        })
    }

    /// Allocate the per-relay run directory (flavor-pid-nanos-seq unique).
    ///
    /// Retention policy: `stop()` does **not** clean up the run directory —
    /// the diagnostics surface (supervised config copy / stub marker / logs)
    /// must remain inspectable after the process dies; multiple restarts of
    /// one relay (backoff re-spawns) reuse the same run_dir, and the
    /// frpc.ini copy is **overwritten** (deterministic content, no
    /// information lost by overwriting); directories are unique across
    /// relays and never overwrite each other. Accumulated cleanup is left to
    /// operations (run_base lives on a temp/supervised partition).
    fn alloc_run_dir(&self, flavor: RelayFlavor) -> PathBuf {
        let seq = self.relay_seq.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        self.cfg
            .run_base
            .join(format!("{}-{}-{nanos}-{seq}", flavor, std::process::id()))
    }

    /// Assemble the startup plan: argv/cwd + probe targets.
    fn prepare_plan(&self, spec: &RelaySpec, run_dir: &Path) -> Result<StartPlan, FrpcError> {
        let bin = match spec.flavor() {
            RelayFlavor::ChmlFrp => self.cfg.bins.chmlfrp.clone(),
            RelayFlavor::Original => self.cfg.bins.original.clone(),
        };
        let health = &self.cfg.health;
        match spec {
            RelaySpec::ChmlFrp { mode } => match mode {
                ChmlFrpMode::ConfigFile(ini_path) => {
                    // Supervised copy: panel proxy parameters pass through
                    // byte for byte; optional admin injection ([common] only,
                    // within the R12 red line).
                    let panel = std::fs::read_to_string(ini_path).map_err(|e| {
                        FrpcError::Config(format!(
                            "failed to read panel frpc.ini {}: {e}",
                            ini_path.display()
                        ))
                    })?;
                    let managed = match &health.inject_admin {
                        Some(admin) => config::augment_chmlfrp_admin(&panel, admin)?,
                        None => panel,
                    };
                    let managed_path = run_dir.join("frpc.ini");
                    std::fs::write(&managed_path, &managed)?;
                    // The copy embeds the panel token ⇒ owner read/write is
                    // enough (unix; umask cannot be relied upon — explicitly
                    // tightened 0644→0600. Windows has no such permission
                    // surface; skipped).
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(
                            &managed_path,
                            std::fs::Permissions::from_mode(0o600),
                        )?;
                    }
                    let parsed = config::parse_ini(&managed).map_err(|e| {
                        FrpcError::Config(format!(
                            "supervised copy unparseable (internal error): {e}"
                        ))
                    })?;
                    let mut targets = config::chmlfrp_probe_targets(&parsed);
                    if let Some(explicit) = health.probe_local_tunnel {
                        targets.local_tunnel = Some(explicit);
                    }
                    Ok(StartPlan {
                        bin,
                        argv: vec!["-c".to_string(), argv_path(&managed_path)?],
                        cwd: run_dir.to_path_buf(),
                        targets,
                    })
                }
                ChmlFrpMode::UserTokenAuto {
                    usertoken,
                    tunnel_id,
                } => {
                    // -u/-p bootstrap: frpc itself fetches the config via the
                    // cfg API and overwrites ./frpc.ini (root.go:151-158
                    // writes cfgFile, default ./frpc.ini relative to cwd) ⇒
                    // the cwd must be writable. The config is opaque to the
                    // supervision layer ⇒ probing is left with only the
                    // explicitly specified local tunnel port (the admin
                    // cannot be predicted).
                    Ok(StartPlan {
                        bin,
                        argv: vec![
                            "-u".to_string(),
                            usertoken.clone(),
                            "-p".to_string(),
                            tunnel_id.to_string(),
                        ],
                        cwd: run_dir.to_path_buf(),
                        targets: ProbeTargets {
                            admin: None,
                            local_tunnel: health.probe_local_tunnel,
                        },
                    })
                }
            },
            RelaySpec::Original { toml } => {
                // The caller's TOML is read-only: argv points at the original
                // file directly, never rewritten.
                let abs = absolute(toml);
                let table = config::parse_original_toml(&abs)?;
                let mut targets = config::original_probe_targets(&table);
                if let Some(explicit) = health.probe_local_tunnel {
                    targets.local_tunnel = Some(explicit);
                }
                Ok(StartPlan {
                    bin,
                    argv: vec!["-c".to_string(), argv_path(&abs)?],
                    cwd: run_dir.to_path_buf(),
                    targets,
                })
            }
        }
    }
}

/// The startup plan (argv/cwd frozen as a snapshot at spawn time; probe
/// targets frozen with it).
struct StartPlan {
    bin: FrpcBinary,
    argv: Vec<String>,
    cwd: PathBuf,
    targets: ProbeTargets,
}

fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    }
}

/// Path → argv parameter (all config paths in this crate come from the UTF-8
/// world; non-UTF-8 fails explicitly here).
fn argv_path(p: &Path) -> Result<String, FrpcError> {
    p.to_str().map(str::to_string).ok_or_else(|| {
        FrpcError::Config(format!(
            "path is not UTF-8, cannot use as argv: {}",
            p.display()
        ))
    })
}

fn spawn_child(plan: &StartPlan) -> Result<Child, FrpcError> {
    let mut cmd = Command::new(&plan.bin.path);
    cmd.args(&plan.argv)
        .current_dir(&plan.cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    cmd.spawn()
        .map_err(|e| FrpcError::Spawn(format!("spawn {} failed: {e}", plan.bin.path.display())))
}

struct ChildLogs {
    _stdout: tokio::task::JoinHandle<()>,
    _stderr: tokio::task::JoinHandle<()>,
}

/// Pipe the subprocess's stdout/stderr line by line into the ring buffer
/// (prevents a full pipe from deadlocking; for diagnostics, read via
/// `logs()`).
fn child_pipes_to_ring(child: &mut Child, inner: &Arc<Inner>) -> ChildLogs {
    let out = {
        let inner = Arc::clone(inner);
        let stdout = child.stdout.take();
        tokio::spawn(async move {
            if let Some(stdout) = stdout {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    inner.push_log(line);
                }
            }
        })
    };
    let err = {
        let inner = Arc::clone(inner);
        let stderr = child.stderr.take();
        tokio::spawn(async move {
            if let Some(stderr) = stderr {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    inner.push_log(line);
                }
            }
        })
    };
    ChildLogs {
        _stdout: out,
        _stderr: err,
    }
}

async fn supervise_loop(
    inner: Arc<Inner>,
    plan: StartPlan,
    mut child: Option<Child>,
    _logs: ChildLogs,
    policy: RestartPolicy,
    shutdown_rx: watch::Receiver<bool>,
) {
    // restarts = successful spawn count (presented by health(), one-to-one
    // with real subprocesses); failures = the backoff-exponent input (both
    // real exits and "failed-restart retries" count) — the two are separated
    // so a spawn failure cannot inflate restarts without a corresponding
    // process (and to avoid double-waiting an already-reaped Child). The
    // stable reset of failures (mirroring the connector's Backoff::reset
    // "success resets"): once a subprocess survives longer than the maximum
    // backoff (policy.max) it resets — sporadic crashes each get independent
    // backoff, so a long-running server doesn't pay the capped 60s blackout
    // on every restart.
    let mut restarts: u32 = 0;
    let mut failures: u32 = 0;
    // The current subprocess's start moment (the stability-window clock
    // base; None during failed-restart retries when there is no process).
    let mut stable_since: Option<Instant> = if child.is_some() {
        Some(Instant::now())
    } else {
        None
    };
    loop {
        // Wait for "subprocess exit", "stability window reached", or
        // "shutdown". wait() happens only on a live, unreaped subprocess
        // (`child = None` = last spawn failed, no process to wait for; go
        // straight to backoff retry).
        let exit = if let Some(c) = child.as_mut() {
            // Remaining stability-window duration (meaningful only when
            // failures>0 and a start moment exists; otherwise this arm pends
            // forever).
            let stable_in = match stable_since {
                Some(t0) if failures > 0 => Some(policy.max.saturating_sub(t0.elapsed())),
                _ => None,
            };
            let stability = async {
                match stable_in {
                    Some(remain) => tokio::time::sleep(remain).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                status = c.wait() => Some(status.ok()),
                _ = stability => {
                    // Stability reached: failures reset (this arm then pends
                    // forever, back to waiting for exit).
                    failures = 0;
                    inner.state.lock().unwrap().failures = 0;
                    continue;
                }
                _ = shutdown_changed(&shutdown_rx) => None,
            }
        } else {
            let delay = policy.delay_for(failures.max(1));
            tokio::select! {
                _ = tokio::time::sleep(delay) => Some(None), // pseudo-event: retry the spawn
                _ = shutdown_changed(&shutdown_rx) => None,
            }
        };

        let Some(exit) = exit else {
            // Shutdown: kill the process, reap it, land on Stopped.
            if let Some(mut c) = child.take() {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            inner.set_phase(RelayPhase::Stopped {
                reason: StopReason::Manual,
            });
            return;
        };

        // Only real exits record an ExitRecord (pseudo-events do not
        // overwrite the last real exit record). exit = Some(status): the
        // subprocess really exited (the select arm already folded wait()'s
        // io failure into the pseudo-event None — this loop never
        // double-waits a reaped Child, so that failure is actually
        // unreachable).
        if let Some(status) = exit {
            let mut st = inner.state.lock().unwrap();
            st.last_exit = Some(ExitRecord {
                code: status.code(),
                success: status.success(),
                at: Instant::now(),
            });
        }

        failures = failures.saturating_add(1);
        inner.state.lock().unwrap().failures = failures;
        if let Some(max) = policy.max_restarts {
            if failures > max {
                inner.set_phase(RelayPhase::Stopped {
                    reason: StopReason::RestartsExhausted,
                });
                return;
            }
        }
        let delay = policy.delay_for(failures);
        inner.set_phase(RelayPhase::Backoff {
            restarts,
            next_restart_in: delay,
        });
        let slept = tokio::select! {
            _ = tokio::time::sleep(delay) => true,
            _ = shutdown_changed(&shutdown_rx) => false,
        };
        if !slept {
            inner.set_phase(RelayPhase::Stopped {
                reason: StopReason::Manual,
            });
            return;
        }
        // Re-spawn: success ⇒ restarts+1 and back to the "live process"
        // shape; failure ⇒ child=None, and the next round retries after the
        // same backoff cadence (supervision does not give up lightly).
        match spawn_child(&plan) {
            Ok(mut next) => {
                restarts += 1;
                stable_since = Some(Instant::now());
                let _logs = child_pipes_to_ring(&mut next, &inner);
                child = Some(next);
                let mut st = inner.state.lock().unwrap();
                st.restarts = restarts;
                st.phase = Some(RelayPhase::Running {
                    pid: child.as_ref().and_then(|c| c.id()).unwrap_or(0),
                });
            }
            Err(e) => {
                child = None;
                stable_since = None;
                inner.push_log(format!("[supervisor] re-spawn failed: {e}"));
            }
        }
    }
}

/// An awaitable future for the watch "shutdown requested" signal (only the
/// false→true edge; an initial true returns immediately).
async fn shutdown_changed(rx: &watch::Receiver<bool>) {
    let mut rx = rx.clone();
    if !*rx.borrow_and_update() {
        let _ = rx.changed().await;
    }
}

async fn probe_loop(
    inner: Arc<Inner>,
    targets: ProbeTargets,
    health: HealthPolicy,
    shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        let report = run_probes(&targets, health.probe_timeout).await;
        inner.state.lock().unwrap().probe = Some(report);
        tokio::select! {
            _ = tokio::time::sleep(health.probe_interval) => {}
            _ = shutdown_changed(&shutdown_rx) => return,
        }
    }
}

/// One supervised relay (the other half of the §3.9 interface).
pub struct ManagedRelay {
    inner: Arc<Inner>,
    task: Option<tokio::task::JoinHandle<()>>,
    prober: Option<tokio::task::JoinHandle<()>>,
}

impl ManagedRelay {
    /// Health snapshot: process phase + restart/failure counters + last exit
    /// + last probe (§3.9 `health()`).
    pub fn health(&self) -> RelayStatus {
        let st = self.inner.state.lock().unwrap();
        RelayStatus {
            flavor: self.inner.flavor,
            phase: st.phase.clone().unwrap_or(RelayPhase::Starting),
            restarts: st.restarts,
            failures: st.failures,
            last_exit: st.last_exit.clone(),
            probe: st.probe.clone(),
            run_dir: self.inner.run_dir.clone(),
        }
    }

    /// Snapshot of the subprocess output ring buffer (diagnostics).
    pub fn logs(&self) -> Vec<String> {
        self.inner
            .state
            .lock()
            .unwrap()
            .logs
            .iter()
            .cloned()
            .collect()
    }

    /// Manual stop: kill the current subprocess (or cancel the pending
    /// restart inside the backoff window) and wait for the tasks to wind
    /// down.
    pub async fn stop(mut self) -> Result<RelayStatus, FrpcError> {
        let _ = self.inner.shutdown_tx.send(true);
        if let Some(p) = self.prober.take() {
            let _ = p.await;
        }
        if let Some(t) = self.task.take() {
            if t.await.is_err() {
                return Err(FrpcError::Spawn(
                    "supervision task terminated abnormally (panic)".into(),
                ));
            }
        }
        Ok(self.health())
    }
}

impl Drop for ManagedRelay {
    fn drop(&mut self) {
        // Drop sends the shutdown signal (while the runtime lives, the
        // supervision task kills the process and cleans up on its own); for
        // deterministic stop semantics, call `stop().await` explicitly.
        let _ = self.inner.shutdown_tx.send(true);
    }
}
