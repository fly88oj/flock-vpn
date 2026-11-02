//! 进程守护（docs/design.md §3.9 实现要点 / §7-M2；frp-compat §2.3、§4-R6）。
//!
//! ChmlFrp frpc 有「控制连接断开后按 5s/10s/20s 重连 3 次、仍失败即**退出进程**」的
//! 魔改行为（原版为无限指数退避；frp-compat §2.3 diff 表）⇒ 托管层必须监控退出并拉起。
//! 本模块 = 监控-重启循环（指数退避）+ 状态机（[`RelayPhase`]）+ 周期健康探测
//! （[`crate::probe`]，目标从配置只读推导）。
//!
//! 深模块契约：调用方只见 `Supervisor::start(spec) -> ManagedRelay` 与
//! `ManagedRelay::health()/stop()`；argv 组装、配置副本、admin 注入、日志环形缓冲
//! 全部内藏。假进程桩（`src/bin/frpc_stub.rs`）支撑「3 退→3 拉」单测（§7-M2 完成标准）。

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

/// 重启退避策略（指数：`initial × multiplier^(n-1)`，封顶 `max`）。
///
/// ChmlFrp frpc 自身重连耗尽（5+10+20=35s）后才退出，故这里的 `initial`（默认 1s）
/// 叠加在魔改等待之上；`max_restarts = None` = 永久守护（隧道是服务端生命线）。
///
/// `max` 兼任**稳定窗口**：子进程一次存活超过 `max` 即视为一个成功纪元，失败计数
/// 归零（对照 flock-client connector 的 `Backoff::reset`「成功即归零」语义）——
/// 否则长期服务端偶发数次 crash 后，每次重启都顶格 `max`（默认 60s）空窗。
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
    /// 第 `restarts` 次退出后的退避时长（restarts ≥ 1）。
    pub fn delay_for(&self, restarts: u32) -> Duration {
        let exp = (restarts.saturating_sub(1)) as f64;
        let factor = self.multiplier.powf(exp);
        let ms = (self.initial.as_millis() as f64 * factor).round() as u64;
        self.max.min(Duration::from_millis(ms))
    }
}

/// 健康探测策略。
#[derive(Clone, Debug)]
pub struct HealthPolicy {
    /// 探测周期（默认 5s）。
    pub probe_interval: Duration,
    /// 单项探测超时（默认 2s）。
    pub probe_timeout: Duration,
    /// ChmlFrp `ConfigFile` 模式：向托管副本的 `[common]` 注入 admin 四键
    /// （R12 红线内：proxy 节字节透传），使 admin 探测可用。
    pub inject_admin: Option<AdminCommon>,
    /// 显式指定本地隧道口探测地址（覆盖从配置推导的结果；UserTokenAuto 模式配置对
    /// 托管层不透明，只能显式给）。
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

/// 托管器构造参数。
#[derive(Clone, Debug)]
pub struct SupervisorConfig {
    /// 双栈定版二进制表（R9 矩阵校验对象）。
    pub bins: FrpcBinaries,
    /// 重启退避策略。
    pub restart: RestartPolicy,
    /// 健康探测策略。
    pub health: HealthPolicy,
    /// 每路中继的 run 目录基点（托管配置副本/日志落点；默认系统临时目录）。
    pub run_base: PathBuf,
    /// 启动期执行 `--version` 实测核对二进制声明（默认关：多一次子进程往返）。
    pub verify_version_at_start: bool,
}

impl SupervisorConfig {
    pub fn new(bins: FrpcBinaries) -> Self {
        Self {
            bins,
            restart: RestartPolicy::default(),
            health: HealthPolicy::default(),
            run_base: std::env::temp_dir().join("flock-frpc"),
            verify_version_at_start: false,
        }
    }
}

/// 中继生命周期阶段（`health()` 快照的主干）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayPhase {
    /// 子进程已 spawn、尚未观测到运行稳定。
    Starting,
    /// 子进程在运行。
    Running { pid: u32 },
    /// 子进程退出，退避等待下一次拉起。
    Backoff {
        restarts: u32,
        next_restart_in: Duration,
    },
    /// 终止（手动停止 / 重启额度耗尽）。
    Stopped { reason: StopReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// `stop()` 调用（含 Drop 信号）。
    Manual,
    /// `max_restarts` 耗尽。
    RestartsExhausted,
}

/// 子进程一次退出的记录。
#[derive(Clone, Debug)]
pub struct ExitRecord {
    pub code: Option<i32>,
    pub success: bool,
    pub at: Instant,
}

/// `ManagedRelay::health()` 的完整返回。
#[derive(Clone, Debug)]
pub struct RelayStatus {
    pub flavor: RelayFlavor,
    pub phase: RelayPhase,
    /// 累计重启次数（= 拉起次数 - 1）。
    pub restarts: u32,
    /// 当前退避指数输入（真实退出与拉起失败重试都计；稳定运行超过
    /// [`RestartPolicy::max`] 后归零——诊断面，退避时长由它驱动）。
    pub failures: u32,
    /// 最近一次子进程退出。
    pub last_exit: Option<ExitRecord>,
    /// 最近一轮健康探测（未配置/首轮未完成时为 None）。
    pub probe: Option<ProbeReport>,
    /// 本路中继的托管目录（配置副本）。
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

/// 托管器：按 [`RelaySpec`] 拉起并守护一路 frpc（§3.9 接口）。
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

    /// 校验 spec（含 R9 矩阵锁）→ 准备托管配置 → 首次 spawn → 启动守护/探测任务。
    ///
    /// 首次 spawn 失败（二进制缺失等）立即返回 `Err`；之后的退出由守护循环按退避策略拉起。
    pub async fn start(&self, spec: RelaySpec) -> Result<ManagedRelay, FrpcError> {
        let validated = validate_spec(&spec, &self.cfg.bins)?;

        if self.cfg.verify_version_at_start {
            validated.bin.verify_declared().await?;
        }
        if !validated.bin.path.is_file() {
            return Err(FrpcError::Spawn(format!(
                "frpc 二进制不存在: {}",
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

        // 首次 spawn（fail-fast；之后的退出走守护循环）
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

    /// 组装启动计划：argv/cwd + 探测目标。
    fn prepare_plan(&self, spec: &RelaySpec, run_dir: &Path) -> Result<StartPlan, FrpcError> {
        let bin = match spec.flavor() {
            RelayFlavor::ChmlFrp => self.cfg.bins.chmlfrp.clone(),
            RelayFlavor::Original => self.cfg.bins.original.clone(),
        };
        let health = &self.cfg.health;
        match spec {
            RelaySpec::ChmlFrp { mode } => match mode {
                ChmlFrpMode::ConfigFile(ini_path) => {
                    // 托管副本：面板 proxy 参数字节透传；可选注入 admin（仅 [common]，R12 红线内）。
                    let panel = std::fs::read_to_string(ini_path).map_err(|e| {
                        FrpcError::Config(format!(
                            "读取面板 frpc.ini 失败 {}: {e}",
                            ini_path.display()
                        ))
                    })?;
                    let managed = match &health.inject_admin {
                        Some(admin) => config::augment_chmlfrp_admin(&panel, admin)?,
                        None => panel,
                    };
                    let managed_path = run_dir.join("frpc.ini");
                    std::fs::write(&managed_path, &managed)?;
                    let parsed = config::parse_ini(&managed).map_err(|e| {
                        FrpcError::Config(format!("托管副本不可解析（内部错误）: {e}"))
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
                    // -u/-p 自举：frpc 自行经 cfg API 拉配置并覆写 ./frpc.ini（root.go:151-158
                    // 写 cfgFile，默认 ./frpc.ini 相对 cwd）⇒ cwd 必须可写。
                    // 配置对托管层不透明 ⇒ 探测只剩显式指定的本地隧道口（admin 无法预知）。
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
                // 调用方 TOML 只读：argv 直指原文件，绝不改写。
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

/// 启动计划（argv/cwd 以 spawn 时刻快照固化；探测目标随之冻结）。
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

/// 路径 → argv 参数（本 crate 配置路径均来自 UTF-8 世界；非 UTF-8 在此显式失败）。
fn argv_path(p: &Path) -> Result<String, FrpcError> {
    p.to_str()
        .map(str::to_string)
        .ok_or_else(|| FrpcError::Config(format!("路径非 UTF-8，无法作为 argv: {}", p.display())))
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
        .map_err(|e| FrpcError::Spawn(format!("spawn {} 失败: {e}", plan.bin.path.display())))
}

struct ChildLogs {
    _stdout: tokio::task::JoinHandle<()>,
    _stderr: tokio::task::JoinHandle<()>,
}

/// 子进程 stdout/stderr 逐行入环形缓冲（防管道塞满致死锁；诊断用，`logs()` 取阅）。
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
    // restarts = 成功拉起次数（health() 呈现，与真实子进程一一对应）；
    // failures = 退避指数输入（真实退出与「拉起失败重试」都计）——两者分离，
    // 防止 spawn 失败把 restarts 顶高而无对应进程（也避免对已收割 Child 重复 wait）。
    // failures 的稳定复位（对照 connector 的 Backoff::reset「成功即归零」）：子进程
    // 一次存活超过最大退避时长（policy.max）即归零——偶发 crash 各自独立计退避，
    // 不至于长期运行后每次重启都顶格 60s 空窗。
    let mut restarts: u32 = 0;
    let mut failures: u32 = 0;
    // 当前子进程的起跑时刻（稳定窗口计时基准；拉起失败重试期间无进程 ⇒ None）。
    let mut stable_since: Option<Instant> = if child.is_some() {
        Some(Instant::now())
    } else {
        None
    };
    loop {
        // 等待「子进程退出」「稳定窗口达标」或「停机」。wait() 只发生在活的、未收割的
        // 子进程上（`child = None` = 上轮拉起失败，无进程可等，直接走退避重试）。
        let exit = if let Some(c) = child.as_mut() {
            // 稳定窗口剩余时长（failures>0 且有起跑时刻才有意义，否则该臂永久挂起）。
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
                    // 稳定达标：failures 归零（复位后该臂转永久挂起，回到等待退出）。
                    failures = 0;
                    inner.state.lock().unwrap().failures = 0;
                    continue;
                }
                _ = shutdown_changed(&shutdown_rx) => None,
            }
        } else {
            let delay = policy.delay_for(failures.max(1));
            tokio::select! {
                _ = tokio::time::sleep(delay) => Some(None), // 伪事件：重试拉起
                _ = shutdown_changed(&shutdown_rx) => None,
            }
        };

        let Some(exit) = exit else {
            // 停机：杀进程、收尸、落 Stopped
            if let Some(mut c) = child.take() {
                let _ = c.kill().await;
                let _ = c.wait().await;
            }
            inner.set_phase(RelayPhase::Stopped {
                reason: StopReason::Manual,
            });
            return;
        };

        // 真退出才记 ExitRecord（伪事件不覆盖上一次真实退出记录）。
        // exit = Some(status)：子进程真退出（select 臂已把 wait() 的 io 失败折叠为
        // 伪事件 None——本循环从不对已收割 Child 重复 wait，该失败实际不可达）。
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
        // 重新拉起：成功 ⇒ restarts+1 并回到「有活进程」形态；
        // 失败 ⇒ child=None，下一轮以同节奏退避后重试（守护不轻言放弃）。
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
                inner.push_log(format!("[supervisor] 重新拉起失败: {e}"));
            }
        }
    }
}

/// watch「已停机」信号的可等待 future（仅 false→true 边沿；初始 true 立即返回）。
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

/// 一路被托管的中继（§3.9 接口的另一半）。
pub struct ManagedRelay {
    inner: Arc<Inner>,
    task: Option<tokio::task::JoinHandle<()>>,
    prober: Option<tokio::task::JoinHandle<()>>,
}

impl ManagedRelay {
    /// 健康快照：进程阶段 + 重启/失败计数 + 最近退出 + 最近探测（§3.9 `health()`）。
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

    /// 子进程输出环形缓冲快照（诊断）。
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

    /// 手动停止：杀当前子进程（或在退避窗口内取消拉起）并等待任务收尾。
    pub async fn stop(mut self) -> Result<RelayStatus, FrpcError> {
        let _ = self.inner.shutdown_tx.send(true);
        if let Some(p) = self.prober.take() {
            let _ = p.await;
        }
        if let Some(t) = self.task.take() {
            if t.await.is_err() {
                return Err(FrpcError::Spawn("守护任务异常终止（panic）".into()));
            }
        }
        Ok(self.health())
    }
}

impl Drop for ManagedRelay {
    fn drop(&mut self) {
        // Drop 即发停机信号（运行时存活期间守护任务自行杀进程收尾）；
        // 需要确定性的停止语义请显式 `stop().await`。
        let _ = self.inner.shutdown_tx.send(true);
    }
}
