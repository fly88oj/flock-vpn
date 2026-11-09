//! Process supervision tests (§7-M2 completion criteria; frp-compat
//! §2.3/§4-R6).
//!
//! Unit tests using the fake process stub (`src/bin/frpc_stub.rs`, invoked
//! via `CARGO_BIN_EXE_frpc_stub`):
//!
//! - **3 exits → 3 restarts**: ChmlFrp frpc's modded "exit the process after
//!   three failed reconnects" behavior is held up by the supervision loop —
//!   the stub exits repeatedly; assert the restart count and the exponential
//!   backoff lower bounds (each round's backoff ≥ initial×2^n; scheduling
//!   only delays, never advances ⇒ the lower-bound assertions are stable);
//! - **stop semantics**: `stop()` kills the current subprocess, lands on
//!   `Stopped{Manual}`, and nothing is re-spawned afterwards;
//! - **restart budget**: `max_restarts` exhausted → `Stopped{
//!   RestartsExhausted}`;
//! - **health probing**: local tunnel port + frpc admin (the serve stub's
//!   HTTP 200 surface);
//! - **argv characterization**: `-c` (ConfigFile/Original) and `-u/-p`
//!   (UserTokenAuto) reach the subprocess;
//! - **R12 end-to-end**: the supervised copy's proxy section is byte-for-byte
//!   identical to the panel input; admin enters `[common]` only.
//!
//! The stub's behavior is selected by the `[stub]` section appended to the
//! test config file (`mode`/`lifetime_ms`); the marker lands in the
//! supervised run_dir (unique per relay).

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

// Backoff cadence (millisecond scale, compressing total runtime; assertions
// rely only on lower bounds — scheduling delay only widens intervals, never
// narrows them).
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

/// The panel ini sample + a `[stub]` behavior section (appended as a new
/// section; the proxy section itself untouched).
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

/// Marker event lines: `(kind, unix_ms, extra)` — extra is the remainder of
/// the line (the argument string on argv lines, the listen address on serve
/// lines).
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

/// Poll until cumulative restarts ≥ want; returns the run_dir (where the
/// marker lands).
async fn wait_until_restarts(relay: &ManagedRelay, want: u32, timeout: Duration) -> PathBuf {
    let deadline = Instant::now() + timeout;
    loop {
        let status = relay.health();
        if let RelayPhase::Stopped { reason } = &status.phase {
            panic!(
                "relay stopped prematurely: {reason:?} (restarts={})",
                status.restarts
            );
        }
        if status.restarts >= want {
            return status.run_dir;
        }
        if Instant::now() > deadline {
            panic!(
                "timed out waiting for restarts>={want} (now {:?}, restarts={}); logs: {:?}",
                status.phase,
                status.restarts,
                relay.logs()
            );
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

/// **Core case: 3 exits → 3 restarts + exponential-backoff lower bounds**.
///
/// After ChmlFrp frpc's three-reconnect exit (the modded behavior), the
/// supervision loop pulls it back up: the stub crashes 3+ times, the marker
/// records 4+ starts; consecutive start intervals are respectively ≥
/// lifetime+initial, lifetime+initial×2, lifetime+initial×4 (the backoff
/// sleep is a lower bound; process scheduling only adds, never subtracts ⇒
/// the lower-bound assertions are stable), and the final interval is
/// significantly larger than the first (direct evidence of exponential
/// growth).
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
        .expect("the stub spec should start");
    let run_dir = wait_until_restarts(&relay, 3, Duration::from_secs(20)).await;
    // Grace window: restarts are booked the instant spawn returns, while the
    // 4th stub process needs a few milliseconds to write its marker —
    // stopping immediately would kill it before it puts pen to paper. 200ms
    // is enough to leave a trace, yet shorter than the next backoff round
    // after the 4th exit (80×2³=640ms), so it introduces no 5th start.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let status = relay.stop().await.expect("stop winds down");
    assert_eq!(
        status.phase,
        RelayPhase::Stopped {
            reason: StopReason::Manual
        }
    );
    // The modded exit shape: non-zero exit code (simulating ChmlFrp's
    // os.Exit(1) after three reconnects).
    assert!(matches!(&status.last_exit, Some(e) if !e.success));

    let marker = run_dir.join("stub-marker.log");
    // Restart count: start events = initial + ≥3 restarts.
    let starts: Vec<u128> = read_marker(&marker)
        .into_iter()
        .filter(|(kind, _, _)| kind == "start")
        .map(|(_, ms, _)| ms)
        .collect();
    assert!(
        starts.len() >= 4,
        "3 crashes should pull at least 3 restarts (4 starts total), got {}",
        starts.len()
    );

    // Exponential-backoff lower bounds: interval_i ≥ stub lifetime + initial
    // × multiplier^i.
    let mut prev = starts[0];
    for (i, &t) in starts.iter().skip(1).take(3).enumerate() {
        let lower = STUB_LIFETIME_MS + INITIAL_MS * MULTIPLIER.pow(i as u32);
        let interval = (t - prev) as u64;
        assert!(
            interval >= lower,
            "restart #{} interval {interval}ms is below the backoff lower bound {lower}ms",
            i + 1
        );
        prev = t;
    }
    // Growth evidence: the 3rd interval ≈ 4× the 1st (with 25% scheduling
    // slack tolerated it should still be significantly larger).
    let i1 = (starts[1] - starts[0]) as u64;
    let i3 = (starts[3] - starts[2]) as u64;
    assert!(
        i3 * 4 >= i1 * 10,
        "backoff did not grow exponentially: i1={i1}ms i3={i3}ms"
    );
}

/// Stop semantics: the running subprocess is killed, lands on
/// `Stopped{Manual}`, and there are no further start events afterwards.
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
        .expect("the run stub should start");

    // Wait for Running (the stub lives forever), confirm exactly 1 start.
    let run_dir = {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let s = relay.health();
            if matches!(s.phase, RelayPhase::Running { .. }) {
                break s.run_dir;
            }
            assert!(
                Instant::now() < deadline,
                "did not enter Running: {:?}",
                s.phase
            );
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

    let status = relay.stop().await.expect("stop winds down");
    assert_eq!(
        status.phase,
        RelayPhase::Stopped {
            reason: StopReason::Manual
        }
    );

    // No respawn after stop (wait window > backoff initial).
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(starts(), 1, "no further spawns after stop");
}

/// Restart budget: `max_restarts=2` → initial + 2 restarts, then
/// `Stopped{RestartsExhausted}`.
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
        .expect("start");

    let deadline = Instant::now() + Duration::from_secs(20);
    let run_dir = loop {
        let s = relay.health();
        if let RelayPhase::Stopped {
            reason: StopReason::RestartsExhausted,
        } = s.phase
        {
            break s.run_dir;
        }
        assert!(
            Instant::now() < deadline,
            "did not stop within the budget: {:?}",
            s.phase
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    // Exactly 3 starts (initial + 2 restarts); no further growth inside the
    // wait window.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let marker = run_dir.join("stub-marker.log");
    let starts = read_marker(&marker)
        .into_iter()
        .filter(|(k, _, _)| k == "start")
        .count();
    assert_eq!(starts, 3, "max_restarts=2 should pull exactly 2 restarts");
    relay
        .stop()
        .await
        .expect("stop on an already-stopped relay should still wind down idempotently");
}

/// Health probing: dual-path report of admin (serve stub 200) + local tunnel
/// port (an explicitly unreachable port); also verifies R12 end-to-end: the
/// supervised copy's proxy section is byte-for-byte identical to the panel
/// input, admin enters `[common]` only.
#[tokio::test]
async fn health_probe_admin_ok_local_tunnel_err_and_r12_managed_copy() {
    common::prewarm_stub();
    let dir = test_dir("probe");
    let serve_marker = dir.join("serve-marker.log");
    let ini = panel_ini_with_stub(&dir, "mode = run");

    // Serve stub: simulates the "frpc admin listener" (HTTP 200); start it
    // first, read the actual port from the marker.
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
        .expect("serve stub starts");
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
        // The local tunnel port is explicitly pointed at a port that is
        // guaranteed to refuse (the golden sample's local 22 is a real sshd
        // on some machines; an explicitly unreachable port keeps the
        // assertion deterministic); admin goes to the injected serve stub.
        probe_local_tunnel: Some("127.0.0.1:1".parse().unwrap()),
    };

    let sup = supervisor("probe", fast_restart_policy(), health);
    let relay = sup
        .start(RelaySpec::ChmlFrp {
            mode: ChmlFrpMode::ConfigFile(ini.clone()),
        })
        .await
        .expect("the run stub should start");

    // Probe report: admin Ok, local_tunnel Err.
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
            "probe report not ready: {:?} logs={:?}",
            s.probe,
            relay.logs()
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    };
    let rep = status.probe.expect("readiness already confirmed");
    assert_eq!(
        rep.admin,
        Some(ProbeResult::Ok),
        "admin should probe the serve stub as Ok"
    );
    assert!(
        matches!(rep.local_tunnel, Some(ProbeResult::Err(_))),
        "local tunnel port (127.0.0.1:1) should fail: {:?}",
        rep.local_tunnel
    );
    assert!(!rep.all_ok(), "all_ok should be false when a path fails");

    // —— R12 end-to-end: the supervised copy ——
    let run_dir = status.run_dir;
    let managed =
        std::fs::read_to_string(run_dir.join("frpc.ini")).expect("supervised copy in place");
    let panel = std::fs::read_to_string(&ini).unwrap();
    let norm = |s: String| s.replace("\r\n", "\n");
    let (managed, panel) = (norm(managed), norm(panel));
    // The proxy section ([ssh] to the end, including the [stub] behavior
    // section) is byte-for-byte identical.
    let tail_panel = &panel[panel.find("[ssh]").unwrap()..];
    let tail_managed = &managed[managed.find("[ssh]").unwrap()..];
    assert_eq!(
        tail_panel, tail_managed,
        "R12: the supervised copy's proxy section must be byte-for-byte identical to the panel input"
    );
    let parsed = parse_ini(&managed).unwrap();
    assert_eq!(
        parsed.get("common", "admin_port"),
        Some(admin_port.to_string().as_str())
    );
    assert_eq!(parsed.get("common", "admin_user"), Some("probe"));
    // The panel's original fields are untouched.
    assert_eq!(parsed.get("common", "server_port"), Some("7000"));

    // argv: ConfigFile mode = -c <run_dir>/frpc.ini (the supervised copy).
    let argv = argv_lines(&run_dir.join("stub-marker.log"));
    let managed_path = run_dir.join("frpc.ini");
    assert!(
        argv.iter()
            .any(|a| a.contains("-c") && a.contains(managed_path.to_str().unwrap())),
        "-c should point at the supervised copy: {argv:?}"
    );

    relay.stop().await.expect("stop winds down");
    let _ = serve.kill().await;
}

/// UserTokenAuto: the argv arrival shape = `-u <usertoken> -p <tunnel_id>`
/// (the modded CLI contract). The usertoken deliberately contains non-ASCII
/// characters to prove non-ASCII argv pass-through.
#[tokio::test]
async fn user_token_auto_argv_shape() {
    common::prewarm_stub();
    let dir = test_dir("userauto");
    let _ini = panel_ini_with_stub(&dir, "mode = run");

    let sup = supervisor("userauto", fast_restart_policy(), HealthPolicy::default());
    let relay = sup
        .start(RelaySpec::ChmlFrp {
            mode: ChmlFrpMode::UserTokenAuto {
                usertoken: "ut-Ünicode-token".into(),
                tunnel_id: 77,
            },
        })
        .await
        .expect("start");
    tokio::time::sleep(Duration::from_millis(250)).await;

    let run_dir = relay.health().run_dir;
    let argv = argv_lines(&run_dir.join("stub-marker.log"));
    assert!(
        argv.iter().any(|a| a.contains("-u ut-Ünicode-token -p 77")),
        "-u/-p should be dispatched per the modded CLI contract: {argv:?}"
    );
    relay.stop().await.expect("stop winds down");
}

/// Original stack: `-c <caller TOML>` and the original file is **never
/// rewritten** (content byte-for-byte unchanged).
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
        .expect("start");
    tokio::time::sleep(Duration::from_millis(250)).await;

    let run_dir = relay.health().run_dir;
    let argv = argv_lines(&run_dir.join("stub-marker.log"));
    assert!(
        argv.iter()
            .any(|a| a.contains("-c") && a.contains(toml.to_str().unwrap())),
        "-c should point at the caller's TOML: {argv:?}"
    );
    let after = std::fs::read(&toml).unwrap();
    assert_eq!(before, after, "the caller's TOML is never rewritten");
    relay.stop().await.expect("stop winds down");
}

/// Stable reset of failures (mirroring the connector's `Backoff::reset`
/// "success resets" semantics): a subprocess surviving one stretch longer
/// than the maximum backoff (`RestartPolicy::max` doubles as the stability
/// window) ⇒ failures resets to zero. Stub lifetime(500ms) > max(150ms):
/// after the first exit failures=1; after the second run stays stable past
/// max, it must **visibly reset to zero** — otherwise, after a long-running
/// server has a few sporadic crashes, every restart pays the capped max (60s
/// by default in production) blackout.
#[tokio::test]
async fn failures_reset_after_stable_run_exceeds_max_backoff() {
    common::prewarm_stub();
    let dir = test_dir("stablereset");
    let ini = panel_ini_with_stub(&dir, "mode = crash\nlifetime_ms = 500");

    let mut policy = fast_restart_policy();
    policy.initial = Duration::from_millis(40);
    policy.max = Duration::from_millis(150); // stability window (< lifetime ⇒ every round can reset)
    let sup = supervisor("stablereset", policy, HealthPolicy::default());
    let relay = sup
        .start(RelaySpec::ChmlFrp {
            mode: ChmlFrpMode::ConfigFile(ini),
        })
        .await
        .expect("the stub spec should start");

    // First prove it really entered a failure epoch (failures ≥ 1), then see
    // it reset to zero while Running — "reset to zero" is what makes it a
    // reset rather than "never counted".
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut saw_failure_episode = false;
    loop {
        let s = relay.health();
        if s.failures >= 1 {
            saw_failure_episode = true;
        }
        if saw_failure_episode
            && s.restarts >= 1
            && matches!(s.phase, RelayPhase::Running { .. })
            && s.failures == 0
        {
            break; // stable run exceeded max ⇒ failures has reset to zero
        }
        assert!(
            Instant::now() < deadline,
            "failures did not reset after a stable run past max: restarts={} failures={} phase={:?}",
            s.restarts,
            s.failures,
            s.phase
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let status = relay.stop().await.expect("stop winds down");
    assert_eq!(
        status.phase,
        RelayPhase::Stopped {
            reason: StopReason::Manual
        }
    );
}

/// The pure-function surface of `RestartPolicy::delay_for`: exponential
/// growth + the cap.
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
        "cap in effect (400→350)"
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
        assert!(
            Instant::now() < deadline,
            "the serve stub did not report its listen address"
        );
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
