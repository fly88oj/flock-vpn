//! R9 version-matrix lock tests (frp-compat §4-R9; docs/design.md §3.9
//! implementation notes).
//!
//! Matrix: ChmlFrp node ⇔ ChmlFrp frpc (`ChmlFrp-0.51.2_251023`),
//! self-hosted node ⇔ same-generation original frpc (`0.71.1`), **cross
//! pairing forbidden**. Mechanism (source-level confirmation in frp-compat
//! §1.3): ChmlFrp is based on v0.51.2 (no control-plane encryption) and the
//! original ≥v0.53.0 (mandatory AES-128-CFB after login, token-derived key)
//! are two mutually incompatible control-plane generations, both directions
//! break ⇒ "of the 4 combinations only the diagonal succeeds" is pinned here
//! (the unit-test form of the CI matrix smoke; end-to-end R1 smoking is left
//! to M5).
//!
//! The process-level cross-check (measured `--version` ↔ declared) is also
//! in this group: the matrix's "declaration surface" is carried by
//! `FrpcBinary::decl_version`, and a declaration that disagrees with the
//! binary's measured output must be rejected. That check path has been
//! removed from the production API
//! (`SupervisorConfig::verify_version_at_start` is always false in
//! production; `probe_version`/`verify_declared` have no production
//! callers) and lives on as an **in-test helper** — production behavior is
//! unchanged while the discipline stays pinned by tests.

mod common;

use std::path::PathBuf;

use flock_frpc::supervisor::SupervisorConfig;
use flock_frpc::{
    check_version_matrix, ChmlFrpMode, FrpcBinaries, FrpcBinary, FrpcError, RelayFlavor, RelaySpec,
    Supervisor, CHMLFRP_PINNED_VERSION, ORIGINAL_PINNED_VERSION,
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

// ---------------------------------------------------------------------------
// `--version` measured cross-check (an in-test helper — the former
// FrpcBinary::probe_version/verify_declared production paths were removed;
// the semantics live on verbatim on the test surface)
// ---------------------------------------------------------------------------

/// Run `<bin> --version` to measure the version (first line, trimmed).
///
/// Both ChmlFrp's `version.Full()` and the original's `version.Full()` print
/// a single-line version string (root.go:127-129, frp-src convention). Use
/// it to catch "the wrong binary is mounted at the path".
async fn probe_version(bin: &FrpcBinary) -> Result<String, FrpcError> {
    let out = tokio::process::Command::new(&bin.path)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| {
            FrpcError::Spawn(format!(
                "--version probe failed {}: {e}",
                bin.path.display()
            ))
        })?;
    if !out.status.success() {
        return Err(FrpcError::Spawn(format!(
            "--version exit code {:?}",
            out.status.code()
        )));
    }
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if first.is_empty() {
        return Err(FrpcError::Spawn("--version output is empty".into()));
    }
    Ok(first)
}

/// Measured version agrees with the declaration + the declaration passes the
/// matrix (the complete check).
async fn verify_declared(bin: &FrpcBinary) -> Result<(), FrpcError> {
    let actual = probe_version(bin).await?;
    if actual != bin.decl_version {
        return Err(FrpcError::Matrix(format!(
            "binary's measured version {actual:?} disagrees with the declared {:?} ({})",
            bin.decl_version,
            bin.path.display()
        )));
    }
    check_version_matrix(bin.flavor, &bin.decl_version, bin)
}

/// The pure-function surface: only the diagonal of the 4 combinations passes
/// (the unit-test pinning of the R9 matrix smoke).
#[test]
fn matrix_diagonal_only() {
    let chmlfrp_bin = bin(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION);
    let original_bin = bin(RelayFlavor::Original, ORIGINAL_PINNED_VERSION);

    // Diagonal ✅
    check_version_matrix(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION, &chmlfrp_bin)
        .expect("ChmlFrp node ⇔ ChmlFrp frpc should be allowed");
    check_version_matrix(
        RelayFlavor::Original,
        ORIGINAL_PINNED_VERSION,
        &original_bin,
    )
    .expect("self-hosted node ⇔ same-generation original frpc should be allowed");

    // Cross ❌ (both directions)
    let err = check_version_matrix(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION, &original_bin)
        .expect_err("ChmlFrp spec × original frpc must be rejected");
    assert!(
        matches!(err, FrpcError::Matrix(_)),
        "a cross pairing should report a Matrix error: {err}"
    );
    let err = check_version_matrix(RelayFlavor::Original, ORIGINAL_PINNED_VERSION, &chmlfrp_bin)
        .expect_err("original spec × ChmlFrp frpc must be rejected");
    assert!(
        matches!(err, FrpcError::Matrix(_)),
        "a cross pairing should report a Matrix error: {err}"
    );
}

/// Pinning discipline: correct stack generation but an unpinned version →
/// rejected (guards against a silent upgrade of "same generation but
/// drifted").
#[test]
fn matrix_rejects_unpinned_versions() {
    let drifted = bin(RelayFlavor::ChmlFrp, "ChmlFrp-0.51.3_260101");
    assert!(check_version_matrix(RelayFlavor::ChmlFrp, "ChmlFrp-0.51.3_260101", &drifted).is_err());

    let drifted = bin(RelayFlavor::Original, "0.72.0");
    assert!(check_version_matrix(RelayFlavor::Original, "0.72.0", &drifted).is_err());
}

/// Under a cross stack, `start()` must fail with a Matrix error (rather than
/// breaking only after spawn).
async fn start_expect_matrix_error(sup: &Supervisor, spec: RelaySpec) {
    match sup.start(spec).await {
        Err(e) => assert!(
            matches!(e, FrpcError::Matrix(_)),
            "expected a Matrix error: {e}"
        ),
        Ok(relay) => {
            let _ = relay.stop().await;
            panic!("a cross stack must be rejected at the start layer")
        }
    }
}

/// RelaySpec validation-layer wiring: `Supervisor::start` runs the same
/// matrix check against the declared binary table.
#[tokio::test]
async fn supervisor_start_enforces_matrix_on_cross_stack() {
    // The cross-stack cases never reach spawn (rejected at start), but the
    // other cases in this process need the hot path — prewarm uniformly.
    common::prewarm_stub();
    // ChmlFrp spec, but the chmlfrp slot holds an original-declared binary →
    // rejected at start (no spawn).
    let bins = FrpcBinaries {
        chmlfrp: bin(RelayFlavor::Original, ORIGINAL_PINNED_VERSION),
        original: bin(RelayFlavor::Original, ORIGINAL_PINNED_VERSION),
    };
    let sup = Supervisor::new(SupervisorConfig::new(bins));
    start_expect_matrix_error(&sup, chmlfrp_spec()).await;

    // Original spec × ChmlFrp-declared binary → likewise rejected.
    let bins = FrpcBinaries {
        chmlfrp: bin(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION),
        original: bin(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION),
    };
    let sup = Supervisor::new(SupervisorConfig::new(bins));
    start_expect_matrix_error(&sup, original_spec()).await;
}

/// An unpinned declaration (correct stack generation, drifted version) is
/// likewise rejected at the start layer.
#[tokio::test]
async fn supervisor_start_rejects_unpinned_decl() {
    let bins = FrpcBinaries {
        chmlfrp: bin(RelayFlavor::ChmlFrp, "ChmlFrp-0.52.0_000000"),
        original: bin(RelayFlavor::Original, ORIGINAL_PINNED_VERSION),
    };
    let sup = Supervisor::new(SupervisorConfig::new(bins));
    start_expect_matrix_error(&sup, chmlfrp_spec()).await;
}

/// `--version` measured cross-check (an in-test helper): declaration
/// disagreeing with what the binary actually prints → rejected (catches
/// "the wrong binary is mounted at the path").
#[tokio::test]
async fn version_probe_cross_checks_declared_version() {
    common::prewarm_stub();
    // The stub's --version prints the FRPC_STUB_VERSION environment variable
    // (set once in this test process; subprocesses inherit it; other tests
    // do not trigger the --version path, no environment cross-talk).
    std::env::set_var("FRPC_STUB_VERSION", CHMLFRP_PINNED_VERSION);

    let ok = bin(RelayFlavor::ChmlFrp, CHMLFRP_PINNED_VERSION);
    let probed = probe_version(&ok).await.expect("--version probe succeeds");
    assert_eq!(probed, CHMLFRP_PINNED_VERSION);
    verify_declared(&ok)
        .await
        .expect("measured=declared=pinned → allowed");

    // Measured ChmlFrp pinned string, declared as 0.71.1 → rejected (version
    // drift).
    let drifted = bin(RelayFlavor::ChmlFrp, ORIGINAL_PINNED_VERSION);
    let err = verify_declared(&drifted)
        .await
        .expect_err("declaration disagreeing with the measurement must be rejected");
    assert!(matches!(err, FrpcError::Matrix(_)), "{err}");
}
