//! Shared utilities for the integration tests.

use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Prewarm the stub binary (once per test process).
///
/// On this dev machine (sandbox/AV environment), the **first**
/// CreateProcess on frpc_stub.exe — in the combination "argv referencing a
/// freshly written file + cwd pointing at its directory" — is synchronously
/// blocked by real-time scanning (it once hung indefinitely; diagnostic
/// experiment: std and tokio spawns with the same arguments hang identically
/// ⇒ environment layer, not library layer; after one warm-up the same
/// combination completes within 10ms). First spawn a `version` mode run
/// with plain arguments that exits immediately to absorb the scan; all later
/// supervision spawns take the hot path. Production supervision is
/// unaffected (no such test stub there).
pub fn prewarm_stub() {
    static WARM: OnceLock<()> = OnceLock::new();
    WARM.get_or_init(|| {
        let ok = Command::new(env!("CARGO_BIN_EXE_frpc_stub"))
            .args(["version", "--print", "warm"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(
            ok,
            "frpc_stub prewarm failed (version mode should exit successfully immediately)"
        );
    });
}
