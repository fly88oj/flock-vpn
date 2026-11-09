//! `RelaySpec` and the R9 version-matrix lock (docs/design.md §3.9 / §5-4;
//! frp-compat §1.3/§4-R9).

use std::fmt;
use std::path::{Path, PathBuf};

/// The pinned ChmlFrp frpc version string (the `frpc --version` output shape;
/// frp-compat §2.1: `pkg/util/version/version.go` = `"ChmlFrp-0.51.2_251023"`).
pub const CHMLFRP_PINNED_VERSION: &str = "ChmlFrp-0.51.2_251023";

/// The pinned original frpc version string (design §5 pins v0.71.1;
/// frp-compat §1: GitHub Releases `v0.71.1 / 2026-10-14`, `frps --version`
/// verified in-container as `0.71.1`).
pub const ORIGINAL_PINNED_VERSION: &str = "0.71.1";

/// The relay stack generation (node style = frpc variant, the two are bound
/// one-to-one).
///
/// The "row/column" of the R9 matrix lock: the two control-plane generations
/// are mutually incompatible (ChmlFrp baseline v0.51.2 has no control-plane
/// encryption; the original ≥v0.53.0 enforces AES-128-CFB token-derived
/// encryption after login — incompatible in both directions, frp-compat
/// §1.3), so the stack generation is the **shared** identity of a node and
/// its frpc binary; cross pairing is forbidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RelayFlavor {
    /// A ChmlFrp node (panel-hosted, CheckProxy whitelist, plan rate limits
    /// 8–32Mbps, frp-compat §2.3).
    ChmlFrp,
    /// A self-hosted original node (frps deployed by operations; frpc and
    /// frps are the same original generation, frp-compat §1).
    Original,
}

impl RelayFlavor {
    /// The pinned frpc version string allowed for this stack generation
    /// (§5 dual-stack pinning; changing a version = edit this table + pass
    /// the golden/matrix tests).
    pub fn pinned_version(self) -> &'static str {
        match self {
            RelayFlavor::ChmlFrp => CHMLFRP_PINNED_VERSION,
            RelayFlavor::Original => ORIGINAL_PINNED_VERSION,
        }
    }
}

impl fmt::Display for RelayFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RelayFlavor::ChmlFrp => "chmlfrp",
            RelayFlavor::Original => "original",
        })
    }
}

/// Relay access spec: the input of `Supervisor::start` (§3.9 interface).
#[derive(Clone, Debug)]
pub enum RelaySpec {
    /// A ChmlFrp node ⇔ ChmlFrp frpc (`ChmlFrp-0.51.2_251023` pinned).
    ChmlFrp {
        /// Access mode: the default [`ChmlFrpMode::ConfigFile`] (`-c`);
        /// `UserTokenAuto` requires explicit opt-in.
        mode: ChmlFrpMode,
    },
    /// A self-hosted original node ⇔ original frpc (v0.71.1 pinned).
    ///
    /// `toml` = the path of the original frpc TOML config file (v0.71.1
    /// dialect: `serverAddr`/`serverPort`/`[[proxies]]` camelCase; a sample
    /// is at `.tmp/frp_0.71.1_linux_amd64/frpc.toml`). The supervision layer
    /// only **reads** this file (deriving probe targets), never rewrites it.
    Original { toml: PathBuf },
}

impl RelaySpec {
    /// The stack generation (the spec-side identity of the R9 matrix).
    pub fn flavor(&self) -> RelayFlavor {
        match self {
            RelaySpec::ChmlFrp { .. } => RelayFlavor::ChmlFrp,
            RelaySpec::Original { .. } => RelayFlavor::Original,
        }
    }
}

/// ChmlFrp access mode (§3.9; frp-compat §2.2/§2.3).
#[derive(Clone, Debug)]
pub enum ChmlFrpMode {
    /// **The default mode**: the frpc.ini paste-exported from the panel's
    /// "Tunnel Management → Config File"; frpc starts with `-c <ini>`.
    ///
    /// The panel-generated proxy parameters (type/ports/name etc.) are
    /// compared item by item by the server-side CheckProxy against the
    /// panel's records; any mismatch is rejected ("client proxy parameter
    /// error", frp-compat §2.3) ⇒ the supervision layer passes those fields
    /// through **byte for byte** (golden-guarded, see [`crate::config`]);
    /// only admin probing fields may be injected into `[common]`.
    ConfigFile(
        /// The panel-exported frpc.ini path.
        PathBuf,
    ),
    /// **Explicit opt-in**: bootstrap via `frpc -u <usertoken> -p
    /// <tunnel_id>` (modded CLI, root.go:92-93).
    ///
    /// Startup flow: frpc itself fetches the panel-generated frpc.ini via
    /// `GET https://cf-v2.uapis.cn/cfg?action=getcfg&token=<usertoken>
    /// &id=<tunnel_id>` → overwrites the local `./frpc.ini` (cwd-relative,
    /// root.go:133-174) → starts the original flow.
    ///
    /// # Risks (R20, must-read before opting in)
    ///
    /// - the cfg API uses HTTPS with **InsecureSkipVerify**
    ///   (`chml/pkg/api/api.go:41-46`): a MITM can intercept the
    ///   all-powerful panel usertoken (a credential that can
    ///   create/delete/modify tunnels);
    /// - the usertoken enters the subprocess command line (readable by other
    ///   users on the same machine via `ps`/`/proc/<pid>/cmdline`);
    /// - the fetched config is opaque to the supervision layer (probe
    ///   targets cannot be pre-derived; [`crate::probe`] is left with only
    ///   the process-state surface).
    ///
    /// Do not enable on organizational/multi-user machines; the default is
    /// [`ChmlFrpMode::ConfigFile`] (the §8-R20 countermeasure).
    UserTokenAuto {
        /// The panel usertoken (**a credential**: full panel authority; keep
        /// out of logs).
        usertoken: String,
        /// The numeric tunnel ID (visible in the panel's "Tunnel
        /// Management"; `-p/--id`).
        tunnel_id: u64,
    },
}

/// A pinned frpc binary declaration (the binary-side identity of the R9
/// matrix).
///
/// `decl_version` is the version **declared by operations** (should match the
/// `<bin> --version` output). Declaration ≠ pin is rejected by
/// [`check_version_matrix`]; the process-level cross-check of "measured
/// `--version` ↔ declared" is a test-surface discipline (carried by an
/// in-test helper in tests/matrix.rs, occupying no production startup path —
/// one extra subprocess round trip, never enabled in production).
#[derive(Clone, Debug)]
pub struct FrpcBinary {
    /// Binary path.
    pub path: PathBuf,
    /// Stack generation.
    pub flavor: RelayFlavor,
    /// Declared version string (the `--version` output shape).
    pub decl_version: String,
}

/// The R9 version-matrix lock: spec stack generation ⇔ frpc binary stack
/// generation ⇔ pinned version; cross pairing forbidden.
///
/// Only the diagonal pairings are legal:
///
/// | spec \ bin | ChmlFrp                    | Original                     |
/// |------------|-----------------------------|------------------------------|
/// | ChmlFrp    | ✅ `ChmlFrp-0.51.2_251023`  | ❌ the two control-plane generations are mutually incompatible |
/// | Original   | ❌ same                     | ✅ `0.71.1`                   |
///
/// Mechanism (source-level confirmation in frp-compat §1.3): a ChmlFrp frpc
/// (v0.51.2 baseline, no control-plane encryption) connecting to an original
/// frps ≥v0.53.0 fails the handshake after the peer enables AES-128-CFB; an
/// original frpc ≥v0.53.0 connecting to a ChmlFrp node likewise fails on the
/// unencrypted control plane — **both directions break**. The CI matrix smoke
/// test (asserting that only the diagonal succeeds across the 4 combinations)
/// is pinned in this function's unit tests (`tests/matrix.rs`).
pub fn check_version_matrix(
    spec_flavor: RelayFlavor,
    decl_version: &str,
    bin: &FrpcBinary,
) -> Result<(), FrpcError> {
    if spec_flavor != bin.flavor {
        return Err(FrpcError::Matrix(format!(
            "R9 version matrix forbids cross pairing: {} spec × {} frpc ({}) — the two control-plane generations are mutually incompatible (frp-compat §1.3)",
            spec_flavor,
            bin.flavor,
            bin.path.display()
        )));
    }
    let pinned = spec_flavor.pinned_version();
    if decl_version != pinned {
        return Err(FrpcError::Matrix(format!(
            "R9 pin check failed: the {} stack requires frpc version {pinned:?}, declared {decl_version:?} ({})",
            spec_flavor,
            bin.path.display()
        )));
    }
    Ok(())
}

/// RelaySpec structural validation (including the R9 matrix). File-level
/// checks (existence/parseability) live at this layer; process-level failures
/// are left to [`crate::supervisor::Supervisor::start`].
pub(crate) fn validate_spec(
    spec: &RelaySpec,
    bins: &FrpcBinaries,
) -> Result<ValidatedSpec, FrpcError> {
    let flavor = spec.flavor();
    match spec {
        RelaySpec::ChmlFrp { mode } => {
            let bin = bins.chmlfrp.clone();
            check_version_matrix(flavor, &bin.decl_version, &bin)?;
            match mode {
                ChmlFrpMode::ConfigFile(ini) => {
                    ensure_readable_file(ini, "ChmlFrp panel frpc.ini")?;
                }
                ChmlFrpMode::UserTokenAuto {
                    usertoken,
                    tunnel_id,
                } => {
                    if usertoken.trim().is_empty() {
                        return Err(FrpcError::Spec("UserTokenAuto: usertoken is empty".into()));
                    }
                    if *tunnel_id == 0 {
                        return Err(FrpcError::Spec("UserTokenAuto: tunnel_id is 0".into()));
                    }
                }
            }
            Ok(ValidatedSpec {
                spec: spec.clone(),
                bin,
            })
        }
        RelaySpec::Original { toml } => {
            let bin = bins.original.clone();
            check_version_matrix(flavor, &bin.decl_version, &bin)?;
            ensure_readable_file(toml, "original frpc.toml")?;
            // Fail early: if the TOML won't parse, don't wait for the
            // subprocess exit code (the file is the caller's asset,
            // read-only).
            let _ = crate::config::parse_original_toml(toml)?;
            Ok(ValidatedSpec {
                spec: spec.clone(),
                bin,
            })
        }
    }
}

/// The dual-stack pinned binary table (held by `Supervisor`; both stacks are
/// resident, dispatched by spec).
#[derive(Clone, Debug)]
pub struct FrpcBinaries {
    /// The ChmlFrp-node stack (`ChmlFrp-0.51.2_251023` pinned).
    pub chmlfrp: FrpcBinary,
    /// The self-hosted original-node stack (`0.71.1` pinned).
    pub original: FrpcBinary,
}

#[derive(Debug)]
pub(crate) struct ValidatedSpec {
    /// The validated spec (participates in startup-plan assembly in its
    /// validated form from here on).
    pub spec: RelaySpec,
    pub bin: FrpcBinary,
}

fn ensure_readable_file(p: &Path, what: &str) -> Result<(), FrpcError> {
    if !p.is_file() {
        return Err(FrpcError::Spec(format!(
            "{what} does not exist or is not a file: {}",
            p.display()
        )));
    }
    Ok(())
}

/// Supervision errors.
#[derive(Debug)]
pub enum FrpcError {
    /// RelaySpec structural/file validation failed.
    Spec(String),
    /// R9 version-matrix violation (cross pairing / not pinned).
    Matrix(String),
    /// Subprocess spawn failed (binary missing / not executable etc.).
    Spawn(String),
    /// Config generation/parsing failure (the golden-guarded surface,
    /// frp-compat §4-R8/R12).
    Config(String),
    /// IO error.
    Io(std::io::Error),
}

impl fmt::Display for FrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrpcError::Spec(m) => write!(f, "frpc spec validation failed: {m}"),
            FrpcError::Matrix(m) => write!(f, "frpc version matrix: {m}"),
            FrpcError::Spawn(m) => write!(f, "frpc subprocess: {m}"),
            FrpcError::Config(m) => write!(f, "frpc config: {m}"),
            FrpcError::Io(e) => write!(f, "frpc IO: {e}"),
        }
    }
}

impl std::error::Error for FrpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrpcError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FrpcError {
    fn from(e: std::io::Error) -> Self {
        FrpcError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bins(chmlfrp_ver: &str, original_ver: &str) -> FrpcBinaries {
        FrpcBinaries {
            chmlfrp: FrpcBinary {
                path: PathBuf::from("bin/chmlfrpc"),
                flavor: RelayFlavor::ChmlFrp,
                decl_version: chmlfrp_ver.into(),
            },
            original: FrpcBinary {
                path: PathBuf::from("bin/frpc"),
                flavor: RelayFlavor::Original,
                decl_version: original_ver.into(),
            },
        }
    }

    #[test]
    fn flavor_pinned_versions() {
        assert_eq!(
            RelayFlavor::ChmlFrp.pinned_version(),
            "ChmlFrp-0.51.2_251023"
        );
        assert_eq!(RelayFlavor::Original.pinned_version(), "0.71.1");
    }

    #[test]
    fn user_token_auto_rejects_empty_token_and_zero_id() {
        let b = bins(CHMLFRP_PINNED_VERSION, ORIGINAL_PINNED_VERSION);
        let err = validate_spec(
            &RelaySpec::ChmlFrp {
                mode: ChmlFrpMode::UserTokenAuto {
                    usertoken: "  ".into(),
                    tunnel_id: 42,
                },
            },
            &b,
        )
        .unwrap_err();
        assert!(matches!(err, FrpcError::Spec(ref m) if m.contains("usertoken")));
        let err = validate_spec(
            &RelaySpec::ChmlFrp {
                mode: ChmlFrpMode::UserTokenAuto {
                    usertoken: "tok".into(),
                    tunnel_id: 0,
                },
            },
            &b,
        )
        .unwrap_err();
        assert!(matches!(err, FrpcError::Spec(ref m) if m.contains("tunnel_id")));
    }

    #[test]
    fn config_file_mode_requires_existing_ini() {
        let b = bins(CHMLFRP_PINNED_VERSION, ORIGINAL_PINNED_VERSION);
        let err = validate_spec(
            &RelaySpec::ChmlFrp {
                mode: ChmlFrpMode::ConfigFile(PathBuf::from("no/such.ini")),
            },
            &b,
        )
        .unwrap_err();
        assert!(matches!(err, FrpcError::Spec(_)));
    }
}
