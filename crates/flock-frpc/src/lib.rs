//! # flock-frpc
//!
//! Dual-stack subprocess supervision of frpc (docs/design.md §3.9 / §5 /
//! §7-M2, ★VPN-16).
//!
//! The Flock VPN server exposes its listening port via FRP relays, but does
//! **not** compile the frp protocol into itself: two pinned frpc binaries
//! (ChmlFrp nodes use `ChmlFrp-0.51.2_251023`, self-hosted nodes use the
//! original `frp v0.71.1`) are supervised as subprocesses, with all
//! behavioral differences isolated inside this crate (§1.4-3). The root
//! reason for choosing subprocess supervision (option A): ChmlFrp is based on
//! v0.51.2 (no control-plane encryption) and the original ≥v0.53.0 (mandatory
//! AES-128-CFB after login) are **two generations of mutually incompatible
//! control planes** (frp-compat §1.3); a dual-stack of subprocesses is the
//! only path that is "compatible with both at zero protocol-maintenance
//! cost" (frp-compat §3).
//!
//! Modules:
//!
//! - [`spec`]: `RelaySpec` (`ChmlFrp{mode}` | `Original{toml}`) and
//!   `ChmlFrpMode` (`ConfigFile` the default `-c` mode / `UserTokenAuto`
//!   explicit opt-in, R20 risk annotation) + the **R9 version-matrix lock**
//!   (ChmlFrp node ⇔ ChmlFrp frpc, self-hosted node ⇔ same-generation
//!   original frpc, cross pairing forbidden);
//! - [`config`]: the config-generator seam (guarded by golden-file tests,
//!   R8/R12 — **do not modify panel-generated proxy parameters**, CheckProxy
//!   would reject, frp-compat §2.3): ChmlFrp INI (v0.51.2 dialect)
//!   generation/parsing/admin injection + original TOML (v0.71.1 dialect)
//!   generation/parsing;
//! - [`probe`]: health probing — the local tunnel port over TCP + the frpc
//!   admin (`/healthz` unauthenticated endpoint, present in both
//!   generations);
//! - [`supervisor`]: `Supervisor::start(spec) -> ManagedRelay` — process
//!   supervision (the ChmlFrp frpc mod that exits the process after three
//!   failed reconnects → restart-on-exit + exponential backoff, frp-compat
//!   §2.3) and `ManagedRelay::health() -> RelayStatus`.
//!
//! Security profile (R20): the cfg API bootstrapped by ChmlFrp `-u/-p` is
//! HTTPS with InsecureSkipVerify (frp-compat §2.2,
//! `chml/pkg/api/api.go:41-46`); the all-powerful panel usertoken can be
//! intercepted by a MITM ⇒ **the `-c` config-file mode is the default**
//! (paste-export from the panel's "Tunnel Management → Config File");
//! `UserTokenAuto` is retained but requires explicit opt-in (see the
//! [`spec::ChmlFrpMode::UserTokenAuto`] docs).
//!
//! This crate is server-side only (with tcp proxies the client connects
//! directly to the frps user port, no frpc needed, frp-compat §1.1).

#![forbid(unsafe_code)]

pub mod config;
pub mod probe;
pub mod spec;
pub mod supervisor;

pub use config::AdminCommon;
pub use probe::{AdminEndpoint, ProbeReport, ProbeResult, ProbeTargets};
pub use spec::{
    check_version_matrix, ChmlFrpMode, FrpcBinaries, FrpcBinary, FrpcError, RelayFlavor, RelaySpec,
    CHMLFRP_PINNED_VERSION, ORIGINAL_PINNED_VERSION,
};
pub use supervisor::{
    ManagedRelay, RelayPhase, RelayStatus, RestartPolicy, StopReason, Supervisor,
};
