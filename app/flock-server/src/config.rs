//! server.toml parsing and the [`ListenerMode`] seam (docs/design.md
//! §2.1/§3.11).
//!
//! **Access layer decoupled from frp (a user hard constraint, top
//! priority)**: `listener.mode` is one of two choices ——
//! - `direct` (**default**): listen directly on `bind`, zero frp logic ——
//!   the Direct code path from this module to runtime never touches
//!   flock-frpc (no Supervisor instantiation, no config generation, no
//!   subprocess launch);
//! - `frp`: local listen on `bind` + `flock-frpc` Supervisor-managed relay
//!   (§3.9/§5).
//!
//! The decoupling discipline lands on types: the config layer defines only
//! its own [`FrpPlan`] type (String/PathBuf/SocketAddr, no flock-frpc
//! types); RelaySpec/FrpcBinaries construction is isolated in `frp.rs`
//! (referenced only by the Frp branch).

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::ticket::TICKET_TTL_SECS;

/// The frp-mode assembly plan (a config-layer own type; no flock-frpc types
/// appear at this layer).
#[derive(Debug, Clone)]
pub struct FrpPlan {
    /// Relay spec (config-layer own shape; `frp.rs` builds flock-frpc's
    /// `RelaySpec` from it).
    pub relay: FrpRelayPlan,
    /// frpc binary path (matching the `relay` stack generation; the R9
    /// version matrix lock is enforced inside flock-frpc).
    pub frpc_bin: PathBuf,
    /// Supervisor run-directory base (managed config/log drop point).
    pub run_base: PathBuf,
}

/// The `[frp]` relay stack generation (review item 14: ChmlFrp
/// assembly-layer wiring —— config-layer own shape, no flock-frpc types
/// referenced).
#[derive(Debug, Clone)]
pub enum FrpRelayPlan {
    /// Original frpc (pinned v0.71.1): the **full embedded text** of the
    /// TOML (v0.71.1 dialect) —— written out to the state directory at
    /// startup and registered as `RelaySpec::Original{toml}` (the real
    /// product path, compatibility unbroken).
    Original { toml: String },
    /// ChmlFrp node (pinned `ChmlFrp-0.51.2_251023`). Default
    /// [`ChmlFrpMode::ConfigFile`] semantics: the path of the frpc.ini
    /// exported by the panel's "tunnel management → config file" (passed
    /// through byte-for-byte, injecting only the admin probe fields); only
    /// an explicit `user_token_auto` opt-in takes the `-u/-p` bootstrap (the
    /// R20 risk is documented on [`UserTokenAuto`]).
    ChmlFrp {
        ini: Option<PathBuf>,
        user_token_auto: Option<UserTokenAuto>,
    },
}

/// The `user_token_auto` opt-in of `[frp] mode = "chmlfrp"` (review item
/// 14).
///
/// **R20 risk (must read before opting in)**: the panel usertoken is an
/// all-powerful credential; the bootstrap pulls it over
/// InsecureSkipVerify HTTPS (a man-in-the-middle can capture the
/// all-powerful token), the token lands in the subprocess command line
/// (readable via `ps` on the same machine), and the pulled config is opaque
/// to the management layer (liveness probing is left with only the process
/// state surface) —— do not enable on organizational/multi-user machines;
/// the default ConfigFile mode has none of these exposures.
#[derive(Debug, Clone, Deserialize)]
pub struct UserTokenAuto {
    /// Panel usertoken (**a credential**: full panel authority; keep out of
    /// logs/repositories).
    pub usertoken: String,
    /// Numeric tunnel ID (visible in the panel's "tunnel management").
    pub tunnel_id: u64,
}

/// Access endpoint shape (the config-layer form of the §3.11 seam enum; the
/// runtime handle is `server::RunningListener`).
#[derive(Debug, Clone)]
pub enum ListenerMode {
    /// Direct listen (**default**) —— zero frp logic (the §2.1 hard
    /// constraint).
    Direct { bind: SocketAddr },
    /// Local listen + flock-frpc-managed relay.
    Frp { bind: SocketAddr, plan: FrpPlan },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// State directory (redb + cluster identity material + frp managed drop
    /// points).
    pub state_dir: PathBuf,
    /// Local listen address (shared by both forms; direct defaults to
    /// 0.0.0.0:9443).
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    /// `direct` (default) | `frp`.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// This server's **client-visible endpoint** inside the directory (a
    /// direct address or a relay user port; host:port string, isomorphic to
    /// ServerEntry.relay_endpoint).
    pub advertise_endpoint: String,
    /// Additional endpoints (the same server via other exposure openings;
    /// the single-server M2 simulation of "still 1-RTT after switching
    /// endpoints", §7-M2).
    #[serde(default)]
    pub extra_endpoints: Vec<String>,
    /// Directory version (the root-signed ClusterDirectory's dir_version;
    /// a change = manual increment + re-signing).
    #[serde(default = "default_dir_version")]
    pub dir_version: u64,
    /// Ticket TTL seconds (default 60 = the §2.2 hard cap; deployments may
    /// lower it to exercise the expiry path).
    #[serde(default = "default_ticket_ttl")]
    pub ticket_ttl_secs: u64,
    /// Admin loopback endpoint (the in-process single-writer entry for
    /// invite minting/redemption/registry management; CLI subcommands go
    /// through it).
    #[serde(default = "default_admin_bind")]
    pub admin_bind: SocketAddr,
    /// Concurrent session cap (review item 7; a permit is taken right after
    /// accept; inbound connections over the cap are politely closed and
    /// counted. Default 1024).
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// M7 (§7-M7.2/§7-M7.5): offline device retention period (days). Beyond
    /// it ⇒ the reaper sets Expired + the VIP returns to the allocation pool
    /// (row retained for audit, excluded from the roster). Default 30;
    /// **0 = never expire** (compatible with the old behavior). u64 is
    /// naturally ≥0 (the "validate ≥0" is carried by the type —— negative
    /// values are unexpressible at the parsing layer).
    #[serde(default = "default_peer_retention_days")]
    pub peer_retention_days: u64,
    /// TUN interface name (M3 data plane, §2.2/§3.12; default "tun0").
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// This node's tun VIP (§2.2 the server itself is also a peer; default
    /// 100.64.0.1. In multi-primary form each server gets its own —— §6.2:
    /// server-a/b/c = .1/.2/.3; device VIPs are assigned by Raft from .11,
    /// never colliding with the server segment).
    #[serde(default = "default_vip")]
    pub vip: std::net::Ipv4Addr,
    /// Read only when mode = "frp".
    pub frp: Option<FrpSection>,
    /// Multi-primary sync (§2.2/§3.11 M4 batch; default None =
    /// single-server form —— m2/m2-direct deployments unchanged).
    #[serde(default)]
    pub sync: Option<SyncSection>,
    /// M8 Web UI admin surface (§7-M8.2; default enabled=true/port=9800 ——
    /// dual bind 127.0.0.1:port + cfg.vip:port, **no bind field is exposed
    /// at all**).
    #[serde(default)]
    pub webui: WebUiSection,
}

/// The `[webui]` config section (fixed by §7-M8.2; **an explicit
/// whitelisted key set** —— `deny_unknown_fields` rejects misconfigured keys
/// like `bind` at the parsing layer, structurally ruling out 0.0.0.0
/// mistakes).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebUiSection {
    /// false = do not assemble the webui.
    #[serde(default = "default_webui_enabled")]
    pub enabled: bool,
    /// Dual-bind port (127.0.0.1:port + cfg.vip:port); validated 1..=65535
    /// and not conflicting with bind/admin_bind/admin_bind+1/raft_bind
    /// (refuses to start).
    #[serde(default = "default_webui_port")]
    pub port: u16,
    /// Session TTL seconds (default 8h; validated 60..=86400).
    #[serde(default = "default_webui_session_ttl")]
    pub session_ttl_secs: u64,
    /// Traffic ring-buffer point count (§M8.5; default 120).
    #[serde(default = "default_webui_series_points")]
    pub series_points: usize,
    /// Sampling interval seconds (default 60).
    #[serde(default = "default_webui_series_interval")]
    pub series_interval_secs: u64,
}

impl Default for WebUiSection {
    fn default() -> Self {
        WebUiSection {
            enabled: default_webui_enabled(),
            port: default_webui_port(),
            session_ttl_secs: default_webui_session_ttl(),
            series_points: default_webui_series_points(),
            series_interval_secs: default_webui_series_interval(),
        }
    }
}

fn default_webui_enabled() -> bool {
    true
}
fn default_webui_port() -> u16 {
    9800
}
fn default_webui_session_ttl() -> u64 {
    28_800
}
fn default_webui_series_points() -> usize {
    120
}
fn default_webui_series_interval() -> u64 {
    60
}

/// The `[sync]` config section.
#[derive(Debug, Clone, Deserialize)]
pub struct SyncSection {
    /// `single` (default) | `raft`.
    #[serde(default = "default_sync_mode")]
    pub mode: String,
    /// Raft form: the node bundle file (an init-cluster product; root public
    /// key + enrollment credential + root-signed directory). Default =
    /// state_dir/bundle.bin (the `enroll` subcommand's drop point).
    pub bundle: Option<PathBuf>,
    /// Raft form: the server-interconnect fabric listen address (§6.2
    /// srvmesh inline network; default 0.0.0.0:9500).
    #[serde(default = "default_raft_bind")]
    pub raft_bind: SocketAddr,
    /// Raft form: the peer dial table `"node-number=host:port"` (§6.2
    /// srvmesh; e.g. "1=raft-1:9500").
    #[serde(default)]
    pub raft_peers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FrpSection {
    /// Relay stack generation: `original` (default) | `chmlfrp` (review
    /// item 14: ChmlFrp panel node).
    #[serde(default = "default_frp_flavor")]
    pub flavor: String,
    /// Full original-frpc TOML text (embedded registration, §7-M2 "server
    /// embeds frpc"; required for flavor=original).
    #[serde(default)]
    pub original_toml: String,
    /// ChmlFrp: the path of the panel-exported frpc.ini (required by the
    /// default ConfigFile mode of flavor=chmlfrp).
    #[serde(default)]
    pub chmlfrp_ini: Option<PathBuf>,
    /// ChmlFrp `UserTokenAuto` explicit opt-in (the R20 risk is documented
    /// on [`UserTokenAuto`]); when present it overrides the ConfigFile mode
    /// and `chmlfrp_ini` may be omitted.
    #[serde(default)]
    pub user_token_auto: Option<UserTokenAuto>,
    /// frpc binary path (default /usr/local/bin/frpc —— the location inside
    /// the deploy images; the chmlfrp generation should point at the
    /// ChmlFrp-pinned frpc binary).
    #[serde(default = "default_frpc_bin")]
    pub frpc_bin: PathBuf,
    /// Run-directory base (default state_dir/frpc-run).
    pub run_base: Option<PathBuf>,
}

fn default_bind() -> SocketAddr {
    "0.0.0.0:9443".parse().expect("const addr")
}
fn default_mode() -> String {
    "direct".into()
}
fn default_dir_version() -> u64 {
    1
}
fn default_ticket_ttl() -> u64 {
    TICKET_TTL_SECS
}
fn default_admin_bind() -> SocketAddr {
    "127.0.0.1:9444".parse().expect("const addr")
}
fn default_max_sessions() -> usize {
    1024
}
fn default_peer_retention_days() -> u64 {
    30
}
fn default_tun_name() -> String {
    "tun0".into()
}
fn default_frpc_bin() -> PathBuf {
    PathBuf::from("/usr/local/bin/frpc")
}
fn default_frp_flavor() -> String {
    "original".into()
}
fn default_vip() -> std::net::Ipv4Addr {
    crate::dataplane::SERVER_VIP
}
fn default_sync_mode() -> String {
    "single".into()
}
fn default_raft_bind() -> SocketAddr {
    "0.0.0.0:9500".parse().expect("const addr")
}

/// Loopback verdict: the whole 127.0.0.0/8 (the IPv4 loopback is an entire
/// class-A block) or ::1.
fn is_loopback(a: &SocketAddr) -> bool {
    match a {
        SocketAddr::V4(v4) => v4.ip().is_loopback(),
        SocketAddr::V6(v6) => v6.ip().is_loopback(),
    }
}

impl ServerConfig {
    /// Parse server.toml (load validation runs right after parsing —— review
    /// items 3/4: invalid configs refuse to start).
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let cfg: Self =
            toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load validation (review items 3/4): invalid configs are rejected here
    /// (refuse to start) rather than running sick.
    pub fn validate(&self) -> Result<(), String> {
        // Review item 3: the admin endpoint (and its +1-derived cluster
        // bootstrap endpoint) must be loopback —— it is the unauthenticated
        // in-process single-writer entry (§3.11 "the 127.0.0.1 bind = the
        // authentication boundary"). Remote-operations intent should go
        // through an SSH tunnel/reverse proxy (stated in the error message),
        // not a widened bind.
        if !is_loopback(&self.admin_bind) {
            return Err(format!(
                "admin_bind {} is not loopback: the admin/cluster-bootstrap endpoints are unauthenticated local management entry points, and binding them to a non-loopback address opens them to the whole network - refusing to start. For remote operations use an SSH tunnel (ssh -L 9444:127.0.0.1:9444 ...) or an authenticated reverse proxy.",
                self.admin_bind
            ));
        }
        // Review item 4: the ticket TTL must not exceed flock-sync's
        // TICKET_TTL_SECS(60s) hard cap (§2.2 cross-server replay window =
        // min(±300s, TTL) —— raising it widens the replay surface).
        // Deployments may lower it (for expiry-path acceptance), never raise
        // it.
        if self.ticket_ttl_secs > crate::ticket::TICKET_TTL_SECS {
            return Err(format!(
                "ticket_ttl_secs {} exceeds the hard cap {} (the §2.2 ticket TTL 60s hard cap: raising it widens the cross-server replay window; it can only be lowered)",
                self.ticket_ttl_secs,
                crate::ticket::TICKET_TTL_SECS
            ));
        }
        // M8 (§M8.2): [webui] validation —— port and TTL tiers + conflicts
        // with existing listening surfaces refuse to start.
        if self.webui.enabled {
            if self.webui.port == 0 {
                return Err("[webui] port is 0 (1..=65535)".into());
            }
            if !(60..=86_400).contains(&self.webui.session_ttl_secs) {
                return Err(format!(
                    "[webui] session_ttl_secs {} out of range 60..=86400 (default 8h)",
                    self.webui.session_ttl_secs
                ));
            }
            if self.webui.series_points == 0 || self.webui.series_interval_secs == 0 {
                return Err("[webui] series_points/series_interval_secs must be ≥ 1".into());
            }
            // Port-conflict surface: bind / admin_bind / admin_bind+1 (the
            // cluster bootstrap endpoint) / raft_bind. (The webui's own dual
            // bind 127.0.0.1:port and vip:port share one port —— not part of
            // self-conflict.)
            let webui_port = self.webui.port;
            let mut conflicts: Vec<(u16, &str)> = Vec::new();
            if self.bind.port() != 0 && self.bind.port() == webui_port {
                conflicts.push((self.bind.port(), "bind"));
            }
            if self.admin_bind.port() != 0 {
                if self.admin_bind.port() == webui_port {
                    conflicts.push((self.admin_bind.port(), "admin_bind"));
                }
                // admin_bind+1 (the cluster bootstrap endpoint): u16 addition
                // via checked_add —— 65535+1 overflow (a direct panic in
                // debug / wraps to 0 in release) means no +1 endpoint exists
                // to conflict with (green review item 7).
                if let Some(boot) = self.admin_bind.port().checked_add(1) {
                    if boot == webui_port {
                        conflicts.push((boot, "admin_bind+1 (cluster bootstrap endpoint)"));
                    }
                }
            }
            if let Some(sync) = &self.sync {
                if sync.raft_bind.port() != 0 && sync.raft_bind.port() == webui_port {
                    conflicts.push((sync.raft_bind.port(), "sync.raft_bind"));
                }
            }
            if let Some((port, face)) = conflicts.first() {
                return Err(format!(
                    "[webui] port {webui_port} conflicts with {face} (:{port}) - the webui dual bind (127.0.0.1:{webui_port} + vip:{webui_port}) needs a dedicated port; refusing to start",
                ));
            }
        }
        Ok(())
    }

    /// Resolve into a ListenerMode (default direct; frp requires an `[frp]`
    /// section).
    pub fn listener_mode(&self) -> Result<ListenerMode, String> {
        match self.mode.as_str() {
            "" | "direct" => Ok(ListenerMode::Direct { bind: self.bind }),
            "frp" => {
                let frp = self
                    .frp
                    .as_ref()
                    .ok_or("listener.mode = \"frp\" requires an [frp] section")?;
                // Review item 14: the [frp].flavor dispatch (original default
                // / chmlfrp); the config layer validates required fields then
                // produces a FrpRelayPlan; RelaySpec construction stays in
                // frp.rs (type isolation).
                let relay = match frp.flavor.as_str() {
                    "" | "original" => {
                        if frp.original_toml.trim().is_empty() {
                            return Err(
                                "[frp] flavor = \"original\" requires the full original_toml text"
                                    .into(),
                            );
                        }
                        FrpRelayPlan::Original {
                            toml: frp.original_toml.clone(),
                        }
                    }
                    "chmlfrp" => match (&frp.user_token_auto, &frp.chmlfrp_ini) {
                        (Some(uta), _) => {
                            if uta.usertoken.trim().is_empty() {
                                return Err("[frp] user_token_auto.usertoken is empty".into());
                            }
                            if uta.tunnel_id == 0 {
                                return Err("[frp] user_token_auto.tunnel_id is 0".into());
                            }
                            FrpRelayPlan::ChmlFrp {
                                ini: frp.chmlfrp_ini.clone(),
                                user_token_auto: Some(uta.clone()),
                            }
                        }
                        (None, Some(ini)) => FrpRelayPlan::ChmlFrp {
                            ini: Some(ini.clone()),
                            user_token_auto: None,
                        },
                        (None, None) => return Err(
                            "[frp] flavor = \"chmlfrp\" requires chmlfrp_ini (the panel-exported \
                                 frpc.ini path; default ConfigFile mode) or an explicit \
                                 [frp.user_token_auto] opt-in"
                                .into(),
                        ),
                    },
                    other => {
                        return Err(format!(
                            "[frp] unknown flavor: {other:?} (original|chmlfrp)"
                        ))
                    }
                };
                Ok(ListenerMode::Frp {
                    bind: self.bind,
                    plan: FrpPlan {
                        relay,
                        frpc_bin: frp.frpc_bin.clone(),
                        run_base: frp
                            .run_base
                            .clone()
                            .unwrap_or_else(|| self.state_dir.join("frpc-run")),
                    },
                })
            }
            other => Err(format!("unknown listener.mode: {other:?} (direct|frp)")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_defaults_to_direct_and_frp_requires_section() {
        let cfg: ServerConfig = toml::from_str(
            r#"
            state_dir = "/tmp/s"
            advertise_endpoint = "127.0.0.1:9443"
        "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.listener_mode().unwrap(),
            ListenerMode::Direct { .. }
        ));
        assert_eq!(cfg.ticket_ttl_secs, 60);
        assert_eq!(cfg.mode, "direct");
        assert_eq!(
            cfg.max_sessions, 1024,
            "concurrent session cap default 1024 (review item 7)"
        );

        let cfg2: ServerConfig = toml::from_str(
            r#"
            state_dir = "/tmp/s"
            advertise_endpoint = "127.0.0.1:27500"
            mode = "frp"
        "#,
        )
        .unwrap();
        assert!(
            cfg2.listener_mode().is_err(),
            "frp without an [frp] section ⇒ rejected"
        );

        let cfg3: ServerConfig = toml::from_str(
            r#"
            state_dir = "/tmp/s"
            advertise_endpoint = "127.0.0.1:27500"
            mode = "frp"
            [frp]
            original_toml = """
serverAddr = "frps"
serverPort = 7000
"""
        "#,
        )
        .unwrap();
        let ListenerMode::Frp { plan, .. } = cfg3.listener_mode().unwrap() else {
            panic!("frp mode");
        };
        match &plan.relay {
            FrpRelayPlan::Original { toml } => assert!(toml.contains("serverAddr")),
            other => panic!("default flavor = original: {other:?}"),
        }
        assert_eq!(plan.run_base, PathBuf::from("/tmp/s/frpc-run"));
    }

    /// Review item 3: the admin/cluster-bootstrap endpoints must be loopback
    /// —— non-loopback refuses to start and the error explains the SSH
    /// tunnel/reverse-proxy alternative; the whole 127.0.0.0/8 and ::1 pass.
    #[test]
    fn admin_bind_must_be_loopback() {
        fn cfg_with_admin(admin: &str) -> ServerConfig {
            let text = format!(
                "state_dir = \"/tmp/s\"\nadvertise_endpoint = \"127.0.0.1:9443\"\nadmin_bind = \"{admin}\""
            );
            toml::from_str(&text).unwrap()
        }
        // The whole loopback block passes (127.x.y.z and ::1).
        for ok in ["127.0.0.1:9444", "127.3.2.1:9444", "[::1]:9444"] {
            let cfg = cfg_with_admin(ok);
            cfg.validate()
                .unwrap_or_else(|e| panic!("{ok} should pass: {e}"));
        }
        // Non-loopback rejected —— the error must explain that remote
        // operations go through an SSH tunnel/reverse proxy.
        for bad in [
            "0.0.0.0:9444",
            "10.1.2.3:9444",
            "[::]:9444",
            "[fe80::1]:9444",
        ] {
            let err = cfg_with_admin(bad).validate().unwrap_err();
            assert!(err.contains("loopback"), "{bad} rejected: {err}");
            assert!(
                err.contains("SSH") || err.contains("reverse proxy"),
                "the error must state the alternative channel: {err}"
            );
        }
    }

    /// Review item 4: ticket_ttl_secs ≤ TICKET_TTL_SECS(60s) —— beyond it
    /// refuses to start; lowering passes (the lowerable semantics are kept:
    /// for expiry-path acceptance deployments).
    #[test]
    fn ticket_ttl_upper_bound_enforced() {
        fn cfg_with_ttl(ttl: u64) -> ServerConfig {
            let text = format!(
                "state_dir = \"/tmp/s\"\nadvertise_endpoint = \"127.0.0.1:9443\"\nticket_ttl_secs = {ttl}"
            );
            toml::from_str(&text).unwrap()
        }
        assert!(
            cfg_with_ttl(60).validate().is_ok(),
            "exactly the hard cap ⇒ passes"
        );
        assert!(
            cfg_with_ttl(6).validate().is_ok(),
            "lowered ⇒ passes (smoke deployments)"
        );
        let err = cfg_with_ttl(61).validate().unwrap_err();
        assert!(err.contains("60"), "the error names the hard cap: {err}");
        assert!(err.contains("only be lowered"), "{err}");
    }

    // ------------------------------------------------------------------
    // M8 (§M8.2/W7): the [webui] section —— defaults / tier validation /
    // port conflicts refusing to start / key-set whitelist
    // ------------------------------------------------------------------

    fn cfg_with_webui(webui: &str) -> ServerConfig {
        let text = format!(
            "state_dir = \"/tmp/s\"
advertise_endpoint = \"127.0.0.1:9443\"
{webui}"
        );
        toml::from_str(&text).unwrap()
    }

    /// Defaults: enabled=true/port=9800/TTL 8h/series 120×60.
    #[test]
    fn webui_section_defaults() {
        let cfg = cfg_with_webui("");
        assert_eq!(cfg.webui.port, 9800);
        assert!(cfg.webui.enabled);
        assert_eq!(cfg.webui.session_ttl_secs, 28_800);
        assert_eq!(cfg.webui.series_points, 120);
        assert_eq!(cfg.webui.series_interval_secs, 60);
        assert!(cfg.validate().is_ok());
        // Explicit override round trip.
        let cfg = cfg_with_webui(
            "[webui]
enabled = false
port = 9900
session_ttl_secs = 3600
series_points = 60
series_interval_secs = 30
",
        );
        assert!(!cfg.webui.enabled);
        assert_eq!(cfg.webui.port, 9900);
        assert_eq!(cfg.webui.session_ttl_secs, 3600);
        assert!(
            cfg.validate().is_ok(),
            "enabled=false skips the port-conflict surface"
        );
    }

    /// TTL tier (60..=86400) and port 0 rejected.
    #[test]
    fn webui_range_validation() {
        assert!(cfg_with_webui(
            "[webui]
session_ttl_secs = 60
"
        )
        .validate()
        .is_ok());
        assert!(cfg_with_webui(
            "[webui]
session_ttl_secs = 86400
"
        )
        .validate()
        .is_ok());
        for bad_ttl in ["59", "86401"] {
            let err = cfg_with_webui(&format!(
                "[webui]
session_ttl_secs = {bad_ttl}
"
            ))
            .validate()
            .unwrap_err();
            assert!(err.contains("60..=86400"), "{bad_ttl}: {err}");
        }
        let err = cfg_with_webui(
            "[webui]
port = 0
",
        )
        .validate()
        .unwrap_err();
        assert!(err.contains("port"), "{err}");
    }

    /// Port conflicts refuse to start (W7): colliding with bind /
    /// admin_bind / admin_bind+1 / raft_bind ⇒ the error names the
    /// conflicting surface; no conflict passes.
    #[test]
    fn webui_port_conflicts_reject() {
        let mk = |extra: &str, webui_port: u16| {
            let text = format!(
                "state_dir = \"/tmp/s\"
advertise_endpoint = \"127.0.0.1:9443\"
{extra}
[webui]
port = {webui_port}
"
            );
            toml::from_str::<ServerConfig>(&text).unwrap()
        };
        // Collides with bind (9443).
        let err = mk("", 9443).validate().unwrap_err();
        assert!(
            err.contains("bind") && err.contains("refusing to start"),
            "{err}"
        );
        // Collides with admin_bind (9444).
        let err = mk("", 9444).validate().unwrap_err();
        assert!(err.contains("admin_bind"), "{err}");
        // Collides with admin_bind+1 (9445, the cluster bootstrap endpoint).
        let err = mk("", 9445).validate().unwrap_err();
        assert!(err.contains("cluster bootstrap endpoint"), "{err}");
        // Collides with raft_bind.
        let err = mk(
            "[sync]
mode = \"raft\"
",
            9500,
        )
        .validate()
        .unwrap_err();
        assert!(err.contains("raft_bind"), "{err}");
        // A dedicated port passes (bind 0.0.0.0:9443 / admin 9444 / raft
        // default 9500 all miss 9800).
        assert!(mk("", 9800).validate().is_ok());
        // bind port 0 (the test ephemeral form) joins no conflict surface.
        let text = "state_dir = \"/tmp/s\"
advertise_endpoint = \"x\"
bind = \"127.0.0.1:0\"
admin_bind = \"127.0.0.1:0\"
[webui]
port = 9800
";
        let cfg: ServerConfig = toml::from_str(text).unwrap();
        assert!(cfg.validate().is_ok());
    }

    /// The +1 derivation at admin_bind=65535 goes through checked_add
    /// (green review item 7): the u16 overflow neither panics (the old
    /// implementation overflow-panicked on `65535 + 1` in debug builds) nor
    /// misreports a port-0 conflict.
    #[test]
    fn webui_port_conflict_admin_bind_65535_no_overflow_panic() {
        let text = "state_dir = \"/tmp/s\"
advertise_endpoint = \"x\"
admin_bind = \"127.0.0.1:65535\"
[webui]
port = 9800
";
        let cfg: ServerConfig = toml::from_str(text).unwrap();
        assert!(
            cfg.validate().is_ok(),
            "65535+1 overflow means no cluster-bootstrap port to conflict with - passes without panicking"
        );
    }

    /// Key-set whitelist (W7 structural misconfiguration defense): unknown
    /// keys like bind in [webui] ⇒ rejected at the parsing layer
    /// (deny_unknown_fields —— a 0.0.0.0 mistake is structurally impossible,
    /// not caught by validation).
    #[test]
    fn webui_unknown_keys_rejected_at_parse() {
        let err = toml::from_str::<ServerConfig>(
            "state_dir = \"/tmp/s\"
advertise_endpoint = \"x\"
[webui]
bind = \"0.0.0.0:9800\"
",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("bind"),
            "the unknown key is named: {err}"
        );
        assert!(
            toml::from_str::<ServerConfig>(
                "state_dir = \"/tmp/s\"
advertise_endpoint = \"x\"
[webui]
listen = \"0.0.0.0\"
"
            )
            .is_err(),
            "any key outside the whitelist rejected"
        );
    }
}
