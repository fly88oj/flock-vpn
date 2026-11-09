//! client.toml (docs/design.md §3.12: `flock-client --config client.toml`).

use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::lang::LanguageSetting;

/// Client configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// State directory (device.keys / pins.bin / directory.bin / vip /
    /// credentials / sr-sig.key).
    pub state_dir: PathBuf,
    /// Local VIP override (default None ⇒ read the state_dir/vip file —
    /// written by the deployment orchestration).
    #[serde(default)]
    pub vip: Option<Ipv4Addr>,
    /// TUN interface name (default "tun0"; the §6.3 A3 assertion targets
    /// `ip link show tun0`).
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// MTU (default 1280, §2.1).
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Endpoint override (for debugging/assertions pinning; default = rotate
    /// over all endpoints in the root-signed directory, §2.3).
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// Control IPC group authorization (§7-M6.2, Unix only): the token file
    /// and socket get chgrp'd to this group (group name resolved against the
    /// local /etc/group or a numeric gid; ignored on Windows — the pipe DACL
    /// covers IU). Default None ⇒ root:root (root-controlled only,
    /// works out of the box).
    #[serde(default)]
    pub control_group: Option<String>,
    /// Hostname override for reporting (M7 §7-M7.7: the "hostname" column of
    /// the key-bind roster registration; default = OS hostname;
    /// truncation/empty semantics aligned with the server-side normalize).
    #[serde(default)]
    pub hostname: Option<String>,
    /// Login configuration (M7: OPAQUE login/key-bind/ticket keepalive;
    /// default absent = no login, roster unavailable).
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    /// General settings (UI language of tray/CLI interactive copy).
    #[serde(default)]
    pub general: GeneralConfig,
}

/// `[general]` section: tray/CLI interactive-copy language (see
/// [`crate::lang`]); operational logs stay English regardless.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GeneralConfig {
    /// `"auto"|"en"|"zh"` (default `auto` = best-effort detection, fallback
    /// `en`); unknown values are a parse error.
    #[serde(default)]
    pub language: LanguageSetting,
}

/// `[auth]` section (M7 §7-M7.7).
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Login username (= device registration owner; the same value as the
    /// `--user` of `device-add`/`redeem`).
    pub username: String,
    /// Password file path (0600, single line; default state_dir/credentials —
    /// written by `flock-client login`).
    #[serde(default)]
    pub credentials_file: Option<PathBuf>,
}

fn default_tun_name() -> String {
    "tun0".into()
}

fn default_mtu() -> u16 {
    crate::tun::MTU
}

impl ClientConfig {
    /// Parse client.toml.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaults_and_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("client.toml");
        std::fs::write(
            &p,
            format!(
                "state_dir = {:?}\n",
                dir.path().join("state").to_str().unwrap()
            ),
        )
        .unwrap();
        let cfg = ClientConfig::load(&p).unwrap();
        assert_eq!(cfg.tun_name, "tun0");
        assert_eq!(cfg.mtu, 1280, "MTU default 1280 (§2.1)");
        assert!(cfg.vip.is_none());
        assert!(cfg.endpoints.is_empty());
        assert!(cfg.hostname.is_none(), "hostname default = OS hostname");
        assert!(cfg.auth.is_none(), "[auth] default absent (no login)");
        assert_eq!(
            cfg.general.language,
            LanguageSetting::Auto,
            "language default auto"
        );

        let cred_path = if cfg!(windows) {
            "C:/custom/cred".to_string()
        } else {
            "/custom/cred".to_string()
        };
        std::fs::write(
            &p,
            format!(
                "state_dir = {:?}\nvip = \"100.64.0.11\"\nendpoints = [\"frps:27500\", \"frps:27501\"]\nhostname = \"box-a\"\n\n[general]\nlanguage = \"zh\"\n\n[auth]\nusername = \"alice\"\ncredentials_file = \"{}\"\n",
                dir.path().join("state").to_str().unwrap(),
                cred_path,
            ),
        )
        .unwrap();
        let cfg = ClientConfig::load(&p).unwrap();
        assert_eq!(cfg.vip, Some("100.64.0.11".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(cfg.endpoints, vec!["frps:27500", "frps:27501"]);
        assert_eq!(cfg.hostname.as_deref(), Some("box-a"));
        assert_eq!(cfg.general.language, LanguageSetting::Zh);
        let auth = cfg.auth.expect("[auth] parsed");
        assert_eq!(auth.username, "alice");
        assert_eq!(
            auth.credentials_file.as_deref(),
            Some(std::path::Path::new(if cfg!(windows) {
                "C:/custom/cred"
            } else {
                "/custom/cred"
            }))
        );
    }

    /// M7: [auth] with username only (credentials_file default None — the
    /// daemon side lands on state_dir/credentials).
    #[test]
    fn parse_auth_section_minimal() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("client.toml");
        std::fs::write(
            &p,
            format!(
                "state_dir = {:?}\n\n[auth]\nusername = \"bob\"\n",
                dir.path().join("s").to_str().unwrap()
            ),
        )
        .unwrap();
        let cfg = ClientConfig::load(&p).unwrap();
        let auth = cfg.auth.expect("[auth]");
        assert_eq!(auth.username, "bob");
        assert!(auth.credentials_file.is_none());
    }

    /// [general] language must be an exact known token ("auto"|"en"|"zh") —
    /// typos surface as a parse error instead of silently falling back.
    #[test]
    fn parse_general_language_rejects_unknown_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("client.toml");
        std::fs::write(
            &p,
            format!(
                "state_dir = {:?}\n\n[general]\nlanguage = \"english\"\n",
                dir.path().join("s").to_str().unwrap()
            ),
        )
        .unwrap();
        assert!(ClientConfig::load(&p).is_err());
    }
}
