//! Config generator seam (docs/design.md §3.9; frp-compat §4-R8/R12).
//!
//! The two stacks use different config dialects, each with its own
//! generation/parsing:
//!
//! - **ChmlFrp INI** (v0.51.2 dialect, `[common]` + `[<proxy>]`
//!   lowercase-underscore keys): structured generation by
//!   [`ChmlFrpIniConfig`], parsing by [`parse_ini`], and `[common]`-only
//!   admin injection by [`augment_chmlfrp_admin`]. **R12 red line**:
//!   panel-generated proxy parameters pass through byte for byte (the
//!   server-side CheckProxy compares them against the panel's records; any
//!   mismatch is rejected — frp-compat §2.3); injection touches only the
//!   admin fields of `[common]`, and proxy sections are preserved as the
//!   original lines.
//! - **Original TOML** (v0.71.1 dialect, camelCase: `serverAddr`/
//!   `[[proxies]]`/`webServer`): structured generation by
//!   [`OriginalTomlConfig`], read-only parsing by [`parse_original_toml`]
//!   (the caller's file is never rewritten).
//!
//! Golden samples (`tests/golden/`) copied byte for byte from the official
//! release archives:
//! `.tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/frpc.ini` and
//! `.tmp/frp_0.71.1_linux_amd64/frpc.toml` (the INI sample's on-disk shape is
//! CRLF — an artifact of unpacking on Windows; golden comparison normalizes
//! line endings).

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use crate::probe::{AdminEndpoint, ProbeTargets};
use crate::spec::FrpcError;

// ---------------------------------------------------------------------------
// ChmlFrp INI (v0.51.2 dialect)
// ---------------------------------------------------------------------------

/// A parsed INI document (order-preserving; the v0.51.2 `k = v` dialect,
/// later duplicate keys override earlier ones).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedIni {
    /// `(section name, ordered key-value pairs)`; section names carry no
    /// brackets (`common`, `ssh`, `range:tcp_port`…).
    pub sections: Vec<(String, Vec<(String, String)>)>,
}

impl ParsedIni {
    /// Fetch a section (first match).
    pub fn section(&self, name: &str) -> Option<&[(String, String)]> {
        self.sections
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, kv)| kv.as_slice())
    }

    /// Fetch a field's value inside a section (case-sensitive keys; the
    /// v0.51.2 panel fields are all lowercase).
    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.section(section)?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Parse a v0.51.2 INI (comments `#`/`;`, blank lines, `[section]`, `k = v`;
/// values keep their quotes — the panel produces none).
pub fn parse_ini(text: &str) -> Result<ParsedIni, FrpcError> {
    let mut doc = ParsedIni::default();
    let mut cur: Option<(String, Vec<(String, String)>)> = None;
    for (ln, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Some(sec) = cur.take() {
                doc.sections.push(sec);
            }
            cur = Some((name.trim().to_string(), Vec::new()));
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(FrpcError::Config(format!(
                "INI line {} is not a section header/key-value/comment: {line:?}",
                ln + 1
            )));
        };
        let key = k.trim().to_string();
        if key.is_empty() {
            return Err(FrpcError::Config(format!(
                "INI line {} has an empty key",
                ln + 1
            )));
        }
        let val = v.trim().to_string();
        let Some((_, entries)) = cur.as_mut() else {
            return Err(FrpcError::Config(format!(
                "INI line {} key-value appears before any section header: {line:?}",
                ln + 1
            )));
        };
        match entries.iter_mut().find(|(ek, _)| *ek == key) {
            Some((_, ev)) => *ev = val, // later duplicate key wins (go-ini semantics)
            None => entries.push((key, val)),
        }
    }
    if let Some(sec) = cur {
        doc.sections.push(sec);
    }
    Ok(doc)
}

/// Admin probing fields for the ChmlFrp frpc.ini (v0.51.2 `[common]`:
/// admin_addr/admin_port/admin_user/admin_pwd; admin_port=0 or absent means
/// the admin listener is disabled).
///
/// `user`/`password` are spliced directly into `[common]` as `k = v` (see
/// [`augment_chmlfrp_admin`]) and must pass the [`validate_ini_scalar`]
/// injection defense; `addr`/`port` are `IpAddr`/`u16`, whose Display forms
/// naturally contain no control characters or brackets and need no check.
#[derive(Clone, Debug)]
pub struct AdminCommon {
    pub addr: IpAddr,
    pub port: u16,
    pub user: String,
    pub password: String,
}

/// INI key/value injection defense: reject control characters (including
/// newline/`\0`/`\t`) and `[`/`]`.
///
/// The v0.51.2 `k = v` dialect has **no quoting/escaping surface** (a value
/// is the bare string to end-of-line) — contrast the original-TOML side,
/// where [`OriginalTomlConfig::render`] goes through [`toml_str`]'s escaping
/// discipline: TOML has an escaping surface and can carry arbitrary
/// characters, INI does not ⇒ any character that could splice out a
/// `[new-section]` line or an extra key-value line is **rejected as an
/// error**, never silently rewritten (a value containing newline/`[`/`]`
/// could inject arbitrary sections into the supervised frpc.ini).
fn validate_ini_scalar(what: &str, s: &str) -> Result<(), FrpcError> {
    if let Some(bad) = s.chars().find(|&c| c.is_control() || c == '[' || c == ']') {
        return Err(FrpcError::Config(format!(
            "INI {what} contains forbidden character {bad:?} (control characters and [ ] — the k = v dialect splices with no escaping surface; section-injection defense)"
        )));
    }
    Ok(())
}

/// **The R12 red-line transform**: inject/overwrite the admin fields in the
/// panel frpc.ini's `[common]`; everything else is preserved byte for byte.
///
/// - Only the `[common]` section is rebuilt, and only the four keys
///   `admin_addr/admin_port/admin_user/admin_pwd` are touched (overwritten in
///   place when present, appended to the section tail when missing);
///   comments/blank lines inside `[common]` are kept in their original
///   positions;
/// - **Proxy sections (including their comments, blank lines, field order,
///   and line-ending style) are copied verbatim** — CheckProxy compares item
///   by item against the panel records (frp-compat §2.3); any proxy-side
///   rewrite could get rejected;
/// - no `[common]` section → refuse (a panel export always contains one;
///   better to fail than to silently leave the supervised surface).
///
/// The output is produced on the copy in the supervised run directory; the
/// panel source file itself is untouched.
pub fn augment_chmlfrp_admin(src: &str, admin: &AdminCommon) -> Result<String, FrpcError> {
    // Injection defense first: admin values are spliced into `[common]` as
    // `k = v` (both the in-place overwrite and the section-tail append
    // paths); credentials containing newline/`[`/`]`/control characters
    // could splice out new sections — rejected as an error, not a single
    // byte written.
    validate_ini_scalar("admin_user value", &admin.user)?;
    validate_ini_scalar("admin_pwd value", &admin.password)?;
    const ADMIN_KEYS: [&str; 4] = ["admin_addr", "admin_port", "admin_user", "admin_pwd"];
    let admin_vals = [
        admin.addr.to_string(),
        admin.port.to_string(),
        admin.user.clone(),
        admin.password.clone(),
    ];

    let mut lines: Vec<&str> = src.split('\n').collect();
    if lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop(); // when the source ends with a newline, split's trailing empty segment does not participate in the rebuild (avoids one extra blank line)
    }
    // Line-ending style follows the source file (split already peeled off
    // \r; CRLF is preserved equivalently by reconstruction).
    let eol = if lines.first().map(|l| l.ends_with('\r')).unwrap_or(false) {
        "\r\n"
    } else {
        "\n"
    };

    let mut out = String::with_capacity(src.len() + 128);
    let mut seen = [false; 4];
    let mut in_common = false;
    let mut has_common = false;

    for raw in &lines {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();

        if let Some(name) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // Leaving [common]: append the section's missing admin keys.
            if in_common {
                flush_admin_tail(&mut out, &seen, &admin_vals, eol);
                in_common = false;
            }
            if name.trim().eq_ignore_ascii_case("common") {
                in_common = true;
                has_common = true;
                out.push_str("[common]");
                out.push_str(eol);
                continue;
            }
        } else if in_common
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !trimmed.starts_with(';')
        {
            // Admin keys inside [common]: overwritten in place; everything
            // else (including comments/blank lines/other fields) preserved
            // as-is.
            if let Some((k, _)) = trimmed.split_once('=') {
                if let Some(idx) = ADMIN_KEYS
                    .iter()
                    .position(|ak| ak.eq_ignore_ascii_case(k.trim()))
                {
                    out.push_str(&format!("{} = {}{}", k.trim(), admin_vals[idx], eol));
                    seen[idx] = true;
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push_str(eol);
    }
    if in_common {
        flush_admin_tail(&mut out, &seen, &admin_vals, eol);
    }
    if !has_common {
        return Err(FrpcError::Config(
            "panel frpc.ini has no [common] section; refusing to inject admin (an incomplete supervised config does not ship)".into(),
        ));
    }
    Ok(out)
}

/// Append the admin keys missing from the source at the `[common]` section's
/// tail.
fn flush_admin_tail(out: &mut String, seen: &[bool; 4], vals: &[String; 4], eol: &str) {
    const KEYS: [&str; 4] = ["admin_addr", "admin_port", "admin_user", "admin_pwd"];
    for i in 0..4 {
        if !seen[i] {
            out.push_str(&format!("{} = {}{}", KEYS[i], vals[i], eol));
        }
    }
}

/// Structured ChmlFrp frpc.ini generator (order-preserving field table;
/// golden output matches the official sample byte for byte).
#[derive(Clone, Debug, Default)]
pub struct ChmlFrpIniConfig {
    common: Vec<(String, String)>,
    proxies: Vec<(String, Vec<(String, String)>)>,
}

impl ChmlFrpIniConfig {
    /// Start with `[common]`: server_addr/server_port (the panel sample's
    /// minimal set, frpc.ini sample:1-3).
    pub fn new(server_addr: impl Into<String>, server_port: u16) -> Self {
        Self {
            common: vec![
                ("server_addr".into(), server_addr.into()),
                ("server_port".into(), server_port.to_string()),
            ],
            proxies: Vec::new(),
        }
    }

    /// Append/overwrite a `[common]` field (e.g. the `user`/`token`/
    /// `tls_enable`/admin four keys).
    ///
    /// key/value must pass [`validate_ini_scalar`]: the INI dialect splices
    /// with no escaping surface (contrast the TOML side's
    /// [`OriginalTomlConfig::render`] with its `toml_str` discipline — that
    /// side escapes, this side rejects); input containing control
    /// characters/newline/`[`/`]` could inject new sections ⇒ returns an
    /// error.
    pub fn common(mut self, key: &str, value: impl Into<String>) -> Result<Self, FrpcError> {
        let value = value.into();
        validate_ini_scalar("common key", key)?;
        validate_ini_scalar("common value", &value)?;
        match self.common.iter_mut().find(|(k, _)| k == key) {
            Some((_, v)) => *v = value,
            None => self.common.push((key.to_string(), value)),
        }
        Ok(self)
    }

    /// Append a tcp proxy section (field order = the panel sample's shape:
    /// type/local_ip/local_port/remote_port).
    pub fn tcp_proxy(
        mut self,
        name: &str,
        local_ip: &str,
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        self.proxies.push((
            name.to_string(),
            vec![
                ("type".to_string(), "tcp".to_string()),
                ("local_ip".to_string(), local_ip.to_string()),
                ("local_port".to_string(), local_port.to_string()),
                ("remote_port".to_string(), remote_port.to_string()),
            ],
        ));
        self
    }

    /// Render the INI text (LF line endings, `k = v` delimiting, one blank
    /// line between sections, the file ending with a newline — byte-for-byte
    /// identical to the official sample after normalization; see
    /// `tests/golden_config.rs`).
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("[common]\n");
        for (k, v) in &self.common {
            out.push_str(&format!("{k} = {v}\n"));
        }
        for (name, entries) in &self.proxies {
            out.push('\n');
            out.push_str(&format!("[{name}]\n"));
            for (k, v) in entries {
                out.push_str(&format!("{k} = {v}\n"));
            }
        }
        out
    }
}

/// Derive probe targets from the panel/supervised INI (read-only derivation,
/// no config changes).
///
/// - admin: a non-zero `admin_port` in `[common]` means enabled (addr
///   defaults to 127.0.0.1 — the v0.51.2 panel export shape), carrying
///   admin_user/admin_pwd (`/api/status` basic auth);
/// - local tunnel port: the first `type = tcp` section's `local_ip`
///   (default 127.0.0.1) + `local_port`.
pub fn chmlfrp_probe_targets(ini: &ParsedIni) -> ProbeTargets {
    let admin = ini
        .get("common", "admin_port")
        .and_then(|p| p.parse::<u16>().ok())
        .filter(|p| *p != 0)
        .map(|port| {
            let addr = ini.get("common", "admin_addr").unwrap_or("127.0.0.1");
            AdminEndpoint {
                addr: SocketAddr::new(addr.parse().unwrap_or("127.0.0.1".parse().unwrap()), port),
                user: ini.get("common", "admin_user").map(str::to_string),
                password: ini.get("common", "admin_pwd").map(str::to_string),
            }
        });
    let local_tunnel = ini.sections.iter().find_map(|(name, kv)| {
        if name.eq_ignore_ascii_case("common") {
            return None;
        }
        let get = |k: &str| kv.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.as_str());
        let is_tcp = get("type")
            .map(|t| t.eq_ignore_ascii_case("tcp"))
            .unwrap_or(false);
        if !is_tcp {
            return None;
        }
        let port = get("local_port").and_then(|p| p.parse::<u16>().ok())?;
        let ip = get("local_ip").unwrap_or("127.0.0.1");
        Some(SocketAddr::new(
            ip.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap()),
            port,
        ))
    });
    ProbeTargets {
        admin,
        local_tunnel,
    }
}

// ---------------------------------------------------------------------------
// Original TOML (v0.71.1 dialect)
// ---------------------------------------------------------------------------

/// Original frpc TOML generator (v0.71.1 camelCase dialect; golden output
/// matches the official sample byte for byte).
#[derive(Clone, Debug, Default)]
pub struct OriginalTomlConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub auth_token: Option<String>,
    pub web_server: Option<WebServerSection>,
    pub proxies: Vec<TcpProxySection>,
}

/// The `[webServer]` section (admin API: `/healthz` unauthenticated +
/// `/api/status` basic auth, common.go:50-60; port=0 means no admin).
#[derive(Clone, Debug)]
pub struct WebServerSection {
    pub addr: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

/// A `[[proxies]]` tcp section.
#[derive(Clone, Debug)]
pub struct TcpProxySection {
    pub name: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
}

impl OriginalTomlConfig {
    /// Top-level start: serverAddr/serverPort (official frpc.toml
    /// sample:1-2).
    pub fn new(server_addr: impl Into<String>, server_port: u16) -> Self {
        Self {
            server_addr: server_addr.into(),
            server_port,
            ..Self::default()
        }
    }

    pub fn auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    pub fn web_server(mut self, ws: WebServerSection) -> Self {
        self.web_server = Some(ws);
        self
    }

    /// Append a tcp proxy (field order = the official sample:
    /// name/type/localIP/localPort/remotePort).
    pub fn tcp_proxy(
        mut self,
        name: &str,
        local_ip: &str,
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        self.proxies.push(TcpProxySection {
            name: name.to_string(),
            local_ip: local_ip.to_string(),
            local_port,
            remote_port,
        });
        self
    }

    /// Render the TOML text (LF; table bodies after the scalar keys,
    /// conforming to TOML grammar order).
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("serverAddr = {}\n", toml_str(&self.server_addr)));
        out.push_str(&format!("serverPort = {}\n", self.server_port));
        if let Some(t) = &self.auth_token {
            out.push_str("\n[auth]\ntoken = ");
            out.push_str(&toml_str(t));
            out.push('\n');
        }
        if let Some(ws) = &self.web_server {
            out.push_str("\n[webServer]\n");
            out.push_str(&format!("addr = {}\n", toml_str(&ws.addr)));
            out.push_str(&format!("port = {}\n", ws.port));
            if let Some(u) = &ws.user {
                out.push_str(&format!("user = {}\n", toml_str(u)));
            }
            if let Some(p) = &ws.password {
                out.push_str(&format!("password = {}\n", toml_str(p)));
            }
        }
        for p in &self.proxies {
            out.push_str("\n[[proxies]]\n");
            out.push_str(&format!("name = {}\n", toml_str(&p.name)));
            out.push_str("type = \"tcp\"\n");
            out.push_str(&format!("localIP = {}\n", toml_str(&p.local_ip)));
            out.push_str(&format!("localPort = {}\n", p.local_port));
            out.push_str(&format!("remotePort = {}\n", p.remote_port));
        }
        out
    }
}

/// TOML basic-string escaping (`\` `"` and control characters; paths and
/// credentials are all safely representable).
fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Read-only parsing of the caller's original frpc TOML (**never rewritten**;
/// parse failures surface before spawn).
pub fn parse_original_toml(path: &Path) -> Result<toml::Table, FrpcError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        FrpcError::Config(format!(
            "failed to read original frpc.toml {}: {e}",
            path.display()
        ))
    })?;
    text.parse::<toml::Table>().map_err(|e| {
        FrpcError::Config(format!(
            "failed to parse original frpc.toml {}: {e}",
            path.display()
        ))
    })
}

/// Derive probe targets from the original TOML (webServer + the first tcp
/// proxy's local tunnel port).
pub fn original_probe_targets(root: &toml::Table) -> ProbeTargets {
    let admin = root
        .get("webServer")
        .and_then(|v| v.as_table())
        .and_then(|ws| {
            let port = ws.get("port").and_then(|v| v.as_integer()).unwrap_or(0);
            if port <= 0 || port > u16::MAX as i64 {
                return None;
            }
            let addr = ws
                .get("addr")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1");
            Some(AdminEndpoint {
                addr: SocketAddr::new(
                    addr.parse()
                        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap()),
                    port as u16,
                ),
                user: ws.get("user").and_then(|v| v.as_str()).map(str::to_string),
                password: ws
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            })
        });
    let local_tunnel = root
        .get("proxies")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter().find_map(|p| {
                let t = p.as_table()?;
                if t.get("type").and_then(|v| v.as_str()) != Some("tcp") {
                    return None;
                }
                let port = t.get("localPort").and_then(|v| v.as_integer())?;
                if port <= 0 || port > u16::MAX as i64 {
                    return None;
                }
                let ip = t
                    .get("localIP")
                    .and_then(|v| v.as_str())
                    .unwrap_or("127.0.0.1");
                Some(SocketAddr::new(
                    ip.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap()),
                    port as u16,
                ))
            })
        });
    ProbeTargets {
        admin,
        local_tunnel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PANEL_SAMPLE: &str = "[common]\nserver_addr = 127.0.0.1\nserver_port = 7000\n\n[ssh]\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = 22\nremote_port = 6000\n";

    #[test]
    fn parse_ini_roundtrip_and_lookup() {
        let doc = parse_ini(PANEL_SAMPLE).unwrap();
        assert_eq!(doc.get("common", "server_addr"), Some("127.0.0.1"));
        assert_eq!(doc.get("ssh", "local_port"), Some("22"));
        assert_eq!(doc.section("missing"), None);
        // Later duplicate key wins.
        let dup = parse_ini("[common]\na = 1\na = 2\n").unwrap();
        assert_eq!(dup.get("common", "a"), Some("2"));
        assert_eq!(dup.section("common").unwrap().len(), 1);
    }

    #[test]
    fn parse_ini_rejects_malformed() {
        assert!(parse_ini("no section = 1\n").is_err());
        assert!(parse_ini("[s]\nbare line\n").is_err());
    }

    #[test]
    fn structured_render_matches_sample_layout() {
        let rendered = ChmlFrpIniConfig::new("127.0.0.1", 7000)
            .tcp_proxy("ssh", "127.0.0.1", 22, 6000)
            .render();
        assert_eq!(rendered, PANEL_SAMPLE);
    }

    #[test]
    fn augment_preserves_proxy_sections_byte_verbatim() {
        // A comment placed inside the proxy section (INI semantics:
        // everything after a section header belongs to it; this is exactly
        // what CheckProxy compares).
        let panel = "[common]\nserver_addr = node.example\nserver_port = 7000\ntoken = tk\n\n[ssh]\n# proxy comments must not be touched either\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = 22\nremote_port = 6000\n";
        let admin = AdminCommon {
            addr: "127.0.0.1".parse().unwrap(),
            port: 7400,
            user: "admin".into(),
            password: "pw".into(),
        };
        let out = augment_chmlfrp_admin(panel, &admin).unwrap();
        // The proxy section is preserved byte for byte (including in-section
        // comment lines).
        let proxy_src = &panel[panel.find("[ssh]").unwrap()..];
        assert!(
            out.ends_with(proxy_src),
            "proxy section was rewritten:\n{out}\nexpected tail:\n{proxy_src}"
        );
        // [common] received the four admin keys.
        let parsed = parse_ini(&out).unwrap();
        assert_eq!(parsed.get("common", "admin_port"), Some("7400"));
        assert_eq!(parsed.get("common", "admin_user"), Some("admin"));
        assert_eq!(parsed.get("common", "admin_pwd"), Some("pw"));
        // Pre-existing fields untouched.
        assert_eq!(parsed.get("common", "token"), Some("tk"));
        assert_eq!(parsed.get("ssh", "remote_port"), Some("6000"));
    }

    #[test]
    fn augment_overrides_existing_admin_in_place() {
        let panel = "[common]\nserver_addr = n\nserver_port = 7000\nadmin_port = 1111\nadmin_user = old\n\n[ssh]\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = 22\nremote_port = 6000\n";
        let admin = AdminCommon {
            addr: "127.0.0.1".parse().unwrap(),
            port: 7400,
            user: "new".into(),
            password: "pw".into(),
        };
        let out = augment_chmlfrp_admin(panel, &admin).unwrap();
        let parsed = parse_ini(&out).unwrap();
        assert_eq!(parsed.get("common", "admin_port"), Some("7400"));
        assert_eq!(parsed.get("common", "admin_user"), Some("new"));
        // In-place override: admin_port still after server_port, before
        // [ssh].
        let common: Vec<&str> = out.lines().collect();
        let i_sp = common
            .iter()
            .position(|l| l.starts_with("server_port"))
            .unwrap();
        let i_ap = common
            .iter()
            .position(|l| l.starts_with("admin_port"))
            .unwrap();
        let i_ssh = common.iter().position(|l| *l == "[ssh]").unwrap();
        assert!(i_sp < i_ap && i_ap < i_ssh);
    }

    #[test]
    fn augment_keeps_crlf_style() {
        let panel = "[common]\r\nserver_addr = n\r\nserver_port = 7000\r\n\r\n[ssh]\r\ntype = tcp\r\nlocal_ip = 127.0.0.1\r\nlocal_port = 22\r\nremote_port = 6000\r\n";
        let admin = AdminCommon {
            addr: "127.0.0.1".parse().unwrap(),
            port: 7400,
            user: "admin".into(),
            password: "pw".into(),
        };
        let out = augment_chmlfrp_admin(panel, &admin).unwrap();
        assert!(out.starts_with("[common]\r\n"));
        assert!(out.contains("admin_port = 7400\r\n"));
        assert!(out.contains("remote_port = 6000\r\n"));
    }

    #[test]
    fn augment_rejects_missing_common() {
        let panel =
            "[ssh]\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = 22\nremote_port = 6000\n";
        let admin = AdminCommon {
            addr: "127.0.0.1".parse().unwrap(),
            port: 7400,
            user: "a".into(),
            password: "b".into(),
        };
        assert!(augment_chmlfrp_admin(panel, &admin).is_err());
    }

    /// Injection attempts must be rejected: admin values are spliced into
    /// `[common]` as `k = v`; credentials containing newline/`[`/`]`/control
    /// characters could splice out new sections (contrast the TOML side's
    /// toml_str escaping discipline — INI has no escaping surface, so only
    /// rejection is possible).
    #[test]
    fn augment_rejects_admin_values_that_could_inject_sections() {
        let over = |user: &str, password: &str| AdminCommon {
            addr: "127.0.0.1".parse().unwrap(),
            port: 7400,
            user: user.into(),
            password: password.into(),
        };
        // Values forging a new section + key-value lines (newline injection).
        assert!(
            augment_chmlfrp_admin(PANEL_SAMPLE, &over("u\n[shadow]\ntoken = pwned", "pw")).is_err()
        );
        assert!(
            augment_chmlfrp_admin(PANEL_SAMPLE, &over("admin", "p\n[shadow]\ntoken = pwned"))
                .is_err()
        );
        // Square brackets (can disturb section-header parsing).
        assert!(augment_chmlfrp_admin(PANEL_SAMPLE, &over("adm[in", "pw")).is_err());
        assert!(augment_chmlfrp_admin(PANEL_SAMPLE, &over("admin", "p]w")).is_err());
        // Control characters (\t/\0 — close kin of newline, likewise
        // rejected).
        assert!(augment_chmlfrp_admin(PANEL_SAMPLE, &over("ad\tmin", "pw")).is_err());
        assert!(augment_chmlfrp_admin(PANEL_SAMPLE, &over("admin", "p\0w")).is_err());
        // Legitimate credentials unaffected (regression).
        assert!(augment_chmlfrp_admin(PANEL_SAMPLE, &over("admin", "p@ss word-9!")).is_ok());
    }

    /// The structured generator follows the same discipline: `common()`'s
    /// key/value containing newline/brackets/control characters is an error
    /// (render splices `k = v` with no escaping surface).
    #[test]
    fn structured_common_rejects_injection_attempts() {
        let base = || ChmlFrpIniConfig::new("node.example", 7000);
        // Key with a newline + section header.
        assert!(base().common("k\n[shadow]", "v").is_err());
        // Value forging a new section + subsequent key-values.
        assert!(base()
            .common("token", "v\n[shadow]\nserver_addr = evil")
            .is_err());
        // Square brackets (rejected in both key and value).
        assert!(base().common("[k]", "v").is_err());
        assert!(base().common("k", "a]b").is_err());
        // Control characters.
        assert!(base().common("k", "v\u{7}").is_err());
        assert!(base().common("k\u{b}", "v").is_err());
        // Legitimate key-values unaffected (regression).
        assert!(base().common("user", "token-6e447a2e28fdb4d0").is_ok());
        assert!(base().common("tls_enable", "true").is_ok());
    }

    #[test]
    fn chmlfrp_probe_targets_derivation() {
        let ini = parse_ini(PANEL_SAMPLE).unwrap();
        let t = chmlfrp_probe_targets(&ini);
        assert_eq!(t.admin, None);
        assert_eq!(t.local_tunnel, Some("127.0.0.1:22".parse().unwrap()));

        let with_admin = parse_ini(
            "[common]\nserver_addr = n\nserver_port = 7000\nadmin_port = 7400\nadmin_user = u\nadmin_pwd = p\n\n[ssh]\ntype = tcp\nlocal_ip = 10.0.0.5\nlocal_port = 9443\nremote_port = 23000\n",
        )
        .unwrap();
        let t = chmlfrp_probe_targets(&with_admin);
        let admin = t.admin.expect("admin");
        assert_eq!(admin.addr, "127.0.0.1:7400".parse().unwrap());
        assert_eq!(admin.user.as_deref(), Some("u"));
        assert_eq!(t.local_tunnel, Some("10.0.0.5:9443".parse().unwrap()));
    }

    #[test]
    fn original_render_and_probe_derivation() {
        let cfg =
            OriginalTomlConfig::new("127.0.0.1", 7000).tcp_proxy("test-tcp", "127.0.0.1", 22, 6000);
        let text = cfg.render();
        let table: toml::Table = text.parse().unwrap();
        assert_eq!(table.get("serverAddr").unwrap().as_str(), Some("127.0.0.1"));
        assert_eq!(table.get("serverPort").unwrap().as_integer(), Some(7000));
        let proxies = table.get("proxies").unwrap().as_array().unwrap();
        assert_eq!(proxies.len(), 1);
        let p = proxies[0].as_table().unwrap();
        assert_eq!(p.get("name").unwrap().as_str(), Some("test-tcp"));
        assert_eq!(p.get("type").unwrap().as_str(), Some("tcp"));
        assert_eq!(p.get("localIP").unwrap().as_str(), Some("127.0.0.1"));
        assert_eq!(p.get("localPort").unwrap().as_integer(), Some(22));
        assert_eq!(p.get("remotePort").unwrap().as_integer(), Some(6000));

        let t = original_probe_targets(&table);
        assert_eq!(t.admin, None);
        assert_eq!(t.local_tunnel, Some("127.0.0.1:22".parse().unwrap()));

        // The full auth/webServer form.
        let full = OriginalTomlConfig::new("frps.example", 7000)
            .auth_token("sec\"ret\\path")
            .web_server(WebServerSection {
                addr: "127.0.0.1".into(),
                port: 7400,
                user: Some("admin".into()),
                password: Some("pw".into()),
            })
            .tcp_proxy("vpn", "127.0.0.1", 9443, 23000)
            .render();
        let table: toml::Table = full.parse().unwrap();
        assert_eq!(
            table.get("auth").unwrap().get("token").unwrap().as_str(),
            Some("sec\"ret\\path")
        );
        let ws = table.get("webServer").unwrap().as_table().unwrap();
        assert_eq!(ws.get("port").unwrap().as_integer(), Some(7400));
        let t = original_probe_targets(&table);
        let admin = t.admin.unwrap();
        assert_eq!(admin.addr, "127.0.0.1:7400".parse().unwrap());
        assert_eq!(t.local_tunnel, Some("127.0.0.1:9443".parse().unwrap()));
    }
}
