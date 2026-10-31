//! 配置生成器接缝（docs/design.md §3.9；frp-compat §4-R8/R12）。
//!
//! 两栈配置方言不同，生成/解析各一套：
//!
//! - **ChmlFrp INI**（v0.51.2 方言，`[common]` + `[<proxy>]` 小写下划线键）：
//!   [`ChmlFrpIniConfig`] 结构化生成、[`parse_ini`] 解析、[`augment_chmlfrp_admin`]
//!   `[common]`-only 的 admin 注入。**R12 红线**：面板生成的 proxy 参数逐字节透传
//!   （服务端 CheckProxy 与面板记录比对，不一致即拒——frp-compat §2.3），
//!   注入只碰 `[common]` 的 admin 字段，proxy 节按原始行原样保留。
//! - **原版 TOML**（v0.71.1 方言，camelCase：`serverAddr`/`[[proxies]]`/`webServer`）：
//!   [`OriginalTomlConfig`] 结构化生成、[`parse_original_toml`] 只读解析（调用方文件
//!   绝不改写）。
//!
//! golden 样本（`tests/golden/`）逐字节复制自官方发行包：
//! `.tmp/chmlfrpc/ChmlFrp-0.51.2_251023_linux_amd64/frpc.ini` 与
//! `.tmp/frp_0.71.1_linux_amd64/frpc.toml`（INI 样本磁盘形态为 CRLF——Windows 侧解包
//! 所致，golden 对比按行尾归一化）。

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use crate::probe::{AdminEndpoint, ProbeTargets};
use crate::spec::FrpcError;

// ---------------------------------------------------------------------------
// ChmlFrp INI（v0.51.2 方言）
// ---------------------------------------------------------------------------

/// 解析后的 INI 文档（保序；v0.51.2 `k = v` 方言，重复键后者覆盖前者）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedIni {
    /// `(节名, 有序键值对)`；节名不含方括号（`common`、`ssh`、`range:tcp_port`…）。
    pub sections: Vec<(String, Vec<(String, String)>)>,
}

impl ParsedIni {
    /// 取节（首个匹配）。
    pub fn section(&self, name: &str) -> Option<&[(String, String)]> {
        self.sections
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, kv)| kv.as_slice())
    }

    /// 取节内字段值（大小写敏感键，v0.51.2 面板字段为全小写）。
    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.section(section)?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// 解析 v0.51.2 INI（注释 `#`/`;`、空行、`[节]`、`k = v`；值不剥引号——面板不产引号）。
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
                "INI 第 {} 行不是节头/键值对/注释: {line:?}",
                ln + 1
            )));
        };
        let key = k.trim().to_string();
        if key.is_empty() {
            return Err(FrpcError::Config(format!("INI 第 {} 行键为空", ln + 1)));
        }
        let val = v.trim().to_string();
        let Some((_, entries)) = cur.as_mut() else {
            return Err(FrpcError::Config(format!(
                "INI 第 {} 行的键值对出现在任何节头之前: {line:?}",
                ln + 1
            )));
        };
        match entries.iter_mut().find(|(ek, _)| *ek == key) {
            Some((_, ev)) => *ev = val, // 重复键后者胜（go-ini 语义）
            None => entries.push((key, val)),
        }
    }
    if let Some(sec) = cur {
        doc.sections.push(sec);
    }
    Ok(doc)
}

/// ChmlFrp frpc.ini 的 admin 探测字段（v0.51.2 `[common]`：admin_addr/admin_port/
/// admin_user/admin_pwd；admin_port=0/缺省即禁用 admin 监听）。
#[derive(Clone, Debug)]
pub struct AdminCommon {
    pub addr: IpAddr,
    pub port: u16,
    pub user: String,
    pub password: String,
}

/// **R12 红线变换**：向面板 frpc.ini 的 `[common]` 注入/覆盖 admin 字段，其余一切逐字节保留。
///
/// - 仅 `[common]` 节被重建，且只动 `admin_addr/admin_port/admin_user/admin_pwd` 四键
///   （存在则原位覆盖，缺失则补在节尾）；`[common]` 内的注释/空行按原位保留；
/// - **proxy 节（含其注释、空行、字段顺序、行尾风格）原样拷贝**——CheckProxy 逐项比对
///   面板记录（frp-compat §2.3），任何 proxy 侧改写都可能被拒；
/// - 无 `[common]` 节 → 拒绝（面板导出必含；宁可失败也不静默脱离托管）。
///
/// 输出写到托管 run 目录的副本上执行；面板源文件本身不动。
pub fn augment_chmlfrp_admin(src: &str, admin: &AdminCommon) -> Result<String, FrpcError> {
    const ADMIN_KEYS: [&str; 4] = ["admin_addr", "admin_port", "admin_user", "admin_pwd"];
    let admin_vals = [
        admin.addr.to_string(),
        admin.port.to_string(),
        admin.user.clone(),
        admin.password.clone(),
    ];

    let mut lines: Vec<&str> = src.split('\n').collect();
    if lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop(); // 源以换行收尾时 split 的尾部空段不参与重建（防多出一空行）
    }
    // 行尾风格跟随源文件（split 已剥离 \r，CRLF 以重建方式等价保留）。
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
            // 离开 [common]：补齐该节缺失的 admin 键
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
            // [common] 内的 admin 键：原位覆盖；其余（含注释/空行/其它字段）原样保留
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
            "面板 frpc.ini 缺 [common] 节，拒绝注入 admin（托管面不完整的配置不出门）".into(),
        ));
    }
    Ok(out)
}

/// 在 `[common]` 节尾补齐源文件缺失的 admin 键。
fn flush_admin_tail(out: &mut String, seen: &[bool; 4], vals: &[String; 4], eol: &str) {
    const KEYS: [&str; 4] = ["admin_addr", "admin_port", "admin_user", "admin_pwd"];
    for i in 0..4 {
        if !seen[i] {
            out.push_str(&format!("{} = {}{}", KEYS[i], vals[i], eol));
        }
    }
}

/// ChmlFrp frpc.ini 结构化生成器（保序字段表；golden 输出与官方样本逐字节一致）。
#[derive(Clone, Debug, Default)]
pub struct ChmlFrpIniConfig {
    common: Vec<(String, String)>,
    proxies: Vec<(String, Vec<(String, String)>)>,
}

impl ChmlFrpIniConfig {
    /// `[common]` 起步：server_addr/server_port（面板样本最小集，frpc.ini 样本:1-3）。
    pub fn new(server_addr: impl Into<String>, server_port: u16) -> Self {
        Self {
            common: vec![
                ("server_addr".into(), server_addr.into()),
                ("server_port".into(), server_port.to_string()),
            ],
            proxies: Vec::new(),
        }
    }

    /// 追加/覆盖 `[common]` 字段（如 `user`/`token`/`tls_enable`/admin 四键）。
    pub fn common(mut self, key: &str, value: impl Into<String>) -> Self {
        let value = value.into();
        match self.common.iter_mut().find(|(k, _)| k == key) {
            Some((_, v)) => *v = value,
            None => self.common.push((key.to_string(), value)),
        }
        self
    }

    /// 追加 tcp proxy 节（字段序 = 面板样本形态：type/local_ip/local_port/remote_port）。
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

    /// 生成 INI 文本（LF 行尾、`k = v` 定界、节间一空行、文件以换行收尾——与官方样本
    /// 归一化后逐字节一致；见 `tests/golden_config.rs`）。
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

/// 从面板/托管 INI 推导探活目标（只读推导，不改配置）。
///
/// - admin：`[common]` 的 `admin_port` 非 0 即启用（addr 缺省 127.0.0.1——v0.51.2 面板
///   导出形态），携带 admin_user/admin_pwd（`/api/status` basic auth）；
/// - 本地隧道口：首个 `type = tcp` 节的 `local_ip`（缺省 127.0.0.1）+ `local_port`。
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
// 原版 TOML（v0.71.1 方言）
// ---------------------------------------------------------------------------

/// 原版 frpc TOML 生成器（v0.71.1 camelCase 方言；golden 输出与官方样本逐字节一致）。
#[derive(Clone, Debug, Default)]
pub struct OriginalTomlConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub auth_token: Option<String>,
    pub web_server: Option<WebServerSection>,
    pub proxies: Vec<TcpProxySection>,
}

/// `[webServer]` 节（admin API：`/healthz` 免认证 + `/api/status` basic auth，
/// common.go:50-60；port=0 即不启动 admin）。
#[derive(Clone, Debug)]
pub struct WebServerSection {
    pub addr: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

/// `[[proxies]]` tcp 节。
#[derive(Clone, Debug)]
pub struct TcpProxySection {
    pub name: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_port: u16,
}

impl OriginalTomlConfig {
    /// 顶层起步：serverAddr/serverPort（官方 frpc.toml 样本:1-2）。
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

    /// 追加 tcp proxy（字段序 = 官方样本：name/type/localIP/localPort/remotePort）。
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

    /// 生成 TOML 文本（LF；表体在标量键之后，符合 TOML 语法序）。
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

/// TOML basic string 转义（`\` `"` 与控制字符；路径/凭据均可安全承载）。
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

/// 只读解析调用方的原版 frpc TOML（**绝不改写**；解析失败早于 spawn 暴露）。
pub fn parse_original_toml(path: &Path) -> Result<toml::Table, FrpcError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        FrpcError::Config(format!("读取原版 frpc.toml 失败 {}: {e}", path.display()))
    })?;
    text.parse::<toml::Table>()
        .map_err(|e| FrpcError::Config(format!("解析原版 frpc.toml 失败 {}: {e}", path.display())))
}

/// 从原版 TOML 推导探活目标（webServer + 首个 tcp proxy 的本地隧道口）。
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
        // 重复键后者胜
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
        // 注释放进 proxy 节内部（INI 语义：节头后的一切属该节；CheckProxy 比对的正是这块）
        let panel = "[common]\nserver_addr = node.example\nserver_port = 7000\ntoken = tk\n\n[ssh]\n# proxy 注释也不许动\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = 22\nremote_port = 6000\n";
        let admin = AdminCommon {
            addr: "127.0.0.1".parse().unwrap(),
            port: 7400,
            user: "admin".into(),
            password: "pw".into(),
        };
        let out = augment_chmlfrp_admin(panel, &admin).unwrap();
        // proxy 节逐字节保留（含节内注释行）
        let proxy_src = &panel[panel.find("[ssh]").unwrap()..];
        assert!(
            out.ends_with(proxy_src),
            "proxy 节被改写:\n{out}\n期望尾部:\n{proxy_src}"
        );
        // common 得到 admin 四键
        let parsed = parse_ini(&out).unwrap();
        assert_eq!(parsed.get("common", "admin_port"), Some("7400"));
        assert_eq!(parsed.get("common", "admin_user"), Some("admin"));
        assert_eq!(parsed.get("common", "admin_pwd"), Some("pw"));
        // 原有字段不动
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
        // 原位覆盖：admin_port 仍在 server_port 之后、[ssh] 之前
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

        // auth/webServer 全量形态
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
