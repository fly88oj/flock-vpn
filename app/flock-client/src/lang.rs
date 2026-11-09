//! UI language pack for tray/CLI interactive copy (M7 follow-up i18n).
//!
//! Scope rule (one place for Chinese, everything else English-only):
//! - **Interactive copy** — tray menu texts, CLI guidance and error prompts
//!   (login/peers/status/usage) — is rendered through [`Lang::tr`]/[`Lang::trf`]
//!   with per-language tables ([`EN_TABLE`]/[`ZH_TABLE`]). The zh table is the
//!   **only** place Chinese text may appear in this crate.
//! - **Operational diagnostic logs** (technical `eprintln` lines on stderr) are
//!   English-only and never go through the pack (industry convention; the lines
//!   e2e/m3/m7 assertion scripts grep are uniformly English).
//!
//! Language selection: `client.toml` `[general] language = "auto"|"en"|"zh"`
//! ([`LanguageSetting`]); `auto` = best-effort detection — Unix consults
//! `LC_ALL`/`LANG`, Windows consults `GetUserDefaultUILanguage` (existing
//! windows-sys dependency, no new crate) — falling back to `en` whenever
//! detection fails or yields something else.
//!
//! Completeness is guarded by tests: the en and zh tables must carry exactly
//! the same key set (no missing entries on either side, no duplicates).

use serde::Deserialize;

/// UI language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// English (default).
    #[default]
    En,
    /// Simplified Chinese.
    Zh,
}

/// `[general] language` setting (`"auto"|"en"|"zh"`; unknown values are a
/// config parse error — typos should surface, not silently fall back).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LanguageSetting {
    /// Best-effort detection ([`Lang::detect`]); fallback `en`.
    #[default]
    Auto,
    En,
    Zh,
}

impl LanguageSetting {
    /// Resolve to a concrete [`Lang`] (`auto` ⇒ detection).
    pub fn resolve(self) -> Lang {
        match self {
            LanguageSetting::Auto => Lang::detect(),
            LanguageSetting::En => Lang::En,
            LanguageSetting::Zh => Lang::Zh,
        }
    }
}

/// Interactive-copy message keys (tray menu / CLI guidance / errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    // —— tray menu ——
    /// "Quit" menu action item.
    TrayQuit,
    /// Connection state label: connected.
    TrayStateConnected,
    /// Connection state label: connecting.
    TrayStateConnecting,
    /// Connection state label: disconnected.
    TrayStateDisconnected,
    /// Connection state label: daemon/service not reachable.
    TrayServiceDown,
    /// Status menu line: `Connection: {0}`.
    TrayStatusLine,
    /// VIP menu line: `VPN IP: {0}`.
    TrayVipLine,
    /// Tooltip: `Flock VPN: {0} · VPN IP {1}`.
    TrayTooltip,

    // —— CLI usage / argument errors ——
    /// Top-level usage text.
    CliUsage,
    /// `--config` without a value.
    CliErrConfigValue,
    /// `--user` + `--service` are mutually exclusive.
    CliErrScopeMutex,
    /// `tray` subcommand not compiled in (headless build).
    CliErrTrayNotBuilt,
    /// `invite` without a path argument.
    CliErrInvitePath,
    /// Unknown subcommand `{0}` (+ usage).
    CliErrUnknownSub,
    /// install/uninstall error doc pointer.
    CliInstallDocHint,

    // —— login ——
    /// client.toml missing `[auth] username`.
    CliLoginErrNoAuth,
    /// Interactive password prompt.
    CliLoginPrompt,
    /// stdin read failure while reading the password.
    CliLoginErrReadPassword,
    /// Empty password rejected.
    CliLoginErrEmptyPassword,
    /// Credentials file write failure.
    CliLoginErrWriteCredentials,
    /// Credentials saved (0600).
    CliLoginCredentialsSaved,
    /// Service password set (PwCommit accepted).
    CliLoginPwSet,
    /// Service password already exists (kept as-is).
    CliLoginPwExists,
    /// Directory has no usable endpoints.
    CliLoginNoEndpoints,
    /// All endpoints tried; aggregated failure guidance.
    CliLoginAllFailed,

    // —— status / peers ——
    /// Token file unreadable (status).
    CliStatusErrToken,
    /// Request denied (token mismatch).
    CliErrDenied,
    /// Unexpected IPC response variant.
    CliErrUnexpectedResp,
    /// Control plane unreachable (status).
    CliStatusErrUnreachable,
    /// Token file unreadable (peers).
    CliPeersErrToken,
    /// PeersUnavailable guidance suffix.
    CliPeersErrUnavailable,
    /// Control plane unreachable (peers).
    CliPeersErrUnreachable,

    // —— peers table ——
    PeersHdrHostname,
    PeersHdrAccount,
    PeersHdrType,
    PeersHdrStatus,
    PeersHdrLatency,
    PeersHdrDown,
    PeersHdrUp,
    PeersStatusOnline,
    PeersStatusOffline,
    PeersStatusServerDown,
}

impl Key {
    /// All keys (table completeness tests consume this).
    pub const ALL: &'static [Key] = &[
        Key::TrayQuit,
        Key::TrayStateConnected,
        Key::TrayStateConnecting,
        Key::TrayStateDisconnected,
        Key::TrayServiceDown,
        Key::TrayStatusLine,
        Key::TrayVipLine,
        Key::TrayTooltip,
        Key::CliUsage,
        Key::CliErrConfigValue,
        Key::CliErrScopeMutex,
        Key::CliErrTrayNotBuilt,
        Key::CliErrInvitePath,
        Key::CliErrUnknownSub,
        Key::CliInstallDocHint,
        Key::CliLoginErrNoAuth,
        Key::CliLoginPrompt,
        Key::CliLoginErrReadPassword,
        Key::CliLoginErrEmptyPassword,
        Key::CliLoginErrWriteCredentials,
        Key::CliLoginCredentialsSaved,
        Key::CliLoginPwSet,
        Key::CliLoginPwExists,
        Key::CliLoginNoEndpoints,
        Key::CliLoginAllFailed,
        Key::CliStatusErrToken,
        Key::CliErrDenied,
        Key::CliErrUnexpectedResp,
        Key::CliStatusErrUnreachable,
        Key::CliPeersErrToken,
        Key::CliPeersErrUnavailable,
        Key::CliPeersErrUnreachable,
        Key::PeersHdrHostname,
        Key::PeersHdrAccount,
        Key::PeersHdrType,
        Key::PeersHdrStatus,
        Key::PeersHdrLatency,
        Key::PeersHdrDown,
        Key::PeersHdrUp,
        Key::PeersStatusOnline,
        Key::PeersStatusOffline,
        Key::PeersStatusServerDown,
    ];
}

/// English pack (default).
pub const EN_TABLE: &[(Key, &str)] = &[
    (Key::TrayQuit, "Quit"),
    (Key::TrayStateConnected, "Connected"),
    (Key::TrayStateConnecting, "Connecting"),
    (Key::TrayStateDisconnected, "Disconnected"),
    (Key::TrayServiceDown, "service not running"),
    (Key::TrayStatusLine, "Connection: {0}"),
    (Key::TrayVipLine, "VPN IP: {0}"),
    (Key::TrayTooltip, "Flock VPN: {0} · VPN IP {1}"),
    (
        Key::CliUsage,
        "\
flock-client [--config <client.toml>] [<subcommand>]

Subcommands:
  (run)                  foreground debug mode (default): tun + routes + connector supervise (no IPC)
  service                daemon: supervise + control-plane IPC + graceful shutdown (§7-M6) + M7 login keepalive
  status                 send one Status request to the daemon and print it (probe without a tray)
  login                  first-time setup: read password -> 0600 credentials file -> set service
                         password + login verification + hostname registration (M7 §7-M7.7; the
                         daemon reads the file non-interactively)
  peers [--json]         member roster (VIP/hostname/account/status/latency/traffic; M7 §7-M7.7)
  install [--user|--service]  install service + tray autostart (default both; --config at install
                         time is recorded into the service definition)
  uninstall [--user|--service]  reverse uninstall
  tray                   tray process (right-click menu: connection status / VPN IP / quit; exits
                         gracefully without a GUI session)
  invite <path>          load invite (b64 text / raw bytes) -> pin cluster root key + store directory
  gen-keys               generate/reuse device keys and print public keys (device-x=/device-ed= b64)
  --smoke                on-machine smoke: create tun + apply routes + print status, then exit
                         (§7-M3 manual checklist)
",
    ),
    (
        Key::CliErrConfigValue,
        "--config requires a value",
    ),
    (
        Key::CliErrScopeMutex,
        "--user and --service are mutually exclusive (default installs both)",
    ),
    (
        Key::CliErrTrayNotBuilt,
        "tray subcommand is not built into this binary (headless --no-default-features build; \
         rebuild with the tray feature to enable it)",
    ),
    (
        Key::CliErrInvitePath,
        "invite requires <file-path>",
    ),
    (
        Key::CliErrUnknownSub,
        "unknown subcommand {0}\n\n{1}",
    ),
    (
        Key::CliInstallDocHint,
        "\n(elevation requirements and the platform matrix: docs/manual/service-install.md)",
    ),
    (
        Key::CliLoginErrNoAuth,
        "client.toml has no [auth] username (login configuration)",
    ),
    (
        Key::CliLoginPrompt,
        "flock-client: login password (user={0}, single line, will be saved to {1}): ",
    ),
    (
        Key::CliLoginErrReadPassword,
        "read password: {0}",
    ),
    (
        Key::CliLoginErrEmptyPassword,
        "password is empty",
    ),
    (
        Key::CliLoginErrWriteCredentials,
        "write credentials file: {0}",
    ),
    (
        Key::CliLoginCredentialsSaved,
        "flock-client: credentials saved (0600): {0}",
    ),
    (
        Key::CliLoginPwSet,
        "flock-client: service password set",
    ),
    (
        Key::CliLoginPwExists,
        "flock-client: service password already exists (kept as-is; if login fails, the password \
         does not match)",
    ),
    (
        Key::CliLoginNoEndpoints,
        "directory has no usable endpoints (run `flock-client invite <file>` first)",
    ),
    (
        Key::CliLoginAllFailed,
        "{0} (all endpoints tried; credentials written to {1} — re-run `flock-client login` after \
         troubleshooting to change the password; check server reachability and whether \
         device-add --user was {2})",
    ),
    (
        Key::CliStatusErrToken,
        "{0} (daemon not running, or this user may not read the control token)",
    ),
    (
        Key::CliErrDenied,
        "request denied (token mismatch — the old token is invalid after a daemon restart, retry)",
    ),
    (
        Key::CliErrUnexpectedResp,
        "unexpected response: {0}",
    ),
    (
        Key::CliStatusErrUnreachable,
        "control plane unreachable: {0} (daemon not running? start it with `flock-client \
         service` or the service manager)",
    ),
    (
        Key::CliPeersErrToken,
        "{0}\n(daemon not running? start it with `flock-client service` or the system service \
         manager; the control-plane token is generated by the daemon at startup)",
    ),
    (
        Key::CliPeersErrUnavailable,
        "{0}\n(guidance: make sure `flock-client service` is running, client.toml configures \
         `[auth] username`, and `flock-client login` has been run to complete password \
         bootstrap)",
    ),
    (
        Key::CliPeersErrUnreachable,
        "control plane unreachable: {0}\n(daemon not running? start it with `flock-client \
         service` or the system service manager)",
    ),
    (Key::PeersHdrHostname, "Hostname"),
    (Key::PeersHdrAccount, "Account"),
    (Key::PeersHdrType, "Type"),
    (Key::PeersHdrStatus, "Status"),
    (Key::PeersHdrLatency, "Latency(ms)"),
    (Key::PeersHdrDown, "Down(B/s)"),
    (Key::PeersHdrUp, "Up(B/s)"),
    (Key::PeersStatusOnline, "online"),
    (Key::PeersStatusOffline, "offline"),
    (Key::PeersStatusServerDown, "service not running"),
];

/// Chinese pack — the only place Chinese text is allowed in this crate.
pub const ZH_TABLE: &[(Key, &str)] = &[
    (Key::TrayQuit, "退出"),
    (Key::TrayStateConnected, "已连接"),
    (Key::TrayStateConnecting, "连接中"),
    (Key::TrayStateDisconnected, "未连接"),
    (Key::TrayServiceDown, "服务未运行"),
    (Key::TrayStatusLine, "连接状态：{0}"),
    (Key::TrayVipLine, "VPN IP：{0}"),
    (Key::TrayTooltip, "Flock VPN：{0} · VPN IP {1}"),
    (
        Key::CliUsage,
        "\
flock-client [--config <client.toml>] [<subcommand>]

子命令：
  (run)                  前台调试模式（缺省）：tun + 路由 + 接入器守护（不起 IPC）
  service                daemon：supervise + 控制面 IPC + 优雅停服（§7-M6）+ M7 登录保持
  status                 向 daemon 发一次 Status 请求并打印（无托盘环境探针）
  login                  首次配置：读口令 → 0600 凭据文件 → 设服务端口令 + 登录验证
                         + hostname 入册（M7 §7-M7.7；daemon 非交互读文件）
  peers [--json]         成员名册（VIP/主机名/账户/状态/延迟/流量；M7 §7-M7.7）
  install [--user|--service]  安装服务+托盘自启（缺省两者；安装时 --config 记入服务定义）
  uninstall [--user|--service] 反向卸载
  tray                   托盘进程（右键菜单：连接状态/VPN IP/退出；无 GUI 会话优雅退出）
  invite <path>          载入邀请（b64 文本/原始字节）→ 钉扎根公钥 + 存根签目录
  gen-keys               生成/复用设备密钥并打印公钥（device-x=/device-ed= b64）
  --smoke                真机冒烟：建 tun + 配路由 + 打印状态即退（§7-M3 手工清单）
",
    ),
    (Key::CliErrConfigValue, "--config 需要一个值"),
    (
        Key::CliErrScopeMutex,
        "--user 与 --service 互斥（缺省 = 两者都装）",
    ),
    (
        Key::CliErrTrayNotBuilt,
        "tray 子命令未编入本构建（--no-default-features 无头档；重编译请启用 tray feature）",
    ),
    (Key::CliErrInvitePath, "invite 需要 <文件路径>"),
    (Key::CliErrUnknownSub, "未知子命令 {0}\n\n{1}"),
    (
        Key::CliInstallDocHint,
        "\n（提权要求与平台矩阵见 docs/manual/service-install.md）",
    ),
    (
        Key::CliLoginErrNoAuth,
        "client.toml 缺 [auth] username（登录配置）",
    ),
    (
        Key::CliLoginPrompt,
        "flock-client: 登录口令（user={0}，单行，将保存到 {1}）: ",
    ),
    (Key::CliLoginErrReadPassword, "读口令: {0}"),
    (Key::CliLoginErrEmptyPassword, "口令为空"),
    (Key::CliLoginErrWriteCredentials, "写凭据文件: {0}"),
    (
        Key::CliLoginCredentialsSaved,
        "flock-client: 凭据已保存（0600）: {0}",
    ),
    (Key::CliLoginPwSet, "flock-client: 服务端口令已设置"),
    (
        Key::CliLoginPwExists,
        "flock-client: 服务端口令已存在（沿用；若登录失败说明口令失配）",
    ),
    (
        Key::CliLoginNoEndpoints,
        "目录无可用端点（先 `flock-client invite <file>`）",
    ),
    (
        Key::CliLoginAllFailed,
        "{0}（端点全试尽；凭据已写入 {1}——排障后重跑 `flock-client login` 可换口令；\
         检查服务端可达性与 device-add --user 是否为 {2}）",
    ),
    (
        Key::CliStatusErrToken,
        "{0}（daemon 未运行，或本用户无权读取控制 token）",
    ),
    (
        Key::CliErrDenied,
        "请求被拒（token 失配——daemon 重启后旧 token 失效，重试）",
    ),
    (Key::CliErrUnexpectedResp, "意外响应: {0}"),
    (
        Key::CliStatusErrUnreachable,
        "控制面不可达: {0}（daemon 未运行？`flock-client service` 或服务管理器启动）",
    ),
    (
        Key::CliPeersErrToken,
        "{0}\n（daemon 未运行？`flock-client service` 或系统服务管理器启动；\
         控制面 token 由 daemon 启动时生成）",
    ),
    (
        Key::CliPeersErrUnavailable,
        "{0}\n（指引：确认 `flock-client service` 在跑、client.toml 配置了 \
         `[auth] username`、且已跑过 `flock-client login` 完成口令引导）",
    ),
    (
        Key::CliPeersErrUnreachable,
        "控制面不可达: {0}\n（daemon 未运行？`flock-client service` 或系统服务管理器启动）",
    ),
    (Key::PeersHdrHostname, "主机名"),
    (Key::PeersHdrAccount, "账户"),
    (Key::PeersHdrType, "类型"),
    (Key::PeersHdrStatus, "状态"),
    (Key::PeersHdrLatency, "延迟(ms)"),
    (Key::PeersHdrDown, "↓流量(B/s)"),
    (Key::PeersHdrUp, "↑流量(B/s)"),
    (Key::PeersStatusOnline, "在线"),
    (Key::PeersStatusOffline, "离线"),
    (Key::PeersStatusServerDown, "服务未运行"),
];

impl Lang {
    fn table(self) -> &'static [(Key, &'static str)] {
        match self {
            Lang::En => EN_TABLE,
            Lang::Zh => ZH_TABLE,
        }
    }

    /// Look up a message (missing entry ⇒ English fallback ⇒ empty string;
    /// the completeness tests keep the missing-entry path unreachable).
    pub fn tr(self, key: Key) -> &'static str {
        let hit = self
            .table()
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, s)| *s);
        hit.or_else(|| EN_TABLE.iter().find(|(k, _)| *k == key).map(|(_, s)| *s))
            .unwrap_or("")
    }

    /// Look up a message and substitute `{0}`, `{1}`, … placeholders with the
    /// given arguments (indexed, so packs may reorder arguments freely).
    pub fn trf(self, key: Key, args: &[&dyn std::fmt::Display]) -> String {
        let mut out = self.tr(key).to_string();
        for (i, a) in args.iter().enumerate() {
            out = out.replace(&format!("{{{i}}}"), &a.to_string());
        }
        out
    }

    /// Best-effort runtime detection (`auto`): Unix consults `LC_ALL`/`LANG`
    /// (a `zh*` locale ⇒ zh), Windows consults `GetUserDefaultUILanguage`
    /// (primary language Chinese ⇒ zh); anything else or failure ⇒ en.
    pub fn detect() -> Lang {
        #[cfg(windows)]
        {
            // SAFETY: parameterless kernel32 query, no side effects.
            let langid = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() };
            Self::from_windows_langid(langid)
        }
        #[cfg(unix)]
        {
            let env = std::env::var("LC_ALL")
                .or_else(|_| std::env::var("LANG"))
                .ok();
            Self::from_unix_locale(env.as_deref())
        }
        #[cfg(not(any(windows, unix)))]
        {
            Lang::En
        }
    }

    /// Unix locale string (`zh_CN.UTF-8` etc.) ⇒ [`Lang`] (None/other ⇒ en).
    pub fn from_unix_locale(locale: Option<&str>) -> Lang {
        match locale {
            Some(s) if s.starts_with("zh") => Lang::Zh,
            _ => Lang::En,
        }
    }

    /// Windows LANGID ⇒ [`Lang`] (decision on the primary-language bits).
    pub fn from_windows_langid(langid: u16) -> Lang {
        // PRIMARYLANGID: low 10 bits; 0x04 = Chinese (zh-CN/zh-TW/zh-HK/…).
        if langid & 0x3ff == 0x04 {
            Lang::Zh
        } else {
            Lang::En
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_of(table: &[(Key, &str)]) -> Vec<Key> {
        table.iter().map(|(k, _)| *k).collect()
    }

    /// Pack completeness: en and zh carry exactly the same key set (no
    /// missing entry on either side, no duplicates, and no key outside
    /// [`Key::ALL`]).
    #[test]
    fn en_and_zh_key_sets_are_identical() {
        let mut en = keys_of(EN_TABLE);
        let mut zh = keys_of(ZH_TABLE);
        let mut all = Key::ALL.to_vec();
        en.sort_by_key(|k| format!("{k:?}"));
        zh.sort_by_key(|k| format!("{k:?}"));
        all.sort_by_key(|k| format!("{k:?}"));
        assert_eq!(en, zh, "en/zh key sets must match exactly");
        assert_eq!(
            en, all,
            "every Key::ALL entry must be present in both packs"
        );
        // No duplicates (a set-equality check alone would not catch them).
        let en_dedup = {
            let mut v = keys_of(EN_TABLE);
            v.sort_by_key(|k| format!("{k:?}"));
            v.dedup();
            v
        };
        assert_eq!(en_dedup.len(), EN_TABLE.len(), "en pack has duplicate keys");
        let zh_dedup = {
            let mut v = keys_of(ZH_TABLE);
            v.sort_by_key(|k| format!("{k:?}"));
            v.dedup();
            v
        };
        assert_eq!(zh_dedup.len(), ZH_TABLE.len(), "zh pack has duplicate keys");
        // Every entry non-empty on both sides.
        assert!(EN_TABLE.iter().all(|(_, s)| !s.is_empty()));
        assert!(ZH_TABLE.iter().all(|(_, s)| !s.is_empty()));
    }

    /// zh is the only place Chinese may appear: scanning the en pack must find
    /// no CJK code point.
    #[test]
    fn en_pack_contains_no_cjk() {
        for (k, s) in EN_TABLE {
            assert!(
                !s.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                "en entry {k:?} must not contain CJK text"
            );
        }
    }

    /// tr/trf: language switch, argument substitution, en fallback for zh.
    #[test]
    fn tr_and_trf_substitute_arguments() {
        assert_eq!(Lang::En.tr(Key::TrayQuit), "Quit");
        assert_eq!(Lang::Zh.tr(Key::TrayQuit), "退出");
        assert_eq!(
            Lang::En.trf(Key::TrayStatusLine, &[&"Connected"]),
            "Connection: Connected"
        );
        assert_eq!(
            Lang::Zh.trf(Key::TrayStatusLine, &[&"已连接"]),
            "连接状态：已连接"
        );
        // Reordering by index is allowed (zh puts {1} before {0}).
        assert_eq!(
            Lang::En.trf(Key::CliErrUnknownSub, &[&"bogus", &"usage-block"]),
            "unknown subcommand bogus\n\nusage-block"
        );
        // No args: placeholders remain verbatim (never panics).
        assert_eq!(Lang::En.tr(Key::TrayVipLine), "VPN IP: {0}");
    }

    /// Detection decision tables (pure helpers).
    #[test]
    fn detection_helpers_classify_locales() {
        assert_eq!(Lang::from_unix_locale(Some("zh_CN.UTF-8")), Lang::Zh);
        assert_eq!(Lang::from_unix_locale(Some("zh")), Lang::Zh);
        assert_eq!(Lang::from_unix_locale(Some("en_US.UTF-8")), Lang::En);
        assert_eq!(Lang::from_unix_locale(Some("C")), Lang::En);
        assert_eq!(Lang::from_unix_locale(None), Lang::En);
        // 0x0804 zh-CN, 0x0404 zh-TW, 0x0C04 zh-HK ⇒ zh; 0x0409 en-US ⇒ en.
        assert_eq!(Lang::from_windows_langid(0x0804), Lang::Zh);
        assert_eq!(Lang::from_windows_langid(0x0404), Lang::Zh);
        assert_eq!(Lang::from_windows_langid(0x0c04), Lang::Zh);
        assert_eq!(Lang::from_windows_langid(0x0409), Lang::En);
        assert_eq!(Lang::from_windows_langid(0x0411), Lang::En);
    }

    /// LanguageSetting serde: exact lowercase tokens; anything else is a
    /// parse error (typos surface instead of silently falling back).
    /// Parsed through a wrapper the same way `[general]` embeds it in
    /// client.toml.
    #[test]
    fn language_setting_parses_exact_tokens() {
        #[derive(Deserialize)]
        struct Wrap {
            language: LanguageSetting,
        }
        let parse = |s: &str| toml::from_str::<Wrap>(s).map(|w| w.language);
        assert_eq!(parse("language = \"auto\"").unwrap(), LanguageSetting::Auto);
        assert_eq!(parse("language = \"en\"").unwrap(), LanguageSetting::En);
        assert_eq!(parse("language = \"zh\"").unwrap(), LanguageSetting::Zh);
        assert!(parse("language = \"english\"").is_err());
        assert!(parse("language = \"ZH\"").is_err());
        // resolve: fixed settings short-circuit; auto goes through detection.
        assert_eq!(LanguageSetting::En.resolve(), Lang::En);
        assert_eq!(LanguageSetting::Zh.resolve(), Lang::Zh);
    }
}
