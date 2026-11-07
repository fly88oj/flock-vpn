//! server.toml 解析与 [`ListenerMode`] 接缝（docs/design.md §2.1/§3.11）。
//!
//! **接入层与 frp 解耦（用户硬约束，最高优先级）**：`listener.mode` 二选一——
//! - `direct`（**缺省**）：直接监听 `bind`，零 frp 逻辑——本模块到运行时的 Direct 代码路径
//!   不触碰 flock-frpc（不实例化 Supervisor、不生成配置、不启动子进程）；
//! - `frp`：本地监听 `bind` + `flock-frpc` Supervisor 托管中转（§3.9/§5）。
//!
//! 解耦纪律落在类型上：config 层只定义自有类型 [`FrpPlan`]（String/PathBuf/SocketAddr，
//! 无 flock-frpc 类型）；RelaySpec/FrpcBinaries 的构造全部隔离在 `frp.rs`（仅 Frp 分支引用）。

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::ticket::TICKET_TTL_SECS;

/// frp 模式的装配计划（config 层自有类型；flock-frpc 类型不出现在此层）。
#[derive(Debug, Clone)]
pub struct FrpPlan {
    /// 中继规格（config 层自有形态；`frp.rs` 据此构造 flock-frpc 的 `RelaySpec`）。
    pub relay: FrpRelayPlan,
    /// frpc 二进制路径（对应 `relay` 栈代；R9 版本矩阵锁在 flock-frpc 内执行）。
    pub frpc_bin: PathBuf,
    /// Supervisor run 目录基点（托管配置/日志落点）。
    pub run_base: PathBuf,
}

/// `[frp]` 的中继栈代（评审项 14：ChmlFrp 装配层接线——config 层自有形态，
/// 不引用 flock-frpc 类型）。
#[derive(Debug, Clone)]
pub enum FrpRelayPlan {
    /// 原版 frpc（v0.71.1 定版）：TOML（v0.71.1 方言）**内嵌全文**——启动时写出到
    /// state 目录再以 `RelaySpec::Original{toml}` 注册（走真实产品路径，兼容不破）。
    Original { toml: String },
    /// ChmlFrp 节点（`ChmlFrp-0.51.2_251023` 定版）。缺省 [`ChmlFrpMode::ConfigFile`]
    /// 语义：面板「隧道管理→配置文件」导出的 frpc.ini 路径（字节级透传，仅注入
    /// admin 探测字段）；`user_token_auto` 显式 opt-in 才走 `-u/-p` 自举（R20 风险
    /// 见 [`UserTokenAuto`] 文档）。
    ChmlFrp {
        ini: Option<PathBuf>,
        user_token_auto: Option<UserTokenAuto>,
    },
}

/// `[frp] mode = "chmlfrp"` 的 `user_token_auto` opt-in（评审项 14）。
///
/// **R20 风险（opt-in 前必读）**：面板 usertoken 是全权凭据，自举走
/// InsecureSkipVerify 的 HTTPS 拉取（中间人可截获全权 token）、token 进入子进程
/// 命令行（同机 `ps` 可读）、拉取配置对托管层不透明（探活只剩进程状态面）——
/// 组织/多用户机器不要启用；缺省 ConfigFile 模式无这些暴露。
#[derive(Debug, Clone, Deserialize)]
pub struct UserTokenAuto {
    /// 面板 usertoken（**凭据**：面板全权；勿入日志/版本库）。
    pub usertoken: String,
    /// 隧道数字 ID（面板「隧道管理」可见）。
    pub tunnel_id: u64,
}

/// 接入端点形态（§3.11 接缝枚字的 config 层形态；运行时句柄见 `server::RunningListener`）。
#[derive(Debug, Clone)]
pub enum ListenerMode {
    /// 直接监听（**缺省**）——零 frp 逻辑（§2.1 硬约束）。
    Direct { bind: SocketAddr },
    /// 本地监听 + flock-frpc 托管中转。
    Frp { bind: SocketAddr, plan: FrpPlan },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// 状态目录（redb + 集群身份材料 + frp 托管落点）。
    pub state_dir: PathBuf,
    /// 本地监听地址（两形态共用；direct 缺省 0.0.0.0:9443）。
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
    /// `direct`（缺省）| `frp`。
    #[serde(default = "default_mode")]
    pub mode: String,
    /// 目录内本服务器的**客户端可见端点**（直连地址或中转用户口；host:port 字符串，
    /// 与 ServerEntry.relay_endpoint 同构）。
    pub advertise_endpoint: String,
    /// 追加端点（同一服务器经其他暴露口；单服 M2 的「换端点仍 1-RTT」模拟，§7-M2）。
    #[serde(default)]
    pub extra_endpoints: Vec<String>,
    /// 目录版本（根签 ClusterDirectory 的 dir_version；变更 = 手动递增 + 重签）。
    #[serde(default = "default_dir_version")]
    pub dir_version: u64,
    /// 票据 TTL 秒（缺省 60 = §2.2 硬顶；部署可调小以便过期路径验收）。
    #[serde(default = "default_ticket_ttl")]
    pub ticket_ttl_secs: u64,
    /// admin loopback 端点（邀请签发/兑换/注册表管理的进程内单写者入口；CLI 子命令走它）。
    #[serde(default = "default_admin_bind")]
    pub admin_bind: SocketAddr,
    /// 并发会话上限（评审项 7；accept 后即占用一个许可，超限的入连被礼貌关闭并
    /// 计数。缺省 1024）。
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// M7（§7-M7.2/§7-M7.5）：离线设备保留期（天）。超过 ⇒ 回收器置 Expired + VIP
    /// 归还分配池（行保留审计、名册排除）。缺省 30；**0 = 永不过期**（兼容旧行为）。
    /// u64 天然 ≥0（「校验 ≥0」由类型承担——负值在解析层即不可表达）。
    #[serde(default = "default_peer_retention_days")]
    pub peer_retention_days: u64,
    /// TUN 接口名（M3 数据面，§2.2/§3.12；缺省 "tun0"）。
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// 本机 tun VIP（§2.2 服务端自身也是 peer；缺省 100.64.0.1。多主形态每台服务器
    /// 各配一个——§6.2：server-a/b/c = .1/.2/.3；设备 VIP 由 Raft 从 .11 起分配，
    /// 与服务器段不撞）。
    #[serde(default = "default_vip")]
    pub vip: std::net::Ipv4Addr,
    /// 仅 mode = "frp" 时读取。
    pub frp: Option<FrpSection>,
    /// 多主同步（§2.2/§3.11 M4 批次；缺省 None = 单服形态——m2/m2-direct 部署不变）。
    #[serde(default)]
    pub sync: Option<SyncSection>,
    /// M8 Web UI 管理面（§7-M8.2；缺省 enabled=true/port=9800——双绑定
    /// 127.0.0.1:port + cfg.vip:port，**不暴露任何 bind 字段**）。
    #[serde(default)]
    pub webui: WebUiSection,
}

/// `[webui]` 配置节（§7-M8.2 定死；**显式白名单键集**——`deny_unknown_fields` 使
/// `bind` 等误配键在解析层即拒，结构上排除 0.0.0.0 误配）。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebUiSection {
    /// false = 不装配 webui。
    #[serde(default = "default_webui_enabled")]
    pub enabled: bool,
    /// 双绑定端口（127.0.0.1:port + cfg.vip:port）；校验 1..=65535 且不与
    /// bind/admin_bind/admin_bind+1/raft_bind 冲突（拒起服）。
    #[serde(default = "default_webui_port")]
    pub port: u16,
    /// 会话 TTL 秒（缺省 8h；校验 60..=86400）。
    #[serde(default = "default_webui_session_ttl")]
    pub session_ttl_secs: u64,
    /// 流量环形缓冲点数（§M8.5；缺省 120）。
    #[serde(default = "default_webui_series_points")]
    pub series_points: usize,
    /// 采样间隔秒（缺省 60）。
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

/// `[sync]` 配置节。
#[derive(Debug, Clone, Deserialize)]
pub struct SyncSection {
    /// `single`（缺省）| `raft`。
    #[serde(default = "default_sync_mode")]
    pub mode: String,
    /// raft 形态：节点捆绑文件（init-cluster 产物；根公钥 + 入群凭证 + 根签目录）。
    /// 缺省 = state_dir/bundle.bin（`enroll` 子命令落点）。
    pub bundle: Option<PathBuf>,
    /// raft 形态：服务器互连织物监听地址（§6.2 srvmesh 内联网；缺省 0.0.0.0:9500）。
    #[serde(default = "default_raft_bind")]
    pub raft_bind: SocketAddr,
    /// raft 形态：对端拨号表 `"节点号=host:port"`（§6.2 srvmesh；例 "1=raft-1:9500"）。
    #[serde(default)]
    pub raft_peers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FrpSection {
    /// 中继栈代：`original`（缺省）| `chmlfrp`（评审项 14：ChmlFrp 面板节点）。
    #[serde(default = "default_frp_flavor")]
    pub flavor: String,
    /// 原版 frpc TOML 全文（内嵌注册，§7-M2「server 内嵌 frpc」；flavor=original 必填）。
    #[serde(default)]
    pub original_toml: String,
    /// ChmlFrp：面板导出的 frpc.ini 路径（flavor=chmlfrp 的缺省 ConfigFile 模式必填）。
    #[serde(default)]
    pub chmlfrp_ini: Option<PathBuf>,
    /// ChmlFrp `UserTokenAuto` 显式 opt-in（R20 风险见 [`UserTokenAuto`]；给此项则
    /// 覆盖 ConfigFile 模式，`chmlfrp_ini` 可省）。
    #[serde(default)]
    pub user_token_auto: Option<UserTokenAuto>,
    /// frpc 二进制路径（缺省 /usr/local/bin/frpc——deploy 镜像内位置；chmlfrp 栈代
    /// 应指向 ChmlFrp 定版 frpc 二进制）。
    #[serde(default = "default_frpc_bin")]
    pub frpc_bin: PathBuf,
    /// run 目录基点（缺省 state_dir/frpc-run）。
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

/// loopback 判定：127.0.0.0/8 全段（IPv4 回环是整段 A 类）或 ::1。
fn is_loopback(a: &SocketAddr) -> bool {
    match a {
        SocketAddr::V4(v4) => v4.ip().is_loopback(),
        SocketAddr::V6(v6) => v6.ip().is_loopback(),
    }
}

impl ServerConfig {
    /// 解析 server.toml（解析后即做加载校验——评审项 3/4：非法配置拒绝起服）。
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let cfg: Self =
            toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// 加载校验（评审项 3/4）：不合法配置在此拒绝（拒绝起服），而非带病运行。
    pub fn validate(&self) -> Result<(), String> {
        // 评审项 3：admin 端点（及其 +1 派生的集群引导端点）必须 loopback——
        // 它是无认证的进程内单写者入口（§3.11「127.0.0.1 绑定 = 认证边界」）。
        // 需要远程运维的意图应走 SSH 隧道/反向代理（在错误信息中说明），而非放宽绑定。
        if !is_loopback(&self.admin_bind) {
            return Err(format!(
                "admin_bind {} 非 loopback：admin/集群引导端点是无认证的本机管理入口，\
                 绑定到非回环地址即对全网开放——拒绝起服。远程运维请走 SSH 隧道\
                 （ssh -L 9444:127.0.0.1:9444 …）或带认证的反向代理。",
                self.admin_bind
            ));
        }
        // 评审项 4：票据 TTL 不得超过 flock-sync 的 TICKET_TTL_SECS(60s) 硬顶
        // （§2.2 跨服重放窗 = min(±300s, TTL)——调大即放大重放面）。部署可调小
        // （过期路径验收用），不可调大。
        if self.ticket_ttl_secs > crate::ticket::TICKET_TTL_SECS {
            return Err(format!(
                "ticket_ttl_secs {} 超过硬顶 {}（§2.2 票据 TTL 60s 硬顶：调大放大跨服\
                 重放窗；只可调小）",
                self.ticket_ttl_secs,
                crate::ticket::TICKET_TTL_SECS
            ));
        }
        // M8（§M8.2）：[webui] 校验——端口与 TTL 档位 + 与既有监听面冲突拒起服。
        if self.webui.enabled {
            if self.webui.port == 0 {
                return Err("[webui] port 为 0（1..=65535）".into());
            }
            if !(60..=86_400).contains(&self.webui.session_ttl_secs) {
                return Err(format!(
                    "[webui] session_ttl_secs {} 超出档位 60..=86400（缺省 8h）",
                    self.webui.session_ttl_secs
                ));
            }
            if self.webui.series_points == 0 || self.webui.series_interval_secs == 0 {
                return Err("[webui] series_points/series_interval_secs 须 ≥ 1".into());
            }
            // 端口冲突面：bind / admin_bind / admin_bind+1（集群引导端点）/ raft_bind。
            // （webui 自身的双绑定 127.0.0.1:port 与 vip:port 同 port——不参与自冲突。）
            let webui_port = self.webui.port;
            let mut conflicts: Vec<(u16, &str)> = Vec::new();
            if self.bind.port() != 0 && self.bind.port() == webui_port {
                conflicts.push((self.bind.port(), "bind"));
            }
            if self.admin_bind.port() != 0 {
                if self.admin_bind.port() == webui_port {
                    conflicts.push((self.admin_bind.port(), "admin_bind"));
                }
                if self.admin_bind.port() + 1 == webui_port {
                    conflicts.push((self.admin_bind.port() + 1, "admin_bind+1（集群引导端点）"));
                }
            }
            if let Some(sync) = &self.sync {
                if sync.raft_bind.port() != 0 && sync.raft_bind.port() == webui_port {
                    conflicts.push((sync.raft_bind.port(), "sync.raft_bind"));
                }
            }
            if let Some((port, face)) = conflicts.first() {
                return Err(format!(
                    "[webui] port {webui_port} 与 {face}（:{port}）冲突——webui 双绑定\
                     （127.0.0.1:{webui_port} + vip:{webui_port}）需独立端口，拒绝起服",
                ));
            }
        }
        Ok(())
    }

    /// 解析为 ListenerMode（缺省 direct；frp 需 `[frp]` 段）。
    pub fn listener_mode(&self) -> Result<ListenerMode, String> {
        match self.mode.as_str() {
            "" | "direct" => Ok(ListenerMode::Direct { bind: self.bind }),
            "frp" => {
                let frp = self
                    .frp
                    .as_ref()
                    .ok_or("listener.mode = \"frp\" 需要 [frp] 段")?;
                // 评审项 14：[frp].flavor 分派（original 缺省 / chmlfrp），config 层
                // 校验必填项后产出 FrpRelayPlan；RelaySpec 构造在 frp.rs（类型隔离）。
                let relay = match frp.flavor.as_str() {
                    "" | "original" => {
                        if frp.original_toml.trim().is_empty() {
                            return Err(
                                "[frp] flavor = \"original\" 需要 original_toml 内嵌全文".into()
                            );
                        }
                        FrpRelayPlan::Original {
                            toml: frp.original_toml.clone(),
                        }
                    }
                    "chmlfrp" => match (&frp.user_token_auto, &frp.chmlfrp_ini) {
                        (Some(uta), _) => {
                            if uta.usertoken.trim().is_empty() {
                                return Err("[frp] user_token_auto.usertoken 为空".into());
                            }
                            if uta.tunnel_id == 0 {
                                return Err("[frp] user_token_auto.tunnel_id 为 0".into());
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
                        (None, None) => {
                            return Err("[frp] flavor = \"chmlfrp\" 需要 chmlfrp_ini（面板导出的 \
                                 frpc.ini 路径；缺省 ConfigFile 模式）或显式 \
                                 [frp.user_token_auto] opt-in"
                                .into())
                        }
                    },
                    other => {
                        return Err(format!("[frp] flavor 未知：{other:?}（original|chmlfrp）"))
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
            other => Err(format!("listener.mode 未知：{other:?}（direct|frp）")),
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
        assert_eq!(cfg.max_sessions, 1024, "并发会话上限缺省 1024（评审项 7）");

        let cfg2: ServerConfig = toml::from_str(
            r#"
            state_dir = "/tmp/s"
            advertise_endpoint = "127.0.0.1:27500"
            mode = "frp"
        "#,
        )
        .unwrap();
        assert!(cfg2.listener_mode().is_err(), "frp 无 [frp] 段 ⇒ 拒");

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
            other => panic!("缺省 flavor = original: {other:?}"),
        }
        assert_eq!(plan.run_base, PathBuf::from("/tmp/s/frpc-run"));
    }

    /// 评审项 3：admin/集群引导端点必须 loopback——非 loopback 拒绝起服且错误说明
    /// SSH 隧道/反代替代；127.0.0.0/8 全段与 ::1 放行。
    #[test]
    fn admin_bind_must_be_loopback() {
        fn cfg_with_admin(admin: &str) -> ServerConfig {
            let text = format!(
                "state_dir = \"/tmp/s\"\nadvertise_endpoint = \"127.0.0.1:9443\"\nadmin_bind = \"{admin}\""
            );
            toml::from_str(&text).unwrap()
        }
        // loopback 全段放行（127.x.y.z 与 ::1）。
        for ok in ["127.0.0.1:9444", "127.3.2.1:9444", "[::1]:9444"] {
            let cfg = cfg_with_admin(ok);
            cfg.validate()
                .unwrap_or_else(|e| panic!("{ok} 应放行: {e}"));
        }
        // 非 loopback 拒绝——错误必须说明远程运维走 SSH 隧道/反代。
        for bad in [
            "0.0.0.0:9444",
            "10.1.2.3:9444",
            "[::]:9444",
            "[fe80::1]:9444",
        ] {
            let err = cfg_with_admin(bad).validate().unwrap_err();
            assert!(err.contains("loopback"), "{bad} 拒: {err}");
            assert!(
                err.contains("SSH") || err.contains("反代") || err.contains("反向代理"),
                "错误需说明替代通道: {err}"
            );
        }
    }

    /// 评审项 4：ticket_ttl_secs ≤ TICKET_TTL_SECS(60s)——超出拒绝起服；调小放行
    /// （语义保留可调小：过期路径验收部署用）。
    #[test]
    fn ticket_ttl_upper_bound_enforced() {
        fn cfg_with_ttl(ttl: u64) -> ServerConfig {
            let text = format!(
                "state_dir = \"/tmp/s\"\nadvertise_endpoint = \"127.0.0.1:9443\"\nticket_ttl_secs = {ttl}"
            );
            toml::from_str(&text).unwrap()
        }
        assert!(cfg_with_ttl(60).validate().is_ok(), "恰为硬顶 ⇒ 放行");
        assert!(
            cfg_with_ttl(6).validate().is_ok(),
            "调小 ⇒ 放行（冒烟部署）"
        );
        let err = cfg_with_ttl(61).validate().unwrap_err();
        assert!(err.contains("60"), "错误点名硬顶: {err}");
        assert!(err.contains("只可调小"), "{err}");
    }

    // ------------------------------------------------------------------
    // M8（§M8.2/W7）：[webui] 节——缺省值/档位校验/端口冲突拒起服/键集白名单
    // ------------------------------------------------------------------

    fn cfg_with_webui(webui: &str) -> ServerConfig {
        let text = format!(
            "state_dir = \"/tmp/s\"
advertise_endpoint = \"127.0.0.1:9443\"
{webui}"
        );
        toml::from_str(&text).unwrap()
    }

    /// 缺省：enabled=true/port=9800/TTL 8h/series 120×60。
    #[test]
    fn webui_section_defaults() {
        let cfg = cfg_with_webui("");
        assert_eq!(cfg.webui.port, 9800);
        assert!(cfg.webui.enabled);
        assert_eq!(cfg.webui.session_ttl_secs, 28_800);
        assert_eq!(cfg.webui.series_points, 120);
        assert_eq!(cfg.webui.series_interval_secs, 60);
        assert!(cfg.validate().is_ok());
        // 显式覆盖往返。
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
        assert!(cfg.validate().is_ok(), "enabled=false 不做端口冲突面");
    }

    /// TTL 档位（60..=86400）与 port 0 拒。
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

    /// 端口冲突拒起服（W7）：与 bind / admin_bind / admin_bind+1 / raft_bind 撞 ⇒
    /// 错误点名冲突面；不冲突放行。
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
        // 与 bind（9443）撞。
        let err = mk("", 9443).validate().unwrap_err();
        assert!(err.contains("bind") && err.contains("拒绝起服"), "{err}");
        // 与 admin_bind（9444）撞。
        let err = mk("", 9444).validate().unwrap_err();
        assert!(err.contains("admin_bind"), "{err}");
        // 与 admin_bind+1（9445 集群引导端点）撞。
        let err = mk("", 9445).validate().unwrap_err();
        assert!(err.contains("集群引导端点"), "{err}");
        // 与 raft_bind 撞。
        let err = mk(
            "[sync]
mode = \"raft\"
",
            9500,
        )
        .validate()
        .unwrap_err();
        assert!(err.contains("raft_bind"), "{err}");
        // 独立端口放行（bind 0.0.0.0:9443 / admin 9444 / raft 缺省 9500 都不撞 9800）。
        assert!(mk("", 9800).validate().is_ok());
        // bind 端口 0（测试 ephemeral 形态）不参与冲突面。
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

    /// 键集白名单（W7 结构防误配）：[webui] 出现 bind 等未知键 ⇒ 解析层即拒
    ///（deny_unknown_fields——0.0.0.0 误配在结构上不可能，而非靠校验拦截）。
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
        assert!(err.to_string().contains("bind"), "未知键点名: {err}");
        assert!(
            toml::from_str::<ServerConfig>(
                "state_dir = \"/tmp/s\"
advertise_endpoint = \"x\"
[webui]
listen = \"0.0.0.0\"
"
            )
            .is_err(),
            "任何白名单外键拒"
        );
    }
}
