//! server.toml 解析与 [`ListenerMode`] 接缝（docs/design.md §2.1/§3.11）。
//!
//! **接入层与 frp 解耦（用户硬约束，最高优先级）**：`listener.mode` 二选一——
//! - `direct`（**缺省**）：直接监听 `bind`，零 frp 逻辑——本模块到运行时的 Direct 代码路径
//!   不触碰 chml-frpc（不实例化 Supervisor、不生成配置、不启动子进程）；
//! - `frp`：本地监听 `bind` + `chml-frpc` Supervisor 托管中转（§3.9/§5）。
//!
//! 解耦纪律落在类型上：config 层只定义自有类型 [`FrpPlan`]（String/PathBuf/SocketAddr，
//! 无 chml-frpc 类型）；RelaySpec/FrpcBinaries 的构造全部隔离在 `frp.rs`（仅 Frp 分支引用）。

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::ticket::TICKET_TTL_SECS;

/// frp 模式的装配计划（config 层自有类型；chml-frpc 类型不出现在此层）。
#[derive(Debug, Clone)]
pub struct FrpPlan {
    /// 原版 frpc TOML（v0.71.1 方言）**内嵌全文**——server.toml `[frp] original_toml`；
    /// 启动时写出到 state 目录再以 `RelaySpec::Original{toml}` 注册（走真实产品路径）。
    pub original_toml: String,
    /// 原版 frpc 二进制路径（v0.71.1 定版；R9 矩阵锁在 chml-frpc 内执行）。
    pub frpc_bin: PathBuf,
    /// Supervisor run 目录基点（托管配置/日志落点）。
    pub run_base: PathBuf,
}

/// 接入端点形态（§3.11 接缝枚字的 config 层形态；运行时句柄见 `server::RunningListener`）。
#[derive(Debug, Clone)]
pub enum ListenerMode {
    /// 直接监听（**缺省**）——零 frp 逻辑（§2.1 硬约束）。
    Direct { bind: SocketAddr },
    /// 本地监听 + chml-frpc 托管中转。
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
    /// TUN 接口名（M3 数据面，§2.2/§3.12；缺省 "tun0"）。
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// 仅 mode = "frp" 时读取。
    pub frp: Option<FrpSection>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FrpSection {
    /// 原版 frpc TOML 全文（内嵌注册，§7-M2「server 内嵌 frpc」）。
    pub original_toml: String,
    /// frpc 二进制路径（缺省 /usr/local/bin/frpc——deploy 镜像内位置）。
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
fn default_tun_name() -> String {
    "tun0".into()
}
fn default_frpc_bin() -> PathBuf {
    PathBuf::from("/usr/local/bin/frpc")
}

impl ServerConfig {
    /// 解析 server.toml。
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    /// 解析为 ListenerMode（缺省 direct；frp 需 `[frp]` 段）。
    pub fn listener_mode(&self) -> Result<ListenerMode, String> {
        match self.mode.as_str() {
            "" | "direct" => Ok(ListenerMode::Direct { bind: self.bind }),
            "frp" => {
                let frp = self
                    .frp
                    .as_ref()
                    .ok_or("listener.mode = \"frp\" 需要 [frp] 段（original_toml 内嵌注册）")?;
                Ok(ListenerMode::Frp {
                    bind: self.bind,
                    plan: FrpPlan {
                        original_toml: frp.original_toml.clone(),
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
        assert!(plan.original_toml.contains("serverAddr"));
        assert_eq!(plan.run_base, PathBuf::from("/tmp/s/frpc-run"));
    }
}
