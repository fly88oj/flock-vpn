//! client.toml（docs/design.md §3.12：`flock-client --config client.toml`）。

use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::Deserialize;

/// 客户端配置。
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// 状态目录（device.keys / pins.bin / directory.bin / vip / credentials / sr-sig.key）。
    pub state_dir: PathBuf,
    /// 本端 VIP 覆盖（缺省 None ⇒ 读 state_dir/vip 文件——部署编排写入）。
    #[serde(default)]
    pub vip: Option<Ipv4Addr>,
    /// TUN 接口名（缺省 "tun0"，§6.3 A3 断言按 `ip link show tun0`）。
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// MTU（缺省 1280，§2.1）。
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// 端点覆盖（调试/断言钉死用；缺省 = 根签目录全部端点轮询，§2.3）。
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// 控制 IPC 组授权（§7-M6.2，仅 Unix）：token 文件与 socket 尝试 chgrp 到该组
    ///（组名查本地 /etc/group 或数字 gid；Windows 忽略——管道 DACL 走 IU）。
    /// 缺省 None ⇒ root:root（仅 root 可控，即装即用）。
    #[serde(default)]
    pub control_group: Option<String>,
    /// 上报 hostname 覆盖（M7 §7-M7.7：key-bind 入册名册的「主机名」列；缺省取 OS
    /// 主机名；截断/空串语义与服务端 normalize 对齐）。
    #[serde(default)]
    pub hostname: Option<String>,
    /// 登录配置（M7：OPAQUE 登录/key-bind/票据保持；缺省无 = 不登录、名册不可用）。
    #[serde(default)]
    pub auth: Option<AuthConfig>,
}

/// `[auth]` 段（M7 §7-M7.7）。
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// 登录用户名（= 设备注册 owner；`device-add`/`redeem` 的 --user 同值）。
    pub username: String,
    /// 口令文件路径（0600，单行；缺省 state_dir/credentials——`flock-client login` 写入）。
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
    /// 解析 client.toml。
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
        assert_eq!(cfg.mtu, 1280, "MTU 缺省 1280（§2.1）");
        assert!(cfg.vip.is_none());
        assert!(cfg.endpoints.is_empty());
        assert!(cfg.hostname.is_none(), "hostname 缺省 = OS 主机名");
        assert!(cfg.auth.is_none(), "[auth] 缺省无（不登录）");

        let cred_path = if cfg!(windows) {
            "C:/custom/cred".to_string()
        } else {
            "/custom/cred".to_string()
        };
        std::fs::write(
            &p,
            format!(
                "state_dir = {:?}\nvip = \"100.64.0.11\"\nendpoints = [\"frps:27500\", \"frps:27501\"]\nhostname = \"box-a\"\n\n[auth]\nusername = \"alice\"\ncredentials_file = \"{}\"\n",
                dir.path().join("state").to_str().unwrap(),
                cred_path,
            ),
        )
        .unwrap();
        let cfg = ClientConfig::load(&p).unwrap();
        assert_eq!(cfg.vip, Some("100.64.0.11".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(cfg.endpoints, vec!["frps:27500", "frps:27501"]);
        assert_eq!(cfg.hostname.as_deref(), Some("box-a"));
        let auth = cfg.auth.expect("[auth] 解析");
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

    /// M7：[auth] 仅 username（credentials_file 缺省 None——daemon 侧落 state_dir/credentials）。
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
}
