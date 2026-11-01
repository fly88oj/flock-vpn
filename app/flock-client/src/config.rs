//! client.toml（docs/design.md §3.12：`flock-client --config client.toml`）。

use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::Deserialize;

/// 客户端配置。
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// 状态目录（device.keys / pins.bin / directory.bin / vip）。
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
            format!("state_dir = {:?}\n", dir.path().join("state").to_str().unwrap()),
        )
        .unwrap();
        let cfg = ClientConfig::load(&p).unwrap();
        assert_eq!(cfg.tun_name, "tun0");
        assert_eq!(cfg.mtu, 1280, "MTU 缺省 1280（§2.1）");
        assert!(cfg.vip.is_none());
        assert!(cfg.endpoints.is_empty());

        std::fs::write(
            &p,
            format!(
                "state_dir = {:?}\nvip = \"100.64.0.11\"\nendpoints = [\"frps:27500\", \"frps:27501\"]\n",
                dir.path().join("state").to_str().unwrap()
            ),
        )
        .unwrap();
        let cfg = ClientConfig::load(&p).unwrap();
        assert_eq!(cfg.vip, Some("100.64.0.11".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(cfg.endpoints, vec!["frps:27500", "frps:27501"]);
    }
}
