//! 路由配置适配器（docs/design.md §2.3：Linux rtnetlink /16 池指向 TUN + rp_filter=1）。
//!
//! 客户端与服务器（§2.2「服务端自身也是 peer」）共用同一计划：
//! - 接口配本端 VIP（/32）；
//! - `100.64.0.0/16` 池路由指向 TUN（innernet 形态；/10 全池路由由部署按需扩大）；
//! - `rp_filter=1` 严格反向路径过滤（RFC 3704 语境，innernet 官方建议，vpn-mesh §3.3）。
//!
//! 平台矩阵（§2.3）：
//! - **Linux**：rtnetlink 0.23（地址 + 路由）+ `/proc/sys/net/ipv4/conf/*/rp_filter` 写 1；
//! - **Windows**：路由注入（wintun 路径 + `route add`）**留待 M5 真机手工验证**
//!   （§7-M3 Windows 真机手工清单——本里程碑无 Windows 容器/驱动环境可自动化），
//!   本适配器返回携带手工指令的显式错误，不静默装作成功；
//! - macOS/Android/iOS：utun / VpnService.Builder 参数按 tun-rs 平台矩阵设计，
//!   未验证（§7-M3「macOS 无设备 ⇒ 标注未验证」）。

use std::fmt;
use std::io;
use std::net::Ipv4Addr;

/// 虚拟网池（RFC 6598 CGNAT 段，§2.1）；路由按 /16 起步（§2.3「/16 池指向 TUN」）。
pub const VIP_POOL: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 64, 0, 0), 16);

/// 路由配置计划。
#[derive(Debug, Clone)]
pub struct RoutePlan {
    /// TUN 接口名。
    pub ifname: String,
    /// 本端 VIP（接口地址，/32）。
    pub local_vip: Ipv4Addr,
    /// 指向 TUN 的目的池。
    pub pool: (Ipv4Addr, u8),
}

impl RoutePlan {
    /// 按缺省池构造。
    pub fn new(ifname: &str, local_vip: Ipv4Addr) -> Self {
        RoutePlan { ifname: ifname.into(), local_vip, pool: VIP_POOL }
    }
}

/// 路由配置错误。
#[derive(Debug)]
pub enum RouteError {
    /// 底层 IO（/proc 写失败等）。
    Io(io::Error),
    /// rtnetlink（仅 Linux）。
    #[cfg(target_os = "linux")]
    Netlink(String),
    /// 平台路径未实现/留待后续里程碑（msg 说明去向）。
    Unsupported(String),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteError::Io(e) => write!(f, "route: io: {e}"),
            #[cfg(target_os = "linux")]
            RouteError::Netlink(m) => write!(f, "route: netlink: {m}"),
            RouteError::Unsupported(m) => write!(f, "route: unsupported: {m}"),
        }
    }
}

impl std::error::Error for RouteError {}

impl From<io::Error> for RouteError {
    fn from(e: io::Error) -> Self {
        RouteError::Io(e)
    }
}

/// 应用路由计划（平台分派；幂等——replace 语义，会话重建不重复累计）。
///
/// async：Linux 路径走 rtnetlink 的 tokio 集成（调用方均在运行时上下文内——
/// server::run / 客户端主循环；避免嵌套运行时）。
pub async fn apply(plan: &RoutePlan) -> Result<(), RouteError> {
    #[cfg(target_os = "linux")]
    {
        apply_linux(plan).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = plan;
        #[cfg(windows)]
        {
            Err(RouteError::Unsupported(format!(
                "Windows 路由注入留待 M5 真机手工验证（§7-M3 清单）；手工等价指令：`route add {}/{} mask {mask} {vip} metric 5`（wintun 接口由 tun-rs 创建）",
                plan.pool.0, plan.pool.1,
                mask = pool_mask(plan.pool.1),
                vip = plan.local_vip,
            )))
        }
        #[cfg(not(windows))]
        {
            Err(RouteError::Unsupported(format!(
                "平台路由配置未实现（macOS utun / 移动端 VpnService 参数，§2.3）；计划：ifname={} vip={}",
                plan.ifname, plan.local_vip
            )))
        }
    }
}

/// 前缀长度 → 点分掩码（Windows 错误消息里给手工指令用；Linux 构建不引用）。
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn pool_mask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let bits = u32::MAX << (32 - prefix.min(32));
    Ipv4Addr::from(bits)
}

// ============================================================================
// Linux：rtnetlink + /proc sysctl
// ============================================================================

#[cfg(target_os = "linux")]
async fn apply_linux(plan: &RoutePlan) -> Result<(), RouteError> {
    use futures::StreamExt as _;
    use rtnetlink::{new_connection, RouteMessageBuilder};

    let (conn, handle, _rx) =
        new_connection().map_err(|e| RouteError::Netlink(format!("connect: {e}")))?;
    tokio::spawn(conn);

    // 1) ifindex（接口已由 TunDevice::open 创建）。
    let mut links = handle
        .link()
        .get()
        .match_name(plan.ifname.clone())
        .execute();
    let ifindex = match links.next().await {
        Some(Ok(msg)) => msg.header.index,
        _ => {
            return Err(RouteError::Netlink(format!(
                "接口 {} 不存在（TUN 未创建？）",
                plan.ifname
            )))
        }
    };
    if ifindex == 0 {
        return Err(RouteError::Netlink(format!("接口 {} ifindex=0", plan.ifname)));
    }

    // 2) 接口地址 vip/32（replace 幂等）。
    handle
        .address()
        .add(ifindex, std::net::IpAddr::V4(plan.local_vip), 32)
        .replace()
        .execute()
        .await
        .map_err(|e| RouteError::Netlink(format!("addr add {}: {e}", plan.local_vip)))?;

    // 3) 池路由 → TUN（replace 幂等；scope link 语义由 dev 路由承载）。
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(plan.pool.0, plan.pool.1)
        .output_interface(ifindex)
        .build();
    handle
        .route()
        .add(route)
        .replace()
        .execute()
        .await
        .map_err(|e| RouteError::Netlink(format!("route add {}/{}: {e}", plan.pool.0, plan.pool.1)))?;

    // 4) rp_filter=1（严格反向路径过滤；all + 本接口，innernet 建议）。
    //    /proc/sys 在无特权容器只读 ⇒ 告警不失败（部署侧以 namespaced sysctl 兜底：
    //    compose `sysctls: net.ipv4.conf.{all,default}.rp_filter=1`；宿主/特权路径
    //    本写生效）。
    set_rp_filter("all");
    set_rp_filter(&plan.ifname);
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_rp_filter(iface: &str) {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter");
    match std::fs::read_to_string(&path) {
        Ok(cur) if cur.trim() == "1" => {}
        _ => {
            if let Err(e) = std::fs::write(&path, b"1\n") {
                eprintln!(
                    "route: rp_filter {path} 写失败（{e}；无特权容器 /proc/sys 只读——部署以 sysctls 兜底）"
                );
            }
        }
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_defaults_to_100_64_slash16() {
        let p = RoutePlan::new("tun0", Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(p.pool, (Ipv4Addr::new(100, 64, 0, 0), 16), "§2.3 /16 池");
        assert_eq!(p.local_vip, Ipv4Addr::new(100, 64, 0, 2));
    }

    #[test]
    fn pool_mask_dotted() {
        assert_eq!(pool_mask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(pool_mask(10), Ipv4Addr::new(255, 192, 0, 0));
        assert_eq!(pool_mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    /// 非 Linux 宿主：apply 必须显式失败（不静默装成功）；Windows 错误注明 M5。
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn non_linux_apply_is_explicit_unsupported() {
        let p = RoutePlan::new("tun0", Ipv4Addr::new(100, 64, 0, 2));
        match apply(&p).await {
            Err(RouteError::Unsupported(msg)) => {
                #[cfg(windows)]
                assert!(msg.contains("M5"), "Windows 路径注明 M5 手工验证：{msg}");
                #[cfg(not(windows))]
                assert!(msg.contains("未实现"), "{msg}");
            }
            other => panic!("期望 Unsupported，得 {other:?}"),
        }
    }
}
