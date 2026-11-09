//! Route configuration adapter (docs/design.md §2.3: Linux rtnetlink /16
//! pool pointing at the TUN + rp_filter=1).
//!
//! Client and server (§2.2 "the server is itself a peer") share one plan:
//! - the interface gets the local VIP (/32);
//! - the `100.64.0.0/16` pool route points at the TUN (innernet shape; the
//!   /10 full-pool route is left to deployment to widen as needed);
//! - `rp_filter=1` strict reverse-path filtering (RFC 3704 language,
//!   innernet's official recommendation, vpn-mesh §3.3).
//!
//! Platform matrix (§2.3):
//! - **Linux**: rtnetlink 0.23 (address + route) + writing 1 to
//!   `/proc/sys/net/ipv4/conf/*/rp_filter`;
//! - **Windows**: route injection (wintun path + `route add`) **pending M5
//!   real-machine manual verification** (§7-M3 Windows manual checklist —
//!   this milestone has no Windows container/driver environment to
//!   automate); this adapter returns an explicit error carrying manual
//!   instructions instead of silently pretending success;
//! - macOS/Android/iOS: utun / VpnService.Builder parameters designed
//!   against the tun-rs platform matrix, unverified (§7-M3 "no macOS device
//!   ⇒ marked unverified").

use std::fmt;
use std::io;
use std::net::Ipv4Addr;

/// Virtual network pool (RFC 6598 CGNAT range, §2.1); routes start at /16
/// (§2.3 "/16 pool pointing at the TUN").
pub const VIP_POOL: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 64, 0, 0), 16);

/// Route configuration plan.
#[derive(Debug, Clone)]
pub struct RoutePlan {
    /// TUN interface name.
    pub ifname: String,
    /// Local VIP (interface address, /32).
    pub local_vip: Ipv4Addr,
    /// Destination pool pointing at the TUN.
    pub pool: (Ipv4Addr, u8),
}

impl RoutePlan {
    /// Construct with the default pool.
    pub fn new(ifname: &str, local_vip: Ipv4Addr) -> Self {
        RoutePlan {
            ifname: ifname.into(),
            local_vip,
            pool: VIP_POOL,
        }
    }
}

/// Route configuration error.
#[derive(Debug)]
pub enum RouteError {
    /// Underlying IO (/proc write failure, etc.).
    Io(io::Error),
    /// rtnetlink (Linux only).
    #[cfg(target_os = "linux")]
    Netlink(String),
    /// Platform path not implemented / deferred to a later milestone (msg
    /// says where it went).
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

/// Apply the route plan (platform dispatch; idempotent — replace semantics,
/// session re-establishment does not accumulate duplicates).
///
/// async: the Linux path uses rtnetlink's tokio integration (all callers are
/// inside a runtime context — server::run / the client main loop; avoids
/// nested runtimes).
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
                "Windows route injection is pending M5 real-machine manual verification (§7-M3 \
                 checklist); manual equivalent: `route add {}/{} mask {mask} {vip} metric 5` \
                 (the wintun interface is created by tun-rs)",
                plan.pool.0,
                plan.pool.1,
                mask = pool_mask(plan.pool.1),
                vip = plan.local_vip,
            )))
        }
        #[cfg(not(windows))]
        {
            Err(RouteError::Unsupported(format!(
                "route configuration not implemented on this platform (macOS utun / mobile \
                 VpnService parameters, §2.3); plan: ifname={} vip={}",
                plan.ifname, plan.local_vip
            )))
        }
    }
}

/// Prefix length → dotted mask (for the manual instructions in the Windows
/// error message; not referenced by Linux builds).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn pool_mask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let bits = u32::MAX << (32 - prefix.min(32));
    Ipv4Addr::from(bits)
}

// ============================================================================
// Linux: rtnetlink + /proc sysctl
// ============================================================================

#[cfg(target_os = "linux")]
async fn apply_linux(plan: &RoutePlan) -> Result<(), RouteError> {
    use futures::StreamExt as _;
    use rtnetlink::{new_connection, RouteMessageBuilder};

    let (conn, handle, _rx) =
        new_connection().map_err(|e| RouteError::Netlink(format!("connect: {e}")))?;
    tokio::spawn(conn);

    // 1) ifindex (the interface was already created by TunDevice::open).
    let mut links = handle
        .link()
        .get()
        .match_name(plan.ifname.clone())
        .execute();
    let ifindex = match links.next().await {
        Some(Ok(msg)) => msg.header.index,
        _ => {
            return Err(RouteError::Netlink(format!(
                "interface {} does not exist (TUN not created?)",
                plan.ifname
            )))
        }
    };
    if ifindex == 0 {
        return Err(RouteError::Netlink(format!(
            "interface {} has ifindex=0",
            plan.ifname
        )));
    }

    // 2) Interface address vip/32 (replace = idempotent).
    handle
        .address()
        .add(ifindex, std::net::IpAddr::V4(plan.local_vip), 32)
        .replace()
        .execute()
        .await
        .map_err(|e| RouteError::Netlink(format!("addr add {}: {e}", plan.local_vip)))?;

    // 3) Pool route → TUN (replace = idempotent; scope-link semantics are
    //    carried by the dev route).
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
        .map_err(|e| {
            RouteError::Netlink(format!("route add {}/{}: {e}", plan.pool.0, plan.pool.1))
        })?;

    // 4) rp_filter=1 (strict reverse-path filtering; all + this interface,
    //    innernet's recommendation).
    //    /proc/sys is read-only in unprivileged containers ⇒ warn, do not
    //    fail (deployment backstops with namespaced sysctls: compose
    //    `sysctls: net.ipv4.conf.{all,default}.rp_filter=1`; the
    //    host/privileged path takes effect from this write).
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
                    "route: rp_filter write to {path} failed ({e}; /proc/sys is read-only in \
                     unprivileged containers — deployment backstops with sysctls)"
                );
            }
        }
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_defaults_to_100_64_slash16() {
        let p = RoutePlan::new("tun0", Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(p.pool, (Ipv4Addr::new(100, 64, 0, 0), 16), "§2.3 /16 pool");
        assert_eq!(p.local_vip, Ipv4Addr::new(100, 64, 0, 2));
    }

    #[test]
    fn pool_mask_dotted() {
        assert_eq!(pool_mask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(pool_mask(10), Ipv4Addr::new(255, 192, 0, 0));
        assert_eq!(pool_mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    /// Non-Linux host: apply must fail explicitly (never silently pretend
    /// success); the Windows error mentions M5.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn non_linux_apply_is_explicit_unsupported() {
        let p = RoutePlan::new("tun0", Ipv4Addr::new(100, 64, 0, 2));
        match apply(&p).await {
            Err(RouteError::Unsupported(msg)) => {
                #[cfg(windows)]
                assert!(
                    msg.contains("M5"),
                    "the Windows path must mention M5 manual verification: {msg}"
                );
                #[cfg(not(windows))]
                assert!(msg.contains("not implemented"), "{msg}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
