//! flock-client 库面（docs/design.md §2.3 / §3.12 / §7-M3）。
//!
//! 模块：
//! - [`tun`]：`TunDevice` 接缝（open/read/write/close）+ tun-rs 适配器（cfg 门控）+
//!   `MockTunDevice`（宿主单测）+ `TunIo/TunSession`（同步设备 → tokio 桥）；
//! - [`route`]：路由配置适配器（Linux rtnetlink /16 池 + rp_filter=1；Windows 注明
//!   留待 M5 真机手工验证）；
//! - [`connector`]：接入器（邀请/钉扎目录加载 → 端点拨号 → `session::initiate`；
//!   指数退避 + 端点轮询）；
//! - [`dataplane`]：IP 包 ↔ `PacketChannel` 桥。
//!
//! 服务器（`flock-server`）以库形式复用 [`tun`]/[`route`]/dataplane 桥
//! （§2.2「服务端自身也是 peer」、§3.11「对上挂 tun 适配器」）——`TunDevice` 接缝按
//! §3.12 落位本 crate，跨 app 复用即此接缝的第二个消费者。

pub mod config;
pub mod connector;
pub mod dataplane;
pub mod route;
pub mod tun;
