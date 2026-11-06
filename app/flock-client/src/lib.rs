//! flock-client 库面（docs/design.md §2.3 / §3.12 / §7-M3）。
//!
//! 模块：
//! - [`tun`]：`TunDevice` 接缝（open/read/write/close）+ tun-rs 适配器（cfg 门控）+
//!   `MockTunDevice`（宿主单测）+ `TunIo/TunSession`（同步设备 → tokio 桥）；
//! - [`route`]：路由配置适配器（Linux rtnetlink /16 池 + rp_filter=1；Windows 注明
//!   留待 M5 真机手工验证）；
//! - [`connector`]：接入器（邀请/钉扎目录加载 → 端点拨号 → `session::initiate`；
//!   指数退避 + 端点轮询）；
//! - [`ctrl`]：控制流半边（M7 §7-M7.7：OPAQUE 登录/key-bind/票据保持的客户端实现——
//!   线类型复用 `flock_protocol::roster`，两端同类型）；
//! - [`dataplane`]：IP 包 ↔ `PacketChannel` 桥；
//! - [`ipc`]：控制 IPC v1 契约 + daemon 服务端 + 客户端单次请求（§7-M6.2——托盘
//!   工程直接消费本模块，`service` 子命令装配服务端）；
//! - [`service`]：daemon 装配（§7-M6.1：supervise 复用 + IPC 服务端 + 状态快照源 +
//!   优雅停服 + Windows SCM 集成）；
//! - [`install`]：服务安装/卸载 + 托盘自启注册（§7-M6.3：Windows SCM/事件日志源/
//!   HKCU Run、systemd 单元、launchd plist）；
//! - [`tray`]：托盘进程（§7-M6 第二阶段；`tray` feature 门控——平台无关核心 + 平台
//!   后端：Windows/macOS tray-icon、Linux ksni）。
//!
//! 服务器（`flock-server`）以库形式复用 [`tun`]/[`route`]/dataplane 桥
//! （§2.2「服务端自身也是 peer」、§3.11「对上挂 tun 适配器」）——`TunDevice` 接缝按
//! §3.12 落位本 crate，跨 app 复用即此接缝的第二个消费者。

pub mod config;
pub mod connector;
pub mod ctrl;
pub mod dataplane;
pub mod install;
pub mod ipc;
// 控制面平台传输（私有：契约/服务端/客户端入口全走 [`ipc`]）。
#[cfg(unix)]
mod ipc_unix;
#[cfg(windows)]
mod ipc_windows;
pub mod route;
pub mod service;
#[cfg(feature = "tray")]
pub mod tray;
pub mod tun;
