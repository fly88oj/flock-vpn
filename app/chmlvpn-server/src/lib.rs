//! # chmlvpn-server（库面）
//!
//! ChmlVPN 服务端装配（单服形态，docs/design.md §2.2/§3.11/§7-M2）。库/二进制分靶：
//! 集成测试（`tests/control_flow.rs` 全链 in-process、`tests/smoke.rs` 容器实跑）经本 lib
//! 复用装配与客户端驱动；`src/main.rs` 只做进程入口（CLI 子命令）。
//!
//! 模块（§3.11 接缝图）：
//! - [`config`]：server.toml + `ListenerMode`（**Direct 缺省**，§2.1 硬约束）；
//! - [`netstate`]：NetState trait（与 M4 chml-sync 对齐）+ redb 单机实现（邀请一次性/
//!   VIP 单调不复用/epoch 传播）；
//! - [`ticket`]：会话票据（TTL/epoch）+ nonce 记账（§2.2 契约序的票据侧）；
//! - [`control`]：控制流消息（postcard）+ [`control::CtrlGuard`]（票据强制契约：
//!   票据 → SR-SIG1 → nonce 记账，顺序有测试断言）；
//! - [`server`]：ServerCore（respond 装配/目录/邀请/杀会话）+ accept 循环；
//! - [`frp`]：**唯一触碰 chml-frpc 的模块**（仅 Frp 模式装配；Direct 代码路径不经过）；
//! - [`admin`]：admin loopback 端点（CLI 写操作的进程内单写者入口）；
//! - [`dataplane`]：M3 服务端数据面（tun VIP 100.64.0.1 + 源 VIP 校验 + 会话包通道，
//!   复用 `chmlvpn-client` 的 TunDevice/route 接缝，§2.2/§3.12）。

#![forbid(unsafe_code)]

pub mod admin;
pub mod config;
pub mod control;
pub mod dataplane;
pub mod frp;
pub mod netstate;
pub mod server;
pub mod ticket;
