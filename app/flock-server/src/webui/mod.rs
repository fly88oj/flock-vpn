//! M8 webui 模块根（docs/design.md §7-M8；文件落位 §M8.8 定死）。
//!
//! 装配（loopback 先行 + VIP 绑定重试任务）在各模块就位后落于本文件
//! （见 [`serve`]）；当前批次先落 HTTP 子集层。

pub mod access;
pub mod http;
pub mod session;
