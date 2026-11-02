//! # flock-server（库面）
//!
//! Flock VPN 服务端装配（单服形态，docs/design.md §2.2/§3.11/§7-M2）。库/二进制分靶：
//! 集成测试（`tests/control_flow.rs` 全链 in-process、`tests/smoke.rs` 容器实跑）经本 lib
//! 复用装配与客户端驱动；`src/main.rs` 只做进程入口（CLI 子命令）。
//!
//! 模块（§3.11 接缝图）：
//! - [`config`]：server.toml + `ListenerMode`（**Direct 缺省**，§2.1 硬约束）；
//! - [`netstate`]：NetState trait（与 M4 flock-sync 对齐）+ redb 单机实现（邀请一次性/
//!   VIP 单调不复用/epoch 传播）；
//! - [`ticket`]：会话票据（TTL/epoch）+ nonce 记账（§2.2 契约序的票据侧）；
//! - [`control`]：控制流消息（postcard）+ [`control::CtrlGuard`]（票据强制契约：
//!   票据 → SR-SIG1 → nonce 记账，顺序有测试断言）；
//! - [`server`]：ServerCore（respond 装配/目录/邀请/杀会话）+ accept 循环；
//! - [`frp`]：**唯一触碰 flock-frpc 的模块**（仅 Frp 模式装配；Direct 代码路径不经过）；
//! - [`admin`]：admin loopback 端点（CLI 写操作的进程内单写者入口）；
//! - [`dataplane`]：M3 服务端数据面（tun VIP 100.64.0.1 + 源 VIP 校验 + 会话包通道，
//!   复用 `flock-client` 的 TunDevice/route 接缝，§2.2/§3.12）；
//! - [`backend`]：NetBackend——单服（redb）与多主（flock-sync Raft）的统一异步写读门面
//!   （feature `multi-primary`；§2.2/§3.11 M4 装配批次）；
//! - [`bundle`]：init-cluster/enroll 的节点捆绑文件（根公钥 + 入群凭证 + 根签目录）；
//! - [`sync`]：多主运行装配（TCP 织物 + SyncNode + 服务器自身 peer 面；feature
//!   `multi-primary`，§6.2 M5 批次）。

#![forbid(unsafe_code)]

use std::path::Path;

/// 秘密文件 0600 落盘（评审项 1：root.seed / node-*.bundle / bundle.bin / frpc.toml）。
///
/// 姿势与 flock-protocol `trust::write_private_file` 一致：unix 下以
/// `OpenOptions::mode(0o600)` **创建**——文件诞生即 0600，不存在「先写后收紧」的
/// 权限窗口；覆盖已存在文件的偏宽旧权限时事后收紧。Windows 原生无 POSIX 权限位，
/// 退化为常规写。
pub fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.flush()?;
        // 覆盖已存在文件可能偏宽的旧权限（创建路径本身无窗口）。
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        std::fs::write(path, bytes)
    }
}

pub mod admin;
pub mod backend;
pub mod bundle;
pub mod config;
pub mod control;
pub mod dataplane;
pub mod frp;
pub mod netstate;
pub mod server;
#[cfg(feature = "multi-primary")]
pub mod sync;
pub mod ticket;

#[cfg(test)]
mod tests {
    use super::*;

    // 评审项 1：秘密文件创建即 0600（unix 段——Windows 无 POSIX 权限位）。
    #[cfg(unix)]
    #[test]
    fn private_file_created_with_0600_and_tightened_on_overwrite() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("root.seed");
        write_private_file(&p, b"secret-hex").expect("write");
        assert_eq!(
            std::fs::metadata(&p).expect("meta").permissions().mode() & 0o777,
            0o600,
            "创建即 0600"
        );
        // 覆盖偏宽旧权限的已存在文件 ⇒ 事后收紧回 0600。
        let p2 = dir.path().join("bundle.bin");
        std::fs::write(&p2, b"x").expect("seed write");
        std::fs::set_permissions(&p2, std::fs::Permissions::from_mode(0o644)).expect("widen");
        write_private_file(&p2, b"secret").expect("overwrite");
        assert_eq!(
            std::fs::metadata(&p2).expect("meta").permissions().mode() & 0o777,
            0o600,
            "覆盖后收紧回 0600"
        );
        assert_eq!(std::fs::read(&p2).unwrap(), b"secret");
    }
}
