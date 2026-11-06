//! Unix socket 控制面（docs/design.md §7-M6.2：Linux/macOS）。
//!
//! `/run/flock`（0755）内 bind `/run/flock/client.sock`，bind 后显式 chmod 0660
//! （bind 前路径不存在、umask 不可控）；`control_group` 配置存在则尝试 chgrp（失败
//! 告警不阻断）。残留 socket 文件（上次异常退出）在 bind 前清理——服务管理器串行
//! 启动保证无并发 daemon 竞态。socket 文件的收尾清理由 daemon 主流程在停机时执行
//! （`spawn_server` 返回的任务 handle abort 后由 service.rs `remove_file`）。

use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;

use crate::ipc::{serve_conn, DaemonControl};

pub(crate) fn spawn_unix_server(
    socket_path: &Path,
    group: Option<&str>,
    ctrl: Arc<DaemonControl>,
) -> io::Result<tokio::task::JoinHandle<()>> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
        // §7-M6.2：目录 0755（umask 可能收紧，显式放开执行/读）。
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
    }
    // 单实例守卫（评审项 7）：bind 前先 connect 旧 socket——**连通即已有 daemon
    // 在跑**：报错返回（上浮 daemon_loop「控制面监听失败」⇒ 非零退出），不抢绑、
    // 不动他人 socket；连接失败才是残留文件（上次异常退出），清理后绑定。
    // 同步 connect：本地 unix socket 即时完成，无长阻塞面。TOCTOU 窗口由服务
    // 管理器串行启动兜底（模块文档）——本守卫为「手跑第二实例」的快失败位。
    if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
        return Err(io::Error::other(format!(
            "已有 daemon 运行（{} 可连）——单实例守卫拒绝二次启动",
            socket_path.display()
        )));
    }
    // 残留清理（见模块文档）。
    let _ = std::fs::remove_file(socket_path);
    let listener = tokio::net::UnixListener::bind(socket_path)?;
    // 0660 + 可选组。
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    if let Some(gname) = group {
        match crate::ipc::resolve_gid(gname) {
            Some(gid) => {
                if let Err(e) = std::os::unix::fs::chown(socket_path, None, Some(gid)) {
                    eprintln!("flock-client: 告警：socket chgrp {gname}({gid}) 失败: {e}");
                }
            }
            None => eprintln!(
                "flock-client: 告警：control_group {gname:?} 无法解析为 gid——socket 保持 root:root"
            ),
        }
    }
    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let ctrl = ctrl.clone();
                    tokio::spawn(async move {
                        let _ = serve_conn(&mut stream, &ctrl).await;
                    });
                }
                // 评审项 4：瞬态（fd 耗尽/对端半途消失等）记日志退避 continue——
                // 不杀 IPC 任务；仅致命（listener 关闭/损坏等其余）上浮返回，
                // daemon 主流程经任务收尾感知。
                Err(e) if crate::ipc::accept_error_is_transient(&e) => {
                    eprintln!(
                        "flock-client: 控制 socket accept 瞬态失败，{}ms 后重试: {e}",
                        crate::ipc::ACCEPT_RETRY_BACKOFF.as_millis()
                    );
                    tokio::time::sleep(crate::ipc::ACCEPT_RETRY_BACKOFF).await;
                }
                Err(e) => {
                    eprintln!("flock-client: 控制 socket accept 失败（致命），IPC 停止: {e}");
                    return;
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{self, ConnState, CtrlReq, CtrlResp, IpcEndpoint};

    /// 平台真实回环：Unix socket 服务端 + 客户端单次请求（临时路径注入）。
    #[tokio::test]
    async fn unix_socket_roundtrip_status_and_denied() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("client.sock");
        let token = ipc::generate_token();
        let ctrl = Arc::new(DaemonControl {
            token,
            status: Arc::new(|| CtrlResp::Status {
                state: ConnState::Connected,
                vip: Some("100.64.0.3".into()),
                endpoint: Some("unix.test:1".into()),
                epoch: 2,
                uptime_secs: 7,
            }),
            shutdown: Arc::new(|| {}),
            peers: None,
        });
        let server = spawn_unix_server(&sock, None, ctrl).expect("bind 临时 socket");
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o660, "socket 0660");

        let resp = ipc::request_once(
            &IpcEndpoint {
                socket_path: sock.clone(),
            },
            CtrlReq::Status { token },
        )
        .await
        .expect("往返");
        assert_eq!(
            resp,
            CtrlResp::Status {
                state: ConnState::Connected,
                vip: Some("100.64.0.3".into()),
                endpoint: Some("unix.test:1".into()),
                epoch: 2,
                uptime_secs: 7,
            }
        );
        let resp = ipc::request_once(
            &IpcEndpoint { socket_path: sock },
            CtrlReq::Status { token: [9; 32] },
        )
        .await
        .expect("往返");
        assert_eq!(resp, CtrlResp::Denied);
        server.abort();
    }

    /// 评审项 7：单实例守卫——socket 被既有监听者占住 ⇒ 二次启动被拒（错误带
    /// 「已有 daemon 运行」——上浮即非零退出），且不清除/不抢绑既有 socket。
    #[tokio::test]
    async fn second_daemon_rejected_while_socket_held() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("guard.sock");
        let holder = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let ctrl = Arc::new(DaemonControl {
            token: ipc::generate_token(),
            status: Arc::new(|| CtrlResp::Ok),
            shutdown: Arc::new(|| {}),
            peers: None,
        });
        let err = spawn_unix_server(&sock, None, ctrl).expect_err("socket 被占 ⇒ 必须拒绝");
        assert!(err.to_string().contains("已有 daemon"), "{err}");
        // 既有 socket 原样保留（占位监听者仍可被连——守卫未清文件）。
        assert!(
            std::os::unix::net::UnixStream::connect(&sock).is_ok(),
            "守卫不得清除在用 socket"
        );
        drop(holder);
    }
}
