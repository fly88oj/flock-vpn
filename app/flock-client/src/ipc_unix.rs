//! Unix-socket control plane (docs/design.md §7-M6.2: Linux/macOS).
//!
//! Inside `/run/flock` (0755), bind `/run/flock/client.sock` and explicitly
//! chmod 0660 after bind (the path does not exist before bind and umask is
//! uncontrollable); when a `control_group` is configured, a chgrp is
//! attempted (failure is a warning, not blocking). A leftover socket file
//! (abnormal exit last time) is cleaned before bind — the service manager's
//! serial startup guarantees no concurrent-daemon race. Socket-file cleanup
//! at teardown is done by the daemon main flow on shutdown (after the task
//! handle returned by `spawn_server` is aborted, service.rs does the
//! `remove_file`).

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
        // §7-M6.2: directory 0755 (umask may have tightened it; explicitly
        // reopen execute/read).
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
    }
    // Single-instance guard (review item 7): before binding, connect to any
    // old socket — **a successful connect means a daemon is already
    // running**: return an error (bubbling up to daemon_loop's "control
    // plane listen failure" ⇒ non-zero exit); do not steal the bind, do not
    // touch someone else's socket; a failed connection means it is a
    // leftover file (abnormal exit last time) — clean it and bind.
    // Synchronous connect: a local unix socket completes immediately, no
    // long-blocking surface. The TOCTOU window is backstopped by the service
    // manager's serial startup (module docs) — this guard is the fast-fail
    // position for "hand-running a second instance".
    if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
        return Err(io::Error::other(format!(
            "a daemon is already running ({} is connectable) — single-instance guard refuses a \
             second start",
            socket_path.display()
        )));
    }
    // Leftover cleanup (see the module docs).
    let _ = std::fs::remove_file(socket_path);
    let listener = tokio::net::UnixListener::bind(socket_path)?;
    // 0660 + optional group.
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    if let Some(gname) = group {
        match crate::ipc::resolve_gid(gname) {
            Some(gid) => {
                if let Err(e) = std::os::unix::fs::chown(socket_path, None, Some(gid)) {
                    eprintln!("flock-client: warning: socket chgrp {gname}({gid}) failed: {e}");
                }
            }
            None => eprintln!(
                "flock-client: warning: control_group {gname:?} could not be resolved to a gid — \
                 socket stays root:root"
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
                // Review item 4: transient (fd exhaustion/peer vanishing
                // mid-flight, etc.) logs, backs off, continues — the IPC task
                // is not killed; only fatal cases (listener closed/broken and
                // the rest) return and bubble up, noticed by the daemon main
                // flow via the task's conclusion.
                Err(e) if crate::ipc::accept_error_is_transient(&e) => {
                    eprintln!(
                        "flock-client: control socket accept transient failure, retrying in {}ms: \
                         {e}",
                        crate::ipc::ACCEPT_RETRY_BACKOFF.as_millis()
                    );
                    tokio::time::sleep(crate::ipc::ACCEPT_RETRY_BACKOFF).await;
                }
                Err(e) => {
                    eprintln!(
                        "flock-client: control socket accept failed (fatal), IPC stopped: {e}"
                    );
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

    /// Real platform loop: Unix socket server + client one-shot request
    /// (temporary path injection).
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
        let server = spawn_unix_server(&sock, None, ctrl).expect("bind temp socket");
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o660, "socket is 0660");

        let resp = ipc::request_once(
            &IpcEndpoint {
                socket_path: sock.clone(),
            },
            CtrlReq::Status { token },
        )
        .await
        .expect("roundtrip");
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
        .expect("roundtrip");
        assert_eq!(resp, CtrlResp::Denied);
        server.abort();
    }

    /// Review item 7: single-instance guard — the socket held by an existing
    /// listener ⇒ a second start is rejected (the error carries "a daemon is
    /// already running" — bubbling up means a non-zero exit), and the
    /// existing socket is neither cleared nor re-bound.
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
        let err = spawn_unix_server(&sock, None, ctrl).expect_err("socket held ⇒ must refuse");
        assert!(err.to_string().contains("already running"), "{err}");
        // The existing socket is preserved as-is (the holding listener can
        // still be connected to — the guard did not clear the file).
        assert!(
            std::os::unix::net::UnixStream::connect(&sock).is_ok(),
            "the guard must not clear an in-use socket"
        );
        drop(holder);
    }
}
