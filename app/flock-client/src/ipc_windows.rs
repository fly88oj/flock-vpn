//! Windows named-pipe control plane (docs/design.md §7-M6.2).
//!
//! Selection: `tokio::net::windows::named_pipe` overlapped IO (overlapped
//! handles on IOCP, same scheduling domain as the existing tokio runtime;
//! multi-connection concurrency = multiple pipe instances, no hand-managed
//! thread pumps). Pipes are created with an explicit DACL — SDDL
//! `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)` (SYSTEM/administrators/
//! interactive-users group full access; the `D:P` protection flag strips
//! inheritance and **does not keep the default DACL's Everyone read**).

use std::ffi::c_void;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

use crate::ipc::{request_over, serve_conn, CtrlReq, CtrlResp, DaemonControl};

/// SDDL of the pipe DACL (module docs; GA maps to read/write on pipes).
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";
/// SDDL of the token file ACL: SYSTEM/administrators full + Builtin Users
/// read-only.
const TOKEN_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";
/// `ERROR_PIPE_BUSY` (server instances momentarily exhausted — consumed in
/// two places: the client's short retry and the server's next-instance
/// creation backoff; review item 4 classification surface).
pub(crate) const ERROR_PIPE_BUSY: i32 = 231;
/// Client busy-retry window.
const CLIENT_RETRY_WINDOW: Duration = Duration::from_millis(500);

/// SECURITY_ATTRIBUTES guard: the SD comes from an SDDL conversion; Drop
/// calls `LocalFree`.
struct SaGuard {
    sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

// SAFETY: SaGuard exclusively owns the heap SD (SDDL conversion product),
// no cross-thread sharing — the raw pointer only blocks auto traits; the
// accept-loop task must be Send to survive across awaits.
unsafe impl Send for SaGuard {}

impl SaGuard {
    /// SDDL → SECURITY_ATTRIBUTES (the DACL via
    /// ConvertStringSecurityDescriptor).
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let mut wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: wide is NUL-terminated; we own the sd out-param and free it
        // on Drop.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_mut_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(SaGuard {
            sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            },
        })
    }
}

impl Drop for SaGuard {
    fn drop(&mut self) {
        // SAFETY: lpSecurityDescriptor comes from the LocalAlloc family (SDDL
        // conversion); Drop holds it uniquely.
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.sa.lpSecurityDescriptor.cast());
        }
    }
}

/// Start the accept loop: the first instance is created **synchronously**
/// (`first_pipe_instance` = the single-daemon guard; an occupied pipe name
/// errors out immediately) + a client connecting right after does not fall
/// through; afterwards, every accepted connection pre-creates the next
/// instance.
pub(crate) fn spawn_named_pipe_server(
    pipe_name: &str,
    ctrl: Arc<DaemonControl>,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(true)
        .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte);
    let sa = SaGuard::from_sddl(PIPE_SDDL)?;
    // SAFETY: sa lives inside the closure moved into the task, covering all
    // create calls (no dangling-pointer window exists).
    let first = unsafe {
        opts.create_with_security_attributes_raw(pipe_name, &sa.sa as *const _ as *mut c_void)
    }?;
    let name = pipe_name.to_string();
    Ok(tokio::spawn(async move {
        let sa = sa; // moved into the task scope (Drop at loop end).
        let mut server = first;
        loop {
            // Review item 4: connect (the pipe's first-accept) error
            // classification — transient (client connected then dropped:
            // NotConnected / peer vanishing mid-flight / resource pressure)
            // logs, backs off, and retries on the **same instance**; the
            // rest is fatal, returns and bubbles up (noticed by the daemon
            // main flow via the task's conclusion).
            if let Err(e) = server.connect().await {
                if crate::ipc::accept_error_is_transient(&e) {
                    eprintln!(
                        "flock-client: control pipe accept transient failure, retrying in {}ms: \
                         {e}",
                        crate::ipc::ACCEPT_RETRY_BACKOFF.as_millis()
                    );
                    tokio::time::sleep(crate::ipc::ACCEPT_RETRY_BACKOFF).await;
                    continue;
                }
                eprintln!("flock-client: control pipe accept failed (fatal), IPC stopped: {e}");
                return;
            }
            let ctrl = ctrl.clone();
            tokio::spawn(async move {
                let mut s = server;
                let _ = serve_conn(&mut s, &ctrl).await;
            });
            // Pre-create the next instance (same DACL; non-first instances
            // must not carry first_pipe_instance). Creation-failure
            // classification (review item 4): ERROR_PIPE_BUSY =
            // AllPipeInstancesBusy (instances exhausted in flight) is
            // transient — back off and retry (existing serve_conn
            // completions release quota); the rest is fatal and bubbles up.
            let next = loop {
                let mut opts = ServerOptions::new();
                opts.pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte);
                // SAFETY: sa is alive for this loop's scope.
                let next = unsafe {
                    opts.create_with_security_attributes_raw(
                        &name,
                        &sa.sa as *const _ as *mut c_void,
                    )
                };
                match next {
                    Ok(s) => break Some(s),
                    Err(e) if e.raw_os_error() == Some(crate::ipc_windows::ERROR_PIPE_BUSY) => {
                        eprintln!(
                            "flock-client: control pipe instances exhausted in flight \
                             (AllPipeInstancesBusy), retrying in {}ms",
                            crate::ipc::ACCEPT_RETRY_BACKOFF.as_millis()
                        );
                        tokio::time::sleep(crate::ipc::ACCEPT_RETRY_BACKOFF).await;
                    }
                    Err(e) => {
                        eprintln!(
                            "flock-client: control pipe next-instance creation failed (fatal), \
                             IPC stopped: {e}"
                        );
                        break None;
                    }
                }
            };
            let Some(next) = next else { return };
            server = next;
        }
    }))
}

/// Token file explicit ACL (§7-M6.2: Users read).
pub(crate) fn set_file_acl_users_read(path: &std::path::Path) -> io::Result<()> {
    set_file_acl_from_sddl(path, TOKEN_FILE_SDDL)
}

/// Secret file (credentials/SR-SIG1 seed) explicit ACL: SYSTEM +
/// administrators + **the file owner** (OW — the creator is the owner, so a
/// non-elevated process keeps read/write; the Windows equivalent of 0600),
/// **no Users entry** (M7 §7-M7.7: the password's at-rest surface = the
/// owner-side local trust domain; tighter than the token file — Users do not
/// even get read).
pub(crate) fn set_file_acl_admins_only(path: &std::path::Path) -> io::Result<()> {
    const SECRETS_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";
    set_file_acl_from_sddl(path, SECRETS_SDDL)
}

/// Build a DACL from an SDDL and apply it explicitly to a file (PROTECTED
/// strips inheritance).
fn set_file_acl_from_sddl(path: &std::path::Path, sddl: &str) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let sd_guard = SaGuard::from_sddl(sddl)?;
    let mut present: windows_sys::core::BOOL = 0;
    let mut defaulted: windows_sys::core::BOOL = 0;
    let mut dacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
    // SAFETY: sd_guard.sa.lpSecurityDescriptor is a valid SD; the out-param
    // pointers are all valid.
    if unsafe {
        GetSecurityDescriptorDacl(
            sd_guard.sa.lpSecurityDescriptor,
            &mut present,
            &mut dacl,
            &mut defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        return Err(io::Error::other("SDDL conversion produced no DACL"));
    }
    // Path to wide: encode_wide (review item 8) — to_string_lossy would
    // replace unrepresentable bytes with U+FFFD and put the ACL on the wrong
    // file; OsStr→UTF-16 direct conversion is lossless.
    let mut wide: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: wide is NUL-terminated; dacl comes from the SD above
    // (SetNamedSecurityInfoW copies, taking no ownership — dropping sd_guard
    // and freeing the original SD is safe).
    let r = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    if r != 0 {
        return Err(io::Error::from_raw_os_error(r as i32));
    }
    Ok(())
}

/// Client one-shot request: `ClientOptions::open` + `request_over`; short
/// retry on busy.
pub(crate) async fn client_request(pipe_name: &str, req: &CtrlReq) -> io::Result<CtrlResp> {
    let deadline = tokio::time::Instant::now() + CLIENT_RETRY_WINDOW;
    loop {
        match ClientOptions::new().open(pipe_name) {
            Ok(mut pipe) => return request_over(&mut pipe, req).await,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{ConnState, IpcEndpoint};

    /// Real platform loop: named-pipe server + client one-shot request (a
    /// non-elevated session may create pipes — unlike wintun/service
    /// installation, this is host-testable).
    #[tokio::test]
    async fn named_pipe_roundtrip_status_and_denied() {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let name = format!(
            r"\\.\pipe\flock-client-ctrl-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );
        let token = crate::ipc::generate_token();
        let ctrl = Arc::new(DaemonControl {
            token,
            status: Arc::new(|| CtrlResp::Status {
                state: ConnState::Disconnected,
                vip: Some("100.64.0.9".into()),
                endpoint: None,
                epoch: 0,
                uptime_secs: 1,
            }),
            shutdown: Arc::new(|| {}),
            peers: None,
        });
        let server =
            spawn_named_pipe_server(&name, ctrl).expect("first instance created (pipe not held)");

        // Right token ⇒ Status snapshot.
        let resp = crate::ipc::request_once(
            &IpcEndpoint {
                pipe_name: name.clone(),
            },
            CtrlReq::Status { token },
        )
        .await
        .expect("roundtrip");
        assert_eq!(
            resp,
            CtrlResp::Status {
                state: ConnState::Disconnected,
                vip: Some("100.64.0.9".into()),
                endpoint: None,
                epoch: 0,
                uptime_secs: 1,
            }
        );
        // Wrong token ⇒ Denied.
        let resp = crate::ipc::request_once(
            &IpcEndpoint { pipe_name: name },
            CtrlReq::Status { token: [0x11; 32] },
        )
        .await
        .expect("roundtrip");
        assert_eq!(resp, CtrlResp::Denied);

        server.abort();
    }
}
