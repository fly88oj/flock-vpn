//! Windows 命名管道控制面（docs/design.md §7-M6.2）。
//!
//! 选型：`tokio::net::windows::named_pipe` 重叠 IO（overlapped 句柄挂 IOCP，与既有
//! tokio 运行时同调度域；多连接并发 = 多管道实例，无需自管线程泵）。管道以显式 DACL
//! 创建——SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)`（SYSTEM/管理员/交互用户组
//! 全权；`D:P` 保护位去除继承，**不沿用默认 DACL 的 Everyone 读**）。

use std::ffi::c_void;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

use crate::ipc::{request_over, serve_conn, CtrlReq, CtrlResp, DaemonControl};

/// 管道 DACL 的 SDDL（模块文档；GA 对管道映射含读/写）。
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";
/// token 文件 ACL 的 SDDL：SYSTEM/管理员全权 + Builtin Users 只读。
const TOKEN_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";
/// `ERROR_PIPE_BUSY`（服务端实例瞬时耗尽——客户端短重试 / 服务端下实例创建退避
/// 重试两处消费；评审项 4 分类面）。
pub(crate) const ERROR_PIPE_BUSY: i32 = 231;
/// 客户端 busy 重试窗口。
const CLIENT_RETRY_WINDOW: Duration = Duration::from_millis(500);

/// SECURITY_ATTRIBUTES 守卫：SD 由 SDDL 转换而来，Drop 时 `LocalFree`。
struct SaGuard {
    sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

// SAFETY：SaGuard 独占 owned 堆上 SD（SDDL 转换产物），无跨线程共享——裸指针仅
// 阻断 auto trait；accept 循环任务跨 await 持有需 Send。
unsafe impl Send for SaGuard {}

impl SaGuard {
    /// SDDL → SECURITY_ATTRIBUTES（DACL 经 ConvertStringSecurityDescriptor）。
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let mut wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY：wide 以 NUL 结尾；sd 出参由我们持有并在 Drop 释放。
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
        // SAFETY：lpSecurityDescriptor 来自 LocalAlloc 族（SDDL 转换），Drop 时唯一持有。
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.sa.lpSecurityDescriptor.cast());
        }
    }
}

/// 起 accept 循环：首实例**同步**创建（`first_pipe_instance` = 单 daemon 守卫，管道名
/// 已被占即报错返回）+ 客户端紧随连接不落空；此后每 accept 一个连接即预建下实例。
pub(crate) fn spawn_named_pipe_server(
    pipe_name: &str,
    ctrl: Arc<DaemonControl>,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(true)
        .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte);
    let sa = SaGuard::from_sddl(PIPE_SDDL)?;
    // SAFETY：sa 活在 move 进任务的闭包内，覆盖全部 create 调用（指针悬垂窗口不存在）。
    let first = unsafe {
        opts.create_with_security_attributes_raw(pipe_name, &sa.sa as *const _ as *mut c_void)
    }?;
    let name = pipe_name.to_string();
    Ok(tokio::spawn(async move {
        let sa = sa; // 移入任务域（Drop 在循环结束）。
        let mut server = first;
        loop {
            // 评审项 4：connect（管首 accept）错误分类——瞬态（客户端连后即断
            // NotConnected/对端半途消失/资源压力）记日志退避后**同一实例**重试；
            // 其余致命上浮返回（daemon 主流程经任务收尾感知）。
            if let Err(e) = server.connect().await {
                if crate::ipc::accept_error_is_transient(&e) {
                    eprintln!(
                        "flock-client: 控制管道 accept 瞬态失败，{}ms 后重试: {e}",
                        crate::ipc::ACCEPT_RETRY_BACKOFF.as_millis()
                    );
                    tokio::time::sleep(crate::ipc::ACCEPT_RETRY_BACKOFF).await;
                    continue;
                }
                eprintln!("flock-client: 控制管道 accept 失败（致命），IPC 停止: {e}");
                return;
            }
            let ctrl = ctrl.clone();
            tokio::spawn(async move {
                let mut s = server;
                let _ = serve_conn(&mut s, &ctrl).await;
            });
            // 预建下实例（同 DACL；非首实例不得带 first_pipe_instance）。创建失败
            // 分类（评审项 4）：ERROR_PIPE_BUSY=AllPipeInstancesBusy（实例在途耗尽）
            // 为瞬态——退避重试（既有 serve_conn 完成即释放额度）；其余致命上浮。
            let next = loop {
                let mut opts = ServerOptions::new();
                opts.pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte);
                // SAFETY：sa 在本循环作用域存活。
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
                            "flock-client: 控制管道实例在途耗尽（AllPipeInstancesBusy），\
                             {}ms 后重试",
                            crate::ipc::ACCEPT_RETRY_BACKOFF.as_millis()
                        );
                        tokio::time::sleep(crate::ipc::ACCEPT_RETRY_BACKOFF).await;
                    }
                    Err(e) => {
                        eprintln!(
                            "flock-client: 控制管道下实例创建失败（致命），IPC 停止: {e}"
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

/// token 文件显式 ACL（§7-M6.2：Users 读）。
pub(crate) fn set_file_acl_users_read(path: &std::path::Path) -> io::Result<()> {
    set_file_acl_from_sddl(path, TOKEN_FILE_SDDL)
}

/// 机密文件（凭据/SR-SIG1 种子）显式 ACL：SYSTEM + 管理员 + **文件属主**（OW——
/// 创建者即属主，非提权进程也保有读写；0600 的 Windows 等价物），**无 Users 条目**
/// （M7 §7-M7.7：口令静止面 = 属主侧本地信任域；比 token 文件更紧——Users 连读都没有）。
pub(crate) fn set_file_acl_admins_only(path: &std::path::Path) -> io::Result<()> {
    const SECRETS_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";
    set_file_acl_from_sddl(path, SECRETS_SDDL)
}

/// 以 SDDL 构造 DACL 并显式落到文件（PROTECTED 去继承）。
fn set_file_acl_from_sddl(path: &std::path::Path, sddl: &str) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let sd_guard = SaGuard::from_sddl(sddl)?;
    let mut present: windows_sys::core::BOOL = 0;
    let mut defaulted: windows_sys::core::BOOL = 0;
    let mut dacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
    // SAFETY：sd_guard.sa.lpSecurityDescriptor 是合法 SD；出参指针均有效。
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
        return Err(io::Error::other("SDDL 转换产物无 DACL"));
    }
    let mut wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY：wide 以 NUL 结尾；dacl 来自上述 SD（SetNamedSecurityInfoW 拷贝语义，
    // 不夺所有权——sd_guard Drop 释放原 SD 安全）。
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

/// 客户端单次请求：`ClientOptions::open` + `request_over`；busy 短重试。
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

    /// 平台真实回环：命名管道服务端 + 客户端单次请求（非提升会话可创建管道——
    /// 与 wintun/服务安装不同，此项宿主可测）。
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
        let server = spawn_named_pipe_server(&name, ctrl).expect("首实例创建（管道未占用）");

        // 对 token ⇒ Status 快照。
        let resp = crate::ipc::request_once(
            &IpcEndpoint {
                pipe_name: name.clone(),
            },
            CtrlReq::Status { token },
        )
        .await
        .expect("往返");
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
        // 错 token ⇒ Denied。
        let resp = crate::ipc::request_once(
            &IpcEndpoint { pipe_name: name },
            CtrlReq::Status { token: [0x11; 32] },
        )
        .await
        .expect("往返");
        assert_eq!(resp, CtrlResp::Denied);

        server.abort();
    }
}
