//! 服务安装/卸载 + 托盘自启注册（docs/design.md §7-M6.3）。
//!
//! `flock-client install [--user|--service]` / `uninstall [--user|--service]`：
//! `--user` 只动托盘自启、`--service` 只动系统服务、缺省两者。安装把**安装时的**
//! `--config` 绝对路径写进服务定义（SCM 工作目录 = system32、systemd/launchd 不继承
//! shell CWD，相对路径不可用）。
//!
//! 平台矩阵与验证边界（§7-M6.6-4）：
//! - **Windows**：windows-service crate（SCM 安装/AUTO_START/恢复策略/事件日志源
//!   注册——编译级验证 + HKCU Run 键宿主可测；**SCM 安装需管理员**，非提升会话给
//!   出清晰错误，真机安装列 docs/manual/service-install.md 手工清单）；
//! - **Linux**：systemd 单元渲染（纯函数宿主可测）+ 写入/enable 命令序列（执行面需
//!   root + systemd 运行；容器内无 systemd 时安装报错即如实返回）；
//! - **macOS**：launchd plist 渲染 + launchctl 命令（**本机无设备 ⇒ 未验证**，文件
//!   与命令照常产出，真机清单留位）。
//!
//! 托盘自启：Windows `HKCU\...\Run`（无需提权）；Linux
//! `~/.config/autostart/*.desktop`；macOS `~/Library/LaunchAgents/*.plist`。

use std::path::{Path, PathBuf};

/// 安装范围（§7-M6.3：`--user` / `--service` / 缺省两者）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    ServiceOnly,
    TrayOnly,
    Both,
}

/// 服务显示名（SCM / 描述行统一）。
pub const SERVICE_DISPLAY_NAME: &str = "Flock VPN Client";
/// Linux 托盘自启文件名。
pub const TRAY_DESKTOP_NAME: &str = "flock-client-tray.desktop";
/// macOS LaunchDaemon/LaunchAgent label 常量。
pub const LAUNCHD_SERVICE_LABEL: &str = "com.flockvpn.client";
pub const LAUNCHD_TRAY_LABEL: &str = "com.flockvpn.client-tray";

// ============================================================================
// 平台常量（路径）
// ============================================================================

/// systemd 单元路径。
#[cfg(target_os = "linux")]
pub const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/flock-client.service";
/// macOS LaunchDaemon plist 路径。
#[cfg(target_os = "macos")]
pub const LAUNCHDAEMON_PATH: &str = "/Library/LaunchDaemons/com.flockvpn.client.plist";
/// macOS 托盘 LaunchAgent plist 路径（用户级，`~/` 展开）。
#[cfg(target_os = "macos")]
pub const TRAY_AGENT_REL: &str = "Library/LaunchAgents/com.flockvpn.client-tray.plist";
/// Linux 托盘自启目录（用户级，`~/` 展开）。
#[cfg(target_os = "linux")]
pub const AUTOSTART_DIR_REL: &str = ".config/autostart";

// ============================================================================
// 入口
// ============================================================================

/// 安装（服务 + 托盘自启，按 scope）。
pub fn install(cfg_path: &Path, scope: Scope) -> Result<(), String> {
    if matches!(scope, Scope::ServiceOnly | Scope::Both) {
        install_service(cfg_path)?;
    }
    if matches!(scope, Scope::TrayOnly | Scope::Both) {
        install_tray()?;
    }
    Ok(())
}

/// 卸载（反向清理）。
pub fn uninstall(scope: Scope) -> Result<(), String> {
    if matches!(scope, Scope::ServiceOnly | Scope::Both) {
        uninstall_service()?;
    }
    if matches!(scope, Scope::TrayOnly | Scope::Both) {
        uninstall_tray()?;
    }
    Ok(())
}

/// 当前 exe 绝对路径（服务定义引用；安装动作与运行时二进制同一份）。
fn current_exe() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("定位当前可执行: {e}"))
}

/// config 绝对路径（服务命令行携带；见模块文档「安装时路径」）。
fn abs_config(cfg_path: &Path) -> Result<PathBuf, String> {
    if cfg_path.is_absolute() {
        return Ok(cfg_path.to_path_buf());
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(cfg_path))
        .map_err(|e| format!("解析相对 config 路径 {}: {e}", cfg_path.display()))
}

// ============================================================================
// 托盘自启命令行引号（评审项 2：含空格路径不得把子命令吞进路径参数）
// ============================================================================

/// Windows HKCU Run 值渲染：`"<exe>" tray`——exe 路径整体加引号（Run 值经
/// CreateProcess 命令行解析，未加引号的空格路径会把首段目录当 exe）。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn tray_run_value(exe: &str) -> String {
    format!("\"{exe}\" tray")
}

/// .desktop `Exec=` 行参数引号转义（Desktop Entry Spec：含保留字符的参数整体
/// 双引号包裹，引号串内仅 `\\`、`\\``、`\\$`、`\\"` 四个转义序列有效——空格为
/// 字面值）。固定整体加引号（spec 允许、形态确定）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn desktop_quote_arg(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    for c in arg.chars() {
        if matches!(c, '\\' | '`' | '$' | '"') {
            out.push('\\'); // 引号串内可转义的仅此四字符
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Linux 托盘自启 .desktop 条目渲染（Exec 行 = `<引号 exe> tray`）。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn render_tray_desktop_entry(exe: &str) -> String {
    format!(
        "\
[Desktop Entry]
Type=Application
Name=Flock VPN Tray
Exec={} tray
X-GNOME-Autostart-enabled=true
",
        desktop_quote_arg(exe)
    )
}

// ============================================================================
// Linux：systemd
// ============================================================================

/// systemd 单元渲染（§7-M6.3；纯函数宿主可测）。
#[cfg(target_os = "linux")]
pub fn render_systemd_unit(exe: &str, cfg: &str) -> String {
    format!(
        "\
# flock-client systemd 单元（flock-client install 生成；docs/design.md §7-M6.3）
[Unit]
Description={SERVICE_DISPLAY_NAME} (Flock VPN daemon)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart={exe} service --config {cfg}
# 优雅停服（IPC Shutdown/exit 0）不复活；仅失败退出重启（§7-M6.1 退出语义）。
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"
    )
}

#[cfg(target_os = "linux")]
fn install_service(cfg_path: &Path) -> Result<(), String> {
    let exe = current_exe()?;
    let cfg = abs_config(cfg_path)?;
    let unit = render_systemd_unit(&exe.to_string_lossy(), &cfg.to_string_lossy());
    write_root_file(Path::new(SYSTEMD_UNIT_PATH), unit.as_bytes(), "sudo")?;
    run_cmd(
        "systemctl",
        &["daemon-reload"],
        "systemctl daemon-reload（需 root）",
    )?;
    run_cmd(
        "systemctl",
        &["enable", "--now", "flock-client"],
        "systemctl enable --now（需 root）",
    )?;
    println!("service 已安装并启用：{SYSTEMD_UNIT_PATH}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_service() -> Result<(), String> {
    // 服务可能未装（清理幂等）：单元文件不存在即跳过 enable/disable 步骤。
    if Path::new(SYSTEMD_UNIT_PATH).exists() {
        run_cmd(
            "systemctl",
            &["disable", "--now", "flock-client"],
            "systemctl disable --now（需 root）",
        )?;
        let _ = run_cmd(
            "systemctl",
            &["reset-failed", "flock-client"],
            "reset-failed",
        );
        std::fs::remove_file(SYSTEMD_UNIT_PATH)
            .map_err(|e| format!("删 {SYSTEMD_UNIT_PATH}: {e}（需 root）"))?;
        run_cmd(
            "systemctl",
            &["daemon-reload"],
            "systemctl daemon-reload（需 root）",
        )?;
    }
    println!("service 已卸载");
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_tray() -> Result<(), String> {
    let exe = current_exe()?;
    let dir = home_dir()?.join(AUTOSTART_DIR_REL);
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    // Exec 行引号转义（评审项 2：含空格路径按 Desktop Entry Spec 加引号）。
    let entry = render_tray_desktop_entry(&exe.to_string_lossy());
    let path = dir.join(TRAY_DESKTOP_NAME);
    std::fs::write(&path, entry).map_err(|e| format!("写 {}: {e}", path.display()))?;
    println!("托盘自启已注册：{}", path.display());
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_tray() -> Result<(), String> {
    let path = home_dir()?.join(AUTOSTART_DIR_REL).join(TRAY_DESKTOP_NAME);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("删 {}: {e}", path.display()))?;
    }
    println!("托盘自启已注销");
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "无 HOME 环境变量（用户级自启不可用）".to_string())
}

// ============================================================================
// macOS：launchd（本机无设备 ⇒ 未验证；文件与命令照常产出，真机清单留位）
// ============================================================================

/// LaunchDaemon/LaunchAgent plist 渲染（RunAtLoad；**无 KeepAlive**——Shutdown 后
/// 不复活，§7-M6.1）。
///
/// `program_args` **逐项**渲染为独立 `<string>`（launchd ProgramArguments 语义：数组
/// 直接 exec、不经 shell——含空格路径无须也不得内嵌引号）。评审项 1 修正：此前
/// 「托盘把 `exe tray` 拼进单参数 + 渲染器无条件补 `service`」产出
/// `["<exe> tray","service"]` 双错形——渲染器改为参数化后由调用方给形态：
/// daemon = `[exe, "service", "--config", cfg]`、tray = `[exe, "tray"]`。
///
/// 纯函数全平台编译（渲染断言进宿主门禁；非 macOS 仅测试消费 ⇒ allow(dead_code)）。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn render_launchd_plist(label: &str, program_args: &[&str]) -> String {
    let args = program_args
        .iter()
        .map(|a| format!("\n        <string>{}</string>", xml_escape(a)))
        .collect::<String>();
    format!(
        "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>{args}
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"
    )
}

#[cfg(target_os = "macos")]
fn install_service(cfg_path: &Path) -> Result<(), String> {
    let exe = current_exe()?;
    let cfg = abs_config(cfg_path)?;
    let exe = exe.to_string_lossy().into_owned();
    let cfg = cfg.to_string_lossy().into_owned();
    let plist = render_launchd_plist(LAUNCHD_SERVICE_LABEL, &[&exe, "service", "--config", &cfg]);
    write_root_file(Path::new(LAUNCHDAEMON_PATH), plist.as_bytes(), "sudo")?;
    run_cmd(
        "launchctl",
        &["load", "-w", LAUNCHDAEMON_PATH],
        "launchctl load（需 root）",
    )?;
    println!("service 已安装并加载：{LAUNCHDAEMON_PATH}（macOS 路径未真机验证，§7-M6.6）");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_service() -> Result<(), String> {
    if Path::new(LAUNCHDAEMON_PATH).exists() {
        let _ = run_cmd(
            "launchctl",
            &["unload", "-w", LAUNCHDAEMON_PATH],
            "launchctl unload（需 root）",
        );
        std::fs::remove_file(LAUNCHDAEMON_PATH)
            .map_err(|e| format!("删 {LAUNCHDAEMON_PATH}: {e}（需 root）"))?;
    }
    println!("service 已卸载（macOS 路径未真机验证）");
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_tray() -> Result<(), String> {
    let exe = current_exe()?;
    // 托盘 LaunchAgent：同一二进制 `tray` 子命令——独立 string 项（评审项 1）。
    let exe = exe.to_string_lossy().into_owned();
    let plist = render_launchd_plist(LAUNCHD_TRAY_LABEL, &[&exe, "tray"]);
    let path = home_dir()?.join(TRAY_AGENT_REL);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, plist).map_err(|e| format!("写 {}: {e}", path.display()))?;
    let _ = run_cmd(
        "launchctl",
        &["load", "-w", &path.to_string_lossy()],
        "launchctl load（用户会话）",
    );
    println!("托盘自启已注册：{}（macOS 路径未真机验证）", path.display());
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_tray() -> Result<(), String> {
    let path = home_dir()?.join(TRAY_AGENT_REL);
    if path.exists() {
        let _ = run_cmd(
            "launchctl",
            &["unload", "-w", &path.to_string_lossy()],
            "launchctl unload（用户会话）",
        );
        std::fs::remove_file(&path).map_err(|e| format!("删 {}: {e}", path.display()))?;
    }
    println!("托盘自启已注销（macOS 路径未真机验证）");
    Ok(())
}

/// plist 文本转义（路径里的 &/</>；属性值上下文）。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ============================================================================
// Unix 共用：root 文件写入 + 命令执行（失败如实上抛 + 提权提示）
// ============================================================================

#[cfg(unix)]
fn write_root_file(path: &Path, bytes: &[u8], sudo_hint: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "写 {} 权限不足（需 root，{sudo_hint} 提升后重试）: {e}",
                path.display()
            )
        } else {
            format!("写 {}: {e}", path.display())
        }
    })
}

#[cfg(unix)]
fn run_cmd(program: &str, args: &[&str], context: &str) -> Result<(), String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{context}: 启动 {program}: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "{context}: {program} {} 退出 {}（{}）",
            args.join(" "),
            out.status.code().unwrap_or(-1),
            stderr.trim()
        ));
    }
    Ok(())
}

// ============================================================================
// Windows：SCM 服务（windows-service crate）+ 事件日志源 + HKCU Run
// ============================================================================

#[cfg(target_os = "windows")]
fn install_service(cfg_path: &Path) -> Result<(), String> {
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
        ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
        ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let exe = current_exe()?;
    let cfg = abs_config(cfg_path)?;

    let manager = match ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
    ) {
        Ok(m) => m,
        Err(e) => {
            return Err(format!(
                "打开服务管理器失败（服务安装需管理员：以提升会话重跑 `flock-client install`）: {e}"
            ))
        }
    };
    // 幂等重装：已存在即先删（DELETE 权限打开；不存在则跳过）。
    match manager.open_service(crate::service::SERVICE_NAME, ServiceAccess::DELETE) {
        Ok(existing) => {
            let _ = existing.stop(); // 停在跑实例（忽略未运行错误）
            existing
                .delete()
                .map_err(|e| format!("删除旧服务定义: {e}"))?;
            println!("已移除旧服务定义（重装）");
        }
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(1060 /* ERROR_SERVICE_DOES_NOT_EXIST */) => {}
        Err(e) => return Err(format!("查询既有服务: {e}")),
    }

    let info = ServiceInfo {
        name: OsString::from(crate::service::SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("--config"),
            OsString::from(cfg.clone()),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem（§7-M6.1：服务在系统上下文，与托盘会话分离）
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::ALL_ACCESS)
        .map_err(|e| format!("创建服务（需管理员）: {e}"))?;
    // 失败恢复策略（§7-M6.3）：第 1/2 次失败重启（延迟 5s），第 3 次起不再动作
    //（封顶 3 次；优雅停服 exit 0 不触发恢复——Restart=on-failure 同语义）。
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                },
                ServiceAction {
                    action_type: ServiceActionType::None,
                    delay: Duration::default(),
                },
            ]),
        })
        .map_err(|e| format!("设置恢复策略: {e}"))?;
    register_event_log_source()?;
    println!(
        "service 已安装：{}（AUTO_START + 失败恢复重启；命令行 service --config {}）",
        crate::service::SERVICE_NAME,
        cfg.display()
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_service() -> Result<(), String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    {
        Ok(m) => m,
        Err(e) => {
            return Err(format!(
            "打开服务管理器失败（服务卸载需管理员：以提升会话重跑 `flock-client uninstall`）: {e}"
        ))
        }
    };
    let service = match manager.open_service(
        crate::service::SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(s) => s,
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(1060 /* ERROR_SERVICE_DOES_NOT_EXIST */) =>
        {
            println!("服务未安装（幂等跳过）");
            return Ok(());
        }
        Err(e) => return Err(format!("查询服务: {e}")),
    };
    let _ = service.stop(); // 停在跑实例（SCM Stop → 优雅停服；忽略未运行错误）
    service
        .delete()
        .map_err(|e| format!("删除服务（需管理员）: {e}"))?;
    unregister_event_log_source();
    println!("service 已卸载");
    Ok(())
}

/// 事件日志源注册（HKLM；随服务安装，需管理员）：TypesSupported 全档。无消息 DLL ⇒
/// 事件以插入串呈现（§7-M6.3；消息模板 DLL 列后续打磨项）。
#[cfg(target_os = "windows")]
fn register_event_log_source() -> Result<(), String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let base = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = base
        .create_subkey(r"SYSTEM\CurrentControlSet\Services\EventLog\Application\flock-client")
        .map_err(|e| format!("注册事件日志源（需管理员）: {e}"))?;
    key.set_value("TypesSupported", &7u32) // ERROR|WARNING|INFORMATION
        .map_err(|e| format!("写 TypesSupported: {e}"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn unregister_event_log_source() {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS};
    use winreg::RegKey;
    let _ = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Services\EventLog\Application",
            KEY_ALL_ACCESS,
        )
        .and_then(|k| k.delete_subkey("flock-client"));
}

#[cfg(target_os = "windows")]
fn install_tray() -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let exe = current_exe()?;
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")
        .map_err(|e| format!("打开 HKCU Run: {e}"))?;
    key.set_value(
        "flock-client-tray",
        // 引号包裹 exe（评审项 2：空格路径下 CreateProcess 才不把目录段当 exe）。
        &tray_run_value(&exe.to_string_lossy()),
    )
    .map_err(|e| format!("写 Run 值: {e}"))?;
    println!("托盘自启已注册：HKCU\\...\\Run\\flock-client-tray");
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_tray() -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    use winreg::RegKey;
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            KEY_SET_VALUE,
        )
        .map_err(|e| format!("打开 HKCU Run: {e}"))?;
    match key.delete_value("flock-client-tray") {
        Ok(()) => {
            println!("托盘自启已注销");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("托盘自启未注册（幂等跳过）");
            Ok(())
        }
        Err(e) => Err(format!("删 Run 值: {e}")),
    }
}

// ============================================================================
// 单元测试（渲染纯函数 + Windows HKCU 侧宿主可测面；SCM/systemd/launchd 执行面
// 列 docs/manual/service-install.md 手工清单）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_unit_renders_required_directives() {
        let unit = render_systemd_unit("/usr/local/bin/flock-client", "/etc/flock/client.toml");
        assert!(
            unit.contains("WantedBy=multi-user.target"),
            "§7-M6.3 拓扑目标"
        );
        assert!(
            unit.contains("Restart=on-failure"),
            "失败重启、优雅停服不复活"
        );
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("Wants=network-online.target"));
        assert!(unit.contains(
            "ExecStart=/usr/local/bin/flock-client service --config /etc/flock/client.toml"
        ));
        assert!(
            !unit.contains("Restart=always"),
            "不得写成 always（Shutdown 会复活）"
        );
    }

    /// 提取 plist 的 ProgramArguments 数组项（逐项断言用——评审项 1：args 必须各自
    /// 独立 `<string>`，不得把「exe+子命令」拼进同项）。
    fn plist_program_args(plist: &str) -> Vec<String> {
        let start = plist
            .find("<key>ProgramArguments</key>")
            .expect("ProgramArguments 键在位");
        let body = &plist[start..];
        let end = body.find("</array>").expect("数组闭合");
        body[..end]
            .split("<string>")
            .skip(1)
            .map(|s| s.split("</string>").next().unwrap().to_string())
            .collect()
    }

    /// daemon 形态：args 逐项 = `[exe, "service", "--config", cfg]`（含空格路径独立
    /// 成项、xml 转义）；RunAtLoad 在、无 KeepAlive。
    #[test]
    fn launchd_plist_daemon_args_are_separate_strings() {
        let exe = "/usr/local/bin/Flock Client/flock-client";
        let cfg = "/etc/flock/client&.toml";
        let plist = render_launchd_plist("com.flockvpn.client", &[exe, "service", "--config", cfg]);
        assert_eq!(
            plist_program_args(&plist),
            vec![
                "/usr/local/bin/Flock Client/flock-client".to_string(),
                "service".to_string(),
                "--config".to_string(),
                "/etc/flock/client&amp;.toml".to_string(), // xml 转义（&）
            ],
            "daemon 形态四项独立 string（exe 不与 service 拼接）"
        );
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(
            !plist.contains("KeepAlive"),
            "无 KeepAlive（Shutdown 不复活）"
        );
    }

    /// tray 形态：args 逐项 = `[exe, "tray"]`——无 `service` 项、无 `--config`
    ///（评审项 1：旧实现托盘形态产出 `["<exe> tray","service"]` 双错形）。
    #[test]
    fn launchd_plist_tray_args_are_exe_tray_only() {
        let exe = "/usr/local/bin/Flock Client/flock-client";
        let plist = render_launchd_plist("com.flockvpn.client-tray", &[exe, "tray"]);
        assert_eq!(
            plist_program_args(&plist),
            vec![
                "/usr/local/bin/Flock Client/flock-client".to_string(),
                "tray".to_string(),
            ],
            "tray 形态两项独立 string"
        );
        assert!(!plist.contains("--config"));
        assert!(!plist.contains("KeepAlive"));
    }

    #[test]
    fn xml_escape_covers_path_characters() {
        assert_eq!(xml_escape("a&b<c>d"), "a&amp;b&lt;c&gt;d");
    }

    /// Windows：HKCU Run 键注册/注销往返（无需提权，宿主可测；服务安装/卸载的 SCM
    /// 面需管理员 → 手工清单）。
    #[cfg(target_os = "windows")]
    #[test]
    fn hkcu_run_tray_autostart_roundtrip() {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
        use winreg::RegKey;
        // 直接调用 install_tray（写的是当前测试进程 exe 路径）——值形如
        // `"<exe>" tray`：exe 引号包裹（评审项 2），内嵌路径与 current_exe 一致。
        install_tray().expect("HKCU Run 写入（无提权面）");
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_READ)
            .unwrap();
        let v: String = key.get_value("flock-client-tray").expect("Run 值存在");
        let exe = std::env::current_exe().unwrap().to_string_lossy().into_owned();
        assert_eq!(v, format!("\"{exe}\" tray"), "Run 值 = 引号 exe + tray");
        uninstall_tray().expect("HKCU Run 删除");
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_READ)
            .unwrap();
        assert!(
            key.get_value::<String, _>("flock-client-tray").is_err(),
            "注销后值不存在"
        );
    }

    /// 评审项 2：自启命令行含空格路径——HKCU Run 值 exe 整体加引号（`"<exe>" tray`）。
    #[test]
    fn tray_run_value_quotes_exe_with_spaces() {
        assert_eq!(
            tray_run_value("/opt/Flock Client/bin/flock-client"),
            "\"/opt/Flock Client/bin/flock-client\" tray"
        );
        assert_eq!(
            tray_run_value("C:\\Program Files\\Flock\\flock-client.exe"),
            "\"C:\\Program Files\\Flock\\flock-client.exe\" tray"
        );
    }

    /// 评审项 2：.desktop Exec 行按 Desktop Entry Spec 引号转义（含空格路径整体
    /// 双引号；引号串内 \\、\\`、\\$、\\" 转义；tray 参数无保留字符不加引号）。
    #[test]
    fn tray_desktop_exec_quotes_and_escapes_per_spec() {
        let entry = render_tray_desktop_entry("/opt/Flock Client/bin/flock-client");
        assert!(
            entry.contains("Exec=\"/opt/Flock Client/bin/flock-client\" tray\n"),
            "Exec 行 = 引号 exe + 裸 tray，得 {entry}"
        );
        // 保留字符转义（spec 四序列）。
        assert_eq!(
            desktop_quote_arg(r##"a"b\c$d`e"##),
            "\"a\\\"b\\\\c\\$d\\`e\""
        );
        // 空参数仍得空引号串（spec：空串必须引号）。
        assert_eq!(desktop_quote_arg(""), "\"\"");
    }
}
