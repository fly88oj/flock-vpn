//! Service install/uninstall + tray autostart registration (docs/design.md
//! §7-M6.3).
//!
//! `flock-client install [--user|--service]` / `uninstall [--user|--service]`:
//! `--user` touches only tray autostart, `--service` only the system
//! service, default both. Installation writes the **installation-time**
//! absolute `--config` path into the service definition (the SCM working
//! directory = system32, systemd/launchd do not inherit the shell CWD, so
//! relative paths are unusable).
//!
//! Platform matrix and verification boundary (§7-M6.6-4):
//! - **Windows**: the windows-service crate (SCM install/AUTO_START/recovery
//!   policy/event-log source registration — compile-level verification + the
//!   HKCU Run key is host-testable; **SCM installation requires an
//!   administrator**; a non-elevated session gets a clear error, and
//!   real-machine installation is on the docs/manual/service-install.md
//!   manual checklist);
//! - **Linux**: systemd unit rendering (pure function, host-testable) + the
//!   write/enable command sequence (the execution side needs root + systemd
//!   running; without systemd in the container, installation errors are
//!   returned honestly);
//! - **macOS**: launchd plist rendering + launchctl commands (**no device
//!   here ⇒ unverified**; files and commands are produced as usual, the
//!   real-machine checklist placeholder remains).
//!
//! Tray autostart: Windows `HKCU\...\Run` (no elevation needed); Linux
//! `~/.config/autostart/*.desktop`; macOS `~/Library/LaunchAgents/*.plist`.

use std::path::{Path, PathBuf};

/// Install scope (§7-M6.3: `--user` / `--service` / default both).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    ServiceOnly,
    TrayOnly,
    Both,
}

/// Service display name (unified across SCM / description lines).
pub const SERVICE_DISPLAY_NAME: &str = "Flock VPN Client";
/// Linux tray autostart file name.
pub const TRAY_DESKTOP_NAME: &str = "flock-client-tray.desktop";
/// macOS LaunchDaemon/LaunchAgent label constants.
pub const LAUNCHD_SERVICE_LABEL: &str = "com.flockvpn.client";
pub const LAUNCHD_TRAY_LABEL: &str = "com.flockvpn.client-tray";

// ============================================================================
// Platform constants (paths)
// ============================================================================

/// systemd unit path (must be inside a unit search directory —
/// `/etc/systemd/system/`; placed in the `/etc/systemd/` root, systemd does
/// not load it and `systemctl enable` reports unit not found).
#[cfg(target_os = "linux")]
pub const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/flock-client.service";
/// macOS LaunchDaemon plist path.
#[cfg(target_os = "macos")]
pub const LAUNCHDAEMON_PATH: &str = "/Library/LaunchDaemons/com.flockvpn.client.plist";
/// macOS tray LaunchAgent plist path (user-level, `~/` expanded).
#[cfg(target_os = "macos")]
pub const TRAY_AGENT_REL: &str = "Library/LaunchAgents/com.flockvpn.client-tray.plist";
/// Linux tray autostart directory (user-level, `~/` expanded).
#[cfg(target_os = "linux")]
pub const AUTOSTART_DIR_REL: &str = ".config/autostart";

// ============================================================================
// Entry points
// ============================================================================

/// Install (service + tray autostart, per scope).
pub fn install(cfg_path: &Path, scope: Scope) -> Result<(), String> {
    if matches!(scope, Scope::ServiceOnly | Scope::Both) {
        install_service(cfg_path)?;
    }
    if matches!(scope, Scope::TrayOnly | Scope::Both) {
        install_tray()?;
    }
    Ok(())
}

/// Uninstall (reverse cleanup).
pub fn uninstall(scope: Scope) -> Result<(), String> {
    if matches!(scope, Scope::ServiceOnly | Scope::Both) {
        uninstall_service()?;
    }
    if matches!(scope, Scope::TrayOnly | Scope::Both) {
        uninstall_tray()?;
    }
    Ok(())
}

/// Absolute path of the current exe (referenced by the service definition;
/// the install action and the runtime binary are one and the same).
fn current_exe() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("locate current executable: {e}"))
}

/// Absolute config path (carried on the service command line; see the
/// "installation-time path" note in the module docs).
fn abs_config(cfg_path: &Path) -> Result<PathBuf, String> {
    if cfg_path.is_absolute() {
        return Ok(cfg_path.to_path_buf());
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(cfg_path))
        .map_err(|e| format!("resolve relative config path {}: {e}", cfg_path.display()))
}

// ============================================================================
// Tray autostart command-line quoting (review item 2: a path with spaces
// must not swallow the subcommand into the path argument)
// ============================================================================

/// Windows HKCU Run value rendering: `"<exe>" tray` — the exe path is quoted
/// as a whole (Run values go through CreateProcess command-line parsing; an
/// unquoted path with spaces would treat the first directory segment as the
/// exe).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn tray_run_value(exe: &str) -> String {
    format!("\"{exe}\" tray")
}

/// `.desktop` `Exec=` line argument quoting/escaping (Desktop Entry Spec: an
/// argument containing reserved characters is wrapped in double quotes as a
/// whole; inside a quoted string only the four escape sequences `\\`, `` \` ``,
/// `\$`, `\"` are valid — spaces are literal). Always quoted as a whole (the
/// spec allows it and the shape is deterministic).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn desktop_quote_arg(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    for c in arg.chars() {
        if matches!(c, '\\' | '`' | '$' | '"') {
            out.push('\\'); // only these four characters are escapable inside a quoted string
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Linux tray-autostart .desktop entry rendering (Exec line = `<quoted exe>
/// tray`).
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
// Linux: systemd
// ============================================================================

/// systemd unit rendering (§7-M6.3; a pure function, host-testable).
#[cfg(target_os = "linux")]
pub fn render_systemd_unit(exe: &str, cfg: &str) -> String {
    format!(
        "\
# flock-client systemd unit (generated by `flock-client install`; docs/design.md §7-M6.3)
[Unit]
Description={SERVICE_DISPLAY_NAME} (Flock VPN daemon)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart={exe} service --config {cfg}
# Graceful shutdown (IPC Shutdown / exit 0) does not restart; only failure
# exits do (§7-M6.1 shutdown semantics).
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
        "systemctl daemon-reload (needs root)",
    )?;
    run_cmd(
        "systemctl",
        &["enable", "--now", "flock-client"],
        "systemctl enable --now (needs root)",
    )?;
    println!("service installed and enabled: {SYSTEMD_UNIT_PATH}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_service() -> Result<(), String> {
    // The service may be absent (idempotent cleanup): if the unit file does
    // not exist, skip the enable/disable steps.
    if Path::new(SYSTEMD_UNIT_PATH).exists() {
        run_cmd(
            "systemctl",
            &["disable", "--now", "flock-client"],
            "systemctl disable --now (needs root)",
        )?;
        let _ = run_cmd(
            "systemctl",
            &["reset-failed", "flock-client"],
            "reset-failed",
        );
        std::fs::remove_file(SYSTEMD_UNIT_PATH)
            .map_err(|e| format!("delete {SYSTEMD_UNIT_PATH}: {e} (needs root)"))?;
        run_cmd(
            "systemctl",
            &["daemon-reload"],
            "systemctl daemon-reload (needs root)",
        )?;
    }
    println!("service uninstalled");
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_tray() -> Result<(), String> {
    let exe = current_exe()?;
    let dir = home_dir()?.join(AUTOSTART_DIR_REL);
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    // Exec-line quoting/escaping (review item 2: paths with spaces get
    // quoted per the Desktop Entry Spec).
    let entry = render_tray_desktop_entry(&exe.to_string_lossy());
    let path = dir.join(TRAY_DESKTOP_NAME);
    std::fs::write(&path, entry).map_err(|e| format!("write {}: {e}", path.display()))?;
    println!("tray autostart registered: {}", path.display());
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_tray() -> Result<(), String> {
    let path = home_dir()?.join(AUTOSTART_DIR_REL).join(TRAY_DESKTOP_NAME);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("delete {}: {e}", path.display()))?;
    }
    println!("tray autostart unregistered");
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn home_dir() -> Result<PathBuf, String> {
    std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
        "no HOME environment variable (user-level autostart unavailable)".to_string()
    })
}

// ============================================================================
// macOS: launchd (no device here ⇒ unverified; files and commands are
// produced as usual, the real-machine checklist placeholder remains)
// ============================================================================

/// LaunchDaemon/LaunchAgent plist rendering (RunAtLoad; **no KeepAlive** —
/// no revival after Shutdown, §7-M6.1).
///
/// `program_args` renders **each item** as its own `<string>` (launchd
/// ProgramArguments semantics: the array is exec'd directly, no shell — a
/// path with spaces needs and must not contain embedded quotes). Review
/// item 1 fix: previously "the tray concatenated `exe tray` into a single
/// argument + the renderer unconditionally appended `service`" produced the
/// doubly-wrong `["<exe> tray","service"]` — the renderer is now
/// parameterized and the caller supplies the shape: daemon = `[exe,
/// "service", "--config", cfg]`, tray = `[exe, "tray"]`.
///
/// A pure function compiled on all platforms (rendering assertions are in
/// the host gate; on non-macOS only tests consume it ⇒ allow(dead_code)).
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
        "launchctl load (needs root)",
    )?;
    println!(
        "service installed and loaded: {LAUNCHDAEMON_PATH} (macOS path not verified on real \
         hardware, §7-M6.6)"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_service() -> Result<(), String> {
    if Path::new(LAUNCHDAEMON_PATH).exists() {
        let _ = run_cmd(
            "launchctl",
            &["unload", "-w", LAUNCHDAEMON_PATH],
            "launchctl unload (needs root)",
        );
        std::fs::remove_file(LAUNCHDAEMON_PATH)
            .map_err(|e| format!("delete {LAUNCHDAEMON_PATH}: {e} (needs root)"))?;
    }
    println!("service uninstalled (macOS path not verified on real hardware)");
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_tray() -> Result<(), String> {
    let exe = current_exe()?;
    // Tray LaunchAgent: the same binary's `tray` subcommand — a separate
    // string item (review item 1).
    let exe = exe.to_string_lossy().into_owned();
    let plist = render_launchd_plist(LAUNCHD_TRAY_LABEL, &[&exe, "tray"]);
    let path = home_dir()?.join(TRAY_AGENT_REL);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, plist).map_err(|e| format!("write {}: {e}", path.display()))?;
    let _ = run_cmd(
        "launchctl",
        &["load", "-w", &path.to_string_lossy()],
        "launchctl load (user session)",
    );
    println!(
        "tray autostart registered: {} (macOS path not verified on real hardware)",
        path.display()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_tray() -> Result<(), String> {
    let path = home_dir()?.join(TRAY_AGENT_REL);
    if path.exists() {
        let _ = run_cmd(
            "launchctl",
            &["unload", "-w", &path.to_string_lossy()],
            "launchctl unload (user session)",
        );
        std::fs::remove_file(&path).map_err(|e| format!("delete {}: {e}", path.display()))?;
    }
    println!("tray autostart unregistered (macOS path not verified on real hardware)");
    Ok(())
}

/// plist text escaping (for &/</> in paths; attribute-value context).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ============================================================================
// Unix shared: root file writes + command execution (failures bubble up
// honestly + elevation hints)
// ============================================================================

#[cfg(unix)]
fn write_root_file(path: &Path, bytes: &[u8], sudo_hint: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "insufficient permission to write {} (root required; elevate with {sudo_hint} \
                 and retry): {e}",
                path.display()
            )
        } else {
            format!("write {}: {e}", path.display())
        }
    })
}

#[cfg(unix)]
fn run_cmd(program: &str, args: &[&str], context: &str) -> Result<(), String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{context}: spawn {program}: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "{context}: {program} {} exited {} ({})",
            args.join(" "),
            out.status.code().unwrap_or(-1),
            stderr.trim()
        ));
    }
    Ok(())
}

// ============================================================================
// Windows: SCM service (windows-service crate) + event log source + HKCU Run
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
                "failed to open the service manager (service installation requires an \
                 administrator: re-run `flock-client install` from an elevated session): {e}"
            ))
        }
    };
    // Idempotent reinstall: delete first when it exists (opened with DELETE
    // access; skipped when absent).
    match manager.open_service(crate::service::SERVICE_NAME, ServiceAccess::DELETE) {
        Ok(existing) => {
            let _ = existing.stop(); // stop a running instance (ignore not-running errors)
            existing
                .delete()
                .map_err(|e| format!("delete old service definition: {e}"))?;
            println!("removed old service definition (reinstall)");
        }
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(1060 /* ERROR_SERVICE_DOES_NOT_EXIST */) => {}
        Err(e) => return Err(format!("query existing service: {e}")),
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
        account_name: None, // LocalSystem (§7-M6.1: the service runs in the system context, separate from the tray session)
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::ALL_ACCESS)
        .map_err(|e| format!("create service (administrator required): {e}"))?;
    // Failure-recovery policy (§7-M6.3): restart on the 1st/2nd failure
    // (5s delay), no action from the 3rd on (capped at 3; graceful-shutdown
    // exit 0 does not trigger recovery — same semantics as
    // Restart=on-failure).
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
        .map_err(|e| format!("set recovery policy: {e}"))?;
    register_event_log_source()?;
    println!(
        "service installed: {} (AUTO_START + failure-recovery restart; command line: service \
         --config {})",
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
                "failed to open the service manager (service uninstallation requires an \
                 administrator: re-run `flock-client uninstall` from an elevated session): {e}"
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
            println!("service not installed (idempotent skip)");
            return Ok(());
        }
        Err(e) => return Err(format!("query service: {e}")),
    };
    let _ = service.stop(); // stop a running instance (SCM Stop -> graceful shutdown; ignore not-running errors)
    service
        .delete()
        .map_err(|e| format!("delete service (administrator required): {e}"))?;
    unregister_event_log_source();
    println!("service uninstalled");
    Ok(())
}

/// Event-log source registration (HKLM; ships with the service install,
/// needs an administrator): TypesSupported at full value. Without a message
/// DLL ⇒ events render as insertion strings (§7-M6.3; a message-template DLL
/// is a later polish item).
#[cfg(target_os = "windows")]
fn register_event_log_source() -> Result<(), String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let base = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = base
        .create_subkey(r"SYSTEM\CurrentControlSet\Services\EventLog\Application\flock-client")
        .map_err(|e| format!("register event log source (administrator required): {e}"))?;
    key.set_value("TypesSupported", &7u32) // ERROR|WARNING|INFORMATION
        .map_err(|e| format!("write TypesSupported: {e}"))?;
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
        .map_err(|e| format!("open HKCU Run: {e}"))?;
    key.set_value(
        "flock-client-tray",
        // The exe is quoted (review item 2: only then does CreateProcess not
        // treat a directory segment as the exe for paths with spaces).
        &tray_run_value(&exe.to_string_lossy()),
    )
    .map_err(|e| format!("write Run value: {e}"))?;
    println!("tray autostart registered: HKCU\\...\\Run\\flock-client-tray");
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
        .map_err(|e| format!("open HKCU Run: {e}"))?;
    match key.delete_value("flock-client-tray") {
        Ok(()) => {
            println!("tray autostart unregistered");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("tray autostart not registered (idempotent skip)");
            Ok(())
        }
        Err(e) => Err(format!("delete Run value: {e}")),
    }
}

// ============================================================================
// Unit tests (rendering pure functions + the host-testable Windows HKCU
// side; the SCM/systemd/launchd execution surface is on the
// docs/manual/service-install.md manual checklist)
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
            "§7-M6.3 topology target"
        );
        assert!(
            unit.contains("Restart=on-failure"),
            "restart on failure; graceful shutdown does not revive"
        );
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("Wants=network-online.target"));
        assert!(unit.contains(
            "ExecStart=/usr/local/bin/flock-client service --config /etc/flock/client.toml"
        ));
        assert!(
            !unit.contains("Restart=always"),
            "must not be always (Shutdown would revive)"
        );
    }

    /// Extract the ProgramArguments array items of a plist (for per-item
    /// assertion — review item 1: args must each be their own `<string>`;
    /// "exe+subcommand" must not be concatenated into one item).
    fn plist_program_args(plist: &str) -> Vec<String> {
        let start = plist
            .find("<key>ProgramArguments</key>")
            .expect("ProgramArguments key present");
        let body = &plist[start..];
        let end = body.find("</array>").expect("array closed");
        body[..end]
            .split("<string>")
            .skip(1)
            .map(|s| s.split("</string>").next().unwrap().to_string())
            .collect()
    }

    /// Daemon shape: args item by item = `[exe, "service", "--config", cfg]`
    /// (a path with spaces its own item, xml-escaped); RunAtLoad present, no
    /// KeepAlive.
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
                "/etc/flock/client&amp;.toml".to_string(), // xml-escaped (&)
            ],
            "daemon shape: four separate strings (exe not concatenated with service)"
        );
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(
            !plist.contains("KeepAlive"),
            "no KeepAlive (Shutdown does not revive)"
        );
    }

    /// Tray shape: args item by item = `[exe, "tray"]` — no `service` item,
    /// no `--config` (review item 1: the old implementation produced the
    /// doubly-wrong `["<exe> tray","service"]` for the tray shape).
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
            "tray shape: two separate strings"
        );
        assert!(!plist.contains("--config"));
        assert!(!plist.contains("KeepAlive"));
    }

    #[test]
    fn xml_escape_covers_path_characters() {
        assert_eq!(xml_escape("a&b<c>d"), "a&amp;b&lt;c&gt;d");
    }

    /// Windows: HKCU Run key register/unregister roundtrip (no elevation
    /// needed, host-testable; the SCM side of service install/uninstall
    /// needs an administrator → manual checklist).
    #[cfg(target_os = "windows")]
    #[test]
    fn hkcu_run_tray_autostart_roundtrip() {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
        use winreg::RegKey;
        // Call install_tray directly (it writes the current test-process exe
        // path) — the value looks like `"<exe>" tray`: exe quoted (review
        // item 2), the embedded path matching current_exe.
        install_tray().expect("HKCU Run write (no elevation surface)");
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_READ)
            .unwrap();
        let v: String = key
            .get_value("flock-client-tray")
            .expect("Run value exists");
        let exe = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            v,
            format!("\"{exe}\" tray"),
            "Run value = quoted exe + tray"
        );
        uninstall_tray().expect("HKCU Run delete");
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_READ)
            .unwrap();
        assert!(
            key.get_value::<String, _>("flock-client-tray").is_err(),
            "value absent after unregistering"
        );
    }

    /// Review item 2: autostart command line with a path containing spaces —
    /// the HKCU Run value quotes the exe as a whole (`"<exe>" tray`).
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

    /// Review item 2: the .desktop Exec line quotes/escapes per the Desktop
    /// Entry Spec (paths with spaces quoted as a whole; inside the quoted
    /// string \\, \` , \$, \" escaped; the tray argument carries no reserved
    /// characters and would go unquoted).
    #[test]
    fn tray_desktop_exec_quotes_and_escapes_per_spec() {
        let entry = render_tray_desktop_entry("/opt/Flock Client/bin/flock-client");
        assert!(
            entry.contains("Exec=\"/opt/Flock Client/bin/flock-client\" tray\n"),
            "Exec line = quoted exe + bare tray, got {entry}"
        );
        // Reserved-character escaping (the spec's four sequences).
        assert_eq!(
            desktop_quote_arg(r##"a"b\c$d`e"##),
            "\"a\\\"b\\\\c\\$d\\`e\""
        );
        // An empty argument still gets an empty quoted string (spec: the
        // empty string must be quoted).
        assert_eq!(desktop_quote_arg(""), "\"\"");
    }
}
