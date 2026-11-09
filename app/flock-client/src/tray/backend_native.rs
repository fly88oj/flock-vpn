//! Windows/macOS 托盘后端（`tray-icon` 内建菜单——muda 经 `tray_icon::menu` 再导出
//! 消费；docs/design.md §7-M6 第二阶段）。
//!
//! 选型与最小泵形态（不引入 winit/tauri/egui 全套 GUI 栈——本进程不建任何窗口）：
//! - tray-icon 支持**无窗口**使用（Windows/macOS 原生托盘后端 + muda 原生菜单），
//!   但事件派发依赖所在线程的**消息泵/事件循环**——两平台各配最小可行泵：
//! - **Windows**：托盘/菜单线程亲和（Win32 消息驱动）——专用线程跑 `GetMessageW` 泵
//!   （tray-icon 官方最小示例形态），主线程的轮询循环经 `PostThreadMessageW`
//!   （自定义 `WM_APP` 消息）唤醒泵消费最新文案；「退出」经 `WM_QUIT` 收泵，
//!   tray Drop 移除图标；
//! - **macOS**：AppKit 要求托盘/NSMenu 在**主线程**且跑事件循环——主线程手动排空
//!   NSApp 事件（`nextEvent…/sendEvent/updateWindows`，50ms 节律消费共享刷新），
//!   轮询/IPC 跑独立线程（自有 tokio rt）。**本机无 macOS 设备：编译级验证 + 真机
//!   清单留位（docs/manual/service-install.md §托盘真机清单）**。
//!
//! 平台差异只在「泵在哪跑、怎么唤醒」；菜单构建（三项：状态/VIP/退出）与轮询驱动
//! （[`drive`]）共用。托盘创建失败（无 GUI 会话等）⇒ 打印清晰日志 + 进程优雅退出
//! （退出码 0，不 panic）。

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use super::icon::{flock_rgba, ICON_SIZE};
use super::{ControlPaths, ExitDecision, MenuTexts, POLL_INTERVAL};

/// 菜单项 id（muda `MenuId` 字符串；「退出」匹配 MenuEvent，两项只读展示）。
const ITEM_STATUS: &str = "flock-status";
const ITEM_VIP: &str = "flock-vip";
const ITEM_EXIT: &str = "flock-exit";

/// 托盘句柄（状态/VIP 只读项 + tooltip；创建线程持有——Win32 菜单与 NSMenu 均线程
/// 亲和，所有变更经拥有线程的泵/循环执行）。
struct NativeTray {
    tray: TrayIcon,
    status: MenuItem,
    vip: MenuItem,
}

/// 建托盘：三项菜单（「连接状态」「VPN IP」disabled 只读项——置灰为只读展示的
/// 平台惯用形态；「退出」动作项）+ 内嵌图标 + tooltip。
///
/// 错误统一 `String`（菜单/图标/托盘三族错误只用于日志后优雅退出，不区分类别）。
fn build_native_tray() -> Result<NativeTray, String> {
    let status = MenuItem::with_id(ITEM_STATUS, "连接状态：服务未运行", false, None);
    let vip = MenuItem::with_id(ITEM_VIP, "VPN IP：—", false, None);
    let exit = MenuItem::with_id(ITEM_EXIT, "退出", true, None);
    let menu = Menu::new();
    menu.append_items(&[&status, &vip, &exit])
        .map_err(|e| format!("菜单构建: {e}"))?;
    let icon =
        Icon::from_rgba(flock_rgba(), ICON_SIZE, ICON_SIZE).map_err(|e| format!("图标: {e}"))?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Flock VPN：服务未运行")
        .with_icon(icon)
        .build()
        .map_err(|e| format!("{e}"))?;
    Ok(NativeTray { tray, status, vip })
}

impl NativeTray {
    /// 应用最新文案（**须在创建线程调用**）。
    fn apply(&self, texts: &MenuTexts) {
        self.status.set_text(&texts.status);
        self.vip.set_text(&texts.vip);
        // Windows szTip 上限 128 字符（含 NUL）——tooltip 文案远短于此。
        let _ = self.tray.set_tooltip(Some(texts.tooltip.as_str()));
    }
}

/// 菜单事件转发线程体：muda 全局通道 → tokio 侧（只读项无动作；仅「退出」转发）。
/// 线程随进程退出终结（recv 阻塞，无泄漏路径）。
fn forward_menu_events(exit_tx: tokio::sync::mpsc::UnboundedSender<()>) {
    loop {
        match MenuEvent::receiver().recv() {
            Ok(ev) if ev.id.0 == ITEM_EXIT => {
                let _ = exit_tx.send(());
            }
            Ok(_) => {}
            Err(_) => return,
        }
    }
}

/// 轮询/退出驱动（平台后端共用）：2s 拍轮询 → `refresh` 回调落位；「退出」→
/// [`super::request_exit`] 裁决——ExitTray 结束循环（StayRunning 继续：token 已重载）。
///
/// `pump_ended`（Windows 专用）：托盘泵线程终结（GetMessageW=-1 错误或 WM_QUIT
/// 收泵）⇒ 立即结束驱动循环——图标已失，不留「无图标僵尸进程」（评审项 8）。
/// macOS 侧持有永不发送的配对端（oneshot）——该臂不触发。
async fn drive(
    paths: &ControlPaths,
    mut refresh: impl FnMut(MenuTexts),
    mut exit_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
    mut pump_ended: tokio::sync::oneshot::Receiver<()>,
) {
    let mut tokens = super::TokenSource::new(paths.token_file.clone());
    let mut ticker = tokio::time::interval(POLL_INTERVAL); // 首拍立即——启动即有文案
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let texts = super::poll_once(paths, &mut tokens).await;
                refresh(texts);
            }
            _ = exit_rx.recv() => {
                match super::request_exit(paths, &mut tokens).await {
                    ExitDecision::ExitTray => break,
                    ExitDecision::StayRunning => continue,
                }
            }
            // Ok（泵发过信号）/Err（发送端 drop）均视为泵已终结——直接退出进程。
            _ = &mut pump_ended => {
                eprintln!("flock-client tray: 托盘泵已结束——进程收尾（不留无图标僵尸进程）");
                break;
            }
        }
    }
}

// ============================================================================
// Windows：托盘线程（GetMessageW 泵）+ 主线程 tokio 驱动
// ============================================================================

#[cfg(windows)]
pub fn run(paths: &ControlPaths) -> Result<(), String> {
    use std::sync::{Arc, Mutex};
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetMessageW, PostThreadMessageW, TranslateMessage, MSG, WM_APP, WM_QUIT,
    };
    /// 自定义线程消息：泵消费最新文案刷新菜单/tooltip（WM_APP 段应用自定义）。
    const WM_APP_TRAY_UPDATE: u32 = WM_APP + 1;

    let latest: Arc<Mutex<Option<MenuTexts>>> = Arc::new(Mutex::new(None));
    let pump_latest = latest.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<u32, String>>();
    // 泵终结信号（评审项 8）：泵线程 GetMessageW=-1（错误）或收泵退出时通知
    // drive 循环结束——图标已失的进程不得继续空转。
    let (pump_end_tx, pump_end_rx) = tokio::sync::oneshot::channel::<()>();
    let tray_thread = std::thread::Builder::new()
        .name("flock-tray".into())
        .spawn(move || {
            // pump_end_tx 随本线程 Drop——「线程意外终结」同样点亮 drive 的该臂。
            let _pump_end_tx = pump_end_tx;
            let native = match build_native_tray() {
                Ok(n) => n,
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            };
            // SAFETY：取本线程 id 供 PostThreadMessageW 唤醒（无参数副作用）。
            let tid = unsafe { GetCurrentThreadId() };
            if ready_tx.send(Ok(tid)).is_err() {
                return; // 主线程已放弃（接收端 drop）
            }
            // 泵循环（tray-icon 官方最小示例形态）：GetMessageW 阻塞等消息；
            // 更新消息消费最新文案；WM_QUIT（0）/错误（-1）结束——native Drop
            // 在本线程发生（Windows 侧 Drop 移除托盘图标）。-1 与正常收泵分别
            // 记日志（评审项 8：-1 不再无声吞掉）。
            // SAFETY：msg 为合法出参指针；句柄参数 NULL = 不按窗口过滤。
            unsafe {
                let mut msg: MSG = std::mem::zeroed();
                loop {
                    let got = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
                    if got == 0 {
                        break; // WM_QUIT（正常收泵）
                    }
                    if got == -1 {
                        eprintln!(
                            "flock-client tray: 消息泵错误（GetMessageW=-1）——图标失联，托盘收尾"
                        );
                        break;
                    }
                    if msg.message == WM_APP_TRAY_UPDATE {
                        if let Some(texts) = pump_latest.lock().expect("托盘状态锁中毒").take()
                        {
                            native.apply(&texts);
                        }
                        continue; // posted 线程消息无窗口句柄，无须 Translate/Dispatch
                    }
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        })
        .map_err(|e| format!("托盘线程创建失败: {e}"))?;

    let thread_id = match ready_rx.recv() {
        Ok(Ok(tid)) => tid,
        Ok(Err(e)) => {
            eprintln!(
                "flock-client tray: 托盘创建失败: {e}——无 GUI 会话或系统托盘不可用，\
                 托盘未启动（进程优雅退出）"
            );
            let _ = tray_thread.join();
            return Ok(());
        }
        Err(_) => {
            let _ = tray_thread.join();
            return Err("托盘线程未就绪（通道提前关闭）".into());
        }
    };

    // 菜单事件转发线程 + tokio 驱动（主线程）。
    let (exit_tx, exit_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    std::thread::Builder::new()
        .name("flock-tray-menu".into())
        .spawn(move || forward_menu_events(exit_tx))
        .map_err(|e| format!("菜单事件线程创建失败: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio 运行时创建失败: {e}"))?;
    let drive_latest = latest.clone();
    rt.block_on(drive(
        paths,
        move |texts| {
            *drive_latest.lock().expect("托盘状态锁中毒") = Some(texts);
            // SAFETY：线程消息投递（唤醒泵消费最新文案）；托盘线程已结束时失败可忽略。
            unsafe { PostThreadMessageW(thread_id, WM_APP_TRAY_UPDATE, 0, 0) };
        },
        exit_rx,
        pump_end_rx,
    ));

    // 收泵：WM_QUIT 令 GetMessageW 返回 0；join 确保图标移除后进程再退。
    // SAFETY：同上。
    unsafe { PostThreadMessageW(thread_id, WM_QUIT, 0, 0) };
    let _ = tray_thread.join();
    eprintln!("flock-client tray: 已退出");
    Ok(())
}

// ============================================================================
// macOS：主线程 NSApp 事件排空 + 独立轮询线程（编译级验证——无设备，真机清单留位）
// ============================================================================

#[cfg(target_os = "macos")]
pub fn run(paths: &ControlPaths) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    // 主线程先行：托盘/菜单创建（AppKit 主线程约束）——失败 ⇒ 优雅退出。
    let native = match build_native_tray() {
        Ok(n) => n,
        Err(e) => {
            eprintln!(
                "flock-client tray: 托盘创建失败: {e}——无 GUI 会话或系统托盘不可用，\
                 托盘未启动（进程优雅退出）"
            );
            return Ok(());
        }
    };
    let latest: Arc<Mutex<Option<MenuTexts>>> = Arc::new(Mutex::new(None));
    let quit = Arc::new(AtomicBool::new(false));

    // 轮询/IPC 线程（自有 tokio rt）：刷新写共享状态（主循环消费）；ExitTray 置退出。
    let poll_latest = latest.clone();
    let poll_quit = quit.clone();
    let poll_paths = paths.clone();
    let poll_thread = std::thread::Builder::new()
        .name("flock-tray-poll".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("flock-client tray: 轮询线程运行时创建失败: {e}——托盘退出");
                    poll_quit.store(true, Ordering::SeqCst);
                    return;
                }
            };
            let (exit_tx, exit_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
            // 菜单事件转发线程（NSApp sendEvent → muda 全局通道 → 本循环）。
            let _ = std::thread::Builder::new()
                .name("flock-tray-menu".into())
                .spawn(move || forward_menu_events(exit_tx));
            let poll_latest = poll_latest;
            // macOS 无独立泵线程（主线程 NSApp 循环即泵）——drive 的泵终结臂配
            // 永不发送的占位通道（tx 随本闭包持有至轮询线程结束，该臂不触发；
            // 线程终结时 tx Drop ⇒ rx Err 点亮 = 同样收尾，语义不劣化）。
            let (_pump_hold_tx, pump_end_rx) = tokio::sync::oneshot::channel::<()>();
            rt.block_on(drive(
                &poll_paths,
                move |texts| {
                    *poll_latest.lock().expect("托盘状态锁中毒") = Some(texts);
                },
                exit_rx,
                pump_end_rx,
            ));
            poll_quit.store(true, Ordering::SeqCst);
        })
        .map_err(|e| format!("轮询线程创建失败: {e}"))?;

    // 主线程：排空 NSApp 事件（菜单点击经 sendEvent 派发到 muda）+ 50ms 节律消费
    // 共享刷新/退出标志（tray-icon mac 后端要求主线程事件循环在跑）。
    use objc2_app_kit::{NSApplication, NSEventMask};
    use objc2_foundation::{NSDate, NSDefaultRunLoopMode};
    // MainThreadMarker::new() 在非主线程返回 None（托盘后端入口保证主线程调用）。
    let Some(mtm) = objc2::MainThreadMarker::new() else {
        return Err("托盘主循环不在主线程（内部错误）".into());
    };
    let app = NSApplication::sharedApplication(mtm);
    let past = NSDate::distantPast();
    // SAFETY：NSDefaultRunLoopMode 是 AppKit 常量全局（不可变 NSString）——objc2 将
    // 其暴露为 extern static，读取引用需 unsafe（惯例姿势）；只读、'static。
    let mode = unsafe { &NSDefaultRunLoopMode };
    while !quit.load(Ordering::SeqCst) {
        while let Some(event) = app.nextEventMatchingMask_untilDate_inMode_dequeue(
            NSEventMask::Any,
            Some(&past),
            mode,
            true,
        ) {
            app.sendEvent(&event);
            app.updateWindows();
        }
        if let Some(texts) = latest.lock().expect("托盘状态锁中毒").take() {
            native.apply(&texts);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = poll_thread.join();
    eprintln!("flock-client tray: 已退出");
    Ok(())
}
