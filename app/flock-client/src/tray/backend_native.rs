//! Windows/macOS tray backend (`tray-icon`'s built-in menu — muda consumed
//! via the `tray_icon::menu` re-export; docs/design.md §7-M6 phase two).
//!
//! Selection and the minimal pump shape (no winit/tauri/egui GUI stack —
//! this process creates no window at all):
//! - tray-icon supports **windowless** use (the native tray backends on
//!   Windows/macOS + muda native menus), but event delivery depends on the
//!   owning thread's **message pump/event loop** — each platform gets a
//!   minimal viable pump:
//! - **Windows**: tray/menu thread affinity (Win32 message-driven) — a
//!   dedicated thread runs the `GetMessageW` pump (tray-icon's official
//!   minimal example shape); the main thread's polling loop wakes the pump
//!   via `PostThreadMessageW` (a custom `WM_APP` message) to consume the
//!   latest texts; "Quit" collects the pump via `WM_QUIT`, and tray Drop
//!   removes the icon;
//! - **macOS**: AppKit requires the tray/NSMenu on the **main thread** with
//!   the event loop running — the main thread manually drains NSApp events
//!   (`nextEvent…/sendEvent/updateWindows`, a 50ms cadence consuming the
//!   shared refresh) while polling/IPC run on a separate thread (with their
//!   own tokio rt). **No macOS device available here: compile-level
//!   verification + the real-machine checklist placeholder
//!   (docs/manual/service-install.md §tray real-machine checklist).**
//!
//! The platform difference is only "where the pump runs and how it is
//! woken"; menu construction (three items: status/VIP/quit — localized via
//! [`crate::lang`]) and the polling driver ([`drive`]) are shared.
//! Tray-creation failure (no GUI session, etc.) ⇒ print a clear log + the
//! process exits gracefully (exit code 0, no panic).

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use super::icon::{flock_rgba, ICON_SIZE};
use super::{ControlPaths, ExitDecision, MenuTexts, POLL_INTERVAL};
use crate::lang::{Key, Lang};

/// Menu item ids (muda `MenuId` strings; "Quit" matches MenuEvent, the two
/// others are read-only display items).
const ITEM_STATUS: &str = "flock-status";
const ITEM_VIP: &str = "flock-vip";
const ITEM_EXIT: &str = "flock-exit";

/// Tray handle (status/VIP read-only items + tooltip; held by the creating
/// thread — both the Win32 menu and NSMenu are thread-affine, all mutations
/// go through the owning thread's pump/loop).
struct NativeTray {
    tray: TrayIcon,
    status: MenuItem,
    vip: MenuItem,
}

/// Build the tray: a three-item menu ("Connection" and "VPN IP" disabled
/// read-only items — greyed-out is the customary read-only display shape
/// across platforms; "Quit" the action item) + the embedded icon + tooltip.
///
/// Errors are uniformly `String` (the three menu/icon/tray error families
/// only feed the log before a graceful exit; no per-class handling).
fn build_native_tray(lang: Lang) -> Result<NativeTray, String> {
    let down = lang.tr(Key::TrayServiceDown);
    let status = MenuItem::with_id(
        ITEM_STATUS,
        lang.trf(Key::TrayStatusLine, &[&down]),
        false,
        None,
    );
    let vip = MenuItem::with_id(ITEM_VIP, lang.trf(Key::TrayVipLine, &[&"—"]), false, None);
    let exit = MenuItem::with_id(ITEM_EXIT, lang.tr(Key::TrayQuit), true, None);
    let menu = Menu::new();
    menu.append_items(&[&status, &vip, &exit])
        .map_err(|e| format!("menu build: {e}"))?;
    let icon =
        Icon::from_rgba(flock_rgba(), ICON_SIZE, ICON_SIZE).map_err(|e| format!("icon: {e}"))?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(lang.trf(Key::TrayTooltip, &[&down, &"—"]))
        .with_icon(icon)
        .build()
        .map_err(|e| format!("{e}"))?;
    Ok(NativeTray { tray, status, vip })
}

impl NativeTray {
    /// Apply the latest texts (**must be called on the creating thread**).
    fn apply(&self, texts: &MenuTexts) {
        self.status.set_text(&texts.status);
        self.vip.set_text(&texts.vip);
        // Windows szTip caps at 128 chars (including NUL) — the tooltip text
        // is far below that.
        let _ = self.tray.set_tooltip(Some(texts.tooltip.as_str()));
    }
}

/// Menu-event forwarder thread body: muda's global channel → the tokio side
/// (read-only items have no action; only "Quit" is forwarded). The thread
/// ends with the process (recv blocks; no leak path).
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

/// Polling/exit driver (shared by platform backends): poll on the 2s beat →
/// the `refresh` callback lands the texts; "Quit" → [`super::request_exit`]
/// verdict — ExitTray ends the loop (StayRunning continues: the token was
/// reloaded).
///
/// `pump_ended` (Windows-specific): the tray pump thread terminated
/// (GetMessageW=-1 error or a WM_QUIT collection) ⇒ end the drive loop
/// immediately — the icon is gone; leave no "iconless zombie process"
/// (review item 8). The macOS side holds a never-sending paired end
/// (oneshot) — that arm never fires.
async fn drive(
    paths: &ControlPaths,
    lang: Lang,
    mut refresh: impl FnMut(MenuTexts),
    mut exit_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
    mut pump_ended: tokio::sync::oneshot::Receiver<()>,
) {
    let mut tokens = super::TokenSource::new(paths.token_file.clone());
    let mut ticker = tokio::time::interval(POLL_INTERVAL); // first tick immediate — texts right at startup
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let texts = super::poll_once(paths, &mut tokens, lang).await;
                refresh(texts);
            }
            _ = exit_rx.recv() => {
                match super::request_exit(paths, &mut tokens).await {
                    ExitDecision::ExitTray => break,
                    ExitDecision::StayRunning => continue,
                }
            }
            // Ok (the pump signalled) / Err (sender dropped) both count as
            // the pump terminated — exit the process directly.
            _ = &mut pump_ended => {
                eprintln!(
                    "flock-client tray: tray pump ended — wrapping up the process (no iconless \
                     zombie)"
                );
                break;
            }
        }
    }
}

// ============================================================================
// Windows: tray thread (GetMessageW pump) + main-thread tokio driver
// ============================================================================

#[cfg(windows)]
pub fn run(paths: &ControlPaths, lang: Lang) -> Result<(), String> {
    use std::sync::{Arc, Mutex};
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetMessageW, PostThreadMessageW, TranslateMessage, MSG, WM_APP, WM_QUIT,
    };
    /// Custom thread message: the pump consumes the latest texts and
    /// refreshes the menu/tooltip (the WM_APP range is application-defined).
    const WM_APP_TRAY_UPDATE: u32 = WM_APP + 1;

    let latest: Arc<Mutex<Option<MenuTexts>>> = Arc::new(Mutex::new(None));
    let pump_latest = latest.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<u32, String>>();
    // Pump-termination signal (review item 8): the pump thread notifies the
    // drive loop to end when GetMessageW=-1 (error) or it collects a quit —
    // a process whose icon is gone must not keep spinning.
    let (pump_end_tx, pump_end_rx) = tokio::sync::oneshot::channel::<()>();
    let tray_thread = std::thread::Builder::new()
        .name("flock-tray".into())
        .spawn(move || {
            // pump_end_tx Drops with this thread — "thread died unexpectedly"
            // also lights that arm of drive.
            let _pump_end_tx = pump_end_tx;
            let native = match build_native_tray(lang) {
                Ok(n) => n,
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            };
            // SAFETY: take this thread's id for PostThreadMessageW wake-ups
            // (no parameter side effects).
            let tid = unsafe { GetCurrentThreadId() };
            if ready_tx.send(Ok(tid)).is_err() {
                return; // main thread gave up (receiver dropped)
            }
            // Pump loop (tray-icon's official minimal example shape):
            // GetMessageW blocks awaiting messages; update messages consume
            // the latest texts; WM_QUIT (0)/error (-1) end it — the native
            // Drop happens on this thread (on Windows, Drop removes the tray
            // icon). -1 and a normal quit are logged separately (review
            // item 8: -1 is no longer swallowed silently).
            // SAFETY: msg is a valid out-param pointer; a NULL handle
            // argument = no window filtering.
            unsafe {
                let mut msg: MSG = std::mem::zeroed();
                loop {
                    let got = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
                    if got == 0 {
                        break; // WM_QUIT (normal pump collection)
                    }
                    if got == -1 {
                        eprintln!(
                            "flock-client tray: message pump error (GetMessageW=-1) — icon lost, \
                             wrapping up the tray"
                        );
                        break;
                    }
                    if msg.message == WM_APP_TRAY_UPDATE {
                        if let Some(texts) =
                            pump_latest.lock().expect("tray state lock poisoned").take()
                        {
                            native.apply(&texts);
                        }
                        continue; // posted thread messages carry no window handle; no Translate/Dispatch needed
                    }
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        })
        .map_err(|e| format!("tray thread creation failed: {e}"))?;

    let thread_id = match ready_rx.recv() {
        Ok(Ok(tid)) => tid,
        Ok(Err(e)) => {
            eprintln!(
                "flock-client tray: tray creation failed: {e} — no GUI session or the system tray \
                 is unavailable, tray not started (process exits gracefully)"
            );
            let _ = tray_thread.join();
            return Ok(());
        }
        Err(_) => {
            let _ = tray_thread.join();
            return Err("tray thread not ready (channel closed early)".into());
        }
    };

    // Menu-event forwarder thread + tokio driver (main thread).
    let (exit_tx, exit_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    std::thread::Builder::new()
        .name("flock-tray-menu".into())
        .spawn(move || forward_menu_events(exit_tx))
        .map_err(|e| format!("menu event thread creation failed: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime creation failed: {e}"))?;
    let drive_latest = latest.clone();
    rt.block_on(drive(
        paths,
        lang,
        move |texts| {
            *drive_latest.lock().expect("tray state lock poisoned") = Some(texts);
            // SAFETY: thread-message post (wakes the pump to consume the
            // latest texts); failure is ignorable once the tray thread has
            // ended.
            unsafe { PostThreadMessageW(thread_id, WM_APP_TRAY_UPDATE, 0, 0) };
        },
        exit_rx,
        pump_end_rx,
    ));

    // Collect the pump: WM_QUIT makes GetMessageW return 0; the join ensures
    // the icon is removed before the process exits.
    // SAFETY: same as above.
    unsafe { PostThreadMessageW(thread_id, WM_QUIT, 0, 0) };
    let _ = tray_thread.join();
    eprintln!("flock-client tray: exited");
    Ok(())
}

// ============================================================================
// macOS: main-thread NSApp event draining + a separate polling thread
// (compile-level verification — no device, real-machine checklist
// placeholder)
// ============================================================================

#[cfg(target_os = "macos")]
pub fn run(paths: &ControlPaths, lang: Lang) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    // Main thread first: tray/menu creation (the AppKit main-thread
    // constraint) — failure ⇒ graceful exit.
    let native = match build_native_tray(lang) {
        Ok(n) => n,
        Err(e) => {
            eprintln!(
                "flock-client tray: tray creation failed: {e} — no GUI session or the system tray \
                 is unavailable, tray not started (process exits gracefully)"
            );
            return Ok(());
        }
    };
    let latest: Arc<Mutex<Option<MenuTexts>>> = Arc::new(Mutex::new(None));
    let quit = Arc::new(AtomicBool::new(false));

    // Polling/IPC thread (its own tokio rt): refreshes write the shared
    // state (consumed by the main loop); ExitTray sets the quit flag.
    let poll_latest = latest.clone();
    let poll_quit = quit.clone();
    let poll_paths = paths.clone();
    let poll_lang = lang;
    let poll_thread = std::thread::Builder::new()
        .name("flock-tray-poll".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!(
                        "flock-client tray: polling thread runtime creation failed: {e} — tray \
                         exiting"
                    );
                    poll_quit.store(true, Ordering::SeqCst);
                    return;
                }
            };
            let (exit_tx, exit_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
            // Menu-event forwarder thread (NSApp sendEvent → muda global
            // channel → this loop).
            let _ = std::thread::Builder::new()
                .name("flock-tray-menu".into())
                .spawn(move || forward_menu_events(exit_tx));
            let poll_latest = poll_latest;
            // macOS has no separate pump thread (the main-thread NSApp loop
            // is the pump) — drive's pump-termination arm gets a
            // never-sending placeholder channel (the tx is held by this
            // closure until the polling thread ends, so the arm never fires;
            // when the thread ends, tx Drop ⇒ rx Err lights it = the same
            // wrap-up, no semantic downgrade).
            let (_pump_hold_tx, pump_end_rx) = tokio::sync::oneshot::channel::<()>();
            rt.block_on(drive(
                &poll_paths,
                poll_lang,
                move |texts| {
                    *poll_latest.lock().expect("tray state lock poisoned") = Some(texts);
                },
                exit_rx,
                pump_end_rx,
            ));
            poll_quit.store(true, Ordering::SeqCst);
        })
        .map_err(|e| format!("polling thread creation failed: {e}"))?;

    // Main thread: drain NSApp events (menu clicks dispatch to muda via
    // sendEvent) + consume the shared refresh/quit flag on a 50ms cadence
    // (the tray-icon mac backend requires the main-thread event loop to be
    // running).
    use objc2_app_kit::{NSApplication, NSEventMask};
    use objc2_foundation::{NSDate, NSDefaultRunLoopMode};
    // MainThreadMarker::new() returns None off the main thread (the tray
    // backend entry point guarantees a main-thread call).
    let Some(mtm) = objc2::MainThreadMarker::new() else {
        return Err("tray main loop not on the main thread (internal error)".into());
    };
    let app = NSApplication::sharedApplication(mtm);
    let past = NSDate::distantPast();
    // SAFETY: NSDefaultRunLoopMode is an immutable AppKit global constant
    // (an immutable NSString) — objc2 exposes it as an extern static, and
    // reading the reference requires unsafe (the customary form);
    // read-only, 'static.
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
        if let Some(texts) = latest.lock().expect("tray state lock poisoned").take() {
            native.apply(&texts);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = poll_thread.join();
    eprintln!("flock-client tray: exited");
    Ok(())
}
