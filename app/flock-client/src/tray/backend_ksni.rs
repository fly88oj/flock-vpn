//! Linux tray backend (`ksni`: pure-Rust DBus StatusNotifierItem — **zero
//! GTK/libappindicator system dependencies**, in line with the project
//! discipline that headless server images carry no GUI dependencies; the
//! zbus backend rides the tokio feature, in the same domain as the existing
//! runtime).
//!
//! Shape: ksni as a direct async service (no window created, no GUI
//! toolchain pulled in) — the `TrayService` is spawned onto the session
//! DBus; menu/icon/tooltip are built on demand from host queries via the
//! `Tray` trait (**the menu is rebuilt from the latest state every time it
//! is opened** — ksni semantics naturally satisfy "refresh on a 2s poll";
//! the tooltip property is refreshed proactively via `update`). A tray host
//! (SNI watcher) that becomes ready later than autostart is not treated as
//! fatal (`assume_sni_available(true)` + `watcher_offline` keeps waiting);
//! DBus itself unreachable ⇒ graceful exit (the probe already ran up front;
//! this is the backstop).
//!
//! Menu labels (status/VIP/quit) render through the language pack passed by
//! the caller.

use ksni::menu::StandardItem;
use ksni::{Icon as KsniIcon, MenuItem as KsniMenuItem, ToolTip, TrayMethods};

use super::icon::{flock_rgba, rgba_to_argb32_network_order, ICON_SIZE};
use super::{menu_texts, ControlPaths, ExitDecision, MenuTexts, POLL_INTERVAL};
use crate::lang::{Key, Lang};

/// `flock-client tray` Linux backend entry point.
pub fn run(paths: &ControlPaths, lang: Lang) -> Result<(), String> {
    // GUI-session pre-check (GUI-less host: graceful exit with a clear log,
    // exit code 0).
    if !super::linux_gui_session_present() {
        eprintln!(
            "flock-client tray: no GUI session detected (no DISPLAY/WAYLAND_DISPLAY or no session \
             DBus), tray not started"
        );
        return Ok(());
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime creation failed: {e}"))?;
    rt.block_on(async move {
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let tray = FlockTray {
            lang,
            texts: menu_texts(None, lang),
            exit_tx,
        };
        // assume_sni_available(true): the desktop-environment tray host may
        // become ready later than autostart (login race) — treat "watcher
        // not registered / no host" as a soft error to wait out, while DBus
        // hard errors still fail directly.
        let handle = match tray.assume_sni_available(true).spawn().await {
            Ok(h) => h,
            Err(e) => {
                eprintln!(
                    "flock-client tray: tray registration failed (DBus unavailable): {e} — tray \
                     not started, exiting gracefully"
                );
                return Ok(());
            }
        };
        eprintln!("flock-client tray: registered (StatusNotifierItem)");

        let mut tokens = super::TokenSource::new(paths.token_file.clone());
        let mut ticker = tokio::time::interval(POLL_INTERVAL); // first tick immediate
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let texts = super::poll_once(paths, &mut tokens, lang).await;
                    // update: mutate tray state and notify the host (tooltip
                    // property refresh; menu rebuilt while open).
                    let _ = handle.update(move |t| t.texts = texts).await;
                }
                _ = exit_rx.recv() => {
                    match super::request_exit(paths, &mut tokens).await {
                        ExitDecision::ExitTray => {
                            handle.shutdown().await;
                            break;
                        }
                        ExitDecision::StayRunning => continue,
                    }
                }
            }
        }
        eprintln!("flock-client tray: exited");
        Ok(())
    })
}

/// ksni tray implementation: menu/tooltip built on demand from host queries
/// (reads `texts` — written by the polling side via `Handle::update`, which
/// also triggers the refresh).
struct FlockTray {
    lang: Lang,
    texts: MenuTexts,
    /// The "Quit" action → drives the loop (the activate callback runs on a
    /// DBus dispatch thread; non-blocking forward).
    exit_tx: tokio::sync::mpsc::UnboundedSender<()>,
}

impl ksni::Tray for FlockTray {
    fn id(&self) -> String {
        "flock-client".into()
    }

    fn title(&self) -> String {
        "Flock VPN".into()
    }

    fn icon_pixmap(&self) -> Vec<KsniIcon> {
        vec![KsniIcon {
            width: ICON_SIZE as i32,
            height: ICON_SIZE as i32,
            // SNI contract: ARGB32, network byte order.
            data: rgba_to_argb32_network_order(&flock_rgba()),
        }]
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_name: String::new(),
            icon_pixmap: self.icon_pixmap(),
            title: "Flock VPN".into(),
            description: self.texts.tooltip.clone(),
        }
    }

    fn menu(&self) -> Vec<KsniMenuItem<FlockTray>> {
        vec![
            // "Connection" and "VPN IP": dynamic read-only items
            // (enabled=false — the customary greyed-out read-only shape).
            KsniMenuItem::Standard(StandardItem {
                label: self.texts.status.clone(),
                enabled: false,
                ..Default::default()
            }),
            KsniMenuItem::Standard(StandardItem {
                label: self.texts.vip.clone(),
                enabled: false,
                ..Default::default()
            }),
            KsniMenuItem::Separator,
            KsniMenuItem::Standard(StandardItem {
                label: self.lang.tr(Key::TrayQuit).into(),
                activate: Box::new(move |t: &mut Self| {
                    let _ = t.exit_tx.send(());
                }),
                ..Default::default()
            }),
        ]
    }

    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        eprintln!(
            "flock-client tray: tray host temporarily unavailable ({reason:?}) — staying up, \
             waiting for it to return"
        );
        true
    }
}
