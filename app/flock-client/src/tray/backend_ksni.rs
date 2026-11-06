//! Linux 托盘后端（`ksni`：纯 Rust 的 DBus StatusNotifierItem——**零 GTK/
//! libappindicator 系统依赖**，与「无头服务器镜像不拖 GUI 依赖」的项目纪律一致；
//! zbus 后端走 tokio 特性，与既有运行时同域）。
//!
//! 形态：ksni 直接 async 服务（不建窗口、不引 GUI 工具链）——`TrayService` spawn 到
//! 会话 DBus；菜单/图标/tooltip 由 `Tray` trait 按宿主询问即时构建（**菜单每次打开
//! 按最新状态重建**——ksni 语义天然满足「2s 轮询刷新」；tooltip 属性经 `update`
//! 主动通知刷新）。托盘宿主（SNI watcher）晚于自启就绪不判死
//! （`assume_sni_available(true)` + `watcher_offline` 保持等待）；DBus 本身连不上
//! ⇒ 优雅退出（探测已前置，此为兜底）。

use ksni::menu::StandardItem;
use ksni::{Icon as KsniIcon, MenuItem as KsniMenuItem, ToolTip, TrayMethods};

use super::icon::{flock_rgba, rgba_to_argb32_network_order, ICON_SIZE};
use super::{menu_texts, ExitDecision, MenuTexts, ControlPaths, POLL_INTERVAL};

/// `flock-client tray` Linux 后端入口。
pub fn run(paths: &ControlPaths) -> Result<(), String> {
    // GUI 会话前置判定（无 GUI 主机：优雅退出并留清晰日志，退出码 0）。
    if !super::linux_gui_session_present() {
        eprintln!(
            "flock-client tray: 未检测到 GUI 会话（无 DISPLAY/WAYLAND_DISPLAY 或无会话 \
             DBus），托盘未启动"
        );
        return Ok(());
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio 运行时创建失败: {e}"))?;
    rt.block_on(async move {
        let (exit_tx, mut exit_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let tray = FlockTray {
            texts: menu_texts(None),
            exit_tx,
        };
        // assume_sni_available(true)：桌面环境托盘宿主可能晚于自启动就绪（登录竞速）
        // ——把「watcher 未注册/无宿主」当软错误等待，DBus 硬错误仍直接失败。
        let handle = match tray.assume_sni_available(true).spawn().await {
            Ok(h) => h,
            Err(e) => {
                eprintln!(
                    "flock-client tray: 托盘注册失败（DBus 不可用）: {e}——托盘未启动，\
                     进程优雅退出"
                );
                return Ok(());
            }
        };
        eprintln!("flock-client tray: 托盘已注册（StatusNotifierItem）");

        let mut tokens = super::TokenSource::new(paths.token_file.clone());
        let mut ticker = tokio::time::interval(POLL_INTERVAL); // 首拍立即
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let texts = super::poll_once(paths, &mut tokens).await;
                    // update：改托盘状态并通知宿主（tooltip 属性刷新；菜单开时重建）。
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
        eprintln!("flock-client tray: 已退出");
        Ok(())
    })
}

/// ksni 托盘实现：菜单/tooltip 按宿主询问即时构建（读 `texts`——轮询侧经
/// `Handle::update` 写入并触发刷新）。
struct FlockTray {
    texts: MenuTexts,
    /// 「退出」动作 → 驱动循环（activate 回调在 DBus 派发线程，非阻塞转发）。
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
            // SNI 契约：ARGB32、network byte order。
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
            // 「连接状态」「VPN IP」：动态只读项（enabled=false——置灰只读惯用形态）。
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
                label: "退出".into(),
                activate: Box::new(move |t: &mut Self| {
                    let _ = t.exit_tx.send(());
                }),
                ..Default::default()
            }),
        ]
    }

    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        eprintln!(
            "flock-client tray: 托盘宿主暂不可用（{reason:?}）——保持运行等待其恢复"
        );
        true
    }
}
