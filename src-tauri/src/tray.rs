//! System tray and native Windows autostart.
//!
//! The tray keeps Varmlen running with no window: closing the window hides it
//! here (the VPN stays up), and Quit — the only path that tears the tunnel
//! down — lives in the tray menu. Autostart is a `~/.config/autostart` entry we
//! store in the current user's Run registry key.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use tauri::AppHandle;

#[cfg(desktop)]
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
#[cfg(desktop)]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
#[cfg(desktop)]
use tauri::{Emitter, Manager};

// --- system tray (desktop only) --------------------------------------------

/// Build the tray icon + menu. Left-click shows the window; the menu has the
/// connect/disconnect toggle, Open, and Quit.
#[cfg(desktop)]
pub fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let toggle = MenuItem::with_id(app, "toggle", "Connect / Disconnect", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Open Varmlen", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&toggle, &sep, &show, &quit])?;

    let mut builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("Varmlen")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "toggle" => {
                let _ = app.emit("tray://toggle", ());
            }
            "show" => show_main(app),
            "quit" => quit_app(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

/// Show + focus the main window (from the tray).
#[cfg(desktop)]
pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Exit the GUI. VarmlenService deliberately keeps a healthy 24/7 tunnel.
#[cfg(desktop)]
pub(crate) fn quit_app(app: &AppHandle) {
    app.exit(0);
}

/// True when launched from the autostart entry's `--minimized` exec.
#[cfg(desktop)]
pub fn launched_minimized() -> bool {
    std::env::args().any(|a| a == "--minimized")
}

// --- close-to-tray preference (shared) -------------------------------------

/// Whether closing the window hides to the tray (true) or fully quits (false).
static CLOSE_TO_TRAY: AtomicBool = AtomicBool::new(true);

#[cfg(desktop)]
pub fn close_to_tray() -> bool {
    CLOSE_TO_TRAY.load(Ordering::Relaxed)
}

#[tauri::command]
pub fn set_close_to_tray(enabled: bool) {
    CLOSE_TO_TRAY.store(enabled, Ordering::Relaxed);
}

/// Reflect the connection status in the tray tooltip (desktop); no-op on mobile.
#[tauri::command]
pub fn set_tray_status(app: AppHandle, status_label: String) {
    #[cfg(desktop)]
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(format!("Varmlen — {status_label}")));
    }
    #[cfg(not(desktop))]
    let _ = (app, status_label);
}

// --- native Windows autostart ----------------------------------------------

#[derive(Serialize)]
pub struct AutostartStatus {
    pub enabled: bool,
    pub minimized: bool,
}

#[tauri::command]
pub fn autostart_status() -> AutostartStatus {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let run = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")
            .ok();
        match run.and_then(|key| key.get_value::<String, _>("Varmlen").ok()) {
            Some(c) => AutostartStatus {
                enabled: true,
                minimized: c.contains("--minimized"),
            },
            None => AutostartStatus {
                enabled: false,
                minimized: false,
            },
        }
    }
    #[cfg(not(windows))]
    AutostartStatus {
        enabled: false,
        minimized: false,
    }
}

#[tauri::command]
pub fn set_autostart(enabled: bool, minimized: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        use winreg::{enums::HKEY_CURRENT_USER, RegKey};
        let (run, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")
            .map_err(|error| format!("open Windows startup registry: {error}"))?;
        if !enabled {
            let _ = run.delete_value("Varmlen");
            return Ok(());
        }
        let exe = std::env::current_exe().map_err(|e| format!("current exe: {e}"))?;
        let command = if minimized {
            format!("\"{}\" --minimized", exe.display())
        } else {
            format!("\"{}\"", exe.display())
        };
        run.set_value("Varmlen", &command)
            .map_err(|error| format!("write Windows startup registry: {error}"))
    }
    #[cfg(not(windows))]
    {
        let _ = (enabled, minimized);
        Ok(())
    }
}
