//! System tray and background mode.
//!
//! * A native tray menu, so it works everywhere: Linux (AppIndicator/StatusNotifier, which
//!   delivers no click events, only menus), Windows and macOS.
//! * Left click on Windows/macOS toggles the main window; right click opens the menu.
//! * Closing the main window keeps SSHBool running in the tray (configurable), with a one-time
//!   notification so the user knows where it went.
//! * Optional launch at login, which starts hidden in the tray (`--minimized`).
//! * The menu refreshes itself from live state (active sessions, workspaces, settings).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use infrastructure::AppState;
use serde_json::json;
use tauri::menu::{
    CheckMenuItemBuilder, Menu, MenuBuilder, MenuEvent, MenuItemBuilder, PredefinedMenuItem,
    SubmenuBuilder,
};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_notification::NotificationExt;

pub const TRAY_ID: &str = "sshbool-tray";
/// Passed by the login item so the app starts hidden in the tray.
pub const MINIMIZED_ARG: &str = "--minimized";
const MAIN: &str = "main";

const KEY_CLOSE_TO_TRAY: &str = "app.closeToTray";
const KEY_HINT_SHOWN: &str = "app.trayHintShown";

/// Events sent to the main window when a tray item needs the UI.
pub mod events {
    pub const FOCUS_SESSION: &str = "tray://focus-session";
    pub const NEW_CONNECTION: &str = "tray://new-connection";
    pub const OPEN_SETTINGS: &str = "tray://open-settings";
}

const REFRESH_EVERY: Duration = Duration::from_secs(3);
const MAX_LABEL: usize = 48;

#[derive(Clone, Debug, Default, PartialEq)]
struct TraySession {
    pane_id: String,
    host_id: String,
    label: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Snapshot {
    sessions: Vec<TraySession>,
    workspaces: Vec<(String, String)>,
    window_visible: bool,
    close_to_tray: bool,
    launch_at_login: bool,
}

/// Background-mode state, managed by Tauri.
pub struct Background {
    close_to_tray: AtomicBool,
    hint_shown: AtomicBool,
    quitting: AtomicBool,
    /// False when the desktop offers no tray (e.g. AppIndicator library missing).
    tray_ok: AtomicBool,
    last: Mutex<Option<Snapshot>>,
    /// Work the UI reports as unsafe to interrupt (e.g. "update"), checked before quitting.
    busy: Mutex<std::collections::BTreeSet<String>>,
}

impl Default for Background {
    fn default() -> Self {
        Self {
            // Matches the historical behaviour: closing the window hides it.
            close_to_tray: AtomicBool::new(true),
            hint_shown: AtomicBool::new(false),
            quitting: AtomicBool::new(false),
            tray_ok: AtomicBool::new(false),
            last: Mutex::new(None),
            busy: Mutex::new(Default::default()),
        }
    }
}

impl Background {
    pub fn close_to_tray(&self) -> bool {
        self.close_to_tray.load(Ordering::Relaxed)
    }

    pub fn set_busy(&self, reason: &str, busy: bool) {
        let mut set = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        if busy {
            set.insert(reason.to_string());
        } else {
            set.remove(reason);
        }
    }

    fn is_busy(&self, reason: &str) -> bool {
        self.busy
            .lock()
            .map(|s| s.contains(reason))
            .unwrap_or(false)
    }
}

pub fn started_minimized() -> bool {
    std::env::args().any(|a| a == MINIMIZED_ARG)
}

// ── settings ─────────────────────────────────────────────────────────

async fn read_bool(app: &AppHandle, key: &str) -> Option<bool> {
    let state = app.try_state::<Arc<AppState>>()?;
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(state.vault.pool())
        .await
        .ok()?;
    row.and_then(|(v,)| serde_json::from_str::<bool>(&v).ok())
}

async fn write_bool(app: &AppHandle, key: &str, value: bool) -> Result<(), String> {
    let state = app
        .try_state::<Arc<AppState>>()
        .ok_or("app state not ready")?;
    sqlx::query("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)")
        .bind(key)
        .bind(value.to_string())
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(state.vault.pool())
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn load_settings(app: &AppHandle) {
    let bg = app.state::<Background>();
    if let Some(v) = read_bool(app, KEY_CLOSE_TO_TRAY).await {
        bg.close_to_tray.store(v, Ordering::Relaxed);
    }
    if let Some(v) = read_bool(app, KEY_HINT_SHOWN).await {
        bg.hint_shown.store(v, Ordering::Relaxed);
    }
}

pub async fn set_close_to_tray(app: &AppHandle, value: bool) -> Result<(), String> {
    write_bool(app, KEY_CLOSE_TO_TRAY, value).await?;
    app.state::<Background>()
        .close_to_tray
        .store(value, Ordering::Relaxed);
    refresh(app, true).await;
    Ok(())
}

pub fn launch_at_login(app: &AppHandle) -> bool {
    app.autolaunch().is_enabled().unwrap_or(false)
}

pub async fn set_launch_at_login(app: &AppHandle, value: bool) -> Result<(), String> {
    let manager = app.autolaunch();
    if value {
        manager.enable().map_err(|e| e.to_string())?;
    } else {
        manager.disable().map_err(|e| e.to_string())?;
    }
    refresh(app, true).await;
    Ok(())
}

// ── window helpers ───────────────────────────────────────────────────

fn main_visible(app: &AppHandle) -> bool {
    app.get_webview_window(MAIN)
        .map(|w| w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(false))
        .unwrap_or(false)
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(MAIN) {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
    spawn_refresh(app);
}

pub fn hide_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(MAIN) {
        let _ = w.hide();
    }
    spawn_refresh(app);
}

fn toggle_main(app: &AppHandle) {
    if main_visible(app) {
        hide_main(app);
    } else {
        show_main(app);
    }
}

/// Called from `on_window_event` for the main window's close button.
pub fn on_main_close_requested(app: &AppHandle, api: &tauri::CloseRequestApi) {
    let Some(bg) = app.try_state::<Background>() else {
        // Tray not set up yet: keep the historical hide-on-close behaviour.
        api.prevent_close();
        if let Some(w) = app.get_webview_window(MAIN) {
            let _ = w.hide();
        }
        return;
    };
    if bg.quitting.load(Ordering::Relaxed) {
        return;
    }
    api.prevent_close();
    if bg.close_to_tray() && !bg.tray_ok.load(Ordering::Relaxed) {
        // No tray to come back from: keep running but stay reachable from the taskbar.
        if let Some(w) = app.get_webview_window(MAIN) {
            let _ = w.minimize();
        }
    } else if bg.close_to_tray() {
        hide_main(app);
        show_background_hint_once(app);
    } else {
        request_quit(app);
    }
}

fn show_background_hint_once(app: &AppHandle) {
    let bg = app.state::<Background>();
    if bg.hint_shown.swap(true, Ordering::Relaxed) {
        return;
    }
    let _ = app
        .notification()
        .builder()
        .title("SSHBool is still running")
        .body(
            "Your sessions stay connected in the background. Use the tray icon to reopen \
             SSHBool, or choose Quit from its menu.",
        )
        .show();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = write_bool(&app, KEY_HINT_SHOWN, true).await;
    });
}

/// Quit, asking first when sessions would be dropped.
pub fn request_quit(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let (sessions, transfers) = match app.try_state::<Arc<AppState>>() {
            Some(state) => {
                let transfers: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM transfer_jobs WHERE status IN ('active', 'queued')",
                )
                .fetch_one(state.vault.pool())
                .await
                .unwrap_or(0);
                (state.connections.sessions_list().await.len(), transfers)
            }
            None => (0, 0),
        };
        let updating = app
            .try_state::<Background>()
            .map(|bg| bg.is_busy("update"))
            .unwrap_or(false);

        let Some(message) = quit_warning(sessions, transfers, updating) else {
            quit_now(&app);
            return;
        };
        // Bring the window up so the warning is not hidden behind other apps.
        show_main(&app);
        let handle = app.clone();
        app.dialog()
            .message(message)
            .title("Quit SSHBool")
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Quit".into(),
                "Cancel".into(),
            ))
            .show(move |confirmed| {
                if confirmed {
                    quit_now(&handle);
                }
            });
    });
}

/// Text for the "really quit?" dialog, or `None` when nothing would be interrupted.
fn quit_warning(sessions: usize, transfers: i64, updating: bool) -> Option<String> {
    let mut lines = Vec::new();
    if updating {
        lines.push("• An update is still downloading or installing.".to_string());
    }
    match sessions {
        0 => {}
        1 => lines.push("• 1 active session will be disconnected.".to_string()),
        n => lines.push(format!("• {n} active sessions will be disconnected.")),
    }
    match transfers {
        0 => {}
        1 => lines.push("• 1 file transfer will be stopped.".to_string()),
        n => lines.push(format!("• {n} file transfers will be stopped.")),
    }
    if lines.is_empty() {
        return None;
    }
    Some(format!("{}\n\nQuit SSHBool anyway?", lines.join("\n")))
}

fn quit_now(app: &AppHandle) {
    if let Some(bg) = app.try_state::<Background>() {
        bg.quitting.store(true, Ordering::Relaxed);
    }
    app.exit(0);
}

// ── menu ─────────────────────────────────────────────────────────────

fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_LABEL {
        return s.to_string();
    }
    let mut out: String = s.chars().take(MAX_LABEL - 1).collect();
    out.push('…');
    out
}

async fn snapshot(app: &AppHandle) -> Snapshot {
    let bg = app.state::<Background>();
    let mut snap = Snapshot {
        window_visible: main_visible(app),
        close_to_tray: bg.close_to_tray(),
        launch_at_login: launch_at_login(app),
        ..Default::default()
    };
    let Some(state) = app.try_state::<Arc<AppState>>() else {
        return snap;
    };
    let pool = state.vault.pool();

    for (pane_id, _session_id, host_id, title) in state.connections.sessions_list().await {
        let host_label: Option<(String,)> = sqlx::query_as("SELECT label FROM hosts WHERE id = ?")
            .bind(&host_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
        let label = match host_label {
            Some((l,)) if !title.is_empty() && title != l => format!("{l} — {title}"),
            Some((l,)) => l,
            None if !title.is_empty() => title,
            None => "SSH session".into(),
        };
        snap.sessions.push(TraySession {
            pane_id,
            host_id,
            label: truncate(&label),
        });
    }
    snap.sessions.sort_by(|a, b| a.label.cmp(&b.label));

    let stored: Option<(String,)> =
        sqlx::query_as("SELECT value FROM settings WHERE key = 'workspaces'")
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    if let Some(list) = stored
        .and_then(|(v,)| serde_json::from_str::<serde_json::Value>(&v).ok())
        .and_then(|v| v.as_array().cloned())
    {
        for ws in list {
            if let (Some(id), Some(name)) = (ws["id"].as_str(), ws["name"].as_str()) {
                snap.workspaces.push((id.to_string(), truncate(name)));
            }
        }
    }
    snap
}

fn build_menu(app: &AppHandle, snap: &Snapshot) -> tauri::Result<Menu<tauri::Wry>> {
    let toggle = MenuItemBuilder::with_id(
        "window:toggle",
        if snap.window_visible {
            "Hide SSHBool"
        } else {
            "Show SSHBool"
        },
    )
    .build(app)?;

    let sessions_title = match snap.sessions.len() {
        0 => "Active sessions".to_string(),
        n => format!("Active sessions ({n})"),
    };
    let mut sessions = SubmenuBuilder::with_id(app, "sessions", sessions_title);
    if snap.sessions.is_empty() {
        sessions = sessions.item(
            &MenuItemBuilder::with_id("sessions:none", "No active sessions")
                .enabled(false)
                .build(app)?,
        );
    } else {
        for s in &snap.sessions {
            sessions = sessions.item(
                &MenuItemBuilder::with_id(format!("session:{}:{}", s.host_id, s.pane_id), &s.label)
                    .build(app)?,
            );
        }
    }

    let mut menu = MenuBuilder::new(app)
        .item(&toggle)
        .separator()
        .item(&sessions.build()?);

    if !snap.workspaces.is_empty() {
        let mut ws = SubmenuBuilder::with_id(app, "workspaces", "Open workspace");
        for (id, name) in &snap.workspaces {
            ws = ws.item(&MenuItemBuilder::with_id(format!("ws:{id}"), name).build(app)?);
        }
        menu = menu.item(&ws.build()?);
    }

    menu.item(&MenuItemBuilder::with_id("new-connection", "New connection…").build(app)?)
        .separator()
        .item(&MenuItemBuilder::with_id("lock", "Lock vault").build(app)?)
        .item(&MenuItemBuilder::with_id("settings", "Settings…").build(app)?)
        .separator()
        .item(
            &CheckMenuItemBuilder::with_id("launch-at-login", "Launch at login")
                .checked(snap.launch_at_login)
                .build(app)?,
        )
        .item(
            &CheckMenuItemBuilder::with_id("close-to-tray", "Keep running when window is closed")
                .checked(snap.close_to_tray)
                .build(app)?,
        )
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&MenuItemBuilder::with_id("quit", "Quit SSHBool").build(app)?)
        .build()
}

/// Rebuild the tray menu and tooltip when the visible state changed (or always, if `force`).
pub async fn refresh(app: &AppHandle, force: bool) {
    if app.try_state::<Background>().is_none() {
        return;
    }
    let snap = snapshot(app).await;
    {
        let bg = app.state::<Background>();
        let mut last = bg.last.lock().unwrap_or_else(|e| e.into_inner());
        if !force && last.as_ref() == Some(&snap) {
            return;
        }
        *last = Some(snap.clone());
    }
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    match build_menu(app, &snap) {
        Ok(menu) => {
            let _ = tray.set_menu(Some(menu));
        }
        Err(e) => tracing::warn!("tray menu rebuild failed: {e}"),
    }
    let tooltip = match snap.sessions.len() {
        0 => "SSHBool".to_string(),
        1 => "SSHBool — 1 active session".to_string(),
        n => format!("SSHBool — {n} active sessions"),
    };
    let _ = tray.set_tooltip(Some(tooltip));
}

fn spawn_refresh(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move { refresh(&app, false).await });
}

fn on_menu_event(app: &AppHandle, event: MenuEvent) {
    let id = event.id().as_ref().to_string();
    match id.as_str() {
        "window:toggle" => toggle_main(app),
        "new-connection" => {
            show_main(app);
            let _ = app.emit_to(MAIN, events::NEW_CONNECTION, ());
        }
        "settings" => {
            show_main(app);
            let _ = app.emit_to(MAIN, events::OPEN_SETTINGS, ());
        }
        "lock" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(state) = app.try_state::<Arc<AppState>>() {
                    if let Err(e) = state.vault.lock().await {
                        tracing::warn!("tray lock failed: {e}");
                        return;
                    }
                    mcp::runtime::McpRuntimeState::global().on_vault_lock();
                    let _ = app.emit(crate::events::APP_LOCK, ());
                }
            });
        }
        "launch-at-login" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let next = !launch_at_login(&app);
                if let Err(e) = set_launch_at_login(&app, next).await {
                    tracing::warn!("launch at login: {e}");
                    refresh(&app, true).await;
                }
            });
        }
        "close-to-tray" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let next = !app.state::<Background>().close_to_tray();
                if let Err(e) = set_close_to_tray(&app, next).await {
                    tracing::warn!("close to tray: {e}");
                    refresh(&app, true).await;
                }
            });
        }
        "quit" => request_quit(app),
        other => {
            if let Some(rest) = other.strip_prefix("session:") {
                if let Some((host_id, pane_id)) = rest.split_once(':') {
                    show_main(app);
                    let _ = app.emit_to(
                        MAIN,
                        events::FOCUS_SESSION,
                        json!({ "hostId": host_id, "paneId": pane_id }),
                    );
                }
            } else if let Some(ws_id) = other.strip_prefix("ws:") {
                let name = app
                    .state::<Background>()
                    .last
                    .lock()
                    .ok()
                    .and_then(|l| {
                        l.as_ref().and_then(|s| {
                            s.workspaces
                                .iter()
                                .find(|(id, _)| id == ws_id)
                                .map(|(_, n)| n.clone())
                        })
                    })
                    .unwrap_or_else(|| "Workspace".into());
                let app = app.clone();
                let ws_id = ws_id.to_string();
                // Creating a window from the (main-thread) menu callback deadlocks on Windows.
                tauri::async_runtime::spawn(async move {
                    crate::commands::windows::open_workspace_window(
                        &app,
                        &ws_id,
                        None,
                        &format!("SSHBool — {name}"),
                    );
                });
            }
        }
    }
}

/// Create the tray icon. Call from `setup` after `AppState` is managed.
pub fn setup(app: &tauri::App) -> tauri::Result<()> {
    app.manage(Background::default());
    let handle = app.handle().clone();
    let initial = build_menu(
        &handle,
        &Snapshot {
            window_visible: !started_minimized(),
            close_to_tray: true,
            ..Default::default()
        },
    )?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("SSHBool")
        .menu(&initial)
        // Windows/macOS: left click toggles the window, right click opens the menu.
        // Linux trays always open the menu (they report no clicks).
        .show_menu_on_left_click(false)
        .on_menu_event(on_menu_event)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    match builder.build(app) {
        Ok(_) => app
            .state::<Background>()
            .tray_ok
            .store(true, Ordering::Relaxed),
        // Never fail startup over the tray (e.g. libayatana-appindicator missing on Linux).
        Err(e) => tracing::warn!("system tray unavailable: {e}"),
    }

    tauri::async_runtime::spawn(async move {
        load_settings(&handle).await;
        refresh(&handle, true).await;
        loop {
            tokio::time::sleep(REFRESH_EVERY).await;
            refresh(&handle, false).await;
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{quit_warning, truncate};

    #[test]
    fn quit_warning_lists_what_would_be_interrupted() {
        assert_eq!(quit_warning(0, 0, false), None);
        let msg = quit_warning(2, 1, true).unwrap();
        assert!(msg.contains("update"));
        assert!(msg.contains("2 active sessions"));
        assert!(msg.contains("1 file transfer "));
        assert!(quit_warning(1, 0, false)
            .unwrap()
            .contains("1 active session "));
    }

    #[test]
    fn truncates_long_labels() {
        assert_eq!(truncate("short"), "short");
        let long = "x".repeat(80);
        let t = truncate(&long);
        assert_eq!(t.chars().count(), super::MAX_LABEL);
        assert!(t.ends_with('…'));
    }
}
