//! Workspace windows, tray and app lifecycle.

use infrastructure::AppState;
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;

use crate::error::AppError;
use tauri::Manager;

/// Open a workspace in its own window, optionally focused on a host.
pub(crate) fn open_workspace_window(
    app: &tauri::AppHandle,
    ws_id: &str,
    host_id: Option<&str>,
    title: &str,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let label = format!("ws_win_{ws_id}_{now}");
    let mut url_str = format!("index.html?wsId={ws_id}");
    if let Some(hid) = host_id {
        url_str.push_str(&format!("&focusHost={hid}"));
    }
    let url = tauri::WebviewUrl::App(url_str.into());

    let _ = tauri::WebviewWindowBuilder::new(app, &label, url)
        .title(title)
        .inner_size(1200.0, 800.0)
        .decorations(false)
        .shadow(true)
        .build();
}

#[tauri::command]
pub async fn workspace_window_open(
    app: tauri::AppHandle,
    ws_id: String,
    title: String,
) -> Result<(), AppError> {
    open_workspace_window(&app, &ws_id, None, &title);
    Ok(())
}

#[tauri::command]
pub async fn window_minimize(window: tauri::Window) -> Result<(), AppError> {
    let _ = window.minimize();
    Ok(())
}

#[tauri::command]
pub async fn window_toggle_maximize(window: tauri::Window) -> Result<(), AppError> {
    if window.is_maximized().unwrap_or(false) {
        let _ = window.unmaximize();
    } else {
        let _ = window.maximize();
    }
    Ok(())
}

#[tauri::command]
pub async fn window_close(window: tauri::Window) -> Result<(), AppError> {
    let _ = window.close();
    Ok(())
}

#[tauri::command]
pub async fn window_toggle_pin(window: tauri::Window) -> Result<bool, AppError> {
    let current = window.is_always_on_top().unwrap_or(false);
    let next = !current;
    let _ = window.set_always_on_top(next);
    Ok(next)
}

/// Returns active SSH sessions + workspaces for the system tray popup.
#[tauri::command]
pub async fn tray_get_data(state: State<'_, Arc<AppState>>) -> Result<Value, AppError> {
    // Active sessions
    let sessions = state.connections.sessions_list().await;
    let sessions_json: Vec<Value> = sessions
        .into_iter()
        .map(|(pane_id, session_id, host_id, title)| {
            json!({
                "paneId": pane_id,
                "sessionId": session_id,
                "hostId": host_id,
                "title": title,
            })
        })
        .collect();

    // Hosts info for each active session (label + workspace_id)
    let pool = state.vault.pool();
    let mut enriched: Vec<Value> = Vec::new();
    for s in &sessions_json {
        let host_id = s["hostId"].as_str().unwrap_or("");
        let row: Option<(String, Option<String>)> =
            sqlx::query_as("SELECT label, workspace_id FROM hosts WHERE id = ?")
                .bind(host_id)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);
        let mut entry = s.clone();
        if let Some((label, ws_id)) = row {
            entry["label"] = json!(label);
            entry["workspaceId"] = json!(ws_id.unwrap_or_default());
        }
        enriched.push(entry);
    }

    Ok(json!({ "sessions": enriched }))
}

/// Opens a workspace window and optionally highlights a specific host.
#[tauri::command]
pub async fn workspace_window_open_with_host(
    app: tauri::AppHandle,
    ws_id: String,
    host_id: Option<String>,
    title: String,
) -> Result<(), AppError> {
    open_workspace_window(&app, &ws_id, host_id.as_deref(), &title);
    Ok(())
}

/// Quit the entire application (asks first when sessions are active).
#[tauri::command]
pub async fn app_quit(app: tauri::AppHandle) -> Result<(), AppError> {
    crate::tray::request_quit(&app);
    Ok(())
}

/// The UI reports work that must not be cut off by quitting (currently "update").
#[tauri::command]
pub async fn app_busy_set(
    bg: State<'_, crate::tray::Background>,
    reason: String,
    busy: bool,
) -> Result<(), AppError> {
    bg.set_busy(&reason, busy);
    Ok(())
}

/// Background-mode preferences shown in Settings → Background.
#[tauri::command]
pub async fn background_settings_get(
    app: tauri::AppHandle,
    bg: State<'_, crate::tray::Background>,
) -> Result<Value, AppError> {
    Ok(json!({
        "closeToTray": bg.close_to_tray(),
        "launchAtLogin": crate::tray::launch_at_login(&app),
    }))
}

#[tauri::command]
pub async fn background_settings_set(
    app: tauri::AppHandle,
    close_to_tray: Option<bool>,
    launch_at_login: Option<bool>,
) -> Result<(), AppError> {
    let internal = |message: String| AppError::Internal { message };
    if let Some(v) = close_to_tray {
        crate::tray::set_close_to_tray(&app, v)
            .await
            .map_err(internal)?;
    }
    if let Some(v) = launch_at_login {
        crate::tray::set_launch_at_login(&app, v)
            .await
            .map_err(internal)?;
    }
    Ok(())
}

/// Explicitly close/destroy the tray popup window.
#[tauri::command]
pub async fn tray_close(app: tauri::AppHandle) -> Result<(), AppError> {
    if let Some(win) = app.get_webview_window("tray_popup") {
        let _ = win.close();
    }
    Ok(())
}
