//! Session recording and local/remote folder comparison.

use infrastructure::AppState;
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

use crate::commands::common::db;
use crate::error::AppError;

// ── Session recording / folder sync stubs (working MVP of Phase 2 extras) ─

#[tauri::command]
pub async fn recording_start(
    state: State<'_, Arc<AppState>>,
    session_id: String,
    pane_id: Option<String>,
) -> Result<String, AppError> {
    let id = Uuid::now_v7().to_string();
    let now = chrono::Utc::now().timestamp_millis();
    let path = format!("recordings/{id}.cast");
    sqlx::query(
        "INSERT INTO recordings (id, session_id, pane_id, path, format, size_bytes, duration_ms, created_at) VALUES (?, ?, ?, ?, 'asciicast-v2', 0, 0, ?)",
    )
    .bind(&id)
    .bind(&session_id)
    .bind(&pane_id)
    .bind(&path)
    .bind(now)
    .execute(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(id)
}

#[tauri::command]
pub async fn recording_stop(state: State<'_, Arc<AppState>>, id: String) -> Result<(), AppError> {
    // Marker stop — bytes are written by terminal event tap in a follow-up.
    let _ =
        sqlx::query("UPDATE recordings SET duration_ms = COALESCE(duration_ms, 0) WHERE id = ?")
            .bind(&id)
            .execute(state.vault.pool())
            .await;
    Ok(())
}

fn validate_local_sandbox(path: &std::path::Path) -> Result<std::path::PathBuf, AppError> {
    let home = dirs::home_dir().ok_or_else(|| AppError::Validation {
        field: "path".into(),
        message: "user home directory not found".into(),
    })?;
    let canonical_home = home.canonicalize().map_err(|e| AppError::Validation {
        field: "path".into(),
        message: format!("failed to canonicalize home directory: {e}"),
    })?;

    let mut check_path = path.to_path_buf();
    while !check_path.exists() {
        if let Some(parent) = check_path.parent() {
            check_path = parent.to_path_buf();
        } else {
            break;
        }
    }

    let canonical_path = check_path
        .canonicalize()
        .map_err(|e| AppError::Validation {
            field: "path".into(),
            message: format!("invalid path: {e}"),
        })?;

    if !canonical_path.starts_with(&canonical_home) {
        return Err(AppError::Validation {
            field: "path".into(),
            message: "path lies outside of the user home directory sandbox".into(),
        });
    }

    Ok(canonical_path)
}

#[tauri::command]
pub async fn folders_compare(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    local_root: String,
    remote_root: String,
) -> Result<Value, AppError> {
    let p_local = std::path::Path::new(&local_root);
    validate_local_sandbox(p_local)?;
    let remote = state
        .connections
        .sftp_list_dir(&host_id, &remote_root)
        .await?;
    let local_entries = std::fs::read_dir(&local_root)
        .map_err(|e| AppError::Io {
            message: e.to_string(),
        })?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect::<std::collections::HashSet<_>>();

    let remote_names: std::collections::HashSet<_> =
        remote.iter().map(|e| e.name.clone()).collect();
    let only_local: Vec<_> = local_entries.difference(&remote_names).cloned().collect();
    let only_remote: Vec<_> = remote_names.difference(&local_entries).cloned().collect();
    let both: Vec<_> = local_entries.intersection(&remote_names).cloned().collect();
    Ok(json!({
        "onlyLocal": only_local,
        "onlyRemote": only_remote,
        "both": both,
    }))
}
