//! Remote editor helpers (git status / diff).

use infrastructure::{validate_safe_remote_path, AppState};
use std::sync::Arc;
use tauri::State;

use crate::error::AppError;

#[tauri::command]
pub async fn editor_git_status(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    path: String,
) -> Result<String, AppError> {
    let safe_path = validate_safe_remote_path(&path)?;
    state
        .connections
        .exec_command(
            &host_id,
            &format!("cd {safe_path} 2>/dev/null; git status -sb 2>&1; echo '---'; git diff --stat 2>&1 | head -n 40"),
        )
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn editor_diff(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    path: String,
) -> Result<String, AppError> {
    let safe_path = validate_safe_remote_path(&path)?;
    state
        .connections
        .exec_command(
            &host_id,
            &format!("git diff -- {safe_path} 2>&1 | head -n 500"),
        )
        .await
        .map_err(Into::into)
}
