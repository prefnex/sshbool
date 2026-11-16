//! Audit log listing and export.

use infrastructure::AppState;
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;

use crate::commands::common::db;
use crate::error::AppError;

// ── Audit ────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn audit_list(
    state: State<'_, Arc<AppState>>,
    limit: Option<u32>,
) -> Result<Vec<Value>, AppError> {
    let lim = limit.unwrap_or(100) as i64;
    let rows: Vec<(
        String,
        i64,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, at, actor, action, target, metadata_json, result FROM audit_log ORDER BY at DESC LIMIT ?",
    )
    .bind(lim)
    .fetch_all(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|(id, at, actor, action, target, meta, result)| {
            json!({
                "id": id, "at": at, "actor": actor, "action": action,
                "target": target, "metadata": meta, "result": result
            })
        })
        .collect())
}

#[tauri::command]
pub async fn audit_export(state: State<'_, Arc<AppState>>) -> Result<String, AppError> {
    let rows = audit_list(state, Some(10_000)).await?;
    Ok(serde_json::to_string_pretty(&rows).unwrap_or_default())
}
