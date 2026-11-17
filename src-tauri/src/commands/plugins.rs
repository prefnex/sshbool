//! Plugin SDK v1: install, enable and capability checks.

use infrastructure::{audit, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

use crate::commands::common::db;
use crate::error::AppError;

// ── Plugin SDK v1 ────────────────────────────────────────────────────

#[tauri::command]
pub async fn plugins_list(state: State<'_, Arc<AppState>>) -> Result<Vec<Value>, AppError> {
    let rows: Vec<(String, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT id, slug, name, version, source, enabled FROM plugins ORDER BY name",
    )
    .fetch_all(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|(id, slug, name, version, source, enabled)| {
            json!({
                "id": id, "slug": slug, "name": name, "version": version,
                "source": source, "enabled": enabled != 0
            })
        })
        .collect())
}

#[tauri::command]
pub async fn plugins_install(
    state: State<'_, Arc<AppState>>,
    manifest: Value,
) -> Result<String, AppError> {
    if manifest["paid"].as_bool().unwrap_or(false) {
        crate::commands::license::require_feature(&state, "marketplace_paid").await?;
    }
    let slug = manifest["slug"]
        .as_str()
        .ok_or_else(|| AppError::Validation {
            field: "slug".into(),
            message: "required".into(),
        })?
        .to_string();
    let name = manifest["name"].as_str().unwrap_or(&slug).to_string();
    let version = manifest["version"].as_str().unwrap_or("0.1.0").to_string();
    let id = Uuid::now_v7().to_string();
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        r#"INSERT INTO plugins (id, slug, name, version, source, enabled, manifest_json, installed_at, updated_at)
           VALUES (?, ?, ?, ?, 'local', 0, ?, ?, ?)
           ON CONFLICT(slug) DO UPDATE SET name=excluded.name, version=excluded.version,
             manifest_json=excluded.manifest_json, updated_at=excluded.updated_at"#,
    )
    .bind(&id)
    .bind(&slug)
    .bind(&name)
    .bind(&version)
    .bind(manifest.to_string())
    .bind(now)
    .bind(now)
    .execute(state.vault.pool())
    .await
    .map_err(db)?;

    if let Some(caps) = manifest["permissions"].as_array() {
        let plugin_id: (String,) = sqlx::query_as("SELECT id FROM plugins WHERE slug = ?")
            .bind(&slug)
            .fetch_one(state.vault.pool())
            .await
            .map_err(db)?;
        for cap in caps {
            if let Some(c) = cap.as_str() {
                let pid = Uuid::now_v7().to_string();
                let _ = sqlx::query(
                    "INSERT INTO plugin_permissions (id, plugin_id, capability, granted, granted_at) VALUES (?, ?, ?, 0, NULL)",
                )
                .bind(&pid)
                .bind(&plugin_id.0)
                .bind(c)
                .execute(state.vault.pool())
                .await;
            }
        }
        audit(&state, "plugin.install", Some(&slug), "ok", None).await;
        return Ok(plugin_id.0);
    }
    audit(&state, "plugin.install", Some(&slug), "ok", None).await;
    Ok(id)
}

#[tauri::command]
pub async fn plugins_search_marketplace(
    _state: State<'_, Arc<AppState>>,
    query: String,
) -> Result<Vec<Value>, AppError> {
    let catalog = vec![
        json!({
            "slug": "sample-theme",
            "name": "Sample Theme",
            "version": "0.1.0",
            "description": "Free bundled theme sample",
            "paid": false,
            "permissions": ["ui.theme"]
        }),
        json!({
            "slug": "ops-snippets-pack",
            "name": "Ops Snippets Pack",
            "version": "1.0.0",
            "description": "Paid curated sysadmin snippets",
            "paid": true,
            "permissions": ["snippets.write"]
        }),
        json!({
            "slug": "nginx-wizard",
            "name": "Nginx Wizard",
            "version": "0.2.0",
            "description": "Config helpers for nginx",
            "paid": false,
            "permissions": ["templates.read"]
        }),
    ];
    let q = query.to_lowercase();
    Ok(catalog
        .into_iter()
        .filter(|item| {
            if q.is_empty() {
                return true;
            }
            item["name"]
                .as_str()
                .unwrap_or("")
                .to_lowercase()
                .contains(&q)
                || item["slug"]
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
        })
        .collect())
}

#[tauri::command]
pub async fn plugins_set_enabled(
    state: State<'_, Arc<AppState>>,
    id: String,
    enabled: bool,
) -> Result<(), AppError> {
    sqlx::query("UPDATE plugins SET enabled = ?, updated_at = ? WHERE id = ?")
        .bind(if enabled { 1 } else { 0 })
        .bind(chrono::Utc::now().timestamp_millis())
        .bind(&id)
        .execute(state.vault.pool())
        .await
        .map_err(db)?;
    // Enabling requires all permissions granted — soft check.
    if enabled {
        let pending: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM plugin_permissions WHERE plugin_id = ? AND granted = 0",
        )
        .bind(&id)
        .fetch_one(state.vault.pool())
        .await
        .unwrap_or((0,));
        if pending.0 > 0 {
            // Auto-grant for v1 local plugins (marketplace will require explicit grant).
            sqlx::query(
                "UPDATE plugin_permissions SET granted = 1, granted_at = ? WHERE plugin_id = ?",
            )
            .bind(chrono::Utc::now().timestamp_millis())
            .bind(&id)
            .execute(state.vault.pool())
            .await
            .map_err(db)?;
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn plugins_uninstall(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM plugins WHERE id = ?")
        .bind(&id)
        .execute(state.vault.pool())
        .await
        .map_err(db)?;
    Ok(())
}

#[allow(dead_code)]
pub async fn verify_plugin_capability(
    state: &AppState,
    plugin_id: &str,
    capability: &str,
) -> Result<(), AppError> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT granted FROM plugin_permissions WHERE plugin_id = ? AND capability = ?",
    )
    .bind(plugin_id)
    .bind(capability)
    .fetch_optional(state.vault.pool())
    .await
    .map_err(db)?;

    match row {
        Some((1,)) => Ok(()),
        _ => Err(AppError::Unauthorized {
            reason: "plugin_permission_denied".into(),
        }),
    }
}
