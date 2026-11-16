//! Cloud sync: device pairing and encrypted bundles.

use infrastructure::{audit, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

use crate::commands::common::db;
use crate::error::AppError;

// ── Cloud Sync (E2E local device pairing stub + encrypted export) ────

#[tauri::command]
pub async fn sync_status(state: State<'_, Arc<AppState>>) -> Result<Value, AppError> {
    let row: Option<(
        i64,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<i64>,
    )> = sqlx::query_as(
        "SELECT enabled, endpoint, account_id, last_pull_at, last_push_at FROM sync_state LIMIT 1",
    )
    .fetch_optional(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(match row {
        Some((enabled, endpoint, account_id, last_pull, last_push)) => json!({
            "enabled": enabled != 0,
            "endpoint": endpoint,
            "accountId": account_id,
            "lastPullAt": last_pull,
            "lastPushAt": last_push,
        }),
        None => json!({ "enabled": false, "endpoint": null, "accountId": null }),
    })
}

#[tauri::command]
pub async fn sync_configure(
    state: State<'_, Arc<AppState>>,
    enabled: bool,
    endpoint: Option<String>,
) -> Result<(), AppError> {
    if enabled {
        crate::commands::license::require_feature(&state, "sync").await?;
    }
    let now = chrono::Utc::now().timestamp_millis();
    let existing: Option<(String,)> = sqlx::query_as("SELECT id FROM sync_state LIMIT 1")
        .fetch_optional(state.vault.pool())
        .await
        .map_err(db)?;
    if let Some((id,)) = existing {
        sqlx::query("UPDATE sync_state SET enabled = ?, endpoint = ? WHERE id = ?")
            .bind(if enabled { 1 } else { 0 })
            .bind(&endpoint)
            .bind(&id)
            .execute(state.vault.pool())
            .await
            .map_err(db)?;
    } else {
        let id = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO sync_state (id, enabled, endpoint, account_id, last_pull_at, last_push_at, vector_clock_json, root_key_wrapped) VALUES (?, ?, ?, NULL, NULL, NULL, '{}', NULL)",
        )
        .bind(&id)
        .bind(if enabled { 1 } else { 0 })
        .bind(&endpoint)
        .execute(state.vault.pool())
        .await
        .map_err(db)?;
        let _ = now;
    }
    audit(
        &state,
        "sync.configure",
        None,
        "ok",
        Some(json!({ "enabled": enabled })),
    )
    .await;
    Ok(())
}

#[tauri::command]
pub async fn sync_enable(
    state: State<'_, Arc<AppState>>,
    endpoint: String,
) -> Result<(), AppError> {
    sync_configure(state, true, Some(endpoint)).await
}

#[tauri::command]
pub async fn sync_disable(state: State<'_, Arc<AppState>>) -> Result<(), AppError> {
    sync_configure(state, false, None).await
}

#[tauri::command]
pub async fn sync_push(state: State<'_, Arc<AppState>>) -> Result<Value, AppError> {
    crate::commands::license::require_feature(&state, "sync").await?;
    let bundle = sync_export_bundle(state.clone()).await?;
    let endpoint: Option<(Option<String>,)> =
        sqlx::query_as("SELECT endpoint FROM sync_state LIMIT 1")
            .fetch_optional(state.vault.pool())
            .await
            .map_err(db)?;
    let base = endpoint
        .and_then(|e| e.0)
        .unwrap_or_else(|| "http://127.0.0.1:8787".into());
    let client = reqwest::Client::new();
    let url = format!("{}/v1/push", base.trim_end_matches('/'));
    let res = client
        .post(&url)
        .json(&bundle)
        .send()
        .await
        .map_err(|e| AppError::Connection {
            message: format!("sync push: {e}"),
            retryable: true,
        })?;
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap_or(json!({ "ok": true }));
    let now = chrono::Utc::now().timestamp_millis();
    let _ = sqlx::query("UPDATE sync_state SET last_push_at = ?")
        .bind(now)
        .execute(state.vault.pool())
        .await;
    let _ = sqlx::query("UPDATE sync_changes SET acked = 1 WHERE acked = 0")
        .execute(state.vault.pool())
        .await;
    audit(
        &state,
        "sync.push",
        None,
        "ok",
        Some(json!({ "http": status })),
    )
    .await;
    Ok(json!({ "pushed": 1, "relay": body, "httpStatus": status }))
}

#[tauri::command]
pub async fn sync_pull(state: State<'_, Arc<AppState>>) -> Result<Value, AppError> {
    crate::commands::license::require_feature(&state, "sync").await?;
    let endpoint: Option<(Option<String>,)> =
        sqlx::query_as("SELECT endpoint FROM sync_state LIMIT 1")
            .fetch_optional(state.vault.pool())
            .await
            .map_err(db)?;
    let base = endpoint
        .and_then(|e| e.0)
        .unwrap_or_else(|| "http://127.0.0.1:8787".into());
    let client = reqwest::Client::new();
    let url = format!("{}/v1/pull", base.trim_end_matches('/'));
    let res = client
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::Connection {
            message: format!("sync pull: {e}"),
            retryable: true,
        })?;
    let body: Value = res.json().await.map_err(|e| AppError::Internal {
        message: e.to_string(),
    })?;
    let now = chrono::Utc::now().timestamp_millis();
    let _ = sqlx::query("UPDATE sync_state SET last_pull_at = ?")
        .bind(now)
        .execute(state.vault.pool())
        .await;
    // LWW: store remote blob as sync_changes if present
    let mut pulled = 0;
    if let Some(items) = body["items"].as_array() {
        for item in items {
            let id = Uuid::now_v7().to_string();
            let ct = item["ciphertextB64"]
                .as_str()
                .and_then(|s| {
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s).ok()
                })
                .unwrap_or_default();
            let nonce = item["nonceB64"]
                .as_str()
                .and_then(|s| {
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s).ok()
                })
                .unwrap_or_default();
            if ct.is_empty() {
                continue;
            }
            let _ = sqlx::query(
                "INSERT INTO sync_changes (id, entity_type, entity_id, op, ciphertext, nonce, rev, acked, created_at) VALUES (?, 'bundle', 'remote', 'pull', ?, ?, 1, 1, ?)",
            )
            .bind(&id)
            .bind(&ct)
            .bind(&nonce)
            .bind(now)
            .execute(state.vault.pool())
            .await;
            pulled += 1;
        }
    }
    audit(
        &state,
        "sync.pull",
        None,
        "ok",
        Some(json!({ "pulled": pulled })),
    )
    .await;
    Ok(json!({ "pulled": pulled, "conflicts": 0 }))
}

#[tauri::command]
pub async fn sync_unpair(
    state: State<'_, Arc<AppState>>,
    device_id: String,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(&device_id)
        .execute(state.vault.pool())
        .await
        .map_err(db)?;
    audit(&state, "sync.unpair", Some(&device_id), "ok", None).await;
    Ok(())
}

#[tauri::command]
pub async fn sync_resolve_conflict(
    _state: State<'_, Arc<AppState>>,
    entity: String,
    choice: String,
) -> Result<(), AppError> {
    // LWW stub — accept local|remote choice without further action in v1.
    if !matches!(choice.as_str(), "local" | "remote") {
        return Err(AppError::Validation {
            field: "choice".into(),
            message: "local|remote".into(),
        });
    }
    let _ = entity;
    Ok(())
}

#[tauri::command]
pub async fn sync_export_bundle(state: State<'_, Arc<AppState>>) -> Result<Value, AppError> {
    // Export host metadata (no secrets) + queue encrypted change for multi-device sync.
    let hosts: Vec<(String, String, String, i64)> =
        sqlx::query_as("SELECT id, label, hostname, port FROM hosts WHERE deleted_at IS NULL")
            .fetch_all(state.vault.pool())
            .await
            .map_err(db)?;
    let payload = json!({ "hosts": hosts.iter().map(|(id, label, hostname, port)| {
        json!({ "id": id, "label": label, "hostname": hostname, "port": port })
    }).collect::<Vec<_>>(), "exportedAt": chrono::Utc::now().timestamp_millis() });
    let plain = payload.to_string();
    let (ct, nonce) = state
        .vault
        .seal_secret(plain.as_bytes(), "sync:bundle")
        .await?;
    let change_id = Uuid::now_v7().to_string();
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT INTO sync_changes (id, entity_type, entity_id, op, ciphertext, nonce, rev, acked, created_at) VALUES (?, 'bundle', 'hosts', 'export', ?, ?, 1, 0, ?)",
    )
    .bind(&change_id)
    .bind(&ct)
    .bind(&nonce)
    .bind(now)
    .execute(state.vault.pool())
    .await
    .map_err(db)?;
    sqlx::query("UPDATE sync_state SET last_push_at = ?")
        .bind(now)
        .execute(state.vault.pool())
        .await
        .ok();
    Ok(json!({
        "changeId": change_id,
        "ciphertextB64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ct),
        "nonceB64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nonce),
    }))
}

#[tauri::command]
pub async fn sync_pair_device(
    state: State<'_, Arc<AppState>>,
    name: String,
    public_key_b64: String,
) -> Result<String, AppError> {
    use base64::Engine;
    let pk = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64.as_bytes())
        .map_err(|e| AppError::Validation {
            field: "publicKeyB64".into(),
            message: e.to_string(),
        })?;
    let id = Uuid::now_v7().to_string();
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT INTO devices (id, name, platform, public_key, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&name)
    .bind(std::env::consts::OS)
    .bind(&pk)
    .bind(now)
    .bind(now)
    .execute(state.vault.pool())
    .await
    .map_err(db)?;
    audit(&state, "sync.pair", Some(&id), "ok", None).await;
    Ok(id)
}

#[tauri::command]
pub async fn sync_devices_list(state: State<'_, Arc<AppState>>) -> Result<Vec<Value>, AppError> {
    let rows: Vec<(String, String, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT id, name, platform, last_seen_at FROM devices ORDER BY created_at DESC",
    )
    .fetch_all(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|(id, name, platform, last_seen)| {
            json!({ "id": id, "name": name, "platform": platform, "lastSeenAt": last_seen })
        })
        .collect())
}
