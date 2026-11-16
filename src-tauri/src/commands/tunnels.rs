//! Proxies and SSH port forwards.

use infrastructure::AppState;
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

use crate::commands::common::db;
use crate::error::AppError;

// ── Proxies & port forwards ──────────────────────────────────────────

#[tauri::command]
pub async fn proxies_list(state: State<'_, Arc<AppState>>) -> Result<Vec<Value>, AppError> {
    let rows: Vec<(String, String, String, String, i64, Option<String>)> =
        sqlx::query_as("SELECT id, name, kind, host, port, username FROM proxies ORDER BY name")
            .fetch_all(state.vault.pool())
            .await
            .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|(id, name, kind, host, port, username)| {
            json!({ "id": id, "name": name, "kind": kind, "host": host, "port": port, "username": username })
        })
        .collect())
}

#[tauri::command]
pub async fn proxies_upsert(
    state: State<'_, Arc<AppState>>,
    proxy: Value,
) -> Result<String, AppError> {
    let id = proxy["id"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        r#"INSERT INTO proxies (id, name, kind, host, port, username, credential_id, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)
           ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind, host=excluded.host,
             port=excluded.port, username=excluded.username, updated_at=excluded.updated_at"#,
    )
    .bind(&id)
    .bind(proxy["name"].as_str().unwrap_or("proxy"))
    .bind(proxy["kind"].as_str().unwrap_or("socks5"))
    .bind(proxy["host"].as_str().unwrap_or("127.0.0.1"))
    .bind(proxy["port"].as_i64().unwrap_or(1080))
    .bind(proxy["username"].as_str())
    .bind(now)
    .bind(now)
    .execute(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(id)
}

#[tauri::command]
pub async fn port_forwards_upsert(
    state: State<'_, Arc<AppState>>,
    forward: Value,
) -> Result<String, AppError> {
    let id = forward["id"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        r#"INSERT INTO port_forwards (id, host_id, kind, bind_addr, bind_port, dest_addr, dest_port, auto_start, label, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, bind_addr=excluded.bind_addr, bind_port=excluded.bind_port,
             dest_addr=excluded.dest_addr, dest_port=excluded.dest_port, auto_start=excluded.auto_start, label=excluded.label"#,
    )
    .bind(&id)
    .bind(forward["hostId"].as_str().unwrap_or(""))
    .bind(forward["kind"].as_str().unwrap_or("local"))
    .bind(forward["bindAddr"].as_str().unwrap_or("127.0.0.1"))
    .bind(forward["bindPort"].as_i64().unwrap_or(0))
    .bind(forward["destAddr"].as_str())
    .bind(forward["destPort"].as_i64())
    .bind(if forward["autoStart"].as_bool().unwrap_or(false) {
        1
    } else {
        0
    })
    .bind(forward["label"].as_str())
    .bind(now)
    .execute(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(id)
}

#[tauri::command]
pub async fn port_forwards_delete(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM port_forwards WHERE id = ?")
        .bind(&id)
        .execute(state.vault.pool())
        .await
        .map_err(db)?;
    Ok(())
}

#[tauri::command]
pub async fn port_forwards_list(
    state: State<'_, Arc<AppState>>,
    host_id: String,
) -> Result<Vec<Value>, AppError> {
    let rows: Vec<(String, String, Option<String>, Option<i64>, Option<String>, Option<i64>, String)> =
        sqlx::query_as(
            "SELECT id, kind, bind_addr, bind_port, dest_addr, dest_port, COALESCE(label,'') FROM port_forwards WHERE host_id = ?",
        )
        .bind(&host_id)
        .fetch_all(state.vault.pool())
        .await
        .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(
            |(id, kind, bind_addr, bind_port, dest_addr, dest_port, label)| {
                json!({
                    "id": id, "kind": kind, "bindAddr": bind_addr, "bindPort": bind_port,
                    "destAddr": dest_addr, "destPort": dest_port, "label": label
                })
            },
        )
        .collect())
}

#[tauri::command]
pub async fn port_forwards_start(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<(), AppError> {
    let row: Option<(String, Option<String>, Option<i64>, Option<String>, Option<i64>)> =
        sqlx::query_as(
            "SELECT host_id, bind_addr, bind_port, dest_addr, dest_port FROM port_forwards WHERE id = ?",
        )
        .bind(&id)
        .fetch_optional(state.vault.pool())
        .await
        .map_err(db)?;
    let Some((host_id, bind_addr, bind_port, dest_addr, dest_port)) = row else {
        return Err(AppError::NotFound {
            entity: "port_forward".into(),
            id: Some(id),
        });
    };
    state
        .connections
        .port_forward_start(
            &id,
            &host_id,
            bind_addr.as_deref().unwrap_or("127.0.0.1"),
            bind_port.unwrap_or(0) as u16,
            dest_addr.as_deref().unwrap_or("127.0.0.1"),
            dest_port.unwrap_or(0) as u16,
        )
        .await?;
    Ok(())
}

#[tauri::command]
pub async fn port_forwards_stop(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<(), AppError> {
    state.connections.port_forward_stop(&id).await?;
    Ok(())
}

#[tauri::command]
pub async fn port_check_available(bind_addr: String, bind_port: u16) -> Result<bool, AppError> {
    match tokio::net::TcpListener::bind((bind_addr.as_str(), bind_port)).await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[tauri::command]
pub async fn auth_fido2_status() -> Result<Value, AppError> {
    Ok(json!({
        "available": false,
        "message": "FIDO2/YubiKey support is stubbed for Phase 2 — password and key auth work today."
    }))
}
