//! Docker management through the remote CLI over SSH.

use infrastructure::{validate_container_id, validate_safe_remote_path, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;

use crate::error::AppError;

// ── Docker (via remote CLI over SSH) ─────────────────────────────────

#[tauri::command]
pub async fn docker_list_containers(
    state: State<'_, Arc<AppState>>,
    host_id: String,
) -> Result<Vec<Value>, AppError> {
    let out = state
        .connections
        .exec_command(
            &host_id,
            "docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>&1",
        )
        .await?;
    if out.to_lowercase().contains("permission denied") || out.contains("Cannot connect") {
        return Err(AppError::Connection {
            message: out.lines().next().unwrap_or("docker unavailable").into(),
            retryable: false,
        });
    }
    Ok(out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let p: Vec<&str> = line.split('\t').collect();
            if p.len() < 4 {
                return None;
            }
            Some(json!({
                "id": p[0], "name": p[1], "image": p[2], "status": p[3],
                "ports": p.get(4).copied().unwrap_or("")
            }))
        })
        .collect())
}

#[tauri::command]
pub async fn docker_container_action(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    container_id: String,
    action: String,
) -> Result<(), AppError> {
    let safe_id = validate_container_id(&container_id)?;
    let cmd = match action.as_str() {
        "start" => format!("docker start {safe_id}"),
        "stop" => format!("docker stop {safe_id}"),
        "restart" => format!("docker restart {safe_id}"),
        "remove" => format!("docker rm -f {safe_id}"),
        _ => {
            return Err(AppError::Validation {
                field: "action".into(),
                message: "start|stop|restart|remove".into(),
            })
        }
    };
    state.connections.exec_command(&host_id, &cmd).await?;
    Ok(())
}

#[tauri::command]
pub async fn docker_list_images(
    state: State<'_, Arc<AppState>>,
    host_id: String,
) -> Result<Vec<Value>, AppError> {
    let out = state
        .connections
        .exec_command(
            &host_id,
            "docker images --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}'",
        )
        .await?;
    Ok(out
        .lines()
        .filter_map(|line| {
            let p: Vec<&str> = line.split('\t').collect();
            if p.len() < 4 {
                return None;
            }
            Some(json!({
                "repository": p[0], "tag": p[1], "id": p[2], "size": p[3],
                "created": p.get(4).copied().unwrap_or("")
            }))
        })
        .collect())
}

#[tauri::command]
pub async fn docker_logs(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    container_id: String,
    tail: Option<u32>,
) -> Result<String, AppError> {
    let safe_id = validate_container_id(&container_id)?;
    let n = tail.unwrap_or(200).min(5000);
    state
        .connections
        .exec_command(&host_id, &format!("docker logs --tail {n} {safe_id} 2>&1"))
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn docker_compose_action(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    path: String,
    action: String,
) -> Result<String, AppError> {
    let safe_path = validate_safe_remote_path(&path)?;
    let action_str = match action.as_str() {
        "up" => "up -d",
        "down" => "down",
        "restart" => "restart",
        "ps" => "ps",
        _ => {
            return Err(AppError::Validation {
                field: "action".into(),
                message: "up|down|restart|ps".into(),
            })
        }
    };
    state
        .connections
        .exec_command(
            &host_id,
            &format!("docker compose -f {safe_path} {action_str} 2>&1"),
        )
        .await
        .map_err(Into::into)
}
