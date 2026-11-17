//! Kubernetes (kubectl over SSH).

use infrastructure::{audit, validate_k8s_name, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;

use crate::error::AppError;

// ── Kubernetes (kubectl over SSH) ────────────────────────────────────

#[tauri::command]
pub async fn k8s_contexts_list(
    state: State<'_, Arc<AppState>>,
    host_id: String,
) -> Result<Vec<Value>, AppError> {
    let out = state
        .connections
        .exec_command(&host_id, "kubectl config get-contexts -o name 2>&1")
        .await?;
    Ok(out
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.contains("error"))
        .map(|name| json!({ "name": name.trim() }))
        .collect())
}

#[tauri::command]
pub async fn k8s_get_pods(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    namespace: Option<String>,
) -> Result<Vec<Value>, AppError> {
    let ns = namespace.unwrap_or_else(|| "default".into());
    let safe_ns = validate_k8s_name(&ns, "namespace")?;
    let out = state
        .connections
        .exec_command(
            &host_id,
            &format!(
                "kubectl get pods -n {safe_ns} -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[*].ready,RESTARTS:.status.containerStatuses[*].restartCount,AGE:.metadata.creationTimestamp --no-headers 2>&1"
            ),
        )
        .await?;
    Ok(out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() < 2 {
                return None;
            }
            Some(json!({
                "name": p[0], "status": p[1],
                "ready": p.get(2).copied().unwrap_or(""),
                "restarts": p.get(3).copied().unwrap_or(""),
                "age": p.get(4).copied().unwrap_or(""),
            }))
        })
        .collect())
}

#[tauri::command]
pub async fn k8s_get_deployments(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    namespace: Option<String>,
) -> Result<Vec<Value>, AppError> {
    let ns = namespace.unwrap_or_else(|| "default".into());
    let safe_ns = validate_k8s_name(&ns, "namespace")?;
    let out = state
        .connections
        .exec_command(
            &host_id,
            &format!("kubectl get deploy -n {safe_ns} --no-headers 2>&1"),
        )
        .await?;
    Ok(out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.is_empty() {
                return None;
            }
            Some(json!({
                "name": p[0],
                "ready": p.get(1).copied().unwrap_or(""),
                "upToDate": p.get(2).copied().unwrap_or(""),
                "available": p.get(3).copied().unwrap_or(""),
                "age": p.get(4).copied().unwrap_or(""),
            }))
        })
        .collect())
}

#[tauri::command]
pub async fn k8s_logs(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    namespace: String,
    pod: String,
    tail: Option<u32>,
) -> Result<String, AppError> {
    let safe_ns = validate_k8s_name(&namespace, "namespace")?;
    let safe_pod = validate_k8s_name(&pod, "pod")?;
    let n = tail.unwrap_or(100).min(5000);
    state
        .connections
        .exec_command(
            &host_id,
            &format!("kubectl logs -n {safe_ns} {safe_pod} --tail={n} 2>&1"),
        )
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn k8s_apply(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    manifest: String,
) -> Result<String, AppError> {
    let escaped = manifest.replace('\'', "'\\''");
    let out = state
        .connections
        .exec_command(
            &host_id,
            &format!("printf '%s' '{escaped}' | kubectl apply -f - 2>&1"),
        )
        .await?;
    audit(&state, "k8s.apply", Some(&host_id), "ok", None).await;
    Ok(out)
}
