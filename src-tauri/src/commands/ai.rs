//! AI assistant providers and requests.

use infrastructure::{redact, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

use crate::commands::common::db;
use crate::error::AppError;

// ── AI Assistant ─────────────────────────────────────────────────────

#[tauri::command]
pub async fn ai_providers_list(state: State<'_, Arc<AppState>>) -> Result<Vec<Value>, AppError> {
    let rows: Vec<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    )> = sqlx::query_as(
        "SELECT id, kind, name, base_url, model, enabled FROM ai_providers ORDER BY created_at",
    )
    .fetch_all(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|(id, kind, name, base_url, model, enabled)| {
            json!({
                "id": id, "kind": kind, "name": name, "baseUrl": base_url,
                "model": model, "enabled": enabled != 0
            })
        })
        .collect())
}

#[tauri::command]
pub async fn ai_providers_upsert(
    state: State<'_, Arc<AppState>>,
    provider: Value,
) -> Result<String, AppError> {
    let id = provider["id"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        r#"INSERT INTO ai_providers (id, kind, name, base_url, model, credential_id, enabled, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, name=excluded.name, base_url=excluded.base_url,
             model=excluded.model, enabled=excluded.enabled, updated_at=excluded.updated_at"#,
    )
    .bind(&id)
    .bind(provider["kind"].as_str().unwrap_or("ollama"))
    .bind(provider["name"].as_str())
    .bind(provider["baseUrl"].as_str().unwrap_or("http://127.0.0.1:11434"))
    .bind(provider["model"].as_str().unwrap_or("llama3.2"))
    .bind(provider["credentialId"].as_str())
    .bind(if provider["enabled"].as_bool().unwrap_or(true) {
        1
    } else {
        0
    })
    .bind(now)
    .bind(now)
    .execute(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(id)
}

#[tauri::command]
pub async fn ai_send(
    state: State<'_, Arc<AppState>>,
    message: String,
    system: Option<String>,
    conversation_id: Option<String>,
) -> Result<Value, AppError> {
    let message = redact(&message);
    let system = system.unwrap_or_else(|| {
        "You are SSHBool AI copilot for sysadmins. Be concise. Prefer safe shell commands.".into()
    });

    let row: Option<(String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT kind, base_url, model, credential_id FROM ai_providers WHERE enabled = 1 ORDER BY updated_at DESC LIMIT 1",
    )
    .fetch_optional(state.vault.pool())
    .await
    .map_err(db)?;

    let (kind, base_url, model, cred_id) = row.unwrap_or_else(|| {
        (
            "ollama".into(),
            Some("http://127.0.0.1:11434".into()),
            Some("llama3.2".into()),
            None,
        )
    });

    let api_key = if let Some(cid) = cred_id {
        let secret: Option<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as("SELECT ciphertext, nonce FROM credentials WHERE id = ?")
                .bind(&cid)
                .fetch_optional(state.vault.pool())
                .await
                .map_err(db)?;
        if let Some((ct, nonce)) = secret {
            let plain = state
                .vault
                .open_secret(&ct, &nonce, &format!("cred:{cid}"))
                .await?;
            Some(String::from_utf8_lossy(&plain).into_owned())
        } else {
            None
        }
    } else {
        None
    };

    let base = base_url.unwrap_or_else(|| "http://127.0.0.1:11434".into());
    let model = model.unwrap_or_else(|| "llama3.2".into());

    let client = reqwest::Client::new();
    let reply = if kind == "ollama" {
        let url = format!("{}/api/chat", base.trim_end_matches('/'));
        let body = json!({
            "model": model,
            "stream": false,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": message }
            ]
        });
        let res = client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Connection {
                message: format!("ollama: {e}"),
                retryable: true,
            })?;
        let v: Value = res.json().await.map_err(|e| AppError::Internal {
            message: e.to_string(),
        })?;
        v["message"]["content"]
            .as_str()
            .unwrap_or("No response from Ollama")
            .to_string()
    } else {
        // OpenAI-compatible
        let url = format!("{}/v1/chat/completions", base.trim_end_matches('/'));
        let mut req = client.post(url).json(&json!({
            "model": model,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": message }
            ]
        }));
        if let Some(key) = api_key {
            req = req.bearer_auth(key);
        }
        let res = req.send().await.map_err(|e| AppError::Connection {
            message: format!("ai provider: {e}"),
            retryable: true,
        })?;
        let v: Value = res.json().await.map_err(|e| AppError::Internal {
            message: e.to_string(),
        })?;
        v["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("No response")
            .to_string()
    };

    let now = chrono::Utc::now().timestamp_millis();
    let conv_id = if let Some(cid) = conversation_id {
        cid
    } else {
        let cid = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO ai_conversations (id, host_id, title, created_at, updated_at) VALUES (?, NULL, ?, ?, ?)",
        )
        .bind(&cid)
        .bind(message.chars().take(48).collect::<String>())
        .bind(now)
        .bind(now)
        .execute(state.vault.pool())
        .await
        .map_err(db)?;
        cid
    };

    for (role, content) in [("user", message.as_str()), ("assistant", reply.as_str())] {
        let mid = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO ai_messages (id, conversation_id, role, content, tokens, created_at) VALUES (?, ?, ?, ?, NULL, ?)",
        )
        .bind(&mid)
        .bind(&conv_id)
        .bind(role)
        .bind(content)
        .bind(now)
        .execute(state.vault.pool())
        .await
        .map_err(db)?;
    }

    Ok(json!({ "conversationId": conv_id, "reply": reply }))
}

#[tauri::command]
pub async fn ai_explain_command(
    state: State<'_, Arc<AppState>>,
    command: String,
) -> Result<Value, AppError> {
    ai_send(
        state,
        format!("Explain this Linux/shell command briefly and warn about dangers:\n`{command}`"),
        Some("You explain shell commands for operators.".into()),
        None,
    )
    .await
}

#[tauri::command]
pub async fn ai_generate_command(
    state: State<'_, Arc<AppState>>,
    goal: String,
) -> Result<Value, AppError> {
    ai_send(
        state,
        format!("Generate a safe shell command for: {goal}\nReturn only the command and a one-line explanation."),
        Some("You generate shell commands. Prefer non-destructive flags.".into()),
        None,
    )
    .await
}
