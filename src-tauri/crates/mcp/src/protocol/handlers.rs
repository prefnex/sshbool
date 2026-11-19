//! Handlers for standard MCP protocol RPC methods.

use crate::approval::nonce::hash_canonical_args;
use crate::approval::ToolCallContext;
use crate::error::McpError;
use crate::protocol::jsonrpc::{JsonRpcRequest, JsonRpcResponse};
use crate::repo::audit::record_dual_audit;
use crate::repo::calls::CallRow;
use crate::runtime::McpRuntimeState;
use crate::tools::{dispatch_tool_call, get_tools_for_mode, tool_risk_tier};
use crate::{CallLogEntry, McpNotifier};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

pub const AGENT_INSTRUCTIONS: &str = r#"You are operating through SSHBool MCP Server — the user's SSH workspace (servers, files, services, containers, Kubernetes).

HOW TO WORK:
1. Call list_hosts first. Every host tool takes a host_id from that list; hosts not listed are not available to you.
2. Prefer read-only tools (get_sysinfo, list_services, read_journal, read_file_preview, grep_files, list_containers, get_container_logs, ...). They run immediately.
3. Write tools (write_file, edit_file_delta, rm_path, ...) and dangerous tools (exec_command, exec_script, restart_service, ...) pause until the user approves them in SSHBool. Always pass a short, honest "reason"; it is shown in the approval dialog. A denial or timeout is final for that call: do not retry the same call in a loop — explain to the user what you need instead.
4. Command results contain stdout, stderr, exit_code and timed_out. A non-zero exit_code means the command failed.
5. Before editing a file, read it; use edit_file_delta with an exact, unique target_content. Pass expected_mtime (from stat_path/read_file_preview) to avoid overwriting concurrent changes.
6. Hosts marked production=true deserve extra care: explain the impact before proposing changes.

SECURITY CONTRACT:
- Never request or transmit private keys, passwords, vault contents or credential files; such paths are denied.
- Every call is checked against the client's mode and host grants, and is recorded in the user's audit log.
"#;

/// Protocol revisions this server speaks (newest first). Responses are plain JSON over HTTP,
/// which is valid for every revision listed.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Pick the client's requested revision when supported, else our newest.
pub fn negotiate_protocol_version(params: &Value) -> &'static str {
    let requested = params.get("protocolVersion").and_then(|v| v.as_str());
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .find(|v| Some(**v) == requested)
        .copied()
        .unwrap_or(SUPPORTED_PROTOCOL_VERSIONS[0])
}

/// Render a tool's JSON result as MCP `CallToolResult` content.
pub fn tool_result(value: Value) -> Value {
    let text = render_tool_text(&value);
    let mut out = json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false,
    });
    if value.is_object() {
        out["structuredContent"] = value;
    }
    out
}

/// A tool failure the agent should read and react to (MCP `isError: true`).
pub fn tool_error(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true,
    })
}

/// Command output reads best as plain text; everything else as pretty JSON.
fn render_tool_text(value: &Value) -> String {
    if let Some(stdout) = value.get("stdout").and_then(|v| v.as_str()) {
        let mut text = stdout.trim_end().to_string();
        if let Some(stderr) = value.get("stderr").and_then(|v| v.as_str()) {
            if !stderr.trim().is_empty() {
                text.push_str("\n--- stderr ---\n");
                text.push_str(stderr.trim_end());
            }
        }
        let mut meta = Vec::new();
        if let Some(code) = value.get("exit_code").and_then(|v| v.as_i64()) {
            meta.push(format!("exit_code={code}"));
        }
        if let Some(sig) = value.get("exit_signal").and_then(|v| v.as_str()) {
            meta.push(format!("signal={sig}"));
        }
        if value.get("timed_out").and_then(|v| v.as_bool()) == Some(true) {
            meta.push("timed_out=true".into());
        }
        if value.get("truncated").and_then(|v| v.as_bool()) == Some(true) {
            meta.push("output_truncated=true".into());
        }
        for key in ["task_id", "log_path", "running"] {
            if let Some(v) = value.get(key) {
                if !v.is_null() {
                    meta.push(format!(
                        "{key}={}",
                        v.as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| v.to_string())
                    ));
                }
            }
        }
        if !meta.is_empty() {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&format!("[{}]", meta.join(" ")));
        }
        return text;
    }
    if let Some(content) = value.get("content").and_then(|v| v.as_str()) {
        // read_file_preview: the file itself, then its metadata.
        let mut meta = value.clone();
        if let Some(obj) = meta.as_object_mut() {
            obj.remove("content");
        }
        return format!("{content}\n[{}]", meta);
    }
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

pub async fn handle_protocol_request(
    pool: &SqlitePool,
    client_id: &str,
    client_name: &str,
    mode: &str,
    notifier: &Arc<dyn McpNotifier>,
    approval_timeout_ms: u64,
    req: JsonRpcRequest,
) -> JsonRpcResponse {
    let runtime = McpRuntimeState::global();

    let call_id = Uuid::now_v7().to_string();
    let started = std::time::Instant::now();
    let now = chrono::Utc::now().timestamp_millis();
    let id = req.id.clone();

    let tool_name = if req.method == "tools/call" {
        req.params["name"].as_str().map(str::to_string)
    } else {
        None
    };
    let tool_args = if req.method == "tools/call" {
        Some(&req.params["arguments"])
    } else {
        None
    };
    let host_id = tool_args
        .and_then(|a| a.get("host_id"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let host_label = if let Some(ref hid) = host_id {
        sqlx::query_scalar::<_, String>("SELECT label FROM hosts WHERE id = ?")
            .bind(hid)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    let result = match req.method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": negotiate_protocol_version(&req.params),
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": "sshbool",
                "title": "SSHBool MCP Server",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": AGENT_INSTRUCTIONS
        })),
        "ping" => return JsonRpcResponse::success(id, json!({})),
        "tools/list" => {
            let tool_objs: Vec<Value> = get_tools_for_mode(mode)
                .into_iter()
                .map(|t| {
                    let read_only = t.tier == "safe";
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                        "annotations": {
                            "readOnlyHint": read_only,
                            "destructiveHint": t.tier == "dangerous",
                            "openWorldHint": true
                        }
                    })
                })
                .collect();
            return JsonRpcResponse::success(id, json!({ "tools": tool_objs }));
        }
        // Not offered (no capability advertised), but answer politely for clients that ask anyway.
        "resources/list" => return JsonRpcResponse::success(id, json!({ "resources": [] })),
        "resources/templates/list" => {
            return JsonRpcResponse::success(id, json!({ "resourceTemplates": [] }))
        }
        "prompts/list" => return JsonRpcResponse::success(id, json!({ "prompts": [] })),
        "tools/call" => {
            let name = tool_name.clone().unwrap_or_default();
            let args = &req.params["arguments"];
            if name.is_empty() {
                Err(McpError::InvalidArguments("Missing tool name".into()))
            } else if runtime.is_vault_locked() {
                Err(McpError::VaultLocked)
            } else if runtime.is_kill_switch_active() {
                Err(McpError::McpStopped)
            } else if let Err(e) =
                crate::policy::enforce::enforce_call_budget(pool, client_id).await
            {
                Err(e)
            } else {
                let ctx = ToolCallContext {
                    pool: pool.clone(),
                    client_id: client_id.to_string(),
                    client_name: client_name.to_string(),
                    mode: mode.to_string(),
                    session_handle: req.params["sessionHandle"]
                        .as_str()
                        .or_else(|| args.get("session_handle").and_then(|v| v.as_str()))
                        .map(str::to_string),
                    notifier: Some(notifier.clone()),
                    approval_timeout_ms,
                    runtime: runtime.clone(),
                };
                dispatch_tool_call(&ctx, &name, args).await
            }
        }
        _ => {
            return JsonRpcResponse::error(id, -32601, format!("Method '{}' not found", req.method))
        }
    };

    let duration_ms = started.elapsed().as_millis() as i64;
    let (decision, err_code, res_val) = match &result {
        Ok(v) => ("allow", None, Some(v.clone())),
        Err(e) => {
            let code = match e {
                McpError::ToolNotAvailable(_) => "-32601",
                McpError::InvalidArguments(_) => "-32602",
                McpError::SensitivePathDenied(_) => "SENSITIVE_PATH_DENIED",
                McpError::ApprovalDenied(_) => "APPROVAL_DENIED",
                McpError::VaultLocked => "VAULT_LOCKED",
                McpError::McpStopped => "MCP_STOPPED",
                McpError::StaleMtime(_) => "STALE_MTIME",
                McpError::HardDeny(_) => "HARD_DENY",
                _ => "-32603",
            };
            ("deny", Some(code.to_string()), None)
        }
    };

    let risk_tier = tool_name
        .as_deref()
        .and_then(tool_risk_tier)
        .unwrap_or("safe");
    let args_hash = tool_args.map(|a| hex::encode(hash_canonical_args(a)));
    let command_preview = tool_args.map(preview_args);

    let call_row = CallRow {
        id: call_id.clone(),
        at: now,
        client_id: Some(client_id.to_string()),
        client_name: Some(client_name.to_string()),
        host_id: host_id.clone(),
        host_label: host_label.clone(),
        session_handle: req.params["sessionHandle"].as_str().map(str::to_string),
        tool: tool_name.clone().unwrap_or_else(|| req.method.clone()),
        args_hash,
        command_preview,
        risk_tier: Some(risk_tier.into()),
        risk_reasons: None,
        ruleset_version: Some(1),
        decision: decision.into(),
        approval_id: None,
        grant_id: None,
        duration_ms: Some(duration_ms),
        result_bytes: res_val.as_ref().map(|v| v.to_string().len() as i64),
        truncated: 0,
        error_code: err_code.clone(),
        reason: tool_args
            .and_then(|a| a.get("reason"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
    };

    let audit_meta = json!({
        "client_id": client_id,
        "tool": tool_name,
        "host_id": host_id,
        "decision": decision,
        "error_code": err_code,
        "duration_ms": duration_ms,
    });

    if let Err(audit_err) = record_dual_audit(
        pool,
        &call_row,
        "mcp.tool_call",
        tool_name.as_deref(),
        decision,
        Some(audit_meta),
    )
    .await
    {
        return JsonRpcResponse::error(id, -32603, format!("Audit write failed: {audit_err}"));
    }

    // Keep what the tool printed so the user can follow results in the Activity view.
    // Best-effort: a failure here must not fail a call that already ran.
    if req.method == "tools/call" {
        let output = res_val.as_ref().map(|v| v.to_string());
        let error_text = result.as_ref().err().map(agent_message);
        if let Err(e) = crate::repo::calls::record_call_output(
            pool,
            &call_id,
            output.as_deref(),
            error_text.as_deref(),
        )
        .await
        {
            tracing::warn!("failed to store MCP call output: {e}");
        }
    }

    notifier.call_recorded(&CallLogEntry {
        id: call_id,
        at: now,
        client_id: Some(client_id.to_string()),
        client_name: Some(client_name.to_string()),
        host_id,
        host_label,
        tool: tool_name.unwrap_or_else(|| req.method.clone()),
        risk_tier: Some(risk_tier.into()),
        decision: decision.into(),
        duration_ms: Some(duration_ms),
        result_bytes: res_val.as_ref().map(|v| v.to_string().len() as i64),
        error_code: err_code,
        command_preview: call_row.command_preview.clone(),
        reason: call_row.reason.clone(),
    });

    match (req.method.as_str(), result) {
        ("tools/call", Ok(val)) => JsonRpcResponse::success(id, tool_result(val)),
        // Tool failures go back as results so the agent can read the reason and adapt.
        ("tools/call", Err(e)) => JsonRpcResponse::success(id, tool_error(&agent_message(&e))),
        (_, Ok(val)) => JsonRpcResponse::success(id, val),
        (_, Err(e)) => JsonRpcResponse::error(id, -32603, e.to_string()),
    }
}

/// Error text for the agent, with a hint on what to do next where one helps.
fn agent_message(e: &McpError) -> String {
    let hint = match e {
        McpError::VaultLocked => " — ask the user to unlock SSHBool, then retry.",
        McpError::McpStopped => " — the user activated the MCP kill switch; stop and ask them.",
        McpError::ApprovalDenied(_) => {
            " — the user did not approve this call. Do not retry it automatically; explain what you need."
        }
        McpError::HostNotInScope(_) => " — call list_hosts to see the hosts you can use.",
        McpError::CapabilityNotGranted(_) => {
            " — the user can allow this per host in SSHBool → MCP → Clients."
        }
        McpError::ToolNotAvailable(_) => " — call tools/list to see the tools available in this client's mode.",
        McpError::SessionExpired(_) => " — call open_session again.",
        McpError::StaleMtime(_) => " — the file changed since you read it; read it again before editing.",
        McpError::RateLimited { .. } => " — wait before retrying.",
        _ => "",
    };
    format!("{e}{hint}")
}

fn preview_args(args: &Value) -> String {
    let raw = args.to_string();
    let redacted = infrastructure::redact::redact(&raw);
    crate::util::truncate_utf8(&redacted, 512).to_string()
}
