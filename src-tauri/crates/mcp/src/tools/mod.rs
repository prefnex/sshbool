//! Tools module defining tool definitions and dispatchers.

pub mod dangerous;
pub mod safe;
pub mod write;

use crate::approval::{gate_dangerous_tool, gate_write_tool, ToolCallContext};
use crate::error::McpError;
use crate::runtime::McpRuntimeState;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub tier: String,
    pub input_schema: Value,
}

pub use dangerous::{
    dangerous_tools, execute_dangerous_tool, read_task_logs_tool, validate_dangerous_tool,
};
pub use safe::execute_safe_tool;
pub use write::{execute_write_tool, validate_write_tool, write_tools};

/// Read-only tools available in every mode.
pub fn safe_tools() -> Vec<ToolDefinition> {
    let mut list = safe::safe_tools();
    list.push(read_task_logs_tool());
    list
}

/// Returns available tools for a client mode.
pub fn get_tools_for_mode(mode: &str) -> Vec<ToolDefinition> {
    match mode {
        "read_only" => safe_tools(),
        "assisted" => {
            let mut list = safe_tools();
            list.extend(write_tools());
            list
        }
        "full" => {
            let mut list = safe_tools();
            list.extend(write_tools());
            list.extend(dangerous_tools());
            list
        }
        _ => safe_tools(),
    }
}

fn tier_for_tool(tool_name: &str) -> Option<&'static str> {
    if dangerous_tools().iter().any(|t| t.name == tool_name) {
        Some("dangerous")
    } else if write_tools().iter().any(|t| t.name == tool_name) {
        Some("write")
    } else if safe_tools().iter().any(|t| t.name == tool_name) {
        Some("safe")
    } else {
        None
    }
}

/// Main entry point for dispatching a tool call by name.
pub async fn dispatch_tool_call(
    ctx: &ToolCallContext,
    tool_name: &str,
    args: &Value,
) -> Result<Value, McpError> {
    if ctx.runtime.is_vault_locked() {
        return Err(McpError::VaultLocked);
    }
    if ctx.runtime.is_kill_switch_active() {
        return Err(McpError::McpStopped);
    }

    let available_tools = get_tools_for_mode(&ctx.mode);
    if !available_tools.iter().any(|t| t.name == tool_name) {
        return Err(McpError::ToolNotAvailable(format!(
            "TOOL_NOT_AVAILABLE: Tool '{tool_name}' is not available in mode '{}'",
            ctx.mode
        )));
    }

    if dangerous_tools().iter().any(|t| t.name == tool_name) {
        validate_dangerous_tool(&ctx.pool, &ctx.client_id, tool_name, args).await?;
        let host_id = crate::scope::resolve_tool_host_id(
            &ctx.pool,
            &ctx.runtime.sessions,
            &ctx.client_id,
            args,
        )
        .await?;
        let grant =
            crate::scope::resolve_host_in_scope(&ctx.pool, &ctx.client_id, &host_id).await?;
        if !grant.exec_allowed {
            return Err(McpError::CapabilityNotGranted(format!(
                "Running commands is not allowed on host {host_id} for this client"
            )));
        }
        let _gate = gate_dangerous_tool(ctx, tool_name, args, &host_id).await?;
        execute_dangerous_tool(ctx, tool_name, args, &host_id).await
    } else if write_tools().iter().any(|t| t.name == tool_name) {
        validate_write_tool(&ctx.pool, &ctx.client_id, tool_name, args).await?;
        let host_id = crate::scope::resolve_tool_host_id(
            &ctx.pool,
            &ctx.runtime.sessions,
            &ctx.client_id,
            args,
        )
        .await?;
        let grant =
            crate::scope::resolve_host_in_scope(&ctx.pool, &ctx.client_id, &host_id).await?;
        // chown/kill run a command, so they need both capabilities.
        let needs_exec = matches!(tool_name, "chown_path" | "kill_process");
        if !grant.write_allowed || (needs_exec && !grant.exec_allowed) {
            return Err(McpError::CapabilityNotGranted(format!(
                "Changing files or processes is not allowed on host {host_id} for this client"
            )));
        }
        if tool_name == "edit_file_delta" {
            // Refuse edits that cannot apply before bothering the user with an approval.
            if let (Some(exec), Some(path), Some(target), Some(replacement)) = (
                ctx.executor(),
                args.get("path").and_then(|v| v.as_str()),
                args.get("target_content").and_then(|v| v.as_str()),
                args.get("replacement_content").and_then(|v| v.as_str()),
            ) {
                let replace_all = args
                    .get("replace_all")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let (content, _) = exec.sftp_read_full(&host_id, path).await?;
                write::apply_edit(&content, target, replacement, replace_all)?;
            }
        }
        let _gate = gate_write_tool(ctx, tool_name, args, &host_id).await?;
        execute_write_tool(ctx, tool_name, args, &host_id).await
    } else if tool_name == "read_task_logs" {
        dangerous::read_task_logs(ctx, args).await
    } else {
        execute_safe_tool(ctx, tool_name, args).await
    }
}

/// Helper for building a default tool call context in tests.
pub fn test_tool_context(pool: sqlx::SqlitePool, client_id: &str, mode: &str) -> ToolCallContext {
    ToolCallContext {
        pool,
        client_id: client_id.to_string(),
        client_name: "TestClient".to_string(),
        mode: mode.to_string(),
        session_handle: None,
        notifier: None,
        approval_timeout_ms: 60_000,
        runtime: McpRuntimeState::global(),
    }
}

pub fn tool_risk_tier(tool_name: &str) -> Option<&'static str> {
    tier_for_tool(tool_name)
}

pub fn exec_show_terminal(args: &Value) -> bool {
    args.get("show_terminal")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub fn exec_timeout_ms(args: &Value) -> u64 {
    args.get("timeout_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(60)
        .clamp(1, 600)
        .saturating_mul(1000)
}
