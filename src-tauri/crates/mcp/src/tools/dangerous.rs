//! DANGEROUS tier tools. Every call needs explicit human approval in SSHBool (no session grants).

use super::ToolDefinition;
use crate::approval::ToolCallContext;
use crate::error::McpError;
use crate::policy::obfuscation::detect_obfuscation;
use crate::policy::risk::classify_command;
use crate::scope::resolve_host_in_scope;
use crate::util::{
    heredoc_delimiter, opt_str, req_str, shell_quote, validate_path, validate_token,
};
use regex::Regex;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::sync::OnceLock;

/// Remote directory for background task logs and pid files.
const TASK_DIR: &str = "/tmp/sshbool-mcp";

fn def(name: &str, description: &str, input_schema: Value) -> ToolDefinition {
    ToolDefinition {
        name: name.into(),
        description: description.into(),
        tier: "dangerous".into(),
        input_schema,
    }
}

const REASON: &str = "Why this is needed — shown to the user in the approval dialog (required)";

pub fn dangerous_tools() -> Vec<ToolDefinition> {
    vec![
        def(
            "exec_command",
            "Run a shell command on a host and return stdout, stderr and exit_code. Requires the \
             user's approval in SSHBool for every call. Prefer the read-only tools when they suffice.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "session_handle": { "type": "string", "description": "Alternative to host_id" },
                    "command": { "type": "string" },
                    "cwd": { "type": "string", "description": "Working directory" },
                    "reason": { "type": "string", "description": REASON },
                    "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 600, "default": 60 }
                },
                "required": ["command", "reason"]
            }),
        ),
        def(
            "exec_script",
            "Run a multi-line script on a host (piped to the interpreter's stdin). Requires approval.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "script_content": { "type": "string" },
                    "interpreter": { "type": "string", "default": "bash", "description": "e.g. bash, sh, python3" },
                    "reason": { "type": "string", "description": REASON },
                    "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 600, "default": 60 }
                },
                "required": ["host_id", "script_content", "reason"]
            }),
        ),
        def(
            "run_background_task",
            "Start a long-running command in the background (detached from the session). Returns a \
             task_id for read_task_logs / cancel_task. Requires approval.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "command": { "type": "string" },
                    "reason": { "type": "string", "description": REASON }
                },
                "required": ["host_id", "command", "reason"]
            }),
        ),
        def(
            "cancel_task",
            "Stop a background task started with run_background_task. Requires approval.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "task_id": { "type": "string" },
                    "reason": { "type": "string", "description": REASON }
                },
                "required": ["host_id", "task_id", "reason"]
            }),
        ),
        def(
            "install_package",
            "Install a system package with the host's package manager (apt/dnf/yum/pacman/apk/zypper). Requires approval.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "package_name": { "type": "string" },
                    "reason": { "type": "string", "description": REASON }
                },
                "required": ["host_id", "package_name", "reason"]
            }),
        ),
        def(
            "restart_service",
            "Restart, reload, start or stop a systemd unit and return its status. Requires approval.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "unit": { "type": "string", "description": "e.g. nginx.service" },
                    "action": { "type": "string", "enum": ["restart", "reload", "start", "stop"], "default": "restart" },
                    "reason": { "type": "string", "description": REASON }
                },
                "required": ["host_id", "unit", "reason"]
            }),
        ),
        def(
            "reboot_host",
            "Reboot the host. The SSH session will drop. Requires approval.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "reason": { "type": "string", "description": REASON }
                },
                "required": ["host_id", "reason"]
            }),
        ),
        def(
            "k8s_apply",
            "kubectl apply a manifest on the host (Secret manifests are refused). Requires approval.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "manifest_yaml": { "type": "string" },
                    "namespace": { "type": "string" },
                    "reason": { "type": "string", "description": REASON }
                },
                "required": ["host_id", "manifest_yaml", "reason"]
            }),
        ),
    ]
}

/// `read_task_logs` only reads a log file the agent's own task created, so it is SAFE tier.
pub fn read_task_logs_tool() -> ToolDefinition {
    ToolDefinition {
        name: "read_task_logs".into(),
        description: "Read the output of a background task started with run_background_task, and \
                      whether it is still running."
            .into(),
        tier: "safe".into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "host_id": { "type": "string" },
                "task_id": { "type": "string" },
                "lines": { "type": "integer", "minimum": 1, "maximum": 5000, "default": 200 }
            },
            "required": ["host_id", "task_id"]
        }),
    }
}

fn require_reason(args: &Value) -> Result<(), McpError> {
    let reason = args
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if reason.is_empty() {
        return Err(McpError::InvalidArguments(
            "Missing required 'reason' (shown to the user when asking for approval)".into(),
        ));
    }
    Ok(())
}

fn secret_manifest_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?im)^\s*kind\s*:\s*["']?secret["']?\s*$"#).expect("regex"))
}

fn deny_catastrophic(text: &str) -> Result<(), McpError> {
    let signals = detect_obfuscation(text);
    if !signals.is_empty() {
        let reasons: Vec<String> = signals.iter().map(|s| s.reason.to_string()).collect();
        return Err(McpError::HardDeny(format!(
            "EVASION_DENIED: Command contains obfuscation: {}",
            reasons.join(", ")
        )));
    }
    let lower = text.to_lowercase();
    if lower.contains("rm -rf /") || lower.contains("rm -rf /*") || lower.contains("mkfs") {
        let risk = classify_command(text);
        return Err(McpError::HardDeny(format!(
            "HARD_DENY: Catastrophic command blocked by policy: {}",
            risk.reasons.join(", ")
        )));
    }
    Ok(())
}

fn task_id_arg(args: &Value) -> Result<&str, McpError> {
    let id = req_str(args, "task_id")?;
    // Task ids are UUIDs we minted; anything else cannot name one of our files.
    if id.len() > 64 || !id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err(McpError::InvalidArguments("Unknown task_id".into()));
    }
    Ok(id)
}

/// Pre-approval validation for DANGEROUS tools (hard invariants, obfuscation, scope).
pub async fn validate_dangerous_tool(
    pool: &SqlitePool,
    client_id: &str,
    tool_name: &str,
    args: &Value,
) -> Result<(), McpError> {
    if let Some(host_id) = args.get("host_id").and_then(|v| v.as_str()) {
        resolve_host_in_scope(pool, client_id, host_id).await?;
    }
    require_reason(args)?;

    match tool_name {
        "exec_command" | "run_background_task" => {
            let cmd = req_str(args, "command")?;
            deny_catastrophic(cmd)?;
            if let Some(cwd) = opt_str(args, "cwd") {
                validate_path(cwd, "cwd")?;
            }
        }
        "exec_script" => {
            deny_catastrophic(req_str(args, "script_content")?)?;
            interpreter_arg(args)?;
        }
        "cancel_task" => {
            task_id_arg(args)?;
        }
        "install_package" => {
            validate_token(
                req_str(args, "package_name")?,
                "package_name",
                &['+', ':', '=', '~'],
            )?;
        }
        "restart_service" => {
            validate_token(req_str(args, "unit")?, "unit", &['@', ':'])?;
            service_action(args)?;
        }
        "k8s_apply" => {
            let yaml = req_str(args, "manifest_yaml")?;
            if secret_manifest_re().is_match(yaml) {
                return Err(McpError::Forbidden(
                    "Applying Kubernetes Secret manifests is prohibited".into(),
                ));
            }
            if let Some(ns) = opt_str(args, "namespace") {
                validate_token(ns, "namespace", &[])?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn interpreter_arg(args: &Value) -> Result<&str, McpError> {
    let interp = opt_str(args, "interpreter").unwrap_or("bash");
    let ok = interp.len() <= 128
        && !interp.starts_with('-')
        && interp
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-'));
    if !ok {
        return Err(McpError::InvalidArguments(format!(
            "interpreter: '{interp}' is not a valid program name"
        )));
    }
    Ok(interp)
}

fn service_action(args: &Value) -> Result<&str, McpError> {
    match opt_str(args, "action").unwrap_or("restart") {
        a @ ("restart" | "reload" | "start" | "stop") => Ok(a),
        other => Err(McpError::InvalidArguments(format!(
            "action: '{other}' must be restart, reload, start or stop"
        ))),
    }
}

/// Executes a DANGEROUS tier tool call after human approval.
pub async fn execute_dangerous_tool(
    ctx: &ToolCallContext,
    tool_name: &str,
    args: &Value,
    host_id: &str,
) -> Result<Value, McpError> {
    let exec = ctx
        .executor()
        .ok_or_else(|| McpError::Internal("Remote executor unavailable".into()))?;
    let run = |command: String| {
        let exec = exec.clone();
        let host_id = host_id.to_string();
        let timeout = super::exec_timeout_ms(args);
        let show = super::exec_show_terminal(args);
        async move { exec.exec_command(&host_id, &command, show, timeout).await }
    };

    match tool_name {
        "exec_command" => {
            let command = req_str(args, "command")?;
            let cmd = match opt_str(args, "cwd") {
                Some(cwd) => format!("cd -- {} && {command}", shell_quote(cwd)),
                None => command.to_string(),
            };
            run(cmd).await
        }
        "exec_script" => {
            let script = req_str(args, "script_content")?;
            let interpreter = interpreter_arg(args)?;
            let eof = heredoc_delimiter(script);
            let flag = if interpreter.ends_with("sh") { " -s" } else { " -" };
            run(format!("{interpreter}{flag} <<'{eof}'\n{script}\n{eof}")).await
        }
        "run_background_task" => {
            let command = req_str(args, "command")?;
            let task_id = uuid::Uuid::now_v7().to_string();
            let log = format!("{TASK_DIR}/{task_id}.log");
            let pid = format!("{TASK_DIR}/{task_id}.pid");
            let inner = shell_quote(command);
            let launch = format!(
                "mkdir -p {TASK_DIR} && chmod 700 {TASK_DIR} && \
                 if command -v setsid >/dev/null 2>&1; then \
                   setsid nohup sh -c {inner} >{log} 2>&1 </dev/null & \
                 else nohup sh -c {inner} >{log} 2>&1 </dev/null & fi; \
                 echo $! >{pid}; cat {pid}"
            );
            let mut out = run(launch).await?;
            let os_pid = out["stdout"].as_str().unwrap_or("").trim().to_string();
            out["task_id"] = json!(task_id);
            out["pid"] = json!(os_pid);
            out["log_path"] = json!(log);
            Ok(out)
        }
        "cancel_task" => {
            let id = task_id_arg(args)?;
            let pid = format!("{TASK_DIR}/{id}.pid");
            run(format!(
                "test -f {pid} || {{ echo 'unknown task'; exit 1; }}; p=$(cat {pid}); \
                 kill -TERM -- -$p 2>/dev/null || kill -TERM $p && echo \"stopped $p\""
            ))
            .await
        }
        "install_package" => {
            let package = shell_quote(req_str(args, "package_name")?);
            run(format!(
                "S=''; [ \"$(id -u)\" = 0 ] || S='sudo -n'; \
                 if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive $S apt-get install -y {package}; \
                 elif command -v dnf >/dev/null; then $S dnf install -y {package}; \
                 elif command -v yum >/dev/null; then $S yum install -y {package}; \
                 elif command -v pacman >/dev/null; then $S pacman -S --noconfirm {package}; \
                 elif command -v apk >/dev/null; then $S apk add {package}; \
                 elif command -v zypper >/dev/null; then $S zypper --non-interactive install {package}; \
                 else echo 'unsupported package manager' >&2; exit 127; fi"
            ))
            .await
        }
        "restart_service" => {
            let unit = shell_quote(req_str(args, "unit")?);
            let action = service_action(args)?;
            run(format!(
                "S=''; [ \"$(id -u)\" = 0 ] || S='sudo -n'; $S systemctl {action} {unit}; rc=$?; \
                 systemctl status --no-pager --lines=15 {unit}; exit $rc"
            ))
            .await
        }
        "reboot_host" => {
            run("S=''; [ \"$(id -u)\" = 0 ] || S='sudo -n'; nohup sh -c \"sleep 1; $S reboot\" >/dev/null 2>&1 </dev/null & echo 'reboot scheduled'".into())
                .await
        }
        "k8s_apply" => {
            let yaml = req_str(args, "manifest_yaml")?;
            let ns = match opt_str(args, "namespace") {
                Some(ns) => format!(" -n {}", shell_quote(ns)),
                None => String::new(),
            };
            let eof = heredoc_delimiter(yaml);
            run(format!("kubectl apply{ns} -f - <<'{eof}'\n{yaml}\n{eof}")).await
        }
        _ => Err(McpError::ToolNotAvailable(format!(
            "Unknown dangerous tool: {tool_name}"
        ))),
    }
}

/// SAFE handler for `read_task_logs`.
pub async fn read_task_logs(ctx: &ToolCallContext, args: &Value) -> Result<Value, McpError> {
    let host_id = req_str(args, "host_id")?;
    resolve_host_in_scope(&ctx.pool, &ctx.client_id, host_id).await?;
    let id = task_id_arg(args)?;
    let lines = crate::util::opt_u64(args, "lines", 200, 1, 5000);
    let exec = ctx
        .executor()
        .ok_or_else(|| McpError::Internal("Remote executor unavailable".into()))?;
    let log = format!("{TASK_DIR}/{id}.log");
    let pid = format!("{TASK_DIR}/{id}.pid");
    let mut out = exec
        .exec_command_readonly(
            host_id,
            &format!(
                "test -f {log} || {{ echo 'unknown task' >&2; exit 1; }}; \
                 if kill -0 \"$(cat {pid} 2>/dev/null)\" 2>/dev/null; then echo '[running]'; else echo '[finished]'; fi; \
                 tail -n {lines} {log}"
            ),
            false,
            30_000,
        )
        .await?;
    if let Some(stdout) = out["stdout"].as_str().map(str::to_string) {
        let (status, rest) = stdout.split_once('\n').unwrap_or((stdout.as_str(), ""));
        out["running"] = json!(status.trim() == "[running]");
        out["stdout"] = json!(rest);
    }
    out["task_id"] = json!(id);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_manifests_are_detected() {
        assert!(secret_manifest_re().is_match("apiVersion: v1\nkind: Secret\n"));
        assert!(secret_manifest_re().is_match("kind:   \"secret\""));
        assert!(!secret_manifest_re().is_match("kind: ConfigMap\n# not a Secret"));
    }

    #[test]
    fn task_ids_are_strict() {
        assert!(task_id_arg(&json!({ "task_id": "0b4e8a2c-1d2f-4c3b-9a8e-7f6d5c4b3a21" })).is_ok());
        for bad in ["../etc/passwd", "1; reboot", "$(id)", ""] {
            assert!(task_id_arg(&json!({ "task_id": bad })).is_err(), "{bad}");
        }
    }

    #[test]
    fn interpreter_is_validated() {
        assert_eq!(interpreter_arg(&json!({})).unwrap(), "bash");
        assert!(interpreter_arg(&json!({ "interpreter": "/usr/bin/python3" })).is_ok());
        assert!(interpreter_arg(&json!({ "interpreter": "bash; rm -rf ~" })).is_err());
    }
}
