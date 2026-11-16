//! SAFE (read-only) tools. They never change remote state and need no approval, so every
//! value interpolated into a shell command is validated and quoted here.

use crate::approval::ToolCallContext;
use crate::error::McpError;
use crate::policy::paths::is_sensitive_read_path;
use crate::scope::{list_hosts_in_scope, resolve_host_in_scope};
use crate::util::{
    opt_str, opt_u64, req_str, shell_quote, strip_ansi, validate_path, validate_token,
};
use serde_json::{json, Value};

use super::ToolDefinition;

const READ_TIMEOUT_MS: u64 = 30_000;
const SEARCH_TIMEOUT_MS: u64 = 90_000;
/// Hidden from grep results even when the agent searches a parent directory.
const GREP_EXCLUDES: &str = "--exclude-dir=.ssh --exclude-dir=.gnupg --exclude-dir=.aws \
--exclude=shadow --exclude=gshadow --exclude='*.pem' --exclude='*.key' --exclude='*.p12' \
--exclude='*.pfx' --exclude='id_*' --exclude='.env*' --exclude=.netrc --exclude=.pgpass \
--exclude=.git-credentials";

fn def(name: &str, description: &str, input_schema: Value) -> ToolDefinition {
    ToolDefinition {
        name: name.into(),
        description: description.into(),
        tier: "safe".into(),
        input_schema,
    }
}

fn host_only() -> Value {
    json!({
        "type": "object",
        "properties": { "host_id": { "type": "string", "description": "Host id from list_hosts" } },
        "required": ["host_id"]
    })
}

pub fn safe_tools() -> Vec<ToolDefinition> {
    vec![
        def(
            "ping",
            "Check that the SSHBool MCP server is reachable.",
            json!({ "type": "object", "properties": {} }),
        ),
        def(
            "list_hosts",
            "List the SSH hosts this client may use (id, label, hostname, user, production flag and \
             whether exec/write is allowed). Start here: every other host tool takes a host_id from this list.",
            json!({ "type": "object", "properties": {} }),
        ),
        def(
            "get_host_details",
            "Get connection metadata for one host in scope (no credentials).",
            host_only(),
        ),
        def(
            "open_session",
            "Open (or reuse) an SSH terminal session on a host and get a session_handle for \
             get_session_info/read_scrollback. Set show_terminal=true to show the terminal to the user.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "reason": { "type": "string", "description": "Why the session is needed (shown to the user)" },
                    "show_terminal": { "type": "boolean", "default": false }
                },
                "required": ["host_id"]
            }),
        ),
        def(
            "list_sessions",
            "List this client's open session handles.",
            json!({ "type": "object", "properties": {} }),
        ),
        def(
            "get_session_info",
            "Get details for a session handle returned by open_session.",
            json!({
                "type": "object",
                "properties": { "session_handle": { "type": "string" } },
                "required": ["session_handle"]
            }),
        ),
        def(
            "read_scrollback",
            "Read the recent terminal output (ANSI stripped) of a session opened with open_session.",
            json!({
                "type": "object",
                "properties": {
                    "session_handle": { "type": "string" },
                    "lines": { "type": "integer", "minimum": 1, "maximum": 2000, "default": 200 }
                },
                "required": ["session_handle"]
            }),
        ),
        def(
            "list_dir",
            "List a remote directory over SFTP (name, path, isDir, size, mode, mtime).",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "path": { "type": "string", "description": "Absolute path, e.g. /var/log" }
                },
                "required": ["host_id", "path"]
            }),
        ),
        def(
            "stat_path",
            "Get metadata for a remote file or directory over SFTP. Use the returned mtime as \
             expected_mtime when writing to avoid overwriting concurrent changes.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "path": { "type": "string" }
                },
                "required": ["host_id", "path"]
            }),
        ),
        def(
            "read_file_preview",
            "Read a remote text file over SFTP: the first max_bytes, or the last max_bytes with \
             from=\"end\" (useful for logs). Works on files of any size; credential files are denied.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "path": { "type": "string" },
                    "max_bytes": { "type": "integer", "minimum": 1, "maximum": 262144, "default": 16384 },
                    "from": { "type": "string", "enum": ["start", "end"], "default": "start" }
                },
                "required": ["host_id", "path"]
            }),
        ),
        def(
            "find_files",
            "Find files by name (shell glob, e.g. '*.conf') under a directory.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "path": { "type": "string" },
                    "pattern": { "type": "string", "description": "Name glob, e.g. nginx*.conf" },
                    "max_depth": { "type": "integer", "minimum": 1, "maximum": 20, "default": 6 },
                    "type": { "type": "string", "enum": ["any", "file", "dir"], "default": "any" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 200 }
                },
                "required": ["host_id", "path", "pattern"]
            }),
        ),
        def(
            "grep_files",
            "Search file contents recursively (grep). Literal match by default; set regex=true for \
             extended regular expressions. Credential files are excluded.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "path": { "type": "string" },
                    "query": { "type": "string" },
                    "regex": { "type": "boolean", "default": false },
                    "ignore_case": { "type": "boolean", "default": false },
                    "include": { "type": "string", "description": "Only files matching this glob, e.g. *.py" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 2000, "default": 200 }
                },
                "required": ["host_id", "path", "query"]
            }),
        ),
        def(
            "get_sysinfo",
            "System summary: hostname, OS, kernel, uptime/load, CPU count, memory and disk usage.",
            host_only(),
        ),
        def(
            "list_processes",
            "List running processes sorted by CPU (or memory) usage.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "sort": { "type": "string", "enum": ["cpu", "mem"], "default": "cpu" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 }
                },
                "required": ["host_id"]
            }),
        ),
        def(
            "list_services",
            "List systemd services and their state. state=failed shows only failed units.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "state": { "type": "string", "enum": ["all", "running", "failed"], "default": "all" }
                },
                "required": ["host_id"]
            }),
        ),
        def(
            "read_journal",
            "Read systemd journal entries, optionally for one unit, since a time, or at/above a priority.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "unit": { "type": "string", "description": "e.g. nginx.service" },
                    "lines": { "type": "integer", "minimum": 1, "maximum": 5000, "default": 200 },
                    "since": { "type": "string", "description": "journalctl --since value, e.g. '1 hour ago'" },
                    "priority": { "type": "string", "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"] }
                },
                "required": ["host_id"]
            }),
        ),
        def(
            "list_containers",
            "List Docker containers (running and stopped) as JSON lines.",
            host_only(),
        ),
        def(
            "get_container_logs",
            "Get the last log lines (stdout+stderr) of a Docker container.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "container_id": { "type": "string", "description": "Container id or name" },
                    "tail": { "type": "integer", "minimum": 1, "maximum": 5000, "default": 200 },
                    "since": { "type": "string", "description": "e.g. 10m, 2h, or an RFC3339 timestamp" }
                },
                "required": ["host_id", "container_id"]
            }),
        ),
        def(
            "inspect_container",
            "Inspect a Docker container (state, mounts, ports, network). Environment values are redacted.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "container_id": { "type": "string" }
                },
                "required": ["host_id", "container_id"]
            }),
        ),
        def("list_images", "List Docker images as JSON lines.", host_only()),
        def(
            "list_k8s_pods",
            "List Kubernetes pods (kubectl on the host) in a namespace, or all namespaces.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "namespace": { "type": "string", "default": "default" },
                    "all_namespaces": { "type": "boolean", "default": false }
                },
                "required": ["host_id"]
            }),
        ),
        def(
            "list_k8s_deployments",
            "List Kubernetes deployments (kubectl on the host) in a namespace, or all namespaces.",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "namespace": { "type": "string", "default": "default" },
                    "all_namespaces": { "type": "boolean", "default": false }
                },
                "required": ["host_id"]
            }),
        ),
        def(
            "get_k8s_logs",
            "Get Kubernetes pod logs (kubectl on the host).",
            json!({
                "type": "object",
                "properties": {
                    "host_id": { "type": "string" },
                    "pod_name": { "type": "string" },
                    "namespace": { "type": "string", "default": "default" },
                    "container": { "type": "string" },
                    "tail": { "type": "integer", "minimum": 1, "maximum": 5000, "default": 200 },
                    "previous": { "type": "boolean", "default": false, "description": "Logs of the previous (crashed) container" }
                },
                "required": ["host_id", "pod_name"]
            }),
        ),
        def(
            "list_snippets",
            "List the user's saved command snippets (name, command body, language, tags).",
            json!({
                "type": "object",
                "properties": { "query": { "type": "string", "description": "Optional filter" } }
            }),
        ),
        def(
            "search_global",
            "Search hosts in scope (label/hostname) and saved snippets.",
            json!({
                "type": "object",
                "properties": { "query": { "type": "string" } },
                "required": ["query"]
            }),
        ),
    ]
}

async fn exec_ro(
    ctx: &ToolCallContext,
    host_id: &str,
    command: &str,
    timeout_ms: u64,
) -> Result<Value, McpError> {
    let exec = ctx
        .executor()
        .ok_or_else(|| McpError::Internal("Remote executor unavailable".into()))?;
    exec.exec_command_readonly(host_id, command, false, timeout_ms)
        .await
}

/// `host_id` argument, checked against the client's scope.
async fn scoped_host<'a>(ctx: &ToolCallContext, args: &'a Value) -> Result<&'a str, McpError> {
    let host_id = req_str(args, "host_id")?;
    resolve_host_in_scope(&ctx.pool, &ctx.client_id, host_id).await?;
    Ok(host_id)
}

/// A path that will be passed to a command: no leading '-' so it can't become an option.
fn command_path<'a>(args: &'a Value, key: &str) -> Result<&'a str, McpError> {
    let path = validate_path(req_str(args, key)?, key)?;
    if path.starts_with('-') {
        return Err(McpError::InvalidArguments(format!(
            "{key}: must not start with '-'"
        )));
    }
    Ok(path)
}

fn k8s_namespace_flag(args: &Value) -> Result<String, McpError> {
    if args.get("all_namespaces").and_then(|v| v.as_bool()) == Some(true) {
        return Ok("--all-namespaces".into());
    }
    let ns = validate_token(
        opt_str(args, "namespace").unwrap_or("default"),
        "namespace",
        &[],
    )?;
    Ok(format!("-n {}", shell_quote(ns)))
}

/// Replace values in `Config.Env` (`KEY=value`) with a placeholder.
fn redact_container_env(inspect: &mut Value) {
    if let Some(items) = inspect.as_array_mut() {
        for item in items {
            if let Some(env) = item
                .get_mut("Config")
                .and_then(|c| c.get_mut("Env"))
                .and_then(|e| e.as_array_mut())
            {
                for var in env.iter_mut() {
                    if let Some(s) = var.as_str() {
                        let key = s.split('=').next().unwrap_or(s);
                        *var = Value::String(format!("{key}=<redacted>"));
                    }
                }
            }
        }
    }
}

async fn host_rows(ctx: &ToolCallContext, filter: Option<&str>) -> Result<Vec<Value>, McpError> {
    let ids = list_hosts_in_scope(&ctx.pool, &ctx.client_id).await?;
    let mut hosts = Vec::new();
    for id in ids {
        let row = sqlx::query_as::<_, (String, String, i64, Option<String>, i64)>(
            "SELECT label, hostname, port, username, production FROM hosts \
             WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(&id)
        .fetch_optional(&ctx.pool)
        .await?;
        let Some((label, hostname, port, username, production)) = row else {
            continue;
        };
        if let Some(q) = filter {
            let q = q.to_lowercase();
            if !label.to_lowercase().contains(&q) && !hostname.to_lowercase().contains(&q) {
                continue;
            }
        }
        let grant = resolve_host_in_scope(&ctx.pool, &ctx.client_id, &id).await?;
        hosts.push(json!({
            "host_id": id,
            "label": label,
            "hostname": hostname,
            "port": port,
            "username": username,
            "production": production != 0,
            "exec_allowed": grant.exec_allowed,
            "write_allowed": grant.write_allowed,
        }));
    }
    Ok(hosts)
}

async fn snippet_rows(ctx: &ToolCallContext, filter: Option<&str>) -> Result<Vec<Value>, McpError> {
    let like = format!("%{}%", filter.unwrap_or("").to_lowercase());
    let rows = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>)>(
        "SELECT id, name, body, language, tags_json FROM snippets \
         WHERE lower(name) LIKE ? OR lower(body) LIKE ? \
         ORDER BY is_favorite DESC, usage_count DESC, name LIMIT 200",
    )
    .bind(&like)
    .bind(&like)
    .fetch_all(&ctx.pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, body, language, tags)| {
            json!({
                "id": id,
                "name": name,
                "body": body,
                "language": language,
                "tags": tags.and_then(|t| serde_json::from_str::<Value>(&t).ok()),
            })
        })
        .collect())
}

/// Dispatches execution of a SAFE tool call.
pub async fn execute_safe_tool(
    ctx: &ToolCallContext,
    tool_name: &str,
    args: &Value,
) -> Result<Value, McpError> {
    let client_id = &ctx.client_id;

    match tool_name {
        "ping" => Ok(json!({ "status": "ok", "timestamp": chrono::Utc::now().timestamp_millis() })),
        "list_hosts" => {
            let hosts = host_rows(ctx, None).await?;
            let hint = if hosts.is_empty() {
                Some("No hosts are shared with this client yet. Ask the user to grant hosts in SSHBool → MCP → Clients.")
            } else {
                None
            };
            Ok(json!({ "hosts": hosts, "hint": hint }))
        }
        "get_host_details" => {
            let host_id = scoped_host(ctx, args).await?;
            let host = host_rows(ctx, None)
                .await?
                .into_iter()
                .find(|h| h["host_id"] == host_id);
            Ok(host.unwrap_or_else(|| json!({ "host_id": host_id })))
        }
        "open_session" => {
            let host_id = scoped_host(ctx, args).await?;
            let show_terminal = args
                .get("show_terminal")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let exec = ctx
                .executor()
                .ok_or_else(|| McpError::Internal("Remote executor unavailable".into()))?;
            let pane_info = exec.open_session(host_id, show_terminal).await?;
            let idle_ttl_ms = 10 * 60 * 1000;
            let max_ttl_ms = 60 * 60 * 1000;
            let session_handle = ctx.runtime.sessions.create_handle(
                client_id.to_string(),
                host_id.to_string(),
                idle_ttl_ms,
                max_ttl_ms,
            );
            if let Some(pane_id) = pane_info["pane_id"].as_str() {
                ctx.runtime.sessions.attach_pane(&session_handle, pane_id);
            }
            let expires_at = chrono::Utc::now().timestamp_millis() + max_ttl_ms as i64;
            Ok(json!({
                "session_handle": session_handle,
                "host_id": host_id,
                "host_label": pane_info["host_label"],
                "production": pane_info["production"],
                "pane_id": pane_info["pane_id"],
                "expires_at": expires_at,
                "idle_timeout_seconds": idle_ttl_ms / 1000,
                "show_terminal": show_terminal,
            }))
        }
        "list_sessions" => {
            let sessions: Vec<Value> = ctx
                .runtime
                .sessions
                .list_for_client(client_id)
                .into_iter()
                .map(|e| {
                    json!({
                        "session_handle": e.session_handle,
                        "host_id": e.host_id,
                        "pane_id": e.pane_id,
                        "created_at": e.created_at,
                        "last_active_at": e.last_active_at,
                    })
                })
                .collect();
            Ok(json!({ "sessions": sessions }))
        }
        "get_session_info" => {
            let handle = req_str(args, "session_handle")?;
            let e = ctx.runtime.sessions.get_owned(handle, client_id)?;
            Ok(json!({
                "session_handle": e.session_handle,
                "host_id": e.host_id,
                "pane_id": e.pane_id,
                "created_at": e.created_at,
                "last_active_at": e.last_active_at,
                "expires_at": e.created_at + e.max_ttl_ms as i64,
            }))
        }
        "read_scrollback" => {
            let handle = req_str(args, "session_handle")?;
            let e = ctx.runtime.sessions.get_owned(handle, client_id)?;
            resolve_host_in_scope(&ctx.pool, client_id, &e.host_id).await?;
            let pane_id = e.pane_id.ok_or_else(|| {
                McpError::InvalidArguments("Session has no terminal pane yet".into())
            })?;
            let lines = opt_u64(args, "lines", 200, 1, 2000) as usize;
            let exec = ctx
                .executor()
                .ok_or_else(|| McpError::Internal("Remote executor unavailable".into()))?;
            let raw = exec.read_pane_output(&pane_id, 512 * 1024).await?;
            let clean = strip_ansi(&raw);
            let all: Vec<&str> = clean.lines().collect();
            let start = all.len().saturating_sub(lines);
            Ok(json!({
                "session_handle": handle,
                "lines": all.len() - start,
                "output": all[start..].join("\n"),
            }))
        }
        "list_dir" => {
            let host_id = scoped_host(ctx, args).await?;
            let path = validate_path(req_str(args, "path")?, "path")?;
            let exec = ctx
                .executor()
                .ok_or_else(|| McpError::Internal("Remote executor unavailable".into()))?;
            exec.sftp_list_dir(host_id, path).await
        }
        "stat_path" => {
            let host_id = scoped_host(ctx, args).await?;
            let path = validate_path(req_str(args, "path")?, "path")?;
            let exec = ctx
                .executor()
                .ok_or_else(|| McpError::Internal("Remote executor unavailable".into()))?;
            exec.sftp_stat(host_id, path).await
        }
        "read_file_preview" => {
            let path = validate_path(req_str(args, "path")?, "path")?;
            if is_sensitive_read_path(path) {
                return Err(McpError::SensitivePathDenied(format!(
                    "Access to sensitive file '{path}' is denied"
                )));
            }
            let host_id = scoped_host(ctx, args).await?;
            let max_bytes = opt_u64(args, "max_bytes", 16_384, 1, 262_144);
            let from_end = opt_str(args, "from") == Some("end");
            let exec = ctx
                .executor()
                .ok_or_else(|| McpError::Internal("Remote executor unavailable".into()))?;
            exec.sftp_read_preview(host_id, path, max_bytes, from_end)
                .await
        }
        "find_files" => {
            let host_id = scoped_host(ctx, args).await?;
            let path = command_path(args, "path")?;
            let pattern = validate_path(req_str(args, "pattern")?, "pattern")?;
            let depth = opt_u64(args, "max_depth", 6, 1, 20);
            let limit = opt_u64(args, "limit", 200, 1, 1000);
            let kind = match opt_str(args, "type") {
                Some("file") => " -type f",
                Some("dir") => " -type d",
                _ => "",
            };
            exec_ro(
                ctx,
                host_id,
                &format!(
                    "find {} -maxdepth {depth}{kind} -name {} 2>/dev/null | head -n {limit}",
                    shell_quote(path),
                    shell_quote(pattern)
                ),
                SEARCH_TIMEOUT_MS,
            )
            .await
        }
        "grep_files" => {
            let host_id = scoped_host(ctx, args).await?;
            let path = command_path(args, "path")?;
            if is_sensitive_read_path(path) {
                return Err(McpError::SensitivePathDenied(format!(
                    "Searching sensitive location '{path}' is denied"
                )));
            }
            let query = validate_path(req_str(args, "query")?, "query")?;
            let limit = opt_u64(args, "limit", 200, 1, 2000);
            let mode = if args.get("regex").and_then(|v| v.as_bool()) == Some(true) {
                "-E"
            } else {
                "-F"
            };
            let case = if args.get("ignore_case").and_then(|v| v.as_bool()) == Some(true) {
                " -i"
            } else {
                ""
            };
            let include = match opt_str(args, "include") {
                Some(glob) => format!(
                    " --include={}",
                    shell_quote(validate_path(glob, "include")?)
                ),
                None => String::new(),
            };
            exec_ro(
                ctx,
                host_id,
                &format!(
                    "grep -RIn {mode}{case}{include} {GREP_EXCLUDES} -e {} -- {} 2>/dev/null | cut -c1-500 | head -n {limit}",
                    shell_quote(query),
                    shell_quote(path)
                ),
                SEARCH_TIMEOUT_MS,
            )
            .await
        }
        "get_sysinfo" => {
            let host_id = scoped_host(ctx, args).await?;
            exec_ro(
                ctx,
                host_id,
                "echo \"hostname: $(hostname 2>/dev/null)\"; \
                 (. /etc/os-release 2>/dev/null && echo \"os: $PRETTY_NAME\"); \
                 echo \"kernel: $(uname -srm)\"; \
                 echo \"uptime: $(uptime)\"; \
                 echo \"cpus: $(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN)\"; \
                 echo '--- memory'; (free -h 2>/dev/null || vm_stat 2>/dev/null); \
                 echo '--- disk'; df -h -x tmpfs -x devtmpfs -x squashfs 2>/dev/null || df -h",
                READ_TIMEOUT_MS,
            )
            .await
        }
        "list_processes" => {
            let host_id = scoped_host(ctx, args).await?;
            let limit = opt_u64(args, "limit", 50, 1, 500) + 1;
            let key = if opt_str(args, "sort") == Some("mem") {
                "%mem"
            } else {
                "%cpu"
            };
            exec_ro(
                ctx,
                host_id,
                &format!(
                    "ps aux --sort=-{key} 2>/dev/null | head -n {limit} || ps aux | head -n {limit}"
                ),
                READ_TIMEOUT_MS,
            )
            .await
        }
        "list_services" => {
            let host_id = scoped_host(ctx, args).await?;
            let filter = match opt_str(args, "state") {
                Some("running") => " --state=running",
                Some("failed") => " --state=failed",
                _ => " --all",
            };
            exec_ro(
                ctx,
                host_id,
                &format!(
                    "systemctl list-units --type=service{filter} --no-pager --plain --no-legend"
                ),
                READ_TIMEOUT_MS,
            )
            .await
        }
        "read_journal" => {
            let host_id = scoped_host(ctx, args).await?;
            let lines = opt_u64(args, "lines", 200, 1, 5000);
            let mut cmd = format!("journalctl --no-pager -n {lines}");
            if let Some(unit) = opt_str(args, "unit") {
                validate_token(unit, "unit", &['@', ':'])?;
                cmd.push_str(&format!(" -u {}", shell_quote(unit)));
            }
            if let Some(since) = opt_str(args, "since") {
                let since = validate_path(since, "since")?;
                cmd.push_str(&format!(" --since {}", shell_quote(since)));
            }
            if let Some(p) = opt_str(args, "priority") {
                validate_token(p, "priority", &[])?;
                cmd.push_str(&format!(" -p {p}"));
            }
            exec_ro(ctx, host_id, &format!("{cmd} 2>&1"), READ_TIMEOUT_MS).await
        }
        "list_containers" => {
            let host_id = scoped_host(ctx, args).await?;
            exec_ro(
                ctx,
                host_id,
                "docker ps -a --no-trunc --format '{{json .}}'",
                READ_TIMEOUT_MS,
            )
            .await
        }
        "get_container_logs" => {
            let host_id = scoped_host(ctx, args).await?;
            let id = validate_token(req_str(args, "container_id")?, "container_id", &[])?;
            let tail = opt_u64(args, "tail", 200, 1, 5000);
            let since = match opt_str(args, "since") {
                Some(s) => format!(
                    " --since {}",
                    shell_quote(validate_token(s, "since", &[':', '+'])?)
                ),
                None => String::new(),
            };
            exec_ro(
                ctx,
                host_id,
                &format!("docker logs --tail {tail}{since} {} 2>&1", shell_quote(id)),
                READ_TIMEOUT_MS,
            )
            .await
        }
        "inspect_container" => {
            let host_id = scoped_host(ctx, args).await?;
            let id = validate_token(req_str(args, "container_id")?, "container_id", &[])?;
            let mut out = exec_ro(
                ctx,
                host_id,
                &format!("docker inspect {}", shell_quote(id)),
                READ_TIMEOUT_MS,
            )
            .await?;
            if let Some(stdout) = out.get("stdout").and_then(|v| v.as_str()) {
                if let Ok(mut parsed) = serde_json::from_str::<Value>(stdout) {
                    redact_container_env(&mut parsed);
                    out["stdout"] =
                        Value::String(serde_json::to_string_pretty(&parsed).unwrap_or_default());
                } else {
                    // Never hand back unparsed inspect output: it may contain secrets in Env.
                    out["stdout"] = Value::String(String::new());
                }
            }
            Ok(out)
        }
        "list_images" => {
            let host_id = scoped_host(ctx, args).await?;
            exec_ro(
                ctx,
                host_id,
                "docker images --format '{{json .}}'",
                READ_TIMEOUT_MS,
            )
            .await
        }
        "list_k8s_pods" | "list_k8s_deployments" => {
            let host_id = scoped_host(ctx, args).await?;
            let kind = if tool_name == "list_k8s_pods" {
                "pods"
            } else {
                "deployments"
            };
            let ns = k8s_namespace_flag(args)?;
            exec_ro(
                ctx,
                host_id,
                &format!("kubectl get {kind} {ns} -o wide 2>&1"),
                READ_TIMEOUT_MS,
            )
            .await
        }
        "get_k8s_logs" => {
            let host_id = scoped_host(ctx, args).await?;
            let pod = validate_token(req_str(args, "pod_name")?, "pod_name", &[])?;
            let ns = validate_token(
                opt_str(args, "namespace").unwrap_or("default"),
                "namespace",
                &[],
            )?;
            let tail = opt_u64(args, "tail", 200, 1, 5000);
            let mut cmd = format!(
                "kubectl logs -n {} --tail={tail} {}",
                shell_quote(ns),
                shell_quote(pod)
            );
            if let Some(c) = opt_str(args, "container") {
                cmd.push_str(&format!(
                    " -c {}",
                    shell_quote(validate_token(c, "container", &[])?)
                ));
            }
            if args.get("previous").and_then(|v| v.as_bool()) == Some(true) {
                cmd.push_str(" --previous");
            }
            exec_ro(ctx, host_id, &format!("{cmd} 2>&1"), READ_TIMEOUT_MS).await
        }
        "list_snippets" => {
            Ok(json!({ "snippets": snippet_rows(ctx, opt_str(args, "query")).await? }))
        }
        "search_global" => {
            let query = req_str(args, "query")?;
            Ok(json!({
                "hosts": host_rows(ctx, Some(query)).await?,
                "snippets": snippet_rows(ctx, Some(query)).await?,
            }))
        }
        _ => Err(McpError::ToolNotAvailable(format!(
            "Unknown tool: {tool_name}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_safe_tool_is_implemented() {
        // The fallback arm must never be reachable for an advertised tool.
        let src = include_str!("safe.rs");
        for t in safe_tools() {
            assert!(
                src.contains(&format!("\"{}\" =>", t.name))
                    || src.contains(&format!("\"{}\" |", t.name)),
                "{} has no handler",
                t.name
            );
        }
    }

    #[test]
    fn container_env_is_redacted() {
        let mut v = json!([{ "Config": { "Env": ["DB_PASSWORD=hunter2", "PATH=/usr/bin"] } }]);
        redact_container_env(&mut v);
        assert_eq!(v[0]["Config"]["Env"][0], "DB_PASSWORD=<redacted>");
        assert_eq!(v[0]["Config"]["Env"][1], "PATH=<redacted>");
    }
}
