//! Developer diagnostics run on the remote host.

use infrastructure::AppState;
use serde_json::Value;
use std::sync::Arc;
use tauri::State;

use crate::error::AppError;

// ── Dev Tools ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn devtools_probe(
    state: State<'_, Arc<AppState>>,
    host_id: String,
) -> Result<Value, AppError> {
    let out = state
        .connections
        .exec_command(
            &host_id,
            r#"
echo '---GIT---'; git --version 2>&1
echo '---NODE---'; node -v 2>&1; npm -v 2>&1
echo '---PYTHON---'; python3 --version 2>&1
echo '---PHP---'; php -v 2>&1 | head -n1
echo '---GO---'; go version 2>&1
echo '---RUST---'; rustc --version 2>&1
echo '---DOCKER---'; docker --version 2>&1
echo '---KUBECTL---'; kubectl version --client --short 2>&1
echo '---ADB---'; adb version 2>&1 | head -n1
echo '---FLUTTER---'; flutter --version 2>&1 | head -n1
"#,
        )
        .await?;
    let mut map = serde_json::Map::new();
    let mut section = String::new();
    for line in out.lines() {
        if let Some(name) = line.strip_prefix("---").and_then(|s| s.strip_suffix("---")) {
            section = name.to_lowercase();
            continue;
        }
        if section.is_empty() || line.trim().is_empty() {
            continue;
        }
        let entry = map
            .entry(section.clone())
            .or_insert_with(|| Value::String(String::new()));
        if let Value::String(s) = entry {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(line.trim());
        }
    }
    Ok(Value::Object(map))
}

#[tauri::command]
pub async fn devtools_git_status(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    path: String,
) -> Result<String, AppError> {
    if path
        .chars()
        .any(|c| matches!(c, ';' | '&' | '|' | '`' | '$' | '(' | ')' | '\n' | '\r'))
    {
        return Err(AppError::Validation {
            field: "path".into(),
            message: "path contains disallowed shell characters".into(),
        });
    }
    let safe_path = path.replace('\'', "'\\''");
    state
        .connections
        .exec_command(
            &host_id,
            &format!("cd '{safe_path}' 2>/dev/null; git status -sb 2>&1; echo '---'; git diff --stat 2>&1 | head -n 40"),
        )
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn devtools_run(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    command: String,
) -> Result<String, AppError> {
    let args: Vec<&str> = command.split_whitespace().collect();
    if args.is_empty() {
        return Err(AppError::Validation {
            field: "command".into(),
            message: "command is empty".into(),
        });
    }

    let is_valid_diagnostic = match args[0] {
        "ping" => args.len() == 4 && args[1] == "-c" && args[2] == "3",
        "dig" => args.len() == 3 && args[1] == "+short",
        "curl" => args.len() == 3 && args[1] == "-I",
        "nslookup" => args.len() == 2,
        "traceroute" => args.len() == 2,
        _ => false,
    };

    if !is_valid_diagnostic {
        return Err(AppError::Validation {
            field: "command".into(),
            message: "invalid diagnostic command structure".into(),
        });
    }

    // Validate that the target host argument is safe (no spaces, shell characters, or option flags)
    let host_arg = args[args.len() - 1];
    let host_safe = !host_arg.starts_with('-')
        && host_arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':');
    if !host_safe {
        return Err(AppError::Validation {
            field: "command".into(),
            message: "invalid target host parameter".into(),
        });
    }

    state
        .connections
        .exec_command(&host_id, &command)
        .await
        .map_err(Into::into)
}
