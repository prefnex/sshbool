//! Sqlx repository layer for the immutable mcp_calls ledger.

use crate::error::McpError;
use sqlx::SqlitePool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CallRow {
    pub id: String,
    pub at: i64,
    pub client_id: Option<String>,
    pub client_name: Option<String>,
    pub host_id: Option<String>,
    pub host_label: Option<String>,
    pub session_handle: Option<String>,
    pub tool: String,
    pub args_hash: Option<String>,
    pub command_preview: Option<String>,
    pub risk_tier: Option<String>,
    pub risk_reasons: Option<String>,
    pub ruleset_version: Option<i64>,
    pub decision: String,
    pub approval_id: Option<String>,
    pub grant_id: Option<String>,
    pub duration_ms: Option<i64>,
    pub result_bytes: Option<i64>,
    pub truncated: i64,
    pub error_code: Option<String>,
    pub reason: Option<String>,
}

/// Records a call entry into the `mcp_calls` table within an open transaction.
/// If this database write fails, the transaction aborts and the caller MUST fail the tool execution.
pub async fn record_call_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    row: &CallRow,
) -> Result<(), McpError> {
    sqlx::query(
        r#"INSERT INTO mcp_calls
        (id, at, client_id, client_name, host_id, host_label, session_handle, tool, args_hash, command_preview, risk_tier, risk_reasons, ruleset_version, decision, approval_id, grant_id, duration_ms, result_bytes, truncated, error_code, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(&row.id)
    .bind(row.at)
    .bind(&row.client_id)
    .bind(&row.client_name)
    .bind(&row.host_id)
    .bind(&row.host_label)
    .bind(&row.session_handle)
    .bind(&row.tool)
    .bind(&row.args_hash)
    .bind(&row.command_preview)
    .bind(&row.risk_tier)
    .bind(&row.risk_reasons)
    .bind(row.ruleset_version)
    .bind(&row.decision)
    .bind(&row.approval_id)
    .bind(&row.grant_id)
    .bind(row.duration_ms)
    .bind(row.result_bytes)
    .bind(row.truncated)
    .bind(&row.error_code)
    .bind(&row.reason)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Standalone call record helper when outside of an active transaction.
pub async fn record_call(pool: &SqlitePool, row: &CallRow) -> Result<(), McpError> {
    let mut tx = pool.begin().await?;
    record_call_tx(&mut tx, row).await?;
    tx.commit().await?;
    Ok(())
}

/// Largest output kept per call; longer output is cut and flagged as truncated.
pub const CALL_OUTPUT_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CallOutputRow {
    pub call_id: String,
    pub output: Option<String>,
    pub error_text: Option<String>,
    pub truncated: i64,
}

fn cap_output(text: &str) -> (String, bool) {
    if text.len() <= CALL_OUTPUT_MAX_BYTES {
        return (text.to_string(), false);
    }
    (
        crate::util::truncate_utf8(text, CALL_OUTPUT_MAX_BYTES).to_string(),
        true,
    )
}

/// Stores what a call returned (or why it failed), redacted and size-capped.
pub async fn record_call_output(
    pool: &SqlitePool,
    call_id: &str,
    output: Option<&str>,
    error_text: Option<&str>,
) -> Result<(), McpError> {
    let mut truncated = false;
    let output = output.map(|t| {
        let (capped, cut) = cap_output(&infrastructure::redact::redact(t));
        truncated |= cut;
        capped
    });
    let error_text = error_text.map(|t| {
        let (capped, cut) = cap_output(&infrastructure::redact::redact(t));
        truncated |= cut;
        capped
    });
    sqlx::query(
        "INSERT OR REPLACE INTO mcp_call_outputs (call_id, output, error_text, truncated) VALUES (?, ?, ?, ?)",
    )
    .bind(call_id)
    .bind(output)
    .bind(error_text)
    .bind(truncated as i64)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_call_output(
    pool: &SqlitePool,
    call_id: &str,
) -> Result<Option<CallOutputRow>, McpError> {
    Ok(sqlx::query_as::<_, CallOutputRow>(
        "SELECT call_id, output, error_text, truncated FROM mcp_call_outputs WHERE call_id = ?",
    )
    .bind(call_id)
    .fetch_optional(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::{cap_output, CALL_OUTPUT_MAX_BYTES};

    #[test]
    fn cap_output_keeps_small_text_intact() {
        let (out, cut) = cap_output("hello world");
        assert_eq!(out, "hello world");
        assert!(!cut);
    }

    #[test]
    fn cap_output_truncates_safely_on_utf8_boundary() {
        let input = "é".repeat(CALL_OUTPUT_MAX_BYTES);
        let (out, cut) = cap_output(&input);
        assert!(cut);
        assert!(out.len() <= CALL_OUTPUT_MAX_BYTES);
        assert!(out.is_char_boundary(out.len()));
    }
}
