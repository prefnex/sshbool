-- Output of each MCP tool call, kept beside the ledger so the Activity view can show
-- what a command actually printed. Secrets are redacted and the text is size-capped
-- before it is written.
CREATE TABLE IF NOT EXISTS mcp_call_outputs (
  call_id    TEXT PRIMARY KEY NOT NULL REFERENCES mcp_calls(id) ON DELETE CASCADE,
  output     TEXT,
  error_text TEXT,
  truncated  INTEGER NOT NULL DEFAULT 0
);
