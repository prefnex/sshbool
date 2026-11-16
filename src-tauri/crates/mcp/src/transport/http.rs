//! Axum HTTP router and request handlers for MCP server transport.

use crate::pairing::{redeem_pairing_code, PairRequest};
use crate::protocol::handlers::handle_protocol_request;
use crate::protocol::jsonrpc::JsonRpcRequest;
use crate::runtime::McpRuntimeState;
use crate::transport::auth::authenticate_bearer_token;
use crate::McpNotifier;
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub bind_port: u16,
    pub notifier: Arc<dyn McpNotifier>,
    pub approval_timeout_ms: u64,
    pub runtime: Arc<McpRuntimeState>,
}

/// True for `127.0.0.1`, `localhost` or `[::1]`, with an optional `:port`.
/// Exact matching matters: a prefix test would accept `localhost.attacker.com` (DNS rebinding).
fn is_loopback_authority(authority: &str) -> bool {
    // Split "host[:port]" / "[v6][:port]".
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((h, tail)) = rest.split_once(']') else {
            return false;
        };
        match tail {
            "" => (h, None),
            t => match t.strip_prefix(':') {
                Some(p) => (h, Some(p)),
                None => return false,
            },
        }
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    port_ok
        && matches!(
            host.to_ascii_lowercase().as_str(),
            "127.0.0.1" | "localhost" | "::1"
        )
}

fn is_loopback_origin(origin: &str) -> bool {
    // Browsers send `null` for opaque origins (file://, sandboxed iframes): not trusted.
    match origin.split_once("://") {
        Some(("http" | "https", authority)) => is_loopback_authority(authority),
        _ => false,
    }
}

/// Router middleware that verifies Host and Origin headers are strictly loopback.
async fn verify_loopback_headers(request: Request, next: Next) -> Result<Response, StatusCode> {
    if let Some(host) = request.headers().get("host") {
        match host.to_str() {
            Ok(h) if is_loopback_authority(h) => {}
            _ => return Err(StatusCode::FORBIDDEN),
        }
    }
    if let Some(origin) = request.headers().get("origin") {
        match origin.to_str() {
            Ok(o) if is_loopback_origin(o) => {}
            _ => return Err(StatusCode::FORBIDDEN),
        }
    }
    Ok(next.run(request).await)
}

fn rpc_error(status: StatusCode, code: i32, message: &str) -> Response {
    (
        status,
        Json(
            json!({ "jsonrpc": "2.0", "id": null, "error": { "code": code, "message": message } }),
        ),
    )
        .into_response()
}

async fn handle_healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok", "mcp": true }))
}

async fn handle_pair(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PairRequest>,
) -> Response {
    match redeem_pairing_code(&state.pool, payload).await {
        Ok(res) => (StatusCode::OK, Json(json!(res))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Streamable HTTP: we answer every POST with a JSON body and push nothing server→client,
/// so the optional GET stream is not offered (the spec's 405 response).
async fn handle_get_stream() -> Response {
    let mut resp = StatusCode::METHOD_NOT_ALLOWED.into_response();
    resp.headers_mut()
        .insert("Allow", HeaderValue::from_static("POST"));
    resp
}

async fn handle_mcp_rpc(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Response {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .map(str::trim);
    let Some(token) = token else {
        return unauthorized("Missing Authorization: Bearer <token> header");
    };
    let client = match authenticate_bearer_token(&state.pool, token).await {
        Ok(c) => c,
        Err(e) => return unauthorized(&e.to_string()),
    };

    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return rpc_error(
                StatusCode::BAD_REQUEST,
                -32700,
                &format!("Parse error: {e}"),
            )
        }
    };
    if value.is_array() {
        return rpc_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "JSON-RPC batches are not supported; send one request per POST",
        );
    }
    // Responses from the client (no method) and notifications (no id) get no body.
    if value.get("method").is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    let payload: JsonRpcRequest = match serde_json::from_value(value) {
        Ok(p) => p,
        Err(e) => {
            return rpc_error(
                StatusCode::BAD_REQUEST,
                -32600,
                &format!("Invalid request: {e}"),
            )
        }
    };
    if payload.id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }

    let response = handle_protocol_request(
        &state.pool,
        &client.id,
        &client.name,
        &client.mode,
        &state.notifier,
        state.approval_timeout_ms,
        payload,
    )
    .await;

    Json(response).into_response()
}

fn unauthorized(message: &str) -> Response {
    let mut resp = rpc_error(StatusCode::UNAUTHORIZED, -32001, message);
    resp.headers_mut().insert(
        "WWW-Authenticate",
        HeaderValue::from_static("Bearer realm=\"sshbool-mcp\""),
    );
    resp
}

/// Constructs the axum Router for the MCP HTTP server.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/mcp/pair", post(handle_pair))
        .route("/mcp", get(handle_get_stream).post(handle_mcp_rpc))
        .layer(middleware::from_fn(verify_loopback_headers))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::{is_loopback_authority, is_loopback_origin};

    #[test]
    fn loopback_hosts_are_exact() {
        for ok in [
            "127.0.0.1",
            "127.0.0.1:47821",
            "localhost",
            "localhost:47821",
            "LOCALHOST:1",
            "[::1]",
            "[::1]:47821",
        ] {
            assert!(is_loopback_authority(ok), "{ok}");
        }
        for bad in [
            "localhost.attacker.com",
            "127.0.0.1.nip.io",
            "127.0.0.1.attacker.com:47821",
            "evil.com",
            "[::1].evil.com",
            "localhost:80x",
            "",
        ] {
            assert!(!is_loopback_authority(bad), "{bad}");
        }
    }

    #[test]
    fn loopback_origins_are_exact() {
        assert!(is_loopback_origin("http://localhost:3000"));
        assert!(is_loopback_origin("http://127.0.0.1"));
        for bad in [
            "null",
            "http://localhost.evil.com",
            "https://evil.com/127.0.0.1",
            "file://localhost",
        ] {
            assert!(!is_loopback_origin(bad), "{bad}");
        }
    }
}
