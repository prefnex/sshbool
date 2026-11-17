//! End-to-end MCP test against a real SSH server, driven by the official MCP TypeScript SDK.
//!
//! Ignored by default. Run with a disposable SSH server, e.g.:
//!
//! ```sh
//! docker run -d --name mcp-e2e -p 127.0.0.1:2222:22 ubuntu:22.04 bash -c \
//!   'apt-get update && apt-get install -y openssh-server && mkdir -p /run/sshd && \
//!    echo root:e2e-test-pass | chpasswd && \
//!    sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config && \
//!    mkdir -p /srv/app && printf "name=demo\nport=8080\n" > /srv/app/app.conf && \
//!    seq 1 5000 > /srv/app/big.log && exec /usr/sbin/sshd -D'
//! MCP_E2E_SSH=127.0.0.1:2222 MCP_E2E_PASSWORD=e2e-test-pass \
//!   cargo test -p sshbool mcp_e2e -- --ignored --nocapture
//! ```
//!
//! The Rust side runs the real server, executor and SSH stack; approvals are answered by a
//! notifier standing in for the user (approve everything except `reboot_host`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use infrastructure::db::{migrate, open_pool};
use infrastructure::ssh::ConnectionManager;
use infrastructure::vault::VaultService;
use infrastructure::AppState;
use mcp::approval::{global_broker, ApprovalOutcome, ApprovalResponse};
use mcp::config::{LoopbackAddr, ServerConfig};
use mcp::pairing::{pair_client_from_app, LocalPairRequest};
use mcp::repo::clients::grant_host_to_client;
use mcp::{
    ApprovalRequest, CallLogEntry, McpNotifier, McpServerHandle, PaneReadyEvent, ServerState,
};
use tokio::sync::RwLock;

struct StandInUser;

impl McpNotifier for StandInUser {
    fn approval_requested(&self, req: &ApprovalRequest) {
        let id = uuid::Uuid::parse_str(&req.id).expect("approval id");
        let outcome = if req.tool == "reboot_host" {
            ApprovalOutcome::Deny
        } else {
            ApprovalOutcome::AllowOnce
        };
        println!(
            "[user] {:?} {} — {:?}",
            outcome, req.tool, req.command_preview
        );
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            global_broker().resolve(
                id,
                ApprovalResponse {
                    outcome,
                    decided_by: Some("e2e".into()),
                },
            );
        });
    }
    fn call_recorded(&self, _entry: &CallLogEntry) {}
    fn server_state_changed(&self, _state: &ServerState) {}
    fn pane_ready(&self, _event: &PaneReadyEvent) {}
}

async fn add_password_host(state: &AppState, host: &str, port: u16, password: &str) -> String {
    let pool = state.vault.pool();
    let now = chrono::Utc::now().timestamp_millis();
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO hosts (id, label, hostname, port, username, auth_method, created_at, updated_at) \
         VALUES (?, 'e2e-box', ?, ?, 'root', 'password', ?, ?)",
    )
    .bind(&id)
    .bind(host)
    .bind(port as i64)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .unwrap();
    let cred_id = uuid::Uuid::now_v7().to_string();
    let aad = format!("cred:{cred_id}");
    let (ct, nonce) = state
        .vault
        .seal_secret(password.as_bytes(), &aad)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO credentials (id, name, kind, ciphertext, nonce, aad, created_at, updated_at) \
         VALUES (?, 'e2e', 'password', ?, ?, ?, ?, ?)",
    )
    .bind(&cred_id)
    .bind(&ct)
    .bind(&nonce)
    .bind(&aad)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)")
        .bind(format!("host:{id}:cred"))
        .bind(&cred_id)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();

    // Trust on first use, as the user would in the fingerprint dialog.
    match state.connections.session_open(&id).await {
        Err(domain::DomainError::FingerprintUnknown {
            fingerprint,
            key_type,
            ..
        }) => {
            sqlx::query(
                "INSERT INTO known_hosts (id, host, port, key_type, fingerprint_sha256, first_seen_at, last_seen_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(uuid::Uuid::now_v7().to_string())
            .bind(host)
            .bind(port as i64)
            .bind(key_type)
            .bind(fingerprint)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        }
        other => panic!("expected an unknown host key on first connect, got {other:?}"),
    }
    id
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a disposable SSH server (MCP_E2E_SSH) and node"]
async fn mcp_e2e_against_real_ssh_server() {
    let target = std::env::var("MCP_E2E_SSH").expect("MCP_E2E_SSH=host:port");
    let password = std::env::var("MCP_E2E_PASSWORD").expect("MCP_E2E_PASSWORD");
    let (host, port) = target.rsplit_once(':').expect("host:port");
    let port: u16 = port.parse().unwrap();

    let dir = std::env::temp_dir().join(format!("sshbool-mcp-e2e-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = open_pool(&dir.join("e2e.sqlite")).await.unwrap();
    migrate(&pool).await.unwrap();
    let vault = VaultService::new(pool.clone());
    vault.init("e2e-vault-password").await.unwrap();
    let connections = ConnectionManager::new(vault.clone());
    let state = Arc::new(AppState {
        vault,
        pool: pool.clone(),
        connections,
        host_sessions: RwLock::new(Default::default()),
    });

    let host_id = add_password_host(&state, host, port, &password).await;

    let mcp_port = 47_900 + (std::process::id() % 90) as u16;
    let runtime = mcp::runtime::McpRuntimeState::global();
    runtime.clear_vault_lock();
    let server = McpServerHandle::start(
        ServerConfig {
            bind_addr: LoopbackAddr::new(mcp_port).unwrap(),
            ruleset_version: 1,
            approval_timeout_ms: 30_000,
        },
        pool.clone(),
        Arc::new(StandInUser),
        Arc::new(crate::mcp_executor::AppMcpExecutor::new(
            state.clone(),
            runtime.clone(),
        )),
    )
    .await
    .unwrap();

    let paired = pair_client_from_app(
        &pool,
        LocalPairRequest {
            client_name: "E2E Agent".into(),
            client_version: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE mcp_clients SET mode = 'full' WHERE id = ?")
        .bind(&paired.client_id)
        .execute(&pool)
        .await
        .unwrap();
    grant_host_to_client(&pool, &paired.client_id, &host_id, true, true, Some("e2e"))
        .await
        .unwrap();

    let script: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "crates",
        "mcp",
        "tests",
        "e2e",
        "client.mjs",
    ]
    .iter()
    .collect();
    let out = tokio::process::Command::new("node")
        .arg(&script)
        .arg(format!("http://127.0.0.1:{mcp_port}/mcp"))
        .arg(&paired.access_token)
        .arg(&host_id)
        .output()
        .await
        .expect("run node");
    println!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));

    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "MCP client checks failed");
}
