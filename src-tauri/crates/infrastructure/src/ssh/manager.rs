//! SSH session / PTY / SFTP manager (russh 0.62).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use domain::DomainError;
use russh::client::{self, AuthResult, Handle};
use russh::keys::{decode_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyBase64};
use russh::ChannelMsg;
use russh::Pty;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock};
use uuid::Uuid;

use crate::vault::VaultService;

async fn read_setting_u64(pool: &sqlx::SqlitePool, key: &str) -> Option<u64> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = ? LIMIT 1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()?;
    let (raw,) = row?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|n| u64::try_from(n).ok()))
}

/// OpenSSH-compatible PTY modes so RHEL/CentOS/AlmaLinux shells behave like a normal terminal.
const DEFAULT_PTY_MODES: &[(Pty, u32)] = &[
    (Pty::VINTR, 3),
    (Pty::VQUIT, 28),
    (Pty::VERASE, 127),
    (Pty::VKILL, 21),
    (Pty::VEOF, 4),
    (Pty::VEOL, 255),
    (Pty::VEOL2, 255),
    (Pty::VSTART, 17),
    (Pty::VSTOP, 19),
    (Pty::VSUSP, 26),
    (Pty::VREPRINT, 18),
    (Pty::VWERASE, 23),
    (Pty::VLNEXT, 22),
    (Pty::ICRNL, 1),
    (Pty::IXON, 1),
    (Pty::IXANY, 1),
    (Pty::IMAXBEL, 1),
    (Pty::IUTF8, 1),
    (Pty::ISIG, 1),
    (Pty::ICANON, 1),
    (Pty::ECHO, 1),
    (Pty::ECHOE, 1),
    (Pty::ECHOK, 1),
    (Pty::IEXTEN, 1),
    (Pty::OPOST, 1),
    (Pty::ONLCR, 1),
    (Pty::CS8, 1),
    (Pty::TTY_OP_ISPEED, 38400),
    (Pty::TTY_OP_OSPEED, 38400),
];

/// Best-effort remote env for UTF-8 + colorized tools (ls, grep, vim, etc.).
/// PTY allocation already sets TERM; these help when sshd AcceptEnv allows them.
async fn set_shell_env(channel: &mut russh::Channel<client::Msg>) {
    // en_US.UTF-8 works on RHEL8/AlmaLinux 8; C.UTF-8 is missing on some minimal images.
    for (key, val) in [
        ("LANG", "en_US.UTF-8"),
        ("LC_CTYPE", "en_US.UTF-8"),
        ("COLORTERM", "truecolor"),
        ("CLICOLOR", "1"),
    ] {
        let _ = channel.set_env(false, key, val).await;
    }
}

/// Give up on a connection attempt (TCP + handshake + auth) after this long.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// Keepalive used when the user has not configured one; with `keepalive_max = 3` a dead
/// link (network down, server powered off) is detected in about a minute.
const DEFAULT_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(15);
/// Backup sweep for sessions whose transport closed without a `disconnected` callback.
const LOST_SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// Output of [`ConnectionManager::exec_capture`].
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ExecCapture {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<String>,
    pub timed_out: bool,
    pub truncated: bool,
}

/// An SSH session that ended without the user asking for it.
#[derive(Clone, Debug)]
pub struct SessionLost {
    pub host_id: String,
    pub session_id: String,
    pub pane_ids: Vec<String>,
    pub reason: String,
}

struct ClientHandler {
    expected_fp: Option<String>,
    learned_fp: Arc<Mutex<Option<(String, String, String)>>>,
    /// Filled with the session id once the session is registered.
    session_slot: Arc<std::sync::Mutex<Option<String>>>,
    lost_tx: mpsc::UnboundedSender<(String, String)>,
}

fn describe_disconnect(reason: &client::DisconnectReason<russh::Error>) -> String {
    match reason {
        client::DisconnectReason::ReceivedDisconnect(info) => {
            if info.message.trim().is_empty() {
                format!("server closed the connection ({:?})", info.reason_code)
            } else {
                format!("server closed the connection: {}", info.message.trim())
            }
        }
        client::DisconnectReason::Error(russh::Error::KeepaliveTimeout) => {
            "server stopped responding (network down or server unreachable)".into()
        }
        client::DisconnectReason::Error(russh::Error::InactivityTimeout) => {
            "connection timed out (no activity)".into()
        }
        client::DisconnectReason::Error(russh::Error::IO(e)) => format!("network error: {e}"),
        client::DisconnectReason::Error(e) => format!("connection lost: {e}"),
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        let sid = self.session_slot.lock().ok().and_then(|slot| slot.clone());
        if let Some(sid) = sid {
            let _ = self.lost_tx.send((sid, describe_disconnect(&reason)));
        }
        match reason {
            client::DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            client::DisconnectReason::Error(e) => Err(e),
        }
    }

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp_sha256 = fingerprint_sha256(server_public_key);
        let fp_md5 = fingerprint_md5(server_public_key);
        let key_type = server_public_key.algorithm().to_string();
        *self.learned_fp.lock().await = Some((fp_sha256.clone(), fp_md5, key_type));
        if let Some(expected) = &self.expected_fp {
            if expected == &fp_sha256 {
                Ok(true)
            } else {
                tracing::warn!(
                    "SSH host key mismatch! expected={}, received={}",
                    expected,
                    fp_sha256
                );
                Ok(false)
            }
        } else {
            tracing::info!(
                "First-time SSH connection host fingerprint learned: {}",
                fp_sha256
            );
            Ok(true)
        }
    }
}

fn fingerprint_sha256(key: &PublicKey) -> String {
    let raw = key.fingerprint(HashAlg::Sha256).to_string();
    if raw.starts_with("SHA256:") {
        raw
    } else {
        format!("SHA256:{raw}")
    }
}

fn fingerprint_md5(key: &PublicKey) -> String {
    let digest = md5::compute(key.public_key_bytes());
    digest
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

struct LiveSession {
    handle: Handle<ClientHandler>,
    host_id: String,
}

struct LivePane {
    host_id: String,
    session_id: String,
    writer: mpsc::Sender<Vec<u8>>,
    /// PTY resize control (cols, rows).
    resize: mpsc::Sender<(u32, u32)>,
}

/// Manages multiplexed SSH sessions.
pub struct ConnectionManager {
    vault: Arc<VaultService>,
    sessions: RwLock<HashMap<String, Arc<Mutex<LiveSession>>>>,
    host_to_session: RwLock<HashMap<String, String>>,
    panes: RwLock<HashMap<String, LivePane>>,
    pane_tx: RwLock<HashMap<String, mpsc::Sender<Vec<u8>>>>,
    /// Raw PTY output retained so pop-out / bring-back can restore the same screen.
    scrollback: RwLock<HashMap<String, Vec<u8>>>,
    forward_tasks: RwLock<HashMap<String, tokio::task::JoinHandle<()>>>,
    forward_ports: RwLock<HashMap<String, u16>>,
    lost_tx: mpsc::UnboundedSender<(String, String)>,
    lost_rx: Mutex<mpsc::UnboundedReceiver<(String, String)>>,
}

const MAX_SCROLLBACK_BYTES: usize = 512_000;

impl ConnectionManager {
    /// Create manager.
    pub fn new(vault: Arc<VaultService>) -> Arc<Self> {
        let (lost_tx, lost_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            vault,
            sessions: RwLock::new(HashMap::new()),
            host_to_session: RwLock::new(HashMap::new()),
            panes: RwLock::new(HashMap::new()),
            pane_tx: RwLock::new(HashMap::new()),
            scrollback: RwLock::new(HashMap::new()),
            forward_tasks: RwLock::new(HashMap::new()),
            forward_ports: RwLock::new(HashMap::new()),
            lost_tx,
            lost_rx: Mutex::new(lost_rx),
        })
    }

    /// Wait for the next session that dropped on its own (network loss, server shutdown,
    /// keepalive timeout...). Its panes and bookkeeping are already cleaned up when this
    /// returns. Meant for a single long-running consumer.
    pub async fn next_lost_session(&self) -> SessionLost {
        let mut rx = self.lost_rx.lock().await;
        loop {
            tokio::select! {
                Some((sid, reason)) = rx.recv() => {
                    if let Some(ev) = self.mark_session_lost(&sid, reason).await {
                        return ev;
                    }
                }
                _ = tokio::time::sleep(LOST_SWEEP_EVERY) => {
                    let closed: Vec<String> = {
                        let sessions = self.sessions.read().await;
                        sessions
                            .iter()
                            .filter(|(_, live)| {
                                live.try_lock().map(|l| l.handle.is_closed()).unwrap_or(false)
                            })
                            .map(|(sid, _)| sid.clone())
                            .collect()
                    };
                    for sid in closed {
                        if let Some(ev) = self
                            .mark_session_lost(&sid, "connection closed".into())
                            .await
                        {
                            return ev;
                        }
                    }
                }
            }
        }
    }

    /// Forget a session that is already dead. `None` if it was closed on purpose before.
    async fn mark_session_lost(&self, session_id: &str, reason: String) -> Option<SessionLost> {
        let live = self.sessions.write().await.remove(session_id)?;
        let host_id = live.lock().await.host_id.clone();
        {
            let mut map = self.host_to_session.write().await;
            if map.get(&host_id).map(String::as_str) == Some(session_id) {
                map.remove(&host_id);
            }
        }
        let pane_ids: Vec<String> = {
            let mut panes = self.panes.write().await;
            let ids: Vec<String> = panes
                .iter()
                .filter(|(_, p)| p.session_id == session_id)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &ids {
                panes.remove(id);
            }
            ids
        };
        {
            let mut tx = self.pane_tx.write().await;
            for id in &pane_ids {
                tx.remove(id);
            }
        }
        let _ = sqlx::query("UPDATE sessions SET ended_at = ? WHERE id = ?")
            .bind(chrono::Utc::now().timestamp_millis())
            .bind(session_id)
            .execute(self.vault.pool())
            .await;
        tracing::warn!("SSH session {session_id} for host {host_id} lost: {reason}");
        Some(SessionLost {
            host_id,
            session_id: session_id.to_string(),
            pane_ids,
            reason,
        })
    }

    pub async fn forward_is_active(&self, forward_id: &str) -> bool {
        self.forward_tasks.read().await.contains_key(forward_id)
    }

    pub async fn forward_local_port(&self, forward_id: &str) -> Option<u16> {
        self.forward_ports.read().await.get(forward_id).copied()
    }

    /// Best-effort check that a TCP port accepts connections on the remote host.
    pub async fn probe_remote_tcp(
        &self,
        host_id: &str,
        addr: &str,
        port: u16,
    ) -> Result<bool, DomainError> {
        // `addr` is interpolated into a shell script: only allow hostname / IP characters.
        if !is_safe_probe_addr(addr) {
            return Err(DomainError::Validation {
                field: "host".into(),
                message: format!("invalid target host: {addr:?}"),
            });
        }
        let cmd = format!(
            "bash -lc 'if timeout 3 bash -c \"echo >/dev/tcp/{addr}/{port}\" 2>/dev/null; then echo SSHBOOL_OPEN; \
             elif ss -tln 2>/dev/null | grep -q \":{port} \"; then echo SSHBOOL_OPEN; \
             elif netstat -tln 2>/dev/null | grep -q \":{port} \"; then echo SSHBOOL_OPEN; \
             else echo SSHBOOL_CLOSED; fi' 2>/dev/null || echo SSHBOOL_CLOSED"
        );
        let out = self.exec_command(host_id, &cmd).await?;
        Ok(out.contains("SSHBOOL_OPEN"))
    }

    /// Open (or reuse) an authenticated session for a host.
    pub async fn session_open(&self, host_id: &str) -> Result<String, DomainError> {
        self.session_open_with_key_pass(host_id, None).await
    }

    pub async fn session_open_with_key_pass(
        &self,
        host_id: &str,
        key_passphrase: Option<String>,
    ) -> Result<String, DomainError> {
        self.session_open_inner(host_id, &mut Vec::new(), key_passphrase)
            .await
    }

    async fn session_open_inner(
        &self,
        host_id: &str,
        chain: &mut Vec<String>,
        key_passphrase: Option<String>,
    ) -> Result<String, DomainError> {
        if let Some(sid) = self.host_to_session.read().await.get(host_id).cloned() {
            return Ok(sid);
        }
        if chain.contains(&host_id.to_string()) {
            return Err(DomainError::Validation {
                field: "jumpHostId".into(),
                message: "ProxyJump cycle detected".into(),
            });
        }
        chain.push(host_id.to_string());

        let row: Option<(String, String, i64, String, Option<String>)> = sqlx::query_as(
            r#"SELECT hostname, COALESCE(username,''), port, auth_method, jump_host_id
               FROM hosts WHERE id = ? AND deleted_at IS NULL"#,
        )
        .bind(host_id)
        .fetch_optional(self.vault.pool())
        .await
        .map_err(|e| DomainError::Crypto(e.to_string()))?;

        let Some((hostname, username, port, auth_method, jump_host_id)) = row else {
            return Err(DomainError::NotFound {
                entity: "host",
                id: Some(host_id.into()),
            });
        };
        let username = if username.is_empty() {
            "root".into()
        } else {
            username
        };
        let port = port as u16;

        let known: Option<(String,)> = sqlx::query_as(
            "SELECT fingerprint_sha256 FROM known_hosts WHERE host = ? AND port = ? LIMIT 1",
        )
        .bind(&hostname)
        .bind(port as i64)
        .fetch_optional(self.vault.pool())
        .await
        .map_err(|e| DomainError::Crypto(e.to_string()))?;

        let learned_fp = Arc::new(Mutex::new(None));
        let session_slot = Arc::new(std::sync::Mutex::new(None));
        let keepalive_interval =
            match read_setting_u64(self.vault.pool(), "connections.keepaliveSecs").await {
                Some(0) => None,
                Some(secs) => Some(std::time::Duration::from_secs(secs)),
                None => Some(DEFAULT_KEEPALIVE),
            };
        let config = client::Config {
            keepalive_interval,
            keepalive_max: 3,
            ..Default::default()
        };
        let config = Arc::new(config);
        let handler = ClientHandler {
            expected_fp: known.as_ref().map(|k| k.0.clone()),
            learned_fp: learned_fp.clone(),
            session_slot: session_slot.clone(),
            lost_tx: self.lost_tx.clone(),
        };

        let connect_and_auth = async {
            let mut handle = if let Some(jump_id) = jump_host_id.filter(|s| !s.is_empty()) {
                let jump_sid = Box::pin(self.session_open_inner(&jump_id, chain, None)).await?;
                let jump_live = self.sessions.read().await.get(&jump_sid).cloned().ok_or(
                    DomainError::NotFound {
                        entity: "session",
                        id: Some(jump_sid),
                    },
                )?;
                let jump_guard = jump_live.lock().await;
                let channel = jump_guard
                    .handle
                    .channel_open_direct_tcpip(hostname.as_str(), port as u32, "127.0.0.1", 0)
                    .await
                    .map_err(|e| DomainError::Conflict(format!("ProxyJump channel: {e}")))?;
                drop(jump_guard);
                let stream = channel.into_stream();
                client::connect_stream(config, stream, handler)
                    .await
                    .map_err(|e| DomainError::Conflict(format!("ProxyJump connect: {e}")))?
            } else {
                client::connect(config, (hostname.as_str(), port), handler)
                    .await
                    .map_err(|e| DomainError::Conflict(format!("connection failed: {e}")))?
            };

            let auth_ok = self
                .authenticate(
                    &mut handle,
                    host_id,
                    &username,
                    &auth_method,
                    key_passphrase.as_deref(),
                )
                .await?;
            Ok::<_, DomainError>((handle, auth_ok))
        };
        let (handle, auth_ok) = tokio::time::timeout(CONNECT_TIMEOUT, connect_and_auth)
            .await
            .map_err(|_| {
                DomainError::Conflict(format!(
                    "connection timed out after {}s ({hostname}:{port} did not respond)",
                    CONNECT_TIMEOUT.as_secs()
                ))
            })??;

        if !auth_ok {
            return Err(DomainError::Unauthorized("bad_password"));
        }

        if let Some((fp, fp_md5, key_type)) = learned_fp.lock().await.clone() {
            if let Some((expected,)) = known {
                if expected != fp {
                    return Err(DomainError::HostKeyChanged {
                        host: hostname.clone(),
                        expected,
                        actual: fp,
                    });
                }
            } else {
                // Host key is unknown / untrusted yet: Disconnect and require explicit user trust
                return Err(DomainError::FingerprintUnknown {
                    host: hostname.clone(),
                    port,
                    fingerprint: fp,
                    fingerprint_md5: Some(fp_md5),
                    key_type,
                });
            }
        }

        let session_id = Uuid::now_v7().to_string();
        let now = chrono::Utc::now().timestamp_millis();
        sqlx::query(
            "INSERT INTO sessions (id, host_id, started_at, client_version, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&session_id)
        .bind(host_id)
        .bind(now)
        .bind(env!("CARGO_PKG_VERSION"))
        .bind(now)
        .execute(self.vault.pool())
        .await
        .map_err(|e| DomainError::Crypto(e.to_string()))?;

        sqlx::query(
            "UPDATE hosts SET last_connected_at = ?, connect_count = connect_count + 1, updated_at = ? WHERE id = ?",
        )
        .bind(now)
        .bind(now)
        .bind(host_id)
        .execute(self.vault.pool())
        .await
        .ok();

        let live = Arc::new(Mutex::new(LiveSession {
            handle,
            host_id: host_id.to_string(),
        }));
        self.sessions.write().await.insert(session_id.clone(), live);
        if let Ok(mut slot) = session_slot.lock() {
            *slot = Some(session_id.clone());
        }
        self.host_to_session
            .write()
            .await
            .insert(host_id.to_string(), session_id.clone());
        Ok(session_id)
    }

    async fn authenticate(
        &self,
        handle: &mut Handle<ClientHandler>,
        host_id: &str,
        username: &str,
        auth_method: &str,
        key_passphrase: Option<&str>,
    ) -> Result<bool, DomainError> {
        match auth_method {
            "password" => {
                let secret = self.load_host_password(host_id).await?;
                let res = handle
                    .authenticate_password(username, secret)
                    .await
                    .map_err(|e| DomainError::Conflict(format!("auth: {e}")))?;
                Ok(matches!(res, AuthResult::Success))
            }
            "agent" => Err(DomainError::Conflict(
                "SSH agent auth requires a running agent; use password or key for now".into(),
            )),
            "key" => {
                let (_key_id, priv_pem) = self.load_host_key(host_id).await?;
                let key = match decode_secret_key(&priv_pem, key_passphrase) {
                    Ok(k) => k,
                    Err(e) => {
                        let msg = e.to_string();
                        let needs_pass = msg.to_ascii_lowercase().contains("encrypted")
                            || msg.to_ascii_lowercase().contains("password")
                            || msg.to_ascii_lowercase().contains("decrypt");
                        if needs_pass && key_passphrase.is_none() {
                            return Err(DomainError::Validation {
                                field: "keyPassphrase".into(),
                                message: "The SSH private key is encrypted. Enter its passphrase to unlock it."
                                    .into(),
                            });
                        }
                        if needs_pass {
                            return Err(DomainError::Validation {
                                field: "keyPassphrase".into(),
                                message: "Wrong key passphrase (or key could not be decrypted)"
                                    .into(),
                            });
                        }
                        return Err(DomainError::Crypto(format!("key decode: {msg}")));
                    }
                };

                let hash = handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|e| DomainError::Conflict(format!("auth: {e}")))?
                    .flatten();
                let res = handle
                    .authenticate_publickey(
                        username,
                        PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                    )
                    .await
                    .map_err(|e| DomainError::Conflict(format!("auth: {e}")))?;
                Ok(matches!(res, AuthResult::Success))
            }
            "fido2" => Err(DomainError::Conflict(
                "FIDO2/YubiKey auth is stubbed — use password or key for now".into(),
            )),
            other => Err(DomainError::Validation {
                field: "authMethod".into(),
                message: format!("unsupported auth method: {other}"),
            }),
        }
    }

    /// Start a local TCP forward through an SSH session (local → remote).
    pub async fn port_forward_start(
        self: &Arc<Self>,
        forward_id: &str,
        host_id: &str,
        bind_addr: &str,
        bind_port: u16,
        dest_addr: &str,
        dest_port: u16,
    ) -> Result<(), DomainError> {
        let session_id = self.session_open(host_id).await?;
        let live =
            self.sessions
                .read()
                .await
                .get(&session_id)
                .cloned()
                .ok_or(DomainError::NotFound {
                    entity: "session",
                    id: Some(session_id),
                })?;

        let listener = tokio::net::TcpListener::bind((bind_addr, bind_port))
            .await
            .map_err(|e| DomainError::Conflict(format!("bind {bind_addr}:{bind_port}: {e}")))?;

        let dest_addr = dest_addr.to_string();
        let mgr = Arc::clone(self);
        let fid = forward_id.to_string();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut socket, peer)) = listener.accept().await else {
                    break;
                };
                let live = live.clone();
                let dest_addr = dest_addr.clone();
                tokio::spawn(async move {
                    let guard = live.lock().await;
                    let channel = match guard
                        .handle
                        .channel_open_direct_tcpip(
                            dest_addr.as_str(),
                            dest_port as u32,
                            peer.ip().to_string(),
                            peer.port() as u32,
                        )
                        .await
                    {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    drop(guard);
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
                });
            }
            let _ = mgr.forward_tasks.write().await.remove(&fid);
            let _ = mgr.forward_ports.write().await.remove(&fid);
        });
        self.forward_tasks
            .write()
            .await
            .insert(forward_id.to_string(), handle);
        self.forward_ports
            .write()
            .await
            .insert(forward_id.to_string(), bind_port);
        Ok(())
    }

    /// Stop a running local forward.
    pub async fn port_forward_stop(&self, forward_id: &str) -> Result<(), DomainError> {
        if let Some(h) = self.forward_tasks.write().await.remove(forward_id) {
            h.abort();
        }
        self.forward_ports.write().await.remove(forward_id);
        Ok(())
    }

    /// Close session.
    pub async fn session_close(&self, session_id: &str) -> Result<(), DomainError> {
        if let Some(live) = self.sessions.write().await.remove(session_id) {
            let host_id = live.lock().await.host_id.clone();
            self.host_to_session.write().await.remove(&host_id);
            let _ = live
                .lock()
                .await
                .handle
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
        }
        let now = chrono::Utc::now().timestamp_millis();
        let _ = sqlx::query("UPDATE sessions SET ended_at = ? WHERE id = ?")
            .bind(now)
            .bind(session_id)
            .execute(self.vault.pool())
            .await;
        Ok(())
    }

    /// Open PTY pane.
    pub async fn pane_open(
        self: &Arc<Self>,
        host_id: &str,
        cols: u32,
        rows: u32,
    ) -> Result<(String, String, mpsc::Receiver<Vec<u8>>), DomainError> {
        let session_id = self.session_open(host_id).await?;
        let live =
            self.sessions
                .read()
                .await
                .get(&session_id)
                .cloned()
                .ok_or(DomainError::NotFound {
                    entity: "session",
                    id: Some(session_id.clone()),
                })?;

        let guard = live.lock().await;
        let mut channel = guard
            .handle
            .channel_open_session()
            .await
            .map_err(|e| DomainError::Conflict(format!("channel: {e}")))?;

        channel
            .request_pty(false, "xterm-256color", cols, rows, 0, 0, DEFAULT_PTY_MODES)
            .await
            .map_err(|e| DomainError::Conflict(format!("pty: {e}")))?;
        set_shell_env(&mut channel).await;
        channel
            .request_shell(false)
            .await
            .map_err(|e| DomainError::Conflict(format!("shell: {e}")))?;
        drop(guard);

        let pane_id = Uuid::now_v7().to_string();
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(256);
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(256);
        let (resize_tx, mut resize_rx) = mpsc::channel::<(u32, u32)>(8);

        self.pane_tx
            .write()
            .await
            .insert(pane_id.clone(), out_tx.clone());
        self.panes.write().await.insert(
            pane_id.clone(),
            LivePane {
                host_id: host_id.to_string(),
                session_id: session_id.clone(),
                writer: in_tx,
                resize: resize_tx,
            },
        );

        let now = chrono::Utc::now().timestamp_millis();
        let _ = sqlx::query(
            "INSERT INTO session_panes (id, session_id, kind, title, created_at) VALUES (?, ?, 'shell', ?, ?)",
        )
        .bind(&pane_id)
        .bind(&session_id)
        .bind(host_id)
        .bind(now)
        .execute(self.vault.pool())
        .await;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = channel.wait() => {
                        match msg {
                            Some(ChannelMsg::Data { ref data }) => {
                                let _ = out_tx.send(data.to_vec()).await;
                            }
                            Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                                let _ = out_tx.send(data.to_vec()).await;
                            }
                            None | Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => break,
                            _ => {}
                        }
                    }
                    Some(bytes) = in_rx.recv() => {
                        if channel.data(&bytes[..]).await.is_err() {
                            break;
                        }
                    }
                    Some((cols, rows)) = resize_rx.recv() => {
                        // SSH window-change so TUIs (htop/vim/tmux) match local size.
                        if channel
                            .window_change(cols, rows, 0, 0)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });

        Ok((pane_id, session_id, out_rx))
    }

    /// Write to pane.
    pub async fn pane_write(&self, pane_id: &str, data: &[u8]) -> Result<(), DomainError> {
        let panes = self.panes.read().await;
        let pane = panes.get(pane_id).ok_or(DomainError::NotFound {
            entity: "pane",
            id: Some(pane_id.into()),
        })?;
        pane.writer
            .send(data.to_vec())
            .await
            .map_err(|_| DomainError::Conflict("pane closed".into()))?;
        Ok(())
    }

    /// Resize pane — send SSH window-change so remote TUIs match local size.
    pub async fn pane_resize(
        &self,
        pane_id: &str,
        cols: u32,
        rows: u32,
    ) -> Result<(), DomainError> {
        let cols = cols.max(2);
        let rows = rows.max(2);
        let panes = self.panes.read().await;
        let pane = panes.get(pane_id).ok_or(DomainError::NotFound {
            entity: "pane",
            id: Some(pane_id.into()),
        })?;
        pane.resize
            .send((cols, rows))
            .await
            .map_err(|_| DomainError::Conflict("pane closed".into()))?;
        Ok(())
    }

    /// Close pane.
    pub async fn pane_close(&self, pane_id: &str) -> Result<(), DomainError> {
        self.panes.write().await.remove(pane_id);
        self.pane_tx.write().await.remove(pane_id);
        self.scrollback.write().await.remove(pane_id);
        Ok(())
    }

    /// Append PTY output to the retained scrollback for this pane.
    pub async fn pane_scrollback_append(&self, pane_id: &str, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut map = self.scrollback.write().await;
        let buf = map.entry(pane_id.to_string()).or_default();
        buf.extend_from_slice(data);
        if buf.len() > MAX_SCROLLBACK_BYTES {
            let excess = buf.len() - MAX_SCROLLBACK_BYTES;
            buf.drain(0..excess);
        }
    }

    /// Full retained scrollback (may be empty for a brand-new pane).
    pub async fn pane_scrollback_get(&self, pane_id: &str) -> Vec<u8> {
        self.scrollback
            .read()
            .await
            .get(pane_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Open a PTY pane and retain scrollback without requiring the webview listener.
    pub async fn pane_open_mcp(
        self: &Arc<Self>,
        host_id: &str,
        cols: u32,
        rows: u32,
    ) -> Result<(String, String), DomainError> {
        let (pane_id, session_id, mut rx) = self.pane_open(host_id, cols, rows).await?;
        let connections = self.clone();
        let pane_id_sb = pane_id.clone();
        tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                connections
                    .pane_scrollback_append(&pane_id_sb, &bytes)
                    .await;
            }
        });
        Ok((pane_id, session_id))
    }

    /// Run a non-interactive command on the host and return stdout+stderr.
    pub async fn exec_command(&self, host_id: &str, command: &str) -> Result<String, DomainError> {
        self.exec_command_with_stdin(host_id, command, None).await
    }

    /// Like [`exec_command`](Self::exec_command) but writes `stdin` to the remote process and
    /// then closes it. Use this for secrets: unlike command-line arguments, stdin is not visible
    /// to other users on the server through `ps` / `/proc/<pid>/cmdline`.
    pub async fn exec_command_with_stdin(
        &self,
        host_id: &str,
        command: &str,
        stdin: Option<&[u8]>,
    ) -> Result<String, DomainError> {
        let session_id = self.session_open(host_id).await?;
        let live =
            self.sessions
                .read()
                .await
                .get(&session_id)
                .cloned()
                .ok_or(DomainError::NotFound {
                    entity: "session",
                    id: Some(session_id),
                })?;
        let guard = live.lock().await;
        let mut channel = guard
            .handle
            .channel_open_session()
            .await
            .map_err(|e| DomainError::Conflict(format!("exec channel: {e}")))?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| DomainError::Conflict(format!("exec: {e}")))?;
        drop(guard);

        if let Some(input) = stdin {
            channel
                .data(input)
                .await
                .map_err(|e| DomainError::Conflict(format!("exec stdin: {e}")))?;
            channel
                .eof()
                .await
                .map_err(|e| DomainError::Conflict(format!("exec stdin eof: {e}")))?;
        }

        let mut out = Vec::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { ref data }) => out.extend_from_slice(data),
                Some(ChannelMsg::ExtendedData { ref data, .. }) => out.extend_from_slice(data),
                None | Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => break,
                Some(ChannelMsg::ExitStatus { .. }) => {}
                _ => {}
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Run `command` on a dedicated exec channel (never in a user's terminal) and capture
    /// stdout, stderr and the exit status. Stops waiting after `timeout`; output beyond
    /// `max_output` bytes per stream is dropped and reported as truncated.
    pub async fn exec_capture(
        &self,
        host_id: &str,
        command: &str,
        timeout: std::time::Duration,
        max_output: usize,
    ) -> Result<ExecCapture, DomainError> {
        let session_id = self.session_open(host_id).await?;
        let live =
            self.sessions
                .read()
                .await
                .get(&session_id)
                .cloned()
                .ok_or(DomainError::NotFound {
                    entity: "session",
                    id: Some(session_id),
                })?;
        let guard = live.lock().await;
        let mut channel = guard
            .handle
            .channel_open_session()
            .await
            .map_err(|e| DomainError::Conflict(format!("exec channel: {e}")))?;
        drop(guard);
        channel
            .exec(true, command)
            .await
            .map_err(|e| DomainError::Conflict(format!("exec: {e}")))?;
        // No stdin: commands that read it see EOF instead of hanging.
        let _ = channel.eof().await;

        let mut cap = ExecCapture::default();
        let push = |buf: &mut Vec<u8>, data: &[u8], truncated: &mut bool| {
            let room = max_output.saturating_sub(buf.len());
            if data.len() > room {
                *truncated = true;
            }
            buf.extend_from_slice(&data[..data.len().min(room)]);
        };
        let deadline = tokio::time::Instant::now() + timeout;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            match tokio::time::timeout_at(deadline, channel.wait()).await {
                Err(_) => {
                    cap.timed_out = true;
                    let _ = channel.close().await;
                    break;
                }
                Ok(Some(ChannelMsg::Data { ref data })) => {
                    push(&mut stdout, data, &mut cap.truncated)
                }
                Ok(Some(ChannelMsg::ExtendedData { ref data, .. })) => {
                    push(&mut stderr, data, &mut cap.truncated)
                }
                Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                    cap.exit_code = Some(exit_status as i32)
                }
                Ok(Some(ChannelMsg::ExitSignal { signal_name, .. })) => {
                    cap.exit_signal = Some(format!("{signal_name:?}"))
                }
                Ok(None) | Ok(Some(ChannelMsg::Close)) => break,
                Ok(Some(_)) => {}
            }
        }
        cap.stdout = String::from_utf8_lossy(&stdout).into_owned();
        cap.stderr = String::from_utf8_lossy(&stderr).into_owned();
        Ok(cap)
    }

    /// List open panes.
    pub async fn sessions_list(&self) -> Vec<(String, String, String, String)> {
        self.panes
            .read()
            .await
            .iter()
            .map(|(pid, p)| {
                (
                    pid.clone(),
                    p.session_id.clone(),
                    p.host_id.clone(),
                    p.host_id.clone(),
                )
            })
            .collect()
    }

    async fn open_sftp(
        &self,
        host_id: &str,
    ) -> Result<russh_sftp::client::SftpSession, DomainError> {
        let session_id = self.session_open(host_id).await?;
        let live =
            self.sessions
                .read()
                .await
                .get(&session_id)
                .cloned()
                .ok_or(DomainError::NotFound {
                    entity: "session",
                    id: Some(session_id),
                })?;
        let guard = live.lock().await;
        let channel = guard
            .handle
            .channel_open_session()
            .await
            .map_err(|e| DomainError::Conflict(format!("sftp channel: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| DomainError::Conflict(format!("sftp subsystem: {e}")))?;
        russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| DomainError::Conflict(format!("sftp: {e}")))
    }

    /// SFTP list directory.
    pub async fn sftp_list_dir(
        &self,
        host_id: &str,
        path: &str,
    ) -> Result<Vec<SftpEntry>, DomainError> {
        let sftp = self.open_sftp(host_id).await?;
        let request = if path.is_empty() { "." } else { path };
        // Resolve `.` / relative paths to absolute so entries never become `.filename`.
        let resolved = sftp
            .canonicalize(request)
            .await
            .unwrap_or_else(|_| request.to_string());
        let base = resolved.trim_end_matches('/').to_string();
        let base = if base.is_empty() {
            "/".to_string()
        } else {
            base
        };

        let entries = sftp
            .read_dir(&base)
            .await
            .map_err(|e| DomainError::Conflict(format!("readdir: {e}")))?;

        let mut out = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let meta = entry.metadata();
            let full = join_remote(&base, &name);
            out.push(SftpEntry {
                name,
                path: full,
                is_dir: meta.file_type().is_dir(),
                size: meta.size.unwrap_or(0),
                mode: meta.permissions.unwrap_or(0),
                mtime: meta.mtime.unwrap_or(0) as i64,
                uid: meta.uid.unwrap_or(0),
                gid: meta.gid.unwrap_or(0),
            });
        }
        out.sort_by(|a, b| match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.cmp(&b.name),
        });
        Ok(out)
    }

    /// Read remote file as UTF-8 (lossy). Cap 5MB for editor.
    pub async fn sftp_read(&self, host_id: &str, path: &str) -> Result<(String, i64), DomainError> {
        let (bytes, mtime) = self.sftp_read_bytes(host_id, path, Some(5_000_000)).await?;
        Ok((String::from_utf8_lossy(&bytes).into_owned(), mtime))
    }

    /// Read remote file as raw bytes. Optional size cap (bytes).
    pub async fn sftp_read_bytes(
        &self,
        host_id: &str,
        path: &str,
        max_bytes: Option<u64>,
    ) -> Result<(Vec<u8>, i64), DomainError> {
        let sftp = self.open_sftp(host_id).await?;
        let meta = sftp
            .metadata(path)
            .await
            .map_err(|e| map_sftp_err("stat", e))?;
        if meta.file_type().is_dir() {
            return Err(DomainError::Conflict(
                "cannot read a directory as a file".into(),
            ));
        }
        let mtime = meta.mtime.unwrap_or(0) as i64;
        let size = meta.size.unwrap_or(0);
        if let Some(max) = max_bytes {
            if size > max {
                return Err(DomainError::Conflict(format!(
                    "file too large (>{max} bytes)"
                )));
            }
        }
        let mut file = sftp.open(path).await.map_err(|e| map_sftp_err("open", e))?;
        let mut buf = Vec::new();
        if size > 0 {
            buf.reserve(size.min(max_bytes.unwrap_or(size)) as usize);
        }
        sftp_read_file_chunked(&mut file, max_bytes, |chunk| {
            buf.extend_from_slice(chunk);
            Ok(true)
        })
        .await?;
        let _ = file.shutdown().await;
        Ok((buf, mtime))
    }

    /// Read at most `max_bytes` from the start (or the end, when `from_end`) of a remote file.
    /// Returns `(bytes, mtime, total_size)`; works for files of any size.
    pub async fn sftp_read_range(
        &self,
        host_id: &str,
        path: &str,
        max_bytes: u64,
        from_end: bool,
    ) -> Result<(Vec<u8>, i64, u64), DomainError> {
        use tokio::io::AsyncSeekExt;
        let sftp = self.open_sftp(host_id).await?;
        let meta = sftp
            .metadata(path)
            .await
            .map_err(|e| map_sftp_err("stat", e))?;
        if meta.file_type().is_dir() {
            return Err(DomainError::Conflict(
                "cannot read a directory as a file".into(),
            ));
        }
        let mtime = meta.mtime.unwrap_or(0) as i64;
        let size = meta.size.unwrap_or(0);
        let mut file = sftp.open(path).await.map_err(|e| map_sftp_err("open", e))?;
        if from_end && size > max_bytes {
            file.seek(std::io::SeekFrom::Start(size - max_bytes))
                .await
                .map_err(|e| map_sftp_err("seek", e))?;
        }
        let mut buf = Vec::with_capacity(max_bytes.min(size.max(1)) as usize);
        let mut chunk = vec![0u8; SFTP_READ_CHUNK];
        while (buf.len() as u64) < max_bytes {
            let n = file
                .read(&mut chunk)
                .await
                .map_err(|e| map_sftp_err("read", e))?;
            if n == 0 {
                break;
            }
            let room = (max_bytes - buf.len() as u64) as usize;
            buf.extend_from_slice(&chunk[..n.min(room)]);
        }
        let _ = file.shutdown().await;
        Ok((buf, mtime, size))
    }

    /// Stream a remote file (or directory tree) onto the local filesystem.
    /// `on_progress(done, total)` — return `false` to cancel.
    pub async fn sftp_download_to<F>(
        &self,
        host_id: &str,
        remote_path: &str,
        local_path: &str,
        mut on_progress: F,
    ) -> Result<u64, DomainError>
    where
        F: FnMut(u64, u64) -> bool + Send,
    {
        let sftp = self.open_sftp(host_id).await?;
        let remote = sftp
            .canonicalize(remote_path)
            .await
            .unwrap_or_else(|_| remote_path.to_string());
        sftp_download_path(&sftp, &remote, Path::new(local_path), &mut on_progress).await
    }

    /// Atomic UTF-8 write: temp + rename (editor).
    pub async fn sftp_write(
        &self,
        host_id: &str,
        path: &str,
        content: &str,
        expected_mtime: Option<i64>,
    ) -> Result<i64, DomainError> {
        self.sftp_write_bytes(host_id, path, content.as_bytes(), expected_mtime)
            .await
    }

    /// Atomic binary write: temp + rename.
    pub async fn sftp_write_bytes(
        &self,
        host_id: &str,
        path: &str,
        content: &[u8],
        expected_mtime: Option<i64>,
    ) -> Result<i64, DomainError> {
        self.sftp_write_bytes_progress(host_id, path, content, expected_mtime, |_, _| true)
            .await
    }

    /// Atomic binary write with byte progress callback `(done, total) -> continue`.
    /// Return `false` from the callback to cancel; the temp file is cleaned up.
    pub async fn sftp_write_bytes_progress<F>(
        &self,
        host_id: &str,
        path: &str,
        content: &[u8],
        expected_mtime: Option<i64>,
        mut on_progress: F,
    ) -> Result<i64, DomainError>
    where
        F: FnMut(u64, u64) -> bool + Send,
    {
        let sftp = self.open_sftp(host_id).await?;
        if let Some(exp) = expected_mtime {
            if let Ok(meta) = sftp.metadata(path).await {
                let cur = meta.mtime.unwrap_or(0) as i64;
                if cur != exp {
                    return Err(DomainError::Conflict(
                        "file changed on disk; reload or force save".into(),
                    ));
                }
            }
        }
        let total = content.len() as u64;
        let tmp = format!("{path}.sshbool.tmp");
        {
            let mut file = sftp
                .create(&tmp)
                .await
                .map_err(|e| DomainError::Conflict(e.to_string()))?;
            use tokio::io::AsyncWriteExt;
            const CHUNK: usize = 64 * 1024;
            let mut written: u64 = 0;
            if !on_progress(0, total) {
                drop(file);
                let _ = sftp.remove_file(&tmp).await;
                return Err(DomainError::Canceled);
            }
            for chunk in content.chunks(CHUNK) {
                file.write_all(chunk)
                    .await
                    .map_err(|e| DomainError::Conflict(e.to_string()))?;
                written += chunk.len() as u64;
                if !on_progress(written, total) {
                    drop(file);
                    let _ = sftp.remove_file(&tmp).await;
                    return Err(DomainError::Canceled);
                }
            }
            file.shutdown()
                .await
                .map_err(|e| DomainError::Conflict(e.to_string()))?;
        }
        let _ = sftp.remove_file(path).await;
        sftp.rename(&tmp, path)
            .await
            .map_err(|e| DomainError::Conflict(e.to_string()))?;
        let meta = sftp.metadata(path).await.ok();
        Ok(meta.and_then(|m| m.mtime).unwrap_or(0) as i64)
    }

    /// Stat a single remote path.
    pub async fn sftp_stat(&self, host_id: &str, path: &str) -> Result<SftpEntry, DomainError> {
        let sftp = self.open_sftp(host_id).await?;
        let meta = sftp
            .metadata(path)
            .await
            .map_err(|e| DomainError::Conflict(e.to_string()))?;
        let name = path
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(path)
            .to_string();
        Ok(SftpEntry {
            name,
            path: path.to_string(),
            is_dir: meta.file_type().is_dir(),
            size: meta.size.unwrap_or(0),
            mode: meta.permissions.unwrap_or(0),
            mtime: meta.mtime.unwrap_or(0) as i64,
            uid: meta.uid.unwrap_or(0),
            gid: meta.gid.unwrap_or(0),
        })
    }

    pub async fn sftp_mkdir(&self, host_id: &str, path: &str) -> Result<(), DomainError> {
        let sftp = self.open_sftp(host_id).await?;
        sftp.create_dir(path)
            .await
            .map_err(|e| DomainError::Conflict(e.to_string()))
    }

    pub async fn sftp_rename(
        &self,
        host_id: &str,
        from: &str,
        to: &str,
    ) -> Result<(), DomainError> {
        let sftp = self.open_sftp(host_id).await?;
        sftp.rename(from, to)
            .await
            .map_err(|e| DomainError::Conflict(e.to_string()))
    }

    pub async fn sftp_delete(
        &self,
        host_id: &str,
        path: &str,
        recursive: bool,
    ) -> Result<(), DomainError> {
        let sftp = self.open_sftp(host_id).await?;
        Self::sftp_delete_path(&sftp, path, recursive).await
    }

    async fn sftp_delete_path(
        sftp: &russh_sftp::client::SftpSession,
        path: &str,
        recursive: bool,
    ) -> Result<(), DomainError> {
        let is_dir = sftp
            .metadata(path)
            .await
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false);
        if is_dir {
            if recursive {
                let entries = sftp
                    .read_dir(path)
                    .await
                    .map_err(|e| DomainError::Conflict(format!("readdir: {e}")))?;
                for entry in entries {
                    let name = entry.file_name();
                    if name == "." || name == ".." {
                        continue;
                    }
                    let child = join_remote(path, &name);
                    Box::pin(Self::sftp_delete_path(sftp, &child, true)).await?;
                }
            }
            sftp.remove_dir(path)
                .await
                .map_err(|e| DomainError::Conflict(e.to_string()))
        } else {
            sftp.remove_file(path)
                .await
                .map_err(|e| DomainError::Conflict(e.to_string()))
        }
    }

    /// Copy remote file or directory (recursive).
    pub async fn sftp_copy(&self, host_id: &str, from: &str, to: &str) -> Result<(), DomainError> {
        let sftp = self.open_sftp(host_id).await?;
        Self::sftp_copy_path(&sftp, from, to).await
    }

    async fn sftp_copy_path(
        sftp: &russh_sftp::client::SftpSession,
        from: &str,
        to: &str,
    ) -> Result<(), DomainError> {
        let meta = sftp
            .metadata(from)
            .await
            .map_err(|e| DomainError::Conflict(e.to_string()))?;
        if meta.file_type().is_dir() {
            let _ = sftp.create_dir(to).await;
            let entries = sftp
                .read_dir(from)
                .await
                .map_err(|e| DomainError::Conflict(format!("readdir: {e}")))?;
            for entry in entries {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                let src = join_remote(from, &name);
                let dst = join_remote(to, &name);
                Box::pin(Self::sftp_copy_path(sftp, &src, &dst)).await?;
            }
            Ok(())
        } else {
            let mut file = sftp.open(from).await.map_err(|e| map_sftp_err("open", e))?;
            let mut buf = Vec::new();
            sftp_read_file_chunked(&mut file, None, |chunk| {
                buf.extend_from_slice(chunk);
                Ok(true)
            })
            .await?;
            let _ = file.shutdown().await;
            let tmp = format!("{to}.sshbool.tmp");
            {
                let mut out = sftp
                    .create(&tmp)
                    .await
                    .map_err(|e| map_sftp_err("create", e))?;
                const CHUNK: usize = 64 * 1024;
                for chunk in buf.chunks(CHUNK) {
                    out.write_all(chunk)
                        .await
                        .map_err(|e| map_sftp_err("write", e))?;
                }
                out.shutdown().await.map_err(|e| map_sftp_err("close", e))?;
            }
            let _ = sftp.remove_file(to).await;
            sftp.rename(&tmp, to)
                .await
                .map_err(|e| map_sftp_err("rename", e))
        }
    }

    pub async fn sftp_chmod(
        &self,
        host_id: &str,
        path: &str,
        mode: u32,
    ) -> Result<(), DomainError> {
        let sftp = self.open_sftp(host_id).await?;
        let meta = russh_sftp::protocol::FileAttributes {
            permissions: Some(mode),
            ..Default::default()
        };
        sftp.set_metadata(path, meta)
            .await
            .map_err(|e| DomainError::Conflict(e.to_string()))
    }

    async fn load_host_password(&self, host_id: &str) -> Result<String, DomainError> {
        let key = format!("host:{host_id}:cred");
        let row: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = ?")
            .bind(&key)
            .fetch_optional(self.vault.pool())
            .await
            .map_err(|e| DomainError::Crypto(e.to_string()))?;
        let Some((cred_id,)) = row else {
            return Err(DomainError::NotFound {
                entity: "credential",
                id: Some(host_id.into()),
            });
        };
        let row: Option<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as("SELECT ciphertext, nonce FROM credentials WHERE id = ?")
                .bind(&cred_id)
                .fetch_optional(self.vault.pool())
                .await
                .map_err(|e| DomainError::Crypto(e.to_string()))?;
        let Some((ct, nonce)) = row else {
            return Err(DomainError::NotFound {
                entity: "credential",
                id: Some(cred_id),
            });
        };
        let plain = self
            .vault
            .open_secret(&ct, &nonce, &format!("cred:{cred_id}"))
            .await?;
        String::from_utf8(plain).map_err(|e| DomainError::Crypto(e.to_string()))
    }

    async fn load_host_key(&self, host_id: &str) -> Result<(String, String), DomainError> {
        let key = format!("host:{host_id}:ssh_key");
        let row: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = ?")
            .bind(&key)
            .fetch_optional(self.vault.pool())
            .await
            .map_err(|e| DomainError::Crypto(e.to_string()))?;
        let Some((key_id,)) = row else {
            return Err(DomainError::NotFound {
                entity: "ssh_key",
                id: Some(host_id.into()),
            });
        };
        let row = sqlx::query_as::<_, (Option<Vec<u8>>, Option<Vec<u8>>)>(
            "SELECT private_ciphertext, private_nonce FROM ssh_keys WHERE id = ?",
        )
        .bind(&key_id)
        .fetch_optional(self.vault.pool())
        .await
        .map_err(|e| DomainError::Crypto(e.to_string()))?;
        let Some((Some(ct), Some(nonce))) = row else {
            return Err(DomainError::NotFound {
                entity: "ssh_key",
                id: Some(key_id),
            });
        };
        let plain = self
            .vault
            .open_secret(&ct, &nonce, &format!("key:{key_id}"))
            .await?;
        let pem = String::from_utf8(plain).map_err(|e| DomainError::Crypto(e.to_string()))?;
        Ok((key_id, pem))
    }

    #[allow(dead_code)]
    async fn reseal_ssh_key(&self, key_id: &str, pem: &[u8]) -> Result<(), DomainError> {
        let (ct, nonce) = self
            .vault
            .seal_secret(pem, &format!("key:{key_id}"))
            .await?;
        let now = chrono::Utc::now().timestamp_millis();
        sqlx::query(
            "UPDATE ssh_keys SET private_ciphertext = ?, private_nonce = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&ct)
        .bind(&nonce)
        .bind(now)
        .bind(key_id)
        .execute(self.vault.pool())
        .await
        .map_err(|e| DomainError::Crypto(e.to_string()))?;
        Ok(())
    }
}

/// SFTP directory entry.
pub struct SftpEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub uid: u32,
    pub gid: u32,
}

fn join_remote(base: &str, name: &str) -> String {
    if base.is_empty() || base == "." {
        format!("./{name}")
    } else if base == "/" {
        format!("/{name}")
    } else if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// OpenSSH and many embedded SFTP servers reject SSH_FXP_READ larger than 32KiB
/// with a generic SSH_FX_FAILURE ("Failure: Failure"). Always read in small chunks
/// — never `read_to_end` into a Vec pre-sized to the whole file, because tokio
/// will then request the entire spare capacity in one packet.
const SFTP_READ_CHUNK: usize = 32 * 1024;

fn map_sftp_err(op: &str, e: impl std::fmt::Display) -> DomainError {
    let raw = e.to_string();
    if raw.contains("Failure") {
        DomainError::Conflict(format!(
            "{op} rejected by the SFTP server ({raw}). The path may be a directory, unreadable, or the read exceeded the server's size limit."
        ))
    } else {
        DomainError::Conflict(format!("{op}: {raw}"))
    }
}

async fn sftp_read_file_chunked<R, F>(
    file: &mut R,
    max_bytes: Option<u64>,
    mut on_chunk: F,
) -> Result<u64, DomainError>
where
    R: tokio::io::AsyncRead + Unpin,
    F: FnMut(&[u8]) -> Result<bool, DomainError>,
{
    let mut buf = vec![0u8; SFTP_READ_CHUNK];
    let mut total = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| map_sftp_err("read", e))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if let Some(max) = max_bytes {
            if total > max {
                return Err(DomainError::Conflict(format!(
                    "file too large (>{max} bytes)"
                )));
            }
        }
        if !on_chunk(&buf[..n])? {
            return Err(DomainError::Canceled);
        }
    }
    Ok(total)
}

async fn sftp_download_path<F>(
    sftp: &russh_sftp::client::SftpSession,
    remote: &str,
    local: &Path,
    on_progress: &mut F,
) -> Result<u64, DomainError>
where
    F: FnMut(u64, u64) -> bool + Send,
{
    let meta = sftp
        .metadata(remote)
        .await
        .map_err(|e| map_sftp_err("stat", e))?;
    if meta.file_type().is_dir() {
        tokio::fs::create_dir_all(local)
            .await
            .map_err(|e| DomainError::Conflict(format!("mkdir {}: {e}", local.display())))?;
        let entries = sftp
            .read_dir(remote)
            .await
            .map_err(|e| map_sftp_err("readdir", e))?;
        let mut written = 0u64;
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let src = join_remote(remote, &name);
            let dst = local.join(&name);
            written += Box::pin(sftp_download_path(sftp, &src, &dst, on_progress)).await?;
        }
        return Ok(written);
    }

    if let Some(parent) = local.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| DomainError::Conflict(format!("mkdir {}: {e}", parent.display())))?;
    }

    let total = meta.size.unwrap_or(0);
    if !on_progress(0, total) {
        return Err(DomainError::Canceled);
    }

    let mut file = sftp
        .open(remote)
        .await
        .map_err(|e| map_sftp_err("open", e))?;
    let mut out = tokio::fs::File::create(local)
        .await
        .map_err(|e| DomainError::Conflict(format!("create {}: {e}", local.display())))?;
    let mut buf = vec![0u8; SFTP_READ_CHUNK];
    let mut written = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| map_sftp_err("read", e))?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])
            .await
            .map_err(|e| DomainError::Conflict(format!("write {}: {e}", local.display())))?;
        written += n as u64;
        if !on_progress(written, total.max(written)) {
            let _ = tokio::fs::remove_file(local).await;
            return Err(DomainError::Canceled);
        }
    }
    out.flush()
        .await
        .map_err(|e| DomainError::Conflict(format!("flush {}: {e}", local.display())))?;
    let _ = file.shutdown().await;
    Ok(written)
}

/// Hostname, IPv4 or IPv6 literal — nothing a shell would interpret.
fn is_safe_probe_addr(addr: &str) -> bool {
    !addr.is_empty()
        && addr.len() <= 253
        && !addr.starts_with('-')
        && addr
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
}

#[cfg(test)]
mod probe_addr_tests {
    use super::is_safe_probe_addr;

    #[test]
    fn accepts_hosts_and_ips() {
        for ok in ["127.0.0.1", "db-1.internal", "fe80::1", "my_host"] {
            assert!(is_safe_probe_addr(ok), "{ok}");
        }
    }

    #[test]
    fn rejects_shell_metacharacters() {
        for bad in ["", "a;id", "$(id)", "a b", "x'y", "-oProxy", "a/b", "`id`"] {
            assert!(!is_safe_probe_addr(bad), "{bad}");
        }
    }
}
