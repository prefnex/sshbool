//! Remote host SSH session handle registry and TTL manager.

use crate::error::McpError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub session_handle: String,
    pub client_id: String,
    pub host_id: String,
    pub created_at: i64,
    pub last_active_at: i64,
    pub idle_ttl_ms: u64,
    pub max_ttl_ms: u64,
    /// Terminal pane backing this handle (set once the SSH pane is open).
    pub pane_id: Option<String>,
}

#[derive(Clone, Default)]
pub struct SessionRegistry {
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Registers a new session handle for a host bound to a specific client.
    pub fn create_handle(
        &self,
        client_id: String,
        host_id: String,
        idle_ttl_ms: u64,
        max_ttl_ms: u64,
    ) -> String {
        let session_handle = format!("mcp_sh_{}", Uuid::now_v7());
        let now = chrono::Utc::now().timestamp_millis();
        let entry = SessionEntry {
            session_handle: session_handle.clone(),
            client_id,
            host_id,
            created_at: now,
            last_active_at: now,
            idle_ttl_ms,
            max_ttl_ms,
            pane_id: None,
        };

        let mut map = self.sessions.lock().expect("session registry lock");
        map.insert(session_handle.clone(), entry);
        session_handle
    }

    /// Validates ownership and TTL for a session handle. Returns host_id if valid.
    pub fn validate_and_touch(
        &self,
        session_handle: &str,
        client_id: &str,
    ) -> Result<String, McpError> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut map = self.sessions.lock().expect("session registry lock");

        let entry = map.get_mut(session_handle).ok_or_else(|| {
            McpError::SessionExpired(format!("Session handle {session_handle} not found"))
        })?;

        // 1. Ownership check (SESSION_NOT_OWNED)
        if entry.client_id != client_id {
            return Err(McpError::Forbidden(format!(
                "SESSION_NOT_OWNED: Handle {session_handle} owned by another client"
            )));
        }

        // 2. Max TTL check
        if now - entry.created_at >= entry.max_ttl_ms as i64 {
            map.remove(session_handle);
            return Err(McpError::SessionExpired(
                "Session exceeded max lifetime".into(),
            ));
        }

        // 3. Idle TTL check
        if now - entry.last_active_at >= entry.idle_ttl_ms as i64 {
            map.remove(session_handle);
            return Err(McpError::SessionExpired("Session idle timeout".into()));
        }

        entry.last_active_at = now;
        Ok(entry.host_id.clone())
    }

    /// Records the terminal pane that backs a handle.
    pub fn attach_pane(&self, session_handle: &str, pane_id: &str) {
        let mut map = self.sessions.lock().expect("session registry lock");
        if let Some(entry) = map.get_mut(session_handle) {
            entry.pane_id = Some(pane_id.to_string());
        }
    }

    /// Validates ownership/TTL like [`validate_and_touch`](Self::validate_and_touch) and returns
    /// a copy of the entry.
    pub fn get_owned(
        &self,
        session_handle: &str,
        client_id: &str,
    ) -> Result<SessionEntry, McpError> {
        self.validate_and_touch(session_handle, client_id)?;
        let map = self.sessions.lock().expect("session registry lock");
        map.get(session_handle).cloned().ok_or_else(|| {
            McpError::SessionExpired(format!("Session handle {session_handle} not found"))
        })
    }

    /// Live (non-expired) handles owned by a client. Expired ones are dropped.
    pub fn list_for_client(&self, client_id: &str) -> Vec<SessionEntry> {
        let now = chrono::Utc::now().timestamp_millis();
        let mut map = self.sessions.lock().expect("session registry lock");
        map.retain(|_, e| {
            now - e.created_at < e.max_ttl_ms as i64
                && now - e.last_active_at < e.idle_ttl_ms as i64
        });
        let mut out: Vec<SessionEntry> = map
            .values()
            .filter(|e| e.client_id == client_id)
            .cloned()
            .collect();
        out.sort_by_key(|e| e.created_at);
        out
    }

    /// Removes a session handle.
    pub fn remove_handle(&self, session_handle: &str) {
        let mut map = self.sessions.lock().expect("session registry lock");
        map.remove(session_handle);
    }

    /// Clears all session handles (e.g., on vault lock).
    pub fn clear(&self) {
        let mut map = self.sessions.lock().expect("session registry lock");
        map.clear();
    }
}
