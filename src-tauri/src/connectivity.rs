//! Connectivity monitoring: internet reachability and SSH sessions that drop on their own.
//!
//! * `network://status` — `{ online: bool }`, emitted when reachability changes.
//! * `ssh://session-lost` — `{ hostId, sessionId, paneIds, reason }` when a session dies
//!   without the user disconnecting (network loss, server reboot/shutdown, keepalive timeout).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use infrastructure::AppState;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::error::AppError;

pub const NETWORK_STATUS: &str = "network://status";
pub const SESSION_LOST: &str = "ssh://session-lost";

const CHECK_EVERY: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Well-known anycast resolvers. Only a TCP handshake is made: no data is sent.
const PROBES: &[&str] = &[
    "1.1.1.1:443",
    "8.8.8.8:443",
    "9.9.9.9:443",
    "[2606:4700:4700::1111]:443",
];

#[derive(Default)]
pub struct NetworkState {
    online: AtomicBool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkStatus {
    online: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionLostEvent {
    host_id: String,
    session_id: String,
    pane_ids: Vec<String>,
    reason: String,
}

#[derive(Clone, Serialize)]
struct TerminalBytes {
    bytes: Vec<u8>,
}

/// True when at least one probe accepts a TCP connection.
async fn probe_internet() -> bool {
    let attempts = PROBES
        .iter()
        .filter_map(|a| a.parse::<SocketAddr>().ok())
        .map(|addr| {
            Box::pin(async move {
                matches!(
                    tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(addr)).await,
                    Ok(Ok(_))
                )
            })
        });
    let mut pending: Vec<_> = attempts.collect();
    while !pending.is_empty() {
        let (ok, _, rest) = futures_util::future::select_all(pending).await;
        if ok {
            return true;
        }
        pending = rest;
    }
    false
}

async fn update_network(app: &AppHandle, force_emit: bool) -> bool {
    let online = probe_internet().await;
    let state = app.state::<NetworkState>();
    let previous = state.online.swap(online, Ordering::Relaxed);
    if force_emit || previous != online {
        if previous != online {
            tracing::info!(
                "network is now {}",
                if online { "online" } else { "offline" }
            );
        }
        let _ = app.emit(NETWORK_STATUS, NetworkStatus { online });
    }
    online
}

/// Re-check reachability now (the UI calls this on browser online/offline events).
#[tauri::command]
pub async fn network_check(app: AppHandle) -> Result<bool, AppError> {
    Ok(update_network(&app, false).await)
}

fn lost_banner(reason: &str) -> Vec<u8> {
    format!("\r\n\x1b[1;31m● Connection lost\x1b[0m \x1b[2m— {reason}\x1b[0m\r\n").into_bytes()
}

/// Start the background monitors. Call from `setup` after `AppState` is managed.
pub fn spawn(app: &tauri::App) {
    app.manage(NetworkState {
        // Assume online until the first probe says otherwise (avoids a false "offline" flash).
        online: AtomicBool::new(true),
    });

    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        update_network(&handle, true).await;
        loop {
            tokio::time::sleep(CHECK_EVERY).await;
            update_network(&handle, false).await;
        }
    });

    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        let Some(state) = handle
            .try_state::<Arc<AppState>>()
            .map(|s| s.inner().clone())
        else {
            return;
        };
        loop {
            let lost = state.connections.next_lost_session().await;
            for pane_id in &lost.pane_ids {
                let _ = handle.emit(
                    &crate::events::terminal_data(pane_id),
                    TerminalBytes {
                        bytes: lost_banner(&lost.reason),
                    },
                );
            }
            let _ = handle.emit(
                SESSION_LOST,
                SessionLostEvent {
                    host_id: lost.host_id,
                    session_id: lost.session_id,
                    pane_ids: lost.pane_ids,
                    reason: lost.reason,
                },
            );
            crate::tray::refresh(&handle, false).await;
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn probes_parse() {
        for p in super::PROBES {
            assert!(p.parse::<std::net::SocketAddr>().is_ok(), "{p}");
        }
    }

    #[test]
    fn banner_is_terminal_safe() {
        let b = String::from_utf8(super::lost_banner("server stopped responding")).unwrap();
        assert!(b.starts_with("\r\n"));
        assert!(b.contains("Connection lost"));
        assert!(b.ends_with("\r\n"));
    }
}
