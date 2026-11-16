//! Remote desktop: native RDP clients, in-app Guacamole RDP and noVNC.

use infrastructure::{audit, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;

use crate::error::AppError;

async fn pick_local_port() -> Result<u16, AppError> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| AppError::Internal {
            message: format!("failed to pick local port for RDP tunnel: {e}"),
        })?;
    let port = listener
        .local_addr()
        .map_err(|e| AppError::Internal {
            message: format!("failed to read local port for RDP tunnel: {e}"),
        })?
        .port();
    Ok(port)
}

async fn resolve_host_vault_password(
    state: &State<'_, Arc<AppState>>,
    host_id: &str,
) -> Option<String> {
    let cred_id = sqlx::query_as::<_, (String,)>("SELECT value FROM settings WHERE key = ?")
        .bind(format!("host:{host_id}:cred"))
        .fetch_optional(state.vault.pool())
        .await
        .ok()?;
    let (cid,) = cred_id?;
    let secret = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT ciphertext, nonce FROM credentials WHERE id = ?",
    )
    .bind(&cid)
    .fetch_optional(state.vault.pool())
    .await
    .ok()?;
    let (ct, nonce) = secret?;
    state
        .vault
        .open_secret(&ct, &nonce, &format!("cred:{cid}"))
        .await
        .ok()
        .map(|plain| String::from_utf8_lossy(&plain).into_owned())
}

#[tauri::command]
pub async fn rdp_launch_native(
    _app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    host_id: Option<String>,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    domain: Option<String>,
    share_clipboard: Option<bool>,
    smart_sizing: Option<bool>,
    admin_mode: Option<bool>,
    full_screen: Option<bool>,
    width: Option<u32>,
    height: Option<u32>,
    color_depth: Option<u32>,
    performance: Option<String>,
    use_ssh_credentials: Option<bool>,
) -> Result<Value, AppError> {
    let u = username.unwrap_or_default();
    let d = domain.unwrap_or_default();
    let use_ssh = use_ssh_credentials.unwrap_or(true);
    let hid = host_id.ok_or(AppError::Validation {
        field: "hostId".into(),
        message: "hostId is required to establish the SSH RDP tunnel".into(),
    })?;

    let mut p = password.as_deref().unwrap_or("").to_string();
    if p == "••••••••" || (use_ssh && p.is_empty()) {
        tracing::info!("RDP Launch: Resolving vault password for host_id = {}", hid);
        if let Some(vault_pass) = resolve_host_vault_password(&state, &hid).await {
            p = vault_pass;
            tracing::info!(
                "RDP Launch: Successfully decrypted password from vault (len={})",
                p.len()
            );
        } else {
            tracing::warn!("RDP Launch: No vault password found for host {}", hid);
        }
    }

    if use_ssh && p.is_empty() {
        return Err(AppError::Validation {
            field: "password".into(),
            message: "No SSH password saved for this host. Add a password in host settings or turn off “Use SSH credentials” and enter RDP credentials manually.".into(),
        });
    }

    let remote_dest = if host.is_empty() || host == "localhost" {
        "127.0.0.1".to_string()
    } else {
        host.clone()
    };

    match state
        .connections
        .probe_remote_tcp(&hid, &remote_dest, port)
        .await
    {
        Ok(true) => {
            tracing::info!("RDP Launch: remote {remote_dest}:{port} is reachable on SSH host {hid}")
        }
        Ok(false) => {
            return Err(AppError::Internal {
                message: format!(
                    "No RDP service is listening on {remote_dest}:{port} on the SSH host. \
                     On Linux install/start xRDP (sudo apt install xrdp && sudo systemctl enable --now xrdp). \
                     On Windows enable Remote Desktop."
                ),
            });
        }
        Err(e) => tracing::warn!("RDP Launch: remote port probe failed: {e}"),
    }

    let tunnel_forward_id = format!("rdp-tunnel-{hid}");
    let local_port = if state
        .connections
        .forward_is_active(&tunnel_forward_id)
        .await
    {
        if let Some(existing) = state
            .connections
            .forward_local_port(&tunnel_forward_id)
            .await
        {
            tracing::info!(
                "RDP Launch: reusing active tunnel on 127.0.0.1:{existing} -> {remote_dest}:{port}"
            );
            existing
        } else {
            let _ = state
                .connections
                .port_forward_stop(&tunnel_forward_id)
                .await;
            let picked = pick_local_port().await?;
            state
                .connections
                .port_forward_start(
                    &tunnel_forward_id,
                    &hid,
                    "127.0.0.1",
                    picked,
                    &remote_dest,
                    port,
                )
                .await?;
            picked
        }
    } else {
        let _ = state
            .connections
            .port_forward_stop(&tunnel_forward_id)
            .await;
        let picked = pick_local_port().await?;
        state
            .connections
            .port_forward_start(
                &tunnel_forward_id,
                &hid,
                "127.0.0.1",
                picked,
                &remote_dest,
                port,
            )
            .await?;
        picked
    };

    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    // VULN-08: pin the RDP server certificate (TOFU) before any client sees the password.
    crate::rdp_cert::verify_or_pin(state.vault.pool(), &hid, &remote_dest, port, local_port)
        .await?;

    let connect_host = "127.0.0.1";
    #[cfg(not(target_os = "windows"))]
    let rdp_client = "native";
    #[cfg(target_os = "windows")]
    let (rdp_client, freerdp_fallback) = {
        let w = width.unwrap_or(1920);
        let h = height.unwrap_or(1080);
        let bpp = color_depth.unwrap_or(32);
        let perf_str = performance.as_deref().unwrap_or("auto");
        let connection_val = match perf_str {
            "modem" => 1,
            "broadband" => 2,
            "lan" => 5,
            _ => 6,
        };
        let mstsc_opts = crate::rdp_windows::MstscLaunchOpts {
            connect_host,
            local_port,
            username: &u,
            password: &p,
            domain: &d,
            share_clipboard: share_clipboard.unwrap_or(true),
            smart_sizing: smart_sizing.unwrap_or(true),
            admin_mode: admin_mode.unwrap_or(false),
            full_screen: full_screen.unwrap_or(false),
            width: w,
            height: h,
            color_depth: bpp,
            connection_type: connection_val,
        };

        crate::rdp_windows::launch_mstsc(&mstsc_opts)
            .map_err(|message| AppError::Internal { message })?;
        ("mstsc", false)
    };

    #[cfg(target_os = "macos")]
    {
        let connect_addr = format!("{connect_host}:{local_port}");
        use std::io::Write;
        use std::process::Command;

        let clipboard_val = if share_clipboard.unwrap_or(true) {
            1
        } else {
            0
        };
        let sizing_val = if smart_sizing.unwrap_or(true) { 1 } else { 0 };
        let admin_val = if admin_mode.unwrap_or(false) { 1 } else { 0 };
        let screen_mode_val = if full_screen.unwrap_or(false) { 2 } else { 1 };

        let w = width.unwrap_or(1920);
        let h = height.unwrap_or(1080);
        let bpp = color_depth.unwrap_or(32);

        let domain_line = if d.is_empty() {
            String::new()
        } else {
            format!("domain:s:{d}\r\n")
        };
        let domain_param = if d.is_empty() {
            String::new()
        } else {
            format!("&domain=s:{d}")
        };

        let rdp_content = format!(
            "full address:s:{connect_addr}\r\n\
             username:s:{u}\r\n\
             {domain_line}\
             prompt for credentials:i:0\r\n\
             authentication level:i:0\r\n\
             redirectclipboard:i:{clipboard_val}\r\n\
             smart sizing:i:{sizing_val}\r\n\
             administrative session:i:{admin_val}\r\n\
             screen mode id:i:{screen_mode_val}\r\n\
             desktopwidth:i:{w}\r\n\
             desktopheight:i:{h}\r\n\
             session bpp:i:{bpp}\r\n"
        );

        let temp_file_name = format!(".sshbool_rdp_{}.rdp", uuid::Uuid::now_v7());
        let temp_path = std::env::temp_dir().join(&temp_file_name);
        if let Ok(mut file) = std::fs::File::create(&temp_path) {
            let _ = file.write_all(rdp_content.as_bytes());
            let _ = Command::new("open").arg(&temp_path).spawn();
        } else {
            let url = format!(
                "rdp://full%20address=s:{connect_addr}&username=s:{u}{domain_param}&redirectclipboard=i:{clipboard_val}&smartsizing=i:{sizing_val}&desktopwidth=i:{w}&desktopheight=i:{h}&bpp=i:{bpp}"
            );
            let _ = Command::new("open").arg(&url).spawn();
        }
    }

    #[cfg(target_os = "linux")]
    {
        let connect_addr = format!("{connect_host}:{local_port}");
        use std::io::Write;
        use std::process::Command;

        let is_wayland = std::env::var("XDG_SESSION_TYPE")
            .map(|v| v.to_lowercase() == "wayland")
            .unwrap_or(false)
            || std::env::var("WAYLAND_DISPLAY").is_ok();

        let w = width.unwrap_or(1920);
        let h = height.unwrap_or(1080);
        let bpp = color_depth.unwrap_or(32);
        let perf_str = performance.as_deref().unwrap_or("auto");
        let _connection_val = match perf_str {
            "modem" => 1,
            "broadband" => 2,
            "lan" => 5,
            _ => 6, // auto
        };

        let has_pass = !p.is_empty();

        let mut args = vec![
            format!("/v:{connect_addr}"),
            format!("/u:{u}"),
            // The certificate was already pinned by rdp_cert::verify_or_pin over this tunnel.
            // FreeRDP's own store is keyed by the random local port, so tofu there would
            // prompt on port reuse; keep the pre-existing behaviour.
            "/cert:ignore".to_string(),
        ];
        if !d.is_empty() {
            args.push(format!("/d:{d}"));
        }
        if has_pass {
            args.push("/from-stdin:force".to_string());
        }
        if share_clipboard.unwrap_or(true) {
            args.push("+clipboard".to_string());
        } else {
            args.push("-clipboard".to_string());
        }
        if smart_sizing.unwrap_or(true) {
            args.push("/smart-sizing".to_string());
        }
        if admin_mode.unwrap_or(false) {
            args.push("/admin".to_string());
        }
        if full_screen.unwrap_or(false) {
            args.push("/f".to_string());
        } else if width.is_some() || height.is_some() {
            args.push(format!("/size:{w}x{h}"));
        }
        args.push(format!("/bpp:{bpp}"));
        let mut spawned = false;
        let mut last_error_msg = String::new();

        // 1. Try Wayland native client if running in Wayland session
        if is_wayland {
            let mut cmd = Command::new("wlfreerdp");
            cmd.args(&args);
            if has_pass {
                cmd.stdin(std::process::Stdio::piped());
            }
            match cmd.spawn() {
                Ok(mut child) => {
                    spawned = true;
                    if has_pass {
                        let p_clone = p.clone();
                        std::thread::spawn(move || {
                            if let Some(mut stdin) = child.stdin.take() {
                                let _ = stdin.write_all(p_clone.as_bytes());
                                let _ = stdin.flush();
                            }
                            let _ = child.wait();
                        });
                    }
                }
                Err(e) => {
                    last_error_msg = e.to_string();
                }
            }
        }

        // 2. Fallback to X11 client (xfreerdp)
        if !spawned {
            let mut cmd = Command::new("xfreerdp");
            cmd.args(&args);
            if has_pass {
                cmd.stdin(std::process::Stdio::piped());
            }
            match cmd.spawn() {
                Ok(mut child) => {
                    spawned = true;
                    if has_pass {
                        let p_clone = p.clone();
                        std::thread::spawn(move || {
                            if let Some(mut stdin) = child.stdin.take() {
                                let _ = stdin.write_all(p_clone.as_bytes());
                                let _ = stdin.flush();
                            }
                            let _ = child.wait();
                        });
                    }
                }
                Err(e) => {
                    last_error_msg = e.to_string();
                }
            }
        }

        if !spawned {
            let msg = if is_wayland {
                format!(
                    "RDP client not found (tried wlfreerdp and xfreerdp). \
                     Please install FreeRDP to connect. Since you are on Wayland, you can run:\n\
                     'sudo apt install freerdp2-wayland' (for native wlfreerdp)\n\
                     or 'sudo apt install freerdp2-x11' (for xfreerdp via XWayland).\n\
                     Details: {last_error_msg}"
                )
            } else {
                format!(
                    "RDP client 'xfreerdp' not found in PATH. Please install FreeRDP to connect, e.g. run:\n\
                     'sudo apt install freerdp2-x11' or 'sudo apt install freerdp3-x11'.\n\
                     Details: {last_error_msg}"
                )
            };
            return Err(AppError::Internal { message: msg });
        }
    }

    #[cfg(not(target_os = "windows"))]
    let freerdp_fallback = false;

    Ok(json!({
        "localHost": connect_host,
        "localPort": local_port,
        "remoteHost": remote_dest,
        "remotePort": port,
        "forwardId": tunnel_forward_id,
        "rdpClient": rdp_client,
        "autoLogin": use_ssh && !p.is_empty(),
        "freerdpFallback": freerdp_fallback,
    }))
}

async fn ensure_desktop_tunnel(
    state: &State<'_, Arc<AppState>>,
    host_id: &str,
    dest_host: &str,
    remote_port: u16,
) -> Result<u16, AppError> {
    let tunnel_id = format!("inapp-desktop-tunnel-{host_id}");

    let local_tcp_port = if state.connections.forward_is_active(&tunnel_id).await {
        if let Some(existing) = state.connections.forward_local_port(&tunnel_id).await {
            existing
        } else {
            let _ = state.connections.port_forward_stop(&tunnel_id).await;
            let picked = pick_local_port().await?;
            state
                .connections
                .port_forward_start(
                    &tunnel_id,
                    host_id,
                    "127.0.0.1",
                    picked,
                    dest_host,
                    remote_port,
                )
                .await?;
            picked
        }
    } else {
        let _ = state.connections.port_forward_stop(&tunnel_id).await;
        let picked = pick_local_port().await?;
        state
            .connections
            .port_forward_start(
                &tunnel_id,
                host_id,
                "127.0.0.1",
                picked,
                dest_host,
                remote_port,
            )
            .await?;
        picked
    };

    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    Ok(local_tcp_port)
}

/// Connect to in-app VNC desktop via local WebSocket-to-SSH bridge (noVNC).
#[tauri::command]
pub async fn desktop_inapp_connect(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    remote_target: String,
    remote_port: u16,
    protocol: Option<String>,
    password: Option<String>,
) -> Result<Value, AppError> {
    let dest_host = if remote_target.is_empty() || remote_target == "localhost" {
        "127.0.0.1".to_string()
    } else {
        remote_target
    };

    let local_tcp_port = ensure_desktop_tunnel(&state, &host_id, &dest_host, remote_port).await?;

    let session_id = format!("{host_id}-{remote_port}");
    let proto = protocol.unwrap_or_else(|| "vnc".into());

    // VULN-16: the password is used by the Rust bridge to answer the VNC challenge and is never
    // returned to the webview. A password typed in the UI wins over the vault one.
    let typed = password.filter(|p| !p.is_empty() && p != "••••••••");
    let vnc_password = match typed {
        Some(p) => Some(p),
        None => resolve_host_vault_password(&state, &host_id).await,
    }
    .map(zeroize::Zeroizing::new);
    let bridge_auth = vnc_password.is_some();

    let (ws_port, access_token) = crate::desktop_bridge::DESKTOP_BRIDGES
        .start_vnc(session_id.clone(), local_tcp_port, vnc_password)
        .await
        .map_err(|e| AppError::Internal { message: e })?;

    Ok(json!({
        "sessionId": session_id,
        "wsPort": ws_port,
        "wsUrl": format!("ws://127.0.0.1:{ws_port}/?token={access_token}"),
        "localTcpPort": local_tcp_port,
        "remoteHost": dest_host,
        "remotePort": remote_port,
        "protocol": proto,
        "bridgeAuth": bridge_auth,
    }))
}

/// Connect to in-app RDP via Guacamole + guacd (credentials stay in Rust token).
#[tauri::command]
pub async fn desktop_guacamole_connect(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    host_id: String,
    remote_target: String,
    remote_port: u16,
    username: Option<String>,
    password: Option<String>,
    domain: Option<String>,
    use_ssh_credentials: Option<bool>,
    width: Option<u32>,
    height: Option<u32>,
    color_depth: Option<u32>,
    performance: Option<String>,
) -> Result<Value, AppError> {
    let use_ssh = use_ssh_credentials.unwrap_or(true);
    let dest_host = if remote_target.is_empty() || remote_target == "localhost" {
        "127.0.0.1".to_string()
    } else {
        remote_target
    };

    let host_row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT username FROM hosts WHERE id = ?")
            .bind(&host_id)
            .fetch_optional(state.vault.pool())
            .await
            .ok()
            .flatten();

    let vault_user = host_row.and_then(|r| r.0).unwrap_or_default();

    let mut u = username.unwrap_or_default();
    if u.is_empty() && use_ssh {
        u = vault_user.clone();
    }

    let vault_pass = resolve_host_vault_password(&state, &host_id).await;
    let p = crate::rdp_credentials::resolve_rdp_password(
        &password.unwrap_or_default(),
        use_ssh,
        vault_pass.as_deref(),
    );

    if use_ssh && p.is_empty() {
        return Err(AppError::Validation {
            field: "password".into(),
            message: "No SSH password saved for this host. Add a password in host settings or enter RDP credentials manually.".into(),
        });
    }

    if u.is_empty() {
        return Err(AppError::Validation {
            field: "username".into(),
            message: "RDP username is required.".into(),
        });
    }

    crate::guacd_manager::ensure_guacd_running(Some(&app))
        .await
        .map_err(|message| AppError::Internal { message })?;

    let local_tcp_port = ensure_desktop_tunnel(&state, &host_id, &dest_host, remote_port).await?;

    // VULN-08: guacd can only ignore certificates, so we pin the certificate ourselves first.
    crate::rdp_cert::verify_or_pin(
        state.vault.pool(),
        &host_id,
        &dest_host,
        remote_port,
        local_tcp_port,
    )
    .await?;

    let session_id = format!("{host_id}-{remote_port}");
    let ws_port = crate::desktop_bridge::DESKTOP_BRIDGES
        .start_guacamole(session_id.clone())
        .await
        .map_err(|e| AppError::Internal { message: e })?;

    let w = width.unwrap_or(1280);
    let h = height.unwrap_or(720);
    let bpp = color_depth.unwrap_or(32);
    let perf = performance.unwrap_or_else(|| "auto".into());

    let token = crate::guacamole_token::build_rdp_token(
        "127.0.0.1",
        local_tcp_port,
        &u,
        &p,
        domain.as_deref(),
        w,
        h,
        bpp,
        &perf,
    )
    .map_err(|message| AppError::Internal { message })?;

    Ok(json!({
        "sessionId": session_id,
        "wsPort": ws_port,
        "wsUrl": format!("ws://127.0.0.1:{ws_port}"),
        "token": token,
        "localTcpPort": local_tcp_port,
        "remoteHost": dest_host,
        "remotePort": remote_port,
        "protocol": "rdp",
        "username": u,
    }))
}

/// Forget a pinned RDP certificate so the next connection trusts the server's current one.
#[tauri::command]
pub async fn rdp_cert_forget(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    remote_target: String,
    remote_port: u16,
) -> Result<(), AppError> {
    let target = if remote_target.is_empty() || remote_target == "localhost" {
        "127.0.0.1".to_string()
    } else {
        remote_target
    };
    crate::rdp_cert::forget(state.vault.pool(), &host_id, &target, remote_port).await?;
    audit(
        &state,
        "rdp.cert_forget",
        Some(&host_id),
        "ok",
        Some(json!({ "target": target, "port": remote_port })),
    )
    .await;
    Ok(())
}

/// Install/start guacd (Docker container or bundled binary).
#[tauri::command]
pub async fn desktop_guacd_setup(
    app: tauri::AppHandle,
    install_docker: Option<bool>,
) -> Result<Value, AppError> {
    let install = install_docker.unwrap_or(false);
    let message = crate::guacd_manager::provision_guacd_bundle(Some(&app), install)
        .map_err(|e| AppError::Internal { message: e })?;

    if !install {
        crate::guacd_manager::ensure_guacd_running(Some(&app))
            .await
            .map_err(|e| AppError::Internal { message: e })?;
    }

    Ok(json!({ "ok": true, "message": message }))
}

/// Disconnect in-app desktop bridge and stop tunnel.
#[tauri::command]
pub async fn desktop_inapp_disconnect(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    remote_port: Option<u16>,
) -> Result<(), AppError> {
    let port = remote_port.unwrap_or(5900);
    let session_id = format!("{host_id}-{port}");
    crate::desktop_bridge::DESKTOP_BRIDGES
        .stop(&session_id)
        .await;

    let tunnel_id = format!("inapp-desktop-tunnel-{host_id}");
    let _ = state.connections.port_forward_stop(&tunnel_id).await;
    Ok(())
}
