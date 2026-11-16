//! SSHBool Tauri application crate.
#![allow(clippy::type_complexity, clippy::too_many_arguments)]

mod commands;
mod connectivity;
mod container;
pub mod desktop_bridge;
mod error;
mod events;
mod guacamole_protocol;
mod guacamole_token;
mod guacd_manager;
#[cfg(test)]
mod mcp_e2e_tests;
mod mcp_executor;
mod rdp_cert;
mod rdp_credentials;
#[cfg(target_os = "windows")]
mod rdp_windows;
mod tray;
mod vnc_auth;

use std::sync::Arc;

use infrastructure::AppState;
use tauri::{Emitter, Manager};
use tracing_subscriber::EnvFilter;

#[cfg(target_os = "windows")]
#[allow(dead_code)]
mod win32 {
    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetConsoleWindow() -> *mut std::ffi::c_void;
    }
    #[link(name = "user32")]
    extern "system" {
        pub fn ShowWindow(hwnd: *mut std::ffi::c_void, nCmdShow: i32) -> i32;
    }
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn hide_console_window() {
    unsafe {
        let hwnd = win32::GetConsoleWindow();
        if !hwnd.is_null() {
            win32::ShowWindow(hwnd, 0); // 0 is SW_HIDE
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // #[cfg(target_os = "windows")]
    // hide_console_window();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("sshbool=info".parse().unwrap()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            tracing::debug!("single instance activated ({} args)", args.len());
            let _ = app.emit("single-instance-deep-link", &args);
            let _ = app.emit("deep-link://new-url", &args);
            // Launching SSHBool again (e.g. from the app menu) brings the tray instance back.
            tray::show_main(app);
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.emit("single-instance-deep-link", &args);
                let _ = window.emit("deep-link://new-url", &args);
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![tray::MINIMIZED_ARG]),
        ))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            use tauri_plugin_deep_link::DeepLinkExt;
            #[cfg(any(target_os = "linux", all(debug_assertions, windows)))]
            if let Err(e) = app.deep_link().register_all() {
                tracing::warn!("Failed to register deep link URL schemes: {e}");
            }

            // ── Deep-link startup args ───────────────────────────────────
            // If this instance was launched directly with a sshbool:// URL (e.g. the OS
            // protocol handler), forward it to the frontend. A second instance never writes
            // files: tauri-plugin-single-instance hands its args to the primary instance.
            {
                let deep_link_arg = std::env::args()
                    .skip(1)
                    .find(|a| a.starts_with("sshbool://"));
                if let Some(url) = deep_link_arg {
                    // Deep links can carry license keys — never log the URL itself.
                    tracing::info!("[STARTUP] deep link detected in args");
                    let _ = app.emit("single-instance-deep-link", vec![url.clone()]);
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                        let _ = window.emit("single-instance-deep-link", vec![url]);
                    }
                }
            }

            // Remove handoff/activation files left in the home directory by older versions.
            if let Some(home) = dirs::home_dir() {
                for stale in [
                    "sshbool_deep_link_handoff.txt",
                    "sshbool_activation_log.txt",
                ] {
                    let _ = std::fs::remove_file(home.join(stale));
                }
            }

            let handle = app.handle().clone();
            tauri::async_runtime::block_on(async move {
                let state = AppState::bootstrap()
                    .await
                    .map_err(|e| format!("bootstrap failed: {e}"))?;
                handle.manage(state);
                Ok::<(), String>(())
            })?;

            // ── System tray + background mode ─────────────────────────
            tray::setup(app)?;
            connectivity::spawn(app);
            commands::mcp::autostart(app);
            // The main window starts hidden (tauri.conf.json) so a login-item launch
            // (`--minimized`) goes straight to the tray without flashing a window.
            if !tray::started_minimized() {
                if let Some(main) = app.get_webview_window("main") {
                    let _ = main.show();
                    let _ = main.set_focus();
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == "main" {
                match event {
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        tray::on_main_close_requested(window.app_handle(), api);
                    }
                    tauri::WindowEvent::Focused(_) => {
                        // Keep the tray's Show/Hide label in sync with the window.
                        let app = window.app_handle().clone();
                        tauri::async_runtime::spawn(
                            async move { tray::refresh(&app, false).await },
                        );
                    }
                    _ => {}
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault::vault_status,
            commands::vault::vault_init,
            commands::vault::vault_unlock,
            commands::vault::vault_lock,
            commands::vault::vault_auto_unlock,
            commands::vault::vault_backup,
            commands::vault::vault_restore,
            commands::vault::keys_list,
            commands::vault::keys_generate,
            commands::vault::keys_import,
            commands::vault::keys_import_file,
            commands::vault::keys_export_public,
            commands::vault::keys_export_private,
            commands::vault::keys_export_private_file,
            commands::vault::keys_rename,
            commands::vault::keys_delete,
            commands::vault::keys_copy_public,
            commands::vault::credentials_list,
            commands::vault::credentials_create,
            commands::vault::credentials_delete,
            commands::hosts::hosts_list_tree,
            commands::hosts::hosts_get,
            commands::hosts::hosts_create,
            commands::hosts::hosts_update,
            commands::hosts::hosts_delete,
            commands::hosts::hosts_toggle_favorite,
            commands::hosts::hosts_toggle_pin,
            commands::hosts::hosts_search,
            commands::hosts::hosts_list_recent,
            commands::hosts::hosts_import,
            commands::hosts::hosts_import_commit,
            commands::hosts::hosts_export,
            commands::hosts::groups_create,
            commands::hosts::groups_rename,
            commands::hosts::groups_delete,
            commands::hosts::tags_list,
            commands::hosts::tags_add,
            commands::hosts::tags_remove,
            commands::hosts::known_hosts_list,
            commands::hosts::known_hosts_trust,
            commands::hosts::known_hosts_delete,
            commands::hosts::session_open,
            commands::hosts::session_close,
            commands::sessions::pane_open,
            commands::sessions::pane_close,
            commands::sessions::pane_resize,
            commands::sessions::pane_write,
            commands::sessions::pane_scrollback,
            commands::sessions::sessions_list,
            commands::sessions::command_history_search,
            commands::transfers::sftp_list_dir,
            commands::transfers::sftp_stat,
            commands::transfers::sftp_mkdir,
            commands::transfers::sftp_rename,
            commands::transfers::sftp_delete,
            commands::transfers::sftp_copy,
            commands::transfers::sftp_chmod,
            commands::transfers::sftp_read,
            commands::transfers::sftp_write,
            commands::transfers::local_home,
            commands::transfers::local_list_dir,
            commands::transfers::local_mkdir,
            commands::transfers::local_rename,
            commands::transfers::local_copy,
            commands::transfers::local_delete,
            commands::transfers::transfer_upload,
            commands::transfers::transfer_upload_many,
            commands::transfers::transfer_download,
            commands::transfers::transfers_list,
            commands::transfers::transfer_pause,
            commands::transfers::transfer_resume,
            commands::transfers::transfer_cancel,
            commands::productivity::snippets_list,
            commands::productivity::snippets_upsert,
            commands::productivity::snippets_delete,
            commands::productivity::snippets_run,
            commands::productivity::notes_list,
            commands::productivity::notes_upsert,
            commands::productivity::notes_delete,
            commands::productivity::templates_list,
            commands::productivity::templates_render,
            commands::productivity::search_global,
            commands::productivity::settings_get,
            commands::productivity::settings_set,
            commands::clipboard::clipboard_write_text,
            commands::clipboard::clipboard_read_text,
            commands::productivity::keybindings_list,
            commands::productivity::keybindings_set,
            commands::productivity::app_info,
            commands::productivity::update_download_and_install,
            commands::tunnels::proxies_list,
            commands::tunnels::proxies_upsert,
            commands::tunnels::port_forwards_upsert,
            commands::tunnels::port_forwards_delete,
            commands::tunnels::port_forwards_list,
            commands::tunnels::port_forwards_start,
            commands::tunnels::port_forwards_stop,
            commands::tunnels::port_check_available,
            commands::monitoring::monitoring_start,
            commands::monitoring::monitoring_stop,
            commands::monitoring::monitoring_snapshot,
            commands::monitoring::monitoring_series,
            commands::monitoring::processes_list,
            commands::monitoring::process_kill,
            commands::monitoring::services_list,
            commands::monitoring::service_control,
            commands::docker::docker_list_containers,
            commands::docker::docker_container_action,
            commands::docker::docker_list_images,
            commands::docker::docker_logs,
            commands::docker::docker_compose_action,
            commands::ai::ai_providers_list,
            commands::ai::ai_providers_upsert,
            commands::ai::ai_send,
            commands::ai::ai_explain_command,
            commands::ai::ai_generate_command,
            commands::recording::recording_start,
            commands::recording::recording_stop,
            commands::recording::folders_compare,
            commands::tunnels::auth_fido2_status,
            commands::editor::editor_git_status,
            commands::editor::editor_diff,
            commands::desktop::rdp_launch_native,
            commands::desktop::desktop_inapp_connect,
            commands::desktop::desktop_inapp_disconnect,
            commands::desktop::desktop_guacamole_connect,
            commands::desktop::rdp_cert_forget,
            commands::desktop::desktop_guacd_setup,
            commands::windows::workspace_window_open,
            commands::windows::window_minimize,
            commands::windows::window_toggle_maximize,
            commands::windows::window_close,
            commands::windows::window_toggle_pin,
            commands::windows::tray_get_data,
            commands::windows::workspace_window_open_with_host,
            commands::windows::app_quit,
            commands::windows::tray_close,
            commands::windows::app_busy_set,
            connectivity::network_check,
            commands::windows::background_settings_get,
            commands::windows::background_settings_set,
            commands::databases::db_connections_list,
            commands::databases::db_connections_upsert,
            commands::databases::db_connections_delete,
            commands::databases::db_query,
            commands::databases::db_introspect,
            commands::databases::db_table_preview,
            commands::databases::db_detect,
            commands::databases::saved_queries_list,
            commands::databases::saved_queries_upsert,
            commands::kubernetes::k8s_contexts_list,
            commands::kubernetes::k8s_get_pods,
            commands::kubernetes::k8s_get_deployments,
            commands::kubernetes::k8s_logs,
            commands::kubernetes::k8s_apply,
            commands::devtools::devtools_probe,
            commands::devtools::devtools_git_status,
            commands::devtools::devtools_run,
            commands::sync::sync_status,
            commands::sync::sync_configure,
            commands::sync::sync_export_bundle,
            commands::sync::sync_pair_device,
            commands::sync::sync_devices_list,
            commands::audit_log::audit_list,
            commands::audit_log::audit_export,
            commands::plugins::plugins_list,
            commands::plugins::plugins_install,
            commands::plugins::plugins_set_enabled,
            commands::plugins::plugins_uninstall,
            commands::sync::sync_enable,
            commands::sync::sync_disable,
            commands::sync::sync_push,
            commands::sync::sync_pull,
            commands::sync::sync_unpair,
            commands::sync::sync_resolve_conflict,
            commands::plugins::plugins_search_marketplace,
            commands::license::license_status,
            commands::license::license_activate,
            commands::license::license_clear,
            commands::team::team_status,
            commands::team::team_join_stub,
            commands::team::team_list_shared,
            commands::team::team_apply_policy,
            commands::team::retention_prune,
            commands::mcp::mcp_server_start,
            commands::mcp::mcp_server_stop,
            commands::mcp::mcp_server_status,
            commands::mcp::mcp_pairing_code_create,
            commands::mcp::mcp_client_pair,
            commands::mcp::mcp_clients_list,
            commands::mcp::mcp_client_set_mode,
            commands::mcp::mcp_client_set_enabled,
            commands::mcp::mcp_client_delete,
            commands::mcp::mcp_client_grant_host,
            commands::mcp::mcp_client_revoke_host,
            commands::mcp::mcp_calls_list,
            commands::mcp::mcp_approvals_pending,
            commands::mcp::mcp_approval_respond,
            commands::mcp::mcp_kill_switch,
            commands::mcp::mcp_grants_list,
            commands::mcp::mcp_grant_revoke,
            commands::mcp::mcp_budgets_get,
            commands::mcp::mcp_budgets_set,
            commands::mcp::mcp_policy_list,
        ])
        .build(tauri::generate_context!())
        .expect("error while building SSHBool")
        .run(|_app, event| {
            if let tauri::RunEvent::Exit = event {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(rt) = rt {
                    rt.block_on(crate::guacd_manager::shutdown_guacd());
                }
            }
        });
}

pub use container::AppContainer;
pub use error::AppError;

/// Shared managed state alias.
pub type ManagedState = Arc<AppState>;
