# Changelog

All notable changes to SSHBool are documented in this file.

## [v0.1.12] - 2026-11-19

### Added

- **MCP Activity Output Viewer**: Persist redacted, size-capped (256 KB) MCP tool outputs in SQLite (`0022_mcp_call_outputs` migration) and inspect them in a split-pane Activity tab with live follow, search, outcome filters (`All`, `Allowed`, `Denied`, `Failed`), syntax-highlighted commands, and ANSI-colored terminal output.
- **Pending Approvals Title-Bar Queue**: Add a title-bar pending-approvals indicator and popover (`PendingApprovalsButton`) so dismissed dialogs remain accessible, can be reopened on any queued request, or denied directly.
- **MCP Approval Queue Navigation**: Support browsing multiple pending approval requests (`Previous` / `Next`), deferring via `Later` without deciding, and automatically pruning expired or resolved requests.
- **Approval Lifecycle Cleanup**: Automatically revoke and notify the UI (`mcp://approval-resolved`) via `PendingApprovalGuard` whenever an approval is decided, times out, or its MCP caller disconnects.

### Fixed

- Prevent main-window flicker when new MCP approval requests arrive while the window is already visible and focused.
- Register the approval broker before emitting `mcp://approval-request` so instant approvals cannot race ahead of the gate.
- Clean up production-confirmation and clipboard-copy timers on request change/unmount, handle clipboard rejections safely, and guard MCP event listener registration against errors.

## [v0.1.11] - 2026-11-18

### Fixed

- Make the MCP approval dialog body scrollable so long commands never push action buttons off screen, and preserve real line breaks in multi-line commands.

## [v0.1.10] - 2026-11-17

### Added

- Make MCP server free for all users (`mcp_server` in `FREE_FEATURES`) with Streamable HTTP protocol compliance, 42 real tools, command-injection hardening, per-host permission enforcement, tray autostart, and pairing UX improvements.
- Refactor backend commands into modular files, enhance RDP certificate/auto-login support, add network connectivity indicator, and add tray background mode.
