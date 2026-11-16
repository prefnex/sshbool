import { confirm } from "@tauri-apps/plugin-dialog"
import { getCurrentWindow } from "@tauri-apps/api/window"
import { useEffect } from "react"

import { ipc } from "@/lib/ipc/commands"

function isBusy(status: string) {
  return status === "active" || status === "queued"
}

/**
 * Warn before closing a secondary window while uploads/downloads are still running.
 * The main window's close/quit is handled in Rust (src-tauri/src/tray.rs): closing it hides
 * SSHBool to the tray, and quitting warns about transfers there. A JS close listener on the
 * main window would destroy it instead of hiding it.
 */
export function useTransferCloseGuard(enabled = true) {
  useEffect(() => {
    if (!enabled) return

    let cancelled = false
    let unlisten: (() => void) | undefined

    void (async () => {
      const win = getCurrentWindow()
      if (win.label === "main" || cancelled) return
      unlisten = await win.onCloseRequested(async (event) => {
        let active = 0
        try {
          const list = await ipc.transfersList()
          active = list.filter((t) => isBusy(t.status)).length
        } catch {
          return
        }
        if (active === 0) return

        event.preventDefault()
        const ok = await confirm(
          active === 1
            ? "A file transfer is still in progress (upload/download). Close SSHBool anyway?"
            : `${active} file transfers are still in progress. Close SSHBool anyway?`,
          {
            title: "Transfers in progress",
            kind: "warning",
            okLabel: "Close anyway",
            cancelLabel: "Keep open",
          }
        )
        if (ok && !cancelled) {
          await win.destroy()
        }
      })
    })()

    return () => {
      cancelled = true
      unlisten?.()
    }
  }, [enabled])
}
