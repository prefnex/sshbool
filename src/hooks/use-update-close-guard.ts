import { confirm } from "@tauri-apps/plugin-dialog"
import { getCurrentWindow } from "@tauri-apps/api/window"
import { useEffect } from "react"

import { ipc } from "@/lib/ipc/commands"

/**
 * Warn before closing while an update download/install is in progress.
 * For the main window Rust owns close/quit (tray.rs), so we only report the busy state.
 */
export function useUpdateCloseGuard(active: boolean, isForced = false) {
  useEffect(() => {
    if (getCurrentWindow().label !== "main") return
    void ipc.appBusySet("update", active).catch(() => {})
    return () => {
      void ipc.appBusySet("update", false).catch(() => {})
    }
  }, [active])

  useEffect(() => {
    if (!active || getCurrentWindow().label === "main") {
      return
    }

    let cancelled = false
    let unlisten: (() => void) | undefined

    void (async () => {
      const win = getCurrentWindow()
      unlisten = await win.onCloseRequested(async (event) => {
        event.preventDefault()

        const ok = await confirm(
          isForced
            ? "A mandatory update is still installing. Closing SSHBool may leave the app in an inconsistent state. Close anyway?"
            : "An update is still downloading or installing. Close SSHBool anyway?",
          {
            title: isForced
              ? "Mandatory update in progress"
              : "Update in progress",
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
  }, [active, isForced])
}
