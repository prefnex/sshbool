import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow"
import { useEffect } from "react"

import { useLayoutStore } from "@/stores/layout.store"
import { useSessionStore } from "@/stores/session.store"

type FocusSessionPayload = { hostId: string; paneId: string }

/**
 * Handles actions picked from the native tray menu (src-tauri/src/tray.rs).
 * Rust targets these at the main window only, so workspace windows ignore them.
 */
export function useTrayEvents() {
  useEffect(() => {
    const win = getCurrentWebviewWindow()
    if (win.label !== "main") return

    let cancelled = false
    const unlisteners: Array<() => void> = []
    const track = (p: Promise<() => void>) => {
      void p.then((fn) => {
        if (cancelled) fn()
        else unlisteners.push(fn)
      })
    }

    track(
      win.listen<FocusSessionPayload>("tray://focus-session", ({ payload }) => {
        const layout = useLayoutStore.getState()
        layout.setSelectedHostId(payload.hostId)
        layout.setActivity("terminal")
        useSessionStore.getState().setActive(payload.paneId)
      })
    )
    track(
      win.listen("tray://new-connection", () => {
        const layout = useLayoutStore.getState()
        layout.setActivity("connections")
        layout.setAddHostOpen(true)
      })
    )
    track(
      win.listen("tray://open-settings", () => {
        useLayoutStore.getState().setActivity("settings")
      })
    )

    return () => {
      cancelled = true
      unlisteners.forEach((fn) => fn())
    }
  }, [])
}
