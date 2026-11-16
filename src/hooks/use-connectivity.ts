import { listen } from "@tauri-apps/api/event"
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow"
import { useEffect } from "react"

import {
  handleSessionLost,
  type SessionLostEvent,
} from "@/features/connections/connect-host"
import { ipc } from "@/lib/ipc/commands"
import { useConnectionStore } from "@/stores/connection.store"
import { useNetworkStore } from "@/stores/network.store"

/**
 * Keeps the network indicator and host connection states in sync with Rust
 * (src-tauri/src/connectivity.rs). The main window drives automatic reconnects;
 * secondary windows only flag the host as lost.
 */
export function useConnectivity() {
  useEffect(() => {
    const isMain = getCurrentWebviewWindow().label === "main"
    const setOnline = useNetworkStore.getState().setOnline
    let cancelled = false
    const unlisteners: Array<() => void> = []
    const track = (p: Promise<() => void>) => {
      void p.then((fn) => {
        if (cancelled) fn()
        else unlisteners.push(fn)
      })
    }

    const recheck = () => {
      void ipc
        .networkCheck()
        .then((online) => {
          if (!cancelled) setOnline(online)
        })
        .catch(() => {})
    }
    recheck()

    track(
      listen<{ online: boolean }>("network://status", ({ payload }) =>
        setOnline(payload.online)
      )
    )
    track(
      listen<SessionLostEvent>("ssh://session-lost", ({ payload }) => {
        if (isMain) {
          void handleSessionLost(payload)
          return
        }
        const conn = useConnectionStore.getState()
        const cur = conn.byHost[payload.hostId]
        if (cur?.status === "connected") {
          conn.setError(payload.hostId, `Connection lost: ${payload.reason}`, {
            lost: true,
          })
        }
      })
    )

    // The OS knows about link changes before our periodic probe does.
    const onOffline = () => {
      setOnline(false)
      recheck()
    }
    window.addEventListener("online", recheck)
    window.addEventListener("offline", onOffline)

    return () => {
      cancelled = true
      unlisteners.forEach((fn) => fn())
      window.removeEventListener("online", recheck)
      window.removeEventListener("offline", onOffline)
    }
  }, [])
}
