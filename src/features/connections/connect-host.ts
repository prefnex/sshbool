import { clearTerminalScrollback } from "@/features/terminal/terminal-scrollback"
import { formatAppError, IpcError, ipc } from "@/lib/ipc/commands"
import { useConnectionStore } from "@/stores/connection.store"
import { useNetworkStore, waitForOnline } from "@/stores/network.store"
import { useSessionStore } from "@/stores/session.store"
import { useTofuStore } from "@/stores/tofu.store"
import { toast } from "@/stores/toast.store"

function errMessage(err: unknown): string {
  if (err instanceof IpcError) return formatAppError(err.appError)
  if (err instanceof Error) return err.message
  return String(err)
}

function needsKeyPassphrase(err: unknown): boolean {
  if (err instanceof IpcError && err.appError.kind === "Validation") {
    return err.appError.field === "keyPassphrase"
  }
  const msg = errMessage(err).toLowerCase()
  return (
    msg.includes("encrypted") ||
    msg.includes("keypassphrase") ||
    msg.includes("passphrase")
  )
}

async function openSessionAndPane(
  hostId: string,
  opts?: { label?: string; openPane?: boolean },
  keyPassphrase?: string
): Promise<void> {
  const { sessionId } = await ipc.sessionOpen(hostId, keyPassphrase)

  const conn = useConnectionStore.getState()
  conn.setConnected(hostId, sessionId)

  if (opts?.openPane !== false) {
    const panes = useSessionStore.getState().panes
    const existing = panes.find((p) => p.hostId === hostId && !p.poppedOut)
    if (!existing) {
      const pane = await ipc.paneOpen(hostId, 120, 40)
      clearTerminalScrollback(pane.paneId)
      useSessionStore.getState().addPane({
        ...pane,
        title: opts?.label ?? pane.title,
      })
    }
  }

  toast.success("Connected", opts?.label ?? "SSH session ready")
}

/** Open SSH session for a host (shared by all tools). Optionally opens a terminal pane. */
export async function connectHost(
  hostId: string,
  opts?: { label?: string; openPane?: boolean }
): Promise<void> {
  cancelReconnect(hostId)
  const conn = useConnectionStore.getState()
  conn.clearError(hostId)
  conn.setConnecting(hostId)

  try {
    await openSessionAndPane(hostId, opts)
  } catch (err) {
    if (err instanceof IpcError && err.appError.kind === "FingerprintUnknown") {
      const { host, port, fingerprint, fingerprintMd5, keyType } = err.appError
      useTofuStore.getState().setPendingFingerprint({
        hostId,
        host,
        port,
        fingerprint,
        fingerprintMd5,
        keyType,
        opts,
      })
      conn.setIdle(hostId)
      return
    }

    if (err instanceof IpcError && err.appError.kind === "HostKeyChanged") {
      const { expected, actual } = err.appError
      useTofuStore.getState().setPendingHostKeyChanged({
        hostId,
        expected,
        actual,
      })
      conn.setError(hostId, "Host key changed - security warning")
      return
    }

    if (needsKeyPassphrase(err)) {
      const pass = window.prompt(
        "This SSH key is encrypted.\n\nEnter the key passphrase (not your vault password).\nIt will be unlocked once and stored safely in the vault."
      )
      if (pass != null && pass.trim()) {
        try {
          await openSessionAndPane(hostId, opts, pass.trim())
          return
        } catch (err2) {
          const message = errMessage(err2)
          conn.setError(hostId, message)
          toast.error("Connection failed", message)
          throw err2
        }
      }
    }
    const message = errMessage(err)
    conn.setError(hostId, message)
    toast.error("Connection failed", message)
    throw err
  }
}

/** Tear down SSH session + panes; SFTP/tools lose access until reconnect. */
export async function disconnectHost(hostId: string): Promise<void> {
  cancelReconnect(hostId)
  const session = useConnectionStore.getState().byHost[hostId]
  const panes = useSessionStore
    .getState()
    .panes.filter((p) => p.hostId === hostId)
  const removePane = useSessionStore.getState().removePane

  for (const p of panes) {
    try {
      await ipc.paneClose(p.paneId)
    } catch {
      /* already gone */
    }
    removePane(p.paneId)
  }

  const sessionId = session?.sessionId ?? panes[0]?.sessionId
  if (sessionId) {
    try {
      await ipc.sessionClose(sessionId)
    } catch {
      /* already gone */
    }
  }

  useConnectionStore.getState().setIdle(hostId)
  toast.info("Disconnected")
}

// ── Automatic reconnect after a dropped session ─────────────────────

/** Payload of the Rust `ssh://session-lost` event (connectivity.rs). */
export type SessionLostEvent = {
  hostId: string
  sessionId: string
  paneIds: string[]
  reason: string
}

const RETRY_DELAYS_MS = [1_000, 3_000, 8_000, 15_000, 30_000]
/** Stop waiting for the network after this long and report the host as lost. */
const MAX_OFFLINE_WAIT_MS = 5 * 60_000

const reconnects = new Map<string, AbortController>()

/** Stop an automatic reconnect in progress (user connected/disconnected by hand). */
export function cancelReconnect(hostId: string): void {
  reconnects.get(hostId)?.abort()
  reconnects.delete(hostId)
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms)
    signal.addEventListener("abort", () => {
      clearTimeout(t)
      reject(new DOMException("aborted", "AbortError"))
    })
  })
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | "timeout"> {
  return Promise.race([
    p,
    new Promise<"timeout">((resolve) =>
      setTimeout(() => resolve("timeout"), ms)
    ),
  ])
}

/** Errors that another attempt cannot fix (they need the user). */
function isPermanent(err: unknown): boolean {
  if (err instanceof IpcError) {
    return [
      "FingerprintUnknown",
      "HostKeyChanged",
      "Unauthorized",
      "Auth",
      "NotFound",
      "Validation",
    ].includes(err.appError.kind)
  }
  return false
}

function hostLabel(hostId: string): string {
  return (
    useSessionStore.getState().panes.find((p) => p.hostId === hostId)?.title ??
    "Server"
  )
}

/** Re-open the SSH session and give every terminal tab of the host a fresh shell. */
async function restoreSession(hostId: string, signal: AbortSignal) {
  const { sessionId } = await ipc.sessionOpen(hostId)
  if (signal.aborted) {
    await ipc.sessionClose(sessionId).catch(() => {})
    throw new DOMException("aborted", "AbortError")
  }
  useConnectionStore.getState().setConnected(hostId, sessionId)

  const sessions = useSessionStore.getState()
  for (const old of sessions.panes.filter((p) => p.hostId === hostId)) {
    if (old.mcpHidden) {
      sessions.removePane(old.paneId)
      continue
    }
    const wasActive = useSessionStore.getState().activePaneId === old.paneId
    const pane = await ipc.paneOpen(hostId, 120, 40)
    clearTerminalScrollback(pane.paneId)
    const store = useSessionStore.getState()
    store.addPane({ ...pane, title: old.title })
    store.removePane(old.paneId)
    if (wasActive) store.setActive(pane.paneId)
  }
}

/**
 * Called for every `ssh://session-lost` event: retries with backoff, waits for the
 * network when it is down, and leaves the host flagged as lost if it cannot come back.
 */
export async function handleSessionLost(ev: SessionLostEvent): Promise<void> {
  const { hostId, reason } = ev
  const current = useConnectionStore.getState().byHost[hostId]
  // Ignore stale events: the user already disconnected, or a newer session exists.
  if (!current || current.status !== "connected") return
  if (current.sessionId && current.sessionId !== ev.sessionId) return

  cancelReconnect(hostId)
  const ctrl = new AbortController()
  reconnects.set(hostId, ctrl)
  const { signal } = ctrl
  const conn = () => useConnectionStore.getState()
  const label = hostLabel(hostId)

  conn().setReconnecting(hostId, reason, 0)
  toast.info("Connection lost", `${label}: ${reason}. Reconnecting…`)

  let lastError: unknown = null
  try {
    for (let i = 0; i < RETRY_DELAYS_MS.length; i++) {
      if (!useNetworkStore.getState().online) {
        conn().setReconnecting(hostId, "Waiting for the network…", i)
        const res = await withTimeout(
          waitForOnline(signal),
          MAX_OFFLINE_WAIT_MS
        )
        if (res === "timeout") {
          lastError = new Error("no network connection")
          break
        }
      }
      await sleep(RETRY_DELAYS_MS[i]!, signal)
      conn().setReconnecting(
        hostId,
        `Reconnecting (attempt ${i + 1} of ${RETRY_DELAYS_MS.length})…`,
        i + 1
      )
      try {
        await restoreSession(hostId, signal)
        toast.success("Reconnected", label)
        return
      } catch (err) {
        if (signal.aborted) return
        lastError = err
        if (isPermanent(err)) break
      }
    }
    const why = lastError ? errMessage(lastError) : reason
    conn().setError(hostId, `Connection lost: ${reason}`, { lost: true })
    toast.error("Could not reconnect", `${label}: ${why}`)
  } catch {
    /* aborted by the user */
  } finally {
    if (reconnects.get(hostId) === ctrl) reconnects.delete(hostId)
  }
}
