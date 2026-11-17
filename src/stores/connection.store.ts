import { create } from "zustand"

export type HostConnStatus =
  | "idle"
  | "connecting"
  | "connected"
  /** The session dropped on its own and SSHBool is trying to restore it. */
  | "reconnecting"
  | "error"

export type HostConnection = {
  status: HostConnStatus
  sessionId?: string
  error?: string
  /** True when the error is a dropped connection (vs. a failed connect). */
  lost?: boolean
  /** While reconnecting: why the session dropped / what we are waiting for. */
  detail?: string
  attempt?: number
}

type ConnectionState = {
  byHost: Record<string, HostConnection>
  get: (hostId: string) => HostConnection
  setConnecting: (hostId: string) => void
  setConnected: (hostId: string, sessionId: string) => void
  setError: (hostId: string, error: string, opts?: { lost?: boolean }) => void
  setReconnecting: (hostId: string, detail: string, attempt?: number) => void
  setIdle: (hostId: string) => void
  clearError: (hostId: string) => void
  isConnected: (hostId: string) => boolean
  isConnecting: (hostId: string) => boolean
}

const idle: HostConnection = { status: "idle" }

export const useConnectionStore = create<ConnectionState>((set, get) => ({
  byHost: {},
  get: (hostId) => get().byHost[hostId] ?? idle,
  setConnecting: (hostId) =>
    set((s) => ({
      byHost: {
        ...s.byHost,
        [hostId]: {
          status: "connecting",
          sessionId: s.byHost[hostId]?.sessionId,
        },
      },
    })),
  setConnected: (hostId, sessionId) =>
    set((s) => ({
      byHost: {
        ...s.byHost,
        [hostId]: { status: "connected", sessionId },
      },
    })),
  setError: (hostId, error, opts) =>
    set((s) => ({
      byHost: {
        ...s.byHost,
        [hostId]: { status: "error", error, lost: opts?.lost },
      },
    })),
  setReconnecting: (hostId, detail, attempt) =>
    set((s) => ({
      byHost: {
        ...s.byHost,
        [hostId]: { status: "reconnecting", detail, attempt },
      },
    })),
  setIdle: (hostId) =>
    set((s) => {
      const next = { ...s.byHost }
      delete next[hostId]
      return { byHost: next }
    }),
  clearError: (hostId) =>
    set((s) => {
      const cur = s.byHost[hostId]
      if (!cur || cur.status !== "error") return s
      const next = { ...s.byHost }
      delete next[hostId]
      return { byHost: next }
    }),
  isConnected: (hostId) => get().byHost[hostId]?.status === "connected",
  isConnecting: (hostId) => get().byHost[hostId]?.status === "connecting",
}))
