import { create } from "zustand"
import { invoke } from "@tauri-apps/api/core"
import { listen } from "@tauri-apps/api/event"
import { formatAppError } from "@/lib/ipc/commands"
import type { AppError } from "@/lib/ipc/types"
import { toast } from "@/stores/toast.store"

export type ApprovalDecision = "allow_once" | "allow_session" | "deny"

export interface McpApprovalRequest {
  approvalId: string
  clientId: string
  clientName: string
  hostId: string | null
  hostLabel: string | null
  production: boolean
  tool: string
  riskTier: "safe" | "write" | "dangerous"
  riskReasons: string[]
  commandText: string | null
  agentReason: string | null
  previewOutput: string | null
  grantable: boolean
  requestedAt: number
  expiresAt: number
}

interface McpApprovalStore {
  /** Pending requests, oldest first. */
  queue: McpApprovalRequest[]
  /** Request shown in the dialog; null falls back to the oldest one. */
  activeId: string | null
  /** Whether the dialog is showing. Closing it keeps the request queued. */
  open: boolean
  /** Request whose decision is being sent right now. */
  respondingId: string | null
  initialized: boolean
  init: () => Promise<void>
  enqueue: (req: McpApprovalRequest) => void
  /** Sends a decision. Resolves to false (and toasts) when it could not be sent. */
  respond: (approvalId: string, decision: ApprovalDecision) => Promise<boolean>
  remove: (approvalId: string) => void
  pruneExpired: (now?: number) => void
  /** Opens the dialog, optionally on a specific request. */
  show: (approvalId?: string) => void
  /** Closes the dialog without deciding; the request stays in the queue. */
  hide: () => void
}

/** Pulls a readable message out of whatever `invoke` rejected with (AppError object, string, Error). */
function readIpcError(e: unknown): { message: string; kind: string | null } {
  if (e && typeof e === "object" && "kind" in e) {
    return {
      message: formatAppError(e as AppError),
      kind: String((e as { kind: unknown }).kind),
    }
  }
  if (typeof e === "string") return { message: e, kind: null }
  if (e instanceof Error) return { message: e.message, kind: null }
  if (e && typeof e === "object" && "message" in e) {
    return { message: String((e as { message: unknown }).message), kind: null }
  }
  return { message: String(e), kind: null }
}

/**
 * True when the request is gone on the backend (expired, already decided, or its caller
 * left), so it must leave the queue instead of leaving the dialog stuck.
 */
export function isTerminalApprovalError(e: unknown): boolean {
  const { message, kind } = readIpcError(e)
  if (kind === "NotFound" || kind === "Conflict") return true
  return /already resolved|timed out|no pending approval gate|not found/i.test(
    message
  )
}

function readRiskTier(
  payload: Record<string, unknown>
): McpApprovalRequest["riskTier"] {
  const raw = payload.riskTier ?? payload.risk_tier
  if (raw === "safe" || raw === "write" || raw === "dangerous") return raw
  return "write"
}

/** Normalizes approval payloads from live events (camelCase) and legacy snake_case. */
export function normalizeApproval(
  payload: Record<string, unknown>
): McpApprovalRequest {
  const hostIdRaw = payload.hostId ?? payload.host_id
  const hostLabelRaw = payload.hostLabel ?? payload.host_label
  const commandRaw =
    payload.commandText ?? payload.commandPreview ?? payload.command_preview
  const previewRaw = payload.previewOutput ?? payload.preview_output
  const agentReasonRaw = payload.agentReason ?? payload.agent_reason
  const riskReasonsRaw = payload.riskReasons ?? payload.risk_reasons
  const requestedAtRaw = payload.requestedAt ?? payload.requested_at
  const expiresAtRaw = payload.expiresAt ?? payload.expires_at

  return {
    approvalId: String(payload.approvalId ?? payload.id ?? ""),
    clientId: String(payload.clientId ?? payload.client_id ?? ""),
    clientName: String(
      payload.clientName ?? payload.client_name ?? "Unknown client"
    ),
    hostId: hostIdRaw != null && hostIdRaw !== "" ? String(hostIdRaw) : null,
    hostLabel:
      hostLabelRaw != null && hostLabelRaw !== "" ? String(hostLabelRaw) : null,
    production: Boolean(payload.production),
    tool: String(payload.tool ?? ""),
    riskTier: readRiskTier(payload),
    riskReasons: Array.isArray(riskReasonsRaw)
      ? riskReasonsRaw.map(String)
      : [],
    commandText:
      commandRaw != null && commandRaw !== "" ? String(commandRaw) : null,
    agentReason:
      agentReasonRaw != null && agentReasonRaw !== ""
        ? String(agentReasonRaw)
        : null,
    previewOutput:
      previewRaw != null && previewRaw !== "" ? String(previewRaw) : null,
    grantable: Boolean(payload.grantable),
    requestedAt: Number(requestedAtRaw ?? Date.now()),
    expiresAt: Number(expiresAtRaw ?? Date.now() + 60_000),
  }
}

let listenersReady = false

export const useMcpApprovalStore = create<McpApprovalStore>((set, get) => ({
  queue: [],
  activeId: null,
  open: false,
  respondingId: null,
  initialized: false,

  init: async () => {
    if (get().initialized) return
    set({ initialized: true })

    // Listen first so nothing that arrives while the pending list loads is missed.
    if (!listenersReady) {
      listenersReady = true
      try {
        await listen<Record<string, unknown>>(
          "mcp://approval-request",
          (event) => get().enqueue(normalizeApproval(event.payload))
        )
        await listen<{ approvalId?: string }>(
          "mcp://approval-resolved",
          (event) => {
            if (event.payload?.approvalId)
              get().remove(event.payload.approvalId)
          }
        )
      } catch (e) {
        listenersReady = false
        console.error("Failed to attach MCP approval listeners", e)
      }
    }

    try {
      const pending = await invoke<McpApprovalRequest[]>(
        "mcp_approvals_pending"
      )
      for (const row of pending) {
        get().enqueue(
          normalizeApproval(row as unknown as Record<string, unknown>)
        )
      }
    } catch (e) {
      console.error("Failed to load pending MCP approvals", e)
    }
  },

  enqueue: (req) => {
    if (!req.approvalId || req.expiresAt <= Date.now()) return
    set((state) => {
      if (state.queue.some((item) => item.approvalId === req.approvalId)) {
        return state
      }
      // Pop the dialog for the first request; later ones wait in the queue so the
      // request the user is reading never changes under them.
      return {
        queue: [...state.queue, req],
        open: state.queue.length === 0 ? true : state.open,
      }
    })
  },

  respond: async (approvalId, decision) => {
    if (get().respondingId) return false
    set({ respondingId: approvalId })
    try {
      await invoke("mcp_approval_respond", { approvalId, decision })
      get().remove(approvalId)
      return true
    } catch (e) {
      console.error("Failed to send approval response", e)
      if (isTerminalApprovalError(e)) {
        get().remove(approvalId)
        toast.info(
          "Request no longer pending",
          "It timed out or the agent cancelled it, so it was dropped from the queue."
        )
      } else {
        toast.error("Approval failed", readIpcError(e).message)
      }
      return false
    } finally {
      set({ respondingId: null })
    }
  },

  remove: (approvalId) => {
    set((state) => {
      if (!state.queue.some((item) => item.approvalId === approvalId)) {
        return state
      }
      const queue = state.queue.filter((item) => item.approvalId !== approvalId)
      return {
        queue,
        activeId: state.activeId === approvalId ? null : state.activeId,
        open: queue.length > 0 && state.open,
      }
    })
  },

  pruneExpired: (now = Date.now()) => {
    for (const item of get().queue) {
      // Keep the one being answered until its response settles.
      if (item.expiresAt <= now && item.approvalId !== get().respondingId) {
        get().remove(item.approvalId)
      }
    }
  },

  show: (approvalId) => {
    set((state) => {
      if (state.queue.length === 0) return state
      const exists =
        approvalId != null &&
        state.queue.some((item) => item.approvalId === approvalId)
      return { open: true, activeId: exists ? approvalId : state.activeId }
    })
  },

  hide: () => set({ open: false }),
}))

export function selectCurrentApproval(
  state: McpApprovalStore
): McpApprovalRequest | null {
  return (
    state.queue.find((item) => item.approvalId === state.activeId) ??
    state.queue[0] ??
    null
  )
}
