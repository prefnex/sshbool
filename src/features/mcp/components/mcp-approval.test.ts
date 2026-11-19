import { beforeEach, describe, expect, it } from "vitest"
import {
  isTerminalApprovalError,
  normalizeApproval,
  selectCurrentApproval,
  useMcpApprovalStore,
  type McpApprovalRequest,
} from "@/stores/mcp.store"

function isGrantButtonVisible(req: McpApprovalRequest): boolean {
  return req.grantable && req.riskTier !== "dangerous"
}

describe("normalizeApproval", () => {
  it("maps snake_case live event payloads", () => {
    const req = normalizeApproval({
      id: "appr-1",
      client_id: "client-1",
      client_name: "Cursor",
      host_id: "host-1",
      host_label: "staging-web-1",
      production: true,
      tool: "exec_command",
      command_preview: "systemctl status nginx",
      agent_reason: "check nginx",
      risk_tier: "dangerous",
      risk_reasons: ["Dangerous tier tool requires human approval"],
      preview_output: null,
      grantable: false,
      expires_at: 1_700_000_000_000,
    })

    expect(req.approvalId).toBe("appr-1")
    expect(req.clientName).toBe("Cursor")
    expect(req.hostLabel).toBe("staging-web-1")
    expect(req.commandText).toBe("systemctl status nginx")
    expect(req.agentReason).toBe("check nginx")
    expect(req.riskTier).toBe("dangerous")
    expect(req.production).toBe(true)
  })
})

describe("MCP approval affordances", () => {
  it("hides session grant for dangerous tier", () => {
    const req: McpApprovalRequest = {
      approvalId: "a1",
      clientId: "c1",
      clientName: "Cursor",
      hostId: "h1",
      hostLabel: "Dev",
      production: false,
      tool: "exec_command",
      riskTier: "dangerous",
      riskReasons: [],
      commandText: "ls",
      agentReason: "diagnostics",
      previewOutput: null,
      grantable: false,
      requestedAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    }
    expect(isGrantButtonVisible(req)).toBe(false)
  })

  it("hides session grant on production hosts even for write tier", () => {
    const req: McpApprovalRequest = {
      approvalId: "a2",
      clientId: "c1",
      clientName: "Cursor",
      hostId: "h1",
      hostLabel: "Prod",
      production: true,
      tool: "write_file",
      riskTier: "write",
      riskReasons: [],
      commandText: null,
      agentReason: null,
      previewOutput: null,
      grantable: false,
      requestedAt: Date.now(),
      expiresAt: Date.now() + 60_000,
    }
    expect(isGrantButtonVisible(req)).toBe(false)
  })
})

function makeReq(id: string, expiresIn = 60_000): McpApprovalRequest {
  return {
    approvalId: id,
    clientId: "c1",
    clientName: "Cursor",
    hostId: "h1",
    hostLabel: "Dev",
    production: false,
    tool: "exec_command",
    riskTier: "dangerous",
    riskReasons: [],
    commandText: "ls",
    agentReason: null,
    previewOutput: null,
    grantable: false,
    requestedAt: Date.now(),
    expiresAt: Date.now() + expiresIn,
  }
}

describe("isTerminalApprovalError", () => {
  it("treats AppError objects for gone requests as terminal", () => {
    expect(
      isTerminalApprovalError({
        kind: "Conflict",
        message: "approval already resolved",
      })
    ).toBe(true)
    expect(
      isTerminalApprovalError({ kind: "NotFound", entity: "approval" })
    ).toBe(true)
    expect(
      isTerminalApprovalError("no pending approval gate — timed out")
    ).toBe(true)
  })

  it("keeps the request for unrelated failures", () => {
    expect(
      isTerminalApprovalError({ kind: "Db", engine: "sqlite", message: "busy" })
    ).toBe(false)
  })
})

describe("approval queue", () => {
  beforeEach(() => {
    useMcpApprovalStore.setState({
      queue: [],
      activeId: null,
      open: false,
      respondingId: null,
    })
  })

  it("opens for the first request and keeps the current one when more arrive", () => {
    const s = useMcpApprovalStore.getState()
    s.enqueue(makeReq("a"))
    s.hide()
    s.enqueue(makeReq("b"))
    const st = useMcpApprovalStore.getState()
    expect(st.queue.map((r) => r.approvalId)).toEqual(["a", "b"])
    // Closed by the user: a second request must not force it open again.
    expect(st.open).toBe(false)
    st.show("b")
    expect(
      selectCurrentApproval(useMcpApprovalStore.getState())?.approvalId
    ).toBe("b")
  })

  it("drops resolved and expired requests and closes when empty", () => {
    const s = useMcpApprovalStore.getState()
    s.enqueue(makeReq("a"))
    s.enqueue(makeReq("b", 1_000))
    s.pruneExpired(Date.now() + 5_000)
    expect(
      useMcpApprovalStore.getState().queue.map((r) => r.approvalId)
    ).toEqual(["a"])
    s.remove("a")
    expect(useMcpApprovalStore.getState().open).toBe(false)
    expect(selectCurrentApproval(useMcpApprovalStore.getState())).toBeNull()
  })

  it("ignores requests that already expired", () => {
    useMcpApprovalStore.getState().enqueue(makeReq("old", -1))
    expect(useMcpApprovalStore.getState().queue).toHaveLength(0)
  })
})
