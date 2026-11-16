import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("@/lib/ipc/commands", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc/commands")>()
  return {
    ...actual,
    ipc: {
      sessionOpen: vi.fn(),
      sessionClose: vi.fn().mockResolvedValue(undefined),
      paneOpen: vi.fn(),
    },
  }
})
vi.mock("@/features/terminal/terminal-scrollback", () => ({
  clearTerminalScrollback: vi.fn(),
}))

import { cancelReconnect, handleSessionLost } from "./connect-host"
import { IpcError, ipc } from "@/lib/ipc/commands"
import { useConnectionStore } from "@/stores/connection.store"
import { useNetworkStore } from "@/stores/network.store"
import { useSessionStore } from "@/stores/session.store"

const HOST = "host-1"
const lostEvent = {
  hostId: HOST,
  sessionId: "s-old",
  paneIds: ["p-old"],
  reason: "server stopped responding",
}

describe("handleSessionLost", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.mocked(ipc.sessionOpen).mockReset()
    vi.mocked(ipc.paneOpen).mockReset()
    useNetworkStore.setState({ online: true })
    useConnectionStore.setState({
      byHost: { [HOST]: { status: "connected", sessionId: "s-old" } },
    })
    useSessionStore.setState({
      panes: [
        { paneId: "p-old", sessionId: "s-old", hostId: HOST, title: "prod" },
      ],
      activePaneId: "p-old",
    })
  })

  afterEach(() => {
    cancelReconnect(HOST)
    vi.useRealTimers()
  })

  it("restores the session and replaces dead terminal tabs", async () => {
    vi.mocked(ipc.sessionOpen).mockResolvedValue({ sessionId: "s-new" })
    vi.mocked(ipc.paneOpen).mockResolvedValue({
      paneId: "p-new",
      sessionId: "s-new",
      hostId: HOST,
      title: "prod",
    })

    const done = handleSessionLost(lostEvent)
    expect(useConnectionStore.getState().byHost[HOST]?.status).toBe(
      "reconnecting"
    )
    await vi.runAllTimersAsync()
    await done

    expect(useConnectionStore.getState().byHost[HOST]).toMatchObject({
      status: "connected",
      sessionId: "s-new",
    })
    const panes = useSessionStore.getState().panes
    expect(panes.map((p) => p.paneId)).toEqual(["p-new"])
    expect(useSessionStore.getState().activePaneId).toBe("p-new")
  })

  it("stops retrying on errors that need the user and flags the host as lost", async () => {
    vi.mocked(ipc.sessionOpen).mockRejectedValue(
      new IpcError({ kind: "Unauthorized", reason: "bad_password" })
    )

    const done = handleSessionLost(lostEvent)
    await vi.runAllTimersAsync()
    await done

    expect(ipc.sessionOpen).toHaveBeenCalledTimes(1)
    expect(useConnectionStore.getState().byHost[HOST]).toMatchObject({
      status: "error",
      lost: true,
    })
  })

  it("waits for the network before retrying", async () => {
    useNetworkStore.setState({ online: false })
    vi.mocked(ipc.sessionOpen).mockResolvedValue({ sessionId: "s-new" })
    vi.mocked(ipc.paneOpen).mockResolvedValue({
      paneId: "p-new",
      sessionId: "s-new",
      hostId: HOST,
      title: "prod",
    })

    const done = handleSessionLost(lostEvent)
    await vi.advanceTimersByTimeAsync(60_000)
    expect(ipc.sessionOpen).not.toHaveBeenCalled()
    expect(useConnectionStore.getState().byHost[HOST]?.detail).toMatch(
      /network/i
    )

    useNetworkStore.getState().setOnline(true)
    await vi.runAllTimersAsync()
    await done
    expect(useConnectionStore.getState().byHost[HOST]?.status).toBe("connected")
  })

  it("ignores events for sessions the user already closed", async () => {
    useConnectionStore.setState({ byHost: {} })
    await handleSessionLost(lostEvent)
    expect(ipc.sessionOpen).not.toHaveBeenCalled()
    expect(useConnectionStore.getState().byHost[HOST]).toBeUndefined()
  })
})
