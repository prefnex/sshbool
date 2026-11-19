import { useEffect, useMemo, useState } from "react"
import { invoke } from "@tauri-apps/api/core"
import {
  Activity,
  AlertTriangle,
  Clock,
  Loader2,
  Radio,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"
import {
  AnsiText,
  TerminalCommand,
  TerminalCopyButton,
  TerminalFrame,
} from "@/features/mcp/components/terminal-view"
import {
  commandFromCall,
  parseToolOutput,
} from "@/features/mcp/lib/terminal-format"
import type { McpCallLog, McpCallOutput } from "../types"

type Filter = "all" | "allowed" | "denied" | "failed"

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "allowed", label: "Allowed" },
  { id: "denied", label: "Denied" },
  { id: "failed", label: "Failed" },
]

/** Error codes that mean policy or the user refused the call (vs. it failing). */
const DENIAL_CODES = new Set([
  "APPROVAL_DENIED",
  "HARD_DENY",
  "SENSITIVE_PATH_DENIED",
  "MCP_STOPPED",
])

/**
 * Outcome of a call for colors and filters. The ledger stores every error as
 * decision "deny", so the error code is what tells a refusal from a failure.
 */
function outcome(call: McpCallLog): "ok" | "denied" | "failed" {
  if (call.errorCode) {
    return DENIAL_CODES.has(call.errorCode) ? "denied" : "failed"
  }
  if (call.decision === "hard_deny" || call.decision === "deny") return "denied"
  if (call.decision === "error" || call.decision === "timeout") return "failed"
  return "ok"
}

const OUTCOME_DOT = {
  ok: "bg-emerald-500",
  denied: "bg-destructive",
  failed: "bg-amber-500",
} as const

function DecisionBadge({ call }: { call: McpCallLog }) {
  const o = outcome(call)
  if (o === "ok") {
    return (
      <Badge
        variant="outline"
        className="gap-1 border-emerald-500/40 text-emerald-600 dark:text-emerald-400"
      >
        <ShieldCheck className="size-3" />
        Allowed
      </Badge>
    )
  }
  if (o === "denied") {
    return (
      <Badge
        variant="outline"
        className="gap-1 border-destructive/40 text-destructive"
      >
        <ShieldAlert className="size-3" />
        Denied
      </Badge>
    )
  }
  return (
    <Badge
      variant="outline"
      className="gap-1 border-amber-500/40 text-amber-600 dark:text-amber-400"
    >
      <AlertTriangle className="size-3" />
      {call.errorCode ?? call.decision}
    </Badge>
  )
}

function formatTime(at: number) {
  const d = new Date(at)
  const sameDay = d.toDateString() === new Date().toDateString()
  return sameDay
    ? d.toLocaleTimeString()
    : `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`
}

function formatDuration(ms?: number) {
  if (ms == null) return "—"
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`
}

/** The stored output of one call, rendered like a terminal session. */
function CallOutput({ call }: { call: McpCallLog }) {
  const [state, setState] = useState<{
    id: string
    data: McpCallOutput | null
    error: string | null
  } | null>(null)

  useEffect(() => {
    let cancelled = false
    invoke<McpCallOutput | null>("mcp_call_output", { callId: call.id })
      .then((data) => {
        if (!cancelled) setState({ id: call.id, data, error: null })
      })
      .catch((e: unknown) => {
        if (!cancelled) setState({ id: call.id, data: null, error: String(e) })
      })
    return () => {
      cancelled = true
    }
  }, [call.id])

  const parsed = useMemo(
    () => parseToolOutput(state?.data?.output),
    [state?.data?.output]
  )

  if (!state || state.id !== call.id) {
    return (
      <div className="flex items-center gap-2 p-4 text-xs text-muted-foreground">
        <Loader2 className="size-3.5 animate-spin" />
        Loading output…
      </div>
    )
  }
  if (state.error) {
    return (
      <p className="p-4 text-xs text-destructive">
        Couldn&apos;t load output: {state.error}
      </p>
    )
  }
  if (!state.data) {
    return (
      <p className="rounded-lg border border-dashed border-border/70 p-4 text-xs text-muted-foreground">
        No output was recorded for this call. Output is kept for calls made
        after this update.
      </p>
    )
  }

  const { errorText, truncated } = state.data
  const hasShell =
    parsed.stdout != null || parsed.stderr != null || parsed.exitCode != null
  const copyText = [parsed.stdout, parsed.stderr, parsed.other, errorText]
    .filter(Boolean)
    .join("\n")
  const exit = parsed.exitCode

  return (
    <TerminalFrame
      title="output"
      className="min-h-40"
      actions={copyText ? <TerminalCopyButton text={copyText} /> : undefined}
      footer={
        <>
          {hasShell && (
            <span
              className={cn(
                "rounded px-1.5 py-px font-semibold",
                exit === 0
                  ? "bg-[#3fb950]/15 text-[#3fb950]"
                  : "bg-[#ff7b72]/15 text-[#ff7b72]"
              )}
            >
              exit {exit ?? "?"}
            </span>
          )}
          {parsed.timedOut && <span className="text-[#e3b341]">timed out</span>}
          {(truncated || parsed.truncated) && (
            <span className="text-[#e3b341]">output truncated</span>
          )}
          <span className="ml-auto">{formatDuration(call.durationMs)}</span>
        </>
      }
    >
      {errorText && <AnsiText text={errorText} tone="error" />}
      {parsed.stdout ? <AnsiText text={parsed.stdout} /> : null}
      {parsed.stderr ? (
        <div
          className={cn(parsed.stdout && "mt-2 border-t border-[#30363d] pt-2")}
        >
          <AnsiText text={parsed.stderr} tone="error" />
        </div>
      ) : null}
      {parsed.other ? <AnsiText text={parsed.other} /> : null}
      {hasShell && !parsed.stdout && !parsed.stderr && !errorText && (
        <span className="text-[#8b949e] italic">(no output)</span>
      )}
    </TerminalFrame>
  )
}

function CallDetail({ call }: { call: McpCallLog }) {
  const command = commandFromCall(call.tool, call.commandPreview)
  return (
    <div className="flex min-h-0 flex-col gap-3 overflow-y-auto pr-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm font-semibold">{call.tool}</span>
        <DecisionBadge call={call} />
        <Badge variant="outline" className="font-mono text-[10px] uppercase">
          {call.riskTier ?? "safe"}
        </Badge>
        <span className="ml-auto flex items-center gap-1 text-xs text-muted-foreground">
          <Clock className="size-3" />
          {formatTime(call.at)}
        </span>
      </div>
      <div className="grid grid-cols-3 gap-2 text-xs">
        <div className="min-w-0 rounded-lg border border-border/70 bg-muted/30 p-2">
          <span className="block text-muted-foreground">Client</span>
          <span className="block truncate font-medium">
            {call.clientName || "System"}
          </span>
        </div>
        <div className="min-w-0 rounded-lg border border-border/70 bg-muted/30 p-2">
          <span className="block text-muted-foreground">Host</span>
          <span className="block truncate font-mono">
            {call.hostLabel ?? "—"}
          </span>
        </div>
        <div className="min-w-0 rounded-lg border border-border/70 bg-muted/30 p-2">
          <span className="block text-muted-foreground">Duration</span>
          <span className="block font-mono">
            {formatDuration(call.durationMs)}
          </span>
        </div>
      </div>
      {call.reason && (
        <div className="rounded-lg border border-border/70 bg-muted/20 p-2.5 text-xs">
          <span className="mb-0.5 block font-medium">Agent reason</span>
          <p className="break-words whitespace-pre-wrap text-muted-foreground">
            {call.reason}
          </p>
        </div>
      )}
      <TerminalCommand
        command={command}
        host={call.hostLabel}
        bodyClassName="max-h-48"
      />
      <CallOutput call={call} />
    </div>
  )
}

interface ActivityTabProps {
  calls: McpCallLog[]
}

export function ActivityTab({ calls }: ActivityTabProps) {
  const [query, setQuery] = useState("")
  const [filter, setFilter] = useState<Filter>("all")
  const [selectedId, setSelectedId] = useState<string | null>(null)
  // While following, the newest call is selected as it arrives.
  const [follow, setFollow] = useState(true)

  const toolCalls = useMemo(
    () => calls.filter((c) => !c.tool.includes("/") && c.tool !== "initialize"),
    [calls]
  )

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return toolCalls.filter((c) => {
      const o = outcome(c)
      if (filter === "allowed" && o !== "ok") return false
      if (filter === "denied" && o !== "denied") return false
      if (filter === "failed" && o !== "failed") return false
      if (!q) return true
      return [c.tool, c.hostLabel, c.clientName, c.commandPreview, c.reason]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q))
    })
  }, [toolCalls, query, filter])

  const selected =
    (follow ? visible[0] : visible.find((c) => c.id === selectedId)) ??
    visible[0] ??
    null

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="flex items-center gap-2 text-sm font-semibold">
          <Activity className="size-4 text-muted-foreground" />
          Activity
          <span className="text-xs font-normal text-muted-foreground tabular-nums">
            ({visible.length}
            {visible.length !== toolCalls.length && ` of ${toolCalls.length}`})
          </span>
        </h3>
        <div className="ml-auto flex items-center gap-1 rounded-lg border border-border/70 p-0.5">
          {FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setFilter(f.id)}
              className={cn(
                "rounded-md px-2 py-0.5 text-xs transition-colors",
                filter === f.id
                  ? "bg-muted font-medium text-foreground"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search commands, hosts…"
            className="h-7 w-52 pl-7 text-xs"
          />
        </div>
        <Button
          variant={follow ? "secondary" : "ghost"}
          size="xs"
          className="gap-1"
          title="Jump to each new call as it arrives"
          onClick={() => {
            if (follow && selected) setSelectedId(selected.id)
            setFollow(!follow)
          }}
        >
          <Radio className={cn("size-3", follow && "text-emerald-500")} />
          {follow ? "Following" : "Follow live"}
        </Button>
      </div>

      {toolCalls.length === 0 ? (
        <div className="flex flex-1 items-center justify-center rounded-xl border border-dashed border-border/70 text-xs text-muted-foreground">
          No tool calls yet. Calls and their output appear here in real time.
        </div>
      ) : (
        <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 md:grid-cols-[minmax(240px,320px)_1fr]">
          <ul className="min-h-0 space-y-1 overflow-y-auto rounded-xl border border-border/70 p-1">
            {visible.length === 0 && (
              <li className="p-3 text-center text-xs text-muted-foreground">
                Nothing matches.
              </li>
            )}
            {visible.map((call) => {
              const active = selected?.id === call.id
              return (
                <li key={call.id}>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedId(call.id)
                      setFollow(false)
                    }}
                    className={cn(
                      "w-full rounded-lg px-2 py-1.5 text-left transition-colors",
                      active ? "bg-muted" : "hover:bg-muted/50"
                    )}
                  >
                    <div className="flex items-center gap-1.5 text-xs">
                      <span
                        className={cn(
                          "size-1.5 shrink-0 rounded-full",
                          OUTCOME_DOT[outcome(call)]
                        )}
                      />
                      <span className="truncate font-mono font-medium">
                        {call.tool}
                      </span>
                      {call.hostLabel && (
                        <span className="truncate text-muted-foreground">
                          · {call.hostLabel}
                        </span>
                      )}
                      <span className="ml-auto shrink-0 text-[10px] text-muted-foreground tabular-nums">
                        {new Date(call.at).toLocaleTimeString()}
                      </span>
                    </div>
                    {call.commandPreview && (
                      <div className="mt-0.5 truncate pl-3 font-mono text-[11px] text-muted-foreground">
                        {commandFromCall(call.tool, call.commandPreview)}
                      </div>
                    )}
                  </button>
                </li>
              )
            })}
          </ul>
          {selected ? (
            <CallDetail key={selected.id} call={selected} />
          ) : (
            <div className="flex items-center justify-center text-xs text-muted-foreground">
              Pick a call to see its output.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
