import { useState } from "react"
import { ShieldAlert } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { useNow } from "@/hooks/use-now"
import { cn } from "@/lib/utils"
import { useMcpApprovalStore } from "@/stores/mcp.store"

/**
 * Title-bar entry for MCP approvals waiting on the user. Stays visible while anything is
 * pending, so a dialog closed by mistake can always be reopened (or the request denied).
 */
export function PendingApprovalsButton() {
  const queue = useMcpApprovalStore((s) => s.queue)
  const dialogOpen = useMcpApprovalStore((s) => s.open)
  const respondingId = useMcpApprovalStore((s) => s.respondingId)
  const show = useMcpApprovalStore((s) => s.show)
  const respond = useMcpApprovalStore((s) => s.respond)
  const [open, setOpen] = useState(false)
  const now = useNow(open && queue.length > 0)

  if (queue.length === 0) return null

  const hasDangerous = queue.some((item) => item.riskTier === "dangerous")

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        render={
          <Button
            variant="ghost"
            size="xs"
            aria-label={`${queue.length} pending approval${queue.length === 1 ? "" : "s"}`}
            title="Pending approvals"
            className={cn(
              "mr-1 gap-1 rounded-md px-1.5 text-xs font-medium",
              hasDangerous
                ? "bg-destructive/10 text-destructive hover:bg-destructive/15"
                : "bg-amber-500/10 text-amber-600 hover:bg-amber-500/15 dark:text-amber-400",
              !dialogOpen && "animate-pulse"
            )}
          />
        }
      >
        <ShieldAlert className="size-3.5" />
        <span className="tabular-nums">{queue.length}</span>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 gap-1.5 p-1.5">
        <div className="px-1.5 pt-1 pb-0.5 text-xs font-medium text-muted-foreground">
          Waiting for your approval
        </div>
        <ul className="max-h-80 space-y-1 overflow-y-auto">
          {queue.map((item, i) => {
            const secs = Math.max(0, Math.floor((item.expiresAt - now) / 1000))
            return (
              <li
                key={item.approvalId}
                className="flex items-center gap-2 rounded-md border border-border/60 p-2 text-xs"
              >
                <button
                  type="button"
                  className="min-w-0 flex-1 text-left"
                  onClick={() => {
                    setOpen(false)
                    show(item.approvalId)
                  }}
                >
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted-foreground tabular-nums">
                      {i + 1}.
                    </span>
                    <span className="truncate font-medium">
                      {item.tool}
                      {item.hostLabel ? ` · ${item.hostLabel}` : ""}
                    </span>
                    <span
                      className={cn(
                        "ml-auto shrink-0 tabular-nums",
                        item.riskTier === "dangerous"
                          ? "text-destructive"
                          : "text-muted-foreground"
                      )}
                    >
                      {secs}s
                    </span>
                  </div>
                  {item.commandText && (
                    <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
                      {item.commandText}
                    </div>
                  )}
                  <div className="mt-0.5 text-[11px] text-muted-foreground">
                    {item.clientName}
                  </div>
                </button>
                <Button
                  variant="ghost"
                  size="xs"
                  className="shrink-0 text-destructive hover:bg-destructive/10 hover:text-destructive"
                  disabled={respondingId === item.approvalId}
                  onClick={() => void respond(item.approvalId, "deny")}
                >
                  Deny
                </Button>
              </li>
            )
          })}
        </ul>
      </PopoverContent>
    </Popover>
  )
}
