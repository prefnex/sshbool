import { useEffect, useRef, useState } from "react"
import { ShieldAlert, Clock, ChevronLeft, ChevronRight } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import { useNow } from "@/hooks/use-now"
import { TerminalCommand } from "@/features/mcp/components/terminal-view"
import { commandFromApproval } from "@/features/mcp/lib/terminal-format"
import {
  selectCurrentApproval,
  useMcpApprovalStore,
  type ApprovalDecision,
  type McpApprovalRequest,
} from "@/stores/mcp.store"

function RiskBadge({ tier }: { tier: McpApprovalRequest["riskTier"] }) {
  if (tier === "dangerous") {
    return (
      <Badge
        variant="outline"
        className="border-destructive/50 text-destructive"
      >
        DANGEROUS
      </Badge>
    )
  }
  if (tier === "write") {
    return (
      <Badge
        variant="outline"
        className="border-amber-500/50 text-amber-600 dark:text-amber-400"
      >
        WRITE
      </Badge>
    )
  }
  return (
    <Badge
      variant="outline"
      className="border-emerald-500/50 text-emerald-600 dark:text-emerald-400"
    >
      SAFE
    </Badge>
  )
}

export function McpApprovalDialog() {
  const init = useMcpApprovalStore((s) => s.init)
  const current = useMcpApprovalStore(selectCurrentApproval)
  const queue = useMcpApprovalStore((s) => s.queue)
  const open = useMcpApprovalStore((s) => s.open)
  const respondingId = useMcpApprovalStore((s) => s.respondingId)
  const respond = useMcpApprovalStore((s) => s.respond)
  const show = useMcpApprovalStore((s) => s.show)
  const hide = useMcpApprovalStore((s) => s.hide)
  const pruneExpired = useMcpApprovalStore((s) => s.pruneExpired)
  const denyRef = useRef<HTMLButtonElement>(null)
  // Keep rendering the last request while the dialog animates closed, instead of
  // unmounting mid-animation (that snap is what made it look jittery).
  const lastShownRef = useRef<McpApprovalRequest | null>(null)
  const confirmTimerRef = useRef<number | null>(null)
  const [confirmProduction, setConfirmProduction] = useState(false)
  const now = useNow(queue.length > 0)

  useEffect(() => {
    void init()
  }, [init])

  useEffect(() => {
    pruneExpired(now)
  }, [now, pruneExpired])

  const currentId = current?.approvalId ?? null
  useEffect(() => {
    if (confirmTimerRef.current !== null) {
      window.clearTimeout(confirmTimerRef.current)
      confirmTimerRef.current = null
    }
    setConfirmProduction(false)
    return () => {
      if (confirmTimerRef.current !== null) {
        window.clearTimeout(confirmTimerRef.current)
        confirmTimerRef.current = null
      }
    }
  }, [currentId])

  if (current) lastShownRef.current = current
  const shown = current ?? lastShownRef.current
  if (!shown) return null

  const isOpen = open && current != null
  const index = Math.max(
    0,
    queue.findIndex((item) => item.approvalId === shown.approvalId)
  )
  const timeLeftSecs = Math.max(0, Math.floor((shown.expiresAt - now) / 1000))
  const responding = respondingId === shown.approvalId

  const handleRespond = (decision: ApprovalDecision) => {
    void respond(shown.approvalId, decision)
  }

  const handleAllowOnce = () => {
    if (
      shown.production &&
      shown.riskTier === "dangerous" &&
      !confirmProduction
    ) {
      setConfirmProduction(true)
      if (confirmTimerRef.current !== null) {
        window.clearTimeout(confirmTimerRef.current)
      }
      confirmTimerRef.current = window.setTimeout(() => {
        confirmTimerRef.current = null
        setConfirmProduction(false)
      }, 3000)
      return
    }
    handleRespond("allow_once")
  }

  const goTo = (offset: number) => {
    const next = queue[(index + offset + queue.length) % queue.length]
    if (next) show(next.approvalId)
  }

  const headerIcon =
    shown.riskTier === "dangerous" ? (
      <ShieldAlert className="h-4 w-4 text-destructive" />
    ) : (
      <ShieldAlert className="h-4 w-4 text-amber-600 dark:text-amber-400" />
    )

  return (
    // Closing (X / Escape / "Later") never decides anything: the request stays queued in
    // the title bar until it is answered or times out. Outside clicks are ignored so a
    // stray click (e.g. on a toast) can't hide it.
    <Dialog
      open={isOpen}
      disablePointerDismissal
      onOpenChange={(next) => {
        if (!next) hide()
      }}
    >
      <DialogContent
        showCloseButton
        initialFocus={denyRef}
        className={cn(
          // Flex column with a scrolling body: long commands must never push the
          // action buttons off screen.
          "flex max-h-[calc(100dvh-2rem)] flex-col gap-3 overflow-hidden sm:max-w-2xl",
          shown.production &&
            shown.riskTier === "dangerous" &&
            "border-destructive/50"
        )}
      >
        <DialogHeader className="shrink-0">
          <div className="flex items-start justify-between gap-3 pr-8">
            <div className="min-w-0 space-y-1">
              <DialogTitle className="flex items-center gap-2 text-sm font-semibold">
                {headerIcon}
                Approve remote action
                {queue.length > 1 && (
                  <span className="flex items-center gap-0.5 text-xs font-normal text-muted-foreground">
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label="Previous pending request"
                      onClick={() => goTo(-1)}
                    >
                      <ChevronLeft className="size-3.5" />
                    </Button>
                    <span className="tabular-nums">
                      {index + 1} of {queue.length}
                    </span>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label="Next pending request"
                      onClick={() => goTo(1)}
                    >
                      <ChevronRight className="size-3.5" />
                    </Button>
                  </span>
                )}
              </DialogTitle>
              <DialogDescription className="text-xs">
                Requested by{" "}
                <span className="font-medium text-foreground">
                  {shown.clientName}
                </span>
              </DialogDescription>
            </div>
            <RiskBadge tier={shown.riskTier} />
          </div>
        </DialogHeader>

        <div className="-mx-1 min-h-0 flex-1 space-y-3 overflow-y-auto px-1">
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div className="min-w-0 rounded-xl border border-border/70 bg-muted/30 p-2 break-words">
              <span className="mb-0.5 block text-muted-foreground">Client</span>
              <span className="font-medium">{shown.clientName}</span>
            </div>
            <div className="min-w-0 rounded-xl border border-border/70 bg-muted/30 p-2 break-words">
              <span className="mb-0.5 block text-muted-foreground">Host</span>
              <span className="font-mono text-xs">
                {shown.hostLabel ?? "—"}
              </span>
              {shown.production && (
                <Badge
                  variant="outline"
                  className="mt-1 border-destructive/50 text-[10px] text-destructive"
                >
                  PRODUCTION
                </Badge>
              )}
            </div>
            <div className="min-w-0 rounded-xl border border-border/70 bg-muted/30 p-2 break-words">
              <span className="mb-0.5 block text-muted-foreground">Tool</span>
              <span className="font-mono text-xs select-all">{shown.tool}</span>
            </div>
          </div>

          {shown.agentReason && (
            <div className="rounded-xl border border-border/70 bg-muted/20 p-3 text-xs">
              <span className="mb-1 block font-medium">Agent reason</span>
              <p className="break-words whitespace-pre-wrap text-muted-foreground">
                {shown.agentReason}
              </p>
            </div>
          )}

          {shown.commandText && (
            <div className="space-y-1.5">
              <span className="text-xs font-medium text-muted-foreground">
                Command (exact bytes)
              </span>
              <TerminalCommand
                command={commandFromApproval(shown.tool, shown.commandText)}
                host={shown.hostLabel}
                bodyClassName="max-h-64"
              />
              <p className="text-[11px] text-muted-foreground">
                Tabs and other non-printable characters are shown as escapes.
              </p>
            </div>
          )}

          {shown.riskReasons.length > 0 && (
            <div className="space-y-1 rounded-xl border border-border/70 bg-muted/20 p-3 text-xs">
              <span className="block font-medium">
                Risk classifier triggers
              </span>
              <ul className="list-inside list-disc space-y-0.5 text-muted-foreground">
                {shown.riskReasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
              <p className="pt-1 text-[11px] text-muted-foreground">
                Risk analysis is advisory. Approve only if you understand the
                command.
              </p>
            </div>
          )}

          <div className="rounded-xl border border-border/70 bg-muted/20 p-3 text-xs">
            <span className="mb-1 block font-medium">Dry-run preview</span>
            {shown.previewOutput ? (
              <pre className="max-h-48 overflow-y-auto font-mono text-xs break-all whitespace-pre-wrap select-all">
                {shown.previewOutput}
              </pre>
            ) : (
              <span className="text-muted-foreground">Preview unavailable</span>
            )}
          </div>
        </div>

        <div className="flex shrink-0 items-center justify-between border-t border-border/70 pt-2 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5" />
            Denied automatically in{" "}
            <span className="inline-block min-w-[3ch] text-right tabular-nums">
              {timeLeftSecs}s
            </span>
            — denial is the default outcome.
          </span>
        </div>

        <DialogFooter className="shrink-0 gap-2 sm:flex-wrap sm:justify-end">
          <Button
            variant="ghost"
            size="sm"
            className="h-8 sm:mr-auto"
            title="Hide this dialog. The request stays pending in the title bar."
            onClick={hide}
          >
            Later
          </Button>
          <Button
            ref={denyRef}
            variant="destructive"
            size="sm"
            className="h-8"
            disabled={responding}
            onClick={() => handleRespond("deny")}
          >
            Deny
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-8"
            disabled={responding}
            onClick={handleAllowOnce}
            title={
              shown.production && shown.riskTier === "dangerous"
                ? "First click arms confirmation; click again within 3 seconds to allow."
                : undefined
            }
          >
            {confirmProduction ? "Confirm on production" : "Allow once"}
          </Button>
          {shown.grantable && (
            <Button
              variant="secondary"
              size="sm"
              className="h-8"
              disabled={responding}
              onClick={() => handleRespond("allow_session")}
            >
              Allow for this session (15 min)
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
