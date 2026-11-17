import { Wifi, WifiOff } from "lucide-react"

import { cn } from "@/lib/utils"
import { useConnectionStore } from "@/stores/connection.store"
import { useNetworkStore } from "@/stores/network.store"

/** Title-bar pill: internet reachability plus hosts being restored. */
export function NetworkIndicator() {
  const online = useNetworkStore((s) => s.online)
  const reconnecting = useConnectionStore(
    (s) =>
      Object.values(s.byHost).filter((c) => c.status === "reconnecting").length
  )

  if (online && reconnecting === 0) {
    return (
      <span
        className="flex size-6 items-center justify-center text-muted-foreground/70"
        title="Online — internet connection is working"
        role="status"
        aria-label="Online"
      >
        <Wifi className="size-3.5" />
      </span>
    )
  }

  const label = !online
    ? "Offline"
    : `Reconnecting ${reconnecting} ${reconnecting === 1 ? "server" : "servers"}`

  return (
    <span
      role="status"
      aria-live="polite"
      title={
        !online
          ? "No internet connection. Sessions will reconnect automatically when it is back."
          : "A connection dropped and SSHBool is restoring it."
      }
      className={cn(
        "mr-1 flex h-6 items-center gap-1.5 rounded-full px-2 text-[11px] font-medium",
        !online
          ? "bg-destructive/15 text-destructive"
          : "bg-amber-500/15 text-amber-600 dark:text-amber-400"
      )}
    >
      {!online ? (
        <WifiOff className="size-3.5" />
      ) : (
        <span className="size-1.5 animate-pulse rounded-full bg-current" />
      )}
      {label}
    </span>
  )
}
