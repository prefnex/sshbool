import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Info } from "lucide-react"

import { Switch } from "@/components/ui/switch"
import { ipc } from "@/lib/ipc/commands"
import { toast } from "@/stores/toast.store"

const QUERY_KEY = ["background-settings"]
const isLinux =
  typeof navigator !== "undefined" && /Linux/i.test(navigator.userAgent)

/** Settings → Background: tray, close behaviour and launch at login (tray.rs). */
export function BackgroundSettings() {
  const qc = useQueryClient()
  const query = useQuery({
    queryKey: QUERY_KEY,
    queryFn: () => ipc.backgroundSettingsGet(),
  })
  const update = useMutation({
    mutationFn: (patch: { closeToTray?: boolean; launchAtLogin?: boolean }) =>
      ipc.backgroundSettingsSet(patch),
    onError: (err: unknown) => {
      toast.error(
        "Could not save setting",
        err instanceof Error ? err.message : String(err)
      )
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: QUERY_KEY })
    },
  })

  const closeToTray = query.data?.closeToTray ?? true
  const launchAtLogin = query.data?.launchAtLogin ?? false

  return (
    <div className="max-w-lg space-y-6">
      <div>
        <h2 className="font-semibold">Background & Tray</h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Keep SSHBool running in the system tray so sessions, tunnels and
          transfers stay alive when the window is closed.
        </p>
      </div>

      <div className="space-y-4 border-t border-border pt-4">
        <SettingRow
          id="close-to-tray"
          title="Keep running when the window is closed"
          description="Closing the window hides SSHBool to the tray. Turn this off to quit when the window is closed."
          checked={closeToTray}
          disabled={query.isLoading || update.isPending}
          onChange={(v) => update.mutate({ closeToTray: v })}
        />
        <SettingRow
          id="launch-at-login"
          title="Launch at login"
          description="Start SSHBool hidden in the tray when you sign in to your computer."
          checked={launchAtLogin}
          disabled={query.isLoading || update.isPending}
          onChange={(v) => update.mutate({ launchAtLogin: v })}
        />
      </div>

      <div className="flex gap-2 rounded-lg border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
        <Info className="mt-0.5 size-3.5 shrink-0" />
        <div className="space-y-1">
          <p>
            Use the tray icon to show SSHBool, jump to an active session, open a
            workspace, lock the vault or quit.
          </p>
          {isLinux && (
            <p>
              On GNOME, the tray icon needs the “AppIndicator and
              KStatusNotifierItem Support” extension. Without it you can still
              reopen SSHBool by launching it again from the app menu.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

function SettingRow({
  id,
  title,
  description,
  checked,
  disabled,
  onChange,
}: {
  id: string
  title: string
  description: string
  checked: boolean
  disabled?: boolean
  onChange: (value: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border p-4">
      <div className="space-y-0.5">
        <label className="cursor-pointer text-sm font-medium" htmlFor={id}>
          {title}
        </label>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      <Switch
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={onChange}
      />
    </div>
  )
}
