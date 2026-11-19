import { useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { Check, Copy } from "lucide-react"

import { cn } from "@/lib/utils"
import {
  parseAnsi,
  renderCommandBytes,
  tokenizeShell,
  type ShellTokenType,
} from "@/features/mcp/lib/terminal-format"

/** Colors on the always-dark terminal surface. */
const TOKEN_CLASS: Record<ShellTokenType, string> = {
  command: "text-[#7ee787] font-semibold",
  keyword: "text-[#ff7b72] font-semibold",
  flag: "text-[#79c0ff]",
  string: "text-[#e3b341]",
  variable: "text-[#d2a8ff]",
  operator: "text-[#ff7b72]",
  comment: "text-[#8b949e] italic",
  number: "text-[#f2cc60]",
  text: "text-[#e6edf3]",
}

export function TerminalCopyButton({
  text,
  label = "Copy",
}: {
  text: string
  label?: string
}) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<number | null>(null)

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current)
      }
    }
  }, [])

  return (
    <button
      type="button"
      className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-[#8b949e] transition-colors hover:bg-white/10 hover:text-[#e6edf3]"
      onClick={() => {
        void navigator.clipboard
          .writeText(text)
          .then(() => {
            setCopied(true)
            if (timerRef.current !== null) {
              window.clearTimeout(timerRef.current)
            }
            timerRef.current = window.setTimeout(() => {
              timerRef.current = null
              setCopied(false)
            }, 1500)
          })
          .catch(() => {})
      }}
    >
      {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
      {copied ? "Copied" : label}
    </button>
  )
}

/** Dark terminal window frame with a title bar. */
export function TerminalFrame({
  title,
  actions,
  footer,
  className,
  bodyClassName,
  children,
}: {
  title?: ReactNode
  actions?: ReactNode
  footer?: ReactNode
  className?: string
  bodyClassName?: string
  children: ReactNode
}) {
  return (
    <div
      className={cn(
        "flex min-h-0 flex-col overflow-hidden rounded-lg border border-[#30363d] bg-[#0d1117] shadow-sm",
        className
      )}
    >
      <div className="flex shrink-0 items-center gap-2 border-b border-[#30363d] bg-[#161b22] px-3 py-1.5">
        <span className="flex gap-1.5" aria-hidden>
          <span className="size-2.5 rounded-full bg-[#ff5f56]/80" />
          <span className="size-2.5 rounded-full bg-[#ffbd2e]/80" />
          <span className="size-2.5 rounded-full bg-[#27c93f]/80" />
        </span>
        <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-[#8b949e]">
          {title}
        </span>
        {actions}
      </div>
      <div
        className={cn(
          "min-h-0 flex-1 overflow-auto p-3 font-mono text-xs leading-relaxed",
          bodyClassName
        )}
      >
        {children}
      </div>
      {footer && (
        <div className="flex shrink-0 items-center gap-2 border-t border-[#30363d] bg-[#161b22] px-3 py-1 font-mono text-[11px] text-[#8b949e]">
          {footer}
        </div>
      )}
    </div>
  )
}

/** A shell prompt plus the command, syntax-colored. Control characters show as escapes. */
export function TerminalCommand({
  command,
  host,
  user,
  className,
  bodyClassName,
}: {
  command: string
  host?: string | null
  user?: string | null
  className?: string
  bodyClassName?: string
}) {
  const tokens = useMemo(
    () => tokenizeShell(renderCommandBytes(command)),
    [command]
  )
  const prompt = `${user ? `${user}@` : ""}${host ?? "remote"}`
  return (
    <TerminalFrame
      title={prompt}
      className={className}
      bodyClassName={bodyClassName}
      actions={<TerminalCopyButton text={command} />}
    >
      <pre className="break-all whitespace-pre-wrap select-text">
        <span className="text-[#3fb950] select-none">{prompt}</span>
        <span className="text-[#8b949e] select-none">:~$ </span>
        {tokens.map((t, i) => (
          <span key={i} className={TOKEN_CLASS[t.type]}>
            {t.text}
          </span>
        ))}
      </pre>
    </TerminalFrame>
  )
}

/** Output text with ANSI colors applied; `tone` tints uncolored text (e.g. stderr). */
export function AnsiText({
  text,
  tone = "default",
}: {
  text: string
  tone?: "default" | "error" | "muted"
}) {
  const segments = useMemo(() => parseAnsi(text), [text])
  const base =
    tone === "error"
      ? "text-[#ffa198]"
      : tone === "muted"
        ? "text-[#8b949e]"
        : "text-[#e6edf3]"
  return (
    <pre className={cn("break-all whitespace-pre-wrap select-text", base)}>
      {segments.map((s, i) => (
        <span
          key={i}
          style={s.fg ? { color: s.fg } : undefined}
          className={cn(s.bold && "font-bold", s.dim && "opacity-70")}
        >
          {s.text}
        </span>
      ))}
    </pre>
  )
}
