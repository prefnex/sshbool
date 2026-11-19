/** Helpers that turn MCP commands and tool output into terminal-looking, colored text. */

export type ShellTokenType =
  | "command"
  | "keyword"
  | "flag"
  | "string"
  | "variable"
  | "operator"
  | "comment"
  | "number"
  | "text"

export interface ShellToken {
  type: ShellTokenType
  text: string
}

/** Words that wrap another command, so the word after them is still a command. */
const WRAPPERS = new Set([
  "sudo",
  "doas",
  "env",
  "nohup",
  "time",
  "timeout",
  "xargs",
  "exec",
  "nice",
  "watch",
  "then",
  "do",
  "else",
  "if",
  "while",
  "until",
])

/** Wrapper options that take a value (`sudo -u postgres`, `watch -n 2`). */
const WRAPPER_ARG_FLAGS = new Set([
  "-u",
  "-g",
  "-n",
  "-s",
  "-k",
  "-C",
  "-D",
  "--user",
  "--group",
])

/** Operators longest-first so `2>&1` wins over `2>` and `>`. */
const OPERATORS = [
  "2>&1",
  "&>>",
  "2>>",
  "&&",
  "||",
  ">>",
  "<<",
  "&>",
  "2>",
  "$(",
  "|",
  ";",
  ">",
  "<",
  "&",
  "(",
  ")",
  "{",
  "}",
]

/** Operators after which the next word starts a new command. */
const COMMAND_STARTERS = new Set(["&&", "||", "|", ";", "&", "(", "$(", "{"])

/**
 * Splits a shell command into colored tokens. A light heuristic, not a full shell
 * parser: it only has to make long one-liners readable.
 */
export function tokenizeShell(input: string): ShellToken[] {
  const tokens: ShellToken[] = []
  let i = 0
  let expectCommand = true
  // Set after a wrapper option such as `-u`, whose value is not the command.
  let wrapperArg = false
  const push = (type: ShellTokenType, text: string) => {
    const last = tokens[tokens.length - 1]
    if (last && last.type === type && type === "text") last.text += text
    else tokens.push({ type, text })
  }

  while (i < input.length) {
    const ch = input[i]

    if (ch === "\n") {
      push("text", ch)
      expectCommand = true
      i += 1
      continue
    }
    if (ch === " " || ch === "\t" || ch === "\r") {
      push("text", ch)
      i += 1
      continue
    }
    const prev = i === 0 ? "\n" : input[i - 1]
    if (ch === "#" && /\s/.test(prev)) {
      const end = input.indexOf("\n", i)
      const stop = end === -1 ? input.length : end
      push("comment", input.slice(i, stop))
      i = stop
      continue
    }
    if (ch === "'" || ch === '"') {
      let j = i + 1
      while (j < input.length && input[j] !== ch) {
        if (ch === '"' && input[j] === "\\") j += 1
        j += 1
      }
      push("string", input.slice(i, Math.min(j + 1, input.length)))
      i = j + 1
      expectCommand = false
      continue
    }
    const op = OPERATORS.find((o) => input.startsWith(o, i))
    if (op) {
      push("operator", op)
      i += op.length
      if (COMMAND_STARTERS.has(op)) expectCommand = true
      continue
    }
    if (ch === "$") {
      const m = /^\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9#?@*!$-])/.exec(
        input.slice(i)
      )
      if (m) {
        push("variable", m[0])
        i += m[0].length
        expectCommand = false
        continue
      }
    }

    // A bare word runs until whitespace, a quote or an operator.
    let j = i
    while (j < input.length) {
      const c = input[j]
      if (/\s/.test(c) || c === "'" || c === '"') break
      if (c === "\\") {
        j += 2
        continue
      }
      if (c === "$" && j > i) break
      if (OPERATORS.some((o) => o !== "$(" && input.startsWith(o, j))) break
      j += 1
    }
    if (j === i) j = i + 1
    const word = input.slice(i, j)
    i = j

    if (expectCommand) {
      if (wrapperArg) {
        push("text", word)
        wrapperArg = false
      } else if (word.startsWith("-")) {
        // An option of the wrapper before it (`sudo -E cmd`).
        push("flag", word)
        wrapperArg = WRAPPER_ARG_FLAGS.has(word)
      } else if (/^\d+(\.\d+)?[smhd]?$/.test(word)) {
        // A duration/count for a wrapper (`timeout 10 cmd`).
        push("number", word)
      } else if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) {
        push("variable", word)
      } else if (WRAPPERS.has(word)) {
        push("keyword", word)
      } else {
        push("command", word)
        expectCommand = false
      }
    } else if (/^--?[A-Za-z0-9]/.test(word)) {
      push("flag", word)
    } else if (/^-?\d+(\.\d+)?$/.test(word)) {
      push("number", word)
    } else {
      push("text", word)
    }
  }
  return tokens
}

/** Shows tabs and control characters as visible escapes, keeping real line breaks. */
export function renderCommandBytes(text: string): string {
  let out = ""
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i)
    if (code === 9) out += "\\t"
    else if (code === 10) out += "\n"
    else if (code === 13) out += "\\r"
    else if (code < 32 || code === 127)
      out += `\\x${code.toString(16).padStart(2, "0")}`
    else out += text[i]
  }
  return out
}

// ── ANSI colors ───────────────────────────────────────────────────────

export interface AnsiSegment {
  text: string
  fg?: string
  bold?: boolean
  dim?: boolean
}

/** Terminal palette (GitHub-dark-ish) for the 16 standard colors. */
const ANSI_16 = [
  "#484f58",
  "#ff7b72",
  "#3fb950",
  "#d29922",
  "#58a6ff",
  "#bc8cff",
  "#39c5cf",
  "#b1bac4",
  "#6e7681",
  "#ffa198",
  "#56d364",
  "#e3b341",
  "#79c0ff",
  "#d2a8ff",
  "#56d4dd",
  "#f0f6fc",
]

function ansi256(n: number): string | undefined {
  if (n < 16) return ANSI_16[n]
  if (n < 232) {
    const v = n - 16
    const steps = [0, 95, 135, 175, 215, 255]
    const r = steps[Math.floor(v / 36) % 6]
    const g = steps[Math.floor(v / 6) % 6]
    const b = steps[v % 6]
    return `rgb(${r}, ${g}, ${b})`
  }
  const gray = 8 + (n - 232) * 10
  return `rgb(${gray}, ${gray}, ${gray})`
}

/** Splits text on ANSI SGR color codes; other escape sequences are dropped. */
export function parseAnsi(input: string): AnsiSegment[] {
  const segments: AnsiSegment[] = []
  let fg: string | undefined
  let bold = false
  let dim = false
  // eslint-disable-next-line no-control-regex
  const re = /\x1b\[([0-9;]*)([A-Za-z])|\x1b\][^\x07]*\x07|\x1b[()][A-Za-z0-9]/g
  let last = 0
  let m: RegExpExecArray | null
  const emit = (text: string) => {
    if (!text) return
    const prev = segments[segments.length - 1]
    if (prev && prev.fg === fg && prev.bold === bold && prev.dim === dim) {
      prev.text += text
    } else {
      segments.push({ text, fg, bold, dim })
    }
  }
  while ((m = re.exec(input))) {
    emit(input.slice(last, m.index))
    last = re.lastIndex
    if (m[2] !== "m") continue
    const codes = (m[1] || "0").split(";").map((c) => Number(c || 0))
    for (let k = 0; k < codes.length; k += 1) {
      const c = codes[k]
      if (c === 0) {
        fg = undefined
        bold = false
        dim = false
      } else if (c === 1) bold = true
      else if (c === 2) dim = true
      else if (c === 22) {
        bold = false
        dim = false
      } else if (c >= 30 && c <= 37) fg = ANSI_16[c - 30]
      else if (c >= 90 && c <= 97) fg = ANSI_16[c - 90 + 8]
      else if (c === 39) fg = undefined
      else if (c === 38 && codes[k + 1] === 5) {
        fg = ansi256(codes[k + 2] ?? 7)
        k += 2
      } else if (c === 38 && codes[k + 1] === 2) {
        fg = `rgb(${codes[k + 2] ?? 0}, ${codes[k + 3] ?? 0}, ${codes[k + 4] ?? 0})`
        k += 4
      } else if (c === 48 && (codes[k + 1] === 5 || codes[k + 1] === 2)) {
        // Backgrounds are ignored; skip their arguments.
        k += codes[k + 1] === 5 ? 2 : 4
      }
    }
  }
  emit(input.slice(last))
  return segments
}

// ── MCP call payloads ─────────────────────────────────────────────────

/** Args that only route the call; they add noise to a command line. */
const ROUTING_ARGS = new Set(["host_id", "session_handle", "reason"])

function quoteArg(value: string): string {
  return /^[\w@%+=:,./-]+$/.test(value)
    ? value
    : `'${value.replace(/'/g, `'\\''`)}'`
}

/**
 * Turns a logged call into something that reads like a command line: the real command
 * for exec tools, otherwise `tool --arg value ...`. `preview` is the stored (redacted,
 * possibly cut) JSON of the call arguments.
 */
export function commandFromCall(tool: string, preview?: string | null): string {
  if (!preview) return tool
  let args: Record<string, unknown> | null = null
  try {
    const parsed: unknown = JSON.parse(preview)
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      args = parsed as Record<string, unknown>
    }
  } catch {
    // Cut at the preview limit: recover the command field if it is there.
    const m = /"(command|script)":"((?:[^"\\]|\\.)*)/.exec(preview)
    if (m) {
      try {
        return JSON.parse(`"${m[2]}"`) as string
      } catch {
        return m[2]
      }
    }
    return `${tool} ${preview}`
  }
  if (!args) return tool
  for (const key of ["command", "script"]) {
    const v = args[key]
    if (typeof v === "string" && v.trim()) return v
  }
  const parts = [tool]
  for (const [key, value] of Object.entries(args)) {
    if (ROUTING_ARGS.has(key) || value == null) continue
    const text = typeof value === "string" ? value : JSON.stringify(value)
    parts.push(`--${key.replace(/_/g, "-")}`, quoteArg(text))
  }
  return parts.join(" ")
}

export interface ParsedToolOutput {
  /** Shell-style result (exec tools and most read tools). */
  stdout?: string
  stderr?: string
  exitCode?: number | null
  timedOut?: boolean
  truncated?: boolean
  /** Anything else, pretty-printed. */
  other?: string
}

/** Understands the `{stdout, stderr, exit_code, ...}` shape tools return; pretty-prints the rest. */
export function parseToolOutput(
  raw: string | null | undefined
): ParsedToolOutput {
  if (!raw) return {}
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    return { other: raw }
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>
    if ("stdout" in obj || "stderr" in obj || "exit_code" in obj) {
      const exit = obj.exit_code ?? obj.exitCode
      return {
        stdout: typeof obj.stdout === "string" ? obj.stdout : undefined,
        stderr: typeof obj.stderr === "string" ? obj.stderr : undefined,
        exitCode: typeof exit === "number" ? exit : null,
        timedOut: obj.timed_out === true,
        truncated: obj.truncated === true,
      }
    }
  }
  return { other: JSON.stringify(value, null, 2) }
}

/** Approval previews hold the raw command for exec tools and the args JSON otherwise. */
export function commandFromApproval(tool: string, text: string): string {
  return text.trimStart().startsWith("{") ? commandFromCall(tool, text) : text
}
