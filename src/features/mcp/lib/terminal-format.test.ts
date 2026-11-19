import { describe, expect, it } from "vitest"
import {
  commandFromApproval,
  commandFromCall,
  parseAnsi,
  parseToolOutput,
  tokenizeShell,
} from "./terminal-format"

const typesOf = (cmd: string) =>
  tokenizeShell(cmd)
    .filter((t) => t.text.trim())
    .map((t) => `${t.type}:${t.text.trim()}`)

describe("tokenizeShell", () => {
  it("colors commands, flags, strings and operators", () => {
    expect(typesOf(`cd ~/app && ls -la | grep "version" 2>&1`)).toEqual([
      "command:cd",
      "text:~/app",
      "operator:&&",
      "command:ls",
      "flag:-la",
      "operator:|",
      "command:grep",
      'string:"version"',
      "operator:2>&1",
    ])
  })

  it("treats sudo as a wrapper and $VARS as variables", () => {
    expect(typesOf("sudo -u postgres psql $DB")).toEqual([
      "keyword:sudo",
      "flag:-u",
      "text:postgres",
      "command:psql",
      "variable:$DB",
    ])
    expect(typesOf("timeout 10 curl -s x")).toEqual([
      "keyword:timeout",
      "number:10",
      "command:curl",
      "flag:-s",
      "text:x",
    ])
    expect(typesOf("FOO=1 echo $HOME")).toEqual([
      "variable:FOO=1",
      "command:echo",
      "variable:$HOME",
    ])
  })

  it("keeps every character", () => {
    const cmd = `a 'b c' "d\\"e" # note`
    expect(
      tokenizeShell(cmd)
        .map((t) => t.text)
        .join("")
    ).toBe(cmd)
  })
})

describe("parseAnsi", () => {
  it("maps SGR colors and resets", () => {
    const segs = parseAnsi("\x1b[32mok\x1b[0m plain \x1b[1;31mbad\x1b[39m")
    expect(segs.map((s) => s.text)).toEqual(["ok", " plain ", "bad"])
    expect(segs[0].fg).toBeDefined()
    expect(segs[1].fg).toBeUndefined()
    expect(segs[2].bold).toBe(true)
  })
})

describe("commandFromCall", () => {
  it("returns the real command for exec tools", () => {
    expect(
      commandFromCall(
        "exec_command",
        JSON.stringify({ command: "ls -la", host_id: "h", reason: "x" })
      )
    ).toBe("ls -la")
  })

  it("recovers the command from a cut preview", () => {
    expect(
      commandFromCall("exec_command", '{"command":"echo \\"hi\\" && ls')
    ).toBe('echo "hi" && ls')
  })

  it("renders other tools as a CLI line without routing args", () => {
    expect(
      commandFromCall(
        "read_journal",
        JSON.stringify({ host_id: "h", unit: "nginx.service", lines: 40 })
      )
    ).toBe("read_journal --unit nginx.service --lines 40")
  })

  it("keeps raw approval commands as-is", () => {
    expect(commandFromApproval("exec_command", "ls {a,b}")).toBe("ls {a,b}")
  })
})

describe("parseToolOutput", () => {
  it("reads the exec result shape", () => {
    const out = parseToolOutput(
      JSON.stringify({
        stdout: "hi\n",
        stderr: "",
        exit_code: 0,
        timed_out: false,
      })
    )
    expect(out.stdout).toBe("hi\n")
    expect(out.exitCode).toBe(0)
  })

  it("pretty-prints anything else", () => {
    expect(parseToolOutput('{"a":1}').other).toBe('{\n  "a": 1\n}')
    expect(parseToolOutput("not json").other).toBe("not json")
  })
})
