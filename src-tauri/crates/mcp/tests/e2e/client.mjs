// MCP end-to-end client checks, run by src-tauri/src/mcp_e2e_tests.rs.
// Uses the official SDK the same way Claude Code / Cursor / other agents do.
//   node client.mjs <url> <token> <host_id>
import http from "node:http"

import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js"

const [url, token, hostId] = process.argv.slice(2)
let failures = 0

function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok ? "" : `  -> ${detail}`}`)
  if (!ok) failures++
}

const text = (res) => (res.content ?? []).map((c) => c.text ?? "").join("\n")

const client = new Client({ name: "sshbool-e2e", version: "1.0.0" })
const transport = new StreamableHTTPClientTransport(new URL(url), {
  requestInit: { headers: { Authorization: `Bearer ${token}` } },
})

async function call(name, args = {}) {
  return client.callTool({ name, arguments: args }, undefined, { timeout: 60_000 })
}

await client.connect(transport)
check("initialize handshake", !!client.getServerVersion()?.name, JSON.stringify(client.getServerVersion()))
check("server instructions", (client.getInstructions() ?? "").includes("list_hosts"))

const { tools } = await client.listTools()
const names = tools.map((t) => t.name)
check("tools/list has read + exec tools", names.includes("list_hosts") && names.includes("exec_command"), names.join(","))
check("no fake DB tools advertised", !names.some((n) => n.includes("db")), names.join(","))
const exec = tools.find((t) => t.name === "exec_command")
check("annotations present", exec?.annotations?.destructiveHint === true)
check("ping (protocol)", (await client.ping()) !== undefined)

let r = await call("list_hosts")
check("list_hosts returns the granted host", text(r).includes(hostId) && text(r).includes("e2e-box"), text(r))
check("structuredContent present", Array.isArray(r.structuredContent?.hosts))

r = await call("get_sysinfo", { host_id: hostId })
check("get_sysinfo runs on the server", !r.isError && /Ubuntu/.test(text(r)), text(r))

r = await call("list_dir", { host_id: hostId, path: "/srv/app" })
check("list_dir over SFTP", text(r).includes("app.conf"), text(r))

r = await call("read_file_preview", { host_id: hostId, path: "/srv/app/big.log", max_bytes: 20, from: "end" })
check("read_file_preview tail of a file", text(r).includes("5000") && r.structuredContent?.truncated === true, text(r))

r = await call("read_file_preview", { host_id: hostId, path: "/etc/shadow" })
check("sensitive file denied as tool error", r.isError === true, text(r))

r = await call("grep_files", { host_id: hostId, path: "/srv/app", query: "x'; touch /tmp/pwned_grep; echo '" })
r = await call("find_files", { host_id: hostId, path: "/srv; touch /tmp/pwned_find", pattern: "*.conf" })
r = await call("grep_files", { host_id: hostId, path: "/srv/app", query: "port=" })
check("grep_files finds literal text", text(r).includes("app.conf:2:port=8080"), text(r))

r = await call("exec_command", { host_id: hostId, command: "ls /tmp/pwned_grep /tmp/pwned_find 2>&1; true", reason: "verify injection guard" })
check("read-only tools are not injectable", !/^\/tmp\/pwned/m.test(text(r)) && /No such file/.test(text(r)), text(r))

r = await call("exec_command", { host_id: hostId, command: "echo hi; echo oops >&2; exit 3", reason: "exit code test" })
check(
  "exec_command returns stdout/stderr/exit_code",
  r.structuredContent?.stdout?.trim() === "hi" && r.structuredContent?.stderr?.trim() === "oops" && r.structuredContent?.exit_code === 3,
  JSON.stringify(r.structuredContent),
)

r = await call("exec_command", { host_id: hostId, command: "echo once >> /tmp/runs; true", reason: "single execution" })
r = await call("exec_command", { host_id: hostId, command: "wc -l < /tmp/runs", reason: "count runs" })
check("silent command runs exactly once", r.structuredContent?.stdout?.trim() === "1", text(r))

r = await call("exec_command", { host_id: hostId, command: "sleep 5", reason: "timeout", timeout_seconds: 1 })
check("exec_command timeout is reported", r.structuredContent?.timed_out === true, JSON.stringify(r.structuredContent))

r = await call("exec_command", { host_id: hostId, command: "pwd", cwd: "/srv/app", reason: "cwd" })
check("exec_command cwd", text(r).includes("/srv/app"), text(r))

r = await call("exec_script", { host_id: hostId, script_content: "x=2\necho $((x*21))", reason: "script" })
check("exec_script", text(r).includes("42"), text(r))

r = await call("edit_file_delta", { host_id: hostId, path: "/srv/app/app.conf", target_content: "port=8080", replacement_content: "port=9090" })
r = await call("read_file_preview", { host_id: hostId, path: "/srv/app/app.conf" })
check("edit_file_delta applies once and keeps the rest", text(r).includes("name=demo\nport=9090"), text(r))

r = await call("edit_file_delta", { host_id: hostId, path: "/srv/app/app.conf", target_content: "=", replacement_content: ":" })
check("ambiguous edit is refused", r.isError === true && /occurs 2 times/.test(text(r)), text(r))

r = await call("write_file", { host_id: hostId, path: "/srv/app/new.txt", content: "hello\n" })
check("write_file", !r.isError, text(r))

r = await call("run_background_task", { host_id: hostId, command: "for i in 1 2 3; do echo tick $i; sleep 0.3; done", reason: "bg" })
const taskId = r.structuredContent?.task_id
check("run_background_task returns task_id", !!taskId, text(r))
await new Promise((res) => setTimeout(res, 2000))
r = await call("read_task_logs", { host_id: hostId, task_id: taskId })
check("read_task_logs shows output and finished", text(r).includes("tick 3") && r.structuredContent?.running === false, text(r))

r = await call("reboot_host", { host_id: hostId, reason: "should be denied" })
check("denied approval comes back as a readable tool error", r.isError === true && /did not approve|denied/i.test(text(r)), text(r))

r = await call("open_session", { host_id: hostId, reason: "watch" })
const handle = r.structuredContent?.session_handle
check("open_session", !!handle, text(r))
await new Promise((res) => setTimeout(res, 1500))
r = await call("read_scrollback", { session_handle: handle, lines: 20 })
check("read_scrollback", !r.isError, text(r))
r = await call("list_sessions")
check("list_sessions", text(r).includes(handle ?? "none"), text(r))

r = await call("list_processes", { host_id: hostId, limit: 5 })
check("list_processes", /PID/.test(text(r)), text(r))

r = await call("list_containers", { host_id: hostId })
check("missing docker is reported, not faked", /not found|exit_code=127/.test(text(r)), text(r))

r = await call("no_such_tool")
check("unknown tool is a tool error", r.isError === true, text(r))

r = await call("list_dir", { host_id: "not-granted", path: "/" })
check("out-of-scope host refused", r.isError === true && /list_hosts/.test(text(r)), text(r))

await client.close()

// Raw HTTP behaviour that SDKs rely on.
function raw(method, headers = {}, body) {
  return new Promise((resolve) => {
    const u = new URL(url)
    const req = http.request({ host: u.hostname, port: u.port, path: u.pathname, method, headers }, (res) => {
      let data = ""
      res.on("data", (c) => (data += c))
      res.on("end", () => resolve({ status: res.statusCode, data, headers: res.headers }))
    })
    if (body) req.write(body)
    req.end()
  })
}
const auth = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }
let h = await raw("POST", { "Content-Type": "application/json" }, "{}")
check("no token -> 401 + WWW-Authenticate", h.status === 401 && !!h.headers["www-authenticate"], `${h.status}`)
h = await raw("POST", { ...auth, Host: "localhost.attacker.com" }, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }))
check("DNS-rebinding Host rejected", h.status === 403, `${h.status}`)
h = await raw("POST", { ...auth, Origin: "http://evil.example" }, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }))
check("foreign Origin rejected", h.status === 403, `${h.status}`)
h = await raw("POST", auth, JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }))
check("notification -> 202 no body", h.status === 202 && h.data === "", `${h.status} ${h.data}`)
h = await raw("POST", auth, "{not json")
check("parse error -> -32700", h.status === 400 && h.data.includes("-32700"), h.data)
h = await raw("GET", { Authorization: `Bearer ${token}` })
check("GET stream -> 405", h.status === 405, `${h.status}`)

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`)
process.exit(failures === 0 ? 0 : 1)
