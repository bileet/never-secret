// never-secret for Pi: runs every tool result through hooks/run.sh, the same redactor the
// Claude Code hook uses, by handing it a Claude-shaped PostToolUse event.
// untyped `pi`, so no dependency on @earendil-works/pi-coding-agent.
import { spawn } from "node:child_process"
import { fileURLToPath } from "node:url"

const RUN = fileURLToPath(new URL("../hooks/run.sh", import.meta.url))
// output is the model's own input (ECHO_TOOLS in hooks/claude.py)
const ECHO = new Set(["edit", "write"])
// Claude names get claude.py's per-tool handling: the read file's own values, `cat .env` commands
const CLAUDE: Record<string, string> = {
  read: "Read",
  bash: "Bash",
  powershell: "Bash",
}

function redact(event: object, cwd: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const p = spawn("sh", [RUN], { cwd })
    let out = "",
      err = ""
    p.stdout.on("data", (d) => (out += d))
    p.stderr.on("data", (d) => (err += d))
    p.on("error", reject)
    p.on("close", (code) => {
      if (code !== 0)
        return reject(new Error(err.trim() || `run.sh exited ${code}`))
      try {
        resolve(
          out
            ? JSON.parse(out).hookSpecificOutput.updatedToolOutput
            : undefined,
        ) // empty: nothing to redact
      } catch (e) {
        reject(e)
      }
    })
    p.stdin.end(JSON.stringify(event))
  })
}

export default function (pi: any) {
  pi.on("tool_result", async (event: any, ctx: any) => {
    if (ECHO.has(event.toolName)) return
    const input = event.input ?? {}
    // content is what the model reads; structuredContent is what code-mode scripts read
    const response = {
      content: event.content,
      structuredContent: event.structuredContent,
    }
    try {
      const clean = await redact(
        {
          hook_event_name: "PostToolUse",
          cwd: ctx.cwd,
          tool_name: CLAUDE[event.toolName] ?? event.toolName,
          tool_input: { ...input, file_path: input.path },
          tool_response: response,
        },
        ctx.cwd,
      )
      if (clean === undefined) return
      return {
        content: clean.content,
        structuredContent: clean.structuredContent,
      }
    } catch (e) {
      // fail closed: unlike the Claude hook, a broken redactor withholds the output instead of passing it
      return {
        content: [
          {
            type: "text",
            text: `never-secret: redaction failed, output withheld (${(e as Error).message})`,
          },
        ],
      }
    }
  })
}
