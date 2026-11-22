// never-secret for OpenCode 2.x: runs every tool result through hooks/run.sh, the same
// redactor the Claude Code hook uses, by handing it a Claude-shaped PostToolUse event.
// plain object instead of Plugin.define (an identity function), so no dependency.
import { existsSync, readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"

const RUN = join(import.meta.dir, "..", "hooks", "run.sh")
const SKILLS = join(import.meta.dir, "..", "skills")

// skills/<id>/SKILL.md as OpenCode 2.x Skill.Info (same shape superpowers registers)
function skills() {
  return readdirSync(SKILLS, { withFileTypes: true })
    .filter(
      (d) => d.isDirectory() && existsSync(join(SKILLS, d.name, "SKILL.md")),
    )
    .map((d) => {
      const dir = join(SKILLS, d.name)
      const path = join(dir, "SKILL.md")
      const [, head = "", body = ""] =
        readFileSync(path, "utf8").match(
          /^---\n([\s\S]*?)\n---\n?([\s\S]*)$/,
        ) ?? []
      const field = (k: string) =>
        head.match(new RegExp(`^${k}:\\s*(.*)$`, "m"))?.[1].trim()
      // OpenCode may not tell the model where the skill lives, so spell out the folder
      const content = body.replaceAll("<this skill's folder>", dir)
      return {
        id: d.name,
        name: field("name") ?? d.name,
        description: field("description"),
        path,
        content,
      }
    })
}
// output is the model's own input or a fixed confirmation (ECHO_TOOLS in hooks/claude.py)
const ECHO = new Set(["edit", "write", "patch", "todowrite", "question"])
// Claude names get claude.py's per-tool handling: the read file's own values, `cat .env` commands
const CLAUDE: Record<string, string> = { read: "Read", shell: "Bash" }

async function redact(event: object, cwd: string) {
  const p = Bun.spawn(["sh", RUN], {
    cwd,
    stdin: new Blob([JSON.stringify(event)]),
    stdout: "pipe",
    stderr: "pipe",
  })
  const [out, err, code] = await Promise.all([
    new Response(p.stdout).text(),
    new Response(p.stderr).text(),
    p.exited,
  ])
  if (code !== 0) throw new Error(err.trim() || `run.sh exited ${code}`)
  return out ? JSON.parse(out).hookSpecificOutput.updatedToolOutput : undefined // empty: nothing to redact
}

export default {
  id: "never-secret",
  async setup(ctx: any) {
    const cwd = ctx.location.directory
    if (typeof ctx.skill?.transform === "function") {
      await ctx.skill.transform((draft: any) => {
        for (const s of skills()) draft.add(s)
      })
    }
    await ctx.tool.hook("execute.after", async (event: any) => {
      if (ECHO.has(event.tool)) return
      const input = event.input ?? {}
      const base = {
        hook_event_name: "PostToolUse",
        cwd,
        tool_name: CLAUDE[event.tool] ?? event.tool,
        tool_input: { ...input, file_path: input.path },
      }
      const done = event.status === "completed"
      try {
        // whole result: model-visible content, structured output (Code Mode scripts read it) and metadata
        const clean = await redact(
          { ...base, tool_response: done ? event.result : event.error.message },
          cwd,
        )
        if (clean === undefined) return
        if (done) event.result = clean
        else event.error.message = clean // an interrupted shell's failure message holds its output
      } catch (e) {
        // fail closed: unlike the Claude hook, a broken redactor withholds the output instead of passing it
        const msg = `never-secret: redaction failed, output withheld (${(e as Error).message})`
        if (done) event.result = { content: msg }
        else event.error.message = msg
      }
    })
  },
}
