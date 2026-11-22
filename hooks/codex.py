#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# ///
"""never-secret hook for Codex.

Uses the shared redaction engine in core/redact.py (imported below); only the wire contract is its own.
Codex's PostToolUse can't rewrite a tool result in place (updatedToolOutput /
updatedMCPToolOutput are parsed but not supported), so:

- When redaction changed anything, the hook returns decision "block" with the
  redacted text as the reason: Codex replaces the tool result with that text
  and the model continues from it. Nothing changed: exit 0, no output.
- Codex has no Read tool; file contents arrive through shell commands, which
  report as Bash (command_files applies a named known file's redactor).
  Every other result shape goes through the same deep walk as every other tool.
"""

import json
import sys

import redact
import values

# Output = the model's own input or a fixed confirmation. Codex file edits are
# apply_patch, whose result is a confirmation, not file content; update_plan
# echoes the plan. Everything else is walked, whatever its name.
ECHO_TOOLS = {"update_plan"}

PREFIX = (
    "never-secret: this tool result contained secret values and was redacted "
    "(Codex can't edit tool results in place, so the redacted output replaces it):\n\n"
)


def redact_response(event):
    """Redacted text for a Codex PostToolUse event, or None to leave it alone."""
    tool, inp, resp = (
        event.get("tool_name"),
        event.get("tool_input") or {},
        event.get("tool_response"),
    )

    if tool in ECHO_TOOLS:
        return None
    vals = values.secret_values(event.get("cwd"))
    fns = ()

    if tool in ("Bash", "exec_command"):
        fns, more = redact.command_files(inp.get("command", ""), event.get("cwd"))
        vals |= more  # `xxd app.py`, `rev .env`

    if isinstance(resp, str):
        return redact.redact_text(resp, fns, vals)  # format rules even on one line
    clean = redact.deep_redact(resp, fns, vals)

    if clean == resp:
        return None

    # the reason is plain text, so a structured result goes back as readable JSON
    return (
        clean
        if isinstance(clean, str)
        else json.dumps(clean, indent=2, ensure_ascii=False)
    )


def hook():
    event = json.load(sys.stdin)

    if event.get("hook_event_name") != "PostToolUse":
        return
    clean = redact_response(event)

    if clean is None or clean == event.get("tool_response"):
        return
    json.dump({"decision": "block", "reason": PREFIX + clean}, sys.stdout)


if __name__ == "__main__":
    hook()
