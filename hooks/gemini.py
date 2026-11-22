#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# ///
"""never-secret hook for Gemini CLI.

Uses the shared redaction engine in core/redact.py (imported below); only the wire contract is its own.
Gemini's AfterTool hook can't edit a result in place, but decision "deny" with a
reason replaces the result the model sees with that reason:

- When redaction changed anything, the hook returns decision "deny" with the
  redacted llmContent as the reason. Nothing changed: exit 0, no output.
- Only llmContent (what the model reads) is redacted; returnDisplay is the
  user's terminal view and is left alone.
- Fails closed: any error exits 2, which makes Gemini hide the result and send
  stderr in its place. (run.sh does the same when no Python is found.)
"""

import json
import os
import sys

import formats
import redact
import values

# Output = the model's own input, the user's answers or a fixed confirmation.
ECHO_TOOLS = {
    "write_file",
    "replace",
    "write_todos",
    "ask_user",
    "enter_plan_mode",
    "exit_plan_mode",
    "update_topic",
}

PREFIX = (
    "never-secret: this tool result contained secret values and was redacted "
    "(Gemini can't edit tool results in place, so the redacted output replaces it):\n\n"
)


def redact_response(event):
    """Redacted llmContent text for a Gemini AfterTool event, or None to leave it alone."""
    tool, inp, resp = (
        event.get("tool_name"),
        event.get("tool_input") or {},
        event.get("tool_response") or {},
    )

    if tool in ECHO_TOOLS:
        return None
    content = resp.get("llmContent") if isinstance(resp, dict) else resp
    cwd = event.get("cwd")
    vals = values.secret_values(cwd)
    fns = ()

    if tool == "run_shell_command":
        fns, more = redact.command_files(inp.get("command", ""), cwd)
        vals |= more  # `xxd app.py`, `rev .env`
    elif tool == "read_file" and inp.get("file_path"):
        path = os.path.join(
            cwd or "", inp["file_path"]
        )  # join keeps an absolute file_path as is
        fn = formats.known_redactor(path)
        fns = (fn,) if fn else ()
        vals |= values.with_encodings(values.known_values(path))

    if isinstance(content, str):
        clean = redact.redact_text(content, fns, vals)  # format rules even on one line
    else:
        clean = redact.deep_redact(
            content, fns, vals
        )  # Part / Part[]: inlineData passes through

    if clean == content:
        return None

    # the reason is plain text, so a structured result goes back as readable JSON
    return (
        clean
        if isinstance(clean, str)
        else json.dumps(clean, indent=2, ensure_ascii=False)
    )


def hook():
    event = json.load(sys.stdin)

    if event.get("hook_event_name") != "AfterTool":
        return
    clean = redact_response(event)

    if clean is not None:
        json.dump({"decision": "deny", "reason": PREFIX + clean}, sys.stdout)


def safe_hook():
    try:
        hook()
    except Exception as e:  # noqa: BLE001 fail closed: exit 2 hides the result, stderr replaces it
        print(f"never-secret: redaction failed, output withheld ({e})", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    safe_hook()
