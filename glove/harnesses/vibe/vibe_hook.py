#!/usr/bin/env python3
"""glove Vibe pre_tool hook — routes shell through the ring-1 sandbox.

Baked at /opt/glove/vibe-hook and declared in ~/.vibe/hooks.toml as a `pre_tool`
hook with `strict = true`. Vibe passes each tool call as JSON on stdin
(`tool_name`, `tool_input`, session context); this hook:

  - rewrites the `bash` tool's `command` to run under the enforcer's per-command
    wrapper (read from /etc/glove/enforcer/tool-wrapper.json), returning a full
    `hook_specific_output.tool_input` replacement — so a prompt-injected command
    can only touch /work + rw mounts + /tmp, has no network, and cannot read the
    harness home or the LLM key;
  - denies egress tool names (e.g. web_fetch/web_search) since the sandbox gives
    the agent no direct web access (the browser MCP is the only path);
  - passes everything else through untouched.

`strict = true` means any failure (bad stdin, missing wrapper, non-zero exit)
becomes a denial — fail closed, never run a command unsandboxed.
"""

from __future__ import annotations

import json
import re
import sys

WRAPPER_FILE = "/etc/glove/enforcer/tool-wrapper.json"
SHELL_TOOLS = frozenset({"bash", "shell"})
DEFAULT_BLOCK_TOOLS = frozenset({"web_fetch", "web_search"})
# Reject attempts to neuter the enforcer by overriding its env in the command.
_NONO_OVERRIDE = re.compile(r"(^|[;&|(\s])NONO_[A-Z0-9_]*=")


def _shq(s: str) -> str:
    """POSIX single-quote so the command survives as one arg to `bash -lc`."""
    return "'" + s.replace("'", "'\\''") + "'"


def wrap_command(wrapper_argv: list[str], command: str) -> str:
    return f"{' '.join(wrapper_argv)} bash -lc {_shq(command)}"


def load_wrapper_argv(path: str | None = None) -> list[str] | None:
    path = path or WRAPPER_FILE  # resolved at call time so it stays patchable
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        argv = data.get("argv")
        if isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv):
            return argv
    except (OSError, ValueError):
        pass
    return None


def process(payload: dict, wrapper_argv: list[str] | None, block_tools=DEFAULT_BLOCK_TOOLS) -> dict | None:
    """Return the hook response dict, or None for passthrough.

    Raises nothing for expected inputs; callers treat exceptions as fail-closed.
    """
    tool_name = payload.get("tool_name")

    if tool_name in SHELL_TOOLS:
        if not wrapper_argv:
            return {"decision": "deny", "reason": "glove enforcer: tool wrapper missing — shell blocked (fail closed)"}
        tool_input = dict(payload.get("tool_input") or {})
        command = tool_input.get("command")
        if not isinstance(command, str):
            return None  # nothing to wrap
        if _NONO_OVERRIDE.search(command):
            return {"decision": "deny", "reason": "glove enforcer: NONO_* env overrides are not allowed"}
        tool_input["command"] = wrap_command(wrapper_argv, command)
        return {"hook_specific_output": {"tool_input": tool_input}}

    if tool_name in block_tools:
        return {
            "decision": "deny",
            "reason": f"glove enforcer: '{tool_name}' is disabled in this sandbox "
            "(no direct web egress; use the browser tool).",
        }

    return None  # passthrough


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be a JSON object")
    except (ValueError, OSError) as e:
        # Fail closed: strict=true turns this non-zero exit into a denial.
        print(f"glove enforcer: unreadable hook input: {e}", file=sys.stderr)
        return 1

    try:
        result = process(payload, load_wrapper_argv())
    except Exception as e:  # noqa: BLE001 - any failure must fail closed
        print(f"glove enforcer: hook error: {e}", file=sys.stderr)
        return 1

    if result is not None:
        sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
