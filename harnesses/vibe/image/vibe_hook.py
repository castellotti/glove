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
  - holds a file tool's write (`write_file`, `edit`, also called from
    `run_typescript`) to the write roots a shell command has
    (/etc/glove/enforcer/write-roots.json: /work, rw mounts, /tmp): those tools
    run in the harness process, outside ring 1, and could otherwise plant what
    Vibe loads from its home later. The path is resolved (`~`, symlinks, `..`
    after them), checked, and the call rewritten to that absolute path, so the
    path written is the path checked;
  - denies egress tool names (e.g. web_fetch/web_search) since the sandbox gives
    the agent no direct web access (the browser MCP is the only path);
  - passes everything else through untouched.

`strict = true` means any failure (bad stdin, missing wrapper, non-zero exit)
becomes a denial — fail closed, never run a command unsandboxed.
"""

from __future__ import annotations

import json
import os
import re
import sys

WRAPPER_FILE = "/etc/glove/enforcer/tool-wrapper.json"
WRITE_ROOTS_FILE = "/etc/glove/enforcer/write-roots.json"
# Vibe 2.26's unified harness names a tool by its group (`file_system.bash`,
# `process.start` for a background command); older releases used bare names.
SHELL_TOOLS = frozenset({"bash", "shell", "file_system.bash", "process.start"})
# Vibe's file tools that write (`edit` reaches the hook as search_replace), and
# the argument names their path may have.
FILE_WRITE_TOOLS = frozenset({"write_file", "edit", "search_replace", "file_system.write_file",
                              "file_system.edit", "file_system.search_replace"})
PATH_KEYS = ("path", "file_path")
# A shell tool's own working dir (the wrapper grants its cwd).
CWD_KEYS = ("cwd", "workdir", "working_directory")
# Spaces a tool might normalize into plain ones: refused, so the checked path is the written one.
_ODD_SPACE = re.compile("[\u00a0\u2000-\u200b\u202f\u205f\u3000\ufeff]")
DEFAULT_BLOCK_TOOLS = frozenset({"web_fetch", "web_search"})  # by name, in any group
# Reject attempts to neuter the enforcer by overriding its env in the command.
_NONO_OVERRIDE = re.compile(r"(^|[;&|(\s])NONO_[A-Z0-9_]*=")


def _shq(s: str) -> str:
    """POSIX single-quote so the command survives as one arg to `bash -c`."""
    return "'" + s.replace("'", "'\\''") + "'"


def wrap_command(wrapper_argv: list[str], command: str) -> str:
    # NON-login shell, same as Pi's enforcer extension: a login shell sources
    # /etc/profile, which nono's default profile denies (deny_shell_configs).
    return f"{' '.join(wrapper_argv)} bash -c {_shq(command)}"


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


def load_write_roots(path: str | None = None) -> list[str] | None:
    try:
        with open(path or WRITE_ROOTS_FILE, encoding="utf-8") as f:
            roots = json.load(f).get("roots")
        if isinstance(roots, list) and roots and all(isinstance(r, str) and r.startswith("/") for r in roots):
            return roots
    except (OSError, ValueError, AttributeError):
        pass
    return None


def checked_path(path: str, roots: list[str], cwd: str) -> str | None:
    """`path` resolved as the write would go (`~`, symlinks), if it is under a
    root (`roots` already resolved); else None."""
    if _ODD_SPACE.search(path) or path != path.strip():  # a tool may strip it after the check
        return None
    real = os.path.realpath(os.path.join(cwd, os.path.expanduser(path)))
    if _ODD_SPACE.search(real):
        return None
    return real if any(os.path.commonpath([real, r]) == r for r in roots) else None


def process(payload: dict, wrapper_argv: list[str] | None, block_tools=DEFAULT_BLOCK_TOOLS,
            write_roots: list[str] | None = None) -> dict | None:
    """Return the hook response dict, or None for passthrough.

    Raises nothing for expected inputs; callers treat exceptions as fail-closed.
    """
    tool_name = payload.get("tool_name")
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else os.getcwd()
    roots = [os.path.realpath(r) for r in write_roots] if write_roots else None

    if tool_name in FILE_WRITE_TOOLS:
        tool_input = payload.get("tool_input") or {}
        given = {k: tool_input[k] for k in PATH_KEYS if k in tool_input}
        if not roots or not given or not all(isinstance(p, str) for p in given.values()):
            return {"decision": "deny", "reason": f"glove enforcer: {tool_name} needs a path and the write roots "
                    "(fail closed)"}
        checked = {k: checked_path(p, roots, cwd) for k, p in given.items()}
        bad = [given[k] for k, v in checked.items() if v is None]
        if bad:
            return {"decision": "deny", "reason": f"glove enforcer: {tool_name} may write only under "
                    f"{', '.join(write_roots)}, not {bad[0]}"}
        return {"hook_specific_output": {"tool_input": {**tool_input, **checked}}}

    if tool_name in SHELL_TOOLS:
        if not wrapper_argv:
            return {"decision": "deny", "reason": "glove enforcer: tool wrapper missing — shell blocked (fail closed)"}
        tool_input = dict(payload.get("tool_input") or {})
        command = tool_input.get("command")
        if not isinstance(command, str):
            return {"decision": "deny", "reason": f"glove enforcer: {tool_name} without a command string (fail closed)"}
        if _NONO_OVERRIDE.search(command):
            return {"decision": "deny", "reason": "glove enforcer: NONO_* env overrides are not allowed"}
        # The tool's own env reaches the shell Vibe starts the wrapper with, before
        # the sandbox (its PATH picks that shell; BASH_ENV, HOME, … run code in it).
        if tool_input.get("env"):
            return {"decision": "deny", "reason": f"glove enforcer: {tool_name} with its own env is not allowed"}
        for k in (k for k in CWD_KEYS if k in tool_input):
            if not roots:
                return {"decision": "deny", "reason": f"glove enforcer: {tool_name}'s {k} needs the write roots "
                        "(fail closed)"}
            checked = checked_path(tool_input[k], roots, cwd) if isinstance(tool_input[k], str) else None
            if checked is None:
                return {"decision": "deny", "reason": f"glove enforcer: {tool_name} may run only under "
                        f"{', '.join(write_roots)}"}
            tool_input[k] = checked
        tool_input["command"] = wrap_command(wrapper_argv, command)
        return {"hook_specific_output": {"tool_input": tool_input}}

    if isinstance(tool_name, str) and tool_name.rsplit(".", 1)[-1] in block_tools:
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
        result = process(payload, load_wrapper_argv(), write_roots=load_write_roots())
    except Exception as e:  # noqa: BLE001 - any failure must fail closed
        print(f"glove enforcer: hook error: {e}", file=sys.stderr)
        return 1

    if result is not None:
        sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
