"""Claude Code adapter: glove's guard rails as managed settings, plus the home.

Claude Code is the one harness whose guard rails live outside its writable
config home. `system_files` renders `/etc/claude-code/managed-settings.json`
(and `managed-mcp.json`), which glove writes under `.glove/harness/` and binds
read-only; managed settings win over every other scope, and an unparseable one
stops Claude Code from starting. They carry:

- `CLAUDE_CODE_SHELL_PREFIX` → /opt/glove/bin/glove-cc-prefix, so the Bash
  tool, `!` commands and hooks all run under the ring-1 tool wrapper (a prefix
  in the process env would yield to the agent's own settings). A stdio MCP
  server is rendered as `glove-cc-prefix --mcp <name>`, which the prefix runs
  from `mcp-<name>.argv` beside the settings under the harness's own sandbox,
  as Pi and Vibe run theirs: the tool profile has no network to reach a sidecar;
- managed-only hooks, permission rules and MCP servers, and deny rules on the
  config home (`//` is an absolute path; Edit rules cover every write tool);
- the switches that keep Claude Code to its inference host.

`render_home` writes the user-scope `settings.json` (cosmetic, model) and merges
the onboarding/trust state into `.claude.json`, which Claude Code also writes.
Contributed skills are linked from /opt/glove/cc/.claude/skills (baked, loaded
with `--add-dir`), not the config home, whose deny rules would hide their files.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from glove.config import ConfigError
from glove.enforcers.base import argv_lines
from glove.harnessconfig import _mount_plan_for, mcp_tool_names, rel_config_home

MANAGED_DIR = "/etc/claude-code"
SHELL_PREFIX = "/opt/glove/bin/glove-cc-prefix"
SKILLS_ROOT = "/opt/glove/cc"  # `--add-dir`: Claude Code loads <dir>/.claude/skills
DEFAULT_HOST = "api.anthropic.com"
# The built-in tools glove approves: every command runs under the tool wrapper
# and every file write stays inside the mounts, as with Pi and Vibe.
ALLOW_TOOLS = ["Bash", "Read", "Edit", "Write", "MultiEdit", "NotebookEdit", "Glob", "Grep", "LS", "Agent",
               "Task", "TodoWrite", "WebSearch"]
# WebFetch fetches from inside the container, which reaches only the session's
# forwarders: refused rather than left to fail.
DENY_TOOLS = ["WebFetch"]
MODES = ("default", "acceptEdits", "plan", "dontAsk")
CONFIG_KEYS = frozenset({"settings", "permissions"})
PERMISSION_KEYS = frozenset({"defaultMode", "allow", "deny"})
MANAGED_ENV = {
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_AUTOUPDATER": "1",
    # the wrapped command runs in a child shell, so a `cd` would not persist
    "CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR": "1",
}


def secret_env(model) -> str:
    """The env var Claude Code reads the key from."""
    return "CLAUDE_CODE_OAUTH_TOKEN" if model.api_key_kind == "oauth" else "ANTHROPIC_API_KEY"


def _config(cfg) -> dict[str, Any]:
    hc = cfg.harness_config or {}
    unknown = set(hc) - CONFIG_KEYS
    perms = hc.get("permissions") or {}
    if unknown or not isinstance(perms, dict) or set(perms) - PERMISSION_KEYS:
        raise ConfigError(f"claude-code harness_config takes {sorted(CONFIG_KEYS)} "
                          f"(permissions: {sorted(PERMISSION_KEYS)})")
    if not isinstance(hc.get("settings") or {}, dict):
        raise ConfigError("claude-code harness_config.settings must be a mapping")
    for key in ("allow", "deny"):
        rules = perms.get(key) or []
        if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
            raise ConfigError(f"claude-code permissions.{key} must be a list of rule strings")
    if perms.get("defaultMode", "default") not in MODES:
        raise ConfigError(f"claude-code permissions.defaultMode must be one of {list(MODES)}")
    return hc


def _mcp(comp, wrapped: bool = False) -> tuple[dict[str, Any], list[str], dict[str, str]]:
    """managed-mcp.json servers from the neutral `mcp` contribution, the
    permission rules their `tools` allowlists imply (other tools prompt), and,
    when `wrapped` (a shell prefix is set), each stdio server's argv file."""
    servers: dict[str, Any] = {}
    allow: list[str] = []
    argv_files: dict[str, str] = {}
    for _ext, item in comp.mcp if comp is not None else []:
        item = dict(item)
        name, transport, tools = item.pop("name"), item.pop("transport", "stdio"), item.pop("tools", None)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ConfigError(f"MCP server name {name!r}: letters, digits, '_' and '-' only")
        if transport == "http":
            servers[name] = {"type": "http", "url": item["url"]}
        else:
            argv = [str(item["command"]), *(str(a) for a in item.get("args") or [])]
            if wrapped:
                if any("\n" in a for a in argv):
                    raise ConfigError(f"MCP server {name!r}: an argument with a newline")
                argv_files[f"mcp-{name}.argv"] = argv_lines(argv)
                argv = [SHELL_PREFIX, "--mcp", name]
            servers[name] = {"type": "stdio", "command": argv[0], "args": argv[1:],
                             **({"env": dict(item["env"])} if item.get("env") else {})}
        if tools is None:
            allow.append(f"mcp__{name}")
        else:
            allow += [f"mcp__{name}__{t}" for t in mcp_tool_names(tools)]
    return servers, allow, argv_files


def managed_settings(cfg, plan, servers: dict[str, Any], mcp_allow: list[str], wrapped: bool) -> dict[str, Any]:
    perms = _config(cfg).get("permissions") or {}
    home = plan.profile.config_home_path
    env = dict(MANAGED_ENV)
    if wrapped:
        env["CLAUDE_CODE_SHELL_PREFIX"] = SHELL_PREFIX
    model = plan.model
    if model is not None and urlsplit(model.base_url).hostname != DEFAULT_HOST:
        # only off the default host: CC treats a base URL as a gateway
        env["ANTHROPIC_BASE_URL"] = model.base_url
    return {
        "allowManagedHooksOnly": True,
        "allowManagedPermissionRulesOnly": True,
        "allowManagedMcpServersOnly": True,
        "allowedMcpServers": [{"serverName": n} for n in servers],
        "permissions": {
            "defaultMode": perms.get("defaultMode", "default"),
            "allow": [*ALLOW_TOOLS, *mcp_allow, *(perms.get("allow") or [])],
            "deny": [f"Read(/{home}/**)", f"Edit(/{home}/**)", *DENY_TOOLS, *(perms.get("deny") or [])],
        },
        "enableArtifact": False,
        "disableClaudeAiConnectors": True,
        "sandbox": {"enabled": False},
        "env": env,
    }


def system_files(cfg, plan) -> dict[str, dict[str, str]]:
    """/etc/claude-code, bound read-only (see the module docstring)."""
    model = plan.model
    if model is not None and model.api != "anthropic-messages":
        raise ConfigError(f"Claude Code speaks only the Anthropic Messages API, not {model.api!r}; "
                          "pick provider anthropic (or an Anthropic-compatible endpoint)")
    wrapped = "tool-wrapper.argv" in plan.policies
    servers, mcp_allow, argv_files = _mcp(plan.composition, wrapped)
    files = {"managed-settings.json": json.dumps(managed_settings(cfg, plan, servers, mcp_allow, wrapped), indent=2)
             + "\n"}
    if servers:
        files["managed-mcp.json"] = json.dumps({"mcpServers": servers}, indent=2) + "\n"
    return {MANAGED_DIR: {**files, **argv_files}}


def _merge_json(path: Path, update: dict[str, Any]) -> None:
    """Deep-merge `update` into the JSON object at `path` (Claude Code keeps its
    own state there: never clobbered)."""
    try:
        doc = json.loads(path.read_text()) if path.is_file() else {}
    except ValueError:
        doc = {}
    if not isinstance(doc, dict):
        doc = {}

    def merge(a: dict, b: dict) -> dict:
        for k, v in b.items():
            a[k] = merge(a[k], v) if isinstance(v, dict) and isinstance(a.get(k), dict) else v
        return a

    path.write_text(json.dumps(merge(doc, update), indent=2) + "\n")


def _skill_links(comp) -> list[tuple[str, str]]:
    """(link name, container path) per contributed skill; a name taken by an
    earlier skill gets its extension's prefix."""
    out: dict[str, str] = {}
    for ext, _src, dest in comp.skills if comp is not None else []:
        name = Path(dest).name
        out[f"{ext}-{name}" if name in out else name] = dest
    return list(out.items())


def entry_args(comp) -> list[str]:
    return ["--add-dir", SKILLS_ROOT] if _skill_links(comp) else []


def image_lines(comp) -> tuple[list[str], list]:
    """Bake the skill links: outside the config home, so the agent can read a
    skill's files (and a tool command run its scripts) by the path Claude Code
    shows it."""
    links = _skill_links(comp)
    if not links:
        return [], []
    d = f"{SKILLS_ROOT}/.claude/skills"
    return ["# Claude Code: contributed skills (loaded with --add-dir)",
            f"RUN mkdir -p {d} && " + " && ".join(f"ln -s {shlex.quote(dest)} {shlex.quote(f'{d}/{name}')}"
                                                for name, dest in links)], []


def render_home(cfg, profile, home_dir: Path, model, comp=None) -> list[Path]:
    hc = _config(cfg)
    if model.api != "anthropic-messages":
        raise ConfigError(f"Claude Code speaks only the Anthropic Messages API, not {model.api!r}")
    cfg_dir = home_dir / rel_config_home(profile)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / profile.transcript_subdir).mkdir(exist_ok=True)

    settings: dict[str, Any] = {
        "model": model.model,
        "includeCoAuthoredBy": False,
        "attribution": {"commit": "", "pr": ""},
        **(hc.get("settings") or {}),
    }
    p_settings = cfg_dir / "settings.json"
    p_settings.write_text(json.dumps(settings, indent=2) + "\n")

    work = _mount_plan_for(cfg).working_dir
    p_state = cfg_dir / ".claude.json"
    _merge_json(p_state, {"hasCompletedOnboarding": True,
                          "projects": {work: {"hasTrustDialogAccepted": True}}})
    return [p_settings, p_state]


def describe(comp) -> list[str]:
    servers, _, _ = _mcp(comp)
    return [f"managed settings → {MANAGED_DIR} (read-only)", *(f"mcp server: {n}" for n in servers),
            *(f"skill: {name} → {dest}" for name, dest in _skill_links(comp))]
