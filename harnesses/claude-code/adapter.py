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
- managed-only hooks (which also keeps installed mods from running),
  permission rules and MCP servers, and no sideloaded plugins; one managed
  hook refuses every MCP tool off the session's allowlist; the tools the
  session's inventory (tools.json) classes shell, file_write and allow are
  approved, `deny` ones denied, and the rest (`ask`, a tool a new release
  adds) prompt;
  Read is denied on the config home and Edit (it covers every write tool) on
  what the harness may write that is not a write root: the whole home and
  /dev/shm (`//` is an absolute path);
- the switches that keep Claude Code to its inference host;
- with `webfetch`, Claude Code's own WebFetch through the egress proxy
  (`HTTPS_PROXY` in the managed env, every session forwarder in `NO_PROXY`).

`render_home` writes the user-scope `settings.json` (cosmetic, model) and merges
the onboarding/trust state into `.claude.json`, which Claude Code also writes;
with an API key injected it also approves the public placeholder Claude Code
reads, which it would otherwise ask about once (a subscription token's is
never asked about).
Contributed skills are linked from /opt/glove/cc/.claude/skills (baked, loaded
with `--add-dir`), not the config home, whose deny rules would hide their files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from glove.api import ConfigError, ExtensionError, scoped
from glove.api.harness import CONTAINER_HOME, INJECTED_KEY, AdapterContext, argv_lines

MANAGED_DIR = "/etc/claude-code"
SHELL_PREFIX = "/opt/glove/bin/glove-cc-prefix"
MCP_GATE = f"{SHELL_PREFIX} --deny-mcp"  # the prefix exits 2 on it (see _mcp_gate)
SKILLS_ROOT = "/opt/glove/cc"  # `--add-dir`: Claude Code loads <dir>/.claude/skills
DEFAULT_HOST = "api.anthropic.com"
# What the harness process may write beyond the write roots, under any
# enforcer (nono+srt: the whole home and /dev/shm; nono: the config home): its
# write tools are denied there, so they reach what a shell command may. Claude
# Code's rules can't say "only these", and deny wins.
HARNESS_WRITABLE = (CONTAINER_HOME, "/dev/shm")
# WebFetch fetches from inside the container, which reaches only the session's
# forwarders: refused rather than left to fail, unless `webfetch` gives it the
# egress proxy.
WEB_FETCH = "WebFetch"
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


def _config(actx: AdapterContext) -> dict[str, Any]:
    hc = dict(actx.harness_config)
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
    if any(r.startswith("mcp__") for r in perms.get("allow") or []):
        raise ConfigError("claude-code permissions.allow: an MCP tool is allowed by its extension's `tools` "
                          "(glove refuses every other)")
    if perms.get("defaultMode", "default") not in MODES:
        raise ConfigError(f"claude-code permissions.defaultMode must be one of {list(MODES)}")
    return hc


def _mcp(actx: AdapterContext, wrapped: bool = False) -> tuple[dict[str, Any], list[str], list[str], dict[str, str]]:
    """managed-mcp.json servers from the neutral `mcp` contribution; the
    permission rules their `tools` allowlists imply: allow rules for the listed
    tools, deny rules for every other tool the server is known to have
    (`all_tools`; Claude Code's rules can't say "only these", and an unknown
    tool would prompt: `_mcp_gate` refuses it); and, when `wrapped` (a shell
    prefix is set), each stdio server's argv file. Claude Code expands `${VAR}`
    (and `${VAR:-default}`) from its own env in a server's command, args, env
    and url, so a value naming one is refused (an argv file is read as written)."""
    servers: dict[str, Any] = {}
    allow: list[str] = []
    deny: list[str] = []
    argv_files: dict[str, str] = {}
    for _ext, item in actx.mcp:
        name, tools = item["name"], item.get("tools")  # core checked them
        if "__" in name:  # Claude Code splits mcp__<server>__<tool> at the first `__`
            raise ConfigError(f"MCP server {name!r}: Claude Code can't tell a server name with `__` from its tools")
        if item["transport"] == "http":
            _no_expansion(name, "url", [item["url"]])
            servers[name] = {"type": "http", "url": item["url"]}
        else:
            argv = [item["command"], *item.get("args", [])]
            if wrapped:
                if any("\n" in a for a in argv):
                    raise ConfigError(f"MCP server {name!r}: an argument with a newline")
                argv_files[f"mcp-{name}.argv"] = argv_lines(argv)
                argv = [SHELL_PREFIX, "--mcp", name]
            _no_expansion(name, "command and args", argv)
            _no_expansion(name, "env", list((item.get("env") or {}).values()))
            servers[name] = {"type": "stdio", "command": argv[0], "args": argv[1:],
                             **({"env": dict(item["env"])} if item.get("env") else {})}
        if tools is None:
            allow.append(f"mcp__{name}")
        else:
            allow += [f"mcp__{name}__{t}" for t in tools]
            deny += [f"mcp__{name}__{t}" for t in item.get("all_tools", []) if t not in tools]
    return servers, allow, deny, argv_files


def _no_expansion(name: str, where: str, values: list[str]) -> None:
    if any("${" in v for v in values):
        raise ConfigError(f"MCP server {name!r}: a `${{` in its {where}: Claude Code would fill in "
                          "a `${VAR}` from its own env")


def _mcp_gate(servers: dict[str, Any], mcp_allow: list[str]) -> dict[str, Any]:
    """A managed PreToolUse hook refusing every MCP tool the session does not
    allow: an unlisted tool would otherwise prompt, and the operator could
    grant it. Its matcher (a regex) matches only those tools; the prefix
    answers its command with exit 2, which blocks the call."""
    # an allow rule names a tool, or (a server without an allowlist) the
    # server; names are [A-Za-z0-9_-] (core checks them), literal in a regex
    allowed = [r + ("__.*" if r.removeprefix("mcp__") in servers else "") for r in mcp_allow]
    matcher = f"^(?!(?:{'|'.join(allowed)})$)mcp__" if allowed else "^mcp__"
    return {"PreToolUse": [{"matcher": matcher, "hooks": [{"type": "command", "command": MCP_GATE}]}]}


def _web_fetch_proxy(actx: AdapterContext) -> str | None:
    """The egress proxy an extension hands WebFetch (`claude-code: {web_fetch:
    {proxy: <url>}}`), if any."""
    proxy = None
    for sec in actx.sections:
        where = f"extension {sec.extension!r} harness"
        match sec.data:
            case {"web_fetch": {"proxy": str() as url} as wf} as section if len(section) == len(wf) == 1 \
                    and url.startswith(f"http://{scoped(actx.session, '')}"):
                proxy = url
            case _:
                raise ExtensionError(
                    f"{where}: `claude-code:` takes {{web_fetch: {{proxy: <a session endpoint's url>}}}}")
    return proxy


def _no_proxy(actx: AdapterContext) -> str:
    """Every name the harness reaches a session forwarder by (and loopback):
    inference, MCP servers and the rest never go through the egress proxy."""
    return ",".join(dict.fromkeys(["localhost", "127.0.0.1", "::1", *actx.harness_hosts]))


def _write_denies(actx: AdapterContext) -> list[str]:
    roots = actx.write_roots or ()
    for p in HARNESS_WRITABLE:
        if any(r == p or r.startswith(f"{p}/") for r in roots):
            raise ConfigError(f"claude-code: write root under {p}: its write tools are denied there")
    return [f"Edit(/{p}/**)" for p in HARNESS_WRITABLE]


def managed_settings(actx: AdapterContext, servers: dict[str, Any], mcp_allow: list[str],
                     mcp_deny: list[str]) -> dict[str, Any]:
    perms = _config(actx).get("permissions") or {}
    home = actx.config_home
    tools = actx.tool_policy
    env = dict(MANAGED_ENV)
    if actx.wrapped:
        env["CLAUDE_CODE_SHELL_PREFIX"] = SHELL_PREFIX
    proxy = _web_fetch_proxy(actx)
    if proxy:
        env.update({"HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "NO_PROXY": _no_proxy(actx)})
    model = actx.model
    if model is not None and urlsplit(model.base_url).hostname != DEFAULT_HOST:
        # only off the default host: CC treats a base URL as a gateway
        env["ANTHROPIC_BASE_URL"] = model.base_url
    return {
        # also keeps installed mods (in-process plugin code) from running
        "allowManagedHooksOnly": True,
        "hooks": _mcp_gate(servers, mcp_allow),
        "allowManagedPermissionRulesOnly": True,
        "disableSideloadFlags": True,
        "allowManagedMcpServersOnly": True,
        "allowedMcpServers": [{"serverName": n} for n in servers],
        "permissions": {
            "defaultMode": perms.get("defaultMode", "default"),
            "allow": [*tools["shell"], *tools["file_write"], *tools["allow"], *([WEB_FETCH] if proxy else []),
                      *mcp_allow, *(perms.get("allow") or [])],
            # WebFetch is denied unless webfetch hands it the egress proxy
            "deny": [f"Read(/{home}/**)", *_write_denies(actx),
                     *(d for d in tools["deny"] if not proxy or d != WEB_FETCH), *mcp_deny, *(perms.get("deny") or [])],
        },
        "enableArtifact": False,
        "disableClaudeAiConnectors": True,
        "sandbox": {"enabled": False},
        "env": env,
    }


def system_files(actx: AdapterContext) -> dict[str, dict[str, str]]:
    """/etc/claude-code, bound read-only (see the module docstring)."""
    model = actx.model
    if model is not None and model.api != "anthropic-messages":
        raise ConfigError(f"Claude Code speaks only the Anthropic Messages API, not {model.api!r}; "
                          "pick provider anthropic (or an Anthropic-compatible endpoint)")
    servers, mcp_allow, mcp_deny, argv_files = _mcp(actx, actx.wrapped)
    settings = managed_settings(actx, servers, mcp_allow, mcp_deny)
    files = {"managed-settings.json": json.dumps(settings, indent=2) + "\n"}
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


def entry_args(actx: AdapterContext) -> list[str]:
    return ["--add-dir", SKILLS_ROOT] if actx.skill_links else []


def image_lines(actx: AdapterContext) -> tuple[list[str], list]:
    """Bake the skill links: outside the config home, so the agent can read a
    skill's files (and a tool command run its scripts) by the path Claude Code
    shows it."""
    lines = actx.skill_link_lines(f"{SKILLS_ROOT}/.claude/skills")
    return (["# Claude Code: contributed skills (loaded with --add-dir)", *lines] if lines else []), []


def render_home(actx: AdapterContext, home_dir: Path) -> list[Path]:
    hc = _config(actx)
    model = actx.model
    if model.api != "anthropic-messages":
        raise ConfigError(f"Claude Code speaks only the Anthropic Messages API, not {model.api!r}")
    cfg_dir = actx.config_dir(home_dir)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / actx.transcript_subdir).mkdir(exist_ok=True)

    settings: dict[str, Any] = {
        "model": model.model,
        "includeCoAuthoredBy": False,
        "attribution": {"commit": "", "pr": ""},
        **(hc.get("settings") or {}),
    }
    p_settings = cfg_dir / "settings.json"
    p_settings.write_text(json.dumps(settings, indent=2) + "\n")

    work = actx.working_dir
    p_state = cfg_dir / ".claude.json"
    state: dict[str, Any] = {"hasCompletedOnboarding": True, "projects": {work: {"hasTrustDialogAccepted": True}}}
    if model.api_key_injected and model.api_key_kind == "api-key":  # an approved key's last 20 chars
        tail = INJECTED_KEY[-20:]
        approved = _approved_keys(p_state)
        state["customApiKeyResponses"] = {"approved": approved + [tail] * (tail not in approved)}
    _merge_json(p_state, state)
    return [p_settings, p_state]


def _approved_keys(path: Path) -> list:
    """The key tails Claude Code's state already approves (a list `_merge_json`
    would replace, not extend)."""
    try:
        doc = json.loads(path.read_text()) if path.is_file() else {}
        approved = doc["customApiKeyResponses"]["approved"]
    except (ValueError, KeyError, TypeError):
        return []
    return approved if isinstance(approved, list) else []


def describe(actx: AdapterContext) -> list[str]:
    # not `_mcp`: `actx` is the early one, without `wrapped`, and system_files checked the servers
    return [f"managed settings → {MANAGED_DIR} (read-only)", *(f"mcp server: {i['name']}" for _, i in actx.mcp),
            *(f"skill: {name} → {dest}" for name, dest in actx.skill_links)]
