"""Mistral Vibe adapter: config.toml (provider, model, MCP servers) + hooks.toml.

MCP servers come from the neutral `harness.mcp` contribution (`comp.mcp`). A
server's `tools` (a list, or comma-separated) is an allowlist: Vibe has no
per-server allowlist (its global `enabled_tools` would hide its own tools too),
so it becomes one `disabled_tools` regex that hides every other `<server>_*`
tool — including ones a later server version adds.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import tomli_w

from glove.harnessconfig import mcp_tool_names, rel_config_home

# Descriptor api → Vibe (backend, api_style).
VIBE_BACKENDS = {"openai-completions": ("generic", "openai"), "mistral-conversations": ("mistral", "openai")}


def _mcp_servers(cfg, comp) -> tuple[list[dict[str, Any]], list[str]]:
    """Each extension's MCP server, then explicit `harness_config.mcp_servers` —
    and the `disabled_tools` patterns their `tools` allowlists imply."""
    servers: list[dict[str, Any]] = []
    disabled: list[str] = []
    for _ext, item in comp.mcp if comp is not None else []:
        item = dict(item)
        allow = item.pop("tools", None)
        if allow is not None:
            names = mcp_tool_names(allow)
            ok = re.fullmatch(r"[a-z0-9_]+", item["name"]) and all(re.fullmatch(r"[A-Za-z0-9_-]+", n) for n in names)
            if not ok:
                raise ValueError(f"vibe mcp {item['name']!r}: bad tools {names}")
            disabled.append(f"re:{item['name']}_(?!(?:{'|'.join(names) or '(?!)'})$).*")
        servers.append(item)
    servers.extend(cfg.harness_config.get("mcp_servers", []))
    return servers, disabled


def render_home(cfg, profile, home_dir: Path, model, comp=None) -> list[Path]:
    cfg_dir = home_dir / rel_config_home(profile)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    # Pre-create the session-log dir so an external monitor (e.g. Layman) can
    # bind-mount it read-only before Vibe's first turn writes messages.jsonl.
    (cfg_dir / profile.sessions_subdir).mkdir(parents=True, exist_ok=True)

    if model.api not in VIBE_BACKENDS:
        raise ValueError(f"Vibe cannot speak the {model.api!r} API; pick an OpenAI-compatible or Mistral provider")
    backend, api_style = VIBE_BACKENDS[model.api]
    model_id = model.model
    # Must NOT be a built-in Vibe alias ("local" is its bundled llamacpp Devstral;
    # Vibe deep-merges models by alias, so a collision silently shadows ours).
    alias = "glove"

    servers, disabled_tools = _mcp_servers(cfg, comp)
    doc: dict[str, Any] = {
        "active_model": alias,
        "auto_approve": True,
        "api_timeout": 1800.0,
        "enable_update_checks": False,
        "enable_auto_update": False,
        "enable_telemetry": False,
        # Use the standard bash tool (spawns via the shell) so glove's pre_tool
        # hook, which rewrites the command text, applies cleanly.
        "experimental_bash_tool": False,
        "mcp_servers": servers,
        "providers": [
            {
                "name": "glove",
                "api_base": model.base_url,
                "api_key_env_var": model.api_key_env or "",
                "api_style": api_style,
                "backend": backend,
                "reasoning_field_name": "reasoning_content",
            }
        ],
        "models": [
            {
                "name": model_id,
                "provider": "glove",
                "alias": alias,
                "temperature": 1.0,
                "input_price": 0.0,
                "output_price": 0.0,
                # "off" does NOT disable thinking for backend=generic; it sends
                # no reasoning_effort so the server applies its pinned default.
                "thinking": "off",
                "auto_compact_threshold": max(1024, int(model.context_window * 0.8)),
                "supports_images": model.vision,
            }
        ],
    }

    # Pass through arbitrary Vibe config from the (git-tracked) session file's
    # `harness_config`, keeping it the single reproducible source of truth.
    # mcp_servers is already merged above; lists extend, scalars/tables override.
    for key, value in cfg.harness_config.items():
        if key == "mcp_servers":
            continue
        if key in ("providers", "models") and isinstance(value, list):
            doc[key].extend(value)
        elif key == "disabled_tools" and isinstance(value, list):
            disabled_tools = [*disabled_tools, *value]
        else:
            doc[key] = value

    if disabled_tools:
        doc["disabled_tools"] = disabled_tools
    path = cfg_dir / "config.toml"
    path.write_bytes(tomli_w.dumps(doc).encode())
    written = [path]

    # Ring-1 tool hook: route every bash tool call through the enforcer's
    # per-command sandbox. Only when an in-container enforcer is
    # active — `none` has no wrapper to invoke.
    if cfg.enforcer != "none":
        written.append(_write_vibe_hooks(cfg_dir))
    return written


VIBE_HOOKS_TOML = """\
# Generated by glove — do not edit by hand.
# Routes every shell command through the ring-1 enforcer. The hook
# rewrites the bash tool's `command` and denies direct-egress tool names.
# strict = true → any hook failure denies the tool (fail closed). The image's
# own python runs it, never a `toolchains` python first on PATH.
[[hooks]]
name = "glove-enforcer"
type = "pre_tool"
match = "*"
command = "/usr/local/bin/python3 /opt/glove/vibe-hook"
strict = true
description = "glove ring-1 sandbox: wrap shell commands, deny web egress tools."
"""


def _write_vibe_hooks(cfg_dir: Path) -> Path:
    path = cfg_dir / "hooks.toml"
    path.write_text(VIBE_HOOKS_TOML)
    return path
