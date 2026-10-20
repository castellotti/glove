"""Pi adapter: models.json + settings.json + mcp.json, and Pi's `-e` extensions.

MCP servers come from the neutral `harness.mcp` contribution (`actx.mcp`) and
are rendered into the read-only `mcp.json` for Pi's built-in MCP, which is on
only when there is one. A server's `tools` allowlist becomes `"exposure":
"hidden"` with each listed tool `direct` (Pi's default, `codemode`, would hide
them from the model, and its scripts could reach the rest). Pi names them
`mcp__<server>__<tool>`; those names join the session's tool inventory, which
the enforcer extension refuses every other tool by. A stdio server runs as its
contributor wrote it (the `skills` extension's go through `glove-confine`, the
tool wrapper). Pi expands `${VAR}` and runs a `!command` in `env` values, so
glove's literal values may hold no `$` and start with no `!`.

Extensions may also contribute Pi code as `harness: {pi: {extensions: [<dir>,
…], tools: [<name>, …]}}`: each directory is baked into the derived image under
/opt/glove/ext/<ext>/ and loaded with `pi -e <path>`, and the tools it
registers are added to the session's tool inventory (passthrough). Skills come
from the neutral `harness.skills` contribution (`actx.skills`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from glove.api import ExtensionError
from glove.api import tool_names as checked_tool_names
from glove.api.harness import AdapterContext, HarnessSection, staged_name

# What Pi sends when the endpoint needs no key (Pi refuses a provider without one).
NO_KEY_PLACEHOLDER = "glove-no-key"
SECTION_KEYS = frozenset({"extensions", "tools"})


def _merged(first: list, extra: list | None) -> list:
    """`first`, then what `extra` adds to it."""
    return [*first, *(e for e in extra or [] if e not in first)]


def _sections(actx: AdapterContext) -> list[tuple[HarnessSection, str]]:
    out = []
    for sec in actx.sections:
        where = f"extension {sec.extension!r} harness"
        if not isinstance(sec.data, dict) or set(sec.data) - SECTION_KEYS:
            raise ExtensionError(f"{where}: `pi:` takes {sorted(SECTION_KEYS)}")
        out.append((sec, where))
    return out


def _pi_name(name: str) -> str:
    """Pi's form of a server or tool name in `mcp__<server>__<tool>` (core
    allows letters, digits, `_` and `-`; Pi replaces the rest with `_`)."""
    return name.replace("-", "_")


def _mcp_servers(actx: AdapterContext) -> dict[str, dict[str, Any]]:
    """mcp.json's `mcpServers`, from the neutral `mcp` contribution. Refused:
    a server without a `tools` allowlist (the inventory names every tool Pi may
    call), and names that are one once Pi has replaced their `-` (Pi drops the
    second server, or suffixes both tools, so the inventory would miss them)."""
    servers: dict[str, dict[str, Any]] = {}
    pi_names: set[str] = set()
    for _ext, item in actx.mcp:
        name, tools = item["name"], item.get("tools")  # core checked them
        where = f"pi mcp {name!r}"
        if tools is None:
            raise ExtensionError(f"{where}: Pi needs its `tools` allowlist")
        if _pi_name(name) in pi_names:
            raise ExtensionError(f"{where}: another server has the same name in Pi")
        pi_names.add(_pi_name(name))
        if len({_pi_name(t) for t in tools}) != len(tools):
            raise ExtensionError(f"{where}: two tools have the same name in Pi")
        if item["transport"] == "http":
            server: dict[str, Any] = {"url": item["url"]}
        else:
            env = item.get("env") or {}  # core made the values strings
            if bad := sorted(k for k, v in env.items() if v.lstrip().startswith("!") or "$" in v):
                raise ExtensionError(f"{where}: env {bad}: Pi would run a `!command` or expand a `$`")
            server = {"command": item["command"], "args": item.get("args", []), **({"env": env} if env else {})}
        servers[name] = {**server, "exposure": "hidden", "toolExposure": dict.fromkeys(tools, "direct")}
    return servers


def tool_names(actx: AdapterContext) -> list[str]:
    """The tools the session's Pi extensions register (`pi: {tools: …}`, a list
    or comma-separated), then the MCP tools glove's servers allow, as Pi names
    them."""
    return [*(n for sec, where in _sections(actx)
              for n in checked_tool_names(f"{where} pi", sec.data.get("tools") or [])),
            *(f"mcp__{_pi_name(s)}__{_pi_name(t)}"
              for s, srv in _mcp_servers(actx).items() for t in srv["toolExposure"])]


def extensions(actx: AdapterContext) -> list[tuple[str, Path]]:
    """(extension, source dir) of every Pi extension the session's extensions contribute."""
    out: list[tuple[str, Path]] = []
    for sec, where in _sections(actx):
        for item in sec.data.get("extensions") or []:
            src = sec.assets / (item["src"] if isinstance(item, dict) else item)
            if not src.is_dir():
                raise ExtensionError(f"{where}: pi extension {src} not found")
            out.append((sec.extension, src))
    return out


def extension_dest(ext: str, src: Path) -> str:
    return f"/opt/glove/ext/{ext}/{src.name}"


def entry_args(actx: AdapterContext) -> list[str]:
    return [arg for ext, src in extensions(actx) for arg in ("-e", extension_dest(ext, src))]


def image_lines(actx: AdapterContext) -> tuple[list[str], list[tuple[str, Path]]]:
    lines: list[str] = []
    staged = extensions(actx)
    for ext, src in staged:
        dest = extension_dest(ext, src)
        lines.append(f"# extension: {ext} (Pi extension)")
        lines.append(f"COPY {staged_name(ext, src)} {dest}")
        if (src / "package.json").is_file():
            lines.append(f"RUN cd {dest} && npm install --no-audit --no-fund")
    return lines, staged


def describe(actx: AdapterContext) -> list[str]:
    """Lines for `glove plan`."""
    return [*(f"pi extension ({ext}): {extension_dest(ext, src)}" for ext, src in extensions(actx)),
            *(f"mcp server: {n}" for n in _mcp_servers(actx))]


def _pi_model(entry: dict[str, Any], model) -> dict[str, Any]:
    """One Pi model entry; `entry` may override id/vision/context for extra models."""
    mid = entry.get("id", model.model)
    reasoning = bool(entry.get("reasoning", model.reasoning))
    out: dict[str, Any] = {
        "id": mid,
        "name": f"{mid} (glove)",
        "reasoning": reasoning,
        "input": ["text", "image"] if entry.get("vision", model.vision) else ["text"],
        "contextWindow": int(entry.get("context_window", model.context_window)),
        "maxTokens": int(entry.get("max_tokens", model.max_tokens)),
        "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
    }
    if reasoning:
        out["thinkingLevelMap"] = {"off": "none", "low": "low", "medium": "medium", "xhigh": "xhigh"}
    return out


def render_home(actx: AdapterContext, home_dir: Path) -> list[Path]:
    model = actx.model
    cfg_dir = actx.config_dir(home_dir)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    model_id = model.model

    servers = _mcp_servers(actx)
    glove_provider: dict[str, Any] = {"baseUrl": model.base_url, "api": model.api}
    # Pi treats a provider with no credential as unconfigured ("No models
    # available"). When the endpoint needs a key, name the env var glove passes
    # the harness (Pi resolves "$VAR" in apiKey), so the key itself is never
    # written into the home.
    # Keyless servers (e.g. llama-server without --api-key) ignore it, but Pi
    # still needs a non-empty value: it is a fixed placeholder, not a secret.
    glove_provider["apiKey"] = f"${model.api_key_env}" if model.api_key_env else NO_KEY_PLACEHOLDER
    if model.api == "openai-completions":
        glove_provider["compat"] = {
            "supportsDeveloperRole": False,
            "supportsReasoningEffort": model.reasoning,
            "thinkingFormat": "reasoning_effort",
            "maxTokensField": "max_tokens",
        }
    models = [_pi_model({}, model), *(_pi_model(dict(e), model) for e in model.extra_models)]
    models_json = {"providers": {"glove": {**glove_provider, "models": models}}}
    settings_json = {
        "defaultProvider": "glove",
        "defaultModel": model_id,
        "defaultThinkingLevel": "low",
        "theme": "dark",
        # skip the project's `.pi/` and `.agents/skills` without asking (the
        # empty trust store below holds no saved decision to override it)
        "defaultProjectTrust": "never",
        # Pi's built-in MCP loads only glove's read-only mcp.json (the project's
        # stays behind trust). Off without a server; a session's own extensions
        # (appended below) never turn it on or off.
        "extensions": [] if servers else ["-builtin:mcp"],
    }
    # An extension's own Pi code reads what it needs (e.g. an endpoint URL) from
    # container env, its `harness.env`; nothing goes into settings.

    # Let the (git-tracked) session file's `harness_config` override Pi settings
    # and model fields without a code change — e.g. `defaultThinkingLevel: xhigh`,
    # or extra per-model tuning if the endpoint supports it. `env` is deep-merged.
    extra_settings = dict(actx.harness_config.get("settings", {}))
    extra_env = extra_settings.pop("env", None)
    # extensions' skills first, then any the session file lists itself
    skills = list(actx.skills)
    # the session's own extensions after glove's, minus any naming the built-in MCP
    extra_ext = [e for e in extra_settings.pop("extensions", None) or [] if not e.endswith("builtin:mcp")]
    settings_json.update(extra_settings)
    settings_json["extensions"] = _merged(settings_json["extensions"], extra_ext)
    if skills:
        settings_json["skills"] = _merged(skills, extra_settings.get("skills"))
    if extra_env:
        settings_json.setdefault("env", {}).update(extra_env)
    model_overrides = actx.harness_config.get("model", {})
    if model_overrides:
        models[0].update(model_overrides)

    written: list[Path] = []
    for name, data in (
        ("models.json", models_json),
        ("settings.json", settings_json),
        ("trust.json", {}),
        # no credentials: llm-auth holds the key (read-only, so /login can't
        # store one where the agent's next start would use it)
        ("auth.json", {}),
        *((("mcp.json", {"mcpServers": servers}),) if servers else ()),
    ):
        p = cfg_dir / name
        p.write_text(json.dumps(data, indent=2) + "\n")
        written.append(p)

    # Files Pi loads that glove has nothing for: its system prompt (in place of,
    # or after, its own), keybindings and, without a server, MCP servers. glove
    # renders them empty (Pi 1.x ignores an empty one) and `protect` binds them
    # read-only, so whatever an earlier run left there (before they were
    # protected) goes, and `/mcp` exposure changes fail to save. Not deleted: a
    # bind source must exist, or the runtime makes it a directory.
    for name in ("SYSTEM.md", "APPEND_SYSTEM.md", "keybindings.json", *(() if servers else ("mcp.json",))):
        (cfg_dir / name).write_text("")
    # glove's brief from before it moved to AGENTS.override.md
    (cfg_dir / "AGENTS.md").unlink(missing_ok=True)

    # glove's always-on enforcer extension (and any selected extensions' Pi
    # extensions) are baked into the image and loaded via `pi -e`; nothing to
    # seed here. The config home's extensions/ (read-only to the agent) still
    # auto-loads what the operator puts there, and is left untouched.
    return written
