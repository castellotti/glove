"""Generate the harness's own config inside the session home.

glove seeds a per-session home directory (bind-mounted to /home/agent) with the
harness's native config so the LLM host/port, MCP servers, and web-search live
entirely inside the container — the operator never edits the harness config by
hand. It also writes the host-sudo-relay context file.

The LLM endpoint comes from the `inference` slot's *model descriptor*
(``ModelDescriptor``) — the only LLM facts core knows. It names the forwarder
the harness talks to (``glove-<session>-llm``, or a cloud hostname aliased onto
it), the wire API, the model id and its capabilities; the provider catalog,
routing and probes live in the `llm` extension.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomli_w

from .config import Config
from .harness import HarnessProfile
from .mounts import MountPlan, compute_mounts

if TYPE_CHECKING:
    from .extensions import Composition

CONTAINER_HOME = "/home/agent"

# Env var glove passes the LLM API key in (never written to a file).
LLM_API_KEY_ENV = "GLOVE_LLM_API_KEY"
# What Pi sends when the endpoint needs no key (Pi refuses a provider without one).
NO_KEY_PLACEHOLDER = "glove-no-key"
DESCRIPTOR_APIS = ("openai-completions", "anthropic-messages", "mistral-conversations")


@dataclass(frozen=True)
class ModelDescriptor:
    """What the harness needs to talk to its model — provider-neutral."""

    base_url: str
    api: str
    model: str
    api_key_env: str | None = None
    vision: bool = False
    context_window: int = 32768
    max_tokens: int = 8192
    reasoning: bool = False
    extra_models: tuple[dict, ...] = ()

    @classmethod
    def from_exports(cls, ex: dict[str, Any]) -> ModelDescriptor:
        missing = [k for k in ("base_url", "api", "model") if not ex.get(k)]
        if missing:
            raise ValueError(f"the inference slot exports no {missing}")
        if ex["api"] not in DESCRIPTOR_APIS:
            raise ValueError(f"inference api {ex['api']!r} is not one of {DESCRIPTOR_APIS}")
        caps = ex.get("capabilities") or {}
        return cls(
            base_url=str(ex["base_url"]), api=str(ex["api"]), model=str(ex["model"]),
            api_key_env=LLM_API_KEY_ENV if ex.get("api_key_secret") else None,
            vision=bool(caps.get("vision")), context_window=int(caps.get("context_window") or 32768),
            max_tokens=int(caps.get("max_tokens") or 8192), reasoning=bool(caps.get("reasoning")),
            extra_models=tuple(ex.get("extra_models") or ()),
        )


def _mount_plan_for(cfg: Config) -> MountPlan:
    """Resolve the same mount plan the runtime renders, for the context file."""
    return compute_mounts(
        cfg.workdir,
        [(a.path, a.mode) for a in cfg.add_dirs],
        allow_sensitive=cfg.allow_sensitive,
    )


def build_environment_context(
    cfg: Config, mount_plan: MountPlan | None = None, comp: Composition | None = None
) -> str:
    """Generate the "How your environment works" block.

    Describes the mounts and their modes, that shell commands have no network,
    the RUN ON HOST relay rule, then each extension's brief in extension order —
    rendered from the *resolved* ``MountPlan`` (the same one the runtime mounts)
    so the paths and modes shown to the agent match reality.
    """
    if mount_plan is None:
        mount_plan = _mount_plan_for(cfg)

    lines = ["# How your environment works", ""]
    lines.append(
        "You run inside a defence-in-depth sandbox: a container (namespace, mounts, "
        "network) with a kernel capability sandbox "
        f"({cfg.enforcer}) wrapping the agent and **every shell command** it runs."
    )
    lines += ["", "## Files", ""]
    lines.append(f"- You start in `{mount_plan.working_dir}` — your working directory.")
    for m in mount_plan.mounts:
        if m.is_workdir:
            role = "your writable workspace (this is the project you were launched on)"
        else:
            role = "extra directory" + (" (read-only)" if m.read_only else " (writable)")
        lines.append(f"- `{m.container_path}` ({m.mode}) — {role}.")
    if not any(m.is_workdir for m in mount_plan.mounts):
        # workdir was absorbed into an add-dir mount; there is no /work.
        lines.append(
            "- (Your working directory lives inside one of the mounts above; there is "
            "no separate `/work`.)"
        )
    lines.append(
        "- Everything else (system dirs) is read-only; your **config/extensions/"
        "session history are NOT reachable from a shell command** — only the agent "
        "itself can read them."
    )
    lines += ["", "## Network", ""]
    lines.append(
        "- **Shell commands have no network at all** (`curl`, `wget`, `pip`, "
        "`npm install` will fail). Only your own tools reach the endpoints below."
    )
    lines.append("- You cannot read the LLM API key or any secret from a shell (`env` hides them).")
    lines += ["", "## Privileged host commands", "", SUDO_RELAY_BODY]
    briefs = comp.rendered_briefs() if comp is not None else []
    if briefs:
        lines += ["", "## Capabilities", ""]
        for _ext, text in briefs:
            lines += [text, ""]
    return "\n".join(lines).rstrip("\n") + "\n"


# The RUN ON HOST relay text, reused inside the generated environment block.
SUDO_RELAY_BODY = """\
Root is **disabled** here and `sudo` will fail. If a task genuinely needs a
privileged **host** command, print it verbatim under a banner and stop:

    ===== RUN ON HOST =====
    <the command>
    =======================

then wait for the operator to run it and paste back the output."""


def render_home(
    cfg: Config,
    profile: HarnessProfile,
    home_dir: Path,
    model: ModelDescriptor,
    *,
    mount_plan: MountPlan | None = None,
    comp: Composition | None = None,
) -> list[Path]:
    """Write the harness config tree under `home_dir`; return files written.

    `model` is the (launch-resolved) descriptor of the inference slot;
    `mount_plan` is the runtime's resolved mount plan (recomputed from `cfg`
    when omitted) so the context file reflects the real mounts.
    """
    home_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if cfg.harness == "vibe":
        written += _render_vibe(cfg, profile, home_dir, model, comp)
    elif cfg.harness == "pi":
        written += _render_pi(cfg, profile, home_dir, model, comp)
    elif cfg.harness == "claude-code":
        written += _render_claude(profile, home_dir, model)

    written.append(_write_context_file(cfg, profile, home_dir, mount_plan, comp))
    return written


def rel_config_home(profile: HarnessProfile) -> Path:
    """The harness config dir relative to the host home (strips CONTAINER_HOME)."""
    return Path(profile.config_home_path).relative_to(CONTAINER_HOME)


def _mcp_servers(cfg: Config, comp: Composition | None) -> tuple[list[dict[str, Any]], list[str]]:
    """Vibe MCP servers: each extension's contribution, then explicit
    `harness_config.mcp_servers` — and Vibe `disabled_tools` patterns.

    An extension's server may carry `enabled_tools` (a list, or comma-separated):
    an allowlist of that server's tools. Vibe has no per-server allowlist (its
    global `enabled_tools` would hide its own tools too), so it becomes one
    regex that hides every other `<server>_*` tool — including ones a later
    server version adds."""
    servers: list[dict[str, Any]] = []
    disabled: list[str] = []
    for item in comp.vibe_mcp if comp is not None else []:
        item = dict(item)
        allow = item.pop("enabled_tools", None)
        if allow is not None:
            names = [t.strip() for t in (allow.split(",") if isinstance(allow, str) else allow) if str(t).strip()]
            ok = re.fullmatch(r"[a-z0-9_]+", item["name"]) and all(re.fullmatch(r"[A-Za-z0-9_-]+", n) for n in names)
            if not ok:
                raise ValueError(f"vibe mcp {item['name']!r}: bad enabled_tools {names}")
            disabled.append(f"re:{item['name']}_(?!(?:{'|'.join(names) or '(?!)'})$).*")
        servers.append(item)
    servers.extend(cfg.harness_config.get("mcp_servers", []))
    return servers, disabled


# Descriptor api → Vibe (backend, api_style).
VIBE_BACKENDS = {"openai-completions": ("generic", "openai"), "mistral-conversations": ("mistral", "openai")}


def _render_vibe(
    cfg: Config, profile: HarnessProfile, home_dir: Path, model: ModelDescriptor, comp: Composition | None
) -> list[Path]:
    cfg_dir = home_dir / rel_config_home(profile)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    # Pre-create the session-log dir so an external monitor (e.g. Layman) can
    # bind-mount it read-only before Vibe's first turn writes messages.jsonl.
    (cfg_dir / "logs" / "session").mkdir(parents=True, exist_ok=True)

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

    # Pass through arbitrary Vibe config from the (git-tracked) glove.yaml
    # `harness_config`, keeping glove.yaml the single reproducible source of
    # truth. mcp_servers is already merged above; lists extend, scalars/tables
    # override.
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
    if cfg.enforcer in ("nono", "nono+srt", "srt"):
        written.append(_write_vibe_hooks(cfg_dir))
    return written


VIBE_HOOKS_TOML = """\
# Generated by glove — do not edit by hand.
# Routes every shell command through the ring-1 enforcer. The hook
# rewrites the bash tool's `command` and denies direct-egress tool names.
# strict = true → any hook failure denies the tool (fail closed).
[[hooks]]
name = "glove-enforcer"
type = "pre_tool"
match = "*"
command = "/opt/glove/vibe-hook"
strict = true
description = "glove ring-1 sandbox: wrap shell commands, deny web egress tools."
"""


def _write_vibe_hooks(cfg_dir: Path) -> Path:
    path = cfg_dir / "hooks.toml"
    path.write_text(VIBE_HOOKS_TOML)
    return path


def _pi_model(entry: dict[str, Any], model: ModelDescriptor) -> dict[str, Any]:
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


def _render_pi(cfg: Config, profile: HarnessProfile, home_dir: Path, model: ModelDescriptor,
               comp: Composition | None = None) -> list[Path]:
    cfg_dir = home_dir / rel_config_home(profile)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    model_id = model.model

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
    }
    # Endpoint URLs (e.g. SEARXNG_URL) reach Pi as container env from the
    # extensions' `harness.env`, which the Pi extensions read directly.

    # Let the (git-tracked) glove.yaml `harness_config` override Pi settings and
    # model fields without a code change — e.g. `defaultThinkingLevel: xhigh`, or
    # extra per-model tuning if the endpoint supports it. `env` is deep-merged.
    extra_settings = dict(cfg.harness_config.get("settings", {}))
    extra_env = extra_settings.pop("env", None)
    # extensions' skills first, then any the session file lists itself
    skills = [dest for _, _, dest in (comp.pi_skills if comp else [])]
    settings_json.update(extra_settings)
    if skills:
        settings_json["skills"] = [*skills, *(s for s in extra_settings.get("skills") or [] if s not in skills)]
    if extra_env:
        settings_json.setdefault("env", {}).update(extra_env)
    model_overrides = cfg.harness_config.get("model", {})
    if model_overrides:
        models[0].update(model_overrides)

    written: list[Path] = []
    for name, data in (
        ("models.json", models_json),
        ("settings.json", settings_json),
    ):
        p = cfg_dir / name
        p.write_text(json.dumps(data, indent=2) + "\n")
        written.append(p)

    # glove's always-on enforcer extension (and any selected extensions' Pi
    # extensions) are baked into the image and loaded via `pi -e`; nothing to
    # seed here. A user extensions/ dir in the config home still auto-loads and
    # is left untouched.
    (cfg_dir / "extensions").mkdir(parents=True, exist_ok=True)
    return written


def _render_claude(profile: HarnessProfile, home_dir: Path, model: ModelDescriptor) -> list[Path]:
    cfg_dir = home_dir / rel_config_home(profile)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    # Claude Code speaks the Anthropic API; an OpenAI-compatible base only works
    # via a shim, so we just record settings for reference.
    settings = {
        "env": {
            "ANTHROPIC_BASE_URL": model.base_url.removesuffix("/v1"),
            "ANTHROPIC_MODEL": model.model,
        }
    }
    p = cfg_dir / "settings.json"
    p.write_text(json.dumps(settings, indent=2) + "\n")
    return [p]


def _write_context_file(
    cfg: Config,
    profile: HarnessProfile,
    home_dir: Path,
    mount_plan: MountPlan | None = None,
    comp: Composition | None = None,
) -> Path:
    rel = Path(profile.context_file).relative_to(CONTAINER_HOME)
    path = home_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    body = build_environment_context(cfg, mount_plan, comp)
    if cfg.brief:
        body += "\n---\n\n# Session brief\n\n" + cfg.brief.strip() + "\n"
    path.write_text(body)
    return path
