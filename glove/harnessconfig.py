"""Generate the harness's own config inside the session home (A.3 + A.6 + B.3).

glove seeds a per-session home directory (bind-mounted to /home/agent) with the
harness's native config so the LLM host/port, MCP servers, and web-search live
entirely inside the container — the operator never edits the harness config by
hand. It also writes the host-sudo-relay context file (A.6).

The LLM endpoint is synthesised from the `llm` forwarder sidecar (A.5): the
harness talks to `glove-<session>-llm:<port>`, which socat-forwards to the host
SSH tunnel, which reaches faustulus. Nothing about faustulus leaks into the
harness config.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import tomli_w

from .config import Config
from .harness import HarnessProfile

CONTAINER_HOME = "/home/agent"

# Env var glove injects the LLM API key into (see Config.llm_api_key).
LLM_API_KEY_ENV = "GLOVE_LLM_API_KEY"

SUDO_RELAY = """\
# glove sandbox — operating rules

Root is **disabled** in this sandbox: you run as an unprivileged user, the root
filesystem is read-only, and `sudo` will fail. This is intentional.

If a task genuinely requires a privileged **host** command (installing a package,
changing host config, anything needing root on the host), do **not** attempt it
inside the container. Instead, print the exact command verbatim under a banner:

    ===== RUN ON HOST =====
    <the command>
    =======================

then stop and wait for the operator to run it and paste back the output.
"""


def container_llm_base(cfg: Config, session: str) -> str | None:
    """`http://glove-<session>-<llm_service>:<port>/v1`, or None if absent."""
    for svc in cfg.services:
        if svc.name == cfg.llm_service:
            return f"http://glove-{session}-{svc.name}:{svc.port}/v1"
    return None


def service_base(cfg: Config, session: str, name: str) -> str | None:
    """`http://glove-<session>-<name>:<port>` for a declared service, else None."""
    for svc in cfg.services:
        if svc.name == name:
            return f"http://glove-{session}-{svc.name}:{svc.port}"
    return None


# Backwards-compatible internal alias.
_service_host = service_base


def render_home(
    cfg: Config, profile: HarnessProfile, session: str, home_dir: Path
) -> list[Path]:
    """Write the harness config tree under `home_dir`; return files written."""
    home_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if cfg.harness == "vibe":
        written += _render_vibe(cfg, profile, session, home_dir)
    elif cfg.harness == "pi":
        written += _render_pi(cfg, profile, session, home_dir)
    elif cfg.harness == "claude-code":
        written += _render_claude(cfg, profile, session, home_dir)

    written.append(_write_context_file(cfg, profile, home_dir))
    return written


def _rel_config_home(profile: HarnessProfile) -> Path:
    return Path(profile.config_home_path).relative_to(CONTAINER_HOME)


def _mcp_servers(cfg: Config, session: str) -> list[dict[str, Any]]:
    """Auto-derive Vibe MCP servers from the network allow-list, then extend
    with any explicit `harness_config.mcp_servers`."""
    servers: list[dict[str, Any]] = []
    names = {s.name for s in cfg.services}
    if "browser" in names:
        base = _service_host(cfg, session, "browser")
        # Vibe's "http" transport speaks Streamable HTTP (it has no SSE client),
        # so point at Playwright MCP's /mcp endpoint, not /sse.
        servers.append(
            {"name": "playwright", "transport": "http", "url": f"{base}/mcp"}
        )
    if "search" in names:
        base = _service_host(cfg, session, "search")
        servers.append(
            {
                "name": "searxng",
                "transport": "stdio",
                "command": "python3",
                "args": ["/opt/glove/searxng_mcp.py"],
                "env": {"SEARXNG_URL": base},
            }
        )
    servers.extend(cfg.harness_config.get("mcp_servers", []))
    return servers


def _render_vibe(
    cfg: Config, profile: HarnessProfile, session: str, home_dir: Path
) -> list[Path]:
    cfg_dir = home_dir / _rel_config_home(profile)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    # Pre-create the session-log dir so an external monitor (e.g. Layman) can
    # bind-mount it read-only before Vibe's first turn writes messages.jsonl.
    (cfg_dir / "logs" / "session").mkdir(parents=True, exist_ok=True)

    llm_base = container_llm_base(cfg, session)
    model_id = cfg.model or "local"
    # Must NOT be a built-in Vibe alias ("local" is its bundled llamacpp Devstral;
    # Vibe deep-merges models by alias, so a collision silently shadows ours).
    alias = "faustulus"

    doc: dict[str, Any] = {
        "active_model": alias,
        "auto_approve": True,
        "api_timeout": 1800.0,
        "enable_update_checks": False,
        "enable_auto_update": False,
        "enable_telemetry": False,
        "mcp_servers": _mcp_servers(cfg, session),
        "providers": [
            {
                "name": "faustulus",
                "api_base": llm_base or "http://glove-llm:8080/v1",
                "api_key_env_var": LLM_API_KEY_ENV if cfg.llm_api_key else "",
                "api_style": "openai",
                "backend": "generic",
                "reasoning_field_name": "reasoning_content",
            }
        ],
        "models": [
            {
                "name": model_id,
                "provider": "faustulus",
                "alias": alias,
                "temperature": 1.0,
                "input_price": 0.0,
                "output_price": 0.0,
                # "off" does NOT disable thinking for backend=generic; it sends
                # no reasoning_effort so the server applies its pinned default.
                "thinking": "off",
                "auto_compact_threshold": 200000,
                "supports_images": True,
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
        else:
            doc[key] = value

    path = cfg_dir / "config.toml"
    path.write_bytes(tomli_w.dumps(doc).encode())
    return [path]


def _render_pi(
    cfg: Config, profile: HarnessProfile, session: str, home_dir: Path
) -> list[Path]:
    cfg_dir = home_dir / _rel_config_home(profile)
    cfg_dir.mkdir(parents=True, exist_ok=True)

    llm_base = container_llm_base(cfg, session) or "http://glove-llm:8080/v1"
    model_id = cfg.model or "local"

    faustulus_provider: dict[str, Any] = {
        "baseUrl": llm_base,
        "api": "openai-completions",
    }
    # Pi treats a provider with no credential as unconfigured ("No models
    # available"). Supply the key inline (provider.apiKey) when the endpoint
    # needs one — sent as Authorization: Bearer by the openai-completions adapter.
    if cfg.llm_api_key:
        faustulus_provider["apiKey"] = str(cfg.llm_api_key)

    models_json = {
        "providers": {
            "faustulus": {
                **faustulus_provider,
                "compat": {
                    "supportsDeveloperRole": False,
                    "supportsReasoningEffort": True,
                    "thinkingFormat": "reasoning_effort",
                    "maxTokensField": "max_tokens",
                },
                "models": [
                    {
                        "id": model_id,
                        "name": f"{model_id} (faustulus, via glove)",
                        "reasoning": True,
                        "thinkingLevelMap": {
                            "off": "none",
                            "low": "low",
                            "medium": "medium",
                            "xhigh": "xhigh",
                        },
                        "input": ["text", "image"],
                        "contextWindow": 262144,
                        "maxTokens": 200000,
                        "cost": {
                            "input": 0,
                            "output": 0,
                            "cacheRead": 0,
                            "cacheWrite": 0,
                        },
                    }
                ],
            }
        }
    }
    settings_json = {
        "defaultProvider": "faustulus",
        "defaultModel": model_id,
        "defaultThinkingLevel": "low",
        "theme": "dark",
    }
    search_host = _service_host(cfg, session, "search")
    if search_host:
        settings_json["env"] = {"SEARXNG_URL": search_host}

    written: list[Path] = []
    for name, data in (
        ("models.json", models_json),
        ("settings.json", settings_json),
    ):
        p = cfg_dir / name
        p.write_text(json.dumps(data, indent=2) + "\n")
        written.append(p)

    # glove's extensions (searxng web_search + browser bridge) are baked into the
    # image and loaded via `pi -e`; nothing to seed here. A user extensions/ dir
    # in the config home still auto-loads and is left untouched.
    (cfg_dir / "extensions").mkdir(parents=True, exist_ok=True)
    return written


def _render_claude(
    cfg: Config, profile: HarnessProfile, session: str, home_dir: Path
) -> list[Path]:
    cfg_dir = home_dir / _rel_config_home(profile)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    llm_base = container_llm_base(cfg, session) or "http://glove-llm:8080/v1"
    # Claude Code speaks the Anthropic API; point it at an OpenAI-compatible
    # base only works via a shim, so we just record settings for reference.
    settings = {
        "env": {
            "ANTHROPIC_BASE_URL": llm_base.removesuffix("/v1"),
            "ANTHROPIC_MODEL": cfg.model or "local",
        }
    }
    p = cfg_dir / "settings.json"
    p.write_text(json.dumps(settings, indent=2) + "\n")
    return [p]


def _write_context_file(
    cfg: Config, profile: HarnessProfile, home_dir: Path
) -> Path:
    rel = Path(profile.context_file).relative_to(CONTAINER_HOME)
    path = home_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    body = SUDO_RELAY
    if cfg.brief:
        body += "\n---\n\n# Session brief\n\n" + cfg.brief.strip() + "\n"
    path.write_text(body)
    return path
