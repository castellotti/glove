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

from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .config import Config
from .harness import HarnessProfile, adapter_call
from .mounts import MountPlan, compute_mounts

if TYPE_CHECKING:
    from .extensions import Composition
    from .toolchains import Toolchain

CONTAINER_HOME = "/home/agent"

# Env var glove passes the LLM API key in (never written to a file).
LLM_API_KEY_ENV = "GLOVE_LLM_API_KEY"
DESCRIPTOR_APIS = ("openai-completions", "anthropic-messages", "mistral-conversations")


@dataclass(frozen=True)
class ModelDescriptor:
    """What the harness needs to talk to its model — provider-neutral."""

    base_url: str
    api: str
    model: str
    api_key_env: str | None = None
    # How the key authenticates: "api-key", or "oauth" (a subscription token the
    # provider catalog allows only for some harnesses); the adapter picks its env.
    api_key_kind: str = "api-key"
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
            api_key_kind=str(ex.get("api_key_kind") or "api-key"),
            vision=bool(caps.get("vision")), context_window=int(caps.get("context_window") or 32768),
            max_tokens=int(caps.get("max_tokens") or 8192), reasoning=bool(caps.get("reasoning")),
            extra_models=tuple(ex.get("extra_models") or ()),
        )


def harness_model(profile: HarnessProfile, exports: dict[str, Any]) -> ModelDescriptor:
    """The descriptor for this harness: the key travels in the env var its
    adapter names (`secret_env(model)`), else `GLOVE_LLM_API_KEY`."""
    model = ModelDescriptor.from_exports(exports)
    name = adapter_call(profile, "secret_env", model) if model.api_key_env else None
    return replace(model, api_key_env=name) if name else model


def mcp_tool_names(tools: str | Sequence[Any]) -> list[str]:
    """An `mcp` contribution's `tools` allowlist (a comma-separated string or a
    list) as tool names."""
    return [t.strip() for t in (tools.split(",") if isinstance(tools, str) else tools) if str(t).strip()]


def _mount_plan_for(cfg: Config) -> MountPlan:
    """Resolve the same mount plan the runtime renders, for the context file."""
    return compute_mounts(
        cfg.workdir,
        [(a.path, a.mode) for a in cfg.add_dirs],
        allow_sensitive=cfg.allow_sensitive,
    )


def build_environment_context(
    cfg: Config, mount_plan: MountPlan | None = None, comp: Composition | None = None,
    toolchains: Sequence[Toolchain] | None = None,
) -> str:
    """Generate the "How your environment works" block.

    Describes the mounts and their modes, that shell commands have no network,
    the RUN ON HOST relay rule, then each extension's brief in extension order —
    rendered from the *resolved* ``MountPlan`` (the same one the runtime mounts)
    so the paths and modes shown to the agent match reality. ``toolchains`` is
    the plan's resolved list (parsed from `cfg` when omitted).
    """
    if mount_plan is None:
        mount_plan = _mount_plan_for(cfg)
    if toolchains is None:
        from .toolchains import parse

        toolchains = parse(cfg.toolchains)

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
    if toolchains:
        from .toolchains import brief

        lines += ["", brief(toolchains, cfg.enforcer, cfg.enforcer_options)]
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
    toolchains: Sequence[Toolchain] | None = None,
) -> list[Path]:
    """Write the harness config tree under `home_dir`; return files written.

    `model` is the (launch-resolved) descriptor of the inference slot;
    `mount_plan` is the runtime's resolved mount plan (recomputed from `cfg`
    when omitted) so the context file and the adapter see the real mounts and
    working dir.
    """
    home_dir.mkdir(parents=True, exist_ok=True)
    if mount_plan is None:
        mount_plan = _mount_plan_for(cfg)
    written: list[Path] = []

    # the harness's native config (its adapter: harnesses/<name>/adapter.py)
    written += adapter_call(profile, "render_home", cfg, profile, home_dir, model, comp, mount_plan, default=[])

    written.append(_write_context_file(cfg, profile, home_dir, mount_plan, comp, toolchains))
    return written


def rel_config_home(profile: HarnessProfile) -> Path:
    """The harness config dir relative to the host home (strips CONTAINER_HOME)."""
    return Path(profile.config_home_path).relative_to(CONTAINER_HOME)


def _write_context_file(
    cfg: Config,
    profile: HarnessProfile,
    home_dir: Path,
    mount_plan: MountPlan | None = None,
    comp: Composition | None = None,
    toolchains: Sequence[Toolchain] | None = None,
) -> Path:
    rel = Path(profile.context_file).relative_to(CONTAINER_HOME)
    path = home_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    body = build_environment_context(cfg, mount_plan, comp, toolchains)
    if cfg.brief:
        body += "\n---\n\n# Session brief\n\n" + cfg.brief.strip() + "\n"
    path.write_text(body)
    return path
