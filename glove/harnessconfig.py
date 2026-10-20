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
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from .config import Config
from .harness import HarnessProfile, adapter_call, get_profile
from .mounts import CONTAINER_HOME
from .naming import scoped

if TYPE_CHECKING:
    from .extensions import Composition
    from .plan import SessionPlan


# Env var glove passes the LLM API key in (never written to a file).
LLM_API_KEY_ENV = "GLOVE_LLM_API_KEY"
# What that variable holds when the inference provider injects the key itself
# (`api_key_injected`): a public placeholder, so the harness never holds the key.
INJECTED_KEY = "glove-injected"
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
    # The provider adds the key on the way (`llm`'s llm-auth sidecar): the
    # harness's variable holds INJECTED_KEY, never the key.
    api_key_injected: bool = False
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
            api_key_injected=bool(ex.get("api_key_injected")),
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


@dataclass(frozen=True)
class HarnessSection:
    """An extension's `harness.<this harness>:` section, rendered by core: a
    list in it holds only the items whose `when:` matches, without `when`."""

    extension: str
    assets: Path  # the extension's directory
    data: Any


@dataclass(frozen=True)
class AdapterContext:
    """What a harness adapter's functions see (`api: 2`). The late fields are
    None (or empty) until the plan has them: `tool_names`, `entry_args`,
    `image_lines` and `describe` run before it exists."""

    session: str
    config_home: str  # the harness's config dir in the container
    transcript_subdir: str | None = None
    sessions_subdir: str | None = None
    harness_config: Mapping[str, Any] = MappingProxyType({})  # without glove's `protect:` opt-ins
    enforcer: str = ""
    mcp: tuple[tuple[str, dict], ...] = ()  # (extension, checked server)
    skills: tuple[str, ...] = ()  # container paths
    skill_links: tuple[tuple[str, str], ...] = ()  # (link name, container path)
    sections: tuple[HarnessSection, ...] = ()
    # late
    model: ModelDescriptor | None = None
    tool_policy: Mapping[str, list[str]] | None = None  # tools.json
    wrapped: bool = False  # a tool wrapper runs every command
    write_roots: tuple[str, ...] | None = None
    harness_hosts: tuple[str, ...] = ()  # the names the harness reaches forwarders by
    working_dir: str | None = None

    def config_dir(self, home_dir: Path) -> Path:
        """The config dir under the session home on the host."""
        return home_dir / rel_config_home(self.config_home)

    def skill_link_lines(self, directory: str) -> list[str]:
        """Dockerfile lines baking `skill_links` into `directory` (none without skills)."""
        if not self.skill_links:
            return []
        q = shlex.quote
        return ["RUN mkdir -p " + directory + " && "
                + " && ".join(f"ln -s {q(dest)} {q(f'{directory}/{name}')}" for name, dest in self.skill_links)]


def adapter_context(comp: Composition, cfg: Config | None = None) -> AdapterContext:
    """The adapter's context for `comp`, with the session's `harness_config`
    when `cfg` is given; `with_plan` adds the late fields (`SessionPlan.adapter`
    is this, built once)."""
    from .extensions import active_items, render_value

    def section(a, data: Any, ctx: dict) -> HarnessSection:
        if isinstance(data, dict):  # inactive items go before rendering: theirs may not render
            data = {k: active_items(v, ctx) if isinstance(v, list) else v for k, v in data.items()}
        return HarnessSection(a.name, a.manifest.path, render_value(data, ctx, f"extension {a.name!r} harness"))

    profile = get_profile(comp.harness)
    return AdapterContext(
        session=comp.session, config_home=profile.config_home_path, transcript_subdir=profile.transcript_subdir,
        sessions_subdir=profile.sessions_subdir, mcp=tuple(comp.mcp), skills=tuple(d for _, _, d in comp.skills),
        skill_links=tuple(comp.skill_links()), sections=tuple(section(*item) for item in comp.harness_items),
        **_cfg_fields(profile, cfg),
    )


def _cfg_fields(profile: HarnessProfile, cfg: Config | None) -> dict[str, Any]:
    """The context's fields that come from the session's config."""
    return {"harness_config": MappingProxyType({k: v for k, v in (cfg.harness_config if cfg else {}).items()
                                                if k not in profile.opt_ins}),
            "enforcer": cfg.enforcer if cfg else ""}


def with_plan(actx: AdapterContext, plan: SessionPlan, cfg: Config | None = None) -> AdapterContext:
    """`actx` with the late fields of `plan`, and `cfg`'s when given (cheap:
    nothing is rendered again)."""
    from .enforcers.base import TOOLS_FILE, write_roots

    return replace(
        actx, **(_cfg_fields(plan.profile, cfg) if cfg is not None else {}),
        model=plan.model, wrapped="tool-wrapper.argv" in plan.policies,
        tool_policy=json.loads(plan.policies[TOOLS_FILE]) if TOOLS_FILE in plan.policies else None,
        write_roots=tuple(write_roots(plan)), working_dir=plan.mount_plan.working_dir,
        harness_hosts=tuple(h for sc in plan.network.sidecars if sc.harness
                            for h in (scoped(plan.session, sc.role), *sc.aliases, *sc.impl_aliases)),
    )


def build_environment_context(plan: SessionPlan) -> str:
    """Generate the "How your environment works" block.

    Describes the mounts and their modes, that shell commands have no network,
    the RUN ON HOST relay rule, then each extension's brief in extension order —
    rendered from the plan (the mounts the runtime binds), so what the agent
    is told matches reality.
    """
    mount_plan = plan.mount_plan
    lines = ["# How your environment works", ""]
    lines.append(
        "You run inside a defence-in-depth sandbox: a container (namespace, mounts, "
        "network) with a kernel capability sandbox "
        f"({plan.enforcer}) wrapping the agent and **every shell command** it runs."
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
    if plan.profile.brief:
        lines += ["", plan.profile.brief]
    briefs = plan.composition.rendered_briefs()
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


def render_home(cfg: Config, plan: SessionPlan, home_dir: Path) -> list[Path]:
    """Write the harness config tree under `home_dir`; return files written.

    The adapter and the context file see the plan's mounts, working dir and
    `model` (the inference slot's descriptor, launch-resolved by `glove up`).
    """
    home_dir.mkdir(parents=True, exist_ok=True)
    # the harness's native config (its adapter: harnesses/<name>/adapter.py)
    written: list[Path] = adapter_call(plan.profile, "render_home", with_plan(plan.adapter, plan, cfg),
                                       home_dir, default=[])
    written.append(_write_context_file(cfg, plan, home_dir))
    return written


def rel_config_home(config_home: str) -> Path:
    """A harness config dir (`HarnessProfile.config_home_path`) relative to the
    host home (strips CONTAINER_HOME)."""
    return Path(config_home).relative_to(CONTAINER_HOME)


def _write_context_file(cfg: Config, plan: SessionPlan, home_dir: Path) -> Path:
    path = home_dir / Path(plan.profile.context_file).relative_to(CONTAINER_HOME)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = build_environment_context(plan)
    if cfg.brief:
        body += "\n---\n\n# Session brief\n\n" + cfg.brief.strip() + "\n"
    path.write_text(body)
    return path
