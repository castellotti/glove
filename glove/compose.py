"""Render the per-session compose project (DESIGN.md A.7 steps 1-2).

Ties together the resolved config, the mount plan (A.4), the network plan
(A.5), and the harness profile (A.3) into a single docker-compose document via
the Jinja template.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .config import Config
from .harness import HarnessProfile, effective_image, get_profile
from .mounts import MountPlan, compute_mounts
from .network import NetworkPlan, build_network_plan

TEMPLATES_DIR = Path(__file__).parent / "templates"
FORWARDER_IMAGE = "glove/forwarder:0.1.0"


@dataclass
class RenderResult:
    session: str
    compose_yaml: str
    mount_plan: MountPlan
    network_plan: NetworkPlan
    profile: HarnessProfile
    environment: dict[str, str]


def _jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def _resolve_env(cfg: Config, profile: HarnessProfile) -> dict[str, str]:
    """Merge profile defaults with config env, dropping null (== unset)."""
    merged: dict[str, str] = dict(profile.default_env)
    for k, v in cfg.env.items():
        if v is None:
            merged.pop(k, None)  # explicit unset
            continue
        merged[k] = str(v)
    return merged


def render_compose(
    cfg: Config,
    *,
    home_dir: str,
    cwd: str | None = None,
    uid: int | None = None,
    gid: int | None = None,
) -> RenderResult:
    session = cfg.resolved_name()
    profile = get_profile(cfg.harness)

    mount_plan = compute_mounts(
        cfg.workdir,
        [(a.path, a.mode) for a in cfg.add_dirs],
        cwd=cwd,
        allow_sensitive=cfg.allow_sensitive,
    )
    network_plan = build_network_plan(cfg, session)
    environment = _resolve_env(cfg, profile)
    # Expose the private search endpoint to the harness (Pi's web_search
    # extension reads $SEARXNG_URL; harmless for others).
    from .harnessconfig import service_base

    search = service_base(cfg, session, "search")
    if search:
        environment.setdefault("SEARXNG_URL", search)
    # Pi's browser bridge extension reads $BROWSER_MCP_URL (the Playwright MCP
    # brought in by the `browser` forwarder sidecar). Harmless for other harnesses.
    browser = service_base(cfg, session, "browser")
    if browser:
        environment.setdefault("BROWSER_MCP_URL", f"{browser}/mcp")
    # LLM API key → container env, referenced by the harness provider's
    # api_key_env_var (keeps the secret out of the generated harness config).
    if cfg.llm_api_key:
        from .harnessconfig import LLM_API_KEY_ENV

        environment[LLM_API_KEY_ENV] = str(cfg.llm_api_key)

    ctx: dict[str, Any] = {
        "session": session,
        "harness": profile,
        "harness_image": effective_image(
            profile, cfg.apt_packages, cfg.pip_packages
        ),
        "home_dir": home_dir,
        "working_dir": mount_plan.working_dir,
        "mounts": mount_plan.mounts,
        "environment": environment,
        "sidecars": network_plan.sidecars,
        "external_networks": network_plan.external_networks,
        "harness_extra_networks": network_plan.harness_extra_networks,
        "harness_host_gateway": network_plan.harness_host_gateway,
        "egress_network": network_plan.egress_network,
        "allow_root": cfg.allow_root,
        "forwarder_image": FORWARDER_IMAGE,
        "uid": uid if uid is not None else os.getuid(),
        "gid": gid if gid is not None else os.getgid(),
    }

    template = _jinja_env().get_template("compose.yml.j2")
    compose_yaml = template.render(**ctx)

    return RenderResult(
        session=session,
        compose_yaml=compose_yaml,
        mount_plan=mount_plan,
        network_plan=network_plan,
        profile=profile,
        environment=environment,
    )
