"""Compatibility shim over the ring-0 render path (PLAN §3.1).

The actual rendering moved to ``glove.runtimes.docker.DockerRuntime.render``,
fed by a runtime-agnostic ``SessionPlan`` (``glove.plan``). This module keeps
the v1 ``render_compose`` / ``RenderResult`` surface so callers and tests that
predate the runtime split keep working; it simply builds a plan and asks the
docker runtime to render it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .harness import HarnessProfile
from .mounts import MountPlan
from .network import NetworkPlan
from .plan import FORWARDER_IMAGE, build_session_plan
from .runtimes.docker import TEMPLATES_DIR, DockerRuntime

__all__ = ["RenderResult", "render_compose", "FORWARDER_IMAGE", "TEMPLATES_DIR"]


@dataclass
class RenderResult:
    session: str
    compose_yaml: str
    mount_plan: MountPlan
    network_plan: NetworkPlan
    profile: HarnessProfile
    environment: dict[str, str]


def render_compose(
    cfg: Config,
    *,
    home_dir: str,
    cwd: str | None = None,
    uid: int | None = None,
    gid: int | None = None,
    env_id: str | None = None,
    overrides: frozenset[str] = frozenset(),
) -> RenderResult:
    plan = build_session_plan(
        cfg,
        env_id=env_id or cfg.resolved_name(),
        home_dir=home_dir,
        cwd=cwd,
        uid=uid,
        gid=gid,
    )
    rendered = DockerRuntime().render(plan, Path("."), overrides=overrides)
    return RenderResult(
        session=plan.session,
        compose_yaml=rendered.compose_yaml,
        mount_plan=plan.mount_plan,
        network_plan=plan.network,
        profile=plan.profile,
        environment=plan.environment,
    )
