"""``SessionPlan`` — the runtime-agnostic description of one session (PLAN §3.1).

Everything the operator decides is resolved here into a single, runtime-neutral
plan (mounts, env, network, hardening, limits). Only a ``Runtime.render()``
knows how to turn it into a concrete project (compose yaml for docker/podman).
Built from a resolved ``Config`` plus the mount (A.4) and network (A.5) plans.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace

from .config import Config
from .hardening import Hardening, Limits
from .harness import HarnessProfile, effective_image, get_profile
from .mounts import Mount, MountPlan, compute_mounts
from .network import NetworkPlan, build_network_plan
from .runtimes.seccomp import default_profile_path, nested_userns_profile_path

FORWARDER_IMAGE = "glove/forwarder:0.2.0"


@dataclass
class SessionPlan:
    """A fully-resolved, runtime-agnostic session (PLAN §3.1)."""

    session: str  # session name; compose project = glove-<session>
    env_id: str
    profile: HarnessProfile
    image: str
    working_dir: str  # container path the harness starts in
    home_dir: str  # host path bind-mounted at /home/agent
    mount_plan: MountPlan
    environment: dict[str, str]
    network: NetworkPlan
    hardening: Hardening
    uid: int
    gid: int
    runtime: str = "docker"
    enforcer: str = "nono"
    forwarder_image: str = FORWARDER_IMAGE
    tools: dict = field(default_factory=dict)
    # Ring-1 enforcer artifacts (populated by build_session_plan). `command` is
    # the wrapped harness entry; `policies` is filename→contents rendered to the
    # session enforcer dir and bind-mounted read-only at policies_container_dir.
    command: list[str] = field(default_factory=list)
    policies: dict[str, str] = field(default_factory=dict)
    enforcer_env: dict[str, str] = field(default_factory=dict)
    policies_host_dir: str | None = None
    policies_container_dir: str = "/etc/glove/enforcer"

    @property
    def project(self) -> str:
        return f"glove-{self.session}"

    @property
    def harness_command(self) -> list[str]:
        return self.command or list(self.profile.entry)

    @property
    def harness_service(self) -> str:
        return f"glove-{self.session}-harness"

    @property
    def mounts(self) -> list[Mount]:
        return self.mount_plan.mounts

    @property
    def allow_root(self) -> bool:
        return self.hardening.allow_root


def _resolve_env(cfg: Config, profile: HarnessProfile) -> dict[str, str]:
    """Merge profile defaults with config env, dropping null (== unset)."""
    merged: dict[str, str] = dict(profile.default_env)
    for k, v in cfg.env.items():
        if v is None:
            merged.pop(k, None)
            continue
        merged[k] = str(v)
    return merged


def _service_env(cfg: Config, session: str, environment: dict[str, str]) -> None:
    """Inject the service-endpoint env vars the harness extensions read.

    Mirrors v1's compose logic; imported lazily to avoid an import cycle with
    harnessconfig (which imports config/harness).
    """
    from .harnessconfig import LLM_API_KEY_ENV, service_base

    search = service_base(cfg, session, "search")
    if search:
        environment.setdefault("SEARXNG_URL", search)
    browser = service_base(cfg, session, "browser")
    if browser:
        environment.setdefault("BROWSER_MCP_URL", f"{browser}/mcp")
    # NOTE: in Phase 2 the LLM key moves into nono's proxy (credential
    # injection). Until then it stays in the harness env, as in v1.
    if cfg.llm_api_key:
        environment[LLM_API_KEY_ENV] = str(cfg.llm_api_key)


def _seccomp_for(cfg: Config) -> tuple[str, bool]:
    """(seccomp profile path, systempaths_unconfined) for the selected enforcer."""
    if cfg.enforcer == "srt":
        strong = str(cfg.enforcer_options.get("srt", {}).get("nested", "weak")) == "strong"
        return nested_userns_profile_path(), strong
    # nono (default) and none run under the vendored Docker default profile.
    return default_profile_path(), False


def build_session_plan(
    cfg: Config,
    *,
    env_id: str,
    home_dir: str,
    cwd: str | None = None,
    uid: int | None = None,
    gid: int | None = None,
    forwarder_image: str = FORWARDER_IMAGE,
) -> SessionPlan:
    """Resolve a ``Config`` into a runtime-agnostic ``SessionPlan``."""
    session = cfg.resolved_name()
    profile = get_profile(cfg.harness)
    uid = uid if uid is not None else os.getuid()
    gid = gid if gid is not None else os.getgid()

    mount_plan = compute_mounts(
        cfg.workdir,
        [(a.path, a.mode) for a in cfg.add_dirs],
        cwd=cwd,
        allow_sensitive=cfg.allow_sensitive,
    )
    network = build_network_plan(cfg, session)

    environment = _resolve_env(cfg, profile)
    _service_env(cfg, session, environment)

    seccomp_profile, systempaths_unconfined = _seccomp_for(cfg)
    limits = cfg.limits if isinstance(cfg.limits, Limits) else Limits(**dict(cfg.limits or {}))

    from .enforcers import get_enforcer

    enforcer = get_enforcer(cfg.enforcer)

    hardening = Hardening(
        user=None if cfg.allow_root else f"{uid}:{gid}",
        seccomp_profile=seccomp_profile,
        systempaths_unconfined=systempaths_unconfined,
        limits=limits,
        allow_root=cfg.allow_root,
    )

    plan = SessionPlan(
        session=session,
        env_id=env_id,
        profile=profile,
        image=effective_image(profile, cfg.apt_packages, cfg.pip_packages),
        working_dir=mount_plan.working_dir,
        home_dir=home_dir,
        mount_plan=mount_plan,
        environment=environment,
        network=network,
        hardening=hardening,
        uid=uid,
        gid=gid,
        runtime=cfg.runtime,
        enforcer=cfg.enforcer,
        forwarder_image=forwarder_image,
        tools=dict(cfg.tools or {}),
    )

    # Ring-1: render policies, wrap the harness entry, collect enforcer env/caps.
    plan.policies = enforcer.render_policies(plan)
    plan.command = enforcer.wrap_harness(plan, list(profile.entry))
    plan.enforcer_env = enforcer.compose_env(plan)
    extra_caps = tuple(enforcer.cap_add(plan))
    if extra_caps:
        plan.hardening = replace(hardening, cap_add=extra_caps)
    return plan
