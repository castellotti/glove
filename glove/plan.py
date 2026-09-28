"""``SessionPlan`` — the runtime-agnostic description of one session.

Everything the operator decides is resolved here into a single, runtime-neutral
plan (mounts, env, network, hardening, limits). Only a ``Runtime.render()``
knows how to turn it into a concrete project (compose yaml for docker/podman).
Built from a resolved ``Config`` plus the mount and network plans.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

from .config import Config
from .extensions import Composition, compose
from .hardening import Hardening, Limits
from .harness import HarnessProfile, effective_image, get_profile
from .mounts import Mount, MountPlan, Protect, compute_mounts, protected_paths
from .network import NetworkPlan, build_network_plan
from .observe import ObserveSettings, netgate_image
from .runtimes.seccomp import default_profile_path, nested_userns_profile_path

if TYPE_CHECKING:
    from .harnessconfig import ModelDescriptor

FORWARDER_IMAGE = "glove/forwarder:0.2.0"


@dataclass
class SessionPlan:
    """A fully-resolved, runtime-agnostic session."""

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
    # Harness env vars the compose file declares *without a value*: compose takes
    # them from the environment of the `compose` process, which session.launch
    # fills from secret_env(cfg). So a secret is never written to disk by glove.
    passthrough_env: list[str] = field(default_factory=list)
    policies_host_dir: str | None = None
    policies_container_dir: str = "/etc/glove/enforcer"
    # Empty files/dirs bound read-only over missing protected paths (set by the
    # CLI once materialised; placeholders are skipped while it is None).
    placeholder_host_dir: str | None = None
    # Network observability (glove/observe.py). `observe` is None unless enabled;
    # `net_host_dir` is the session's net/ (set by the CLI once materialised) —
    # bind-mounted into the netgate collector only, never into the harness.
    observe: ObserveSettings | None = None
    netgate_image: str | None = None
    net_host_dir: str | None = None
    control_host_dir: str | None = None  # ~/.glove/control/<env>/<session>, ro into the gate
    # Extensions (glove/extensions.py): the selected set with every rendered
    # contribution, and the inference slot's model descriptor.
    composition: Composition | None = None
    model: ModelDescriptor | None = None
    derived_dockerfile: str | None = None  # FROM base + extension layers (None: base only)

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
    def protect(self) -> tuple[Protect, ...]:
        return self.mount_plan.protect

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


def secret_env_names(plan: SessionPlan) -> list[str]:
    """The harness's secret env var names (``SessionPlan.passthrough_env``).
    Planning needs only the names, so it never resolves a secret reference."""
    from .harnessconfig import LLM_API_KEY_ENV

    return [LLM_API_KEY_ENV] if plan.model is not None and plan.model.api_key_env else []


def secret_env(plan: SessionPlan) -> dict[str, str]:
    """Secret env for `compose up`/`run` only: the harness's LLM key (from the
    inference provider's secret setting) and every extension compose secret. A
    `keychain:`/`env:` reference is resolved here, in memory, so no file holds a
    secret."""
    from .config import resolve_secret
    from .extensions import resolve_secrets

    env: dict[str, str] = {}
    comp = plan.composition
    if comp is None:
        return env
    inference = comp.slots.get("inference")
    setting = inference.exports.get("api_key_secret") if inference else None
    if setting:
        from .harnessconfig import LLM_API_KEY_ENV

        env[LLM_API_KEY_ENV] = resolve_secret(inference.settings[setting])
    env.update(resolve_secrets(comp))
    return env


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
    resume: bool = False,
    session_id: str | None = None,
    state_dir: str | None = None,
) -> SessionPlan:
    """Resolve a ``Config`` into a runtime-agnostic ``SessionPlan``.

    ``resume``/``session_id`` are transient run options: they append the
    harness's own resume flag to the entry (inside the ring-1 wrapper) and are
    deliberately *not* stored on ``Config`` — they must never persist into
    ``glove.effective.yaml`` or the env file. ``session_id`` implies resume;
    ``resume`` with no id ⇒ continue the most recent session.

    ``state_dir`` holds per-extension state (``<state_dir>/<ext>/``); it defaults
    to ``ext/`` beside the harness home."""
    session = cfg.resolved_name()
    profile = get_profile(cfg.harness)
    uid = uid if uid is not None else os.getuid()
    gid = gid if gid is not None else os.getgid()

    # Compose the selected extensions first: their endpoints, env, host services
    # and image layers feed the network plan, env and image below.
    comp = compose(
        cfg.extensions, harness=cfg.harness, session=session,
        state_root=Path(state_dir) if state_dir else Path(home_dir).parent / "ext",
    )
    own = {h.name for h in comp.host_services}
    cfg.host_services = [*(h for h in cfg.host_services if h.name not in own), *comp.host_services]

    mount_plan = compute_mounts(
        cfg.workdir,
        [(a.path, a.mode) for a in cfg.add_dirs],
        cwd=cwd,
        allow_sensitive=cfg.allow_sensitive,
    )
    mount_plan = replace(
        mount_plan, protect=protected_paths(mount_plan.mounts, protect_ide_files=cfg.protect_ide_files)
    )
    network = build_network_plan(cfg, session, comp)

    environment = _resolve_env(cfg, profile)
    for k, v in comp.harness_env.items():
        environment.setdefault(k, v)  # an explicit `env:` entry wins

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

    # Extension layers get their own content-addressed derived image. srt needs
    # bwrap/socat/srt baked in; its image gets an `-srt` suffix.
    from .harnessconfig import ModelDescriptor
    from .image import content_hash, render_dockerfile

    base = effective_image(profile, cfg.apt_packages, cfg.pip_packages)
    base = f"{base}-srt" if cfg.enforcer == "srt" else base
    derived_df = None
    derived = None
    if comp.image_layers or comp.pi_extensions:
        derived_df, staged = render_dockerfile(base, profile, comp)
        derived = content_hash(derived_df, staged)
    image = effective_image(profile, cfg.apt_packages, cfg.pip_packages, derived)
    if cfg.enforcer == "srt":
        image = f"{image}-srt"

    plan = SessionPlan(
        session=session,
        env_id=env_id,
        profile=profile,
        image=image,
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
        composition=comp,
        model=ModelDescriptor.from_exports(comp.slot_exports("inference")) if "inference" in comp.slots else None,
        derived_dockerfile=derived_df,
    )
    plan.passthrough_env = secret_env_names(plan)
    plan.observe = network.observe
    if network.gated:
        plan.netgate_image = netgate_image()

    # Ring-1: render policies, wrap the (extension-augmented) harness entry,
    # collect enforcer env/caps. Pi loads capability code as `-e <path>`.
    entry = list(profile.entry)
    if cfg.harness == "pi":
        for ext, src in comp.pi_extensions:
            entry += ["-e", comp.pi_extension_dest(ext, src)]
    # Resume flag goes on `entry` (post-`--`, inside the sandbox), never on the
    # wrapper prefix. session_id=None ⇒ continue-last.
    if resume or session_id is not None:
        entry += profile.resume_args(session_id)
    plan.policies = enforcer.render_policies(plan)
    plan.command = enforcer.wrap_harness(plan, entry)
    plan.enforcer_env = enforcer.compose_env(plan)

    # Fold enforcer-requested caps/tmpfs into the hardening spec in one replace.
    updates: dict = {}
    extra_caps = tuple(enforcer.cap_add(plan))
    if extra_caps:
        updates["cap_add"] = extra_caps
    extra_tmpfs = tuple(t for t in enforcer.extra_tmpfs(plan) if t not in hardening.tmpfs)
    if extra_tmpfs:
        updates["tmpfs"] = (*hardening.tmpfs, *extra_tmpfs)
    if updates:
        plan.hardening = replace(hardening, **updates)
    return plan
