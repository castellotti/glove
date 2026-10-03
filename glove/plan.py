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

from .config import Config, ConfigError
from .enforcers.base import srt_suffix, uses_srt
from .exports import export_dirs, transcripts_wanted
from .extensions import Composition, compose
from .hardening import Hardening, Limits
from .harness import HarnessProfile, adapter_call, effective_image, get_profile
from .mounts import Mount, MountPlan, Protect, compute_mounts, protected_paths
from .naming import project_name, scoped
from .network import NetworkPlan, build_network_plan
from .runtimes.seccomp import default_profile_path, nested_userns_profile_path

if TYPE_CHECKING:
    from .harnessconfig import ModelDescriptor
    from .toolchains import Toolchain

FORWARDER_IMAGE = "glove/forwarder:0.2.0"
# `corporate_ca`'s read-only bind: under /etc/glove, which every enforcer
# already lets the harness and its commands read (nono: GLOVE_READ; srt: the
# whole rootfs is readable), so trusting it needs no policy change.
CORPORATE_CA_PATH = "/etc/glove/corporate-ca.pem"


@dataclass
class SessionPlan:
    """A fully-resolved, runtime-agnostic session."""

    session: str  # session id; compose project = glove-<session>
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
    # Extensions (glove/extensions.py): the selected set with every rendered
    # contribution.
    composition: Composition
    runtime: str = "docker"
    enforcer: str = "nono"
    enforcer_options: dict = field(default_factory=dict)
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
    # The adapter's read-only system config (`system_files(plan)`): container
    # dir → {filename: contents}, e.g. Claude Code's /etc/claude-code managed
    # settings. Rendered under .glove/harness/ like the policies; the CLI fills
    # system_mounts with (host dir, container dir) once written.
    system_files: dict[str, dict[str, str]] = field(default_factory=dict)
    system_mounts: list[tuple[str, str]] = field(default_factory=list)
    # Empty files/dirs bound read-only over missing protected paths (set by the
    # CLI once materialised; placeholders are skipped while it is None).
    placeholder_host_dir: str | None = None
    # observe's transcripts export (glove/exports.py): the host dir bound over
    # the harness's transcript directory (None: not exported).
    transcripts_host_dir: str | None = None
    transcripts_container_dir: str | None = None
    # The inference slot's model descriptor.
    model: ModelDescriptor | None = None
    derived_dockerfile: str | None = None  # FROM base + extension layers (None: base only)
    derived_staged: list[tuple[str, Path]] = field(default_factory=list)  # its build-context sources
    # `corporate_ca`: the validated host PEM, bound read-only at
    # CORPORATE_CA_PATH (None: unset, nothing rendered).
    corporate_ca_host_path: str | None = None
    # `toolchains`: the validated blocks baked into the derived image ([]: unset).
    toolchains: list[Toolchain] = field(default_factory=list)

    @property
    def project(self) -> str:
        return project_name(self.session)

    @property
    def harness_command(self) -> list[str]:
        return self.command or list(self.profile.entry)

    @property
    def harness_service(self) -> str:
        return scoped(self.session, "harness")

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
    return [plan.model.api_key_env] if plan.model is not None and plan.model.api_key_env else []


def write_system_files(plan: SessionPlan, root: Path) -> None:
    """Write `plan.system_files` under `root` (one dir per container dir) and
    record the read-only binds. Only a dir of its own under /etc qualifies: never
    /etc itself, glove's enforcer dir, or a path the agent writes."""
    import re
    import shutil

    if root.exists():
        shutil.rmtree(root)
    plan.system_mounts = []
    for target, files in sorted(plan.system_files.items()):
        if not re.fullmatch(r"/etc/[a-z0-9][a-z0-9._-]*", target) or target == plan.policies_container_dir:
            raise ConfigError(f"harness {plan.profile.name!r}: system files must go in a dir of their own "
                              f"under /etc, not {target!r}")
        d = root / target.removeprefix("/etc/")
        d.mkdir(parents=True)
        for fname, content in files.items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", fname):
                raise ConfigError(f"harness {plan.profile.name!r}: bad system file name {fname!r}")
            (d / fname).write_text(content)
        plan.system_mounts.append((str(d), target))


def secret_env(plan: SessionPlan) -> dict[str, str]:
    """Secret env for `compose up`/`run` only: the harness's LLM key (from the
    inference provider's secret setting), every extension compose secret, and
    what extensions' `launch_env` hooks return (e.g. a freshly registered VPN
    key). A `keychain:`/`env:` reference is resolved here, in memory, so no file
    holds a secret."""
    from .config import resolve_secret
    from .extensions import launch_env, resolve_secrets

    env: dict[str, str] = {}
    comp = plan.composition
    inference = comp.slots.get("inference")
    setting = inference.exports.get("api_key_secret") if inference else None
    if setting and plan.model is not None and plan.model.api_key_env:
        env[plan.model.api_key_env] = resolve_secret(inference.settings[setting])
    hooked = launch_env(comp)
    env.update(hooked)
    env.update(resolve_secrets(comp, provided=hooked))
    return env


def secret_refs(plan: SessionPlan) -> list[tuple[str, str]]:
    """(label, reference) of every secret the session will resolve at launch,
    for `glove check` (which verifies they exist without reading them)."""
    comp = plan.composition
    out: list[tuple[str, str]] = []
    inference = comp.slots.get("inference")
    setting = inference.exports.get("api_key_secret") if inference else None
    if setting and inference.settings.get(setting):
        out.append((f"{inference.name}.{setting}", str(inference.settings[setting])))
    # every secret-type setting that is set (compose secrets, and ones only a
    # launch hook reads, e.g. vpn.register_user)
    for a in comp.active:
        for name, spec in a.manifest.settings_schema.items():
            value = a.settings.get(name)
            label = f"{a.name}.{name}"
            if spec.get("type") == "secret" and value not in (None, "", "generate") and \
                    all(lbl != label for lbl, _ in out):
                out.append((label, str(value)))
    return out


def _seccomp_for(cfg: Config) -> tuple[str, bool]:
    """(seccomp profile path, systempaths_unconfined) for the selected enforcer."""
    if uses_srt(cfg.enforcer):
        strong = str(cfg.enforcer_options.get("srt", {}).get("nested", "weak")) == "strong"
        return nested_userns_profile_path(), strong
    # nono (default) and none run under the vendored Docker default profile.
    return default_profile_path(), False


def _extension_mounts(comp: Composition, mounts: list[Mount]) -> list[Mount]:
    """Extensions' read-only harness mounts (`mounts:` in a manifest), under the
    same rule as the session's own: never a private path."""
    from .extensions import ExtensionError
    from .sessiondir import exposes_private

    out = []
    taken = {m.container_path for m in mounts}
    for ext, host, target in comp.harness_mounts:
        exposed = exposes_private(comp.session_dir, Path(host))
        if exposed:
            raise ExtensionError(f"extension {ext!r}: mount {host} would expose {exposed[1]} ({exposed[0]}) "
                                 "to the harness; name a directory that does not contain it")
        if target in taken:
            raise ExtensionError(f"extension {ext!r}: mount point {target} clashes with another mount")
        taken.add(target)
        out.append(Mount(host_path=host, container_path=target, mode="ro"))
    return out


def build_session_plan(
    cfg: Config,
    *,
    home_dir: str,
    cwd: str | None = None,
    uid: int | None = None,
    gid: int | None = None,
    resume: bool = False,
    session_id: str | None = None,
    state_dir: str | None = None,
    session_dir: str | None = None,
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
    sd_path = Path(session_dir) if session_dir else None
    comp = compose(
        cfg.extensions, harness=cfg.harness, session=session,
        state_root=Path(state_dir) if state_dir else Path(home_dir).parent / "ext",
        session_dir=sd_path, subnet=cfg.subnet,
        export_dirs=export_dirs(session),
        work_dir=Path(os.path.realpath(os.path.expanduser(cfg.workdir))) if cfg.workdir else None,
    )
    own = {h.name for h in comp.host_services}
    cfg.host_services = [*(h for h in cfg.host_services if h.name not in own), *comp.host_services]

    mount_plan = compute_mounts(
        cfg.workdir,
        [(a.path, a.mode) for a in cfg.add_dirs],
        cwd=cwd,
        allow_sensitive=cfg.allow_sensitive,
    )
    mount_plan = replace(mount_plan, mounts=[*mount_plan.mounts, *_extension_mounts(comp, mount_plan.mounts)])
    mount_plan = replace(
        mount_plan, protect=protected_paths(mount_plan.mounts, protect_ide_files=cfg.protect_ide_files)
    )
    network = build_network_plan(cfg, session, comp)

    environment = _resolve_env(cfg, profile)
    for k, v in comp.harness_env.items():
        environment.setdefault(k, v)  # an explicit `env:` entry wins
    toolchains: list[Toolchain] = []
    if cfg.toolchains:
        from . import toolchains as tcs

        # checked at plan time, so `glove check` fails early (every mount
        # target is /work, /mnt/… or the home: none can shadow tcs.ROOT)
        toolchains = tcs.resolve(cfg.toolchains, sd_path)
        for k, v in tcs.harness_env(toolchains).items():
            if k in comp.harness_env:
                raise ConfigError(f"toolchains: env {k!r} is also set by an extension")
            environment.setdefault(k, v)
    corporate_ca = None
    if cfg.corporate_ca:
        from .cafile import resolve_ca_file

        # checked at plan time, so `glove check` fails early
        corporate_ca = str(resolve_ca_file("corporate_ca", cfg.corporate_ca, sd_path))
        # Node *adds* these to its built-in roots: trust is widened, never
        # replaced, and verification is never turned off. Non-Node tools
        # (curl, python) keep the image's store (README: corporate_ca).
        environment.setdefault("NODE_EXTRA_CA_CERTS", CORPORATE_CA_PATH)

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
    # bwrap/socat/srt baked in: its image is the `-srt` overlay (enforcers/srt_image).
    from .harnessconfig import harness_model
    from .image import content_hash, render_dockerfile

    suffix = srt_suffix() if uses_srt(cfg.enforcer) else ""
    base = f"{effective_image(profile, cfg.apt_packages, cfg.pip_packages)}{suffix}"
    derived_df, staged = render_dockerfile(base, profile, comp, toolchains)
    derived = content_hash(derived_df, staged) if derived_df is not None else None
    image = f"{effective_image(profile, cfg.apt_packages, cfg.pip_packages, derived)}{suffix}"

    plan = SessionPlan(
        session=session,
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
        enforcer_options=dict(cfg.enforcer_options or {}),
        tools=dict(cfg.tools or {}),
        composition=comp,
        model=harness_model(profile, comp.slot_exports("inference")) if "inference" in comp.slots else None,
        derived_dockerfile=derived_df,
        derived_staged=staged,
        corporate_ca_host_path=corporate_ca,
        toolchains=toolchains,
    )
    plan.passthrough_env = secret_env_names(plan)
    if transcripts_wanted(comp) and profile.transcript_subdir:
        plan.transcripts_host_dir = str(comp.export_dirs["observe"] / "transcripts")
        plan.transcripts_container_dir = f"{profile.config_home_path}/{profile.transcript_subdir}"

    # Ring-1: render policies, wrap the (extension-augmented) harness entry,
    # collect enforcer env/caps. The adapter may extend the entry (Pi loads
    # capability code as `-e <path>`).
    entry = [*profile.entry, *adapter_call(profile, "entry_args", comp, default=[])]
    # Resume flag goes on `entry` (post-`--`, inside the sandbox), never on the
    # wrapper prefix. session_id=None ⇒ continue-last.
    if resume or session_id is not None:
        entry += profile.resume_args(session_id)
    plan.policies = enforcer.render_policies(plan)
    wrapper = enforcer.tool_wrapper_argv(plan)
    if wrapper:
        # The same argv one per line, for a harness glue that has no JSON parser
        # (Claude Code's shell prefix is a bash script).
        plan.policies["tool-wrapper.argv"] = "".join(f"{a}\n" for a in wrapper)
    plan.system_files = adapter_call(profile, "system_files", cfg, plan, default={})
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
