"""``SessionPlan`` — the runtime-agnostic description of one session.

Everything the operator decides is resolved here into a single, runtime-neutral
plan (mounts, env, network, hardening, limits). Only a ``Runtime.render()``
knows how to turn it into a concrete project (compose yaml for docker/podman).
Built from a resolved ``Config`` plus the mount and network plans.
"""

from __future__ import annotations

import contextlib
import json
import os
import posixpath
import re
import shutil
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

from .cafile import CA_BUNDLE_ENV, CA_BUNDLE_PATH, CORPORATE_CA_PATH, resolve_ca_file
from .config import GIT_CONFIG_ENV, Config, ConfigError, git_config_pairs
from .enforcers.base import TOOLS_FILE, WRITE_ROOTS_FILE, argv_lines, srt_suffix, uses_srt, write_roots
from .exports import export_dirs, transcripts_wanted
from .extensions import Composition, compose
from .hardening import Hardening, Limits
from .harness import HarnessProfile, adapter_call, effective_image, get_profile, tool_inventory
from .harnessconfig import CONTAINER_HOME, INJECTED_KEY, AdapterContext, adapter_context, with_plan
from .mounts import (
    Mount,
    MountPlan,
    Protect,
    check_path,
    compute_mounts,
    overlaps,
    protected_home,
    protected_paths,
)
from .naming import project_name, scoped
from .network import NetworkPlan, build_network_plan
from .runtimes.seccomp import default_profile_path, nested_userns_profile_path

if TYPE_CHECKING:
    from .harnessconfig import ModelDescriptor

FORWARDER_DIR = Path(__file__).parent / "forwarder"


def forwarder_image() -> str:
    """The forwarder's tag, content-addressed like every glove-built image."""
    from .image import content_hash

    return f"glove/forwarder:0.2.0-{content_hash('', [('forwarder', FORWARDER_DIR)])}"


@dataclass
class SessionPlan:
    """A fully-resolved, runtime-agnostic session."""

    session: str  # session id; compose project = glove-<session>
    profile: HarnessProfile
    image: str
    working_dir: str  # container path the harness starts in
    home_dir: str  # host path bind-mounted at CONTAINER_HOME (`home_mount`)
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
    forwarder_image: str = field(default_factory=forwarder_image)
    tools: dict = field(default_factory=dict)
    # Ring-1 enforcer artifacts (populated by build_session_plan). `command` is
    # the wrapped harness entry; `policies` is filename→contents rendered to the
    # session enforcer dir and bind-mounted read-only at policies_container_dir.
    command: list[str] = field(default_factory=list)
    policies: dict[str, str] = field(default_factory=dict)
    enforcer_env: dict[str, str] = field(default_factory=dict)
    policies_host_dir: str | None = None
    policies_container_dir: str = "/etc/glove/enforcer"
    # The adapter's read-only system config (`system_files(plan)`): container
    # dir → {filename: contents}, e.g. Claude Code's /etc/claude-code managed
    # settings. Rendered under .glove/harness/ like the policies; the CLI fills
    # system_mounts with (host dir, container dir) once written.
    system_files: dict[str, dict[str, str]] = field(default_factory=dict)
    system_mounts: list[tuple[str, str]] = field(default_factory=list)
    # The adapter's context without the late fields (harnessconfig.adapter_context),
    # built once: every later adapter call adds the plan's fields to it.
    adapter: AdapterContext | None = field(default=None, repr=False, compare=False)
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
    # Container paths of the extra CAs the harness trusts (corporate_ca's, a
    # channel's `trust`): its NODE_EXTRA_CA_CERTS, and the launch probe's trust.
    trusted_cas: list[str] = field(default_factory=list)

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


def home_mount(home_dir: str) -> Mount:
    """The harness home: the session's `.glove/home`, read-only at CONTAINER_HOME
    (the config home is re-bound read-write over it: `protected_home`)."""
    return Mount(host_path=os.path.realpath(home_dir), container_path=CONTAINER_HOME, mode="ro")


def _opt_ins(cfg: Config, profile: HarnessProfile) -> set[str]:
    """The harness's `protect:` opt-ins the session turns on
    (`harness_config.<key>: true`)."""
    on = set()
    for key in sorted(profile.opt_ins & set(cfg.harness_config)):
        if not isinstance(cfg.harness_config[key], bool):
            raise ConfigError(f"harness_config.{key} must be true or false")
        if cfg.harness_config[key]:
            on.add(key)
    return on


def _resolve_env(cfg: Config, profile: HarnessProfile) -> dict[str, str]:
    """Merge profile defaults with config env, dropping null (== unset)."""
    merged: dict[str, str] = dict(profile.default_env)
    for k, v in cfg.env.items():
        if v is None:
            merged.pop(k, None)
            continue
        merged[k] = str(v)
    return merged


def validate_system_files(plan: SessionPlan) -> None:
    """Only a dir of its own under /etc qualifies for `plan.system_files`: never
    /etc itself, glove's enforcer dir, or a path the agent writes."""
    for target, files in plan.system_files.items():
        if not re.fullmatch(r"/etc/[a-z0-9][a-z0-9._-]*", target) or target == plan.policies_container_dir:
            raise ConfigError(f"harness {plan.profile.name!r}: system files must go in a dir of their own "
                              f"under /etc, not {target!r}")
        bad = [f for f in files if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", f)]
        if bad:
            raise ConfigError(f"harness {plan.profile.name!r}: bad system file name {bad[0]!r}")


def write_in_place(d: Path, files: dict[str, str]) -> None:
    """Make `d` hold exactly `files` (mode 0644). A running session binds such
    dirs read-only (policies, system files), so `d` is updated in place, never
    deleted and recreated: a changed file is replaced atomically, an unchanged
    one is left alone, and stale entries are removed."""
    d.mkdir(parents=True, exist_ok=True)
    for stale in set(d.iterdir()) - {d / f for f in files}:
        _remove(stale)
    for fname, content in files.items():
        dest = d / fname
        if dest.is_file() and not dest.is_symlink() and dest.read_text() == content:
            continue
        fd, tmp = tempfile.mkstemp(dir=d.parent, prefix=".tmp-")  # beside, not inside, the bound dir
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, dest)


def write_system_files(plan: SessionPlan, root: Path) -> None:
    """Write `plan.system_files` under `root` (one dir per container dir) and
    record the read-only binds."""
    validate_system_files(plan)
    plan.system_mounts = []
    dirs: set[Path] = set()
    for target, files in sorted(plan.system_files.items()):
        d = root / target.removeprefix("/etc/")
        write_in_place(d, files)
        dirs.add(d)
        plan.system_mounts.append((str(d), target))
    if root.is_dir():
        for stale in set(root.iterdir()) - dirs:  # a dir the harness no longer renders
            _remove(stale)


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def secret_env(plan: SessionPlan) -> dict[str, str]:
    """Secret env for `compose up`/`run` only: every extension compose secret
    (the LLM key or token goes to llm-auth this way, never the harness), and
    what extensions' `launch_env` hooks return (e.g. a freshly registered VPN
    key). A `keychain:`/`env:` reference is resolved here, in memory, so no file
    holds a secret."""
    from .extensions import launch_env, resolve_secrets

    comp = plan.composition
    hooked = launch_env(comp)
    return {**hooked, **resolve_secrets(comp, provided=hooked)}


def secret_refs(plan: SessionPlan) -> list[tuple[str, str]]:
    """(label, reference) of every secret the session will resolve at launch,
    for `glove check` (which verifies they exist without reading them)."""
    # every secret-type setting that is set (the LLM key, compose secrets, and
    # ones only a launch hook reads, e.g. vpn.register_user)
    # ones nested deeper (a list of hosts, a plugin's relay) come from the
    # extension's contribute hook (`secret_refs`: label → reference)
    out = []
    for a in plan.composition.active:
        out += [(f"{a.name}.{name}", str(value)) for name, spec in a.manifest.settings_schema.items()
                if spec.get("type") == "secret" and (value := a.settings.get(name)) not in (None, "", "generate")]
        out += [(f"{a.name}.{label}", str(ref)) for label, ref in (a.contributed.get("secret_refs") or {}).items()]
    return out


def _seccomp_for(cfg: Config) -> tuple[str, bool]:
    """(seccomp profile path, systempaths_unconfined) for the selected enforcer."""
    if uses_srt(cfg.enforcer):
        return nested_userns_profile_path(), cfg.enforcer_options["srt"]["nested"] == "strong"
    # nono (default) and none run under the vendored Docker default profile.
    return default_profile_path(), False


def _extension_mounts(comp: Composition, mounts: list[Mount]) -> list[Mount]:
    """Extensions' read-only harness mounts (`mounts:` in a manifest), under the
    same rule as the session's own: never a private path; and their `outputs:`
    (read-only) and `inputs:` (read-write) at /work/<name>."""
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
    for o in comp.outputs:
        # its mount point is in /work, which the agent writes: never through a link
        check_path(str(comp.work_dir), o.name, "dir")
        out.append(Mount(host_path=str(o.host), container_path=o.target, mode="rw" if o.input else "ro"))
    return out


def git_config_parameters(pairs: list[tuple[str, str]]) -> str:
    """`GIT_CONFIG_PARAMETERS`, git's command-line config (`-c`) in the env, so
    the harness and every command it runs read it. Later pairs win."""
    def q(s: str) -> str:
        return "'" + s.replace("'", "'\\''") + "'"
    return " ".join(f"{q(k)}={q(v)}" for k, v in pairs)


def _check_baked_sources(comp: Composition, mounts: list[Mount]) -> None:
    """A host tree a `contribute` hook bakes into the image (`copy_host`) is
    never one an agent can write (this session's rw mounts, `/work` included,
    or another registered session's `work/`: it would change what the next
    session bakes and runs), nor glove's state (a session's `.glove/`, its
    session file, glove's home)."""
    from .registry import RegistryError, glove_home, load_registry
    from .sessiondir import SESSION_FILE, STATE_DIR

    guarded = [(Path(m.host_path), "writable by an agent") for m in mounts if not m.read_only]
    guarded.append((glove_home(), "glove's home"))
    if comp.session_dir is not None:
        guarded += [(comp.session_dir / STATE_DIR, "glove state"), (comp.session_dir / SESSION_FILE, "glove state")]
    with contextlib.suppress(RegistryError):
        for e in load_registry():
            guarded += [(Path(e.dir) / "work", "writable by an agent"), (Path(e.dir) / STATE_DIR, "glove state")]
    for ext, layer in comp.image_layers:
        for src, _dst in layer.get("copy_host") or []:
            for g, what in guarded:
                if overlaps(Path(src), g):
                    raise ConfigError(f"extension {ext!r}: {src} is {what} (it overlaps {os.path.realpath(g)}); "
                                      "what is baked into the image must not be")


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
    # checked at plan time, so `glove check` fails early; sidecars may trust it too
    ca = resolve_ca_file("corporate_ca", cfg.corporate_ca, sd_path) if cfg.corporate_ca else None
    comp = compose(
        cfg.extensions, harness=cfg.harness, session=session,
        state_root=Path(state_dir) if state_dir else Path(home_dir).parent / "ext",
        session_dir=sd_path, subnet=cfg.subnet,
        export_dirs=export_dirs(session),
        work_dir=Path(os.path.realpath(os.path.expanduser(cfg.workdir))) if cfg.workdir else None,
        corporate_ca=ca, enforcer=cfg.enforcer, enforcer_options=cfg.enforcer_options,
    )
    own = {h.name for h in comp.host_services}
    cfg.host_services = [*(h for h in cfg.host_services if h.name not in own), *comp.host_services]

    mount_plan = compute_mounts(
        cfg.workdir,
        [(a.path, a.mode) for a in cfg.add_dirs],
        cwd=cwd,
        allow_sensitive=cfg.allow_sensitive,
    )
    _check_baked_sources(comp, mount_plan.mounts)
    session_roots = [m.container_path for m in mount_plan.mounts]  # /work and the add-dirs
    mount_plan = replace(mount_plan, mounts=[*mount_plan.mounts, *_extension_mounts(comp, mount_plan.mounts)])
    opted = _opt_ins(cfg, profile)
    files = [(posixpath.join(mount_plan.working_dir, e.path), e.source) for e in profile.protect
             if not e.home and (e.opt_in is None or e.opt_in in opted)]
    home = home_mount(home_dir)
    mount_plan = replace(mount_plan, protect=protected_paths(
        mount_plan.mounts, protect_ide_files=cfg.protect_ide_files, files=files,
    ) + protected_home(home, profile.config_home_path, [e.path for e in profile.protect if e.home]))
    network = build_network_plan(cfg, session, comp)

    # glove alone sets git's config env vars (GIT_CONFIG_PARAMETERS, below)
    for source, env in (("the harness profile", profile.default_env), ("the session's `env:`", cfg.env),
                        ("an extension's env", comp.harness_env)):
        owned = sorted(k for k in env if GIT_CONFIG_ENV.fullmatch(str(k)))
        if owned:
            raise ConfigError(f"{source} sets {owned[0]}: git config goes in the session's `git_config:` "
                              "(or an extension's `harness.git_config`)")
    environment = _resolve_env(cfg, profile)
    for k, v in comp.harness_env.items():
        environment.setdefault(k, v)  # an explicit `env:` entry wins
    # Through Docker Desktop's file sharing a `.git` the agent just created can
    # read as another uid, and git refuses it ("dubious ownership"). The
    # container has one user, so safe.directory's guard (another user's repo
    # configuring this user's git) has nothing to protect at the mount roots.
    # Exact paths only: bookworm's git (2.39) has no `dir/*` patterns, so a repo
    # nested deeper (a clone into /work/<repo>) needs an opt-in: an extension's
    # `harness.git_config` (github: '*') or the session's `git_config:`.
    environment["GIT_CONFIG_PARAMETERS"] = git_config_parameters([
        *(("safe.directory", r) for r in session_roots), *comp.git_config,
        *git_config_pairs(cfg.git_config, "git_config"),
    ])
    corporate_ca = str(comp.corporate_ca) if comp.corporate_ca else None
    trusted_cas = list(comp.trusted_cas)
    if corporate_ca:
        trusted_cas.append(CORPORATE_CA_PATH)
        for k in CA_BUNDLE_ENV:  # Python, curl, git, gh (Go): the baked bundle
            environment.setdefault(k, CA_BUNDLE_PATH)
    if len(trusted_cas) > 1:  # Node takes one extra bundle (TODO: one built at harness start)
        raise ConfigError(f"the harness would trust {len(trusted_cas)} extra CAs ({', '.join(trusted_cas)}; "
                          "e.g. corporate_ca and llm `auth: oauth`'s session CA): not supported together yet")
    if trusted_cas:
        # Node *adds* these to its built-in roots: trust is widened, never
        # replaced, and verification is never turned off. Other tools get
        # corporate_ca's baked bundle (cafile.CA_BUNDLE_ENV), a channel's CA only Node.
        environment.setdefault("NODE_EXTRA_CA_CERTS", trusted_cas[0])

    seccomp_profile, systempaths_unconfined = _seccomp_for(cfg)
    limits = cfg.limits if isinstance(cfg.limits, Limits) else Limits(**dict(cfg.limits or {}))

    from .enforcers import get_enforcer

    enforcer = get_enforcer(cfg.enforcer)
    if cfg.tools and enforcer.tool_sandbox != "nono":
        raise ConfigError(f"`tools:` sets nono's tool-profile command lists; enforcer {cfg.enforcer!r} runs "
                          "commands without nono, so it would be ignored — remove it")

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
    actx = adapter_context(comp, cfg)
    derived_df, staged = render_dockerfile(base, profile, comp, actx)
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
        enforcer_options=cfg.enforcer_options,
        tools=dict(cfg.tools),
        composition=comp,
        model=harness_model(profile, comp.slot_exports("inference")) if "inference" in comp.slots else None,
        derived_dockerfile=derived_df,
        derived_staged=staged,
        corporate_ca_host_path=corporate_ca,
        trusted_cas=trusted_cas,
        adapter=actx,
    )
    if plan.model is not None and plan.model.api_key_env:
        # The harness never holds a key: its variable gets a placeholder and the
        # provider adds the key on the way (`llm`'s llm-auth).
        if not plan.model.api_key_injected:
            raise ConfigError(f"inference provider {comp.slots['inference'].name!r} exports a key it does not "
                              "inject; glove passes no secret into the harness")
        plan.environment[plan.model.api_key_env] = INJECTED_KEY
    if transcripts_wanted(comp) and profile.transcript_subdir:
        plan.transcripts_host_dir = str(comp.export_dirs["observe"] / "transcripts")
        plan.transcripts_container_dir = f"{profile.config_home_path}/{profile.transcript_subdir}"

    # Ring-1: render policies, wrap the (extension-augmented) harness entry,
    # collect enforcer env/caps. The adapter may extend the entry (Pi loads
    # capability code as `-e <path>`).
    entry = [*profile.entry, *adapter_call(profile, "entry_args", actx, default=[])]
    # Resume flag goes on `entry` (post-`--`, inside the sandbox), never on the
    # wrapper prefix. session_id=None ⇒ continue-last.
    if resume or session_id is not None:
        entry += profile.resume_args(session_id)
    plan.policies = enforcer.render_policies(plan)
    plan.policies[WRITE_ROOTS_FILE] = json.dumps({"roots": write_roots(plan)}, indent=2) + "\n"
    plan.policies[TOOLS_FILE] = json.dumps(tool_inventory(profile, cfg.tool_allow, actx), indent=2) + "\n"
    wrapper = enforcer.tool_wrapper_argv(plan)
    if wrapper:
        plan.policies["tool-wrapper.argv"] = argv_lines(wrapper)
    plan.system_files = adapter_call(profile, "system_files", with_plan(actx, plan), default={})
    validate_system_files(plan)  # a bad adapter fails at `plan`, not at `up`
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
