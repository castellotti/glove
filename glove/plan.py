"""``SessionPlan`` — the runtime-agnostic description of one session.

Everything the operator decides is resolved here into a single, runtime-neutral
plan (mounts, env, network, hardening, limits). Only a ``Runtime.render()``
knows how to turn it into a concrete project (compose yaml for docker/podman).
Built from a resolved ``Config`` plus the mount and network plans.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace

from .config import Config, ConfigError
from .hardening import Hardening, Limits
from .harness import HarnessProfile, effective_image, get_profile
from .mounts import Mount, MountPlan, compute_mounts
from .network import NetworkPlan, build_network_plan
from .observe import ObserveSettings, netgate_image
from .runtimes.seccomp import default_profile_path, nested_userns_profile_path

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
    # Network observability (glove/observe.py). `observe` is None unless enabled;
    # `net_host_dir` is the session's net/ (set by the CLI once materialised) —
    # bind-mounted into the netgate collector only, never into the harness.
    observe: ObserveSettings | None = None
    netgate_image: str | None = None
    net_host_dir: str | None = None
    control_host_dir: str | None = None  # ~/.glove/control/<env>/<session>, ro into the gate

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
    from .harnessconfig import service_base

    # Single construction site for the browser MCP endpoint: derived from the
    # declared `browser` service, whether it came from a browser provider
    # (browsers.apply_browser) or was hand-wired in the config.
    # (SEARXNG_URL is injected by the `search` plugin; see _plugin_env.)
    browser = service_base(cfg, session, "browser")
    if browser:
        environment.setdefault("BROWSER_MCP_URL", f"{browser}/mcp")


def secret_env(cfg: Config) -> dict[str, str]:
    """The harness's secret env vars and their values, passed to compose at run
    time only (``SessionPlan.passthrough_env``). The LLM key lives in the user's
    config and nowhere else on disk. NOTE: in Phase 2 it moves into nono's proxy
    (credential injection) and leaves the harness env too."""
    from .harnessconfig import LLM_API_KEY_ENV

    return {LLM_API_KEY_ENV: str(cfg.llm_api_key)} if cfg.llm_api_key else {}


def _plugin_env(cfg: Config, session: str, plugins, environment: dict[str, str]) -> None:
    """Inject each enabled plugin's `env_from_services` endpoints (e.g. the
    `search` plugin's SEARXNG_URL from the `search` sidecar)."""
    from .harnessconfig import service_base

    for plugin in plugins:
        for var, service_name in plugin.env_from_services.items():
            base = service_base(cfg, session, service_name)
            if base:
                environment.setdefault(var, base)


def _validate_plugin_services(cfg: Config, plugins) -> None:
    """Fail early when an enabled plugin's required forwarder service is absent —
    the capability reaches the network only through that sidecar."""
    declared = {s.name for s in cfg.harness_services}
    for plugin in plugins:
        missing = [s for s in plugin.requires_services if s not in declared]
        if missing:
            raise ConfigError(
                f"plugin {plugin.name!r} requires service(s) {missing} that are "
                "not declared — add them under `services:` and include 'service' "
                f"in `net` (e.g. services: [{{name: {missing[0]}, to: …}}], "
                "net: [service])."
            )


def _plugin_entry(cfg: Config, base_entry: list[str], plugins) -> list[str]:
    """Augment the harness entry with each enabled plugin's contribution.

    Pi loads capability code as extensions (``-e <path>``); other harnesses use
    MCP wiring instead, so their entry is unchanged."""
    entry = list(base_entry)
    if cfg.harness == "pi":
        for plugin in plugins:
            for ext in plugin.pi_extensions:
                entry += ["-e", ext]
    return entry


def _legacy_bridges(cfg: Config) -> list[tuple[str, str]]:
    """Pre-plugin configs that imply a plugin: `(plugin_name, deprecation)`.

    Single source of truth for the back-compat shim — a declared `search`
    service implies the `search` plugin; a top-level `browser:` block (provider
    set) implies `browser`. `_apply_plugin_config` injects the names,
    `legacy_warnings` surfaces the messages, so the bridge rule and its warning
    can't drift.
    """
    from .plugins.browser import provider_name

    bridges: list[tuple[str, str]] = []
    if any(s.name == "search" for s in cfg.harness_services) and "search" not in cfg.plugins:
        bridges.append((
            "search",
            "a `search` service without `plugins: [search]` is deprecated — add "
            "`plugins: [search]` (implied for now).",
        ))
    if provider_name(cfg) is not None and "browser" not in cfg.plugins:
        bridges.append((
            "browser",
            "top-level `browser:` is deprecated — use `plugins: [browser]` with "
            "`plugin_options: {browser: {…}}` (still works for now).",
        ))
    return bridges


def _apply_plugin_config(cfg: Config, session: str) -> None:
    """Expand plugin-driven config before the network/plan is built.

    For the browser plugin this means running the provider wiring (host services,
    the `browser` forwarder sidecar, harness env). Runs here — not in the CLI — so
    every plan (run, dry-run, `policy show`, tests) composes the same session.

    Back-compat: legacy configs that imply a plugin (see `_legacy_bridges`) get
    that plugin injected here. Canonical options live in `plugin_options.browser`.
    """
    from .plugins.browser import apply_browser

    for plugin_name, _ in _legacy_bridges(cfg):
        cfg.plugins = [*cfg.plugins, plugin_name]
    if "browser" in cfg.plugins:
        opts = cfg.plugin_options.get("browser", {})
        if opts:
            # explicit top-level browser:/--browser wins over plugin_options
            cfg.browser = {**opts, **(cfg.browser or {})}
        if not (cfg.browser or {}).get("provider"):
            cfg.browser = {**(cfg.browser or {}), "provider": "host-mcp"}  # v2 default
        apply_browser(cfg, session)


def legacy_warnings(cfg: Config) -> list[str]:
    """Deprecation notices for pre-plugin config that still works via the shim."""
    return [msg for _, msg in _legacy_bridges(cfg)]


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
) -> SessionPlan:
    """Resolve a ``Config`` into a runtime-agnostic ``SessionPlan``.

    ``resume``/``session_id`` are transient run options: they append the
    harness's own resume flag to the entry (inside the ring-1 wrapper) and are
    deliberately *not* stored on ``Config`` — they must never persist into
    ``glove.effective.yaml`` or the env file. ``session_id`` implies resume;
    ``resume`` with no id ⇒ continue the most recent session."""
    session = cfg.resolved_name()
    profile = get_profile(cfg.harness)
    uid = uid if uid is not None else os.getuid()
    gid = gid if gid is not None else os.getgid()

    # Expand plugin-driven config (e.g. browser provider wiring) first, so the
    # mount/network plans and validation below see the composed session.
    _apply_plugin_config(cfg, session)

    mount_plan = compute_mounts(
        cfg.workdir,
        [(a.path, a.mode) for a in cfg.add_dirs],
        cwd=cwd,
        allow_sensitive=cfg.allow_sensitive,
    )
    network = build_network_plan(cfg, session)

    # Resolve enabled plugins (fails loudly on an unknown name) and validate that
    # each one's required forwarder services are declared.
    from .plugins import resolve_plugins

    plugins = resolve_plugins(cfg.plugins)
    _validate_plugin_services(cfg, plugins)

    environment = _resolve_env(cfg, profile)
    _service_env(cfg, session, environment)
    _plugin_env(cfg, session, plugins, environment)

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

    # Fold the enabled plugin set into the image tag so it gets its own composed
    # image. srt needs bwrap/socat/srt baked in; its image gets an `-srt` suffix.
    image = effective_image(profile, cfg.apt_packages, cfg.pip_packages, cfg.plugins)
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
        passthrough_env=list(secret_env(cfg)),
    )
    plan.observe = network.observe
    if network.gated:
        plan.netgate_image = netgate_image()

    # Ring-1: render policies, wrap the (plugin-augmented) harness entry, collect
    # enforcer env/caps.
    entry = _plugin_entry(cfg, list(profile.entry), plugins)
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
