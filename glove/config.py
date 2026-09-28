"""The internal session configuration (``Config``) and secret references.

A session's ``glove-session.yml`` (schema v3, ``glove/sessiondir.py``) is
translated into a ``Config``, which the planner consumes. The fully resolved
("effective") config round-trips to YAML (``.glove/effective.yml``) so a
session is reproducible.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .hardening import Limits


class ConfigError(ValueError):
    """Raised for malformed or contradictory configuration."""


@dataclass
class AddDir:
    path: str
    mode: str = "ro"  # "ro" | "rw"

    def __post_init__(self) -> None:
        if self.mode not in ("ro", "rw"):
            raise ConfigError(f"add_dir mode must be ro|rw, got {self.mode!r}")


@dataclass
class HostService:
    """A host-side helper glove starts in a detached tmux session.

    These run on the host (outside the sandbox) using host trust the container
    deliberately lacks — e.g. the headed Chrome and Playwright MCP of the
    `playwright` extension's host mode. `command` may use placeholders glove
    expands: {session}, {workdir}, {home}.
    """

    name: str
    command: str
    ready_port: int | None = None  # glove waits for / dedupes on this port
    ready_timeout: float = 60.0  # seconds to wait for ready_port
    keep: bool = False  # leave running after `glove down` (e.g. Chrome)


@dataclass
class Service:
    """A forwarder sidecar / network allow-list entry."""

    name: str
    to: str  # target host:port the sidecar forwards to
    port: int = 0  # listen port inside the internal net (default: target port)
    join_network: str | None = None  # external docker network to also join
    host_gateway: bool = False  # add extra_hosts host.docker.internal:host-gateway
    # Network observability (glove/observe.py): None ⇒ gated in tcp mode when the
    # top-level `observe.enabled` is on; False ⇒ opt out (stays plain socat); a
    # mapping annotates it ({mode, tool, scope, upstream}).
    observe: Any = None
    # False: a listener for egress-stack components (e.g. SearXNG's outbound
    # proxy), joined only to `join_network` — never to the harness's network and
    # never offered to the harness. Requires join_network.
    harness: bool = True

    def __post_init__(self) -> None:
        if self.port == 0:
            _, _, tport = self.to.rpartition(":")
            try:
                self.port = int(tport)
            except ValueError as e:  # pragma: no cover - defensive
                raise ConfigError(
                    f"service {self.name!r}: cannot infer port from {self.to!r}"
                ) from e
        # host.docker.internal targets imply the host-gateway extra_hosts entry.
        if "host.docker.internal" in self.to:
            self.host_gateway = True
        if not self.harness and not self.join_network:
            raise ConfigError(
                f"service {self.name!r}: harness: false needs join_network — it is a listener "
                "for components on that network, and is never reachable from the sandbox"
            )


@dataclass
class Config:
    harness: str = "vibe"
    provider: str = "docker"  # docker | podman (autodetect handled in cli)
    # NEW in v2. `runtime` is the ring-0 layer (docker | podman |
    # apple-container | gondolin | utm); for docker/podman it also drives which
    # compose CLI `provider` shells out to. `enforcer` is the ring-1 in-container
    # sandbox (nono | srt | none).
    runtime: str = "docker"
    enforcer: str = "nono"
    # Internal (set from the session directory, never a session-file key):
    # work/ is /work, and the name is the session id.
    workdir: str = "."
    name: str | None = None
    add_dirs: list[AddDir] = field(default_factory=list)
    net: list[str] = field(default_factory=lambda: ["none"])
    # Opt-in capabilities: extension name → its settings (glove/extensions.py).
    # An extension not listed contributes nothing — no containers, no mounts,
    # no image layers. The `llm` extension (the required `inference` slot) is
    # where the model, endpoint and API key are configured.
    extensions: dict[str, Any] = field(default_factory=dict)
    allow_root: bool = False
    allow_sensitive: bool = False  # permit mounting / or $HOME
    # Ring-0 ro binds over .vscode/.envrc/.mcp.json in rw mounts; a missing one
    # gets an empty placeholder (creates it on the host), hence opt-in.
    protect_ide_files: bool = False
    rebuild: bool = False
    services: list[Service] = field(default_factory=list)
    harness_config: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    # Free-text session brief appended to the harness context file, e.g.
    # what the agent should work on in /work.
    brief: str | None = None
    # Host-side helpers glove auto-starts in detached tmux sessions:
    # SSH model tunnel, headed Chrome, Playwright MCP. Managed lifecycle:
    # port-deduped, health-checked, torn down on `glove down` (unless keep).
    host_services: list[HostService] = field(default_factory=list)
    # Extra packages baked into the harness image on top of its defaults, so the
    # sandboxed agent has the tools a session needs (the box has no egress to
    # install them at runtime). Changing these yields a distinct image tag.
    apt_packages: list[str] = field(default_factory=list)
    pip_packages: list[str] = field(default_factory=list)
    # Resource bounds (ring 0) and the ring-1 tool policy knobs.
    limits: Limits = field(default_factory=Limits)
    tools: dict[str, Any] = field(default_factory=dict)
    enforcer_options: dict[str, Any] = field(default_factory=dict)
    # Network observability (docs/planning/network-observability.md): routes the
    # service forwarders through the instrumented netgate and records flows to
    # the session's net/ dir. Off by default; validated in glove/observe.py.
    observe: dict[str, Any] | bool = field(default_factory=dict)
    # Internal (not a session-file key): the session's /24 from the user's
    # subnet pool, recorded in the registry; each session network gets a /27.
    subnet: str | None = None

    @property
    def harness_services(self) -> list[Service]:
        """Services offered to the harness (excludes `harness: false` listeners)."""
        return [s for s in self.services if s.harness]

    def resolved_name(self) -> str:
        # The session id (glove/sessiondir.py); the CLI always sets it.
        return self.name or "session"

    def to_dict(self) -> dict[str, Any]:
        # Extension secret settings are references (keychain:/env:), validated
        # as such, so the effective config never holds a secret value.
        return asdict(self)

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False)


SECRET_REF_PREFIXES = ("keychain:", "env:")


def is_secret_ref(value: str) -> bool:
    """True if `value` names where a secret lives rather than holding it."""
    return str(value).startswith(SECRET_REF_PREFIXES)


def resolve_secret(value: str) -> str:
    """Resolve a secret setting to its value, in memory only.

    `keychain:<service>` reads the macOS Keychain generic password for that
    service; `env:<VAR>` reads the process environment; anything else is the
    literal value. Called at launch, never while planning or rendering, so a
    dry-run never touches the Keychain and nothing is written to disk.
    """
    value = str(value)
    if value.startswith("keychain:"):
        service = value.removeprefix("keychain:")
        if not service:
            raise ConfigError("keychain: reference needs a service name (keychain:<service>)")
        if not shutil.which("security"):
            raise ConfigError(f"{value}: the macOS `security` tool is not available on this host")
        r = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-w"],
            capture_output=True, text=True, check=False,
        )
        secret = r.stdout.rstrip("\n")
        if r.returncode != 0 or not secret:
            raise ConfigError(f"{value}: no Keychain generic password for service {service!r}")
        return secret
    if value.startswith("env:"):
        var = value.removeprefix("env:")
        secret = os.environ.get(var, "")
        if not var or not secret:
            raise ConfigError(f"{value}: environment variable {var!r} is not set")
        return secret
    return value


def secret_exists(value: str) -> tuple[bool, str]:
    """Whether a secret reference resolves, WITHOUT reading the secret:
    `keychain:` asks only for the item's attributes (no decrypt, no prompt)."""
    value = str(value)
    if value.startswith("keychain:"):
        service = value.removeprefix("keychain:")
        if not shutil.which("security"):
            return False, "the macOS `security` tool is not available on this host"
        r = subprocess.run(["security", "find-generic-password", "-s", service],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return (r.returncode == 0,
                "Keychain item exists" if r.returncode == 0
                else f"no Keychain item; create it with `glove keychain set {service}`")
    if value.startswith("env:"):
        var = value.removeprefix("env:")
        return bool(os.environ.get(var)), "set" if os.environ.get(var) else f"${var} is not set"
    return False, "not a reference (keychain:<service> | env:<VAR>)"


def keychain_set(service: str) -> int:
    """Store a secret in the login Keychain, prompting for it: `-w` as the last
    option makes `security` read it from the terminal, so it is never in argv."""
    if not service or service.startswith("-"):
        raise ConfigError(f"invalid Keychain service name {service!r}")
    if not shutil.which("security"):
        raise ConfigError("the macOS `security` tool is not available on this host")
    user = os.environ.get("USER") or "glove"
    return subprocess.run(["security", "add-generic-password", "-U", "-a", user, "-s", service, "-w"],
                          check=False).returncode


def split_csv(value: str) -> list[str]:
    """Split a comma-separated string into stripped, non-empty tokens.

    The one normalization rule for comma-list config/flags (`net`), shared by
    the config coercer and the CLI so they can't drift on what a comma-string
    means.
    """
    return [p.strip() for p in value.split(",") if p.strip()]


def _load_mapping(path: Path) -> dict[str, Any]:
    text = path.read_text()
    data = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top-level config must be a mapping")
    return data


def _coerce(data: dict[str, Any]) -> Config:
    """Build a Config from a plain mapping, coercing nested structures."""
    data = dict(data)  # shallow copy; we pop as we go
    add_dirs_raw = data.pop("add_dirs", []) or []
    services_raw = data.pop("services", []) or []
    host_services_raw = data.pop("host_services", []) or []

    add_dirs = [_coerce_add_dir(x) for x in add_dirs_raw]
    services = [Service(**x) if isinstance(x, dict) else _coerce_service(x) for x in services_raw]
    host_services = [
        x if isinstance(x, HostService) else HostService(**x)
        for x in host_services_raw
    ]

    net = data.pop("net", None)
    if isinstance(net, str):
        net = split_csv(net)

    limits_raw = data.pop("limits", None)

    known = set(Config.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown config keys: {sorted(unknown)}")

    cfg = Config(**data)
    cfg.add_dirs = add_dirs
    cfg.services = services
    cfg.host_services = host_services
    if net is not None:
        cfg.net = net
    if limits_raw is not None:
        cfg.limits = _coerce_limits(limits_raw)
    return cfg


def _coerce_limits(x: Any) -> Limits:
    if isinstance(x, Limits):
        return x
    if isinstance(x, dict):
        allowed = set(Limits.__dataclass_fields__)
        unknown = set(x) - allowed
        if unknown:
            raise ConfigError(f"unknown limits keys: {sorted(unknown)}")
        return Limits(**x)
    raise ConfigError(f"invalid limits (expected mapping): {x!r}")


def _coerce_add_dir(x: Any) -> AddDir:
    if isinstance(x, AddDir):
        return x
    if isinstance(x, str):
        path, _, mode = x.partition(":")
        return AddDir(path=path, mode=mode or "ro")
    if isinstance(x, dict):
        return AddDir(**x)
    raise ConfigError(f"invalid add_dir entry: {x!r}")


def _coerce_service(x: Any) -> Service:
    raise ConfigError(f"invalid service entry (expected mapping): {x!r}")


def load_config(path: Path | None) -> Config:
    """Load a Config from a file, or return defaults when path is None."""
    if path is None:
        return Config()
    return _coerce(_load_mapping(path))
