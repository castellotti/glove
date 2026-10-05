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
class Config:
    harness: str = ""  # a harnesses/<name> plugin; session files must name one
    provider: str = "docker"  # docker | podman (autodetect handled in cli)
    # NEW in v2. `runtime` is the ring-0 layer (docker | podman |
    # apple-container | gondolin | utm); for docker/podman it also drives which
    # compose CLI `provider` shells out to. `enforcer` is the ring-1 in-container
    # sandbox (nono | nono+srt | srt | none).
    runtime: str = "docker"
    enforcer: str = "nono"
    # Internal (set from the session directory, never a session-file key):
    # work/ is /work, and the name is the session id.
    workdir: str = "."
    name: str | None = None
    add_dirs: list[AddDir] = field(default_factory=list)
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
    harness_config: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    # Free-text session brief appended to the harness context file, e.g.
    # what the agent should work on in /work.
    brief: str | None = None
    # Optional PEM bundle of a private (e.g. TLS-intercepting proxy) CA the
    # harness should trust *in addition to* the public roots; bound read-only.
    # A public certificate, never a secret. Relative to the session dir.
    corporate_ca: str | None = None
    # Host-side helpers glove auto-starts in detached tmux sessions:
    # SSH model tunnel, headed Chrome, Playwright MCP. Managed lifecycle:
    # port-deduped, health-checked, torn down on `glove down` (unless keep).
    host_services: list[HostService] = field(default_factory=list)
    # Extra packages baked into the harness image on top of its defaults, so the
    # sandboxed agent has the tools a session needs (the box has no egress to
    # install them at runtime). Changing these yields a distinct image tag.
    apt_packages: list[str] = field(default_factory=list)
    pip_packages: list[str] = field(default_factory=list)
    # Version-pinned language toolchains (glove/toolchains.py): each block is a
    # mapping {lang, version, manager, project, install, packages, browsers,
    # config_files, install_flags}, validated by the planner and baked into the
    # derived image. Empty: nothing.
    toolchains: list[dict[str, Any]] = field(default_factory=list)
    # Resource bounds (ring 0) and the ring-1 tool policy knobs.
    limits: Limits = field(default_factory=Limits)
    tools: dict[str, Any] = field(default_factory=dict)
    enforcer_options: dict[str, Any] = field(default_factory=dict)
    # Internal (not a session-file key): the session's /24 from the user's
    # subnet pool, recorded in the registry; each session network gets a /27.
    subnet: str | None = None

    def __post_init__(self) -> None:
        from .enforcers import enforcer_options

        # checked and filled once, so every reader sees the same normalized value
        self.enforcer_options = enforcer_options(self.enforcer_options)

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
    host_services_raw = data.pop("host_services", []) or []
    # v2 forwarder machinery, still present in effective.yml files written
    # before v3 M5: forwarders come only from extensions now.
    for legacy in ("services", "net", "observe"):
        data.pop(legacy, None)

    add_dirs = [_coerce_add_dir(x) for x in add_dirs_raw]
    host_services = [
        x if isinstance(x, HostService) else HostService(**x)
        for x in host_services_raw
    ]

    limits_raw = data.pop("limits", None)
    if data.get("toolchains") is None:
        data.pop("toolchains", None)
    elif not isinstance(data["toolchains"], list):
        raise ConfigError("`toolchains` must be a list of blocks ({lang, version, manager, …})")

    known = set(Config.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown config keys: {sorted(unknown)}")

    cfg = Config(**data)
    cfg.add_dirs = add_dirs
    cfg.host_services = host_services
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


def load_config(path: Path | None) -> Config:
    """Load a Config from a file, or return defaults when path is None."""
    if path is None:
        return Config()
    return _coerce(_load_mapping(path))
