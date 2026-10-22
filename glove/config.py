"""The internal session configuration (``Config``) and secret references.

A session's ``glove-session.yml`` (schema v3, ``glove/sessiondir.py``) is
translated into a ``Config``, which the planner consumes. The fully resolved
("effective") config round-trips to YAML (``.glove/effective.yml``) so a
session is reproducible.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

import yaml

from .hardening import Limits


class ConfigError(ValueError):
    """Raised for malformed or contradictory configuration."""


# libyaml's parser when PyYAML has it: a plan parses every manifest and fragment
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def load_yaml(text: str) -> Any:
    """`yaml.safe_load`, several times faster with libyaml; an error is a `yaml.YAMLError`."""
    try:
        return yaml.load(text, Loader=_LOADER)
    except UnicodeError as e:  # libyaml's, for text it cannot encode (a lone surrogate)
        raise yaml.YAMLError(str(e)) from e


@dataclass
class AddDir:
    path: str
    mode: str = "ro"  # "ro" | "rw"

    def __post_init__(self) -> None:
        if self.mode not in ("ro", "rw"):
            raise ConfigError(f"add_dir mode must be ro|rw, got {self.mode!r}")


@dataclass
class Config:
    harness: str = ""  # a harnesses/<name> plugin; session files must name one
    provider: str = "docker"  # docker | podman (autodetect handled in cli)
    # `runtime` is the ring-0 layer (docker | podman); it also names the
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
    # Empty ring-0 placeholders over a missing .vscode/.idea/.envrc/.mcp.json in
    # rw mounts (creates them on the host), hence opt-in; present ones are always ro.
    protect_ide_files: bool = False
    harness_config: dict[str, Any] = field(default_factory=dict)
    # `harness_config.tools.allow`: tools the session adds to its harness's tool
    # inventory (passthrough only; glove/harness.py tool_inventory). glove's key,
    # taken out of harness_config so no adapter renders it (Vibe's own `tools`
    # tables stay).
    tool_allow: list[str] = field(default_factory=list)
    env: dict[str, Any] = field(default_factory=dict)
    # git config for the harness and its commands (key → value or values), after
    # core's mount-root safe.directory and extensions' (glove/plan.py).
    git_config: dict[str, Any] = field(default_factory=dict)
    # Free-text session brief appended to the harness context file, e.g.
    # what the agent should work on in /work.
    brief: str | None = None
    # Optional PEM bundle of a private (e.g. TLS-intercepting proxy) CA the
    # harness should trust *in addition to* the public roots; bound read-only.
    # A public certificate, never a secret. Relative to the session dir.
    corporate_ca: str | None = None
    # Extra packages baked into the harness image on top of its defaults, so the
    # sandboxed agent has the tools a session needs (the box has no egress to
    # install them at runtime). Changing these yields a distinct image tag.
    apt_packages: list[str] = field(default_factory=list)
    pip_packages: list[str] = field(default_factory=list)
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
        self.tools = _tools(self.tools)
        self.harness_config, self.tool_allow = _tool_allow(self.harness_config, self.tool_allow)
        self.git_config = self.git_config or {}
        git_config_pairs(self.git_config, "git_config")

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


def keychain_service(ref: str) -> str | None:
    """The service of a `keychain:<service>` reference, else None."""
    ref = str(ref)
    return (ref.removeprefix("keychain:") or None) if ref.startswith("keychain:") else None


def resolve_secret(value: str) -> str:
    """Resolve a secret setting to its value, in memory only.

    `keychain:<service>` reads the OS credential store (`keychain_tool`);
    `env:<VAR>` reads the process environment; anything else is the literal
    value. Called at launch, never while planning or rendering, so a dry-run
    never touches the credential store and nothing is written to disk.
    """
    value = str(value)
    if value.startswith("keychain:"):
        service = value.removeprefix("keychain:")
        if not service:
            raise ConfigError("keychain: reference needs a service name (keychain:<service>)")
        try:
            tool = keychain_tool()
            secret = _keychain_read(tool, service)
            if secret is None:
                raise ConfigError(f"no {_STORE[tool]} item for service {service!r}")
            if not secret.startswith(KEYCHAIN_PARTS):
                return secret
            n, _, digest = secret.removeprefix(KEYCHAIN_PARTS).partition(":")
            count = int(n) if n.isdigit() else 0
            parts = [_keychain_read(tool, f"{service}.part{i}") for i in range(1, count + 1)] or [None]
        except ConfigError as e:
            raise ConfigError(f"{value}: {e}") from e
        joined = "".join(p or "" for p in parts)
        if None in parts or hashlib.sha256(joined.encode()).hexdigest() != digest:
            raise ConfigError(f"{value}: its parts ({service}.part<n>) are missing or don't match; store it again")
        return joined
    if value.startswith("env:"):
        var = value.removeprefix("env:")
        secret = os.environ.get(var, "")
        if not var or not secret:
            raise ConfigError(f"{value}: environment variable {var!r} is not set")
        return secret
    return value


def secret_exists(value: str) -> tuple[bool, str]:
    """Whether a secret reference resolves, without handing the secret over:
    on macOS `keychain:` asks only for the item's attributes (no decrypt, no
    prompt); `secret-tool` has no such lookup, so it reads and discards it (a
    locked collection may prompt to unlock)."""
    value = str(value)
    if value.startswith("keychain:"):
        service = value.removeprefix("keychain:")
        try:
            tool = keychain_tool()
            found = (_keychain_read(tool, service) is not None if tool == "secret-tool" else subprocess.run(
                _lookup(tool, service, read=False), capture_output=True, check=False).returncode == 0)
        except ConfigError as e:
            return False, str(e)
        return found, (f"{_STORE[tool]} item exists" if found
                       else f"no {_STORE[tool]} item; create it with `glove keychain set {service}`")
    if value.startswith("env:"):
        var = value.removeprefix("env:")
        return bool(os.environ.get(var)), "set" if os.environ.get(var) else f"${var} is not set"
    return False, "not a reference (keychain:<service> | env:<VAR>)"


# `keychain:` is the OS credential store, so one session file works on macOS
# and Linux: the login Keychain (`security`), or the Secret Service of a
# desktop session (`secret-tool`: GNOME Keyring, KWallet). Nothing else: a
# secret never falls back to a file.
_STORE = {"security": "Keychain", "secret-tool": "Secret Service"}
# The head of a value stored in parts (each tool takes a bounded value per
# write), under the service itself: `glove-parts:<n>:<sha256>`.
KEYCHAIN_PARTS = "glove-parts:"
NO_STORE = "without a Secret Service (a server, SSH), use env:<VAR>"


def keychain_tool() -> str:
    """The credential store's CLI on this host, else a ConfigError saying why."""
    if sys.platform == "darwin":
        if shutil.which("security"):
            return "security"
        raise ConfigError("the macOS `security` tool is not available on this host")
    if shutil.which("secret-tool"):
        return "secret-tool"
    raise ConfigError(f"keychain: on Linux needs `secret-tool` (package libsecret-tools); {NO_STORE}")


def secret_service_attrs(service: str) -> list[str]:
    """A `keychain:<service>` item's Secret Service attributes (`secret-tool`)."""
    return ["application", "glove", "service", service]


def _lookup(tool: str, service: str, *, read: bool = True) -> list[str]:
    if tool == "security":
        return ["security", "find-generic-password", "-s", service, *(["-w"] if read else [])]
    return ["secret-tool", "lookup", *secret_service_attrs(service)]


def _keychain_read(tool: str, service: str) -> str | None:
    """The stored value, None if there is none; a ConfigError if secret-tool
    fails otherwise (no Secret Service, a locked or missing collection)."""
    r = subprocess.run(_lookup(tool, service), capture_output=True, encoding="utf-8", check=False)
    if r.returncode and tool == "secret-tool" and r.stderr.strip():  # a missing item fails silently
        raise ConfigError(f"{r.stderr.strip()}; {NO_STORE}")  # it names itself
    secret = r.stdout.rstrip("\n")
    return secret if r.returncode == 0 and secret else None


def _coerce(data: dict[str, Any]) -> Config:
    """Build a Config from a plain mapping, coercing nested structures."""
    data = dict(data)  # shallow copy; we pop as we go
    add_dirs_raw = data.pop("add_dirs", []) or []

    add_dirs = [_coerce_add_dir(x) for x in add_dirs_raw]

    limits_raw = data.pop("limits", None)
    known = set(Config.__dataclass_fields__)
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown config keys: {sorted(unknown)}")

    cfg = Config(**data)
    cfg.add_dirs = add_dirs
    if limits_raw is not None:
        cfg.limits = _coerce_limits(limits_raw)
    return cfg


def _tool_allow(hc: Any, allow: list[str]) -> tuple[Any, list[str]]:
    """`harness_config` without glove's `tools.allow`, and that list."""
    tools = hc.get("tools") if isinstance(hc, dict) else None
    if not isinstance(tools, dict) or "allow" not in tools:
        return hc, allow
    added = tools["allow"]
    if not isinstance(added, list) or not all(isinstance(n, str) for n in added):
        raise ConfigError(f"harness_config.tools.allow must be a list of tool names, got {added!r}")
    rest = {k: v for k, v in tools.items() if k != "allow"}
    hc = {k: v for k, v in hc.items() if k != "tools"} | ({"tools": rest} if rest else {})
    return hc, [*allow, *(n for n in added if n not in allow)]


def _tools(raw: Any) -> dict[str, list[str]]:
    """`tools:`, nono's tool-profile command lists. An unknown key (or a typo)
    is refused, never silently ignored; a blank key or value is unset."""
    from .enforcers.nono.policies import TOOLS_KEYS

    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"`tools` must be a mapping of {', '.join(TOOLS_KEYS)}, got {raw!r}")
    unknown = set(raw) - set(TOOLS_KEYS)
    if unknown:
        raise ConfigError(f"unknown tools keys: {sorted(unknown)} (known: {', '.join(TOOLS_KEYS)})")
    out = {k: v for k, v in raw.items() if v is not None}
    for k, v in out.items():
        if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
            raise ConfigError(f"tools.{k} must be a list of command names, got {v!r}")
    return out


# The env vars git reads config from: glove alone sets them (GIT_CONFIG_PARAMETERS).
GIT_CONFIG_ENV = re.compile(r"GIT_CONFIG_(?:PARAMETERS|COUNT|KEY_\d+|VALUE_\d+)")
_GIT_KEY = re.compile(r"[A-Za-z][A-Za-z0-9-]*(?:\.[^\n]+)?\.[A-Za-z][A-Za-z0-9-]*\Z")


def git_config_pairs(raw: Any, where: str) -> list[tuple[str, str]]:
    """A `git_config:` mapping (the session's, or an extension's
    `harness.git_config`) as (key, value) pairs: each key takes a value or a
    list of them (a multi-valued key such as safe.directory)."""
    if not raw:
        return []
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be a mapping of git config key → value(s), got {raw!r}")
    out = []
    for k, v in raw.items():
        if not isinstance(k, str) or not _GIT_KEY.fullmatch(k):
            raise ConfigError(f"{where}: {k!r} is not a git config key (section[.subsection].name)")
        for x in v if isinstance(v, list) else [v]:
            if isinstance(x, bool):
                x = str(x).lower()
            if not isinstance(x, str | int) or any(c in str(x) for c in "\n\0"):
                raise ConfigError(f"{where}.{k}: want a single-line value, got {x!r}")
            out.append((k, str(x)))
    return out


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
