"""The extension hook protocol (`api: 2`): `@hook`, the context a hook gets and
what each hook may return. Core calls a hook only through
`extensions.call_hook`, and only for a selected extension."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any

from .manifest import ExtensionError, check_contribution

_MARK = "__glove_hook__"


def hook(fn: Callable) -> Callable:
    """Mark `fn` as a hook; its name must be one core calls."""
    if fn.__name__ not in HOOKS:
        raise TypeError(f"@hook {fn.__name__!r} is not a hook glove calls ({', '.join(sorted(HOOKS))})")
    setattr(fn, _MARK, True)
    return fn


def hooks_of(module: ModuleType, ext: str) -> dict[str, Callable]:
    """The module's marked hooks. A function named like a hook but unmarked is
    refused: a missing `@hook` would silently skip it."""
    marked = {n: getattr(module, n) for n in HOOKS if getattr(getattr(module, n, None), _MARK, False)}
    if unmarked := sorted(n for n in HOOKS if callable(getattr(module, n, None)) and n not in marked):
        raise ExtensionError(f"extension {ext!r}: {unmarked} not marked @hook (did you forget `@hook`?)")
    return marked


_EMPTY: Mapping[str, Any] = MappingProxyType({})


@dataclass(frozen=True)
class HookContext:
    """What a hook sees: the names of the template context, plus host paths
    only where the manifest declares a reason (hygiene, not a boundary: a hook
    is host code). Mappings are read-only."""

    name: str
    settings: Mapping[str, Any] = _EMPTY
    harness: str = ""
    renders: tuple[str, ...] = ()
    trusted: bool = True
    session: Mapping[str, Any] = _EMPTY  # id, subnet, secrets_dir
    names: Mapping[str, Any] = _EMPTY  # project, harness_network, prefix
    slot: Mapping[str, Any] = _EMPTY  # slot → {provider, **exports}, filled so far
    endpoint: Mapping[str, Any] = _EMPTY
    own_endpoints: Mapping[str, Any] = _EMPTY
    active: tuple[str, ...] = ()
    state_dir: Path | None = None  # its own: <state_root>/<name>
    assets: Path | None = None  # the extension's directory
    images: Mapping[str, str] = _EMPTY
    libs: Mapping[str, Any] = _EMPTY
    mount: Mapping[str, str] = _EMPTY
    output: Mapping[str, Any] = _EMPTY
    input: Mapping[str, Any] = _EMPTY
    session_dir: Path | None = None  # declared: a path setting, mounts, outputs/inputs or host_files
    work_dir: Path | None = None  # declared: outputs/inputs, a `work` privilege or host_files
    export_dirs: Mapping[str, Path] = _EMPTY  # the in-tree owner of an export root
    forwarders: tuple[Mapping[str, Any], ...] = ()  # the forwarder slot's provider, once planned
    grants: Mapping[str, Any] = _EMPTY

    def __post_init__(self) -> None:
        for f in fields(self):
            v = getattr(self, f.name)
            if isinstance(v, dict):
                object.__setattr__(self, f.name, MappingProxyType(v))
            elif isinstance(v, list):
                object.__setattr__(self, f.name, tuple(v))


# --- results ----------------------------------------------------------------------

# The keys a `forwarder` hook's service may set. Core names it after the
# endpoint, joins its networks (the harness net with its aliases, the target's
# network) and applies the sidecar hardening set; privileges are never granted.
FORWARDER_KEYS = frozenset({
    "image", "command", "entrypoint", "environment", "volumes", "tmpfs", "depends_on", "healthcheck", "init",
    "restart", "stop_grace_period", "stop_signal", "labels",
})
DOCTOR_STATUS = frozenset({"ok", "warn", "fail"})


def _forwarder(out: Any) -> str | None:
    if out is None:
        return None
    if not isinstance(out, dict) or set(out) - {"service", "facts", "aliases"}:
        return "want {service, facts, aliases} or None"
    if bad := sorted(set(out.get("service") or {}) - FORWARDER_KEYS):
        return f"the service sets {bad} (core owns names, networks and security keys)"
    return None


def _launch_env(out: Any) -> str | None:
    if not isinstance(out, dict) or set(out) - {"secrets", "env"}:
        return "want {secrets: {<its secret>: value}, env: {VAR: value}}"
    if not all(isinstance(out.get(k) or {}, dict) for k in ("secrets", "env")):
        return "secrets and env are mappings"
    return None


def _resolve(out: Any) -> str | None:
    ok = isinstance(out, tuple) and len(out) == 2 and isinstance(out[0], dict) and isinstance(out[1], list)
    return None if ok else "want (exports, notes): a mapping and a list"


def _doctor(out: Any) -> str | None:
    ok = isinstance(out, list) and all(isinstance(c, tuple | list) and len(c) == 3 and c[1] in DOCTOR_STATUS
                                       for c in out)
    return None if ok else f"want a list of (name, status, detail), status in {sorted(DOCTOR_STATUS)}"


RESULTS: dict[str, Callable[[Any], str | None]] = {
    "contribute": lambda out: None,  # check_contribution: the manifest's table
    "materialize": lambda out: None,
    "forwarder": _forwarder,
    "launch_env": _launch_env,
    "resolve": _resolve,
    "diagnose": lambda out: None if out is None or isinstance(out, str) else "want a hint (a string) or None",
    "doctor": _doctor,
}
# teardown (R16.C) joins with its first consumer
HOOKS = frozenset(RESULTS)


def validate_result(name: str, ext: str, out: Any) -> Any:
    """`out` as hook `name` must return it, else an `ExtensionError` naming why."""
    if name == "contribute":
        return check_contribution(ext, {} if out is None else out)
    if name == "launch_env" and out is None:
        out = {}
    if err := RESULTS[name](out):
        raise ExtensionError(f"extension {ext!r}: {name}: {err}")
    return out
