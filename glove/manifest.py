"""The `api: 2` manifest schema, as data: what each `extension.yml` key holds,
and how a `contribute` hook's value for it merges with the manifest's; plus the
slot exports core and other extensions read. `docs/extensions.md` is written
from these tables."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import ConfigError

API_VERSION = 2


class ExtensionError(ConfigError):
    """A manifest, setting or composition problem (always names the extension)."""


@dataclass(frozen=True)
class Key:
    """`type`: the value's type in a manifest (None: a hook-only key). `merge`:
    how a `contribute` hook's value joins it — `cat` (lists concatenate) or
    `add` (a hook adds names; one the manifest sets too is refused) — None: a
    hook may not return it."""

    type: type | None
    merge: str | None = None


KEYS = {
    "api": Key(int), "name": Key(str), "summary": Key(str), "provides": Key(list), "requires": Key(list),
    "auto": Key(bool), "selectable": Key(bool), "settings": Key(dict), "host_files": Key(bool),
    "validate": Key(list), "exports": Key(dict, "add"), "endpoints": Key(dict, "add"), "networks": Key(dict),
    "services": Key(str), "images": Key(dict), "privileges": Key(dict, "add"), "limits": Key(dict),
    "secrets": Key(dict), "channels": Key(dict, "add"), "outputs": Key(dict), "inputs": Key(dict),
    "mounts": Key(dict), "trust": Key(list, "cat"), "verify": Key(list, "cat"), "harness": Key(dict, "add"),
    "hooks": Key(str), "cli": Key(str),
    # hook-only: values that exist only at plan time
    "vars": Key(None, "add"),  # the extension's own compose fragment ({{ vars.x }})
    "egress_hosts": Key(None, "cat"),  # names its sidecars reach (doctor: does the egress admit them?)
    "secret_refs": Key(None, "add"),  # label → secret ref, for the plan's list of secrets
    "host_services": Key(None, "cat"),  # until R16.C moves them into playwright
}
# What a hook's `harness:` may hold: image layers (only these may `copy_host`),
# env, skills (container paths), mcp items and a brief (its text, not a template).
HARNESS_CONTRIB = {"image": list, "env": dict, "skills": list, "mcp": list, "brief": str}


def _is(v: Any, types: type | tuple) -> bool:
    """isinstance, but a bool is no int."""
    types = types if isinstance(types, tuple) else (types,)
    return isinstance(v, types) and (bool in types or not isinstance(v, bool))


def check_manifest(name: str, raw: dict[str, Any]) -> None:
    """The version, no unknown or hook-only key, and each key's type."""
    if raw.get("api") != API_VERSION:
        raise ExtensionError(f"extension {name!r} is written for api {raw.get('api')!r}; glove speaks api "
                             f"{API_VERSION} (see docs/extensions.md)")
    unknown = sorted(k for k in raw if k not in KEYS or KEYS[k].type is None)
    if unknown:
        raise ExtensionError(f"extension {name!r}: unknown manifest keys {unknown}")
    for k, v in raw.items():
        if v is not None and not _is(v, KEYS[k].type):
            raise ExtensionError(f"extension {name!r}: `{k}` must be a {KEYS[k].type.__name__}")


def check_contribution(name: str, out: Any) -> dict[str, Any]:
    """A `contribute` hook's result: a mapping of the keys a hook may return,
    each of its manifest type (lists and mappings)."""
    where = f"extension {name!r}: contribute"
    if not isinstance(out, dict):
        raise ExtensionError(f"{where}: must return a mapping")
    for k, v in out.items():
        key = KEYS.get(k)
        if key is None or key.merge is None:
            raise ExtensionError(f"{where}: {k!r} is not a key a hook may return "
                                 f"({sorted(n for n, x in KEYS.items() if x.merge)})")
        want = list if key.merge == "cat" else dict
        if not isinstance(v, want):
            raise ExtensionError(f"{where}: {k!r} must be a {want.__name__}")
        if k == "harness":
            for hk, hv in v.items():
                if hk not in HARNESS_CONTRIB or not isinstance(hv, HARNESS_CONTRIB[hk]):
                    raise ExtensionError(f"{where}: harness takes {sorted(HARNESS_CONTRIB)} "
                                         "(image, skills, mcp: lists; env: a mapping; brief: a string)")
    return out


def merge_names(where: str, mine: dict | None, more: dict | None, *, active=lambda _spec: True) -> dict:
    """An `add` key: the manifest's entries (those `active`) and the hook's new
    ones. A name both set is refused: nothing is silently masked."""
    mine, more = mine or {}, more or {}
    if both := sorted(n for n in more if n in mine and active(mine[n])):
        raise ExtensionError(f"{where}: {both} set by both the manifest and the contribute hook")
    return {**mine, **more}


# --- slot exports -----------------------------------------------------------------
#
# The exports of a slot's provider that core or other extensions read, by
# type (a tuple: any of them), and the ones every provider must set. Keys not
# named here are the provider's own (its templates may use them; core never does).

_STR, _INT, _OPT_STR = (str,), (int,), (str, type(None))
SLOT_EXPORTS: dict[str, dict[str, tuple]] = {
    "egress": {
        "proxy_host": _STR, "proxy_port": _INT, "proxy_url": _STR, "network": _STR, "route": _STR,
        "anonymising": (bool,), "resolver": _OPT_STR, "exit_identity": (dict,), "shares": (list,),
        "guard_hosts": (list,), "guard_cidrs": (list,),
    },
    "inference": {
        "base_url": _STR, "api": _STR, "model": _STR, "api_key_secret": _OPT_STR, "api_key_kind": _OPT_STR,
        "api_key_injected": (bool,), "auth_header": _OPT_STR, "auth_scheme": _OPT_STR,
        "capabilities": (dict,), "extra_models": (list,), "probe_headers": (dict, type(None)),
    },
    "browser": {"host_ports": (dict,)},
}
REQUIRED_EXPORTS = {"egress": ("proxy_host", "proxy_port", "proxy_url"), "inference": ("base_url", "api", "model")}


def _coerce(v: Any, types: tuple) -> Any:
    """A templated int or bool export renders as a string: read it back."""
    s = v.strip().lower() if isinstance(v, str) else ""
    if bool in types and s in ("true", "false"):
        return s == "true"
    return int(s) if int in types and s.lstrip("-").isdigit() else v


def check_slot_exports(slot: str, provider: str, exports: dict[str, Any]) -> dict[str, Any]:
    """`exports`, checked against the slot's schema, with a templated int or
    bool export (`"{{ settings.port }}"`) read back as one."""
    where = f"extension {provider!r}: the {slot} slot's exports"
    schema = SLOT_EXPORTS.get(slot, {})
    exports = {k: _coerce(v, schema[k]) if k in schema else v for k, v in exports.items()}
    if missing := [k for k in REQUIRED_EXPORTS.get(slot, ()) if exports.get(k) in (None, "")]:
        raise ExtensionError(f"{where} need {missing}")
    for k, types in schema.items():
        v = exports.get(k)
        if v is not None and not _is(v, types):
            raise ExtensionError(f"{where}: {k} must be {' or '.join(t.__name__ for t in types)}, got {v!r}")
    if slot == "egress":
        ident = exports.get("exit_identity")
        if ident is not None and set(ident) not in ({"url"}, {"source", "volume", "file"}):
            raise ExtensionError(f"{where}: exit_identity is {{url: https://…}} or {{source:, volume:, file:}}")
        if not all(isinstance(x, str) for x in exports.get("shares") or []):
            raise ExtensionError(f"{where}: shares is a list of volume names")
    return exports
