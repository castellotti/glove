"""Extensions: manifest loading, settings, slots and composition (api: 1).

An extension is a directory holding ``extension.yml`` plus assets (compose
fragment, Pi extensions, brief, container code, an optional ``hooks.py`` and
``cli.py``). First-party extensions live in-tree under ``extensions/``; more may
load from ``extension_paths`` in ``~/.glove/config.yml``, marked *out-of-tree*
(the Linux "taint") and refused privilege exceptions unless listed in
``trusted_extensions``.

Core never imports an extension: ``hooks.py``/``cli.py`` are loaded by path
(``load_module``), and ``uv run lint-imports`` forbids ``glove`` → ``extensions``.

``compose(...)`` turns the session's ``extensions:`` map into a ``Composition``:
the selected extensions in dependency order, with validated settings, filled
slots and every contribution rendered through a restricted, sandboxed Jinja
context (``settings``, ``session``, ``slot``, ``names``, ``endpoint``, ``state``,
``assets``, ``images``, ``libs``, ``harness``, and ``exports`` for the owners of
an export root). No other host path reaches a template.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import re
import secrets as pysecrets
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml
from jinja2 import StrictUndefined, TemplateError
from jinja2.sandbox import ImmutableSandboxedEnvironment

from .config import ConfigError, HostService, git_config_pairs, is_secret_ref
from .exports import ensure_dir
from .harness import CONTRIBUTIONS, get_profile, known_harnesses
from .mounts import WORK_TARGET, host_path
from .naming import project_name, scoped
from .sessiondir import PLACEHOLDER
from .userconfig import load_user_config
from .verify import KINDS as VERIFY_KINDS

API_VERSION = 1
IN_TREE_DIR = Path(__file__).resolve().parent.parent / "extensions"
MANIFEST = "extension.yml"

# Exclusive slots core knows. `inference` is required for every harness session.
# `forwarder` replaces the socat forwarder behind every endpoint (its provider's
# `forwarder` hook renders one service per endpoint; observe's netgate).
SLOTS = frozenset({"egress", "inference", "browser", "forwarder"})
REQUIRED_SLOTS = frozenset({"inference"})

# Export roots (§3.4): the only session data outside the session directory.
# root → the in-tree extension that owns it. Core creates, checks (by path) and
# revokes them; `observe` binds its root, the forwarder reads `control` (ro)
# only while `filter` is active.
EXPORT_ROOTS = {"observe": "observe", "control": "filter"}

MANIFEST_KEYS = frozenset({
    "api", "name", "summary", "provides", "requires", "conflicts", "auto", "selectable",
    "settings", "exports", "services", "networks", "privileges", "secrets", "limits", "verify",
    "harness", "host_services", "cli", "hooks", "validate", "images", "endpoints", "mounts", "channels",
})
SETTING_TYPES = frozenset({"string", "enum", "bool", "int", "number", "list", "map", "secret", "path"})
_NAME = re.compile(r"^[a-z][a-z0-9-]*\Z")
_ENV_VAR = re.compile(r"^[A-Z][A-Z0-9_]*\Z")


# A channel's directory in the harness and in the sidecars that serve it (see
# `Channel`).
CHANNEL_ROOT = "/run/glove"


class ExtensionError(ConfigError):
    """A manifest, setting or composition problem (always names the extension)."""


# --- manifests ---------------------------------------------------------------


@dataclass(frozen=True)
class Manifest:
    name: str
    path: Path
    raw: dict[str, Any]
    out_of_tree: bool = False
    trusted: bool = True

    @property
    def summary(self) -> str:
        return str(self.raw.get("summary", ""))

    @property
    def provides(self) -> list[str]:
        return list(self.raw.get("provides") or [])

    @property
    def auto(self) -> bool:
        return bool(self.raw.get("auto", False))

    @property
    def selectable(self) -> bool:
        return bool(self.raw.get("selectable", True))

    @property
    def settings_schema(self) -> dict[str, dict]:
        return dict(self.raw.get("settings") or {})

    @property
    def cli(self) -> Path | None:
        c = self.raw.get("cli")
        return self.path / c if c else None

    @property
    def hooks_path(self) -> Path | None:
        h = self.raw.get("hooks")
        return self.path / h if h else None

    @property
    def taint(self) -> str:
        if not self.out_of_tree:
            return "in-tree"
        return "out-of-tree (trusted)" if self.trusted else "out-of-tree"


def _load_manifest(directory: Path, *, out_of_tree: bool, trusted: set[str]) -> Manifest:
    f = directory / MANIFEST
    try:
        raw = yaml.safe_load(f.read_text()) or {}
    except (OSError, yaml.YAMLError) as e:
        raise ExtensionError(f"{f}: cannot read manifest: {e}") from e
    if not isinstance(raw, dict):
        raise ExtensionError(f"{f}: manifest must be a mapping")
    name = raw.get("name")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ExtensionError(f"{f}: `name` must match {_NAME.pattern}, got {name!r}")
    if raw.get("api") != API_VERSION:
        raise ExtensionError(f"extension {name!r}: api must be {API_VERSION}, got {raw.get('api')!r}")
    unknown = set(raw) - MANIFEST_KEYS
    if unknown:
        raise ExtensionError(f"extension {name!r}: unknown manifest keys {sorted(unknown)}")
    for k in ("provides", "requires", "conflicts"):
        if not isinstance(raw.get(k) or [], list):
            raise ExtensionError(f"extension {name!r}: `{k}` must be a list")
    bad_slots = [s for s in raw.get("provides") or [] if s not in SLOTS]
    if bad_slots:
        raise ExtensionError(f"extension {name!r}: unknown slot(s) {bad_slots} (known: {sorted(SLOTS)})")
    for key, spec in (raw.get("settings") or {}).items():
        _check_setting_spec(name, key, spec)
    return Manifest(name=name, path=directory.resolve(), raw=raw, out_of_tree=out_of_tree,
                    trusted=(not out_of_tree) or name in trusted)


def _candidate_dirs(root: Path) -> list[Path]:
    """`root` itself if it holds a manifest, else its children that do."""
    if (root / MANIFEST).is_file():
        return [root]
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if (p / MANIFEST).is_file())


def discover(in_tree: Path | None = None) -> dict[str, Manifest]:
    """Every loadable manifest: in-tree first, then `extension_paths`."""
    user = load_user_config()
    trusted = set(user.trusted_extensions)
    found: dict[str, Manifest] = {}
    for d in _candidate_dirs(in_tree or IN_TREE_DIR):
        m = _load_manifest(d, out_of_tree=False, trusted=trusted)
        found[m.name] = m
    for root in user.extension_paths:
        for d in _candidate_dirs(Path(root).expanduser()):
            m = _load_manifest(d, out_of_tree=True, trusted=trusted)
            if m.name in found:
                raise ExtensionError(
                    f"out-of-tree extension {m.name!r} ({d}) shadows an existing extension "
                    f"({found[m.name].path}); rename it"
                )
            found[m.name] = m
    return found


def load_module(path: Path, name: str) -> ModuleType:
    """Import an extension's `hooks.py`/`cli.py` by path (never by package name)."""
    spec = importlib.util.spec_from_file_location(f"glove_ext_{name.replace('-', '_')}_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ExtensionError(f"extension {name!r}: cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- settings -----------------------------------------------------------------


def _check_setting_spec(ext: str, key: str, spec: Any) -> None:
    if not isinstance(spec, dict) or spec.get("type") not in SETTING_TYPES:
        raise ExtensionError(f"extension {ext!r}: setting {key!r} needs a `type` in {sorted(SETTING_TYPES)}")
    if spec["type"] == "enum" and not spec.get("values"):
        raise ExtensionError(f"extension {ext!r}: enum setting {key!r} needs `values`")


def _coerce_setting(ext: str, key: str, spec: dict, value: Any) -> Any:
    t = spec["type"]
    where = f"{ext}.{key}"
    if value == PLACEHOLDER:
        raise ExtensionError(f"{where} is still {PLACEHOLDER!r} — set it in your session file")
    if value in (spec.get("also") or []):  # a literal accepted besides the type, e.g. `auto`
        return value
    if t in ("string", "path"):
        if not isinstance(value, str):
            raise ExtensionError(f"{where} must be a string, got {value!r}")
        pattern = spec.get("pattern")
        if pattern and not re.fullmatch(pattern, value):
            raise ExtensionError(f"{where} must match {pattern!r}, got {value!r}")
        escapes = value.startswith(("/", "~")) or ".." in Path(value).parts
        if t == "path" and spec.get("within") == "session" and escapes:
            raise ExtensionError(f"{where} must be a relative path inside the session directory, got {value!r}")
        return value
    if t == "enum":
        values = [str(v) for v in spec["values"]]
        if str(value) not in values:
            raise ExtensionError(f"{where} must be one of {values}, got {value!r}")
        return str(value)
    if t == "bool":
        if not isinstance(value, bool):
            raise ExtensionError(f"{where} must be true|false, got {value!r}")
        return value
    if t == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ExtensionError(f"{where} must be an integer, got {value!r}")
        return value
    if t == "number":
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ExtensionError(f"{where} must be a number, got {value!r}")
        return value
    if t == "list":
        if not isinstance(value, list):
            raise ExtensionError(f"{where} must be a list, got {value!r}")
        pattern = spec.get("pattern")  # for every item, when given
        bad = [v for v in value if pattern and not (isinstance(v, str) and re.fullmatch(pattern, v))]
        if bad:
            raise ExtensionError(f"{where}: {bad} must match {pattern!r}")
        return list(value)
    if t == "map":
        if not isinstance(value, dict):
            raise ExtensionError(f"{where} must be a mapping, got {value!r}")
        return {**(spec.get("default") or {}), **value} if isinstance(spec.get("default"), dict) else dict(value)
    if t == "secret":
        # A secret setting names where the secret lives; the value is resolved in
        # memory at launch and never written to a file.
        if not isinstance(value, str) or not (is_secret_ref(value) or value == "generate"):
            raise ExtensionError(
                f"{where} is a secret: use a reference (keychain:<service> | env:<VAR>)"
                + (" or `generate`" if spec.get("default") == "generate" else "")
                + " — never the value itself"
            )
        return value
    raise ExtensionError(f"{where}: unsupported type {t!r}")  # pragma: no cover


def validate_settings(m: Manifest, given: dict[str, Any] | None) -> dict[str, Any]:
    """The extension's settings with defaults applied; unknown keys are an error."""
    given = dict(given or {})
    schema = m.settings_schema
    unknown = set(given) - set(schema)
    if unknown:
        raise ExtensionError(f"extension {m.name!r}: unknown setting(s) {sorted(unknown)} (known: {sorted(schema)})")
    out: dict[str, Any] = {}
    for key, spec in schema.items():
        if key in given and given[key] is not None:
            out[key] = _coerce_setting(m.name, key, spec, given[key])
        elif "default" in spec:
            out[key] = spec["default"]
        elif spec.get("required"):
            raise ExtensionError(f"extension {m.name!r}: setting {key!r} is required")
        else:
            out[key] = None
    return out


# --- predicates + templating --------------------------------------------------


def _lookup(ctx: dict[str, Any], dotted: str) -> Any:
    cur: Any = ctx
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def when_matches(when: dict[str, Any] | None, ctx: dict[str, Any]) -> bool:
    """Minimal predicate: every key's value equals (or is in, for a list) the
    context value. Keys are setting names, `harness`, `renders` (the harness's
    contributions, a list: it matches when it holds a wanted one) or dotted
    `slot.<s>.<k>`. `{set: true|false}` asks whether the value is set (not null
    or empty)."""
    if not when:
        return True
    for key, want in when.items():
        have = _lookup(ctx, key) if "." in key else ctx.get("settings", {}).get(key, ctx.get(key))
        if isinstance(want, dict) and set(want) == {"set"}:
            if (have not in (None, "", [], {})) != bool(want["set"]):
                return False
            continue
        wants = want if isinstance(want, list) else [want]
        haves = have if isinstance(have, list) else [have]
        if not any(h == w or str(h) == str(w) for w in wants for h in haves):
            return False
    return True


def when_context(settings: dict[str, Any], harness: str) -> dict[str, Any]:
    """What a `when:` sees for an extension: its settings, the harness and the
    contributions the harness renders (`renders: mcp`, not a list of harnesses)."""
    return {"settings": settings, "harness": harness, "renders": sorted(get_profile(harness).contributions)}


_JINJA = ImmutableSandboxedEnvironment(undefined=StrictUndefined, keep_trailing_newline=True)


def render_value(value: Any, ctx: dict[str, Any], where: str = "") -> Any:
    """Render every string in `value` (recursively) with the restricted context."""
    if isinstance(value, str):
        if "{{" not in value and "{%" not in value:
            return value
        try:
            return _JINJA.from_string(value).render(**ctx)
        except TemplateError as e:
            raise ExtensionError(f"{where}: template error: {e}") from e
    if isinstance(value, list):
        return [render_value(v, ctx, where) for v in value]
    if isinstance(value, dict):
        return {k: render_value(v, ctx, where) for k, v in value.items()}
    return value


def active_items(items: list | None, ctx: dict[str, Any]) -> list:
    """List entries whose optional `when:` matches, with `when` removed."""
    out = []
    for item in items or []:
        if isinstance(item, dict):
            if not when_matches(item.get("when"), ctx):
                continue
            item = {k: v for k, v in item.items() if k != "when"}
        out.append(item)
    return out


# --- composition ----------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    """Where an endpoint's forwarder dials. `network` is the network it dials
    over (None: the endpoint's own listen networks suffice)."""

    host: str
    port: int
    kind: str  # service | slot | host | remote
    network: str | None = None


@dataclass(frozen=True)
class Endpoint:
    """A single-purpose forwarder `glove-<id>-<name>:<port>`.

    `harness: True` puts it on the harness network (the only way the harness
    reaches anything); `listen_networks` are extra networks it listens on for
    sidecars (e.g. the browser sidecar's private net). `aliases` are extra
    names on the harness network (e.g. a cloud API hostname)."""

    name: str
    extension: str
    port: int
    target: Target
    harness: bool = True
    listen_networks: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    observe: dict[str, Any] | None = None
    # An egress consumer's hop to its target (`harness: false`): rendered only
    # when a `forwarder` provider can interpose on it; otherwise consumers dial
    # the target directly and `url` is the target's.
    interpose: bool = False
    interposed: bool = False

    def host(self, session: str) -> str:
        return scoped(session, self.name)

    def url(self, session: str) -> str:
        if self.interpose and not self.interposed:
            return f"http://{self.target.host}:{self.target.port}"
        return f"http://{self.host(session)}:{self.port}"


@dataclass(frozen=True)
class Channel:
    """A directory the harness (and every command it runs) shares with some of
    an extension's sidecars: a session tmpfs volume at /run/glove/<name> in
    both, writable by the session uid. It carries no network: a relay's client
    leaves requests there (files and FIFOs, which every enforcer allows, unlike
    a Unix socket) and the sidecar answers them."""

    name: str
    extension: str
    services: tuple[str, ...]

    @property
    def path(self) -> str:
        return f"{CHANNEL_ROOT}/{self.name}"

    def volume(self, session: str) -> str:
        return scoped(session, f"chan-{self.name}")


@dataclass
class Active:
    """One selected extension, resolved."""

    manifest: Manifest
    settings: dict[str, Any]
    auto_added: bool = False
    exports: dict[str, Any] = field(default_factory=dict)
    hooks: ModuleType | None = None
    mounts: dict[str, str] = field(default_factory=dict)  # mount name → container path

    @property
    def name(self) -> str:
        return self.manifest.name


@dataclass
class Composition:
    session: str
    harness: str
    active: list[Active]
    slots: dict[str, Active]
    state_root: Path
    endpoints: list[Endpoint] = field(default_factory=list)
    harness_env: dict[str, str] = field(default_factory=dict)
    git_config: list[tuple[str, str]] = field(default_factory=list)  # `harness.git_config` pairs
    image_layers: list[tuple[str, dict]] = field(default_factory=list)  # (ext, layer)
    # Neutral contributions, collected only when the harness renders them
    # (harness.yml `contributions`): skills as (ext, src dir baked into the image
    # or None for a path under a mount, container path); MCP servers as (ext, spec).
    skills: list[tuple[str, Path | None, str]] = field(default_factory=list)
    mcp: list[tuple[str, dict]] = field(default_factory=list)
    # `harness.<this harness>:` sections, for its adapter: (extension, section, template context)
    harness_items: list[tuple[Active, Any, dict]] = field(default_factory=list)
    # (ext, host dir, container path): read-only harness binds from `mounts:`
    harness_mounts: list[tuple[str, str, str]] = field(default_factory=list)
    briefs: list[tuple[str, str]] = field(default_factory=list)
    channels: list[Channel] = field(default_factory=list)
    host_services: list[HostService] = field(default_factory=list)
    networks: dict[str, dict] = field(default_factory=dict)  # logical name → {internal, owner}
    fragments: list[tuple[Active, dict]] = field(default_factory=list)  # rendered compose docs
    secrets: dict[str, tuple[str, str]] = field(default_factory=dict)  # compose name → (ext, setting)
    verify: list[tuple[str, dict]] = field(default_factory=list)
    privileges: dict[str, list[dict]] = field(default_factory=dict)  # "ext/service" → exceptions
    # The session directory (hooks only — never a template) and its /24.
    session_dir: Path | None = None
    # The harness's /work on the host: trusted extensions may bind a named
    # subdirectory of it into a sidecar (`{{ work.host }}/<dir>`), never all of it.
    work_dir: Path | None = None
    subnet: str | None = None
    has_forwarder: bool = False  # a `forwarder` provider is selected
    # Export root → this session's host dir (created by the CLI, never here).
    export_dirs: dict[str, Path] = field(default_factory=dict)
    # Set once the network plan exists: one entry per forwarder (role, listen,
    # harness, and what the forwarder provider reported), and the grants —
    # both for hooks (observe writes them into session.json).
    forwarders: list[dict[str, Any]] = field(default_factory=list)
    grants: dict[str, Any] = field(default_factory=dict)

    def by_name(self, name: str) -> Active | None:
        return next((a for a in self.active if a.name == name), None)

    @property
    def channel_paths(self) -> list[str]:
        """The channels' directories in the harness: writable under every
        enforcer and profile (they carry no network)."""
        return [c.path for c in self.channels]

    def slot_exports(self, slot: str) -> dict[str, Any]:
        a = self.slots.get(slot)
        return dict(a.exports) if a else {}

    def state_dir(self, ext: str) -> Path:
        return self.state_root / ext

    def owner(self, root: str) -> Active | None:
        """The active in-tree owner of an export root."""
        a = self.by_name(EXPORT_ROOTS[root])
        return a if a is not None and not a.manifest.out_of_tree else None

    def export_access(self, a: Active) -> dict[str, bool]:
        """Export roots `a` may bind: root → read-only?"""
        out: dict[str, bool] = {}
        if a.manifest.out_of_tree:
            return out
        if self.owner("observe") is a:
            out["observe"] = False
        filt = self.owner("control")
        if filt is not None and (a is filt or self.slots.get("forwarder") is a):
            out["control"] = a is not filt  # the gates only ever read rules.json
        return out

    def skill_dest(self, ext: str, src: Path) -> str:
        return f"/opt/glove/skills/{ext}/{src.name}"

    def rendered_briefs(self) -> list[tuple[str, str]]:
        out = []
        for ext, text in self.briefs:
            a = self.by_name(ext)
            out.append((ext, render_value(text, base_context(self, a), f"extension {ext!r} brief").strip()))
        return [(e, t) for e, t in out if t]


def _requirements(m: Manifest, ctx: dict[str, Any]) -> list[tuple[str, str]]:
    """[(kind, name)] with kind extension|slot, honouring `when:`."""
    out = []
    for r in m.raw.get("requires") or []:
        if isinstance(r, str):
            out.append(("slot", r) if r in SLOTS else ("extension", r))
        elif isinstance(r, dict):
            if not when_matches(r.get("when"), ctx):
                continue
            if "slot" in r:
                out.append(("slot", r["slot"]))
            elif "extension" in r:
                out.append(("extension", r["extension"]))
            else:
                raise ExtensionError(f"extension {m.name!r}: a requirement needs `slot` or `extension`")
        else:
            raise ExtensionError(f"extension {m.name!r}: bad requirement {r!r}")
    return out


def _names(session: str) -> dict[str, Any]:
    return {
        "project": project_name(session),
        "harness_network": scoped(session, "net"),
        "prefix": scoped(session, ""),
    }


def base_context(comp: Composition, a: Active) -> dict[str, Any]:
    """The restricted template context for extension `a`."""
    return {
        **when_context(a.settings, comp.harness),
        "session": {"id": comp.session, "subnet": comp.subnet or "", "secrets_dir": SECRETS_DIR},
        "names": _names(comp.session),
        "slot": {s: {"provider": p.name, **p.exports} for s, p in comp.slots.items()},
        "endpoint": {
            e.name: {"host": e.host(comp.session), "port": e.port, "url": e.url(comp.session),
                     "aliases": list(e.aliases), "interposed": e.interposed}
            for e in comp.endpoints
        },
        # the endpoints this extension declared, e.g. for a sidecar dialling its own forwarders
        "own_endpoints": {e.name: {"host": e.host(comp.session), "port": e.port}
                          for e in comp.endpoints if e.extension == a.name},
        "state": str(comp.state_dir(a.name)),
        "mount": dict(a.mounts),
        # /work on the host, and where the `work` privilege binds it in a sidecar
        "work": {"host": str(comp.work_dir or ""), "target": WORK_TARGET},
        "assets": str(a.manifest.path),
        "images": {k: image_tag(a, k) for k in (a.manifest.raw.get("images") or {})},
        "libs": {lib.name: {"images": {k: image_tag(lib, k) for k in (lib.manifest.raw.get("images") or {})}}
                 for lib in required_libs(comp, a)},
        "exports": {root: str(comp.export_dirs[root]) for root in comp.export_access(a) if root in comp.export_dirs},
    }


def required_libs(comp: Composition, a: Active) -> list[Active]:
    """Active extensions `a` requires by name (e.g. `gate`): their images are
    `a`'s to run."""
    names = {r for kind, r in _requirements(a.manifest, when_context(a.settings, comp.harness))
             if kind == "extension"}
    return [x for x in comp.active if x.name in names]


def image_tag(a: Active, name: str) -> str:
    """Local tag for an extension-built image: content-addressed by its context."""
    spec = (a.manifest.raw.get("images") or {}).get(name) or {}
    from .image import content_hash

    ctx_dir = a.manifest.path / str(spec.get("build", name))
    return f"glove/ext-{a.name}-{name}:{content_hash('', [(name, ctx_dir)])}"


def select(
    requested: dict[str, Any], *, harness: str, manifests: dict[str, Manifest] | None = None,
) -> list[Active]:
    """Validate the `extensions:` map, expand `auto` requirements, fill slots,
    check conflicts, and return the extensions in dependency order."""
    manifests = manifests if manifests is not None else discover()
    if not isinstance(requested, dict):
        raise ExtensionError("`extensions` must be a mapping of name → settings")
    chosen: dict[str, Active] = {}
    for name, given in requested.items():
        m = manifests.get(name)
        if m is None:
            raise ExtensionError(f"unknown extension {name!r}; known: {', '.join(sorted(manifests)) or '(none)'}")
        if not m.selectable:
            raise ExtensionError(f"extension {name!r} is a library extension and cannot be selected directly")
        if given is not None and not isinstance(given, dict):
            raise ExtensionError(f"extension {name!r}: settings must be a mapping (use `{name}: {{}}` for none)")
        chosen[name] = Active(m, validate_settings(m, given))

    def ctx_of(a: Active, slots: dict[str, Active]) -> dict[str, Any]:
        return {**when_context(a.settings, harness),
                "slot": {s: {"provider": p.name, **p.manifest.raw.get("exports", {})} for s, p in slots.items()}}

    # Expand auto-added library requirements to a fixed point.
    changed = True
    while changed:
        changed = False
        slots = _fill_slots(chosen)
        for a in list(chosen.values()):
            for kind, req in _requirements(a.manifest, ctx_of(a, slots)):
                if kind != "extension" or req in chosen:
                    continue
                m = manifests.get(req)
                if m is None or not m.auto:
                    raise ExtensionError(
                        f"extension {a.name!r} requires {req!r} — add `{req}: {{}}` to `extensions`"
                        if m is not None else f"extension {a.name!r} requires unknown extension {req!r}"
                    )
                chosen[req] = Active(m, validate_settings(m, {}), auto_added=True)
                changed = True

    slots = _fill_slots(chosen)
    for a in chosen.values():
        for kind, req in _requirements(a.manifest, ctx_of(a, slots)):
            if kind == "slot" and req not in slots:
                providers = sorted(n for n, m in manifests.items() if req in m.provides)
                raise ExtensionError(
                    f"extension {a.name!r} requires the {req!r} slot — add one of {providers} to `extensions`"
                )
        for c in a.manifest.raw.get("conflicts") or []:
            if c in chosen or c in slots:
                raise ExtensionError(f"extension {a.name!r} conflicts with {c!r}")
        for rule in a.manifest.raw.get("validate") or []:
            if when_matches(rule.get("when"), ctx_of(a, slots)) and "error" in rule:
                raise ExtensionError(f"extension {a.name!r}: {rule['error']}")
            req = rule.get("require")
            if req and when_matches(rule.get("when"), ctx_of(a, slots)) and not when_matches(req, ctx_of(a, slots)):
                raise ExtensionError(f"extension {a.name!r}: {rule.get('message', f'requires {req}')}")
    for req in sorted(REQUIRED_SLOTS):
        if req not in slots:
            providers = sorted(n for n, m in manifests.items() if req in m.provides)
            raise ExtensionError(
                f"no extension fills the required {req!r} slot — add one of {providers} to `extensions` "
                "(e.g. `llm: {provider: llama.cpp, location: host, endpoint: 127.0.0.1:8080, model: auto}`)"
            )
    return _toposort(chosen, slots, harness)


def _fill_slots(chosen: dict[str, Active]) -> dict[str, Active]:
    slots: dict[str, Active] = {}
    for a in chosen.values():
        for s in a.manifest.provides:
            if s in slots:
                raise ExtensionError(
                    f"extensions {slots[s].name!r} and {a.name!r} both provide the exclusive {s!r} slot — pick one"
                )
            slots[s] = a
    return slots


def _toposort(chosen: dict[str, Active], slots: dict[str, Active], harness: str) -> list[Active]:
    deps: dict[str, set[str]] = {}
    for a in chosen.values():
        ctx = when_context(a.settings, harness)
        d = set()
        for kind, req in _requirements(a.manifest, ctx):
            d.add(slots[req].name if kind == "slot" else req)
        d.discard(a.name)
        deps[a.name] = d
    order: list[Active] = []
    done: set[str] = set()
    visiting: set[str] = set()

    def visit(n: str) -> None:
        if n in done:
            return
        if n in visiting:
            raise ExtensionError(f"extension requirement cycle through {n!r}")
        visiting.add(n)
        for d in sorted(deps[n]):
            visit(d)
        visiting.discard(n)
        done.add(n)
        order.append(chosen[n])

    for n in sorted(chosen):
        visit(n)
    return order


def generate_secret() -> str:
    """A random per-launch secret for `default: generate` secret settings."""
    return pysecrets.token_urlsafe(18)  # 24 chars


# --- contributions --------------------------------------------------------------

# Logical network names an extension may use. The harness network (`net`) is
# core's alone; `llm` carries only inference forwarders; `hostgw` only
# host-gateway forwarders; `wan` only the active egress provider's containers;
# `lan` only the forwarders of `via: lan` endpoints (a named LAN host, never
# reached by the harness itself).
CORE_NETWORKS = {
    "net": {"internal": True},
    "egress": {"internal": True},
    "wan": {"internal": False},
    "llm": {"internal": False},
    "hostgw": {"internal": False},
    "lan": {"internal": False},
}
HOST_GATEWAY = "host.docker.internal"


def _endpoint(comp: Composition, a: Active, name: str, spec: dict) -> Endpoint:
    where = f"extension {a.name!r} endpoint {name!r}"
    if not _NAME.fullmatch(name):
        raise ExtensionError(f"{where}: name must match {_NAME.pattern}")
    t = spec.get("target") or {}
    harness = bool(spec.get("harness", True))
    listen = tuple(spec.get("listen_networks") or ())
    for net in listen:
        if net not in (a.manifest.raw.get("networks") or {}) and net != "egress":
            raise ExtensionError(f"{where}: listen network {net!r} is not declared by the extension")
    if "service" in t:
        svc = str(t["service"])
        net = t.get("network")
        if not net:
            raise ExtensionError(f"{where}: a service target needs the `network` the service is on")
        target = Target(scoped(comp.session, svc), int(t["port"]), "service", net)
    elif "slot" in t:
        slot = str(t["slot"])
        ex = comp.slot_exports(slot)
        if not ex.get("proxy_host"):
            raise ExtensionError(f"{where}: the {slot!r} slot is empty or exports no proxy_host")
        target = Target(str(ex["proxy_host"]), int(ex["proxy_port"]), "slot", str(ex.get("network", "egress")))
    elif "host_port" in t:
        require_trust(a, f"{where}: reaching a host port")
        target = Target(HOST_GATEWAY, int(t["host_port"]), "host", "hostgw")
    elif "address" in t:
        # a remote host:port: the inference provider over `llm`, the egress
        # provider over `wan` (e.g. corporate's raw TCP endpoints), or — over
        # `lan` — a host the user named, for a sidecar only (e.g. ssh)
        via = str(t.get("via", "llm"))
        if via == "lan":
            if harness:
                raise ExtensionError(f"{where}: a `via: lan` endpoint is for a sidecar (harness: false); "
                                     "the harness never reaches a LAN host itself")
        else:
            slot = {"llm": "inference", "wan": "egress"}.get(via)
            if slot is None or slot not in a.manifest.provides:
                raise ExtensionError(f"{where}: only the inference provider (via: llm), the egress provider "
                                     "(via: wan) or a sidecar's LAN host (via: lan) may dial a remote address")
        require_trust(a, f"{where}: dialling a remote address")
        host, _, port = str(t["address"]).rpartition(":")
        if not host or not port.isdigit():
            raise ExtensionError(f"{where}: address must be host:port, got {t['address']!r}")
        if via == "lan" and not lan_host(host):
            raise ExtensionError(
                f"{where}: a `via: lan` address must be a private IPv4 address (10/8, 172.16/12, "
                f"192.168/16) or a LAN name (one label, or under {', '.join(LAN_SUFFIXES)}), got {host!r}; "
                "`lan` is a direct route, so a public host would bypass the egress provider")
        target = Target(host, int(port), "remote", via)
    else:
        raise ExtensionError(f"{where}: target needs service|slot|host_port|address")
    interpose = bool(spec.get("interpose", False))
    if interpose and (harness or target.kind != "slot"):
        raise ExtensionError(f"{where}: `interpose` is for an egress consumer's hop (harness: false, target: slot)")
    return Endpoint(
        name=name, extension=a.name, port=int(spec.get("port", target.port)), target=target, harness=harness,
        listen_networks=listen, aliases=_aliases(spec.get("aliases"), where), observe=spec.get("observe"),
        interpose=interpose, interposed=interpose and comp.has_forwarder,
    )


_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\Z")

# What a `via: lan` endpoint may dial. `lan` is a routable, NAT'd bridge with no
# tunnel, so it must never carry a public host (that would bypass the egress
# provider, its DNS and the VPN): private IPv4 literals, or names that only a
# LAN resolver answers. Docker's own names (host.docker.internal, …) are the
# host, reached only by `host_port` over `hostgw`.
LAN_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
LAN_SUFFIXES = (".lan", ".local", ".home.arpa", ".internal")


def lan_host(host: str) -> bool:
    h = host.lower()
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        pass
    else:
        return ip.version == 4 and any(ip in n for n in LAN_NETWORKS)
    if not _HOSTNAME.fullmatch(h) or h == "localhost" or h.endswith(".docker.internal") or h == "docker.internal":
        return False
    if re.fullmatch(r"[0-9.]+", h):  # a malformed IPv4 literal, never a name
        return False
    return "." not in h or h.endswith(LAN_SUFFIXES)


def _aliases(items: Any, where: str) -> tuple[str, ...]:
    """Network aliases (DNS names on the harness network), rendered into compose as-is."""
    out = tuple(str(x) for x in items or ())
    bad = [x for x in out if not _HOSTNAME.fullmatch(x)]
    if bad:
        raise ExtensionError(f"{where}: aliases must be hostnames, got {bad!r}")
    return out


def require_trust(a: Active, what: str) -> None:
    if not a.manifest.trusted:
        raise ExtensionError(
            f"{what} is a privilege; out-of-tree extension {a.name!r} is not in `trusted_extensions` "
            "(~/.glove/config.yml)"
        )


def set_harness_env(comp: Composition, where: str, k: str, v: Any) -> None:
    """One harness env var from an extension (manifest or `contribute` hook):
    the key is rendered into compose as-is, so it must be a plain name."""
    if not isinstance(k, str) or not _ENV_VAR.fullmatch(k):
        raise ExtensionError(f"{where}: env key {k!r} must match {_ENV_VAR.pattern}")
    if k in comp.harness_env:
        raise ExtensionError(f"{where}: env {k!r} is already set by another extension")
    comp.harness_env[k] = str(v)


# `harness:` keys every extension may use; a harness's own name keys a section
# only its adapter reads (e.g. `pi: {extensions: [...]}`).
HARNESS_KEYS = frozenset({"image", "env", "git_config", "brief"}) | CONTRIBUTIONS


def _harness_contrib(comp: Composition, a: Active, ctx: dict) -> None:
    h = a.manifest.raw.get("harness") or {}
    where = f"extension {a.name!r} harness"
    allowed = HARNESS_KEYS | set(known_harnesses())
    for k in h:
        if k not in allowed:
            raise ExtensionError(f"{where}: unknown key {k!r} (known: {sorted(HARNESS_KEYS)} or a harness name)")
    profile = get_profile(comp.harness)
    image = h.get("image") or {}
    for key in ("*", comp.harness):
        for layer in active_items([image[key]] if isinstance(image.get(key), dict) else image.get(key), ctx):
            layer = render_value(layer, ctx, where)
            # a package name has no whitespace: a template may expand a list
            # setting into several ("{% for l in settings.x %}pkg-{{ l }} {% endfor %}")
            for k in ("apt", "pip", "npm"):
                if layer.get(k):
                    layer[k] = [p for item in layer[k] for p in str(item).split()]
            comp.image_layers.append((a.name, layer))
    for k, v in (h.get("env") or {}).items():  # a value, or {value:, when:} (unset unless it matches)
        if isinstance(v, dict):
            if set(v) - {"value", "when"} or "value" not in v:
                raise ExtensionError(f"{where}: env {k!r}: want a value or {{value: …, when: …}}")
            if not when_matches(v.get("when"), ctx):
                continue
            v = v["value"]
        if v is None:
            raise ExtensionError(f"{where}: env {k!r} has no value (use `when:` to leave it unset)")
        set_harness_env(comp, where, k, render_value(v, ctx, f"{where} env {k!r}"))
    comp.git_config += git_config_pairs(render_value(h.get("git_config"), ctx, where), f"{where} git_config")
    if profile.renders("skills"):
        for item in active_items(h.get("skills"), ctx):
            spec = render_value(item if isinstance(item, dict) else {"src": item}, ctx, where)
            if "mount" in spec:  # {mount: <name>, path: <rel>}: a skill in one of its mounts, if mounted
                if spec["mount"] not in a.mounts:
                    continue
                rel = str(spec.get("path", ""))
                host = next(h for e, h, t in comp.harness_mounts if e == a.name and t == a.mounts[spec["mount"]])
                bad = not rel or rel.startswith("/") or ".." in rel.split("/")
                if bad or not Path(host, rel, "SKILL.md").is_file():
                    raise ExtensionError(f"{where}: skill {rel!r} has no SKILL.md in mount {spec['mount']!r} ({host})")
                comp.skills.append((a.name, None, f"{a.mounts[spec['mount']]}/{rel}"))
                continue
            src = (a.manifest.path / str(spec["src"])).resolve()
            if not (src / "SKILL.md").is_file() or not src.is_relative_to(a.manifest.path.resolve()):
                raise ExtensionError(f"{where}: skill {spec['src']!r} needs a SKILL.md inside the extension")
            comp.skills.append((a.name, src, comp.skill_dest(a.name, src)))
    if profile.renders("mcp"):
        comp.mcp.extend((a.name, item) for item in render_value(active_items(h.get("mcp"), ctx), ctx, where))
    if h.get(comp.harness) is not None:
        comp.harness_items.append((a, h[comp.harness], ctx))
    brief = h.get("brief")
    if isinstance(brief, str | dict):
        for item in active_items([brief], ctx):
            path = a.manifest.path / render_value(item if isinstance(item, str) else item["file"], ctx, where)
            if not path.is_file():
                raise ExtensionError(f"{where}: brief {path} not found")
            # rendered late (rendered_briefs): launch-time resolution (e.g. the
            # llm's `model: auto`) changes what a brief says
            comp.briefs.append((a.name, path.read_text()))


def _harness_mounts(comp: Composition, a: Active, ctx: dict) -> None:
    """`mounts: {<name>: {setting: <path setting>, when: …}}` — a host directory
    the user named in a setting, bound read-only into the harness at
    /mnt/<ext>-<name>. An empty setting mounts nothing. Plan-time checks (it
    exists, exposes no private path) run in the planner, with the user's mounts."""
    settings = a.manifest.raw.get("settings") or {}
    for name, spec in (a.manifest.raw.get("mounts") or {}).items():
        where = f"extension {a.name!r} mount {name!r}"
        if not _NAME.fullmatch(str(name)) or not isinstance(spec, dict) or set(spec) - {"setting", "when"}:
            raise ExtensionError(f"{where}: want {{setting: <a path setting>, when: …}}")
        key = spec.get("setting")
        if (settings.get(key) or {}).get("type") != "path":
            raise ExtensionError(f"{where}: `setting` must name one of its `path` settings")
        if "default" in settings[key]:  # the user names every host dir the harness sees
            raise ExtensionError(f"{where}: setting {key!r} may not have a default")
        value = a.settings.get(key)
        if not value or not when_matches(spec.get("when"), ctx):
            continue
        try:
            host = host_path(comp.session_dir, str(value))
        except ValueError:
            raise ExtensionError(f"{where}: {a.name}.{key} must be an absolute path here") from None
        if not host.is_dir():
            raise ExtensionError(f"{where}: {a.name}.{key} = {value!r} is not a directory ({host})")
        target = f"/mnt/{a.name}-{name}"
        a.mounts[name] = target
        comp.harness_mounts.append((a.name, str(host), target))


def _channels(comp: Composition, a: Active, ctx: dict) -> None:
    """`channels: {<name>: {services: [<its service>, …], when: …}}` — a
    directory shared by the harness and those sidecars (`Channel`). A new edge
    into the harness, so a privilege: in-tree or trusted extensions only."""
    for name, spec in (a.manifest.raw.get("channels") or {}).items():
        where = f"extension {a.name!r} channel {name!r}"
        if not _NAME.fullmatch(str(name)) or not isinstance(spec, dict) or set(spec) - {"services", "when"}:
            raise ExtensionError(f"{where}: want {{services: [<service>, …], when: …}}")
        if not when_matches(spec.get("when"), ctx):
            continue
        services = spec.get("services") or []
        if not isinstance(services, list) or not services or not all(isinstance(x, str) for x in services):
            raise ExtensionError(f"{where}: `services` must name at least one of its services")
        require_trust(a, f"{where}: a directory shared with the harness")
        if any(c.name == name for c in comp.channels):
            raise ExtensionError(f"{where}: channel {name!r} is declared twice")
        comp.channels.append(Channel(name=str(name), extension=a.name, services=tuple(services)))


def _host_services(comp: Composition, a: Active, ctx: dict, items: list) -> None:
    for item in active_items(items, ctx):
        require_trust(a, f"extension {a.name!r}: a host service")
        r = render_value(item, ctx, f"extension {a.name!r} host service")
        comp.host_services.append(HostService(
            name=f"{a.name}-{r['name']}", command=str(r["command"]),
            ready_port=int(r["ready_port"]) if r.get("ready_port") not in (None, "") else None,
            keep=str(r.get("keep", False)).lower() in ("true", "1"),
        ))


def _hook_ctx(comp: Composition, a: Active) -> dict[str, Any]:
    ctx = base_context(comp, a)
    ctx["state_dir"] = comp.state_dir(a.name)
    ctx["session_dir"] = comp.session_dir
    ctx["active"] = [x.name for x in comp.active]
    ctx["forwarders"] = [dict(f) for f in comp.forwarders]
    ctx["grants"] = dict(comp.grants)
    return ctx


def compose(
    requested: dict[str, Any],
    *,
    harness: str,
    session: str,
    state_root: Path,
    manifests: dict[str, Manifest] | None = None,
    session_dir: Path | None = None,
    subnet: str | None = None,
    export_dirs: dict[str, Path] | None = None,
    work_dir: Path | None = None,
) -> Composition:
    """Select, order and render every extension's contribution for one session."""
    active = select(requested, harness=harness, manifests=manifests)
    comp = Composition(session=session, harness=harness, active=active, slots={}, state_root=state_root,
                       session_dir=session_dir, work_dir=work_dir, subnet=subnet,
                       export_dirs=dict(export_dirs or {}),
                       has_forwarder=any("forwarder" in a.manifest.provides for a in active))
    for a in active:
        if a.manifest.hooks_path:
            a.hooks = load_module(a.manifest.hooks_path, a.name)
        # Slot exports are visible to later extensions (topological order).
        ctx = base_context(comp, a)
        contributed: dict[str, Any] = {}
        if a.hooks is not None and hasattr(a.hooks, "contribute"):
            try:
                contributed = a.hooks.contribute(_hook_ctx(comp, a)) or {}
            except ExtensionError:
                raise
            except ValueError as e:
                raise ExtensionError(f"extension {a.name!r}: {e}") from e
        a.exports = {**render_value(a.manifest.raw.get("exports") or {}, ctx, f"extension {a.name!r} exports"),
                     **(contributed.get("exports") or {})}
        for s in a.manifest.provides:
            comp.slots[s] = a
        ctx = base_context(comp, a)
        for net, spec in (a.manifest.raw.get("networks") or {}).items():
            if net in CORE_NETWORKS or not when_matches((spec or {}).get("when"), ctx):
                continue
            if not (spec or {}).get("internal", True):
                raise ExtensionError(f"extension {a.name!r}: private network {net!r} must be internal")
            comp.networks[net] = {"internal": True, "owner": a.name}
        endpoints = {**(a.manifest.raw.get("endpoints") or {}), **(contributed.get("endpoints") or {})}
        for name, spec in endpoints.items():
            if not when_matches(spec.get("when"), ctx):
                continue
            ep = _endpoint(comp, a, name, render_value(spec, ctx, f"extension {a.name!r} endpoint {name!r}"))
            if any(e.name == ep.name for e in comp.endpoints):
                raise ExtensionError(f"endpoint {ep.name!r} is declared twice")
            comp.endpoints.append(ep)
            if ep.interpose and not ep.interposed:
                continue  # no hop rendered: its consumers dial the target directly
            for net in (ep.target.network, *ep.listen_networks):
                if net in CORE_NETWORKS and net != "net":
                    comp.networks.setdefault(net, {**CORE_NETWORKS[net], "owner": "core"})
        _harness_mounts(comp, a, base_context(comp, a))
        ctx = base_context(comp, a)
        _harness_contrib(comp, a, ctx)
        for k, v in (contributed.get("env") or {}).items():
            set_harness_env(comp, f"extension {a.name!r} contribute", k, v)
        _host_services(comp, a, ctx, [*(a.manifest.raw.get("host_services") or []),
                                      *(contributed.get("host_services") or [])])
        for item in active_items([*(a.manifest.raw.get("verify") or []), *(contributed.get("verify") or [])], ctx):
            if not isinstance(item, dict) or item.get("kind") not in VERIFY_KINDS:
                raise ExtensionError(f"extension {a.name!r}: verify {item!r} needs a kind in {sorted(VERIFY_KINDS)}")
            comp.verify.append((a.name, render_value(item, ctx, f"extension {a.name!r} verify")))
        for sname, setting in (a.manifest.raw.get("secrets") or {}).items():
            spec = setting if isinstance(setting, dict) else {"from": setting}
            if when_matches(spec.get("when"), ctx):
                comp.secrets[f"{a.name}-{sname}"] = (a.name, str(spec["from"]))
        _channels(comp, a, ctx)
        ctx["channel"] = {c.name: {"path": c.path} for c in comp.channels}  # for services fragments
        frag = a.manifest.raw.get("services")
        if frag:
            path = a.manifest.path / frag
            text = render_value(path.read_text(), ctx, f"extension {a.name!r} {frag}")
            doc = yaml.safe_load(text) or {}
            if not isinstance(doc, dict):
                raise ExtensionError(f"extension {a.name!r}: {frag} must render to a mapping")
            # Core networks a fragment joins exist for the session (who may
            # join which is checked when the fragment is hardened).
            for svc in (doc.get("services") or {}).values():
                nets = (svc or {}).get("networks") or []
                for net in nets if isinstance(nets, list) else nets.keys():
                    if net in CORE_NETWORKS and net != "net":
                        comp.networks.setdefault(net, {**CORE_NETWORKS[net], "owner": "core"})
            if any(doc.values()):  # a fragment whose `{% if %}` left nothing adds nothing
                comp.fragments.append((a, doc))
    return comp


# Where compose secrets appear in a sidecar. Not /run/secrets: podman's default
# mounts.conf mounts its subscription dir over /run/secrets at start, hiding
# the files compose copied in (verified on podman machine 6.1).
SECRETS_DIR = "/run/glove-secrets"


def secret_env_var(compose_name: str) -> str:
    return "GLOVE_SECRET_" + re.sub(r"[^A-Z0-9]", "_", compose_name.upper())


def resolve_secrets(comp: Composition, provided: dict[str, str] | None = None) -> dict[str, str]:
    """Env for `compose up`: every declared compose secret, resolved in memory
    (keychain:/env: refs) or generated per launch. Never written to a file.
    Secrets a `launch_env` hook already `provided` (by env var) are kept as is."""
    from .config import resolve_secret

    provided = provided or {}
    env: dict[str, str] = {}
    for cname, (ext, setting) in comp.secrets.items():
        var = secret_env_var(cname)
        if var in provided:
            env[var] = provided[var]
            continue
        a = comp.by_name(ext)
        value = a.settings.get(setting) if a else None
        if value in (None, ""):
            raise ExtensionError(f"extension {ext!r}: secret setting {setting!r} is not set")
        env[var] = generate_secret() if value == "generate" else resolve_secret(value)
    return env


# --- lifecycle hooks --------------------------------------------------------------
#
# Besides `contribute` (plan time, pure) and `resolve` (after the sidecars are
# up), an extension's hooks.py may define:
#   materialize(ctx)               — write its state under ctx["state_dir"] when the
#                                    session is rendered (`glove plan`/`up`, never `check`);
#   launch_env(ctx, resolve_secret) → {"secrets": {name: value}, "env": {VAR: value}}
#                                    — host-side work at `glove up`, in memory only
#                                    (e.g. the vpn register hook). `secrets` fill the
#                                    extension's own compose secrets; `env` fills
#                                    null-valued `environment:` keys of its sidecars;
#   diagnose(ctx, check, run)      → str | None — explain a failed verify check.



def materialize(comp: Composition) -> None:
    for a in comp.active:
        if a.hooks is not None and hasattr(a.hooks, "materialize"):
            ensure_dir(comp.state_dir(a.name))
            a.hooks.materialize(_hook_ctx(comp, a))


def launch_env(comp: Composition) -> dict[str, str]:
    """Run every `launch_env` hook; returns env for `compose` (secret values
    under their GLOVE_SECRET_* names). Held in memory by the caller only."""
    from .config import resolve_secret

    env: dict[str, str] = {}
    for a in comp.active:
        if a.hooks is None or not hasattr(a.hooks, "launch_env"):
            continue
        try:
            out = a.hooks.launch_env(_hook_ctx(comp, a), resolve_secret) or {}
        except ValueError as e:
            raise ExtensionError(f"extension {a.name!r}: {e}") from e
        own = {k.removeprefix(f"{a.name}-") for k, (ext, _) in comp.secrets.items() if ext == a.name}
        for name, value in (out.get("secrets") or {}).items():
            if name not in own:
                raise ExtensionError(f"extension {a.name!r}: launch hook returned undeclared secret {name!r}")
            env[secret_env_var(f"{a.name}-{name}")] = str(value)
        for var, value in (out.get("env") or {}).items():
            if not _ENV_VAR.fullmatch(var) or var.startswith("GLOVE_") or var in env:
                raise ExtensionError(f"extension {a.name!r}: launch hook returned a bad env name {var!r}")
            env[var] = str(value)
    return env


# The keys a `forwarder` hook's service may set. Core names it after the
# endpoint, joins its networks (the harness net with its aliases, the target's
# network) and applies the sidecar hardening set; privileges are never granted.
FORWARDER_KEYS = frozenset({
    "image", "command", "entrypoint", "environment", "volumes", "tmpfs", "depends_on", "healthcheck", "init",
    "restart", "stop_grace_period", "stop_signal", "labels",
})


def forwarder_service(comp: Composition, ep: dict[str, Any]) -> tuple[dict, dict, list[str]] | None:
    """(service fragment, facts, extra harness-net aliases) for one endpoint from
    the `forwarder` slot's hook — ``forwarder(ctx, endpoint) -> {service, facts,
    aliases} | None`` — or None: the endpoint stays a socat forwarder."""
    a = comp.slots.get("forwarder")
    if a is None or a.hooks is None or not hasattr(a.hooks, "forwarder"):
        return None
    try:
        out = a.hooks.forwarder(_hook_ctx(comp, a), ep)
    except ValueError as e:
        raise ExtensionError(f"extension {a.name!r}: endpoint {ep['name']!r}: {e}") from e
    if not out:
        return None
    svc = dict(out.get("service") or {})
    bad = set(svc) - FORWARDER_KEYS
    if bad:
        raise ExtensionError(f"extension {a.name!r}: forwarder for {ep['name']!r} sets {sorted(bad)} "
                             "(core owns names, networks and security keys)")
    prefix = f"{ep['container']}-"
    aliases = list(_aliases(out.get("aliases"), f"extension {a.name!r} forwarder"))
    if any(not x.startswith(prefix) for x in aliases):
        raise ExtensionError(f"extension {a.name!r}: forwarder aliases must start with {prefix!r}")
    return svc, dict(out.get("facts") or {}), aliases
