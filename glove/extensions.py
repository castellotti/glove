"""Extensions: manifest loading, settings, slots and composition (api: 2).

An extension is a directory holding ``extension.yml`` plus assets (compose
fragment, Pi extensions, brief, container code, an optional ``hooks.py`` and
``cli.py``). First-party extensions live in-tree under ``extensions/``; more may
load from ``extension_paths`` in ``~/.glove/config.yml``, marked *out-of-tree*
(the Linux "taint") and refused privilege exceptions unless listed in
``trusted_extensions``.

Core never imports an extension: ``hooks.py``/``cli.py`` load by path as
modules of a package ``glove_ext.<name>`` (``load_module``), and ``uv run
lint-imports`` forbids ``glove`` → ``extensions``. The schema is
``glove/manifest.py``; the hook protocol ``glove/hooks.py``.

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
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml
from jinja2 import StrictUndefined, TemplateError
from jinja2.sandbox import ImmutableSandboxedEnvironment

from .config import HostService, git_config_pairs, is_secret_ref
from .exports import ensure_dir
from .harness import CONTRIBUTIONS, get_profile, known_harnesses
from .hooks import HookContext, hooks_of, validate_result
from .manifest import KEYS, ExtensionError, check_manifest, check_slot_exports, merge_names
from .mounts import WORK_TARGET, check_path, host_path
from .naming import project_name, scoped
from .sessiondir import PLACEHOLDER
from .userconfig import load_user_config
from .verify import KINDS as VERIFY_KINDS
from .verify import item_error as verify_item_error

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

SETTING_TYPES = frozenset({"string", "enum", "bool", "int", "number", "list", "map", "secret", "path"})
_NAME = re.compile(r"^[a-z][a-z0-9-]*\Z")
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")  # one path component, never `..`
_ENV_VAR = re.compile(r"^[A-Z][A-Z0-9_]*\Z")


# A channel's directory in the harness and in the sidecars that serve it (see
# `Channel`).
CHANNEL_ROOT = "/run/glove"


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
    check_manifest(name, raw)
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
    """Import an extension's `hooks.py`/`cli.py` by path, as a module of the
    package `glove_ext.<name>` on its directory: it imports its own files
    relatively (`from . import relay_policy`)."""
    pkg = f"glove_ext.{name.replace('-', '_')}"
    root = next((d for d in path.parents if (d / MANIFEST).is_file()), path.parent)
    sys.modules.setdefault("glove_ext", ModuleType("glove_ext")).__path__ = []
    sys.modules.setdefault(pkg, ModuleType(pkg)).__path__ = [str(root)]  # the extension's own directory
    spec = importlib.util.spec_from_file_location(f"{pkg}.{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ExtensionError(f"extension {name!r}: cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up there
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
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
    """The value at `dotted`, or None. A `*` part matches every key of a
    mapping, and the result is then the list of what was found below it
    (`settings.plugins.*.relay`: the plugins' relays)."""
    parts = dotted.split(".")
    found: list[Any] = [ctx]
    for part in parts:
        found = [v for cur in found if isinstance(cur, dict)
                 for v in (cur.values() if part == "*" else [cur[part]] if part in cur else [])]
    if "*" in parts:
        return [v for v in found if v not in (None, "", [], {})]
    return found[0] if found else None


def when_matches(when: dict[str, Any] | None, ctx: dict[str, Any]) -> bool:
    """Minimal predicate: every key's value equals (or is in, for a list) the
    context value. Keys are setting names, `harness`, `renders` (the harness's
    contributions, a list: it matches when it holds a wanted one) or dotted
    (`slot.<s>.<k>`; a `*` part matches any key, as in `settings.plugins.*.relay`,
    and gives the list of values found). `{set: true|false}` asks whether the value is set (not null
    or empty). `any: [<when>, …]` matches when one of its predicates does."""
    if not when:
        return True
    for key, want in when.items():
        if key == "any":
            if not isinstance(want, list) or not any(when_matches(w, ctx) for w in want):
                return False
            continue
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


def _entry_active(ctx: dict[str, Any]):
    """Whether a mapping entry's `when:` matches (for `merge_names`)."""
    return lambda spec: when_matches(spec.get("when") if isinstance(spec, dict) else None, ctx)


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
    a Unix socket) and the sidecar answers them. A `read_only` channel is
    written by its sidecars only: the harness and its commands just read it.
    `trust` names a file in it holding a CA the harness trusts (e.g. llm-auth's
    session CA; core wires the trust, see `Composition.trusted_cas`)."""

    name: str
    extension: str
    services: tuple[str, ...]
    read_only: bool = False
    trust: str | None = None

    @property
    def path(self) -> str:
        return f"{CHANNEL_ROOT}/{self.name}"

    def volume(self, session: str) -> str:
        return scoped(session, f"chan-{self.name}")


@dataclass(frozen=True)
class Output:
    """A directory beside the session's work dir (`<session>/<name>/`) that
    some of the extension's sidecars write (at `path`) and the harness reads,
    read-only, at /work/<name> (`target`; e.g. web_download's files). An
    `input` is the reverse (`inputs:`): the harness writes it at /work/<name>
    and its sidecars read it, read-only, at the same path (e.g. files the
    browser may upload). The agent never holds the host path, so it cannot swap
    it for a link that the bind would follow when a sidecar restarts — unlike a
    subdirectory of /work."""

    extension: str
    name: str
    host: Path
    services: tuple[str, ...]
    input: bool = False

    @property
    def path(self) -> str:
        return self.target if self.input else f"{OUTPUT_ROOT}/{self.name}"

    @property
    def target(self) -> str:
        return f"{WORK_TARGET}/{self.name}"


# beside the outputs in the session dir
RESERVED_OUTPUTS = frozenset({"work", "local"})
OUTPUT_ROOT = "/run/glove-output"  # where an output's sidecars write it


@dataclass
class Active:
    """One selected extension, resolved."""

    manifest: Manifest
    settings: dict[str, Any]
    auto_added: bool = False
    exports: dict[str, Any] = field(default_factory=dict)
    hooks: dict[str, Any] = field(default_factory=dict)  # its `@hook` functions by name
    mounts: dict[str, str] = field(default_factory=dict)  # mount name → container path
    # what its `contribute` hook returned (plan time), for the keys core reads
    # beside the manifest's (`spec`)
    contributed: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.manifest.name

    def spec(self, key: str) -> Any:
        """A manifest key with what its `contribute` hook added (`KEYS` says
        how; a name both set is refused)."""
        mine, more = self.manifest.raw.get(key), self.contributed.get(key)
        if KEYS[key].merge == "cat":
            return [*(mine or []), *(more or [])]
        return merge_names(f"extension {self.name!r} {key}", mine, more)

    def set_exports(self, exports: dict[str, Any]) -> None:
        """Its exports, checked against the schema of each slot it provides."""
        for s in self.manifest.provides:
            check_slot_exports(s, self.name, exports)
        self.exports = exports


@dataclass
class Composition:
    session: str
    harness: str
    active: list[Active]
    slots: dict[str, Active]
    state_root: Path
    endpoints: list[Endpoint] = field(default_factory=list)
    harness_env: dict[str, str] = field(default_factory=dict)
    # harness env vars the harness process reads and shell commands never see
    # (`env: {…, shell: false}`; the tool wrapper unsets them, enforcers.base.scrub_argv;
    # `enforcer: none` has no wrapper)
    shell_hidden_env: set[str] = field(default_factory=set)
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
    outputs: list[Output] = field(default_factory=list)
    host_services: list[HostService] = field(default_factory=list)
    networks: dict[str, dict] = field(default_factory=dict)  # logical name → {internal, owner}
    fragments: list[tuple[Active, dict]] = field(default_factory=list)  # rendered compose docs
    secrets: dict[str, tuple[str, str]] = field(default_factory=dict)  # compose name → (ext, setting)
    verify: list[tuple[str, dict]] = field(default_factory=list)
    privileges: dict[str, list[dict]] = field(default_factory=dict)  # "ext/service" → exceptions
    # The session directory (hooks only — never a template) and its /24.
    session_dir: Path | None = None
    # The harness's /work on the host: a trusted extension's sidecar binds all
    # of it with the `work` privilege (github), never a path inside it.
    work_dir: Path | None = None
    # The session's validated `corporate_ca` PEM on the host (symlinks
    # resolved): core binds it into the sidecars a manifest's `trust:` names.
    corporate_ca: Path | None = None
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
        """The writable channels' directories in the harness: writable under
        every enforcer and profile (they carry no network)."""
        return [c.path for c in self.channels if not c.read_only]

    @property
    def read_channel_paths(self) -> list[str]:
        """The read-only channels' directories: readable under every enforcer."""
        return [c.path for c in self.channels if c.read_only]

    @property
    def trusted_cas(self) -> list[str]:
        """CA certificates the harness trusts, published in read-only channels."""
        return [f"{c.path}/{c.trust}" for c in self.channels if c.trust]

    def slot_exports(self, slot: str) -> dict[str, Any]:
        a = self.slots.get(slot)
        return dict(a.exports) if a else {}

    def state_dir(self, ext: str) -> Path:
        return self.state_root / ext

    def outputs_of(self, ext: str) -> list[Output]:
        return [o for o in self.outputs if o.extension == ext]

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

    def skill_links(self) -> list[tuple[str, str]]:
        """(link name, container path) per contributed skill, for a harness
        that loads skills from one directory of links; a name taken by an
        earlier skill gets its extension's prefix (and a number, if need be)."""
        out: dict[str, str] = {}
        for ext, _src, dest in self.skills:
            name = base = Path(dest).name
            n = 1
            while name in out:  # never overwrite one: `<ext>-<name>`, then `<ext>-<name>-2`, …
                name = f"{ext}-{base}" + (f"-{n}" if n > 1 else "")
                n += 1
            out[name] = dest
        return list(out.items())

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
        # the extension's `outputs:`/`inputs:`: where its sidecars see each, and where the harness does
        **{key: {o.name: {"path": o.path, "target": o.target} for o in comp.outputs_of(a.name) if o.input == inp}
           for key, inp in (("output", False), ("input", True))},
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
    and return the extensions in dependency order."""
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


_TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]+\Z")  # an MCP server's or a tool's name
# what an `mcp:` item may say: fields every harness renders alike, never one
# harness's own (auth, headers, timeouts)
MCP_FIELDS = {"stdio": {"command", "args", "env"}, "http": {"url"}}


def tool_names(where: str, tools: Any) -> list[str]:
    """A list of tool names, or a comma-separated string of them, as names."""
    if not isinstance(tools, str | list) or not all(isinstance(t, str) for t in tools):
        raise ExtensionError(f"{where}: want a list of tool names, or a comma-separated string")
    names = [t.strip() for t in (tools.split(",") if isinstance(tools, str) else tools) if t.strip()]
    if bad := [n for n in names if not _TOOL_NAME.fullmatch(n)]:
        raise ExtensionError(f"{where}: {bad}: letters, digits, '_' and '-' only")
    return names


def mcp_server(where: str, item: Any) -> dict[str, Any]:
    """One rendered `mcp:` item, checked: `transport` set (`stdio` or `http`;
    `streamable-http` is `http`), `args` strings, `tools`/`all_tools` lists
    (absent when unset)."""
    name = item.get("name") if isinstance(item, dict) else None
    if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name):
        raise ExtensionError(f"{where}: an mcp item needs a name of letters, digits, '_' and '-', got {item!r}")
    where = f"{where} mcp {name!r}"
    server = dict(item)
    t = item.get("transport", "stdio")
    transport = server["transport"] = "http" if t == "streamable-http" else t
    if not isinstance(t, str) or transport not in MCP_FIELDS:
        raise ExtensionError(f"{where}: transport is stdio or http, got {t!r}")
    allowed = {"name", "transport", "tools", "all_tools"} | MCP_FIELDS[transport]
    if extra := sorted(server.keys() - allowed):
        raise ExtensionError(f"{where}: {extra} aren't {transport} fields every harness renders alike "
                             f"(it takes {', '.join(sorted(allowed))})")
    required = "url" if transport == "http" else "command"
    if not isinstance(server.get(required), str) or not server[required]:
        raise ExtensionError(f"{where}: needs a {required}")
    if "args" in server:
        if not isinstance(args := server["args"], list) or not all(isinstance(x, str | int | float) for x in args):
            raise ExtensionError(f"{where}: args is a list of strings")
        server["args"] = [str(x) for x in args]
    if "env" in server:
        env = server["env"]
        if not isinstance(env, dict) or not all(_ENV_VAR.fullmatch(str(k)) and isinstance(v, str | int | float)
                                                for k, v in env.items()):
            raise ExtensionError(f"{where}: env maps names ({_ENV_VAR.pattern}) to strings")
        server["env"] = {k: str(v) for k, v in env.items()}
    for k in ("tools", "all_tools"):
        if server.get(k) is None:
            server.pop(k, None)
        else:
            server[k] = tool_names(f"{where} {k}", server[k])
    return server


# `harness:` keys every extension may use; a harness's own name keys a section
# only its adapter reads (e.g. `pi: {extensions: [...]}`).
HARNESS_KEYS = frozenset({"image", "env", "git_config", "brief"}) | CONTRIBUTIONS


def _harness_contrib(comp: Composition, a: Active, ctx: dict, contributed: dict[str, Any]) -> None:
    """The manifest's `harness:` section, plus what a `contribute` hook
    returned for it: `image` layers (only these may `copy_host`: host paths
    the hook checked), `env`, `skills` (container paths of SKILL.md dirs in the
    image) and `mcp` items, each taken as is (never rendered)."""
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
            if "copy_host" in layer:
                raise ExtensionError(f"{where}: image `copy_host` comes only from a contribute hook")
            comp.image_layers.append((a.name, layer))
    comp.image_layers += [(a.name, layer) for layer in contributed.get("image") or []]
    # a value, or {value:, when:, shell:} (unset unless `when` matches; `shell: false`
    # hides it from shell commands)
    for k, v in (h.get("env") or {}).items():
        shell = True
        if isinstance(v, dict):
            shell = v.get("shell", True)
            if set(v) - {"value", "when", "shell"} or "value" not in v or not isinstance(shell, bool):
                raise ExtensionError(f"{where}: env {k!r}: want a value or {{value: …, when: …, shell: false}}")
            if not when_matches(v.get("when"), ctx):
                continue
            v = v["value"]
        if v is None:
            raise ExtensionError(f"{where}: env {k!r} has no value (use `when:` to leave it unset)")
        set_harness_env(comp, where, k, render_value(v, ctx, f"{where} env {k!r}"))
        if not shell:
            comp.shell_hidden_env.add(k)
    for k, v in (contributed.get("env") or {}).items():
        set_harness_env(comp, f"extension {a.name!r} contribute", k, v)
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
        comp.skills += [(a.name, None, str(dest)) for dest in contributed.get("skills") or []]
    if profile.renders("mcp"):
        for item in [*render_value(active_items(h.get("mcp"), ctx), ctx, where), *(contributed.get("mcp") or [])]:
            server = mcp_server(where, item)
            if any(s["name"] == server["name"] for _, s in comp.mcp):
                raise ExtensionError(f"{where}: mcp server {server['name']!r} is already set by another extension")
            comp.mcp.append((a.name, server))
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


def _outputs(comp: Composition, a: Active, ctx: dict, key: str = "outputs") -> None:
    """`outputs: {<name>: {services: [<its service>, …], when: …}}` — see
    `Output`. Core binds it into those services (rw) and the harness (ro);
    `inputs:` (key) the other way round. A new edge into the harness, so a
    privilege: in-tree or trusted extensions only."""
    for name, spec in (a.manifest.raw.get(key) or {}).items():
        where = f"extension {a.name!r} {key[:-1]} {name!r}"
        if not _NAME.fullmatch(str(name)) or not isinstance(spec, dict) or set(spec) - {"services", "when"}:
            raise ExtensionError(f"{where}: want {{services: [<service>, …], when: …}}")
        if not when_matches(spec.get("when"), ctx):
            continue
        services = spec.get("services") or []
        if not isinstance(services, list) or not services or not all(isinstance(x, str) for x in services):
            raise ExtensionError(f"{where}: `services` must name at least one of its services")
        require_trust(a, f"{where}: a directory shared with the harness")
        if comp.session_dir is None or comp.work_dir is None:
            raise ExtensionError(f"{where}: needs a session directory (with a work dir)")
        if name in RESERVED_OUTPUTS or any(o.name == name for o in comp.outputs):
            raise ExtensionError(f"{where}: the name is taken")
        comp.outputs.append(Output(a.name, name, comp.session_dir / name, tuple(services), key == "inputs"))


def _channels(comp: Composition, a: Active, ctx: dict) -> None:
    """`channels: {<name>: {services: [<its service>, …], read_only: <bool>,
    trust: <file>, when: …}}` — a directory shared by the harness and those
    sidecars (`Channel`). A new edge into the harness, so a privilege: in-tree
    or trusted extensions only."""
    channels = merge_names(f"extension {a.name!r} channels", a.manifest.raw.get("channels"),
                           a.contributed.get("channels"),
                           active=_entry_active(ctx))
    for name, spec in channels.items():
        where = f"extension {a.name!r} channel {name!r}"
        if (not _NAME.fullmatch(str(name)) or not isinstance(spec, dict)
                or set(spec) - {"services", "read_only", "trust", "when"}
                or not isinstance(spec.get("read_only", False), bool)
                or ("trust" in spec and not (spec.get("read_only") and _FILE_NAME.fullmatch(str(spec["trust"]))))):
            raise ExtensionError(f"{where}: want {{services: [<service>, …], read_only: <bool>, "
                                 "trust: <a file name, in a read_only channel>, when: …}}")
        if not when_matches(spec.get("when"), ctx):
            continue
        services = spec.get("services") or []
        if not isinstance(services, list) or not services or not all(isinstance(x, str) for x in services):
            raise ExtensionError(f"{where}: `services` must name at least one of its services")
        require_trust(a, f"{where}: a directory shared with the harness")
        if any(c.name == name for c in comp.channels):
            raise ExtensionError(f"{where}: channel {name!r} is declared twice")
        comp.channels.append(Channel(name=str(name), extension=a.name, services=tuple(services),
                                     read_only=spec.get("read_only", False), trust=spec.get("trust")))


def _host_services(comp: Composition, a: Active, ctx: dict) -> None:
    """What its contribute hook returned for `host_services` (R16.C moves them
    into playwright)."""
    for item in active_items(a.contributed.get("host_services"), ctx):
        require_trust(a, f"extension {a.name!r}: a host service")
        r = render_value(item, ctx, f"extension {a.name!r} host service")
        comp.host_services.append(HostService(
            name=f"{a.name}-{r['name']}", command=str(r["command"]),
            ready_port=int(r["ready_port"]) if r.get("ready_port") not in (None, "") else None,
            keep=str(r.get("keep", False)).lower() in ("true", "1"),
        ))


def declares_host_paths(m: Manifest, *, work: bool = False) -> bool:
    """Whether a hook of `m` gets the session dir (or, with `work`, the work
    dir) in its context: trusted, and its manifest names a reason — outputs
    or inputs, `host_files: true`, and a `path` setting or `mounts` (session
    dir) or a `work` privilege (work dir)."""
    raw = m.raw
    if not m.trusted:
        return False
    if raw.get("host_files") or raw.get("outputs") or raw.get("inputs"):
        return True
    if work:
        return any(isinstance(p, dict) and p.get("work") for v in (raw.get("privileges") or {}).values()
                   for p in (v if isinstance(v, list) else [v]))
    return bool(raw.get("mounts")) or any(isinstance(x, dict) and x.get("type") == "path"
                                          for x in (raw.get("settings") or {}).values())


_SHARED = ("harness", "session", "names", "slot", "endpoint", "own_endpoints", "images", "libs", "mount", "output",
           "input")


def hook_context(comp: Composition, a: Active) -> HookContext:
    """`a`'s hook context: see `HookContext`."""
    t = base_context(comp, a)
    forwarder = comp.slots.get("forwarder") is a
    return HookContext(
        name=a.name, settings=a.settings, renders=t["renders"], trusted=a.manifest.trusted,
        active=[x.name for x in comp.active], state_dir=comp.state_dir(a.name), assets=a.manifest.path,
        session_dir=comp.session_dir if declares_host_paths(a.manifest) else None,
        work_dir=comp.work_dir if declares_host_paths(a.manifest, work=True) else None,
        export_dirs={r: comp.export_dirs[r] for r in comp.export_access(a) if r in comp.export_dirs},
        forwarders=[dict(f) for f in comp.forwarders] if forwarder else [],
        grants=dict(comp.grants) if forwarder else {},
        **{k: t[k] for k in _SHARED},
    )


def call_hook(comp: Composition, a: Active, name: str, *args: Any) -> Any:
    """Run `a`'s hook `name` (None when it has none) and check what it
    returned. A `ValueError` (`ConfigError`) it raises names the extension and
    hook; anything else is a bug, and propagates with a note saying where."""
    fn = a.hooks.get(name)
    if fn is None:
        return None
    if not any(x is a for x in comp.active):
        raise ExtensionError(f"extension {a.name!r} is not selected: its hooks never run")
    try:
        out = fn(hook_context(comp, a), *args)
    except ExtensionError:
        raise
    except ValueError as e:
        raise ExtensionError(f"extension {a.name!r}: {name}: {e}") from e
    except Exception as e:
        e.add_note(f"(in the {name} hook of extension {a.name!r})")
        raise
    return validate_result(name, a.name, out)


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
    corporate_ca: Path | None = None,
) -> Composition:
    """Select, order and render every extension's contribution for one session."""
    active = select(requested, harness=harness, manifests=manifests)
    comp = Composition(session=session, harness=harness, active=active, slots={}, state_root=state_root,
                       session_dir=session_dir, work_dir=work_dir, corporate_ca=corporate_ca, subnet=subnet,
                       export_dirs=dict(export_dirs or {}),
                       has_forwarder=any("forwarder" in a.manifest.provides for a in active))
    for a in active:
        if a.manifest.hooks_path:
            a.hooks = hooks_of(load_module(a.manifest.hooks_path, a.name), a.name)
        # Slot exports are visible to later extensions (topological order).
        ctx = base_context(comp, a)
        a.contributed = contributed = call_hook(comp, a, "contribute") or {}
        where = f"extension {a.name!r}"
        a.spec("privileges")  # no name set twice
        if not all(isinstance(x, str) for x in a.spec("trust")):
            raise ExtensionError(f"{where}: `trust` lists its services")
        a.set_exports(merge_names(f"{where} exports",
                                  render_value(a.manifest.raw.get("exports") or {}, ctx, f"{where} exports"),
                                  contributed.get("exports")))
        comp.slots.update(dict.fromkeys(a.manifest.provides, a))
        ctx = base_context(comp, a)
        for net, spec in (a.manifest.raw.get("networks") or {}).items():
            if net in CORE_NETWORKS or not when_matches((spec or {}).get("when"), ctx):
                continue
            if not (spec or {}).get("internal", True):
                raise ExtensionError(f"extension {a.name!r}: private network {net!r} must be internal")
            comp.networks[net] = {"internal": True, "owner": a.name}
        endpoints = merge_names(f"{where} endpoints", a.manifest.raw.get("endpoints"), contributed.get("endpoints"),
                                active=_entry_active(ctx))
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
        _outputs(comp, a, ctx)
        _outputs(comp, a, ctx, "inputs")
        _harness_mounts(comp, a, base_context(comp, a))
        ctx = base_context(comp, a)
        _harness_contrib(comp, a, ctx, contributed.get("harness") or {})
        _host_services(comp, a, ctx)
        for item in active_items(a.spec("verify"), ctx):
            if not isinstance(item, dict) or item.get("kind") not in VERIFY_KINDS:
                raise ExtensionError(f"extension {a.name!r}: verify {item!r} needs a kind in {sorted(VERIFY_KINDS)}")
            comp.verify.append((a.name, render_value(item, ctx, f"extension {a.name!r} verify")))
        for sname, setting in (a.manifest.raw.get("secrets") or {}).items():
            spec = setting if isinstance(setting, dict) else {"from": setting}
            if when_matches(spec.get("when"), ctx):
                comp.secrets[f"{a.name}-{sname}"] = (a.name, str(spec["from"]))
        _channels(comp, a, ctx)
        ctx["channel"] = {c.name: {"path": c.path} for c in comp.channels}  # for services fragments
        ctx["vars"] = contributed.get("vars") or {}  # what its contribute hook computed for them
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
        _check_verify(a, comp.verify, set((doc.get("services") or {}) if frag else ()))
    return comp


def _check_verify(a: Active, checks: list[tuple[str, dict]], services: set[str]) -> None:
    """Each of the extension's checks has its kind's fields, and one that runs a
    command (`argv`) runs it in one of the extension's own sidecars (never the
    harness, never another extension's: it may hold a credential)."""
    for ext, item in checks:
        if ext != a.name:
            continue
        where = f"extension {a.name!r}: verify {item.get('name')!r}"
        if err := verify_item_error(item):
            raise ExtensionError(f"{where}: {err}")
        if item.get("kind") != "exec-ok" and "argv" not in item and item.get("source") != "exec":
            continue
        argv = item.get("argv")
        if item.get("service") not in services or not isinstance(argv, list) or not argv or not all(
                isinstance(x, str) for x in argv):
            raise ExtensionError(f"{where}: {item.get('kind')} needs `service`, one of its own ({sorted(services)}), "
                                 "and `argv`, a list of strings")


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
# up), an extension's hooks.py may define (`docs/extensions.md`):
#   materialize(ctx)               — write its state under ctx.state_dir when the
#                                    session is rendered (`glove plan`/`up`, never `check`);
#   launch_env(ctx, resolve_secret) → {"secrets": {name: value}, "env": {VAR: value}}
#                                    — host-side work at `glove up`, in memory only
#                                    (e.g. the vpn register hook). `secrets` fill the
#                                    extension's own compose secrets; `env` fills
#                                    null-valued `environment:` keys of its sidecars;
#   diagnose(ctx, check, run)      → str | None — explain a failed verify check;
#   doctor(ctx, probe)             → [(name, status, detail)] — `glove doctor`/`check`.


def materialize(comp: Composition) -> None:
    for o in comp.outputs:
        check_path(str(comp.session_dir), o.name, "dir")
        o.host.mkdir(mode=0o755, exist_ok=True)
    for a in comp.active:
        if "materialize" in a.hooks:
            ensure_dir(comp.state_dir(a.name))
            call_hook(comp, a, "materialize")


def launch_env(comp: Composition) -> dict[str, str]:
    """Run every `launch_env` hook; returns env for `compose` (secret values
    under their GLOVE_SECRET_* names). Held in memory by the caller only."""
    from .config import resolve_secret

    env: dict[str, str] = {}
    for a in comp.active:
        if "launch_env" not in a.hooks:
            continue
        out = call_hook(comp, a, "launch_env", resolve_secret)
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


def forwarder_service(comp: Composition, ep: dict[str, Any]) -> tuple[dict, dict, list[str]] | None:
    """(service fragment, facts, extra harness-net aliases) for one endpoint from
    the `forwarder` slot's hook — ``forwarder(ctx, endpoint) -> {service, facts,
    aliases} | None`` — or None: the endpoint stays a socat forwarder."""
    a = comp.slots.get("forwarder")
    out = call_hook(comp, a, "forwarder", ep) if a is not None else None
    if not out:
        return None
    svc = dict(out.get("service") or {})
    prefix = f"{ep['container']}-"
    aliases = list(_aliases(out.get("aliases"), f"extension {a.name!r} forwarder"))
    if any(not x.startswith(prefix) for x in aliases):
        raise ExtensionError(f"extension {a.name!r}: forwarder aliases must start with {prefix!r}")
    return svc, dict(out.get("facts") or {}), aliases
