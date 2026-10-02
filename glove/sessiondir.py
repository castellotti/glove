"""A glove session is a directory.

::

    <dir>/
      glove-session.yml   the one file the user edits (schema v3)
      work/               → /work (rw)
      local/              optional user-private host assets; never mounted
      .glove/             0700; only home/ and enforcer/ are ever mounted
        id                stable session id: <dirname>-<6 hex>
        compose.yml  effective.yml  baseline.yml  template.yml
        home/  enforcer/  ext/<name>/  placeholders/  host-logs/

Deleting the directory deletes the session; what outlives it is its registry
row and what an extension explicitly exported (``~/.glove/observe/<id>/``),
both removed by ``glove gc``. This module owns the layout, the id, the file
schema and ``glove new``'s materialization; ``glove/cli.py`` drives it.
"""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .config import Config, ConfigError, _coerce
from .enforcers.base import default_enforcer
from .exports import ensure_dir
from .mounts import host_path

SESSION_FILE = "glove-session.yml"
STATE_DIR = ".glove"
SCHEMA_VERSION = 3
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
PLACEHOLDER = "<set-me>"

# <dirname>-<6 hex>: a valid compose project suffix and Layman's SAFE_NAME.
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}-[0-9a-f]{6}$")

# Keys a v3 session file may hold. Everything else is refused, with a pointer
# for the v2 keys that v3 replaced.
FILE_KEYS = frozenset({
    "glove", "template", "harness", "enforcer", "runtime", "mounts", "limits", "extensions",
    "harness_config", "env", "brief", "corporate_ca", "tools", "enforcer_options", "apt_packages", "pip_packages",
    "protect_ide_files", "allow_root", "allow_sensitive", "host_services", "toolchains",
})
V2_KEYS = {
    "name": "the session is the directory; its id is in .glove/id",
    "workdir": "/work is the session's work/ directory",
    "add_dirs": "use `mounts: [{path: ..., mode: ro|rw}]`",
    "net": "network access comes only from extensions",
    "services": "forwarders come only from extensions",
    "observe": "network observability is an extension: `extensions: {observe: {}}` (plus `filter: {}` for rules)",
    "config_home_source": "the harness home is .glove/home",
    "host_setup": "use host_services",
    "provider": "set `runtime`",
    "rebuild": "pass `glove up --rebuild`",
}


class SessionError(ConfigError):
    """A missing, malformed or conflicting session directory."""


@dataclass(frozen=True)
class SessionDir:
    root: Path

    @property
    def file(self) -> Path:
        return self.root / SESSION_FILE

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def local(self) -> Path:
        return self.root / "local"

    @property
    def state(self) -> Path:
        return self.root / STATE_DIR

    @property
    def home(self) -> Path:
        return self.state / "home"

    @property
    def ext(self) -> Path:
        return self.state / "ext"

    @property
    def compose(self) -> Path:
        return self.state / "compose.yml"

    @property
    def effective(self) -> Path:
        return self.state / "effective.yml"

    @property
    def baseline(self) -> Path:
        return self.state / "baseline.yml"

    @property
    def template_record(self) -> Path:
        return self.state / "template.yml"

    def read_id(self) -> str | None:
        try:
            sid = (self.state / "id").read_text().strip()
        except OSError:
            return None
        return sid if ID_RE.match(sid) else None


def find(path: str | Path | None = None) -> SessionDir:
    """The session at ``path``, or the nearest one at/above the cwd."""
    if path is not None:
        root = Path(path).expanduser().resolve()
        if not (root / SESSION_FILE).is_file():
            raise SessionError(f"{root} is not a glove session (no {SESSION_FILE}); create one with "
                               f"`glove new <template> {path}`")
        return SessionDir(root)
    cwd = Path.cwd().resolve()
    for d in (cwd, *cwd.parents):
        if (d / SESSION_FILE).is_file():
            return SessionDir(d)
    raise SessionError(f"no {SESSION_FILE} in {cwd} or its parents; create a session with "
                       "`glove new <template> <dir>` (templates: " + ", ".join(list_templates()) + ")")


def sanitize(name: str) -> str:
    """A dirname as the id prefix: lowercase ``[a-z0-9_-]``, starting alnum."""
    s = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-_")
    return s[:40].rstrip("-_") or "session"


def new_id(dirname: str) -> str:
    return f"{sanitize(dirname)}-{secrets.token_hex(3)}"


def ensure_state(sd: SessionDir) -> tuple[str, bool]:
    """Create ``.glove/`` (0700) and its id if missing. Returns (id, created)."""
    ensure_dir(sd.state)
    ignore = sd.state / ".gitignore"
    if not ignore.exists():
        ignore.write_text("# glove session state: never commit\n*\n")
    sid = sd.read_id()
    if sid is not None:
        return sid, False
    sid = new_id(sd.root.name)
    (sd.state / "id").write_text(sid + "\n")
    return sid, True


# --- the session file -----------------------------------------------------------


def load_file(sd: SessionDir) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(sd.file.read_text())
    except (OSError, yaml.YAMLError) as e:
        raise SessionError(f"{sd.file}: {e}") from e
    if not isinstance(raw, dict):
        raise SessionError(f"{sd.file}: must be a mapping")
    if raw.get("glove") != SCHEMA_VERSION:
        raise SessionError(f"{sd.file}: needs `glove: {SCHEMA_VERSION}` (this is glove v3's session schema)")
    old = sorted(set(raw) & set(V2_KEYS))
    if old:
        raise SessionError(f"{sd.file}: v2 key(s) {old} are not part of the v3 schema — "
                           + "; ".join(f"{k}: {V2_KEYS[k]}" for k in old))
    unknown = sorted(set(raw) - FILE_KEYS)
    if unknown:
        raise SessionError(f"{sd.file}: unknown key(s) {unknown} (known: {sorted(FILE_KEYS)})")
    from .harness import known_harnesses

    harness = raw.get("harness")
    if harness not in known_harnesses():
        raise SessionError(f"{sd.file}: `harness` must be one of {known_harnesses()}, got {harness!r}")
    return raw


def _mount(sd: SessionDir, item: Any) -> tuple[str, str]:
    if isinstance(item, str):
        path, _, mode = item.rpartition(":") if item.endswith((":ro", ":rw")) else (item, "", "ro")
    elif isinstance(item, dict) and set(item) <= {"path", "mode"} and "path" in item:
        path, mode = str(item["path"]), str(item.get("mode", "ro"))
    else:
        raise SessionError(f"{sd.file}: bad mount {item!r} (want {{path: <dir>, mode: ro|rw}})")
    if mode not in ("ro", "rw"):
        raise SessionError(f"{sd.file}: mount {path!r}: mode must be ro|rw")
    host = host_path(sd.root, path)
    exposed = exposes_private(sd.root, host)
    if exposed:
        raise SessionError(f"{sd.file}: mount {path!r} would expose {exposed[1]} ({exposed[0]}) to the harness; "
                           "mount a directory that does not contain it")
    return str(host), mode


def exposes_private(root: Path | None, host: Path) -> tuple[Path, str] | None:
    """The private path a harness mount of `host` would expose, if any.

    Never glove's own state, the private local/ assets or the session file (the
    agent would rewrite its own grants) — including via an ancestor — nor
    glove's home (every session's exports and rules.json) or another registered
    session's state. Used for the session's `mounts:` and extensions' mounts."""
    from .registry import RegistryError, glove_home, load_registry

    private = [(glove_home(), "glove's home")]
    if root is not None:
        private += [(root / STATE_DIR, ".glove/"), (root / "local", "local/"), (root / SESSION_FILE, SESSION_FILE)]
    with contextlib.suppress(RegistryError):
        private += [(Path(e.dir) / STATE_DIR, f"session {e.id}'s state") for e in load_registry()]
    host = Path(os.path.realpath(host))
    for guarded, what in private:
        p = Path(os.path.realpath(guarded))
        if host == p or p.is_relative_to(host) or host.is_relative_to(p):
            return p, what
    return None


def autodetect_provider() -> str:
    return "podman" if not shutil.which("docker") and shutil.which("podman") else "docker"


def session_provider(sd: SessionDir, cfg: Config | None = None) -> str:
    """The compose provider the session last ran under (effective.yml), else its
    session file's runtime — never a guess from PATH while either says otherwise."""
    from .userconfig import load_user_config

    if cfg is not None:
        return cfg.provider
    try:
        runtime = load_file(sd).get("runtime") or load_user_config().runtime
    except ConfigError:
        return autodetect_provider()
    return runtime if runtime in ("docker", "podman") else autodetect_provider()


def to_config(sd: SessionDir, raw: dict[str, Any], session_id: str, *, subnet: str | None = None,
              default_runtime: str = "docker") -> Config:
    """The session file as the internal ``Config`` the planner consumes."""
    data = {k: v for k, v in raw.items() if k not in ("glove", "template", "mounts")}
    data.setdefault("runtime", default_runtime)
    data.setdefault("enforcer", default_enforcer(data["runtime"]))
    data["provider"] = data["runtime"] if data["runtime"] in ("docker", "podman") else "docker"
    data["add_dirs"] = [{"path": p, "mode": m} for p, m in (_mount(sd, x) for x in raw.get("mounts") or [])]
    data["name"] = session_id
    data["workdir"] = str(sd.work)
    data["subnet"] = subnet
    if data.get("extensions") is None:
        data["extensions"] = {}
    if not isinstance(data["extensions"], dict):
        raise SessionError(f"{sd.file}: `extensions` must be a mapping of name → settings")
    try:
        return _coerce(data)
    except (ConfigError, TypeError) as e:
        raise SessionError(f"{sd.file}: {e}") from e


# --- effective / baseline ----------------------------------------------------------


def write_effective(path: Path, cfg: Config, resolved: dict[str, Any] | None = None) -> None:
    """``effective.yml``: the resolved config plus launch-time resolutions
    (e.g. llm ``model: auto``). Secret settings are references, never values."""
    doc = {"config": cfg.to_dict(), "resolved": resolved or {}}
    path.write_text(yaml.safe_dump(doc, sort_keys=False))


def read_effective(path: Path) -> tuple[Config | None, dict[str, Any]]:
    try:
        doc = yaml.safe_load(path.read_text()) or {}
        return _coerce(doc.get("config") or {}), doc.get("resolved") or {}
    except (OSError, yaml.YAMLError, ConfigError, TypeError, AttributeError):
        return None, {}


# --- templates ------------------------------------------------------------------------


def list_templates() -> list[str]:
    if not TEMPLATES_DIR.is_dir():
        return []
    return sorted(d.name for d in TEMPLATES_DIR.iterdir() if (d / SESSION_FILE).is_file())


def _is_git_url(spec: str) -> bool:
    return spec.startswith(("https://", "http://", "ssh://", "git@", "file://")) or spec.endswith(".git")


def read_template(spec: str) -> tuple[str, str]:
    """(template text, canonical source) for an in-tree name, a path to a
    directory or file, or a git URL (shallow-cloned to a temp dir)."""
    if _is_git_url(spec):
        with tempfile.TemporaryDirectory(prefix="glove-template-") as tmp:
            r = subprocess.run(["git", "clone", "--depth", "1", "--quiet", "--", spec, tmp],
                               capture_output=True, text=True, check=False)
            if r.returncode != 0:
                raise SessionError(f"cannot clone template {spec}: {r.stderr.strip()[-300:]}")
            f = Path(tmp) / SESSION_FILE
            if not f.is_file():
                raise SessionError(f"template {spec} has no {SESSION_FILE} at its root")
            return f.read_text(), spec
    p = Path(spec).expanduser()
    if "/" in spec or spec.startswith(".") or p.is_absolute():
        f = p / SESSION_FILE if p.is_dir() else p
        if not f.is_file():
            raise SessionError(f"no template at {spec} (expected a directory with {SESSION_FILE}, or the file)")
        return f.read_text(), str(f.resolve())
    f = TEMPLATES_DIR / spec / SESSION_FILE
    if not f.is_file():
        raise SessionError(f"unknown template {spec!r}; bundled: {', '.join(list_templates()) or '(none)'}; "
                           "or pass a path or git URL")
    return f.read_text(), spec


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def materialize(spec: str, dest: Path) -> tuple[SessionDir, str]:
    """``glove new``: copy the template's session file, create ``work/`` and
    ``.glove/`` (with a fresh id). Returns (session dir, id)."""
    text, source = read_template(spec)
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SessionError(f"template {spec}: {e}") from e
    if not isinstance(raw, dict) or raw.get("glove") != SCHEMA_VERSION:
        raise SessionError(f"template {spec}: not a glove v{SCHEMA_VERSION} session file")
    dest = dest.expanduser().resolve()
    sd = SessionDir(dest)
    if sd.file.exists():
        raise SessionError(f"{sd.file} already exists; this directory is already a session")
    if sd.state.exists():
        raise SessionError(f"{sd.state} already exists; remove it or pick another directory")
    dest.mkdir(parents=True, exist_ok=True)
    sd.file.write_text(text)
    sd.work.mkdir(exist_ok=True)
    sid, _ = ensure_state(sd)
    sd.template_record.write_text(yaml.safe_dump({"source": source, "sha256": digest(text)}, sort_keys=False))
    return sd, sid


def template_drift(sd: SessionDir) -> tuple[str, str] | None:
    """(source, unified diff session-file ← current template) when the template
    changed since ``glove new``; None when unchanged or unknown."""
    try:
        rec = yaml.safe_load(sd.template_record.read_text()) or {}
        text, _ = read_template(str(rec["source"]))
    except (OSError, yaml.YAMLError, KeyError, TypeError, SessionError):
        return None
    if digest(text) == rec.get("sha256"):
        return None
    diff = difflib.unified_diff(sd.file.read_text().splitlines(keepends=True), text.splitlines(keepends=True),
                                fromfile=f"{SESSION_FILE} (yours)", tofile=f"template {rec['source']} (now)")
    return str(rec["source"]), "".join(diff)


def placeholders_left(raw: Any, path: str = "") -> list[str]:
    """Dotted paths of every ``<set-me>`` still in the session file."""
    if isinstance(raw, dict):
        return [p for k, v in raw.items() for p in placeholders_left(v, f"{path}.{k}" if path else str(k))]
    if isinstance(raw, list):
        return [p for i, v in enumerate(raw) for p in placeholders_left(v, f"{path}[{i}]")]
    return [path] if isinstance(raw, str) and PLACEHOLDER in raw else []


def remove_state(sd: SessionDir) -> None:
    shutil.rmtree(sd.state)
