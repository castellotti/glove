"""A glove session is a directory.

::

    <dir>/
      glove-session.yml   the one file the user edits (schema v3)
      work/               → /work (rw)
      local/              optional user-private host assets; never mounted
      skills/             optional plugin/skill checkouts (the `skills` extension
                          bakes a filtered copy); never mounted
      .glove/             0700; only home/ and enforcer/ are ever mounted
        id                stable session id: <dirname>-<6 hex>
        compose.yml  effective.yml  baseline.yml  template.yml
        home/  enforcer/  ext/<name>/  placeholders/

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

from .config import Config, ConfigError, _coerce, load_yaml
from .enforcers.base import default_enforcer
from .exports import ensure_dir
from .mounts import host_path, overlaps

SESSION_FILE = "glove-session.yml"
STATE_DIR = ".glove"
SCHEMA_VERSION = 3
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
PLACEHOLDER = "<set-me>"

# <dirname>-<6 hex>: a valid compose project suffix and Layman's SAFE_NAME (`_`: older ids).
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}-[0-9a-f]{6}\Z")

# Keys a v3 session file may hold. Everything else is refused, with a pointer
# for the keys round 16 moved into extensions.
FILE_KEYS = frozenset({
    "glove", "template", "harness", "enforcer", "runtime", "mounts", "limits", "extensions", "harness_config",
    "env", "git_config", "brief", "corporate_ca", "tools", "enforcer_options", "apt_packages", "pip_packages",
    "protect_ide_files", "allow_root", "allow_sensitive",
})
MOVED_KEYS = {
    "host_services": "a session starts no host processes; `playwright: {mode: host}` runs the host's Chrome",
    "toolchains": "an extension now: `extensions: {toolchains: {blocks: [...]}}`",
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
    """A dirname as the id prefix: lowercase ``[a-z0-9-]`` (a hostname: it names aliases)."""
    s = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return s[:40].rstrip("-") or "session"


def new_id(dirname: str) -> str:
    return f"{sanitize(dirname)}-{secrets.token_hex(3)}"


def ensure_private(sd: SessionDir) -> Path:
    """``.glove/``, created 0700 and git-ignored if missing."""
    ensure_dir(sd.state)
    ignore = sd.state / ".gitignore"
    if not ignore.exists():
        ignore.write_text("# glove session state: never commit\n*\n")
    return sd.state


def ensure_state(sd: SessionDir) -> str:
    """Create ``.glove/`` (0700), its id and ``work/`` (a hand-copied template) if missing; returns the id."""
    ensure_private(sd)
    sd.work.mkdir(exist_ok=True)
    if (sid := sd.read_id()) is None:
        sid = new_id(sd.root.name)
        (sd.state / "id").write_text(sid + "\n")
    return sid


# --- the session file -----------------------------------------------------------


def load_file(sd: SessionDir) -> dict[str, Any]:
    try:
        raw = load_yaml(sd.file.read_text())
    except (OSError, yaml.YAMLError) as e:
        raise SessionError(f"{sd.file}: {e}") from e
    if not isinstance(raw, dict):
        raise SessionError(f"{sd.file}: must be a mapping")
    if raw.get("glove") != SCHEMA_VERSION:
        raise SessionError(f"{sd.file}: needs `glove: {SCHEMA_VERSION}` (this is glove v3's session schema)")
    old = sorted(set(raw) & set(MOVED_KEYS))
    if old:
        raise SessionError(f"{sd.file}: key(s) {old} are no longer session keys — "
                           + "; ".join(f"{k}: {MOVED_KEYS[k]}" for k in old))
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

    Never glove's own state, the private local/ assets, the skills/ checkouts
    (baked, filtered, by the `skills` extension) or the session file (the
    agent would rewrite its own grants) — including via an ancestor — nor
    glove's home (every session's exports and rules.json) or another registered
    session's state. Used for the session's `mounts:` and extensions' mounts."""
    from .registry import RegistryError, glove_home, load_registry

    private = [(glove_home(), "glove's home")]
    if root is not None:
        private += [(root / STATE_DIR, ".glove/"), (root / "local", "local/"), (root / "skills", "skills/"),
                    (root / SESSION_FILE, SESSION_FILE)]
    with contextlib.suppress(RegistryError):
        private += [(Path(e.dir) / STATE_DIR, f"session {e.id}'s state") for e in load_registry()]
    for guarded, what in private:
        if overlaps(host, guarded):
            return Path(os.path.realpath(guarded)), what
    return None


def autodetect_provider() -> str:
    return "podman" if not shutil.which("docker") and shutil.which("podman") else "docker"


def session_provider(sd: SessionDir, cfg: Config | None = None) -> str:
    """The compose provider the session last ran under (effective.yml), else its
    session file's runtime — never a guess from PATH while either says otherwise."""
    from .runtimes import known_runtimes
    from .userconfig import load_user_config

    if cfg is not None:
        return cfg.provider
    try:
        runtime = load_file(sd).get("runtime") or load_user_config().runtime
    except ConfigError:
        return autodetect_provider()
    return runtime if runtime in known_runtimes() else autodetect_provider()


def to_config(sd: SessionDir, raw: dict[str, Any], session_id: str, *, subnet: str | None = None,
              default_runtime: str = "docker") -> Config:
    """The session file as the internal ``Config`` the planner consumes."""
    from .runtimes import known_runtimes

    data = {k: v for k, v in raw.items() if k not in ("glove", "template", "mounts")}
    data.setdefault("runtime", default_runtime)
    if data["runtime"] not in (runtimes := known_runtimes()):
        raise SessionError(f"{sd.file}: `runtime` must be one of {runtimes}, got {data['runtime']!r}")
    data.setdefault("enforcer", default_enforcer(data["runtime"]))
    data["provider"] = data["runtime"]
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
        doc = load_yaml(path.read_text()) or {}
        # an older glove's record may hold keys Config has since dropped
        known = {k: v for k, v in (doc.get("config") or {}).items() if k in Config.__dataclass_fields__}
        resolved = doc.get("resolved")
        return _coerce(known), resolved if isinstance(resolved, dict) else {}
    except (OSError, yaml.YAMLError, ConfigError, TypeError, AttributeError):
        return None, {}


# --- templates ------------------------------------------------------------------------


def list_templates() -> list[str]:
    if not TEMPLATES_DIR.is_dir():
        return []
    return sorted(d.name for d in TEMPLATES_DIR.iterdir() if (d / SESSION_FILE).is_file())


def _is_git_url(spec: str) -> bool:
    return spec.startswith(("https://", "http://", "ssh://", "git@", "file://")) or spec.endswith(".git")


@contextlib.contextmanager
def _template_file(spec: str):
    """(the template's session file, canonical source, template dir) for an
    in-tree name, a path to a directory or file, or a git URL (shallow-cloned to
    a temp dir, removed on exit). The dir is None for a path to a bare file:
    whatever sits beside it is not the template's."""
    if _is_git_url(spec):
        with tempfile.TemporaryDirectory(prefix="glove-template-") as tmp:
            r = subprocess.run(["git", "clone", "--depth", "1", "--quiet", "--", spec, tmp],
                               capture_output=True, text=True, check=False)
            if r.returncode != 0:
                raise SessionError(f"cannot clone template {spec}: {r.stderr.strip()[-300:]}")
            f = Path(tmp) / SESSION_FILE
            if not f.is_file():
                raise SessionError(f"template {spec} has no {SESSION_FILE} at its root")
            yield f, spec, f.parent
        return
    p = Path(spec).expanduser()
    if "/" in spec or spec.startswith(".") or p.is_absolute():
        f = p / SESSION_FILE if p.is_dir() else p
        if not f.is_file():
            raise SessionError(f"no template at {spec} (expected a directory with {SESSION_FILE}, or the file)")
        yield f, str(f.resolve()), p if p.is_dir() else None
        return
    f = TEMPLATES_DIR / spec / SESSION_FILE
    if not f.is_file():
        raise SessionError(f"unknown template {spec!r}; bundled: {', '.join(list_templates()) or '(none)'}; "
                           "or pass a path or git URL")
    yield f, spec, f.parent


def read_template(spec: str) -> tuple[str, str]:
    """(template text, canonical source): see `_template_file`."""
    with _template_file(spec) as (f, source, _):
        return f.read_text(), source


def _template_local(tdir: Path | None, spec: str) -> list[Path]:
    """The entries of a template directory's `local/` (private host assets, e.g.
    a hook script or a CA certificate), parents first. A symlink (local/ itself,
    or in it) is refused: it could copy any host file into the session."""
    local = tdir / "local" if tdir else None
    if local is None or not (local.is_dir() or local.is_symlink()):
        return []
    entries = [] if local.is_symlink() else sorted(local.rglob("*"))
    if local.is_symlink() or any(p.is_symlink() for p in entries):
        raise SessionError(f"template {spec}: local/ is or holds a symlink; copy the files themselves")
    return entries


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def materialize(spec: str, dest: Path) -> tuple[SessionDir, str]:
    """``glove new``: copy the template's session file (and its ``local/``),
    create ``work/`` and ``.glove/`` (with a fresh id). Returns (session dir, id)."""
    with _template_file(spec) as (f, source, tdir):
        text = f.read_text()
        local = _template_local(tdir, spec)
        try:
            raw = load_yaml(text)
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
        if local:
            (dest / "local").mkdir(mode=0o700, exist_ok=True)
        for entry in local:  # parents first; never over a file already there
            target = dest / "local" / entry.relative_to(tdir / "local")
            if entry.is_dir():
                target.mkdir(exist_ok=True)
            elif not target.exists():
                shutil.copy2(entry, target)
        sid = ensure_state(sd)
        sd.template_record.write_text(yaml.safe_dump({"source": source, "sha256": digest(text)}, sort_keys=False))
        return sd, sid


def template_drift(sd: SessionDir) -> tuple[str, str] | None:
    """(source, unified diff session-file ← current template) when the template
    changed since ``glove new``; None when unchanged or unknown."""
    try:
        rec = load_yaml(sd.template_record.read_text()) or {}
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
