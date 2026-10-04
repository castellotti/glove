"""Harness plugins: `harnesses/<name>/` beside `extensions/`.

Each harness is a directory with a declarative `harness.yml` (the profile:
image tag, TUI entry, config home, context file, resume flags, …), an
`image/` build context and an optional `adapter.py` that renders the harness's
native config. Core knows no harness by name: it reads the manifests and imports
an adapter by path only for the harness a session selected, so no other
harness's code runs.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml

from .config import ConfigError

HARNESSES_DIR = Path(__file__).resolve().parent.parent / "harnesses"
MANIFEST = "harness.yml"
MANIFEST_KEYS = frozenset({
    "api", "name", "summary", "image", "entry", "config_home", "context_file", "env", "sessions_subdir",
    "transcript_subdir", "runtime_paths", "pip", "resume", "contributions",
})
REQUIRED_KEYS = ("name", "image", "entry", "config_home", "context_file")
# Harness-neutral extension contributions a harness may render (`harness.<key>`
# in an extension manifest); see glove/extensions.py `_harness_contrib`.
CONTRIBUTIONS = frozenset({"mcp", "skills"})


@dataclass(frozen=True)
class HarnessProfile:
    name: str
    image: str  # image tag glove builds/uses
    entry: list[str]  # TUI entry command
    config_home_env: str  # env var pointing the harness at its config dir
    config_home_path: str  # in-container config dir (on a writable volume)
    context_file: str  # in-container path for the sudo-relay instruction
    # Where this harness writes its `*.jsonl` transcripts, relative to
    # `config_home_path`. sessions_dir joins this onto the host home.
    sessions_subdir: str = "sessions"
    # The directory observe's `transcripts: true` exports (relative to
    # `config_home_path`); None ⇒ this harness's transcripts are not exported.
    transcript_subdir: str | None = "sessions"
    default_env: dict[str, str] = field(default_factory=dict)
    # Read-only paths the harness's own interpreter/runtime needs beyond nono's
    # default system reads — e.g. the python venv or node prefix the entry binary
    # execs from. Added to the ring-1 *harness* profile's read list so `nono run`
    # can actually launch the TUI (its shebang/interpreter lives here). Omitting
    # them makes the harness exec fail with exit 127 under Landlock.
    runtime_paths: tuple[str, ...] = ("/usr/local",)
    # Command that installs Python packages into the image, for extension/user `pip`
    # layers. None ⇒ this harness ships no Python installer (a `pip` layer is an error).
    pip_install: tuple[str, ...] | None = None
    # apt packages a `pip` layer needs first (installed once, before the first
    # pip layer), for a base image without Python.
    pip_bootstrap: tuple[str, ...] = ()
    # Resume-flag mapping (see resume_args). `resume_continue` re-opens the most
    # recent session; `resume_session` re-opens a specific id — the literal
    # "{id}" token is replaced with the requested session id. None ⇒ the harness
    # can't resume that way, and resume_args raises.
    resume_continue: tuple[str, ...] | None = None
    resume_session: tuple[str, ...] | None = None
    # Neutral extension contributions it renders (subset of CONTRIBUTIONS).
    contributions: frozenset[str] = frozenset()
    # The plugin directory; None for a profile built in code (tests).
    path: Path | None = None

    @property
    def dockerfile(self) -> Path:
        return (self.path or HARNESSES_DIR / self.name) / "image" / "Dockerfile"

    def renders(self, contribution: str) -> bool:
        return contribution in self.contributions

    def resume_args(self, session_id: str | None) -> list[str]:
        """Harness flags to resume a session; raises if unsupported.

        `session_id is None` ⇒ continue the most recent session; otherwise
        re-open that specific id."""
        if session_id is None:
            if not self.resume_continue:
                raise ConfigError(
                    f"harness {self.name!r} does not support --resume"
                )
            return list(self.resume_continue)
        if not self.resume_session:
            raise ConfigError(
                f"harness {self.name!r} does not support --session"
            )
        return [session_id if p == "{id}" else p for p in self.resume_session]


def _strs(v: object, where: str) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"{where}: want a list of strings")
    return tuple(v)


def load_profile(path: Path) -> HarnessProfile:
    """A `HarnessProfile` from `<path>/harness.yml`."""
    where = f"{path / MANIFEST}"
    raw = yaml.safe_load((path / MANIFEST).read_text()) or {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: want a mapping")
    unknown = set(raw) - MANIFEST_KEYS
    missing = [k for k in REQUIRED_KEYS if k not in raw]
    if unknown or missing or raw.get("api") != 1:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}, missing {missing}, or api is not 1")
    if raw["name"] != path.name:
        raise ConfigError(f"{where}: name {raw['name']!r} must match its directory {path.name!r}")
    home = raw["config_home"]
    pip = raw.get("pip") or {}
    resume = raw.get("resume") or {}
    contrib = frozenset(_strs(raw.get("contributions") or [], f"{where} contributions"))
    if contrib - CONTRIBUTIONS:
        raise ConfigError(f"{where}: contributions must be among {sorted(CONTRIBUTIONS)}")
    # optional keys: set only when given, so the dataclass holds the defaults
    opt: dict[str, Any] = {}
    if "sessions_subdir" in raw:
        opt["sessions_subdir"] = str(raw["sessions_subdir"])
    if "transcript_subdir" in raw:
        opt["transcript_subdir"] = raw["transcript_subdir"]
    if "runtime_paths" in raw:
        opt["runtime_paths"] = _strs(raw["runtime_paths"], f"{where} runtime_paths")
    return HarnessProfile(
        name=raw["name"], image=str(raw["image"]), entry=list(_strs(raw["entry"], f"{where} entry")),
        config_home_env=str(home["env"]), config_home_path=str(home["path"]),
        context_file=str(raw["context_file"]),
        default_env={str(k): str(v) for k, v in (raw.get("env") or {}).items()},
        pip_install=_strs(pip["install"], f"{where} pip.install") if "install" in pip else None,
        pip_bootstrap=_strs(pip.get("bootstrap") or [], f"{where} pip.bootstrap"),
        resume_continue=_strs(resume["continue"], f"{where} resume") if "continue" in resume else None,
        resume_session=_strs(resume["session"], f"{where} resume") if "session" in resume else None,
        contributions=contrib, path=path, **opt,
    )


def effective_image(
    profile: HarnessProfile,
    apt_packages: list[str] | None = None,
    pip_packages: list[str] | None = None,
    derived: str | None = None,
) -> str:
    """Image tag for a profile, suffixed with a hash when extra packages or an
    extension-derived layer (``derived``: its content hash, see glove/image.py)
    are requested, so each distinct composition gets its own image. With
    nothing extra, returns the plain minimal base tag."""
    apt_packages = apt_packages or []
    pip_packages = pip_packages or []
    if not apt_packages and not pip_packages and not derived:
        return profile.image
    payload = (
        "apt:" + ",".join(sorted(apt_packages))
        + "|pip:" + ",".join(sorted(pip_packages))
        + "|derived:" + (derived or "")
    )
    digest = hashlib.sha1(payload.encode()).hexdigest()[:10]
    base, sep, tag = profile.image.rpartition(":")
    return f"{base}:{tag}-{digest}" if sep else f"{profile.image}-{digest}"


def known_harnesses() -> list[str]:
    return sorted(p.parent.name for p in HARNESSES_DIR.glob(f"*/{MANIFEST}"))


@cache
def get_profile(name: str) -> HarnessProfile:
    path = HARNESSES_DIR / name
    if "/" in name or name.startswith(".") or not (path / MANIFEST).is_file():
        raise ValueError(f"unknown harness {name!r}; known: {', '.join(known_harnesses())}")
    return load_profile(path)


@cache
def _adapter_module(path: Path) -> ModuleType | None:
    file = path / "adapter.py"
    if not file.is_file():
        return None
    spec = importlib.util.spec_from_file_location(f"glove_harness_{path.name.replace('-', '_')}", file)
    if spec is None or spec.loader is None:
        raise ConfigError(f"harness {path.name!r}: cannot load {file}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # the standard recipe: visible to tracebacks, pickling, tests
    spec.loader.exec_module(module)
    return module


def adapter_call(profile: HarnessProfile, name: str, *args, default=None, **kw):
    """Call `adapter.<name>(…)` (its `adapter.py`, imported on first use) when
    the harness defines it; else `default`."""
    fn = getattr(_adapter_module(profile.path) if profile.path is not None else None, name, None)
    return fn(*args, **kw) if fn is not None else default
