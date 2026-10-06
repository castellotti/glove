"""Harness plugins: `harnesses/<name>/` beside `extensions/`.

Each harness is a directory with a declarative `harness.yml` (the profile:
image tag, TUI entry, config home, context file, resume flags, …), an
`image/` build context and an optional `adapter.py` that renders the harness's
native config. Core knows no harness by name: it reads the manifests and imports
an adapter by path only for the harness a session selected, so no other
harness's code runs.
"""

from __future__ import annotations

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
    "transcript_subdir", "runtime_paths", "pip", "resume", "contributions", "trusted_files",
    "masked_files", "protected_home", "version", "audited_version", "brief",
})
REQUIRED_KEYS = ("name", "image", "version", "audited_version", "entry", "config_home", "context_file")
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
    # Files under its working dir the harness loads its own config from (e.g.
    # Claude Code's project settings, whose `env` and commands it applies
    # outside ring 1), a trailing `/` marking a directory: ring 0 binds them
    # read-only (an empty placeholder when missing), so the agent cannot plant one.
    trusted_files: tuple[str, ...] = ()
    # Like trusted_files, but the harness never sees the working dir's own copy
    # (always the empty placeholder): config a repo could use against glove,
    # e.g. Vibe's project hooks, which run before glove's and can shadow it.
    masked_files: tuple[str, ...] = ()
    # What it loads from its own (writable) home, relative to the home; a
    # trailing `/` marks a directory: its settings, hooks and trust store, and
    # the dirs it loads code from. Ring 0 binds them read-only, so the agent
    # cannot reconfigure the harness or plant code in it for the next start.
    protected_home: tuple[str, ...] = ()
    # The harness release its image installs (the HARNESS_VERSION build arg).
    version: str = ""
    # What the agent should know about this harness under glove (`brief:`, a
    # markdown file in the harness dir), added to its context file.
    brief: str = ""
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
    version = str(raw["version"])
    if str(raw["audited_version"]) != version:
        raise ConfigError(f"{where}: version {version} has not been audited (audited_version: "
                          f"{raw['audited_version']}); a new release can add a dir it loads code or config "
                          "from — re-audit protected_home, trusted_files and masked_files, then set audited_version")
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
    for key, base in (("trusted_files", "working dir"), ("masked_files", "working dir"), ("protected_home", "home")):
        if key in raw:
            opt[key] = _strs(raw[key], f"{where} {key}")
            # a trailing `/` marks a directory; no other empty, `.` or `..` part
            if any(f.startswith("/") or {"", ".", ".."} & set(f.removesuffix("/").split("/")) for f in opt[key]):
                raise ConfigError(f"{where}: {key} are relative to the {base}, without '.' or '..'")
    if "brief" in raw:
        brief = (path / str(raw["brief"])).resolve()
        if not brief.is_relative_to(path.resolve()) or not brief.is_file():
            raise ConfigError(f"{where}: brief {raw['brief']!r} must be a file in the harness directory")
        opt["brief"] = brief.read_text().strip()
    return HarnessProfile(
        name=raw["name"], image=str(raw["image"]), entry=list(_strs(raw["entry"], f"{where} entry")),
        config_home_env=str(home["env"]), config_home_path=str(home["path"]),
        context_file=str(raw["context_file"]),
        default_env={str(k): str(v) for k, v in (raw.get("env") or {}).items()},
        pip_install=_strs(pip["install"], f"{where} pip.install") if "install" in pip else None,
        pip_bootstrap=_strs(pip.get("bootstrap") or [], f"{where} pip.bootstrap"),
        resume_continue=_strs(resume["continue"], f"{where} resume") if "continue" in resume else None,
        resume_session=_strs(resume["session"], f"{where} resume") if "session" in resume else None,
        contributions=contrib, version=version, path=path, **opt,
    )


def base_contexts(profile: HarnessProfile) -> list[tuple[str, Path]]:
    """What the base image is built from: its `image/` context, then the named
    build contexts every harness Dockerfile uses (glove-pty, the entrypoint)."""
    from .enforcers.base import ENTRYPOINT_DIR, PTY_DIR

    return [("image", profile.dockerfile.parent), ("glovepty", PTY_DIR), ("gloveentry", ENTRYPOINT_DIR)]


def base_image(profile: HarnessProfile) -> str:
    """The harness's base image tag: its version tag plus a hash of everything
    the base is built from (its build contexts and the harness release), so a
    changed base is rebuilt, and every image built on it follows."""
    from .image import content_hash

    return f"{profile.image}-{content_hash(profile.version, base_contexts(profile))}"


def effective_image(
    profile: HarnessProfile,
    apt_packages: list[str] | None = None,
    pip_packages: list[str] | None = None,
    derived: str | None = None,
) -> str:
    """Image tag for a profile, suffixed with a hash when extra packages or an
    extension-derived layer (``derived``: its content hash, see glove/image.py)
    are requested, so each distinct composition gets its own image. With
    nothing extra, returns the base tag."""
    apt_packages = apt_packages or []
    pip_packages = pip_packages or []
    base = base_image(profile)
    if not apt_packages and not pip_packages and not derived:
        return base
    from .image import content_hash

    payload = (
        "apt:" + ",".join(sorted(apt_packages))
        + "|pip:" + ",".join(sorted(pip_packages))
        + "|derived:" + (derived or "")
    )
    return f"{base}-{content_hash(payload, [])}"


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
