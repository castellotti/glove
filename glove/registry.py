"""Environment identity registry.

An *environment* is the unit of identity: the pair `(invocation_dir, harness)`,
where `invocation_dir` is the directory you run `glove` from (NOT the mounted
`/work` dir). `registry.json` under `~/.glove/` (or `$GLOVE_HOME`) is the source
of truth binding each pair to a stable, human-friendly `env-id`.

All config + state for an environment lives under `~/.glove/envs/<env-id>/`;
nothing is ever written into the invocation dir.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields
from pathlib import Path


def glove_home() -> Path:
    """Base dir for all glove state: `$GLOVE_HOME` or `~/.glove`."""
    root = os.environ.get("GLOVE_HOME")
    return Path(root) if root else Path.home() / ".glove"


def envs_root() -> Path:
    """`<glove_home>/envs` — one dir per `(invocation_dir, harness)` env."""
    return glove_home() / "envs"


def env_dir(env_id: str) -> Path:
    return envs_root() / env_id


def sessions_root(env_id: str) -> Path:
    """`<env_dir>/sessions` — one dir per `glove run … --name` session."""
    return env_dir(env_id) / "sessions"


def session_dir(env_id: str, session_name: str) -> Path:
    return sessions_root(env_id) / session_name


def session_token(env_id: str, session_name: str) -> str:
    """Compose-project token for a session: `<env>` for the default (unnamed)
    session, else `<env>-<name>`. The compose project is `glove-<token>`."""
    return env_id if session_name == env_id else f"{env_id}-{session_name}"


def registry_path() -> Path:
    return glove_home() / "registry.json"


class RegistryError(ValueError):
    """Raised for an invalid registry operation (e.g. an env-id name clash)."""


@dataclass
class EnvEntry:
    dir: str  # abs realpath of the invocation dir
    harness: str
    env_id: str
    # Resolved harness home (abs realpath), written back at `glove run` time.
    # `None` for envs registered before this field existed (back-compat) or
    # never yet run. External monitors (e.g. Layman) read this to locate an
    # env's transcript logs, falling back to `<env-id>/home` when it is None.
    home: str | None = None


def load_registry() -> list[EnvEntry]:
    path = registry_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    # Degrade, never crash, on entries a different glove build wrote: drop keys
    # this build doesn't know (forward-compat with future schema fields) and skip
    # entries missing a required one, rather than letting one bad row take out
    # every reader (external monitors read this file too).
    known = {f.name for f in fields(EnvEntry)}
    out: list[EnvEntry] = []
    for e in data:
        if not isinstance(e, dict):
            continue
        try:
            out.append(EnvEntry(**{k: v for k, v in e.items() if k in known}))
        except TypeError:
            continue
    return out


def save_registry(entries: list[EnvEntry]) -> None:
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(e) for e in entries], indent=2) + "\n")


@contextmanager
def _registry_lock():
    """Serialize registry read-modify-write across concurrent glove processes.

    Several `glove run`/`init` invocations can mutate `registry.json` at once; an
    unlocked load-modify-save would let a later writer clobber an earlier one's
    change. A sibling `.lock` file (never the registry itself, which may not
    exist yet) is held exclusively for the whole critical section.
    """
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with open(lock_path, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def _short(dir_real: str) -> str:
    return hashlib.sha1(dir_real.encode()).hexdigest()[:6]


def find_env_id(dir: str, harness: str) -> str | None:
    """The env-id bound to `(realpath(dir), harness)`, or None if unregistered."""
    dir_real = os.path.realpath(dir)
    for e in load_registry():
        if e.dir == dir_real and e.harness == harness:
            return e.env_id
    return None


def derive_env_id(entries: list[EnvEntry], dir_real: str, harness: str) -> str:
    """Simple-when-possible, deterministic given the registry.

    - basename if unused
    - `<base>-<harness>` when the basename is already held by the SAME dir
      (a second harness in one dir)
    - `<base>-<short(dir)>` on a cross-directory basename collision
    - append the other suffix, then a uuid as a last resort
    """
    base = os.path.basename(dir_real) or "env"
    used = {e.env_id for e in entries}
    if base not in used:
        return base

    holder = next((e for e in entries if e.env_id == base), None)
    if holder is not None and holder.dir == dir_real:  # noqa: SIM108 - ternary would be unreadable here
        candidate = f"{base}-{harness}"
    else:
        candidate = f"{base}-{_short(dir_real)}"
    if candidate not in used:
        return candidate

    combined = f"{base}-{harness}-{_short(dir_real)}"
    if combined not in used:
        return combined
    return f"{base}-{uuid.uuid4().hex[:8]}"


def create_env(dir: str, harness: str, *, name: str | None = None) -> str:
    """Register (or re-bind) `(dir, harness)` and return its env-id.

    An explicit `name` forces the env-id; otherwise it's derived. Any existing
    binding for the same `(dir, harness)` is replaced. A forced name already held
    by a *different* `(dir, harness)` is refused: an env-id owns the whole
    `~/.glove/envs/<env-id>/` tree (config, home, sessions, state), so two
    bindings cannot share one without clobbering each other.
    """
    dir_real = os.path.realpath(dir)
    with _registry_lock():
        entries = load_registry()
        if name is not None:
            env_id = name
            clash = next(
                (
                    e
                    for e in entries
                    if e.env_id == env_id and (e.dir, e.harness) != (dir_real, harness)
                ),
                None,
            )
            if clash is not None:
                raise RegistryError(
                    f"env-id {env_id!r} is already bound to {clash.harness} @ "
                    f"{clash.dir}; pick another --name"
                )
        else:
            env_id = derive_env_id(entries, dir_real, harness)
        # Re-binding the same (dir, harness) replaces its entry, but the resolved
        # `home` recorded by an earlier `glove run` is env state, not identity —
        # carry it forward so a re-`init` doesn't null the canonical pointer.
        prior = next(
            (e for e in entries if e.dir == dir_real and e.harness == harness), None
        )
        home = prior.home if prior is not None else None
        entries = [
            e for e in entries if not (e.dir == dir_real and e.harness == harness)
        ]
        entries.append(
            EnvEntry(dir=dir_real, harness=harness, env_id=env_id, home=home)
        )
        save_registry(entries)
    return env_id


def record_home(env_id: str, home: str) -> bool:
    """Persist the resolved harness `home` for the registered `env_id`.

    Returns True if the stored value changed. A no-op (False) when `env_id` has
    no registry entry — an ad-hoc `--config`-only run keyed by `--env` is not
    registered, so there is no canonical row to update (and Layman, which reads
    the registry, would not see such an env either way). Locked so overlapping
    `glove run` invocations don't clobber each other's updates.
    """
    with _registry_lock():
        entries = load_registry()
        changed = False
        for e in entries:
            if e.env_id == env_id and e.home != home:
                e.home = home
                changed = True
        if changed:
            save_registry(entries)
        return changed


def resolve_env_id(dir: str, harness: str, *, create: bool = False) -> str | None:
    """Existing env-id for `(dir, harness)`; create one when `create` is set."""
    existing = find_env_id(dir, harness)
    if existing is not None:
        return existing
    if not create:
        return None
    return create_env(dir, harness)
