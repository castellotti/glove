"""Session registry: ``~/.glove/registry.json`` (v2).

A glove session is a directory (see ``glove/sessiondir.py``); the registry is
the index of them, keyed by the session id stored in ``<dir>/.glove/id``::

    {"v": 2, "sessions": [{id, dir, harness, template, created, grants, subnet}]}

External monitors (Layman) read it to list sessions and their grants. A row is
the only thing a deleted session directory leaves behind (plus what an
extension explicitly exported); ``glove gc`` removes both.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

REGISTRY_VERSION = 2


def glove_home() -> Path:
    """Base dir for all glove state: `$GLOVE_HOME` or `~/.glove`."""
    root = os.environ.get("GLOVE_HOME")
    return Path(root) if root else Path.home() / ".glove"


def ensure_home() -> list[str]:
    """Create the glove home and its ``control/`` as the invoking user
    (idempotent). Returns warnings for the caller to print.

    ``control/`` always exists alongside the home, because Layman decides when it
    starts whether to mount it, and must never create it itself (a missing bind
    source is created root-owned by Docker on Linux)."""
    home = glove_home()
    home.mkdir(parents=True, exist_ok=True)
    control = home / "control"
    control.mkdir(exist_ok=True)
    st = control.stat()
    if st.st_uid != os.getuid():
        return [
            f"{control} is owned by uid {st.st_uid}, not by you (uid {os.getuid()}): glove creates it, "
            f"and cannot create sessions' rules directories in it. Fix with: "
            f"sudo chown {os.getuid()}:{os.getgid()} {control}"]
    return []


def observe_dir(session_id: str) -> Path:
    """``~/.glove/observe/<id>/`` — the only session data kept outside its dir."""
    return glove_home() / "observe" / session_id


def control_dir(session_id: str) -> Path:
    """``~/.glove/control/<id>/`` — where ``rules.json`` lives."""
    return glove_home() / "control" / session_id


def registry_path() -> Path:
    return glove_home() / "registry.json"


class RegistryError(ValueError):
    """Raised for an unusable registry or an invalid registry operation."""


@dataclass
class SessionEntry:
    id: str
    dir: str  # abs realpath of the session directory
    harness: str
    template: str | None = None
    created: str | None = None  # ISO-8601 UTC
    # {"observe": {...} | None, "filter": {...} | None} (Layman handoff §4)
    grants: dict = field(default_factory=lambda: {"observe": None, "filter": None})
    subnet: str | None = None  # the session's /24 from the user's subnet pool


def _read() -> dict | None:
    path = registry_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        raise RegistryError(f"{path} is unreadable ({e}); fix or move it aside") from e
    if isinstance(data, list):
        raise RegistryError(
            f"{path} is a glove v2 registry (environments, not session directories). glove v3 does not "
            f"migrate or overwrite it: move it aside (e.g. `mv {path} {path.with_name('registry.v2.json')}`) "
            "and recreate sessions with `glove new`.")
    if not isinstance(data, dict) or data.get("v") != REGISTRY_VERSION:
        raise RegistryError(f"{path}: unsupported registry version {data.get('v') if isinstance(data, dict) else '?'}")
    return data


def load_registry() -> list[SessionEntry]:
    data = _read()
    if data is None:
        return []
    # Degrade, never crash, on rows a different glove build wrote: drop keys
    # this build doesn't know and skip rows missing a required one.
    known = {f.name for f in fields(SessionEntry)}
    out: list[SessionEntry] = []
    for e in data.get("sessions") or []:
        if not isinstance(e, dict):
            continue
        try:
            out.append(SessionEntry(**{k: v for k, v in e.items() if k in known}))
        except TypeError:
            continue
    return out


def save_registry(entries: list[SessionEntry]) -> None:
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"v": REGISTRY_VERSION, "sessions": [asdict(e) for e in entries]}, indent=2) + "\n")
    os.replace(tmp, path)  # readers (Layman) never see a half-written file


@contextmanager
def registry_lock():
    """Serialize registry read-modify-write across concurrent glove processes.

    A sibling `.lock` file (never the registry itself, which may not exist yet)
    is held exclusively for the whole critical section."""
    path = registry_path()
    ensure_home()
    lock_path = path.with_name(path.name + ".lock")
    with open(lock_path, "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def find(session_id: str) -> SessionEntry | None:
    return next((e for e in load_registry() if e.id == session_id), None)


def upsert(entry: SessionEntry) -> None:
    with registry_lock():
        entries = [e for e in load_registry() if e.id != entry.id]
        entries.append(entry)
        save_registry(entries)


def update(session_id: str, **changes) -> SessionEntry | None:
    """Change fields of one row; None when the id is not registered."""
    with registry_lock():
        entries = load_registry()
        row = next((e for e in entries if e.id == session_id), None)
        if row is None:
            return None
        for k, v in changes.items():
            setattr(row, k, v)
        save_registry(entries)
        return row


def remove(session_ids: set[str]) -> int:
    with registry_lock():
        entries = load_registry()
        kept = [e for e in entries if e.id not in session_ids]
        if len(kept) != len(entries):
            save_registry(kept)
        return len(entries) - len(kept)


def overlapping(subnets, others) -> str | None:
    """The first of ``subnets`` that overlaps any of ``others``."""
    nets = [ipaddress.ip_network(o, strict=False) for o in others]
    return next((x for x in subnets if any(ipaddress.ip_network(x, strict=False).overlaps(n) for n in nets)), None)


def allocate_subnet(pool: str, taken: set[str], prefix: int = 24) -> str:
    """The first /``prefix`` of ``pool`` overlapping none of ``taken`` (other
    sessions' subnets and the runtime's existing networks)."""
    try:
        net = ipaddress.ip_network(pool)
    except ValueError as e:
        raise RegistryError(f"subnet_pool {pool!r}: {e}") from e
    if net.version != 4 or net.prefixlen > prefix:
        raise RegistryError(f"subnet_pool {pool!r} must be an IPv4 network of /{prefix} or larger")
    used = [ipaddress.ip_network(t, strict=False) for t in taken if t]
    for sub in net.subnets(new_prefix=prefix):
        if not any(sub.overlaps(u) for u in used):
            return str(sub)
    raise RegistryError(f"subnet_pool {pool} is exhausted ({len(used)} sessions registered); "
                        "run `glove gc` or widen `subnet_pool` in ~/.glove/config.yml")
