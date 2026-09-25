"""Host-side ``rules.json`` editing for ``glove net block|unblock|rules``.

The CLI and Layman write the **same file** by atomic rename, so each edit
re-reads it first rather than trusting a cached copy. Every write is validated
with the gate's own validator (``glove.netgate.policy``) before it lands, so the
CLI can never produce a file the gate would reject. Pure file I/O: no network,
no name resolution (a blocked hostname is a glob, never looked up).
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from .netgate.policy import PolicyError, validate
from .netgate.records import iso_utc, ulid
from .netgate.writer import write_json_atomic


def empty(env_id: str, session: str) -> dict:
    return {"v": 1, "env": env_id, "session": session, "updated_at": iso_utc(),
            "updated_by": "glove-cli", "default": "allow", "rules": []}


def load(path: Path, env_id: str, session: str) -> dict:
    """The current rules document (an empty one if the file is absent).

    Raises PolicyError when the existing file is invalid, rather than silently
    replacing someone else's (e.g. Layman's) broken write."""
    if not path.is_file():
        return empty(env_id, session)
    try:
        data = json.loads(path.read_text())
    except ValueError as e:
        raise PolicyError(f"{path} is not valid JSON ({e}); fix or remove it first") from e
    ruleset = validate(data, env=env_id, session=session)
    # both keys are optional in a valid file; fill them so callers can index
    data.setdefault("default", ruleset.default)
    data.setdefault("rules", [])
    return data


def save(path: Path, data: dict, env_id: str, session: str) -> None:
    data = {**data, "updated_at": iso_utc(), "updated_by": "glove-cli"}
    validate(data, env=env_id, session=session)  # never write what the gate would reject
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not write_json_atomic(path, data):
        raise OSError(f"could not write {path}")


def block_rule(target: str, *, port: int | None, terminate: bool, note: str | None,
               action: str = "block") -> dict:
    """A rule for a host glob, an IP, or a CIDR — decided by shape, not lookup."""
    try:
        ipaddress.ip_network(target, strict=False)
        match: dict = {"ip": target}
    except ValueError:
        match = {"host": target.lower()}
    if port is not None:
        match["port"] = port
    rule: dict = {"id": f"r_{ulid()}", "action": action, "match": match}
    if terminate:
        rule["terminate"] = True
    if note:
        rule["note"] = note
    return rule


def remove(data: dict, key: str) -> list[dict]:
    """Drop rules whose id equals ``key``, or whose host/ip match equals it."""
    keep, gone = [], []
    for r in data["rules"]:
        m = r.get("match", {})
        if key in (r.get("id"), m.get("host"), m.get("ip")) or m.get("host") == key.lower():
            gone.append(r)
        else:
            keep.append(r)
    data["rules"] = keep
    return gone
