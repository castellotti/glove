"""Export roots: the only session data kept outside the session directory (§3.4).

- ``~/.glove/observe/<id>/`` — owned by the in-tree ``observe`` extension: its
  collector writes ``net/``; with ``transcripts: true`` core binds
  ``transcripts/`` over the harness's transcript directory.
- ``~/.glove/control/<id>/`` — exists only while the in-tree ``filter``
  extension is active: ``rules.json``, read-only in every gate.

Core creates them (as the invoking user, 0700), refuses a render in which any
harness bind could reach ``net/`` or ``control/``, writes the ``grants`` Layman
reads, and revokes ``control/<id>/`` when ``filter`` is removed (its
``rules.json`` moves to ``.glove/ext/filter/rules.revoked.json``).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .hardening import HardeningError

if TYPE_CHECKING:
    from .extensions import Composition
    from .plan import SessionPlan


def export_dirs(session_id: str) -> dict[str, Path]:
    from .registry import control_dir, observe_dir

    return {"observe": observe_dir(session_id), "control": control_dir(session_id)}


def ensure_dir(path: Path) -> Path:
    """Create ``path`` as the invoking user, mode 0700. Sidecars that bind it run
    as this same uid:gid, so this is what lets them write (or read) it.

    A directory someone else created (e.g. a root-run Layman on native Linux
    Docker, which the ownership contract forbids) cannot be chmod'ed back; say
    so rather than fail with a bare EPERM."""
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path, 0o700)
    except PermissionError as e:
        # the leaf, or the nearest existing parent we could not create it in.
        # os.path.exists, not Path.exists: on 3.11/3.12 the latter re-raises
        # EACCES when a foreign 0700 parent can't be searched.
        owned = next(p for p in (path, *path.parents) if os.path.exists(p))
        st = owned.stat()
        raise HardeningError(
            f"{owned} is owned by uid {st.st_uid}, not by you (uid {os.getuid()}): glove creates it, and "
            f"the session's sidecars run as your uid and need it. Fix with: sudo chown "
            f"{os.getuid()}:{os.getgid()} {owned} (handoff §3, 'Ownership')"
        ) from e
    return path


def transcripts_wanted(comp: Composition | None) -> bool:
    owner = comp.owner("observe") if comp is not None else None
    return bool(owner is not None and owner.exports.get("transcripts"))


def grants(comp: Composition | None, prev: dict | None = None, *, now: str | None = None) -> dict[str, Any]:
    """``grants`` for ``session.json`` and the registry row (Layman handoff §4).
    ``prev`` (the registry row's) keeps a filter grant's ``since``."""
    from datetime import UTC, datetime

    observe = comp.owner("observe") if comp is not None else None
    filt = comp.owner("control") if comp is not None else None
    if observe is None:
        return {"observe": None, "filter": None}
    out: dict[str, Any] = {"observe": {"net": True, "transcripts": transcripts_wanted(comp)}}
    if filt is None:
        out["filter"] = {"granted": False}
    else:
        since = ((prev or {}).get("filter") or {}).get("since")
        if not ((prev or {}).get("filter") or {}).get("granted") or not since:
            since = now or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        out["filter"] = {"granted": True, "since": since}
    return out


def prepare(comp: Composition, state_root: Path) -> list[str]:
    """Create what the active owners need; revoke ``control/<id>/`` if ``filter``
    is gone. Returns notes for the caller to print."""
    notes: list[str] = []
    dirs = comp.export_dirs
    if comp.owner("observe") is not None:
        ensure_dir(dirs["observe"])
        if transcripts_wanted(comp):
            ensure_dir(dirs["observe"] / "transcripts")
    control = dirs.get("control")
    if control is None:
        return notes
    if comp.owner("control") is not None:
        ensure_dir(control)
    elif control.exists():
        rules = control / "rules.json"
        if rules.is_file():
            keep = state_root / "filter"
            ensure_dir(keep)
            shutil.move(str(rules), keep / "rules.revoked.json")
            notes.append(f"filter removed: {rules} moved to {keep / 'rules.revoked.json'}")
        shutil.rmtree(control)
        notes.append(f"filter access revoked: removed {control}")
    return notes


def _within(child: str, parent: str) -> bool:
    return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)


def validate_export_isolation(plan: SessionPlan) -> None:
    """Refuse to render if the agent could see or write its own flow record or
    rules. No harness bind may share a path with ``observe/<id>/net`` or
    ``control/<id>``; only the transcripts bind may sit inside the observe root.
    A harness bind at or above ``net/`` would let the agent read its surveillance
    record; one inside it would let the agent forge it. Not waivable."""
    comp = plan.composition
    if comp is None or not comp.export_dirs:
        return
    binds = [("home", plan.home_dir), *((m.container_path, m.host_path) for m in plan.mounts)]
    if plan.policies_host_dir:
        binds.append(("enforcer", plan.policies_host_dir))
    binds += [(target, host) for host, target in plan.system_mounts]
    observe_root = comp.export_dirs["observe"]
    guarded = [
        ("observe export", str(observe_root), "read or forge its own flow record"),
        ("control/ (rules.json)", str(comp.export_dirs["control"]), "read or rewrite its own network rules"),
    ]
    checks = [(label, path, g) for label, path in binds for g in guarded]
    if plan.transcripts_host_dir:
        net = str(observe_root / "net")
        t = ("transcripts", plan.transcripts_host_dir)
        checks += [(*t, ("observe net/", net, "read or forge its own flow record")),
                   (*t, guarded[1])]
        if os.path.realpath(plan.transcripts_host_dir) != os.path.realpath(observe_root / "transcripts"):
            raise HardeningError("the transcripts bind must be the observe export's transcripts/ dir")
    for label, host_path, (what, g, harm) in checks:
        g, rp = os.path.realpath(g), os.path.realpath(host_path)
        if _within(g, rp) or _within(rp, g):
            raise HardeningError(
                f"refusing to render: {what} dir {g} overlaps the harness mount {rp} ({label}) — "
                f"the agent could {harm}. Move the mount outside it."
            )
