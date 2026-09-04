"""Bind-mount computation.

Restrict the harness filesystem to the workdir (rw) plus explicitly added
paths. Dedup so a parent mount absorbs its children, widening the parent's
mode when a child needs stronger access. Map surviving host paths to distinct
container mountpoints and, when the workdir lives inside an absorbing parent,
compute the container working_dir instead of adding a redundant mount.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class MountError(ValueError):
    """Raised for refused or malformed mount requests."""


@dataclass(frozen=True)
class Mount:
    host_path: str  # realpath on the host
    container_path: str  # mountpoint inside the container
    mode: str  # "ro" | "rw"
    is_workdir: bool = False

    @property
    def read_only(self) -> bool:
        return self.mode == "ro"


@dataclass(frozen=True)
class MountPlan:
    mounts: list[Mount]
    working_dir: str  # container path the harness should start in


@dataclass(frozen=True)
class _Request:
    host_path: str
    mode: str
    is_workdir: bool


def _widen(a: str, b: str) -> str:
    """Return the stronger of two modes (rw beats ro)."""
    return "rw" if "rw" in (a, b) else "ro"


def _is_ancestor(ancestor: Path, descendant: Path) -> bool:
    """Component-wise ancestor test (avoids /a/b matching /a/bc)."""
    a_parts = ancestor.parts
    d_parts = descendant.parts
    return len(a_parts) <= len(d_parts) and d_parts[: len(a_parts)] == a_parts


def compute_mounts(
    workdir: str,
    add_dirs: list[tuple[str, str]] | None = None,
    *,
    cwd: str | None = None,
    allow_sensitive: bool = False,
) -> MountPlan:
    """Compute the deduplicated mount set and container working_dir.

    Args:
        workdir: host path that becomes /work (always rw).
        add_dirs: list of (host_path, mode) where mode is "ro" or "rw".
        cwd: the original working directory used to derive working_dir; when it
            falls inside an absorbing parent no extra mount is added.
            Defaults to the resolved workdir.
        allow_sensitive: permit mounting "/" or $HOME wholesale.
    """
    add_dirs = add_dirs or []

    requests: list[_Request] = [
        _Request(os.path.realpath(workdir), "rw", True),
    ]
    for host_path, mode in add_dirs:
        if mode not in ("ro", "rw"):
            raise MountError(f"invalid mode {mode!r} for {host_path}")
        requests.append(_Request(os.path.realpath(host_path), mode, False))

    home = os.path.realpath(os.path.expanduser("~"))
    for req in requests:
        if not allow_sensitive and req.host_path in ("/", home):
            raise MountError(
                f"refusing to mount {req.host_path!r} wholesale; "
                "pass allow_sensitive/--allow-sensitive to override"
            )

    # Sort shallowest-first so an ancestor is always considered before its
    # descendants. Keep the workdir as a tie-break winner so it retains /work.
    ordered = sorted(
        requests,
        key=lambda r: (len(Path(r.host_path).parts), not r.is_workdir, r.host_path),
    )

    accepted: list[_Request] = []
    # Map from an accepted request's host_path to its (possibly widened) mode.
    modes: dict[str, str] = {}
    for req in ordered:
        p = Path(req.host_path)
        ancestor = next(
            (a for a in accepted if _is_ancestor(Path(a.host_path), p)), None
        )
        if ancestor is not None:
            if _widen(modes[ancestor.host_path], req.mode) != modes[ancestor.host_path]:
                modes[ancestor.host_path] = _widen(modes[ancestor.host_path], req.mode)
            continue
        accepted.append(req)
        modes[req.host_path] = req.mode

    # Assign container mountpoints; guard against /mnt/<basename> collisions.
    used_names: set[str] = set()
    mounts: list[Mount] = []
    workdir_real = os.path.realpath(workdir)
    for req in accepted:
        if req.is_workdir:
            container_path = "/work"
        else:
            base = os.path.basename(req.host_path.rstrip("/")) or "root"
            name = base
            i = 2
            while name in used_names:
                name = f"{base}-{i}"
                i += 1
            used_names.add(name)
            container_path = f"/mnt/{name}"
        mounts.append(
            Mount(
                host_path=req.host_path,
                container_path=container_path,
                mode=modes[req.host_path],
                is_workdir=req.is_workdir,
            )
        )

    # Deterministic emission order: workdir first, then by container path.
    mounts.sort(key=lambda m: (not m.is_workdir, m.container_path))

    working_dir = _resolve_working_dir(mounts, cwd, workdir_real)
    return MountPlan(mounts=mounts, working_dir=working_dir)


def _resolve_working_dir(
    mounts: list[Mount], cwd: str | None, workdir_real: str
) -> str:
    """Map the original cwd onto whichever mount absorbs it."""
    target = os.path.realpath(cwd) if cwd else workdir_real
    target_path = Path(target)
    # Deepest containing mount wins.
    best: Mount | None = None
    for m in mounts:
        if _is_ancestor(Path(m.host_path), target_path):
            if best is None or len(Path(m.host_path).parts) > len(
                Path(best.host_path).parts
            ):
                best = m
    if best is None:
        return "/work"
    rel = os.path.relpath(target, best.host_path)
    if rel == ".":
        return best.container_path
    return os.path.normpath(os.path.join(best.container_path, rel))
