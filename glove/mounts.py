"""Bind-mount computation.

Restrict the harness filesystem to the workdir (rw) plus explicitly added
paths. Dedup so a parent mount absorbs its children, widening the parent's
mode when a child needs stronger access. Map surviving host paths to distinct
container mountpoints and, when the workdir lives inside an absorbing parent,
compute the container working_dir instead of adding a redundant mount.
"""

from __future__ import annotations

import os
import re
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
class Protect:
    """A read-only bind nested over a path inside a rw mount (ring 0).

    Files the *host* later executes or trusts (git hooks and config, IDE and
    direnv settings) must not be plantable by the agent. ``host_path`` is None
    for a placeholder: the path does not exist yet, so an empty file/dir from
    glove's session state is bound over it (docker creates the mountpoint)."""

    container_path: str
    host_path: str | None
    kind: str  # "file" | "dir"
    read_only: bool = True

    @property
    def name(self) -> str:
        return os.path.basename(self.container_path)


@dataclass(frozen=True)
class MountPlan:
    mounts: list[Mount]
    working_dir: str  # container path the harness should start in
    protect: tuple[Protect, ...] = ()  # rendered after `mounts`, so they overlay


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


# Always protected when present at the root of a rw mount.
GIT_PROTECTED = (".git/hooks", ".git/config")
# Protected only with `protect_ide_files: true` (a missing one gets a
# placeholder, which creates an empty file/dir on the host — hence opt-in).
IDE_PROTECTED = {".vscode": "dir", ".envrc": "file", ".mcp.json": "file"}
_HOOKS_PATH = re.compile(r"^\s*hookspath\s*=\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)


def _inside(root: str, path: str) -> bool:
    return _is_ancestor(Path(root), Path(path)) and path != root


def _hooks_path(git_config: str, repo: str) -> str | None:
    """`core.hooksPath` from a repo's .git/config, resolved against the repo
    (git resolves a relative value against the worktree root). Best-effort: a
    plain-text scan; quoting and includes are not followed."""
    try:
        text = Path(git_config).read_text(errors="replace")
    except OSError:
        return None
    m = _HOOKS_PATH.search(text)
    if not m:
        return None
    value = os.path.expanduser(m.group(1).strip().strip('"'))
    return os.path.realpath(os.path.join(repo, value))


def protected_paths(mounts: list[Mount], *, protect_ide_files: bool = False) -> tuple[Protect, ...]:
    """Ring-0 read-only binds for every rw mount (§6.3 of the v3 plan).

    Covers `.git/hooks` and `.git/config` at the mount root and, when
    `core.hooksPath` points inside the mount, that directory too. `.git` itself
    is re-bound read-write first, so it is a mount point: renaming or removing
    it fails (EBUSY) — otherwise `mv .git x && git init` would replace the
    protected hooks wholesale. Sources are realpath'd and must stay inside the
    mount: a symlink can never turn this into a bind of some other host path.
    Residual gap (documented): a path created later (e.g. `git init` in a
    directory with no repo yet) or a nested repo/submodule is not covered."""
    out: list[Protect] = []
    seen: set[str] = set()

    def add(root: Mount, host: str | None, rel: str, kind: str, read_only: bool = True) -> None:
        cpath = os.path.normpath(os.path.join(root.container_path, rel))
        if cpath not in seen:
            seen.add(cpath)
            out.append(Protect(container_path=cpath, host_path=host, kind=kind, read_only=read_only))

    for m in mounts:
        if m.mode != "rw":
            continue
        git = os.path.join(m.host_path, ".git")
        if os.path.isdir(git) and not os.path.islink(git):
            add(m, os.path.realpath(git), ".git", "dir", read_only=False)  # pin: no rename
        for rel in GIT_PROTECTED:
            real = os.path.realpath(os.path.join(m.host_path, rel))
            if os.path.lexists(os.path.join(m.host_path, rel)) and os.path.exists(real) and _inside(m.host_path, real):
                add(m, real, os.path.relpath(real, m.host_path), "dir" if os.path.isdir(real) else "file")
        hooks = _hooks_path(os.path.join(m.host_path, ".git", "config"), m.host_path)
        if hooks and os.path.isdir(hooks) and _inside(m.host_path, hooks):
            add(m, hooks, os.path.relpath(hooks, m.host_path), "dir")
        if protect_ide_files:
            for rel, kind in IDE_PROTECTED.items():
                path = os.path.join(m.host_path, rel)
                real = os.path.realpath(path)
                if not os.path.lexists(path):
                    add(m, None, rel, kind)  # placeholder
                elif os.path.exists(real) and _inside(m.host_path, real):
                    add(m, real, os.path.relpath(real, m.host_path), kind)
    return tuple(out)


def _resolve_working_dir(
    mounts: list[Mount], cwd: str | None, workdir_real: str
) -> str:
    """Map the original cwd onto whichever mount absorbs it."""
    target = os.path.realpath(cwd) if cwd else workdir_real
    target_path = Path(target)
    # Deepest containing mount wins.
    best: Mount | None = None
    for m in mounts:
        if _is_ancestor(Path(m.host_path), target_path) and (
            best is None
            or len(Path(m.host_path).parts) > len(Path(best.host_path).parts)
        ):
            best = m
    if best is None:
        return "/work"
    rel = os.path.relpath(target, best.host_path)
    if rel == ".":
        return best.container_path
    return os.path.normpath(os.path.join(best.container_path, rel))


def write_placeholders(directory: Path, protect: tuple[Protect, ...]) -> Path:
    """Create the empty file/dir sources for placeholder binds (outside /work)."""
    directory.mkdir(parents=True, exist_ok=True)
    for p in protect:
        if p.host_path is None:
            target = directory / p.name
            if p.kind == "dir":
                target.mkdir(exist_ok=True)
            else:
                target.touch(exist_ok=True)
    return directory
