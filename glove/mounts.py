"""Bind-mount computation.

Restrict the harness filesystem to the workdir (rw) plus explicitly added
paths. Dedup so a parent mount absorbs its children, widening the parent's
mode when a child needs stronger access. Map surviving host paths to distinct
container mountpoints and, when the workdir lives inside an absorbing parent,
compute the container working_dir instead of adding a redundant mount.
"""

from __future__ import annotations

import os
import posixpath
import re
import shutil
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path

# Where the session's work dir mounts (the harness's, and a sidecar's with the
# `work` privilege), and the harness home.
WORK_TARGET = "/work"
CONTAINER_HOME = "/home/agent"


class MountError(ValueError):
    """Raised for refused or malformed mount requests."""


def host_path(root: Path | None, value: str) -> Path:
    """A host path from a session file: ``~`` expanded, relative to ``root``
    (the session directory), symlinks resolved. A relative path with no root
    raises ValueError."""
    p = Path(os.path.expanduser(value))
    if not p.is_absolute():
        if root is None:
            raise ValueError(f"{value!r} must be an absolute path here")
        p = root / p
    return Path(os.path.realpath(p))


def overlaps(a: Path, b: Path) -> bool:
    """`a` and `b` (symlinks resolved) are one directory, or one holds the other."""
    a, b = Path(os.path.realpath(a)), Path(os.path.realpath(b))
    return a.is_relative_to(b) or b.is_relative_to(a)


def existing_host_path(root: Path | None, value: str, kind: str) -> Path:
    """`host_path`, which must exist as a `kind` ("file": regular file, or
    "dir"). Raises ValueError naming `value`."""
    p = host_path(root, value)
    if not p.exists():
        raise ValueError(f"{value!r} does not exist ({p})")
    if not (p.is_file() if kind == "file" else p.is_dir()):
        raise ValueError(f"{value!r} is not a {'regular file' if kind == 'file' else 'directory'} ({p})")
    return p


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
    direnv settings), or the harness loads its config or code from, must not
    be plantable by the agent. ``host_path`` is None
    for a placeholder: the path does not exist yet, so an empty file/dir from
    glove's session state is bound over it (docker creates the mountpoint)."""

    container_path: str
    host_path: str | None
    kind: str  # "file" | "dir"
    read_only: bool = True

    @property
    def placeholder(self) -> str:
        """Its placeholder source, relative to the placeholder dir: the
        container path, so a bind nested in a placeholder has its mount point
        there, and two placeholders never share a source."""
        return self.container_path.lstrip("/")


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
            container_path = WORK_TARGET
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


# Trusted by the host (git, IDEs, direnv, agent CLIs) when the user opens a rw
# mount, relative to its root: (path, kind, placeholder). Ring 0 binds each one
# present read-only, and srt denies writing it (`enforcers/nono_srt.py`). A
# missing one with `placeholder` is bound over an empty one only with
# `protect_ide_files: true` (that creates an empty file/dir on the host — hence
# opt-in); the others are left alone, so a fresh /work keeps `git init` working.
HOST_TRUSTED = (
    (".git/hooks", "dir", False), (".git/config", "file", False), (".gitmodules", "file", False),
    *((f".claude/{f}", "file", False) for f in ("settings.json", "settings.local.json")),
    *((f".claude/{d}", "dir", False) for d in ("commands", "agents", "hooks", "skills")),
    (".vscode", "dir", True), (".idea", "dir", True), (".envrc", "file", True), (".mcp.json", "file", True),
)
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


def protected_paths(
    mounts: list[Mount], *, protect_ide_files: bool = False, files: Sequence[tuple[str, str]] = (),
) -> tuple[Protect, ...]:
    """Ring-0 read-only binds for every rw mount (§6.3 of the v3 plan).

    `files` (container path, source; the harness profile's working-dir
    `protect:` entries, a trailing `/` marking a directory) are always
    protected: with source "auto" the mount's own copy, or a placeholder when
    missing; with "empty" always the placeholder (the harness never sees the
    mount's own copy). Each directory between one and the mount root is pinned
    read-write (a missing one is created at launch), so `mv .claude x` cannot
    swap in a fresh copy. Shallower paths go first, so a path inside a masked
    directory binds inside its placeholder (no pin over it).

    Then, at each rw mount's root, the HOST_TRUSTED paths present (and, when
    `core.hooksPath` points inside the mount, that directory), their
    directories pinned the same way: `.git` is a mount point, so `mv .git x &&
    git init` fails (EBUSY) instead of replacing the protected hooks
    wholesale. One already inside a read-only bind (a harness's masked
    directory) is covered. Sources are realpath'd and must stay inside the
    mount: a symlink can never turn this into a bind of some other host path.
    Residual gap (documented): a path created later (e.g. `git init` in a
    directory with no repo yet) or a nested repo/submodule is not covered."""
    out: dict[str, Protect] = {}
    add = partial(_add, out)
    for path, source in sorted(files, key=lambda f: f[0].rstrip("/").count("/")):
        _protect_path(mounts, path, add, source=source)

    def trust(m: Mount, rel: str, kind: str, host: str | None) -> None:
        parts = rel.split("/")
        if any(getattr(out.get(os.path.normpath(os.path.join(m.container_path, *parts[:i]))), "read_only", False)
               for i in range(1, len(parts) + 1)):
            return  # covered
        for i in range(1, len(parts)):
            add(m, os.path.join(m.host_path, *parts[:i]), "/".join(parts[:i]), "dir", read_only=False)  # pin
        add(m, host, rel, kind)

    for m in (m for m in mounts if m.mode == "rw"):
        for rel, kind, placeholder in HOST_TRUSTED:
            path = os.path.join(m.host_path, rel)
            real = os.path.realpath(path)
            if not os.path.lexists(path):
                if placeholder and protect_ide_files:
                    trust(m, rel, kind, None)
            elif os.path.exists(real) and _inside(m.host_path, real):
                trust(m, os.path.relpath(real, m.host_path), "dir" if os.path.isdir(real) else "file", real)
        hooks = _hooks_path(os.path.join(m.host_path, ".git", "config"), m.host_path)
        if hooks and os.path.isdir(hooks) and _inside(m.host_path, hooks):
            trust(m, os.path.relpath(hooks, m.host_path), "dir", hooks)
    ro = [p.container_path for p in out.values() if p.read_only]  # no pin reopens a read-only bind
    keep = (p for p in out.values() if p.read_only or not any(_inside(r, p.container_path) for r in ro))
    return tuple(sorted(keep, key=lambda p: p.container_path.count("/")))  # parents first


def protected_home(home: Mount, config_home: str, paths: Sequence[str]) -> tuple[Protect, ...]:
    """Ring 0 for the harness home, which is bound read-only: the harness's
    config home (`config_home`, a container path) re-bound read-write, the one
    place a harness writes (measured: Pi, Vibe and Claude Code replace files and
    create lock dirs there, so it is writable as a whole), and over it
    read-only binds of what the harness loads from there (`paths`, the
    profile's `~/` `protect:` entries, relative to `home`; a trailing `/`
    marks a directory),
    pinned like a trusted file. They bind the home's own copy, never a
    placeholder: glove renders the files there (a missing one is created empty
    at launch), and an empty directory changes nothing. An entry outside the
    config home is read-only with the home: it is only checked (no symlink)."""
    if not _inside(home.container_path, posixpath.normpath(config_home)):
        raise MountError(f"config home {config_home} must be inside {home.container_path}")
    rel = posixpath.relpath(config_home, home.container_path)
    check_path(home.host_path, rel, "dir")
    conf = Mount(host_path=os.path.join(home.host_path, rel), container_path=config_home, mode="rw")
    out: dict[str, Protect] = {}
    _add(out, conf, conf.host_path, ".", "dir", read_only=False)
    for entry in paths:
        check_path(home.host_path, entry.rstrip("/"), "dir" if entry.endswith("/") else "file")
        # outside the config home: the read-only home covers it (no bind)
        _protect_path([home, conf], posixpath.join(home.container_path, entry), partial(_add, out), source="own")
    return tuple(out.values())


def check_path(root: str, rel: str, kind: str) -> None:
    """Refuse a symlink, or a file where a directory belongs (or the reverse),
    on the way from `root` to `rel` (`kind` is the last one's)."""
    parts = rel.split("/")
    for i in range(1, len(parts) + 1):
        host = os.path.join(root, *parts[:i])
        is_dir = i < len(parts) or kind == "dir"
        if os.path.islink(host) or (os.path.exists(host) and os.path.isdir(host) != is_dir):
            raise MountError(f"{host}: glove protects it or mounts over it, so it must be a "
                             f"{'directory' if is_dir else 'regular file'}, not a symlink")


def _add(out: dict[str, Protect], root: Mount, host: str | None, rel: str, kind: str, read_only: bool = True) -> None:
    cpath = os.path.normpath(os.path.join(root.container_path, rel))
    if cpath not in out or (read_only and not out[cpath].read_only):  # read-only wins over a pin
        out[cpath] = Protect(container_path=cpath, host_path=host, kind=kind, read_only=read_only)


def _protect_path(mounts: list[Mount], path: str, add, *, source: str = "auto") -> None:
    """Protect `path` (a trailing `/` marks a directory), pinning the dirs above
    it. Its bind source: the mount's own copy if it exists, else a placeholder
    ("auto"); always the placeholder ("empty"); always its own ("own", created
    at launch when missing)."""
    kind = "dir" if path.endswith("/") else "file"
    path = path.rstrip("/")
    m = max((m for m in mounts if _is_ancestor(Path(m.container_path), Path(path))),
            key=lambda m: len(m.container_path), default=None)
    if m is None or m.mode != "rw":
        return  # not agent-writable: the read-only mount or rootfs covers it
    parts = os.path.relpath(path, m.container_path).split("/")
    check_path(m.host_path, "/".join(parts), kind)
    for i in range(1, len(parts) + 1):
        sub = "/".join(parts[:i])
        host = os.path.join(m.host_path, sub)
        last = i == len(parts)
        if not last:
            add(m, host, sub, "dir", read_only=False)  # pin: no rename
        else:
            own = source == "own" or (source == "auto" and os.path.exists(host))
            add(m, host if own else None, sub, kind)


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
        return WORK_TARGET
    rel = os.path.relpath(target, best.host_path)
    if rel == ".":
        return best.container_path
    return os.path.normpath(os.path.join(best.container_path, rel))


def make_bind_sources(protect: tuple[Protect, ...], home_dir: str, mount_points: Sequence[str] = ()) -> None:
    """Create the bind sources that do not exist yet: the dirs pinned over a
    trusted file, the config home and its protected files and dirs (empty);
    a placeholder's mount point in a read-only dir bind (`core.hooksPath` of
    `.claude`); and the `mount_points` (container paths, e.g. tmpfs targets)
    under the read-only home, where the runtime cannot create one."""
    ro = [p for p in protect if p.read_only and p.host_path and p.kind == "dir"]
    for p in protect:
        host = p.host_path or next((os.path.join(d.host_path, posixpath.relpath(p.container_path, d.container_path))
                                    for d in ro if _inside(d.container_path, p.container_path)), None)
        if host and not os.path.lexists(host):
            _make_empty(Path(host), p.kind)
    for target in mount_points:
        if _inside(CONTAINER_HOME, target):
            rel = posixpath.relpath(target, CONTAINER_HOME)
            check_path(home_dir, rel, "dir")
            os.makedirs(os.path.join(home_dir, rel), exist_ok=True)


def missing_bind_targets(mounts: list[Mount], protect: tuple[Protect, ...], *, create: bool = False) -> list[str]:
    """The host paths in a rw mount (the user's tree) that the binds of
    `protect` will create, i.e. that do not exist yet: a pinned dir, an
    "own" file, a placeholder's mount point. `glove down` removes each one
    still empty (`remove_empty`). One nested in a placeholder dir has its
    mount point in glove's state, not here. `create` (at launch) makes each, empty, through no symlink:
    Docker Desktop's native layer cannot make one nested in another bind ("outside of rootfs")."""
    holders = {p.container_path for p in protect if p.host_path is None and p.kind == "dir"}
    out = []
    for p in protect:
        m = max((m for m in mounts if _inside(m.container_path, p.container_path)),
                key=lambda m: len(m.container_path), default=None)
        if m is None or m.mode != "rw" or posixpath.dirname(p.container_path) in holders:
            continue
        rel = posixpath.relpath(p.container_path, m.container_path)
        host = os.path.join(m.host_path, rel)
        if create:  # the agent may have run since the plan checked the way (a mount point too): again, and O_EXCL
            check_path(m.host_path, rel, p.kind)
        if not os.path.lexists(host):
            out.append(host)
            if create:
                os.mkdir(host) if p.kind == "dir" else os.close(os.open(host, os.O_WRONLY | os.O_CREAT | os.O_EXCL))
    return out


def remove_empty(paths: Sequence[str]) -> tuple[list[str], list[str]]:
    """Remove each path that is still an empty regular file or an empty
    directory (never a symlink, never one with content, never through a
    symlinked parent), deepest first so a pinned dir goes after the
    placeholder in it: (removed, failed with why)."""
    removed, failed = [], []
    for path in sorted(set(paths), key=lambda p: p.count("/"), reverse=True):
        if os.path.realpath(os.path.dirname(path)) != os.path.dirname(path):
            failed.append(f"{path}: a symlink on the way")
            continue
        try:
            st = os.lstat(path)
            if stat.S_ISREG(st.st_mode) and st.st_size == 0:
                os.unlink(path)
            elif stat.S_ISDIR(st.st_mode) and not os.listdir(path):
                os.rmdir(path)
            else:
                continue
        except FileNotFoundError:
            continue
        except OSError as e:
            failed.append(f"{path}: {e.strerror or e}")
            continue
        removed.append(path)
    return removed, failed


def write_placeholders(directory: Path, protect: tuple[Protect, ...], *, fresh: bool = False) -> Path:
    """Create the empty file/dir sources for placeholder binds (outside /work),
    and the mount point of each bind nested in a placeholder directory (the
    runtime cannot create one in a read-only bind). `fresh` (at launch, no
    harness running) starts from none: an earlier run's file placeholder may
    now sit inside a placeholder dir, which must be empty."""
    if fresh:
        shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True, exist_ok=True)
    holders = {p.container_path for p in protect if p.host_path is None and p.kind == "dir"}
    for p in protect:
        if p.host_path is None or posixpath.dirname(p.container_path) in holders:
            _make_empty(directory / p.placeholder, p.kind)
    return directory


def _make_empty(target: Path, kind: str) -> None:
    if kind == "dir":
        target.mkdir(parents=True, exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch(exist_ok=True)
