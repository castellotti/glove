"""`glove playwright record`'s host side: the `recording` setting, and
a capture copied out of the sidecar, checked and written.

The sidecar runs a browser, so its tar is hostile input, like a download:
only `<id>/<name>` and `<id>/shots/<name>` regular files with a known name
are read, sizes are capped, PNGs must start with the PNG signature, and every
JSON value is parsed, checked against its schema and written back from the
parsed value, so nothing else passes through. Anything else is dropped and
counted. The files are written through directory file descriptors with
O_NOFOLLOW|O_EXCL: `<session>/browser-output/` is the sidecar's to write, so
a link planted there is refused, never followed.
"""

from __future__ import annotations

import contextlib
import errno
import functools
import io
import json
import math
import os
import re
import secrets
import shutil
import stat
import sys
import tarfile
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_ID = r"[0-9]{8}-[0-9]{6}-[0-9a-f]{6}"
ID = re.compile(rf"^{_ID}\Z")
NAME = re.compile(r"^[a-z0-9-]+\.(png|json|jsonl)\Z")
WALL = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_TAR = 200 * 1024 * 1024
MAX_FILE = {"png": 8 * 1024 * 1024, "json": 64 * 1024, "jsonl": 32 * 1024 * 1024}
MAX_SHOTS = 400
TITLE_MAX = 300
COORD = 1 << 14
STOP_REASONS = {"viewer-closed", "interrupted", "stop", "max_seconds", "cap", "error"}
DEFAULTS = {"to": "session", "max_seconds": 600, "motion_hz": 120}
DIR = "recordings"  # under the session state dir and, with `to: work`, browser-output/
_DIRFLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
TMP = re.compile(rf"^\.{_ID}\.[0-9a-f]{{8}}\Z")  # a copy being written
PLANTED = re.compile(rf"^\.planted-{_ID}-[0-9a-f]{{8}}\Z")  # one moved aside
STALE_S = 3600  # a working copy this old was left by a killed `record`
PLANTED_KEEP = 10  # entries moved aside kept for the operator to look at
PLACE_TRIES = 3  # renames tried while the sidecar plants <id> again


def spec(settings: dict[str, Any]) -> dict[str, Any] | None:
    """`recording` with its defaults, or None when off; ValueError when it can't apply."""
    rec = settings.get("recording")
    if rec is None:
        return None
    if unknown := set(rec) - set(DEFAULTS):
        raise ValueError(f"playwright.recording: unknown key(s) {', '.join(sorted(unknown))} "
                         "(to, max_seconds, motion_hz)")
    out = {**DEFAULTS, **rec}
    if out["to"] not in ("session", "work"):
        raise ValueError("playwright.recording.to: session or work")
    for key, lo, hi in (("max_seconds", 10, 3600), ("motion_hz", 0, 500)):
        if not _int(out[key], lo, hi):
            raise ValueError(f"playwright.recording.{key}: an integer from {lo} to {hi}")
    if settings["mode"] != "novnc" or settings["allow_control"] is not True:
        raise ValueError("playwright.recording records the operator's input in the noVNC view: it needs "
                         "mode: novnc and allow_control: true")
    if out["to"] == "work" and settings["downloads"] != "work":
        raise ValueError("playwright.recording: to: work writes into <session>/browser-output/, which "
                         "needs downloads: work")
    return out


def _int(v: Any, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _num(v: Any, lo: float, hi: float) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and lo <= v <= hi


def _str(v: Any, n: int, pattern: re.Pattern | None = None) -> bool:
    return isinstance(v, str) and len(v) <= n and (pattern is None or bool(pattern.fullmatch(v)))


def _event(o: Any) -> dict[str, Any] | None:
    keys = ("t", "xt", "wall", "type", "button", "x", "y", "mask")
    if not isinstance(o, dict) or set(o) != set(keys):
        return None
    ok = (_int(o["t"], 0, 10**8) and _int(o["xt"], 0, 2**32 - 1) and _str(o["wall"], 24, WALL)
          and o["type"] in ("down", "up", "move", "wheel") and _int(o["button"], 0, 255)
          and _int(o["x"], 0, COORD) and _int(o["y"], 0, COORD) and _int(o["mask"], 0, 0xFFFF))
    return {k: o[k] for k in keys} if ok else None


def _window(o: Any) -> dict[str, Any] | None:
    keys = ("id", "title", "x", "y", "w", "h")
    if not isinstance(o, dict) or set(o) != set(keys):
        return None
    ok = (_int(o["id"], 0, 2**32) and _str(o["title"], TITLE_MAX) and _int(o["x"], -COORD, COORD)
          and _int(o["y"], -COORD, COORD) and _int(o["w"], 0, COORD) and _int(o["h"], 0, COORD))
    return {k: o[k] for k in keys} if ok else None


def _size(v: Any) -> bool:
    return isinstance(v, list) and len(v) == 2 and all(_int(n, 0, COORD) for n in v)


def windows_row(o: Any) -> dict[str, Any] | None:
    keys = ("t", "wall", "reason", "display", "windows")
    if not isinstance(o, dict) or set(o) != set(keys) or not isinstance(o["windows"], list):
        return None
    wins = [_window(w) for w in o["windows"][:64]]
    ok = (_int(o["t"], 0, 10**8) and _str(o["wall"], 24, WALL) and o["reason"] in ("arm", "change", "stop")
          and _size(o["display"]) and None not in wins)
    return {**{k: o[k] for k in keys[:4]}, "windows": wins} if ok else None


# meta.json: each key's check; unknown keys are dropped
META = {
    "capture": lambda v: _int(v, 1, 1),
    "glove_version": lambda v: _str(v, 64),
    "display": _size,
    "viewport": lambda v: _str(v, 16),
    "armed": lambda v: _str(v, 24, WALL),
    "stopped_at": lambda v: _str(v, 24, WALL),
    "max_seconds": lambda v: _int(v, 0, 86400),
    "motion_hz": lambda v: _int(v, 0, 1000),
    "stopped": lambda v: v in STOP_REASONS,
    "error": lambda v: _str(v, 300),
    "duration_ms": lambda v: _int(v, 0, 10**8),
    "events": lambda v: _int(v, 0, 10**7),
    "shots": lambda v: _int(v, 0, 10**4),
    "dropped_shots": lambda v: _int(v, 0, 10**7),
    "shot_ms": lambda v: isinstance(v, dict) and set(v) <= {"min", "median", "max"}
                         and all(_num(n, 0, 10**6) for n in v.values()),
}


def _meta(o: Any) -> dict[str, Any] | None:
    if not isinstance(o, dict) or not META["stopped"](o.get("stopped")):
        return None
    return {k: v for k, v in o.items() if k in META and META[k](v)}


@dataclass
class Capture:
    id: str
    files: dict[str, bytes] = field(default_factory=dict)  # relative path → checked content
    dropped: int = 0  # files or lines left out
    meta: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    windows: list[dict[str, Any]] = field(default_factory=list)


def parse(raw: str | bytes, check) -> dict[str, Any] | None:
    """`raw` parsed as JSON and passed through `check`; None if it isn't valid."""
    try:
        return check(json.loads(raw))
    except (ValueError, RecursionError):  # RecursionError: deeply nested
        return None


def _jsonl(raw: bytes, check) -> tuple[list[dict[str, Any]], int]:
    good, bad = [], 0
    for line in raw.decode("utf-8", "replace").splitlines():
        if (o := parse(line, check)) is None:
            bad += 1
        else:
            good.append(o)
    return good, bad


def _members(tar: tarfile.TarFile, cid: str) -> tuple[int, dict[str, bytes]]:
    """The tar's acceptable files (relative path → bytes), and how many were dropped."""
    raw: dict[str, bytes] = {}
    dropped = shots = 0
    for m in tar.getmembers():
        if m.isdir() and m.name.rstrip("/") in (cid, f"{cid}/shots"):
            continue
        parts = m.name.split("/")
        rel, name = "/".join(parts[1:]), parts[-1]
        ok_path = parts[0] == cid and (len(parts) == 2 or (len(parts) == 3 and parts[1] == "shots"))
        kind = name.rsplit(".", 1)[-1]
        if not (m.isreg() and ok_path and NAME.fullmatch(name) and m.size <= MAX_FILE[kind]) or rel in raw:
            dropped += 1
            continue
        if len(parts) == 3:
            shots += 1
            if kind != "png" or shots > MAX_SHOTS:
                dropped += 1
                continue
        f = tar.extractfile(m)
        body = f.read(MAX_FILE[kind] + 1) if f else b""
        if len(body) > MAX_FILE[kind] or (kind == "png" and not body.startswith(PNG_MAGIC)):
            dropped += 1
            continue
        raw[rel] = body
    return dropped, raw


def read_tar(data: bytes, cid: str) -> Capture:
    """The capture `cid` from the sidecar's tar, checked (module docstring)."""
    if not ID.fullmatch(cid):
        raise ValueError(f"not a capture id: {cid[:40]!r}")
    cap = Capture(cid)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
            cap.dropped, raw = _members(tar, cid)
    except (tarfile.TarError, EOFError) as e:
        raise ValueError(f"the capture is not a readable tar: {e}") from e
    for rel, body in raw.items():
        if rel.startswith("shots/"):
            cap.files[rel] = body
        elif rel == "meta.json":
            if (meta := parse(body, _meta)) is None:
                cap.dropped += 1
            else:
                cap.meta = meta
                cap.files[rel] = (json.dumps(meta, indent=1) + "\n").encode()
        elif rel in ("events.jsonl", "windows.jsonl"):
            rows, bad = _jsonl(body, _event if rel == "events.jsonl" else windows_row)
            cap.dropped += bad
            setattr(cap, rel.split(".")[0], rows)
            cap.files[rel] = "".join(json.dumps(r) + "\n" for r in rows).encode()
        else:
            cap.dropped += 1
    return cap


def _dir(base: Path, mode: int) -> int:
    """`<base>/recordings/` (made if missing), opened without following a link (nor at `base`)."""
    fd = os.open(base, _DIRFLAGS)
    try:
        with contextlib.suppress(FileExistsError):
            os.mkdir(DIR, mode, dir_fd=fd)
        return os.open(DIR, _DIRFLAGS, dir_fd=fd)
    finally:
        os.close(fd)


def write(base: Path, cap: Capture, *, private: bool, untrusted: bool = False) -> tuple[Path, list[str]]:
    """Write `cap` to `<base>/recordings/<id>/`, never following a link and never over an
    existing entry; the path, and the names of entries moved aside. `base` must exist;
    `recordings/` is made if missing. It is written as a hidden `.<id>.<token>/` and renamed
    into place once whole, so `<id>/` is never partial. An existing `<id>` raises
    FileExistsError, except with `untrusted` (the sidecar can write in `base`): there one that
    isn't exactly `cap`'s files is moved aside to a hidden `.planted-<id>-<token>` first, and
    FileExistsError means glove's copy is already there."""
    dmode, fmode = (0o700, 0o600) if private else (0o755, 0o644)
    top, tmp, asides = _dir(base, dmode), f".{cap.id}.{secrets.token_hex(4)}", []
    try:
        _prune(top)
        os.mkdir(tmp, dmode, dir_fd=top)
        try:
            _fill(top, tmp, cap.files, dmode, fmode)
            for _ in range(PLACE_TRIES):
                try:
                    _rename_excl(tmp, cap.id, top)
                    break
                except FileExistsError:
                    if not untrusted or _holds(top, cap.id, cap.files):
                        raise
                    if aside := _set_aside(top, cap.id):
                        asides.append(aside)
            else:  # the sidecar plants it again each time: give up, leaving what was moved aside
                raise OSError(errno.EBUSY, f"planted again after being moved aside ({', '.join(asides)})",
                              str(base / DIR / cap.id))
        except BaseException:
            shutil.rmtree(tmp, dir_fd=top, ignore_errors=True)
            raise
    finally:
        os.close(top)
    return base / DIR / cap.id, asides


def _create(name: str, mode: int, dir_fd: int) -> int:
    """A new file in `dir_fd`, never over one nor through a link."""
    return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=dir_fd)


def _at(rel: str, fds: list[int]) -> tuple[str, int]:
    """`rel`'s file name and the fd of its directory: `<id>/` (fds[0]) or `<id>/shots/` (fds[1])."""
    return rel.split("/")[-1], fds[-1] if rel.startswith("shots/") else fds[0]


def _fill(top: int, tmp: str, files: dict[str, bytes], dmode: int, fmode: int) -> None:
    fds = [os.open(tmp, _DIRFLAGS, dir_fd=top)]
    try:
        if any(rel.startswith("shots/") for rel in files):
            os.mkdir("shots", dmode, dir_fd=fds[0])
            fds.append(os.open("shots", _DIRFLAGS, dir_fd=fds[0]))
        for rel, body in sorted(files.items()):
            name, where = _at(rel, fds)
            with os.fdopen(_create(name, fmode, where), "wb") as f:
                f.write(body)
    finally:
        for fd in fds:
            os.close(fd)


@functools.cache
def _noreplace() -> tuple[Any, int]:
    """libc's atomic no-replace rename and its flag: renameatx_np(RENAME_EXCL) on macOS,
    renameat2(RENAME_NOREPLACE) on Linux; (None, 0) where there is none."""
    import ctypes  # only when a capture is written, not on every session launch

    name, flag = ("renameatx_np", 0x4) if sys.platform == "darwin" else ("renameat2", 0x1)
    try:
        fn = getattr(ctypes.CDLL(None, use_errno=True), name)
    except (OSError, AttributeError):
        return None, 0
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    return fn, flag


def _rename_excl(src: str, dst: str, dfd: int) -> None:
    """Rename `src` to `dst` in `dfd`, never over an existing entry (FileExistsError)."""
    fn, flag = _noreplace()
    if fn is not None:
        import ctypes  # loaded by _noreplace already

        if fn(dfd, os.fsencode(src), dfd, os.fsencode(dst), flag) == 0:
            return
        if (e := ctypes.get_errno()) not in (errno.EINVAL, errno.ENOSYS, errno.ENOTSUP):
            raise OSError(e, os.strerror(e), dst)  # EEXIST: FileExistsError
    # no atomic no-replace on this file system: check, then rename (a plain rename replaces an empty
    # directory, and fails on a non-empty one)
    if _exists(dst, dfd):
        raise FileExistsError(errno.EEXIST, "already exists", dst)
    try:
        os.rename(src, dst, src_dir_fd=dfd, dst_dir_fd=dfd)
    except OSError as e:
        if e.errno in (errno.EEXIST, errno.ENOTEMPTY):
            raise FileExistsError(errno.EEXIST, "already exists", dst) from e
        raise


def _exists(name: str, dfd: int) -> bool:
    try:
        os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _holds(top: int, cid: str, files: dict[str, bytes]) -> bool:
    """Whether `<top>/<cid>/` is a directory holding exactly `files` (nothing followed): glove's copy."""
    fds: list[int] = []
    try:
        fds.append(os.open(cid, _DIRFLAGS, dir_fd=top))
        shots = {rel[6:] for rel in files if rel.startswith("shots/")}
        if set(os.listdir(fds[0])) != {rel for rel in files if "/" not in rel} | ({"shots"} if shots else set()):
            return False
        if shots:
            fds.append(os.open("shots", _DIRFLAGS, dir_fd=fds[0]))
            if set(os.listdir(fds[1])) != shots:
                return False
        for rel, body in files.items():
            name, where = _at(rel, fds)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=where)
            with os.fdopen(fd, "rb") as f:
                st = os.fstat(f.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_size != len(body) or f.read(len(body) + 1) != body:
                    return False
        return True
    except OSError:  # not a directory, a link, gone meanwhile
        return False
    finally:
        for fd in fds:
            os.close(fd)


def _set_aside(top: int, cid: str) -> str | None:
    """Rename `<top>/<cid>` (whatever it is; never followed) to a hidden name, which no
    `browser-event recordings` lists; that name, or None if it is gone meanwhile."""
    aside = f".planted-{cid}-{secrets.token_hex(4)}"
    try:
        os.rename(cid, aside, src_dir_fd=top, dst_dir_fd=top)
    except FileNotFoundError:
        return None
    return aside


def _prune(top: int) -> None:
    """Remove the hidden working copies a killed `record` left (older than STALE_S), and all but the
    newest PLANTED_KEEP entries moved aside, so neither piles up."""
    now, planted = time.time(), []
    with os.scandir(top) as it:
        for e in it:
            if not e.name.startswith("."):
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if PLANTED.fullmatch(e.name):
                planted.append((st.st_mtime, e.name, st.st_mode))
            elif TMP.fullmatch(e.name) and now - st.st_mtime > STALE_S:
                _remove(top, e.name, st.st_mode)
    for _, name, mode in sorted(planted)[:-PLANTED_KEEP]:
        _remove(top, name, mode)


def _remove(top: int, name: str, mode: int) -> None:
    if stat.S_ISDIR(mode):
        shutil.rmtree(name, dir_fd=top, ignore_errors=True)
    else:
        with contextlib.suppress(OSError):
            os.unlink(name, dir_fd=top)


def printable(s: str) -> str:
    """A page-set string (a window title) safe to print: no control or format characters."""
    return "".join(c for c in s if unicodedata.category(c) not in ("Cc", "Cf"))


def front_title(row: dict[str, Any]) -> str:
    """The title of the window on top in a windows.jsonl row ("" if none)."""
    return printable(row["windows"][-1]["title"]) if row.get("windows") else ""


def summary(cap: Capture) -> str:
    presses, drags, held = 0, [], {}
    for e in cap.events:
        if e["type"] == "down":
            presses += 1
            held[e["button"]] = e
        elif e["type"] == "up" and (d := held.pop(e["button"], None)) is not None:
            drags.append((math.hypot(e["x"] - d["x"], e["y"] - d["y"]), e["t"] - d["t"]))
    seconds = cap.meta.get("duration_ms", 0) / 1000
    parts = [f"{presses} press(es)", f"{seconds:.1f} s", f"stopped: {cap.meta.get('stopped', '?')}"]
    if drags:
        parts.insert(1, "drags " + ", ".join(f"{px:.0f} px in {ms} ms" for px, ms in drags[:6]))
    if cap.windows:
        parts.append(f"last title: {front_title(cap.windows[-1])[:80]!r}")
    if cap.dropped:
        parts.append(f"{cap.dropped} file(s)/line(s) dropped as invalid")
    return "; ".join(parts)
