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

import io
import json
import math
import os
import re
import tarfile
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ID = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}\Z")
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


def write(base: Path, cap: Capture, *, private: bool) -> Path:
    """Write `cap` to `<base>/recordings/<id>/`, never following a link and never
    overwriting: `base` must exist; `recordings/` is made if missing; `<id>/` must not exist."""
    dmode, fmode = (0o700, 0o600) if private else (0o755, 0o644)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fds = [os.open(base, flags)]
    try:
        for part, exist_ok in ((DIR, True), (cap.id, False)):
            try:
                os.mkdir(part, dmode, dir_fd=fds[-1])
            except FileExistsError:
                if not exist_ok:
                    raise
            fds.append(os.open(part, flags, dir_fd=fds[-1]))
        if any(rel.startswith("shots/") for rel in cap.files):
            os.mkdir("shots", dmode, dir_fd=fds[-1])
            fds.append(os.open("shots", flags, dir_fd=fds[-1]))
        for rel, body in sorted(cap.files.items()):
            where = fds[-1] if rel.startswith("shots/") else fds[2]
            fd = os.open(rel.split("/")[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, fmode,
                         dir_fd=where)
            with os.fdopen(fd, "wb") as f:
                f.write(body)
    finally:
        for fd in fds:
            os.close(fd)
    return base / DIR / cap.id


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
