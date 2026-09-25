"""The NDJSON writer: one line per record, size-rotated, never fatal.

Honours the reader contract in the handoff brief §2:

- each record is one complete ``\\n``-terminated line, written with a single
  ``write(2)`` on an ``O_APPEND`` descriptor, so a tailer never sees a torn line
  (a disk-full partial write is the one exception; readers skip lines that do
  not parse);
- rotation renames ``flows.ndjson`` → ``flows-<ts>.ndjson`` and immediately
  opens a fresh, empty one (new inode), so a tailer detects rotation by inode
  change and never finds the live file missing;
- rotated names are ``<name>-<YYYYmmddTHHMMSSmmm>Z.ndjson``, plus ``-<n>``
  (1, 2, ...) before ``.ndjson`` when the same millisecond is taken; rotation
  order is ``(stamp, n)`` with no suffix as 0 (``rotated_files``). Sorting the
  names as strings is wrong: ``-`` sorts before ``.``, so ``…Z-1.ndjson``
  would come before the older ``…Z.ndjson``.

Every failure path (unwritable dir, full disk, rename error) counts the record
as dropped and returns False. The writer never raises — telemetry must not take
the gate down.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path

from . import ROTATE_BYTES, ROTATE_KEEP

FILE_MODE = 0o600
_ROTATED = re.compile(r"-(\d{8}T\d{9}Z)(?:-(\d+))?\.ndjson")


def rotation_key(name: str, prefix: str) -> tuple[str, int] | None:
    """``(stamp, n)`` for a rotated ``<prefix>-<stamp>[-<n>].ndjson``, else None."""
    if not name.startswith(prefix):
        return None
    m = _ROTATED.fullmatch(name[len(prefix):])
    return (m.group(1), int(m.group(2) or 0)) if m else None


def rotated_files(directory: str | os.PathLike, name: str) -> list[Path]:
    """Rotated files of ``name`` in rotation order (oldest first). Names glove
    did not produce are ignored, so pruning never deletes them."""
    keyed = []
    for p in Path(directory).glob(f"{name}-*.ndjson"):
        key = rotation_key(p.name, name)
        if key is not None:
            keyed.append((key, p))
    return [p for _, p in sorted(keyed)]


def _rotation_stamp(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=UTC)
    return dt.strftime("%Y%m%dT%H%M%S") + f"{dt.microsecond // 1000:03d}Z"


class NdjsonWriter:
    def __init__(
        self,
        directory: str | os.PathLike,
        name: str = "flows",
        *,
        max_bytes: int = ROTATE_BYTES,
        keep: int = ROTATE_KEEP,
        clock=time.time,
    ):
        self.directory = Path(directory)
        self.name = name
        self.max_bytes = max_bytes
        self.keep = keep
        self._clock = clock
        self._fd: int | None = None
        self._size = 0
        self.opened_at: float | None = None  # when the live file's oldest record was written
        self.written = 0
        self.dropped = 0
        self.rotations = 0
        self._last_key: tuple[str, int] | None = None

    @property
    def path(self) -> Path:
        return self.directory / f"{self.name}.ndjson"

    def _open(self) -> None:
        if self._fd is not None:
            return
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, FILE_MODE)
        st = os.fstat(fd)
        self._size = st.st_size
        # an existing file: its oldest record is at least as old as its creation;
        # mtime is a safe lower bound on age only if we take the *earlier* of the two
        self.opened_at = min(self._clock(), st.st_mtime) if st.st_size else None
        self._fd = fd

    def _close(self) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None

    def write(self, record: dict) -> bool:
        try:
            line = (json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
        except (TypeError, ValueError):
            self.dropped += 1
            return False
        try:
            self._open()
            assert self._fd is not None
            n = os.write(self._fd, line)
        except OSError:
            self.dropped += 1
            self._close()  # retry a fresh open on the next record
            return False
        self._size += n
        if self.opened_at is None:
            self.opened_at = self._clock()
        if n != len(line):
            self.dropped += 1
            return False
        self.written += 1
        if self._size >= self.max_bytes:
            self.rotate()
        return True

    def rotated_files(self) -> list[Path]:
        return rotated_files(self.directory, self.name)

    def _next_key(self, stamp: str) -> tuple[str, int]:
        """A rotation key strictly after every existing (and previously issued)
        one, so rotation order is always ``(stamp, n)`` order and no name is
        ever reused — not after pruning, and not if the clock steps back."""
        taken = [k for p in self.directory.glob(f"{self.name}-*.ndjson")
                 if (k := rotation_key(p.name, self.name)) is not None]
        if self._last_key is not None:
            taken.append(self._last_key)
        newest = max(taken, default=None)
        if newest is None or (stamp, 0) > newest:
            return stamp, 0
        return newest[0], newest[1] + 1

    def rotate(self) -> None:
        self._close()
        if not self.path.exists():
            return
        key = self._next_key(_rotation_stamp(self._clock()))
        stamp, n = key
        target = self.directory / (f"{self.name}-{stamp}.ndjson" if n == 0 else f"{self.name}-{stamp}-{n}.ndjson")
        try:
            os.replace(self.path, target)
        except OSError:
            return
        self._last_key = key
        self.rotations += 1
        self._size = 0
        self.opened_at = None
        # Open the fresh file now, not on the next record, so a tailer never
        # finds flows.ndjson missing between rotation and the next write.
        with contextlib.suppress(OSError):
            self._open()
        files = self.rotated_files()
        for old in files[: max(0, len(files) - self.keep)]:
            with contextlib.suppress(OSError):
                old.unlink()

    def expire(self, retain_s: float) -> int:
        """Retention: rotate the live file once its oldest record is retain/4
        old, and delete rotated files last written more than ``retain_s`` ago —
        so no record outlives about 1.25x retain. Returns files deleted."""
        now = self._clock()
        if self.opened_at is not None and now - self.opened_at >= retain_s / 4:
            self.rotate()
        gone = 0
        for old in self.rotated_files():
            try:
                if now - old.stat().st_mtime > retain_s:
                    old.unlink()
                    gone += 1
            except OSError:
                pass
        return gone

    def close(self) -> None:
        self._close()


def read_json_dict(path: str | os.PathLike) -> dict | None:
    """A JSON object from ``path``; None if it is missing, unreadable or not a dict."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_json_atomic(path: str | os.PathLike, data: dict) -> bool:
    """Write ``data`` by temp-file + rename, mode 0600. False on any failure.

    The temp name is unique to this process: ``rules.json`` has two writers
    (the CLI and Layman), and a shared temp name would let one clobber the
    other's half-written file before its rename."""
    path = Path(path)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
        try:
            os.write(fd, (json.dumps(data, indent=2) + "\n").encode())
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink()
        return False
    return True
