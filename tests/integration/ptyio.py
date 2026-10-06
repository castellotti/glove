"""A command on a pseudo-terminal, for the live checks that need one (no glove
imports: in_pty.py runs without the project)."""

from __future__ import annotations

import contextlib
import fcntl
import os
import pty
import re
import select
import struct
import termios
import time

# pump_until re-searches this many bytes before the new ones
OVERLAP = 4096
ANSI = r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)"


class Tui:
    """A command on a pty (of `rows` by `cols` if given); everything it draws
    collects in `buf`."""

    def __init__(self, argv: list[str], env: dict[str, str], rows: int | None = None,
                 cols: int | None = None) -> None:
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvpe(argv[0], argv, env)
        self.buf = bytearray()
        self.waited: float | None = None
        if rows and cols:
            self.resize(rows, cols)

    def resize(self, rows: int, cols: int) -> None:
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("hhhh", rows, cols, 0, 0))

    def _read(self, seconds: float) -> bool | None:
        """Wait up to `seconds` for output: True when some arrived, None at
        the end of it (the command exited)."""
        r, _, _ = select.select([self.fd], [], [], seconds)
        if not r:
            return False
        try:
            chunk = os.read(self.fd, 65536)
        except OSError:
            return None
        if not chunk:
            return None
        self.buf.extend(chunk)
        return True

    def pump(self, seconds: float) -> bytes:
        """Read for `seconds`; returns what arrived."""
        mark, end = len(self.buf), time.time() + seconds
        while time.time() < end and self._read(0.1) is not None:
            pass
        return bytes(self.buf[mark:])

    def pump_until(self, pattern: str, timeout: float, settle: float = 1.0) -> bytes:
        """Read until what arrives (escape sequences stripped) matches
        `pattern`, then `settle` seconds more for the rest of the redraw; or
        `timeout` seconds in all. Returns what arrived; `waited` is the
        seconds until the match (None: no match)."""
        rx, mark, start = re.compile(pattern), len(self.buf), time.time()
        seen = mark  # searched up to here, less an overlap for a match (or escape) split across reads
        self.waited = None
        while time.time() - start < timeout:
            got = self._read(0.1)
            if got is None:
                break
            if got and rx.search(self.text(bytes(self.buf[max(mark, seen - OVERLAP):]))):
                self.waited = time.time() - start
                self.pump(settle)
                break
            seen = len(self.buf)
        return bytes(self.buf[mark:])

    def wait_drawn(self, width: int = 20, timeout: float = 90, settle: float = 2) -> bytes:
        """Read until the TUI draws a rule `width` wide (its input box, so it
        is up), printing how long that took; returns what arrived."""
        out = self.pump_until(f"[─━]{{{width}}}", timeout, settle)
        print(f"  (drawn after {self.waited:.1f}s)" if self.waited else f"  (no rule drawn in {timeout:.0f}s)",
              flush=True)
        return out

    def send(self, keys: bytes, wait: float = 0) -> bytes:
        os.write(self.fd, keys)
        return self.pump(wait)

    @staticmethod
    def text(b: bytes) -> str:
        """`b` without escape sequences."""
        return re.sub(ANSI, "", b.decode(errors="replace"))

    def kill(self) -> None:
        """The terminal gone: the command and everything in its process group
        (it leads its own session), e.g. a compose client it started."""
        with contextlib.suppress(OSError):  # already gone
            os.killpg(self.pid, 9)
        with contextlib.suppress(ChildProcessError):  # already reaped
            os.waitpid(self.pid, 0)
