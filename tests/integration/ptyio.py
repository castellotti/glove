"""A command on a pseudo-terminal, for the live checks that need one (no glove
imports: in_pty.py runs without the project)."""

from __future__ import annotations

import fcntl
import os
import pty
import re
import select
import struct
import termios
import time

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
        if rows and cols:
            self.resize(rows, cols)

    def resize(self, rows: int, cols: int) -> None:
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("hhhh", rows, cols, 0, 0))

    def pump(self, seconds: float) -> bytes:
        """Read for `seconds`; returns what arrived."""
        mark, end = len(self.buf), time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                self.buf.extend(chunk)
        return bytes(self.buf[mark:])

    def send(self, keys: bytes, wait: float = 0) -> bytes:
        os.write(self.fd, keys)
        return self.pump(wait)

    @staticmethod
    def text(b: bytes) -> str:
        """`b` without escape sequences."""
        return re.sub(ANSI, "", b.decode(errors="replace"))

    def kill(self) -> None:
        try:
            os.kill(self.pid, 9)
            os.waitpid(self.pid, 0)
        except OSError:
            pass
