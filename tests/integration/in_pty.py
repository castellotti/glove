"""Run a command on a fresh pty and print what it wrote (for tty checks).

    uv run --no-project python tests/integration/in_pty.py <cmd...>

The integration scripts use it to run `docker|podman run -it …` as if from a
terminal, e.g. to check that a tool command cannot open the harness's /dev/tty.
"""

from __future__ import annotations

import os
import pty
import select
import sys
import time

pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
out = b""
end = time.time() + float(os.environ.get("IN_PTY_TIMEOUT", "60"))
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
sys.stdout.write(out.decode(errors="replace").replace("\r", ""))
