"""Run a command on a fresh pty and print what it wrote (for tty checks).

    uv run --no-project python tests/integration/in_pty.py <cmd...>

The integration scripts use it to run `docker|podman run -it …` as if from a
terminal, e.g. to check that a tool command cannot open the harness's /dev/tty.
"""

from __future__ import annotations

import os
import sys

from ptyio import Tui

out = Tui(sys.argv[1:], dict(os.environ)).pump(float(os.environ.get("IN_PTY_TIMEOUT", "60")))
sys.stdout.write(out.decode(errors="replace").replace("\r", ""))
