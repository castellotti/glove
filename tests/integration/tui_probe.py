"""Drive a session's harness TUI on a pty and print what it shows: the screen
text after startup, then after each key sequence (Python escapes, e.g. "\\r"
for Enter, "\\x1b" for Escape). For checks by eye, such as what a harness does
when it saves a setting to its read-only config.

    uv run python tests/integration/tui_probe.py <session-dir> ['/model\\r' …]
"""

from __future__ import annotations

import re
import sys

from live_common import live_session, summary
from ptyio import Tui


def screen(b: bytes, tail: int) -> str:
    return re.sub(r"[ \t]+", " ", Tui.text(b))[-tail:]


def main(directory: str, keys: list[str]) -> int:
    with live_session(directory) as s:
        tui = s.tui(40, 120)
        print("=== startup\n" + screen(tui.wait_drawn(settle=3), 3000))
        for k in keys:
            print(f"=== after {k!r}\n" + screen(tui.send(k.encode().decode("unicode_escape").encode(), 8), 2500))
        tui.kill()
    return summary()  # no checks: a FAIL only if the run itself failed


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))
