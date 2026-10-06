"""What the live drivers rely on that runs without containers: the pty reader's
waits (tests/integration/ptyio.py) and what lib_session.sh asks glove about a
runtime."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

INTEGRATION = Path(__file__).parent / "integration"
sys.path.insert(0, str(INTEGRATION))

from ptyio import Tui  # noqa: E402


def _sh(script: str) -> Tui:
    return Tui(["sh", "-c", script], {"PATH": os.environ["PATH"]}, 24, 80)


def test_pump_until_stops_at_the_match_and_times_it():
    tui = _sh("sleep 0.3; printf '\\033[1mREADY\\033[0m\\n'; sleep 30")
    t = time.time()
    out = tui.pump_until("READY", 10, settle=0.2)
    tui.kill()
    assert b"READY" in out and time.time() - t < 5
    assert 0.2 < tui.waited < 5


def test_pump_until_gives_up_at_the_timeout():
    tui = _sh("echo nothing-here; sleep 30")
    out = tui.pump_until("READY", 0.5)
    tui.kill()
    assert tui.waited is None and b"nothing-here" in out


def test_kill_takes_the_whole_process_group():
    tui = _sh("sleep 30 & echo child=$!; wait")
    tui.pump_until(r"child=\d+", 5, settle=0)
    child = int(Tui.text(bytes(tui.buf)).split("child=")[1].split()[0])
    tui.kill()
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)


@pytest.mark.parametrize(("rt", "banner", "srt_refused"), [("docker", "", False), ("podman", "false", True)])
def test_runtime_facts(rt, banner, srt_refused):
    root = Path(__file__).parent.parent
    out = subprocess.run(["bash", "-c", '. "$ROOT/tests/integration/lib_session.sh"; runtime_facts; '
                          'echo "banner=${PODMAN_COMPOSE_WARNING_LOGS:-}"; echo "srt=$SRT_REFUSED"'],
                         env={**{k: v for k, v in os.environ.items() if k != "PODMAN_COMPOSE_WARNING_LOGS"},
                              "ROOT": str(root), "RT": rt}, capture_output=True, text=True, check=True)
    lines = dict(ln.split("=", 1) for ln in out.stdout.splitlines())
    assert lines["banner"] == banner
    assert bool(lines["srt"]) is srt_refused
    assert not srt_refused or "not supported on the podman runtime" in lines["srt"]
