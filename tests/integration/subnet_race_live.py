"""Live: `glove up` re-allocates when another network takes its subnet between
the plan and `compose up` (driven by test_subnet_race.sh).

    uv run python tests/integration/subnet_race_live.py <session-dir>

The race is made deterministic with a shim for the runtime's CLI, first on
`glove up`'s PATH: on the first `compose … up` it creates a foreign network on
the session's planned subnet, then runs the real command (which fails on the
overlap). Checks:
  1. `glove up` (on a pty) says the subnet was taken and retries, and the
     harness draws;
  2. the session now has a different subnet; the foreign network is untouched;
  3. `glove down --wipe` leaves no container, network or volume.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml
from live_common import check, glove, glove_up, leftovers, summary
from ptyio import Tui

from glove.registry import overlapping

SHIM = """#!/bin/sh
case " $* " in
  *" compose "*" up "*)
    if [ ! -e {mark} ]; then
      touch {mark}
      {real} network create --subnet {subnet} {foreign} >/dev/null
    fi ;;
esac
exec {real} "$@"
"""


def subnets(compose: Path) -> list[str]:
    nets = (yaml.safe_load(compose.read_text()) or {}).get("networks") or {}
    return [c["subnet"] for n in nets.values() for c in (n.get("ipam") or {}).get("config") or []]


def main(directory: str) -> int:
    sd = Path(directory).resolve()
    rt = os.environ.get("RT", "docker")
    out = glove("plan", str(sd))
    check("`glove plan`", out.returncode == 0, (out.stdout + out.stderr)[-300:])
    sid = (sd / ".glove" / "id").read_text().strip()
    planned = subnets(sd / ".glove" / "compose.yml")
    taken, foreign = planned[0], f"glove-race-{os.getpid()}"
    shims = sd.parent / "shim"
    shims.mkdir(exist_ok=True)
    (shims / rt).write_text(SHIM.format(mark=shims / "raced", real=shutil.which(rt), subnet=taken, foreign=foreign))
    (shims / rt).chmod(0o755)
    env = {**os.environ, "PATH": f"{shims}:{os.environ['PATH']}"}
    print(f"== session {sid}: planned {', '.join(planned)}; {foreign} takes {taken} at compose up")
    tui = glove_up(sd, env)
    try:
        tui.wait_drawn(timeout=300)
        said = " ".join(Tui.text(bytes(tui.buf)).split())
        check("`glove up` notices the taken subnet and retries",
              "took this session's subnet" in said and "re-allocating and retrying" in said, said[-400:])
        check("and the harness draws", tui.waited is not None, said[-300:])
        now = subnets(sd / ".glove" / "compose.yml")
        check("the session re-allocated its subnets clear of the foreign network",
              now != planned and not overlapping(now, [taken]),
              f"{planned} → {now}")
        info = subprocess.run([rt, "network", "inspect", foreign], capture_output=True, text=True)
        check("the foreign network is untouched", info.returncode == 0 and taken in info.stdout,
              (info.stdout + info.stderr)[-200:])
    finally:
        tui.kill()
        down = glove("down", "--wipe", str(sd))
        subprocess.run([rt, "network", "rm", foreign], capture_output=True)
    check("`glove down --wipe`", down.returncode == 0, (down.stdout + down.stderr)[-300:])
    left = leftovers(rt, f"glove-{sid}-")
    check("no container, network or volume left", not any(left.values()), str(left))
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
