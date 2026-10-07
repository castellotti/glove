"""Live: one harness per session, git config from one owner, and nothing left
after `glove down` (driven by test_teardown.sh).

    uv run python tests/integration/teardown_live.py <session-dir>

The session file opts into nested repos (`git_config: {safe.directory: "*"}`)
and its llm is the host stub. Checks:
  1. git through the agent's shell tool: core's safe.directory (the mount
     roots) and the session's `git_config:` reach the tool command; a repo in
     /work and a nested one in /work/sub work;
  2. `glove up` (on a pty) runs the harness as glove-<id>-harness; a second
     `glove up` is refused while it runs, and leaves it alone;
  3. its client killed and the harness stopped: the next `glove up` removes the
     leftover and starts a new harness;
  4. `glove down --wipe`, with that harness's client killed too, leaves no
     container, network or volume.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

from live_common import check, glove, glove_up, inspect, kept, leftovers, live_session, summary, wait_for
from ptyio import Tui


def main(directory: str) -> int:
    with live_session(directory) as s:
        rt, name = s.rt, s.plan.harness_service

        print("== git through the agent's shell tool")
        out = s.sh("echo SAFE=$(git config --get-all safe.directory | tr '\\n' ,); "
                   "cd /work && git init -q && git -c user.email=a@b -c user.name=t commit -q --allow-empty -m x "
                   "&& echo WORK=$(git status --short --branch 2>&1 | head -1); "
                   "mkdir -p sub && cd sub && git init -q && echo SUB=$(git status --short --branch 2>&1 | head -1)")
        m = re.search(r"SAFE=(\S*)", out)
        safe = m[1].strip(",").split(",") if m else []
        check("safe.directory: core's mount root, then the session's opt-in", safe[:1] == ["/work"] and "*" in safe,
              str(safe))
        check("a repo in /work", "WORK=##" in out and "dubious" not in out, out[-300:])
        check("a nested repo in /work/sub", "SUB=##" in out and "dubious" not in out, out[-300:])

        def harness() -> tuple[bool, str | None]:
            """Whether it is running, and its container id (None: no container)."""
            i = inspect(rt, name)
            return bool((i.get("State") or {}).get("Running")), i.get("Id")

        print(f"== one harness per session ({name})")
        first = glove_up(s.sd.root)
        first.wait_drawn(timeout=300)  # read as it draws: a full pty would block `glove up` before the harness
        check("`glove up` runs the harness under its name", bool(wait_for(lambda: harness()[0], 30)),
              " ".join(Tui.text(bytes(first.buf)).split())[-300:])
        first_id = harness()[1]
        second = glove("up", str(s.sd.root))
        said = " ".join((second.stdout + second.stderr).split())
        check("a second `glove up` is refused while it runs",
              second.returncode != 0 and "already running" in said and "launching harness" not in said, said[-300:])
        check("and the running harness is left alone", harness() == (True, first_id))

        print("== a killed client")
        first.kill()  # `glove up` and its compose client, not the container
        print(f"  (client killed: the harness is {'running' if harness()[0] else 'stopped'})")
        subprocess.run([rt, "stop", "-t", "2", name], capture_output=True)  # it exits; no client removes it
        print(f"  (stopped: {'left behind' if harness()[1] else 'removed by the runtime'})")
        third = glove_up(s.sd.root)
        third.wait_drawn(timeout=300)
        new = wait_for(lambda: (h := harness())[0] and h[1] != first_id, 30)
        check("the next `glove up` removes the leftover and starts a new harness", bool(new),
              " ".join(Tui.text(bytes(third.buf)).split())[-300:])
        third.kill()  # its harness still running, for `glove down`

        if not kept():
            print("== glove down --wipe")
            down = glove("down", "--wipe", str(s.sd.root))
            check("`glove down --wipe`", down.returncode == 0, (down.stdout + down.stderr)[-300:])
            left = leftovers(rt, s.prefix)
            check("no container, network or volume left", not any(left.values()), str(left))
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
