"""What the live drivers (`*_live.py`) share: PASS/FAIL checks, a session started
the way `glove up` does, and its harness TUI on a pty.

    with live_session(directory) as s:   # images, sidecars, resolve, home
        check("…", "x" in s.sh("echo x"))
    return summary()

Teardown is `glove down`'s, with the volumes.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ptyio import Tui

from glove.cli import _materialize_plan, _open, prepare_harness
from glove.plan import SessionPlan, secret_env
from glove.session import _compose_base, ensure_images, start_sidecars, teardown

RESULTS: list[bool] = []
# The shell tool's name, where it isn't `bash`.
BASH_TOOL = {"claude-code": "Bash"}


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}: {name}" + (f"  [{detail}]" if detail and not ok else ""), flush=True)


def summary() -> int:
    print(f"== RESULT: {sum(RESULTS)} passed, {len(RESULTS) - sum(RESULTS)} failed")
    return 0 if all(RESULTS) else 1


@dataclass
class LiveSession:
    sd: object  # glove.sessiondir.SessionDir
    sid: str
    cfg: object  # glove.config.Config
    plan: SessionPlan
    secrets: dict[str, str]
    env: dict[str, str]  # os.environ plus the secrets compose interpolates
    base: list[str]  # `<rt> compose -p … -f …`

    @property
    def rt(self) -> str:
        return self.cfg.provider

    @property
    def bash_tool(self) -> str:
        return BASH_TOOL.get(self.cfg.harness, "bash")

    def run(self, *argv: str, entry: str | None = None, extra: tuple[str, ...] = (),
            timeout: int = 300) -> subprocess.CompletedProcess:
        """`compose run` of the harness service (`extra`: compose-run flags)."""
        return subprocess.run([*self.base, "run", "--rm", "-T", *extra, *(["--entrypoint", entry] if entry else []),
                               self.plan.harness_service, *argv], env=self.env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=timeout)

    def call(self, tool: str, args: dict) -> str:
        """One tool call through the agent (`<harness> -p "CALL …"` to the stub): its output."""
        r = self.run(*self.plan.harness_command, "-p", f"CALL {tool} {json.dumps(args)}")
        return r.stdout + r.stderr

    def sh(self, cmd: str) -> str:
        """One shell command through the agent's own tool: what the model saw."""
        out = self.call(self.bash_tool, {"command": cmd})
        return " ".join(out[out.find("TOOL RESULT"):].split()) if "TOOL RESULT" in out else out[-600:]

    def tui(self, rows: int, cols: int) -> Tui:
        """The harness as `glove up` attaches it, on a pty."""
        return Tui([*self.base, "run", "--rm", self.plan.harness_service, *self.plan.harness_command], self.env,
                   rows, cols)


@contextmanager
def live_session(directory: str, *, logs: str | None = None) -> Iterator[LiveSession]:
    """Start the session in `directory` as `glove up` does, minus the harness;
    on the way out print the last lines of sidecar `glove-<id>-<logs>`, then tear
    everything down."""
    sd, _, sid, cfg = _open(Path(directory))
    plan, _, _ = _materialize_plan(sd, sid, cfg)
    secrets = secret_env(plan)
    s = LiveSession(sd, sid, cfg, plan, secrets, {**os.environ, **secrets},
                    _compose_base(cfg.provider, plan.project, sd.compose))
    print(f"== session {sid} ({cfg.harness}, enforcer {plan.enforcer}, runtime {s.rt})")
    try:
        t = time.time()
        ensure_images(cfg, plan, s.rt)
        print(f"  (images ready in {time.time() - t:.0f}s: {plan.image})", flush=True)
        start_sidecars(plan, sd.compose, provider=s.rt, env=s.env)
        prepare_harness(sd, cfg, plan, secrets)
        yield s
    finally:
        if logs:
            r = subprocess.run([s.rt, "logs", f"glove-{sid}-{logs}"], capture_output=True, text=True)
            print(f"== glove-{sid}-{logs} log (last lines)\n" + "".join(f"    {ln}\n" for ln in
                                                                     (r.stdout + r.stderr).splitlines()[-25:]))
        teardown(sid, provider=s.rt, wipe=True)
