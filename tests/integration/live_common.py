"""What the live drivers (`*_live.py`) share: PASS/FAIL checks, a session started
the way `glove up` does, and its harness TUI on a pty.

    with live_session(directory) as s:   # preflight, images, sidecars, resolve, home
        check("…", "x" in s.sh("echo x"))
    return summary()

An exception while starting or inside the block is a FAIL (its traceback
printed); a failed start ends the driver with its summary. Teardown is
`glove down`'s, with the volumes, unless KEEP is set (see `kept`).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import traceback
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import yaml
from ptyio import Tui

from extensions.observe.netview import read_records
from glove import registry
from glove.cli import _materialize_plan, _open, preflight, prepare_harness
from glove.plan import SessionPlan, secret_env
from glove.session import _compose_base, compose_process_env, ensure_images, start_sidecars, teardown

RESULTS: list[bool] = []
# Each harness's own tools, by what they do: shell, file write (name, path
# argument, content argument, extra arguments), web search and fetch.
TOOLS = {
    "pi": {"bash": "bash", "write": ("write", "path", "content", {}), "search": "web_search", "fetch": "web_fetch"},
    "vibe": {"bash": "bash", "write": ("write_file", "file_path", "content", {"overwrite": True}),
             "search": "searxng_web_search", "fetch": "webfetch_fetch_url"},
    "claude-code": {"bash": "Bash", "write": ("Write", "file_path", "content", {}),
                    "search": "mcp__searxng__web_search", "fetch": "WebFetch"},
}


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}: {name}" + (f"  [{detail}]" if detail and not ok else ""), flush=True)


def summary() -> int:
    print(f"== RESULT: {sum(RESULTS)} passed, {len(RESULTS) - sum(RESULTS)} failed")
    return 0 if all(RESULTS) else 1


def glove(*args: str, cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    """The glove CLI, as the operator runs it."""
    return subprocess.run([sys.executable, "-m", "glove.cli", *args], cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=timeout)


def glove_up(directory, env: dict[str, str] | None = None) -> Tui:
    """`glove up` as an operator runs it, on a terminal of its own."""
    return Tui([sys.executable, "-m", "glove.cli", "up", str(directory)], env or dict(os.environ), 30, 100)


def leftovers(rt: str, prefix: str) -> dict[str, list[str]]:
    """The containers, networks and volumes named `prefix…` still there."""
    return {kind: subprocess.run([rt, *cmd, "-q", "--filter", f"name={prefix}"], capture_output=True,
                                 text=True).stdout.split()
            for kind, cmd in (("containers", ["ps", "-a"]), ("networks", ["network", "ls"]),
                              ("volumes", ["volume", "ls"]))}


def container_log(rt: str, container: str) -> str:
    """A container's log, stdout and stderr."""
    r = subprocess.run([rt, "logs", container], capture_output=True, text=True)
    return r.stdout + r.stderr


def inspect(rt: str, name: str) -> dict:
    """`<rt> inspect <name>`, or {} when there is no such object."""
    out = subprocess.run([rt, "inspect", name], capture_output=True, text=True).stdout
    return (json.loads(out) or [{}])[0] if out.strip() else {}


def wait_for(fn, timeout: float = 30.0, step: float = 1.0):
    """`fn()` once it is truthy, or its last value after `timeout` seconds."""
    end = time.time() + timeout
    while True:
        v = fn()
        if v or time.time() > end:
            return v
        time.sleep(step)


@dataclass
class LiveSession:
    sd: object  # glove.sessiondir.SessionDir
    sid: str
    cfg: object  # glove.config.Config
    plan: SessionPlan
    secrets: dict[str, str]
    env: dict[str, str]  # a compose process's: os.environ, the runtime's, the secrets it interpolates
    base: list[str]  # `<rt> compose -p … -f …`

    @property
    def rt(self) -> str:
        return self.cfg.provider

    @property
    def tools(self) -> dict:
        """This harness's tool names (`TOOLS`)."""
        return TOOLS[self.cfg.harness]

    @property
    def bash_tool(self) -> str:
        return self.tools["bash"]

    @property
    def prefix(self) -> str:
        """The session's container and network names start with it."""
        return f"glove-{self.sid}"

    @property
    def net(self) -> Path:
        """The observe dir's net/ (flows, status), symlinks resolved."""
        return Path(os.path.realpath(registry.observe_dir(self.sid))) / "net"

    def containers(self) -> list[str]:
        """The names of the session's running containers."""
        return subprocess.run([self.rt, "ps", "--format", "{{.Names}}", "--filter", f"name={self.prefix}-"],
                              capture_output=True, text=True).stdout.split()

    def flows(self, phases: tuple[str, ...] | None = None) -> list[dict]:
        """The flow records so far (only those `phases`, if given)."""
        return [r for r in read_records(self.net) if phases is None or r.get("phase") in phases]

    def start(self) -> None:
        """What `glove up` does before it attaches the harness."""
        preflight(self.sd, self.cfg, self.plan)
        t = time.time()
        ensure_images(self.cfg, self.plan, self.rt)
        print(f"  (images ready in {time.time() - t:.0f}s: {self.plan.image})", flush=True)
        start_sidecars(self.plan, self.sd.compose, provider=self.rt, env=self.env)
        prepare_harness(self.sd, self.cfg, self.plan, self.secrets)

    def relaunch(self) -> None:
        """Re-read the session file and start again, as the next `glove up`
        would (sidecars recreated where they changed)."""
        self.sd, self.sid, self.cfg, self.plan, self.secrets = _materialize(self.sd.root)
        self.env = compose_process_env(self.rt, self.secrets)
        self.start()

    def run(self, *argv: str, entry: str | None = None, extra: tuple[str, ...] = (),
            timeout: int = 300) -> subprocess.CompletedProcess:
        """`compose run` of the harness service (`extra`: compose-run flags)."""
        return subprocess.run([*self.base, "run", "--rm", "-T", *extra, *(["--entrypoint", entry] if entry else []),
                               self.plan.harness_service, *argv], env=self.env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=timeout)

    def ask(self, prompt: str, timeout: int = 300) -> str:
        """`<harness> -p <prompt>` (wrapped, in the hardened service): its output."""
        r = self.run(*self.plan.harness_command, "-p", prompt, timeout=timeout)
        return r.stdout + r.stderr

    def call(self, tool: str, args: dict, timeout: int = 300) -> str:
        """One tool call through the agent (`CALL …` to the stub): its output."""
        return self.ask(f"CALL {tool} {json.dumps(args)}", timeout)

    def sh(self, cmd: str) -> str:
        """One shell command through the agent's own tool: what the model saw."""
        out = self.call(self.bash_tool, {"command": cmd})
        return " ".join(out[out.find("TOOL RESULT"):].split()) if "TOOL RESULT" in out else out[-600:]

    def tui(self, rows: int, cols: int) -> Tui:
        """The harness as `glove up` attaches it, on a pty."""
        return Tui([*self.base, "run", "--rm", self.plan.harness_service, *self.plan.harness_command], self.env,
                   rows, cols)


def kept() -> bool:
    """KEEP set: the drivers leave the session running."""
    return bool(os.environ.get("KEEP"))


def _materialize(directory: Path) -> tuple:
    sd, _, sid, cfg = _open(directory)
    plan, _, _ = _materialize_plan(sd, sid, cfg)
    return sd, sid, cfg, plan, secret_env(plan)


@contextmanager
def live_session(directory: str, *, logs: str | None = None,
                 patch: Callable[[LiveSession, dict], None] | None = None) -> Iterator[LiveSession]:
    """Start the session in `directory` as `glove up` does, minus the harness;
    on the way out print the last lines of sidecar `glove-<id>-<logs>`, then tear
    everything down (not with KEEP set). `patch(s, compose)` edits the rendered
    compose project before it starts (a driver's stand-ins; never glove's)."""
    sd, sid, cfg, plan, secrets = _materialize(Path(directory))
    s = LiveSession(sd, sid, cfg, plan, secrets, compose_process_env(cfg.provider, secrets),
                    _compose_base(cfg.provider, plan.project, sd.compose))
    print(f"== session {sid} ({cfg.harness}, enforcer {plan.enforcer}, runtime {s.rt})")
    started = False
    try:
        if patch:
            doc = yaml.safe_load(sd.compose.read_text())
            patch(s, doc)
            sd.compose.write_text(yaml.safe_dump(doc, sort_keys=False))
        s.start()
        started = True
        yield s
    except Exception as e:  # a FAIL, then the teardown and the summary
        traceback.print_exc()
        check(f"{'live run' if started else 'launch'} ({type(e).__name__})", False, str(e)[-600:])
    finally:
        if logs:
            print(f"== glove-{sid}-{logs} log (last lines)\n" + "".join(
                f"    {ln}\n" for ln in container_log(s.rt, f"glove-{sid}-{logs}").splitlines()[-25:]))
        if kept():
            print(f"== KEEP: {s.plan.project} left running (glove down {sd.root})")
        else:
            teardown(sid, provider=s.rt, wipe=True)
    if not started:  # nothing to run the block against: the driver ends here
        raise SystemExit(summary())
