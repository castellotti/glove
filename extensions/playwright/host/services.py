"""Host mode's host-side processes: the headed Chrome and the Playwright MCP
attached to it. They run outside the sandbox by design (the host's Chrome),
so `launch_env` starts them as the user, in detached tmux sessions the
operator can `tmux attach` to (plain background processes with a log when
tmux is absent), skipping one whose port already answers; `teardown` stops
them at `glove down`, except a kept Chrome."""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

READY_TIMEOUT = 60.0  # seconds to wait for a service's port
LOGS = "host-logs"  # in the extension's state dir: logs and pids without tmux


@dataclass(frozen=True)
class Service:
    name: str
    command: str
    port: int  # glove waits for it, and reuses a service already answering on it
    keep: bool = False  # left running at `glove down`


def _port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _tmux(session: str, name: str) -> str:
    return f"glove-{session}-host-playwright-{name}"


def _ready(port: int) -> bool:
    deadline = time.time() + READY_TIMEOUT
    while time.time() < deadline:
        if _port_open(port):
            return True
        time.sleep(0.5)
    return False


def start(services: list[Service], session: str, state_dir: Path) -> None:
    """Start each service not already up, and wait until its port answers."""
    have_tmux = shutil.which("tmux") is not None
    log_dir = state_dir / LOGS
    log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    print("playwright: starting the host browser…", flush=True)
    for svc in services:
        if _port_open(svc.port):
            print(f"  • {svc.name}: already up on :{svc.port} (reusing)")
            continue
        if have_tmux:
            tmux = _tmux(session, svc.name)
            subprocess.run(["tmux", "kill-session", "-t", tmux], capture_output=True, check=False)
            subprocess.run(["tmux", "new-session", "-d", "-s", tmux, svc.command], check=True)
            where = f"tmux attach -t {tmux}"
        else:
            log = log_dir / f"{svc.name}.log"
            with log.open("wb") as fh:
                proc = subprocess.Popen(svc.command, shell=True, stdout=fh, stderr=subprocess.STDOUT,
                                        start_new_session=True)
            (log_dir / f"{svc.name}.pid").write_text(str(proc.pid))
            where = f"log: {log}"
        if _ready(svc.port):
            print(f"  ✓ {svc.name}: ready on :{svc.port}   ({where})")
        else:
            print(f"  ✗ {svc.name}: not ready on :{svc.port} after {READY_TIMEOUT:.0f}s — check {where}")


def stop(services: list[Service], session: str, state_dir: Path) -> None:
    """Stop the services glove started, except the kept ones (a no-op for one not running)."""
    have_tmux = shutil.which("tmux") is not None
    for svc in services:
        name = svc.name
        if svc.keep:
            print(f"  • playwright {name}: keep_browser, left running")
            continue
        stopped = have_tmux and subprocess.run(["tmux", "kill-session", "-t", _tmux(session, name)],
                                               capture_output=True, check=False).returncode == 0
        # (the second: a launch before round 16, core's `.glove/host-logs`)
        for pidfile in (state_dir / LOGS / f"{name}.pid", state_dir.parents[1] / LOGS / f"playwright-{name}.pid"):
            if pidfile.exists():
                with contextlib.suppress(ProcessLookupError, ValueError, PermissionError):
                    os.killpg(os.getpgid(int(pidfile.read_text())), 15)
                    stopped = True
                pidfile.unlink(missing_ok=True)
        if stopped:
            print(f"  • playwright {name}: stopped")
