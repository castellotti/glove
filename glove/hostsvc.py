"""Host-side services, auto-managed by glove.

Some things the sandbox reaches must run on the *host*, using host trust the
container deliberately lacks: the SSH port-forward to a remote LLM, a
headed Chrome, and the Playwright MCP that attaches to it. These run outside the
sandbox by design, so glove (which runs on the host as the user) starts them —
in detached tmux sessions so the operator can `tmux attach` to watch, with port
health-checks to avoid duplicates, and teardown on `glove down`.

Falls back to plain backgrounded processes (with logfiles) when tmux is absent.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

from rich.console import Console

from .config import Config, HostService

console = Console()


def _expand(
    command: str, cfg: Config, session: str, session_dir: Path | None = None
) -> str:
    """Expand {placeholders} so presets stay session-agnostic."""
    for key, val in _tokens(cfg, session, session_dir).items():
        command = command.replace("{" + key + "}", val)
    return command


def _tokens(
    cfg: Config, session: str, session_dir: Path | None = None
) -> dict[str, str]:
    return {
        "session": session,
        "workdir": os.path.realpath(cfg.workdir),
        # Host-side dir for browser output (e.g. Playwright screenshots). It lives
        # in glove's OWN session state, never inside the project working tree —
        # glove is a generic sandbox and must not litter the repo it is launched
        # on. When no session dir is known (bare expansion), fall back under
        # ~/.glove. The agent still receives screenshots inline from the browser
        # tool; it does not read them from this path.
        "media_dir": str(
            (session_dir / "media")
            if session_dir is not None
            else Path.home() / ".glove" / "media" / session
        ),
        "chrome_profile": str(Path.home() / ".glove" / "chrome-profile"),
        "home": str(Path.home()),
    }


def media_dir_for(
    cfg: Config, session: str, session_dir: Path | None = None
) -> Path:
    return Path(_tokens(cfg, session, session_dir)["media_dir"])


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _tmux_name(session: str, svc: str) -> str:
    return f"glove-{session}-host-{svc}"


def _wait_ready(svc: HostService) -> bool:
    if svc.ready_port is None:
        return True
    deadline = time.time() + svc.ready_timeout
    while time.time() < deadline:
        if _port_open(svc.ready_port):
            return True
        time.sleep(0.5)
    return False


def start_host_services(cfg: Config, session: str, session_dir: Path) -> None:
    """Start each host service that isn't already up; wait for readiness."""
    if not cfg.host_services:
        return

    # Ensure the screenshot output dir exists so Playwright's --output-dir is
    # valid. This lives under glove's session state, not the project working tree.
    media_dir_for(cfg, session, session_dir).mkdir(parents=True, exist_ok=True)

    have_tmux = shutil.which("tmux") is not None
    log_dir = session_dir / "host-logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    console.print("[bold]starting host services…[/bold]")
    for svc in cfg.host_services:
        if svc.ready_port is not None and _port_open(svc.ready_port):
            console.print(
                f"  [green]•[/green] {svc.name}: already up on :{svc.ready_port} "
                "(reusing)"
            )
            continue

        command = _expand(svc.command, cfg, session, session_dir)
        if have_tmux:
            tmux = _tmux_name(session, svc.name)
            subprocess.run(["tmux", "kill-session", "-t", tmux],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["tmux", "new-session", "-d", "-s", tmux, command], check=True)
            where = f"tmux attach -t {tmux}"
        else:
            logfile = log_dir / f"{svc.name}.log"
            with logfile.open("wb") as fh:
                proc = subprocess.Popen(
                    command, shell=True, stdout=fh, stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            (log_dir / f"{svc.name}.pid").write_text(str(proc.pid))
            where = f"log: {logfile}"

        if _wait_ready(svc):
            ready = f"ready on :{svc.ready_port}" if svc.ready_port else "started"
            console.print(f"  [green]✓[/green] {svc.name}: {ready}   [dim]{where}[/dim]")
        else:
            console.print(
                f"  [red]✗[/red] {svc.name}: not ready on :{svc.ready_port} after "
                f"{svc.ready_timeout:.0f}s — check [dim]{where}[/dim]"
            )


def stop_host_services(cfg: Config, session: str, session_dir: Path) -> None:
    """Tear down services glove started, except those marked keep."""
    if not cfg.host_services:
        return
    have_tmux = shutil.which("tmux") is not None
    log_dir = session_dir / "host-logs"
    for svc in cfg.host_services:
        if svc.keep:
            console.print(f"  [dim]• {svc.name}: keep=true, left running[/dim]")
            continue
        if have_tmux:
            subprocess.run(["tmux", "kill-session", "-t", _tmux_name(session, svc.name)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pidfile = log_dir / f"{svc.name}.pid"
        if pidfile.exists():
            with contextlib.suppress(ProcessLookupError, ValueError, PermissionError):
                os.killpg(os.getpgid(int(pidfile.read_text())), 15)
            pidfile.unlink(missing_ok=True)
        console.print(f"  [dim]• {svc.name}: stopped[/dim]")


def describe_host_services(
    cfg: Config, session: str, session_dir: Path | None = None
) -> None:
    """Print the expanded commands (for --dry-run)."""
    if not cfg.host_services:
        return
    console.print("\n[bold]host services[/bold] (glove starts these in tmux):")
    for svc in cfg.host_services:
        console.print(f"  [cyan]{svc.name}[/cyan]"
                      + (f" (:{svc.ready_port})" if svc.ready_port else "")
                      + (" [dim]keep[/dim]" if svc.keep else ""))
        console.print(f"    {_expand(svc.command, cfg, session, session_dir)}")


def print_host_setup(cfg: Config) -> None:
    """Legacy: print manual host_setup commands (not auto-managed)."""
    if not cfg.host_setup:
        return
    console.print()
    console.rule("[bold yellow]RUN ON HOST manually (host_setup)")
    for i, cmd in enumerate(cfg.host_setup, 1):
        console.print(f"[bold]{i}.[/bold] [cyan]{cmd}[/cyan]")
    console.rule()
