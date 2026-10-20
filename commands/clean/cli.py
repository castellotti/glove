"""`glove clean` — remove what glove left on Docker and Podman.

A session's stack is the compose project `glove-<session id>`: compose labels
its containers, networks and volumes with that project, so the labels (not
names) say what is glove's. A project counts only when its id is a v3 session
id (`ID_RE`); anything else on a runtime is never glove's to remove.

A stack is *dead* when its session no longer exists: its registry row's
directory is gone or now holds another session, or there is no row (a session
of another GLOVE_HOME, e.g. an integration test's). Nothing of a dead session
can be restarted, so its whole stack goes, volumes included. A running stack
is always left alone.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import typer
from rich.console import Console

from glove.api.commands import ID_RE, RegistryError, SessionDir, load_registry, project_name

PROJECT_LABEL = "com.docker.compose.project"
RUNTIMES = ("docker", "podman")
_PREFIX = project_name("")

console = Console()
err = Console(stderr=True)


@dataclass
class Stack:
    """One session's resources on one runtime."""

    runtime: str
    sid: str
    containers: dict[str, str] = field(default_factory=dict)  # id → state
    networks: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)

    @property
    def running(self) -> bool:
        return "running" in self.containers.values()

    def describe(self) -> str:
        return ", ".join(f"{len(v)} {k}" for k, v in (("container(s)", self.containers), ("network(s)", self.networks),
                                                      ("volume(s)", self.volumes)) if v)


def _out(cli: str, *args: str) -> list[str] | None:
    """The command's stdout lines; None when the runtime can't answer."""
    try:
        r = subprocess.run([cli, *args], capture_output=True, text=True, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.splitlines() if r.returncode == 0 else None


def runtimes(only: str | None = None) -> list[str]:
    """The runtimes to look at: `only`, else each one on PATH."""
    return [only] if only else [c for c in RUNTIMES if shutil.which(c)]


def _labelled(cli: str, kind: str, labels: str, *fields: str) -> list[list[str]] | None:
    """[project, *fields] of each `kind` (container|network|volume) carrying
    compose's project label; `labels` is where `inspect` keeps its labels."""
    ls = ["ps", "-aq"] if kind == "container" else [kind, "ls", "-q"]
    ids = _out(cli, *ls, "--filter", f"label={PROJECT_LABEL}")
    if not ids:
        return ids
    fmt = " ".join([f'{{{{index {labels} "{PROJECT_LABEL}"}}}}', *(f"{{{{{f}}}}}" for f in fields)])
    rows = _out(cli, kind, "inspect", "-f", fmt, *ids)
    return None if rows is None else [r.split() for r in rows if r.strip()]


def stacks(cli: str) -> list[Stack] | None:
    """Every glove v3 session's stack on `cli`; None when it can't be asked."""
    found = (_labelled(cli, "container", ".Config.Labels", ".Id", ".State.Status"),
             _labelled(cli, "network", ".Labels", ".Name"),
             _labelled(cli, "volume", ".Labels", ".Name"))
    if any(f is None for f in found):
        return None
    by: dict[str, Stack] = {}

    def stack(project: str) -> Stack | None:
        sid = project.removeprefix(_PREFIX)
        if not project.startswith(_PREFIX) or not ID_RE.match(sid):
            return None
        return by.setdefault(sid, Stack(cli, sid))

    containers, networks, volumes = found
    for project, cid, state in (r for r in containers if len(r) == 3):
        if (s := stack(project)) is not None:
            s.containers[cid] = state
    for rows, attr in ((networks, "networks"), (volumes, "volumes")):
        for project, name in (r for r in rows if len(r) == 2):
            if (s := stack(project)) is not None:
                getattr(s, attr).append(name)
    return sorted(by.values(), key=lambda s: s.sid)


def remove(s: Stack, *, volumes: bool) -> list[str]:
    """Remove a stack's containers, then its networks (and volumes); the
    resources the runtime refused."""
    failed = []
    for kind, names in (("container", list(s.containers)), ("network", s.networks),
                        ("volume", s.volumes if volumes else [])):
        for name in names:
            cmd = [s.runtime, "rm", "-f", name] if kind == "container" else [s.runtime, kind, "rm", name]
            if subprocess.run(cmd, capture_output=True, check=False).returncode != 0:
                failed.append(f"{s.runtime} {kind} {name}")
    return failed


def live_sessions() -> set[str]:
    """The ids of the registered sessions whose directory still holds them."""
    return {e.id for e in load_registry() if SessionDir(Path(e.dir)).read_id() == e.id}


def command(
    yes: bool = typer.Option(False, "--yes", "-y", help="do not ask"),
    dry_run: bool = typer.Option(False, "--dry-run", help="list only"),
    runtime: str | None = typer.Option(None, "--runtime", help="docker | podman (default: each on PATH)"),
) -> None:
    """Remove the stacks (containers, networks, volumes) of sessions that no
    longer exist. A running stack and a live session's are left alone.
    (`glove gc` removes their registry rows and exports.)"""
    if runtime not in (None, *RUNTIMES):
        err.print(f"[red]error:[/red] --runtime: expected one of {', '.join(RUNTIMES)}, got {runtime!r}")
        raise typer.Exit(1)
    try:
        live = live_sessions()
    except RegistryError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e
    dead: list[Stack] = []
    for rt in runtimes(runtime):
        found = stacks(rt)
        if found is None:
            err.print(f"[yellow]warn:[/yellow] {rt} did not answer: its stacks were not checked")
            continue
        for s in found:
            if s.sid in live:
                continue
            if s.running:  # a session of another GLOVE_HOME, or one whose directory went while up
                err.print(f"[yellow]warn:[/yellow] {rt} stack {project_name(s.sid)} is running: left alone")
            else:
                dead.append(s)
    if not dead:
        console.print("[green]✓[/green] nothing to clean")
        return
    for s in dead:
        console.print(f"  {s.runtime} stack {project_name(s.sid)}: {s.describe()}")
    if dry_run:
        return
    if not yes and not typer.confirm("Remove these?", default=False):
        raise typer.Exit(1)
    for f in (f for s in dead for f in remove(s, volumes=True)):
        err.print(f"[yellow]warn:[/yellow] could not remove {f}")
    console.print(f"[green]✓[/green] removed {len(dead)} stack(s)")
