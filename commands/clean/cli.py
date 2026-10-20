"""`glove clean` — remove what glove left on Docker and Podman.

A session's stack is the compose project `glove-<session id>`: compose labels
its containers, networks and volumes with that project, so the labels (not
names) say what is glove's. A project counts only when its id is a v3 session
id (`ID_RE`); anything else on a runtime is never glove's to remove.

A stack whose session is live in this registry, or with a container that is
not `exited`/`dead` (running, starting, paused, …), is never touched. Of the
rest, the stopped containers and the networks go. The volumes (VPN state,
observe events, …) go only when the session is provably gone: its row's
directory now holds another session (re-launched under a new id). A missing
directory may have moved, and a project with no row may be another
GLOVE_HOME's (an integration test's): their volumes stay unless `--volumes`.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

import typer

from glove.api.commands import ID_RE, RegistryError, console, err, fail, load_registry, project_name, row_state

PROJECT_LABEL = "com.docker.compose.project"
RUNTIMES = ("docker", "podman")
STOPPED = frozenset({"exited", "dead"})
TIMEOUT = 60  # seconds, per runtime call
_PREFIX = project_name("")


@dataclass
class Stack:
    """One session's resources on one runtime."""

    runtime: str
    sid: str
    containers: dict[str, str] = field(default_factory=dict)  # id → state
    networks: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return any(state not in STOPPED for state in self.containers.values())

    def describe(self) -> str:
        return ", ".join(f"{len(v)} {k}" for k, v in (("container(s)", self.containers), ("network(s)", self.networks),
                                                      ("volume(s)", self.volumes)) if v)


def _out(cli: str, *args: str, partial: bool = False) -> list[str] | None:
    """The command's stdout lines; None when the runtime can't answer. With
    `partial`, a failure that still printed lines returns them (an `inspect` of
    several ids, one of which went in the meantime)."""
    try:
        r = subprocess.run([cli, *args], capture_output=True, text=True, check=False, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.splitlines() if r.returncode == 0 or (partial and r.stdout.strip()) else None


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
    rows = _out(cli, kind, "inspect", "-f", fmt, *ids, partial=True)
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
            try:
                ok = subprocess.run(cmd, capture_output=True, check=False, timeout=TIMEOUT).returncode == 0
            except subprocess.TimeoutExpired:
                ok = False
            if not ok:
                failed.append(f"{s.runtime} {kind} {name}")
    return failed


def row_states() -> dict[str, str]:
    """Each registered session's state (`row_state`: ok, missing or stale)."""
    return {e.id: row_state(e) for e in load_registry()}


def command(
    yes: bool = typer.Option(False, "--yes", "-y", help="do not ask"),
    dry_run: bool = typer.Option(False, "--dry-run", help="list only"),
    volumes: bool = typer.Option(False, "--volumes", help="also the volumes of sessions that may still exist "
                                                           "elsewhere (a moved directory, another GLOVE_HOME)"),
    runtime: str | None = typer.Option(None, "--runtime", help="docker | podman (default: each on PATH)"),
) -> None:
    """Remove the stopped stacks of sessions that no longer exist here: their
    containers and networks, and their volumes when the session is provably gone
    (its directory now holds another session). Nothing live or active is touched.
    (`glove gc` removes their registry rows and exports.)"""
    if runtime not in (None, *RUNTIMES):
        raise fail(f"--runtime: expected one of {', '.join(RUNTIMES)}, got {runtime!r}")
    try:
        states = row_states()
    except RegistryError as e:
        raise fail(str(e)) from e
    dead: list[tuple[Stack, bool]] = []  # (stack, its volumes go)
    for rt in runtimes(runtime):
        found = stacks(rt)
        if found is None:
            err.print(f"[yellow]warn:[/yellow] {rt} did not answer: its stacks were not checked")
            continue
        for s in found:
            state = states.get(s.sid)
            if state == "ok":
                continue
            if s.active:  # another GLOVE_HOME's, or one whose directory went while up
                err.print(f"[yellow]warn:[/yellow] {rt} stack {project_name(s.sid)} is active: left alone")
                continue
            gone = state == "stale" or volumes
            if s.containers or s.networks or (gone and s.volumes):
                dead.append((s, gone))
            if s.volumes and not gone:
                why = "its directory is missing (moved?)" if state == "missing" else "not in this registry"
                console.print(f"  [dim]keeping {rt} {project_name(s.sid)}'s {len(s.volumes)} volume(s): {why}; "
                              "--volumes removes them[/dim]")
    if not dead:
        console.print("[green]✓[/green] nothing to clean")
        return
    for s, gone in dead:
        shown = Stack(s.runtime, s.sid, s.containers, s.networks, s.volumes if gone else [])
        console.print(f"  {s.runtime} stack {project_name(s.sid)}: {shown.describe()}")
    if dry_run:
        return
    if not yes and not typer.confirm("Remove these?", default=False):
        raise typer.Exit(1)
    for f in (f for s, gone in dead for f in remove(s, volumes=gone)):
        err.print(f"[yellow]warn:[/yellow] could not remove {f}")
    console.print(f"[green]✓[/green] removed {len(dead)} stack(s)")
