"""`glove rm` — remove a session's state, exports and registry row."""

from __future__ import annotations

import shutil
from pathlib import Path

import typer

from glove.api.commands import (
    DIR_ARG,
    SESSION_FILE,
    RegistryError,
    SessionError,
    console,
    err,
    export_dirs,
    fail,
    find_session,
    remove_rows,
    remove_state,
    stop,
)

RANK = 6  # its place in `glove --help` (commands/README.md)


def _remove_exports(sid: str) -> list[Path]:
    gone = []
    for p in export_dirs(sid).values():
        if p.is_dir():
            shutil.rmtree(p)
            gone.append(p)
    return gone


def command(
    directory: Path | None = DIR_ARG,
    all_: bool = typer.Option(False, "--all", help="also delete the directory itself (work/ included)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="do not ask"),
    provider: str | None = typer.Option(None),
) -> None:
    """`down --wipe`, then delete .glove/, the exports and the registry row.
    work/ and glove-session.yml stay unless --all."""
    try:
        sd = find_session(directory)
    except SessionError as e:
        raise fail(str(e)) from e
    sid = sd.read_id()
    what = f"the whole directory {sd.root}" if all_ else f"{sd.state} (work/ and {SESSION_FILE} stay)"
    if not yes and not typer.confirm(f"Remove session {sid or '(never launched)'}: {what}?", default=False):
        raise typer.Exit(1)
    if sid is not None:
        stop(sd, sid, provider, wipe=True, mark=not all_)  # --all deletes them
        for p in _remove_exports(sid):
            console.print(f"[dim]removed {p}[/dim]")
        try:
            remove_rows({sid})
        except RegistryError as e:
            err.print(f"[yellow]warn:[/yellow] {e}")
    if all_:
        shutil.rmtree(sd.root)
    elif sd.state.exists():
        remove_state(sd)
    console.print(f"[green]✓[/green] removed {what}")
