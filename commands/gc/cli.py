"""`glove gc` — remove the registry rows (and exports) of sessions that are gone."""

from __future__ import annotations

import shutil
from pathlib import Path

import typer

from glove.api.commands import ID_RE, RegistryError, console, fail, glove_home, load_registry, remove_rows, row_state

RANK = 9  # its place in `glove --help` (commands/README.md)


def command(yes: bool = typer.Option(False, "--yes", "-y", help="do not ask")) -> None:
    """Remove registry rows whose directory is gone (or no longer that session),
    with their exports under ~/.glove/observe and ~/.glove/control."""
    try:
        entries = load_registry()
    except RegistryError as e:
        raise fail(str(e)) from e
    dead = {e.id for e in entries if row_state(e) != "ok"}
    live = {e.id for e in entries} - dead
    orphans: list[Path] = []
    for root in (glove_home() / "observe", glove_home() / "control"):
        if root.is_dir():
            # only v3 session ids: anything else there is not glove v3's to remove
            orphans += [p for p in sorted(root.iterdir())
                        if p.is_dir() and ID_RE.match(p.name) and p.name not in live]
    if not dead and not orphans:
        console.print("[green]✓[/green] nothing to collect")
        return
    for sid in sorted(dead):
        console.print(f"  registry row {sid}")
    for p in orphans:
        console.print(f"  {p}")
    if not yes and not typer.confirm("Remove these?", default=False):
        raise typer.Exit(1)
    for p in orphans:
        shutil.rmtree(p)
    remove_rows(dead)
    console.print(f"[green]✓[/green] removed {len(dead)} row(s), {len(orphans)} export dir(s)")
