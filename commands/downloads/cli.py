"""`glove downloads …` — the files a session's sidecars saved."""

from __future__ import annotations

from pathlib import Path

import typer

from glove.api.commands import (
    DIR_ARG,
    SessionError,
    console,
    fail,
    find_session,
    mark_downloads,
    quarantine_supported,
)

RANK = 11  # its place in `glove --help` (commands/README.md)

app = typer.Typer(add_completion=False, help="Files the session's sidecars saved (web_download, …).")


@app.command("mark")
def mark_cmd(directory: Path | None = DIR_ARG) -> None:
    """Stamp the macOS quarantine attribute on new files in the session's
    download dirs, as `glove down` does (Gatekeeper then vets one opened from Finder)."""
    if not quarantine_supported():
        console.print("[dim]nothing to do: the quarantine attribute is macOS-only[/dim]")
        return
    try:
        sd = find_session(directory)
    except SessionError as e:
        raise fail(str(e)) from e
    if not sd.effective.is_file():
        raise fail(f"{sd.root} has never been planned (no {sd.effective.name})")
    r = mark_downloads(sd)
    if r is None or r.failed:
        raise typer.Exit(1)
    if not r.stamped:
        console.print(f"[dim]nothing new to quarantine ({r.already} already marked)[/dim]")
