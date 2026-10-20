"""`glove new` — materialize a session directory from a template."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.syntax import Syntax

from glove.api.commands import (
    RegistryError,
    SessionError,
    console,
    ensure_home,
    fail,
    find_session,
    load_registry,
    load_session_file,
    materialize_session,
    placeholders_left,
    sync_registry,
    template_drift,
)

RANK = 1  # its place in `glove --help` (commands/README.md)


def command(
    template: str = typer.Argument(..., help="bundled template name, a path, or a git URL"),
    directory: Path = typer.Argument(Path("."), help="the session directory (created if missing)"),
    diff: bool = typer.Option(False, "--diff", help="show how the template changed since `glove new`"),
) -> None:
    """Materialize a session: glove-session.yml, work/ and .glove/ (0700)."""
    if diff:
        try:
            sd = find_session(directory)
        except SessionError as e:
            raise fail(str(e)) from e
        drift = template_drift(sd)
        if drift is None:
            console.print("[green]✓[/green] the template is unchanged since `glove new`")
            return
        console.print(f"[bold]template {drift[0]} changed since `glove new`[/bold] (your file ← template now)\n")
        console.print(Syntax(drift[1], "diff", theme="ansi_dark"))
        return
    try:
        ensure_home()
        load_registry()  # refuse early on a v2 registry, before writing the directory
        sd, sid = materialize_session(template, directory)
        raw = load_session_file(sd)
        sync_registry(sd, sid, raw)
    except (SessionError, RegistryError) as e:
        raise fail(str(e)) from e
    console.print(f"[green]✓[/green] session [bold]{sid}[/bold] from template [cyan]{template}[/cyan] at {sd.root}")
    todo = placeholders_left(raw)
    if todo:
        console.print(f"  set these in [cyan]{sd.file}[/cyan]: {', '.join(todo)}")
    cd = "" if sd.root == Path.cwd().resolve() else f"cd {sd.root} && "
    console.print(f"  then: [cyan]{cd}glove check && glove up[/cyan]")
