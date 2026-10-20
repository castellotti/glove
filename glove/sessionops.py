"""What more than one command (`commands/<name>/`) shares: the consoles,
errors, and the session machinery. Re-exported from `glove.api.commands`."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from . import quarantine
from . import registry as reg
from . import sessiondir as sdm
from .sessiondir import SessionDir

console = Console()
err = Console(stderr=True)

DIR_ARG = typer.Argument(None, help="session directory (default: the nearest one at or above the cwd)")


def fail(msg: str, code: int = 1) -> typer.Exit:
    err.print(f"[red]error:[/red] {msg}")
    return typer.Exit(code)


def row_state(e: reg.SessionEntry) -> str:
    sd = SessionDir(Path(e.dir))
    if not sd.root.is_dir():
        return "missing"
    return "ok" if sd.read_id() == e.id else "stale"


def mark_downloads(sd: SessionDir) -> quarantine.Marked | None:
    """Stamp the macOS quarantine attribute on what the session's sidecars
    saved: its `outputs:` dirs (e.g. <session>/downloads/), as recorded at
    plan time; see glove/quarantine.py. None off macOS."""
    if not quarantine.supported():
        return None
    _, resolved = sdm.read_effective(sd.effective)
    names = [n for n in resolved.get("outputs") or [] if isinstance(n, str) and Path(n).name == n]
    r = quarantine.mark(sd.root / n for n in names)
    if r.stamped:
        console.print(f"[dim]quarantined {r.stamped} downloaded file(s)[/dim]")
    for path, why in r.failed:
        err.print(f"[yellow]warn:[/yellow] not quarantined: {path}: {why}")
    return r


def print_checks(title: str, checks: list) -> None:
    """Print `glove check`/`glove doctor` results; exit 1 if any failed."""
    from rich.markup import escape

    from .doctor import worst_status

    glyph = {"ok": "[green]✓[/green]", "warn": "[yellow]![/yellow]", "fail": "[red]✗[/red]",
             "info": "[cyan]·[/cyan]", "skip": "[dim]-[/dim]"}
    console.print(f"{title}\n")
    for c in checks:
        console.print(f"  {glyph.get(c.status, '?')} [bold]{escape(c.name)}[/bold]  [dim]{escape(c.detail)}[/dim]")
    raise typer.Exit(1 if worst_status(checks) == "fail" else 0)
