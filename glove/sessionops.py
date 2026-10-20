"""What more than one command (`commands/<name>/`) shares: the consoles,
errors, and the session machinery. Re-exported from `glove.api.commands`."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from . import registry as reg
from .sessiondir import SessionDir

console = Console()
err = Console(stderr=True)


def fail(msg: str, code: int = 1) -> typer.Exit:
    err.print(f"[red]error:[/red] {msg}")
    return typer.Exit(code)


def row_state(e: reg.SessionEntry) -> str:
    sd = SessionDir(Path(e.dir))
    if not sd.root.is_dir():
        return "missing"
    return "ok" if sd.read_id() == e.id else "stale"
