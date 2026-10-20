"""What more than one command (`commands/<name>/`) shares: the consoles,
errors, and the session machinery. Re-exported from `glove.api.commands`."""

from __future__ import annotations

import typer
from rich.console import Console

console = Console()
err = Console(stderr=True)


def fail(msg: str, code: int = 1) -> typer.Exit:
    err.print(f"[red]error:[/red] {msg}")
    return typer.Exit(code)
