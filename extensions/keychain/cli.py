"""`glove keychain …` — secrets in the OS credential store."""

from __future__ import annotations

import sys

import typer
from rich.console import Console

from glove.api import ConfigError

from .store import keychain_set

console = Console(highlight=False)
err = Console(stderr=True)

app = typer.Typer(add_completion=False, help="Secrets in the macOS Keychain or the Linux Secret Service "
                                             "(referenced as keychain:<service>).")


def _fail(msg: str) -> typer.Exit:
    err.print(f"[red]error:[/red] {msg}")
    return typer.Exit(1)


@app.command("set")
def set_cmd(
    service: str = typer.Argument(..., help="service name"),
    stdin: bool = typer.Option(False, "--stdin", help="read the secret from stdin (one line; for scripts)"),
) -> None:
    """Store (or replace) a secret, prompting for it — it never appears in argv or a file."""
    secret = None
    if stdin:
        if sys.stdin.isatty():
            raise _fail("--stdin reads a piped secret; without it, glove prompts (and hides what you type)")
        secret = sys.stdin.read().removesuffix("\n").removesuffix("\r")
    try:
        rc = keychain_set(service, secret)
    except ConfigError as e:
        raise _fail(str(e)) from e
    if rc != 0:
        raise typer.Exit(rc)
    console.print(f"[green]✓[/green] stored; reference it as [cyan]keychain:{service}[/cyan]")
