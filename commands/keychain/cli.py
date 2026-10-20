"""`glove keychain …` — secrets in the macOS Keychain."""

from __future__ import annotations

import sys

import typer

from glove.api import ConfigError, keychain_set
from glove.api.commands import console, fail

app = typer.Typer(add_completion=False, help="Secrets in the macOS Keychain (referenced as keychain:<service>).")


@app.command("set")
def set_cmd(
    service: str = typer.Argument(..., help="Keychain service name"),
    stdin: bool = typer.Option(False, "--stdin", help="read the secret from stdin (one line; for scripts)"),
) -> None:
    """Store (or replace) a secret, prompting for it — it never appears in argv or a file."""
    secret = None
    if stdin:
        if sys.stdin.isatty():
            raise fail("--stdin reads a piped secret; without it, glove prompts (and hides what you type)")
        secret = sys.stdin.read().removesuffix("\n").removesuffix("\r")
    try:
        rc = keychain_set(service, secret)
    except ConfigError as e:
        raise fail(str(e)) from e
    if rc != 0:
        raise typer.Exit(rc)
    console.print(f"[green]✓[/green] stored; reference it as [cyan]keychain:{service}[/cyan]")
