"""`glove version` — print the glove version."""

from __future__ import annotations

from rich.console import Console

from glove.api.commands import VERSION


def command() -> None:
    """Print the glove version."""
    Console().print(VERSION)
