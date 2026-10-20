"""`glove version` — print the glove version."""

from __future__ import annotations

from rich.console import Console

from glove.api.commands import VERSION

RANK = 17  # its place in `glove --help` (commands/README.md)


def command() -> None:
    """Print the glove version."""
    Console().print(VERSION)
