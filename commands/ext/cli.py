"""`glove ext` — every extension glove can load."""

from __future__ import annotations

from glove.api import ExtensionError
from glove.api.commands import console, discover, fail

RANK = 16  # its place in `glove --help` (commands/README.md)


def command() -> None:
    """Every extension glove can load, with its origin and CLI."""
    try:
        manifests = discover()
    except ExtensionError as e:
        raise fail(str(e)) from e
    for name, m in sorted(manifests.items()):
        tags = [m.taint, *(["library"] if not m.selectable else []),
                *([f"provides {','.join(m.provides)}"] if m.provides else []),
                *([f"cli: glove {name} …"] if m.cli else [])]
        console.print(f"[cyan]{name}[/cyan] [dim]({'; '.join(tags)})[/dim] — {m.summary}")
