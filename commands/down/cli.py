"""`glove down` — stop a session."""

from __future__ import annotations

from pathlib import Path

import typer

from glove.api.commands import DIR_ARG, SessionError, fail, find_session, stop

RANK = 5  # its place in `glove --help` (commands/README.md)


def command(
    directory: Path | None = DIR_ARG,
    provider: str | None = typer.Option(None),
    wipe: bool = typer.Option(False, "--wipe", help="also remove volumes and the network-observability record"),
) -> None:
    """Stop the session's containers and host services."""
    try:
        sd = find_session(directory)
    except SessionError as e:
        raise fail(str(e)) from e
    sid = sd.read_id()
    if sid is None:
        raise fail(f"{sd.root} has never been launched (no .glove/id)")
    stop(sd, sid, provider, wipe=wipe)
