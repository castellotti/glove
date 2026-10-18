"""`glove observe status|flows` — read the session's observe export."""

from __future__ import annotations

import collections
import json
from pathlib import Path

import typer
from rich.console import Console

from glove.api import ConfigError, ExtSession, ext_session

app = typer.Typer(add_completion=False, help="Network observability: gate status and flow records.")
console = Console(highlight=False)
err = Console(stderr=True)

DIR_OPT = typer.Option(None, "--dir", help="session directory (default: the nearest one)")


def session(directory: Path | None, name: str = "observe") -> ExtSession:
    """The launched session at `directory` (or the nearest one) that enables
    extension `name`; exits 1 if none."""
    try:
        return ext_session(name, directory)
    except ConfigError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e


def net_dir(s: ExtSession) -> Path:
    return s.export_dir("observe") / "net"


@app.command("status")
def status(
    directory: Path | None = DIR_OPT,
    json_out: bool = typer.Option(False, "--json", help="machine-readable output"),
) -> None:
    """Gate health, record mode, services, upstream and resolver state."""
    from .netview import render_status, summarize

    s = session(directory)
    ndir = net_dir(s)
    summary = summarize(ndir)
    if json_out:
        console.print_json(json.dumps(summary))
        return
    for line in render_status(s.id, ndir, summary):
        console.print(line)
    if not summary["observed"]:
        raise typer.Exit(1)


@app.command("flows")
def flows(
    directory: Path | None = DIR_OPT,
    follow: bool = typer.Option(False, "--follow", "-f", help="keep tailing (survives rotation)"),
    json_out: bool = typer.Option(False, "--json", help="print raw NDJSON records"),
    tail: int | None = typer.Option(None, "--tail", "-n", help="only the last N records"),
) -> None:
    """Print the session's flow records (rotated files first, then live)."""
    from .netview import follow_records, format_record, iter_records

    ndir = net_dir(session(directory))
    if not ndir.is_dir():
        err.print(f"[red]error:[/red] no net/ dir at {ndir}: `glove up` creates it")
        raise typer.Exit(1)

    def emit(rec: dict) -> None:
        if json_out:
            print(json.dumps(rec, separators=(",", ":")), flush=True)
        else:
            console.print(format_record(rec))

    if tail is None:
        records = iter_records(ndir)
    else:  # `--tail 0 --follow`: only new records
        records = collections.deque(iter_records(ndir), maxlen=tail) if tail > 0 else ()
    for rec in records:
        emit(rec)
    if follow:
        try:
            for rec in follow_records(ndir, from_end=True):
                emit(rec)
        except KeyboardInterrupt:
            pass
