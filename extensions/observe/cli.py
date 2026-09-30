"""`glove observe status|flows` — read the session's observe export."""

from __future__ import annotations

import collections
import json
from pathlib import Path

import typer
from rich.console import Console

from glove import registry
from glove import sessiondir as sdm

app = typer.Typer(add_completion=False, help="Network observability: gate status and flow records.")
console = Console(highlight=False)
err = Console(stderr=True)

DIR_OPT = typer.Option(None, "--dir", help="session directory (default: the nearest one)")


def session_id(directory: Path | None) -> str:
    """The session id of `directory` (or the nearest session dir); exits 1 if none."""
    try:
        sd = sdm.find(directory)
    except sdm.SessionError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e
    sid = sd.read_id()
    if sid is None:
        err.print(f"[red]error:[/red] {sd.root} has never been launched (no .glove/id)")
        raise typer.Exit(1)
    return sid


def net_dir(sid: str) -> Path:
    return registry.observe_dir(sid) / "net"


@app.command("status")
def status(
    directory: Path | None = DIR_OPT,
    json_out: bool = typer.Option(False, "--json", help="machine-readable output"),
) -> None:
    """Gate health, record mode, services, upstream and resolver state."""
    from extensions.observe.netview import render_status, summarize

    sid = session_id(directory)
    ndir = net_dir(sid)
    summary = summarize(ndir)
    if json_out:
        console.print_json(json.dumps(summary))
        return
    for line in render_status(sid, ndir, summary):
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
    from extensions.observe.netview import follow_records, format_record, iter_records

    ndir = net_dir(session_id(directory))
    if not ndir.is_dir():
        err.print(f"[red]error:[/red] no net/ dir at {ndir} — add `observe: {{}}` to the session's extensions")
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
