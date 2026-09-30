"""`glove filter block|unblock|rules|validate` — edit the session's rules.json.

Writes only ``~/.glove/control/<id>/rules.json``, and only while the filter
grant is on (glove created the directory): the same file and writer contract
as Layman (atomic rename, validated with the gate's own validator first).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from extensions.gate.netgate.policy import PolicyError, parse_bytes, read_file, sha256_hex
from extensions.observe.cli import DIR_OPT, net_dir, session_id
from glove import registry

app = typer.Typer(add_completion=False, help="Network rules (the filter grant): block, unblock, show, validate.")
console = Console(highlight=False)
err = Console(stderr=True)


def _fail(msg: str) -> typer.Exit:
    err.print(f"[red]error:[/red] {escape(msg)}")
    return typer.Exit(1)


def _rules_target(directory: Path | None) -> tuple[str, Path]:
    """(session id, rules.json path). The id is both the rules file's `env`
    and its `session` (Layman handoff §3)."""
    sid = session_id(directory)
    return sid, registry.control_dir(sid) / "rules.json"


@app.command("block")
def block(
    target: str = typer.Argument(..., help="host glob (e.g. '*.doubleclick.net'), IP, or CIDR"),
    port: int | None = typer.Option(None, "--port", help="only this destination port"),
    terminate: bool = typer.Option(False, "--terminate", help="also cut matching established flows"),
    allow: bool = typer.Option(False, "--allow", help="write an allow rule instead (e.g. under default block)"),
    note: str | None = typer.Option(None, "--note", help="free-text note shown in `glove filter rules`"),
    directory: Path | None = DIR_OPT,
) -> None:
    """Append a rule to the session's rules.json (the file Layman writes too).

    Rules apply to new connections within ~1s; --terminate also cuts matching
    established ones. glove's built-in SSRF guard runs first and cannot be
    overridden by an allow rule."""
    from extensions.filter.netrules import block_rule, load, save

    try:
        sid, path = _rules_target(directory)
        data = load(path, sid, sid)
        rule = block_rule(target, port=port, terminate=terminate, note=note, action="allow" if allow else "block")
        data["rules"] = [*data["rules"], rule]
        save(path, data, sid, sid)
    except (PolicyError, OSError, ValueError) as e:
        raise _fail(str(e)) from e
    console.print(f"[green]✓[/green] {rule['action']} {rule['match']} → {rule['id']}  [dim]{path}[/dim]")


@app.command("unblock")
def unblock(
    key: str = typer.Argument(..., help="rule id (r_…) or the exact host glob / IP / CIDR it matches"),
    directory: Path | None = DIR_OPT,
) -> None:
    """Remove rules by id or by the exact target they match."""
    from extensions.filter.netrules import load, remove, save

    try:
        sid, path = _rules_target(directory)
        data = load(path, sid, sid)
        gone = remove(data, key)
        if not gone:
            err.print(f"[yellow]no rule matches {key!r}[/yellow]")
            raise typer.Exit(1)
        save(path, data, sid, sid)
    except (PolicyError, OSError) as e:
        raise _fail(str(e)) from e
    for r in gone:
        console.print(f"[green]✓[/green] removed {r['id']} ({r['action']} {r['match']})")


def _rules_file_state(path: Path, st: dict) -> str:
    """Whether the gate has enforced or rejected the bytes now on disk, by
    SHA-256 (status.json `rules.sha256` / `rules.last_rejected.sha256`)."""
    try:
        raw = read_file(path)
    except PolicyError as e:
        return f"[red]{e}[/red]"
    if raw is None:
        return "[dim]absent (default allow)[/dim]"
    digest = sha256_hex(raw)
    if "sha256" not in st:
        state = "[dim](this gate predates write confirmation)[/dim]"
    elif digest == st.get("sha256"):
        state = "[green]enforced[/green]"
    elif digest == (st.get("last_rejected") or {}).get("sha256"):
        state = "[red]rejected[/red]"
    else:
        state = "[yellow]pending[/yellow] (not yet read by the gate, or the gate is stopped)"
    return f"sha256 {digest[:12]} {state}"


@app.command("validate")
def validate(
    file: str = typer.Argument(..., help="rules.json to check, or - for stdin"),
    env: str | None = typer.Option(None, "--env", help="the gate's session id: the file's `env` must equal it"),
    session: str | None = typer.Option(None, "--session", help="the file's `session` must equal it (the session id)"),
    json_out: bool = typer.Option(False, "--json", help="one JSON object on stdout"),
) -> None:
    """Check a rules file with the gate's own validator. Pure: reads only FILE —
    no ~/.glove, no Docker, no network. Exit 0 when the gate would accept it,
    1 when it would reject it."""
    raw = rs = error = None
    try:
        raw = sys.stdin.buffer.read() if file == "-" else read_file(file)
        if raw is None:
            raise PolicyError(f"cannot read {Path(file).name}: no such file or directory")
        rs = parse_bytes(raw, env=env, session=session)
    except PolicyError as e:
        error = str(e)
    result = {"ok": rs is not None, "error": error, "sha256": sha256_hex(raw) if raw is not None else None,
              "default": rs.default if rs is not None else None,
              "active_count": len(rs.rules) if rs is not None else None}
    if json_out:
        print(json.dumps(result), flush=True)
    elif rs is not None:
        console.print(f"[green]✓[/green] valid: default {result['default']}, {result['active_count']} rule(s)  "
                      f"[dim]sha256 {result['sha256']}[/dim]")
    else:
        err.print(f"[red]✗ rejected:[/red] {escape(error)}", highlight=False)
    if rs is None:
        raise typer.Exit(1)


@app.command("rules")
def rules(
    directory: Path | None = DIR_OPT,
    json_out: bool = typer.Option(False, "--json", help="print the rules document"),
) -> None:
    """Show the effective rules, their provenance, and the gates' load result."""
    from extensions.filter.netrules import load
    from extensions.gate.netgate.writer import read_json_dict

    sid, path = _rules_target(directory)
    if not path.parent.is_dir():
        raise _fail(f"{sid} has no filter grant (no {path.parent}); add `filter: {{}}` and run `glove up`")
    try:
        data, problem = load(path, sid, sid), None
    except PolicyError as e:
        data, problem = None, str(e)
    if json_out:
        console.print_json(json.dumps(data or {"error": problem}))
        return
    status = read_json_dict(net_dir(sid) / "status.json") or {}
    console.print(f"[bold]{sid}[/bold]  [dim]{path}[/dim]")
    if problem:
        console.print(f"  [red]rules.json is invalid:[/red] {problem}")
        console.print("  [dim]the gates keep their last known-good set until this is fixed[/dim]")
        raise typer.Exit(1)
    st = status.get("rules") or {}
    if st:
        state = "[green]loaded[/green]" if st.get("ok") else f"[red]REJECTED[/red] — {st.get('error')}"
        console.print(f"  gate: {state}  active={st.get('active_count')}  loaded_at={st.get('loaded_at')}")
        console.print(f"  this file: {_rules_file_state(path, st)}")
    console.print(f"  default: {data['default']}   updated_by: {data.get('updated_by')} at {data.get('updated_at')}")
    console.print("  [dim]then glove's built-in SSRF guard (always first, not overridable)[/dim]")
    if not data["rules"]:
        console.print("  [dim](no rules)[/dim]")
    for i, r in enumerate(data["rules"], 1):
        extra = ("  terminate" if r.get("terminate") else "") + (f"  # {r['note']}" if r.get("note") else "")
        console.print(f"  {i:>2}. {r['action']:<5} {r['match']}  [dim]{r['id']}[/dim]{extra}")
