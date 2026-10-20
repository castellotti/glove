"""What more than one command (`commands/<name>/`) shares: the consoles,
errors, and the session machinery. Re-exported from `glove.api.commands`."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console

from . import quarantine
from . import registry as reg
from . import sessiondir as sdm
from .harness import adapter_call
from .sessiondir import SessionDir, SessionError

console = Console()
err = Console(stderr=True)

DIR_ARG = typer.Argument(None, help="session directory (default: the nearest one at or above the cwd)")


def fail(msg: str, code: int = 1) -> typer.Exit:
    err.print(f"[red]error:[/red] {msg}")
    return typer.Exit(code)


def row_state(e: reg.SessionEntry) -> str:
    sd = SessionDir(Path(e.dir))
    if not sd.root.is_dir():
        return "missing"
    return "ok" if sd.read_id() == e.id else "stale"


def mark_downloads(sd: SessionDir) -> quarantine.Marked | None:
    """Stamp the macOS quarantine attribute on what the session's sidecars
    saved: its `outputs:` dirs (e.g. <session>/downloads/), as recorded at
    plan time; see glove/quarantine.py. None off macOS."""
    if not quarantine.supported():
        return None
    _, resolved = sdm.read_effective(sd.effective)
    names = [n for n in resolved.get("outputs") or [] if isinstance(n, str) and Path(n).name == n]
    r = quarantine.mark(sd.root / n for n in names)
    if r.stamped:
        console.print(f"[dim]quarantined {r.stamped} downloaded file(s)[/dim]")
    for path, why in r.failed:
        err.print(f"[yellow]warn:[/yellow] not quarantined: {path}: {why}")
    return r


def print_checks(title: str, checks: list) -> None:
    """Print `glove check`/`glove doctor` results; exit 1 if any failed."""
    from rich.markup import escape

    from .doctor import worst_status

    glyph = {"ok": "[green]✓[/green]", "warn": "[yellow]![/yellow]", "fail": "[red]✗[/red]",
             "info": "[cyan]·[/cyan]", "skip": "[dim]-[/dim]"}
    console.print(f"{title}\n")
    for c in checks:
        console.print(f"  {glyph.get(c.status, '?')} [bold]{escape(c.name)}[/bold]  [dim]{escape(c.detail)}[/dim]")
    raise typer.Exit(1 if worst_status(checks) == "fail" else 0)


def ensure_home() -> None:
    """``registry.ensure_home``, printing its warnings (see there)."""
    for w in reg.ensure_home():
        err.print(f"[yellow]⚠[/yellow] {w}")


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _foreign_subnets(raw: dict, sid: str) -> set[str]:
    """Subnets of the runtime's existing networks that are not this session's."""
    from .session import foreign_networks

    return {x for subnets in foreign_networks(raw.get("runtime") or "docker", sid).values() for x in subnets}


def sync_registry(sd: SessionDir, sid: str, raw: dict, *, check_runtime: bool = False) -> reg.SessionEntry:
    """Register the session (or follow a moved directory) and give it a subnet.

    The subnet avoids other sessions' and — when allocating, or with
    ``check_runtime`` (``glove up``) — the runtime's existing networks; a
    session whose subnet a foreign network has since taken is re-allocated.
    A directory copied with its ``.glove/`` carries the original's id; two live
    directories with one id would share compose projects and exports, so that
    is refused rather than guessed at."""

    from .userconfig import load_user_config

    root = str(sd.root)
    ensure_home()
    # Asking the runtime can be slow: not under the lock (except a first allocation).
    foreign = _foreign_subnets(raw, sid) if check_runtime else None
    with reg.registry_lock():
        entries = reg.load_registry()
        row = next((e for e in entries if e.id == sid), None)
        if row is not None and row.dir != root:
            other = SessionDir(Path(row.dir))
            if other.root.is_dir() and other.read_id() == sid:
                raise SessionError(
                    f"{sd.root} and {other.root} carry the same session id {sid} (a copied directory?). "
                    f"Give this copy its own identity with `rm {sd.state / 'id'}`, then re-run.")
            err.print(f"[yellow]⚠[/yellow] session {sid} moved: {row.dir} → {root}")
            row.dir = root
        if row is None:
            row = reg.SessionEntry(id=sid, dir=root, harness=raw["harness"], created=now())
            entries.append(row)
        row.harness = raw["harness"]
        row.template = raw.get("template")
        if foreign is None:
            foreign = set() if row.subnet else _foreign_subnets(raw, sid)
        if row.subnet and reg.overlapping([row.subnet], foreign):
            err.print(f"[yellow]⚠[/yellow] subnet {row.subnet} is now used by another network; re-allocating")
            row.subnet = None
        if not row.subnet:
            taken = {e.subnet for e in entries if e.id != sid and e.subnet} | foreign
            row.subnet = reg.allocate_subnet(load_user_config().subnet_pool, taken)
        reg.save_registry(entries)
    return row


def open_session(dir_arg: Path | None, *, register: bool = True, check_runtime: bool = False):
    """(session dir, raw file, id, Config) — the session at ``dir_arg``."""
    from .userconfig import load_user_config

    sd = sdm.find(dir_arg)
    raw = sdm.load_file(sd)
    if register:
        sid = sdm.ensure_state(sd)
        subnet = sync_registry(sd, sid, raw, check_runtime=check_runtime).subnet
    else:  # read-only callers (check): never create state or registry rows
        sid = sd.read_id() or sdm.new_id(sd.root.name)
        row = reg.find(sid)
        subnet = row.subnet if row else None
    cfg = sdm.to_config(sd, raw, sid, subnet=subnet, default_runtime=load_user_config().runtime)
    return sd, raw, sid, cfg


def print_extensions(plan) -> None:
    """Every active extension and exactly what it grants (reviewable)."""
    comp = plan.composition
    console.print("\n[bold]extensions[/bold]")
    for a in comp.active:
        tags = [a.manifest.taint]
        if a.auto_added:
            tags.append("auto")
        if a.manifest.provides:
            tags.append("provides " + ",".join(a.manifest.provides))
        console.print(f"  [cyan]{a.name}[/cyan] [dim]({'; '.join(tags)})[/dim] — {a.manifest.summary}")
    for e in comp.endpoints:
        where = "harness" if e.harness else "sidecars only"
        console.print(f"    endpoint {e.name} :{e.port} → {e.target.host}:{e.target.port} "
                      f"[dim]({e.extension}; {where}; via {e.target.network or 'net'})[/dim]")
    for ext, layer in comp.image_layers:
        shown = ", ".join(f"{k}={v}" for k, v in layer.items() if k in ("apt", "pip", "npm") and v)
        if shown:
            console.print(f"    image layer ({ext}): {shown}")
    for ext, item in comp.mcp:
        console.print(f"    mcp server ({ext}): {item.get('name')}")
    for ext, _src, dest in comp.skills:
        console.print(f"    skill ({ext}): {dest}")
    for line in adapter_call(plan.profile, "describe", plan.adapter, default=[]):
        console.print(f"    {line}")
    for key, privs in comp.privileges.items():
        console.print(f"    [yellow]privilege exception[/yellow] {key}: {privs}")
    for a in comp.active:
        for k, v in (a.exports.get("resolved") or {}).items():
            console.print(f"    resolved ({a.name}): {k} = {v}")
    if plan.model is not None:
        m = plan.model
        console.print(f"    model: {m.model} via {m.base_url} ({m.api}; vision={m.vision}, "
                      f"context={m.context_window}, key={'yes' if m.api_key_env else 'no'})")
