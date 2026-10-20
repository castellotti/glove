"""What more than one command (`commands/<name>/`) shares: the consoles,
errors, and the session machinery. Re-exported from `glove.api.commands`."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from . import exports, quarantine
from . import registry as reg
from . import session as _session
from . import sessiondir as sdm
from .config import ConfigError
from .doctor import worst_status
from .extensions import materialize
from .extsession import run_teardown
from .harness import adapter_call, get_profile
from .harnessconfig import render_home
from .mounts import make_bind_sources, write_placeholders
from .plan import build_session_plan, write_in_place, write_system_files
from .runtimes import get_runtime
from .sessiondir import SessionDir, SessionError
from .sessions import list_sessions, match_session, sessions_dir, widening_warnings
from .userconfig import load_user_config

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
    return {x for subnets in _session.foreign_networks(raw.get("runtime") or "docker", sid).values() for x in subnets}


def sync_registry(sd: SessionDir, sid: str, raw: dict, *, check_runtime: bool = False) -> reg.SessionEntry:
    """Register the session (or follow a moved directory) and give it a subnet.

    The subnet avoids other sessions' and — when allocating, or with
    ``check_runtime`` (``glove up``) — the runtime's existing networks; a
    session whose subnet a foreign network has since taken is re-allocated.
    A directory copied with its ``.glove/`` carries the original's id; two live
    directories with one id would share compose projects and exports, so that
    is refused rather than guessed at."""
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


def materialize_plan(sd: SessionDir, sid: str, cfg, *, resume: bool = False, session: str | None = None,
                      home: bool = True, overrides: frozenset[str] = frozenset()):
    """Build the plan and write everything the session needs under .glove/
    (policies, placeholders, compose.yml, effective/baseline, the harness home).
    Returns (plan, compose yaml, seeded home files)."""
    want_resume = resume or session is not None
    prev_cfg = None
    resume_id = session
    if want_resume:
        ref = _validate_resume(get_profile(cfg.harness), sd.home, session, sid)
        if ref is not None:
            resume_id = ref.id
        prev_cfg, _ = sdm.read_effective(sd.baseline)
    plan = build_session_plan(
        cfg, home_dir=str(sd.home), cwd=str(sd.work),
        resume=want_resume, session_id=resume_id, state_dir=str(sd.ext), session_dir=str(sd.root),
    )
    for o in plan.composition.outputs:
        # an older glove kept these in work/<name>/: the new mount hides that directory
        old = sd.work / o.name
        if old.is_dir() and not old.is_symlink() and any(old.iterdir()):
            err.print(f"[yellow]⚠ work/{o.name}/ has files that /work/{o.name} no longer shows: it is now "
                      f"{o.host}; move them there[/yellow]")
    if prev_cfg is not None:
        widened = widening_warnings(prev_cfg, cfg)
        if widened:
            err.print("[yellow]⚠ resuming with broader access than the original session; prior "
                      "conversation context will run with the new grants:[/yellow]")
            for w in widened:
                err.print(f"  [yellow]•[/yellow] {w}")
    ensure_home()
    # Export roots (observe/<id>, control/<id>) and the grants they carry:
    # created for the active owners, control/<id> revoked when filter is gone.
    row = next((e for e in reg.load_registry() if e.id == sid), None)
    plan.composition.grants = exports.grants(plan.composition, row.grants if row else None)
    for note in exports.prepare(plan.composition, sd.ext):
        err.print(f"[yellow]{note}[/yellow]")
    # Extension state (e.g. SearXNG's settings) under .glove/ext/<name>/, and
    # what export-root owners write there (observe: net/session.json).
    materialize(plan.composition)
    # Ring-1 policies are written before render so the read-only bind source
    # exists; they live in .glove/, never inside /work, never agent-writable.
    if plan.policies:
        enforcer_dir = sd.state / "enforcer"
        write_in_place(enforcer_dir, plan.policies)
        plan.policies_host_dir = str(enforcer_dir)
    # The adapter's read-only system config (e.g. Claude Code's managed
    # settings), likewise in .glove/ and bound read-only.
    write_system_files(plan, sd.state / "harness")
    # a pinned dir, the config home or a file protected in it, or a tmpfs mount
    # point under the read-only home may not exist yet
    make_bind_sources(plan.protect, plan.home_dir, plan.hardening.tmpfs)
    if any(p.host_path is None for p in plan.protect):
        plan.placeholder_host_dir = str(write_placeholders(sd.state / "placeholders", plan.protect))
    rendered = get_runtime(cfg.runtime).render(plan, sd.state, overrides=overrides)
    reg.update(sid, grants=plan.composition.grants)
    if plan.model is None:  # unreachable: `inference` is a required slot
        raise ConfigError("no inference provider")
    sd.compose.write_text(rendered.compose_yaml)
    # effective.yml tracks the current run (`glove down` stops its host
    # services; `glove plan` shows its resolutions); baseline.yml is written
    # once, so the widening check compares against the session's origin.
    _, resolved = sdm.read_effective(sd.effective)
    # what extensions resolved from the host at plan time (e.g. corporate's
    # routes via an interface), for the record and `glove plan`
    ext_resolved = {a.name: a.exports["resolved"] for a in plan.composition.active if a.exports.get("resolved")}
    resolved = {k: v for k, v in resolved.items() if k != "extensions"}
    if ext_resolved:
        resolved["extensions"] = ext_resolved
    # the dirs sidecars write (`glove down` quarantines them without re-planning)
    resolved["outputs"] = [o.name for o in plan.composition.outputs if not o.input]
    sdm.write_effective(sd.effective, cfg, resolved)
    if not sd.baseline.exists():
        sdm.write_effective(sd.baseline, cfg)
    home_files = render_home(cfg, plan, sd.home) if home else []
    return plan, rendered.compose_yaml, home_files


def one_resume(resume: bool, session: str | None) -> None:
    if resume and session is not None:
        raise fail("pass either --resume (last) or --session <id> (specific), not both.")


IKNOW = typer.Option([], "--i-know-what-i-am-doing", help="waive a hardening row by key (repeatable)")


def _validate_resume(profile, home_dir: Path, session_id: str | None, sid: str):
    """Validate a resume request, returning the resolved `SessionRef` or None.

    `--session <id>` returns the transcript find_session resolved (so the caller
    can hand the harness its canonical id). `--resume` (continue-last) returns
    None: glove only confirms *some* transcript exists — the harness makes the
    final choice of which conversation to continue."""
    refs = conversations(profile, home_dir, sid)
    if not refs:
        raise ConfigError(f"no previous conversation to resume in session {sid!r}; run `glove up` without "
                          "--resume/--session to start one.")
    if session_id is None:
        return None
    ref = match_session(refs, session_id)
    if ref is None:
        available = "\n".join(f"  {r.id}  [{_fmt_mtime(r.mtime)}]" for r in refs)
        raise ConfigError(f"no conversation matching {session_id!r} in session {sid!r}. available:\n{available}")
    return ref


def _fmt_mtime(mtime: float) -> str:
    return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")


def conversations(profile, home_dir: Path, sid: str):
    """Transcripts in the harness home, plus observe's transcripts export (where
    they are written while `transcripts: true`), newest first."""
    dirs = [sessions_dir(profile, Path(home_dir))]
    if profile.transcript_subdir == profile.sessions_subdir:
        dirs.append(reg.observe_dir(sid) / "transcripts")
    refs = [r for d in dirs if d.is_dir() for r in list_sessions(d)]
    return sorted(refs, key=lambda r: r.mtime, reverse=True)


def stop(sd: SessionDir, sid: str, provider: str | None, *, wipe: bool, mark: bool = True) -> None:
    cfg, _ = sdm.read_effective(sd.effective)
    provider = provider or sdm.session_provider(sd, cfg)
    for w in run_teardown(sd, sid, provider, cfg.extensions if cfg is not None else {}):
        err.print(f"[yellow]warn:[/yellow] {w}")
    _session.teardown(sid, provider=provider, wipe=wipe)
    if mark:
        mark_downloads(sd)
    if wipe:
        # the flow/exit record and status; session.json and transcripts stay
        net = reg.observe_dir(sid) / "net"
        gone = [f for f in (*net.glob("flows*.ndjson"), *net.glob("exit*.ndjson"), net / "status.json") if f.is_file()]
        for f in gone:
            f.unlink()
        if gone:
            console.print(f"[dim]removed {len(gone)} network-observability file(s) from {net}[/dim]")
