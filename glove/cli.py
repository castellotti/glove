"""glove command-line interface.

A session is a directory holding ``glove-session.yml`` (see
``glove/sessiondir.py``). Every session command takes an optional directory
and otherwise uses the nearest session at or above the cwd:

    glove new <template|path|git-url> [dir]    materialize a session
    glove check | plan | up | down | rm         work with one session
    glove ls | ps | gc                          all sessions (~/.glove/registry.json)
    glove keychain set <service>                store a secret, prompting for it
"""

from __future__ import annotations

import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.syntax import Syntax

from . import __version__
from . import registry as reg
from . import sessiondir as sdm
from .config import ConfigError
from .hardening import HardeningError
from .harness import adapter_call, known_harnesses
from .harnessconfig import render_home
from .hostsvc import describe_host_services, start_host_services, stop_host_services
from .naming import scoped
from .plan import build_session_plan, write_in_place, write_system_files
from .runtimes import get_runtime, known_runtimes
from .sessiondir import SessionDir, SessionError

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Run agentic harnesses inside constrained Docker/Podman sandboxes. A session is a directory.",
)
console = Console()
err = Console(stderr=True)

_DIR_ARG = typer.Argument(None, help="session directory (default: the nearest one at or above the cwd)")


def _fail(msg: str, code: int = 1) -> typer.Exit:
    err.print(f"[red]error:[/red] {msg}")
    return typer.Exit(code)


def _ensure_home() -> None:
    """``registry.ensure_home``, printing its warnings (see there)."""
    for w in reg.ensure_home():
        err.print(f"[yellow]⚠[/yellow] {w}")


def _print_checks(title: str, checks: list) -> None:
    """Print `glove check`/`glove doctor` results; exit 1 if any failed."""
    from rich.markup import escape

    from .doctor import worst_status

    glyph = {"ok": "[green]✓[/green]", "warn": "[yellow]![/yellow]", "fail": "[red]✗[/red]",
             "info": "[cyan]·[/cyan]", "skip": "[dim]-[/dim]"}
    console.print(f"{title}\n")
    for c in checks:
        console.print(f"  {glyph.get(c.status, '?')} [bold]{escape(c.name)}[/bold]  [dim]{escape(c.detail)}[/dim]")
    raise typer.Exit(1 if worst_status(checks) == "fail" else 0)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _foreign_subnets(raw: dict, sid: str) -> set[str]:
    """Subnets of the runtime's existing networks that are not this session's."""
    try:
        nets = get_runtime(raw.get("runtime") or "docker").network_subnets()
    except (ValueError, AttributeError, OSError):
        return set()
    return {x for name, subnets in nets.items() if not name.startswith(scoped(sid, "")) for x in subnets}


def _sync_registry(sd: SessionDir, sid: str, raw: dict, *, check_runtime: bool = False) -> reg.SessionEntry:
    """Register the session (or follow a moved directory) and give it a subnet.

    The subnet avoids other sessions' and — when allocating, or with
    ``check_runtime`` (``glove up``) — the runtime's existing networks; a
    session whose subnet a foreign network has since taken is re-allocated.
    A directory copied with its ``.glove/`` carries the original's id; two live
    directories with one id would share compose projects and exports, so that
    is refused rather than guessed at."""
    import ipaddress

    from .userconfig import load_user_config

    root = str(sd.root)
    _ensure_home()
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
            row = reg.SessionEntry(id=sid, dir=root, harness=raw["harness"], created=_now())
            entries.append(row)
        row.harness = raw["harness"]
        row.template = raw.get("template")
        if foreign is None:
            foreign = set() if row.subnet else _foreign_subnets(raw, sid)
        if row.subnet and any(ipaddress.ip_network(row.subnet).overlaps(ipaddress.ip_network(f, strict=False))
                              for f in foreign):
            err.print(f"[yellow]⚠[/yellow] subnet {row.subnet} is now used by another network; re-allocating")
            row.subnet = None
        if not row.subnet:
            taken = {e.subnet for e in entries if e.id != sid and e.subnet} | foreign
            row.subnet = reg.allocate_subnet(load_user_config().subnet_pool, taken)
        reg.save_registry(entries)
    return row


def _open(dir_arg: Path | None, *, register: bool = True, check_runtime: bool = False):
    """(session dir, raw file, id, Config) — the session at ``dir_arg``."""
    from .userconfig import load_user_config

    sd = sdm.find(dir_arg)
    raw = sdm.load_file(sd)
    if register:
        sid, _ = sdm.ensure_state(sd)
        subnet = _sync_registry(sd, sid, raw, check_runtime=check_runtime).subnet
    else:  # read-only callers (check): never create state or registry rows
        sid = sd.read_id() or sdm.new_id(sd.root.name)
        row = reg.find(sid)
        subnet = row.subnet if row else None
    cfg = sdm.to_config(sd, raw, sid, subnet=subnet, default_runtime=load_user_config().runtime)
    return sd, raw, sid, cfg


# --- glove new ---------------------------------------------------------------------


@app.command()
def new(
    template: str = typer.Argument(..., help="bundled template name, a path, or a git URL"),
    directory: Path = typer.Argument(Path("."), help="the session directory (created if missing)"),
    diff: bool = typer.Option(False, "--diff", help="show how the template changed since `glove new`"),
) -> None:
    """Materialize a session: glove-session.yml, work/ and .glove/ (0700)."""
    if diff:
        try:
            sd = sdm.find(directory)
        except SessionError as e:
            raise _fail(str(e)) from e
        drift = sdm.template_drift(sd)
        if drift is None:
            console.print("[green]✓[/green] the template is unchanged since `glove new`")
            return
        console.print(f"[bold]template {drift[0]} changed since `glove new`[/bold] (your file ← template now)\n")
        console.print(Syntax(drift[1], "diff", theme="ansi_dark"))
        return
    try:
        _ensure_home()
        reg.load_registry()  # refuse early on a v2 registry, before writing the directory
        sd, sid = sdm.materialize(template, directory)
        _sync_registry(sd, sid, sdm.load_file(sd))
    except (SessionError, reg.RegistryError) as e:
        raise _fail(str(e)) from e
    console.print(f"[green]✓[/green] session [bold]{sid}[/bold] from template [cyan]{template}[/cyan] at {sd.root}")
    todo = sdm.placeholders_left(sdm.load_file(sd))
    if todo:
        console.print(f"  set these in [cyan]{sd.file}[/cyan]: {', '.join(todo)}")
    cd = "" if sd.root == Path.cwd().resolve() else f"cd {sd.root} && "
    console.print(f"  then: [cyan]{cd}glove check && glove up[/cyan]")


# --- plan / up ---------------------------------------------------------------------


def _materialize_plan(sd: SessionDir, sid: str, cfg, *, resume: bool = False, session: str | None = None,
                      home: bool = True,
                      overrides: frozenset[str] = frozenset()):
    """Build the plan and write everything the session needs under .glove/
    (policies, placeholders, compose.yml, effective/baseline, the harness home).
    Returns (plan, compose yaml, seeded home files)."""
    want_resume = resume or session is not None
    prev_cfg = None
    resume_id = session
    if want_resume:
        from .harness import get_profile

        ref = _validate_resume(get_profile(cfg.harness), sd.home, session, sid)
        if ref is not None:
            resume_id = ref.id
        prev_cfg, _ = sdm.read_effective(sd.baseline)
    plan = build_session_plan(
        cfg, home_dir=str(sd.home), cwd=str(sd.work),
        resume=want_resume, session_id=resume_id, state_dir=str(sd.ext), session_dir=str(sd.root),
    )
    if prev_cfg is not None:
        from .sessions import widening_warnings

        widened = widening_warnings(prev_cfg, cfg)
        if widened:
            err.print("[yellow]⚠ resuming with broader access than the original session; prior "
                      "conversation context will run with the new grants:[/yellow]")
            for w in widened:
                err.print(f"  [yellow]•[/yellow] {w}")
    _ensure_home()
    # Export roots (observe/<id>, control/<id>) and the grants they carry:
    # created for the active owners, control/<id> revoked when filter is gone.
    from . import exports

    row = next((e for e in reg.load_registry() if e.id == sid), None)
    plan.composition.grants = exports.grants(plan.composition, row.grants if row else None)
    for note in exports.prepare(plan.composition, sd.ext):
        err.print(f"[yellow]{note}[/yellow]")
    # Extension state (e.g. SearXNG's settings) under .glove/ext/<name>/, and
    # what export-root owners write there (observe: net/session.json).
    from .extensions import materialize

    materialize(plan.composition)
    # Ring-1 policies are written before render so the read-only bind source
    # exists; they live in .glove/, never inside /work, never agent-writable.
    if plan.policies:
        enforcer_dir = sd.state / "enforcer"
        write_in_place(enforcer_dir, plan.policies)
        plan.policies_host_dir = str(enforcer_dir)
    # The adapter's read-only system config (e.g. Claude Code's managed
    # settings), likewise in .glove/ and bound read-only.
    from .mounts import make_pinned_dirs

    write_system_files(plan, sd.state / "harness")
    make_pinned_dirs(plan.protect)  # a pinned dir over a trusted file may not exist yet
    if any(p.host_path is None for p in plan.protect):
        from .mounts import write_placeholders

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
    sdm.write_effective(sd.effective, cfg, resolved)
    if not sd.baseline.exists():
        sdm.write_effective(sd.baseline, cfg)
    home_files = render_home(cfg, plan.profile, sd.home, plan.model, mount_plan=plan.mount_plan,
                             toolchains=plan.toolchains,
                             comp=plan.composition) if home else []
    return plan, rendered.compose_yaml, home_files


def _one_resume(resume: bool, session: str | None) -> None:
    if resume and session is not None:
        raise _fail("pass either --resume (last) or --session <id> (specific), not both.")


_IKNOW = typer.Option([], "--i-know-what-i-am-doing", help="waive a hardening row by key (repeatable)")


@app.command("plan")
def plan_cmd(
    directory: Path | None = _DIR_ARG,
    compose: bool = typer.Option(False, "--compose", help="also print the rendered compose project"),
    resume: bool = typer.Option(False, "--resume", "-r", help="render as `glove up --resume` would"),
    session: str | None = typer.Option(None, "--session", help="render as `glove up --session <id>` would"),
    iknow: list[str] = _IKNOW,
) -> None:
    """Render the session (writes .glove/, launches nothing) and show what it grants."""
    _one_resume(resume, session)
    try:
        sd, _, sid, cfg = _open(directory)
        plan, compose_yaml, home_files = _materialize_plan(sd, sid, cfg, resume=resume, session=session,
                                                           overrides=frozenset(iknow))
    except (ConfigError, ValueError, HardeningError, OSError, NotImplementedError) as e:
        raise _fail(str(e)) from e
    console.print(
        f"[bold]session:[/bold] {sid}  [bold]dir:[/bold] {sd.root}  [bold]harness:[/bold] {cfg.harness}  "
        f"[bold]enforcer:[/bold] {cfg.enforcer}  [bold]subnet:[/bold] {cfg.subnet or '-'}")
    console.print(f"[dim]compose project written to {sd.compose}[/dim]")
    if compose:
        console.print()
        console.print(Syntax(compose_yaml, "yaml", theme="ansi_dark"))
    _print_extensions(plan)
    _, resolved = sdm.read_effective(sd.effective)
    if resolved.get("model"):
        m = resolved["model"]
        console.print(f"    [bold]resolved at last launch[/bold] ({resolved.get('at', '?')}): model {m.get('model')}, "
                      f"vision={m.get('vision')}, context={m.get('context_window')}")
    _print_summary(plan, home_files)
    describe_host_services(cfg, sid, sd.state)


@app.command()
def up(
    directory: Path | None = _DIR_ARG,
    rebuild: bool = typer.Option(False, "--rebuild", help="rebuild the images"),
    resume: bool = typer.Option(False, "--resume", "-r", help="reopen the most recent conversation"),
    session: str | None = typer.Option(None, "--session",
                                       help="reopen a conversation by id (full/partial UUID or path)"),
    iknow: list[str] = _IKNOW,
) -> None:
    """Build, start the sidecars, resolve launch-time settings, attach the harness."""
    _one_resume(resume, session)
    try:
        sd, _, sid, cfg = _open(directory, check_runtime=True)
        todo = sdm.placeholders_left(sdm.load_file(sd))
        if todo:
            raise SessionError(f"{sd.file}: set {', '.join(todo)} first (they still say {sdm.PLACEHOLDER})")
        if cfg.runtime not in ("docker", "podman"):
            raise ConfigError(f"runtime {cfg.runtime!r} is not implemented yet; use docker or podman")
        # the harness home is rendered in prepare(), once the model is resolved
        plan, _, _ = _materialize_plan(sd, sid, cfg, resume=resume, session=session, home=False,
                                       overrides=frozenset(iknow))
        from .plan import secret_env

        # Resolve secret references (keychain:/env:) now, in memory, so a
        # missing key fails before anything starts.
        secrets = secret_env(plan)
    except (ConfigError, ValueError, HardeningError, OSError, NotImplementedError) as e:
        raise _fail(str(e)) from e

    start_host_services(cfg, sid, sd.state)
    from .session import launch

    # Only transcripts written at/after launch belong to this run (see the hint).
    launched_at = time.time()

    def prepare() -> None:
        # Launch-time resolution (e.g. llm `model: auto`) through a throwaway
        # container on the harness network, recorded in effective.yml, then the
        # final harness home.
        from dataclasses import asdict

        _resolve_extensions(plan, cfg.provider, secrets)
        # keeps what plan time recorded (the extensions' resolutions)
        _, resolved = sdm.read_effective(sd.effective)
        sdm.write_effective(sd.effective, cfg, {**resolved, "at": _now(), "model": asdict(plan.model)})
        render_home(cfg, plan.profile, sd.home, plan.model, mount_plan=plan.mount_plan, comp=plan.composition,
                    toolchains=plan.toolchains)

    import subprocess

    try:
        launch(cfg, plan, sd.compose, provider=cfg.provider, rebuild=rebuild, secrets=secrets, prepare=prepare)
    except ConfigError as e:
        raise _fail(str(e)) from e
    except subprocess.CalledProcessError as e:
        raise _fail(f"`{' '.join(e.cmd[:2])} …` failed (exit {e.returncode}); see its output above. "
                    "`glove down` removes what did start.") from e
    _print_resume_hint(plan.profile, sd.home, sid, since=launched_at)


def _resolve_extensions(plan, provider: str, secrets: dict[str, str]) -> None:
    """Run each active extension's `resolve` hook (after sidecars are up) and
    refresh the model descriptor from the inference slot's resolved exports."""
    from .extensions import base_context
    from .harnessconfig import LLM_API_KEY_ENV, harness_model
    from .session import probe_http

    comp = plan.composition
    name = plan.model.api_key_env if plan.model is not None else None
    key = {LLM_API_KEY_ENV: secrets[name]} if name in secrets else None
    for a in comp.active:
        if a.hooks is None or not hasattr(a.hooks, "resolve"):
            continue
        ex = a.exports

        def probe(url, method="GET", body=None, auth=False, _ex=ex):
            return probe_http(provider, plan, url, method=method, body=body, auth_env=key if auth else None,
                              auth_header=_ex.get("auth_header", "Authorization"),
                              auth_scheme=_ex.get("auth_scheme", "Bearer"),
                              headers=_ex.get("probe_headers") or {})

        try:
            a.exports, notes = a.hooks.resolve(base_context(comp, a), ex, probe)
        except ValueError as e:
            raise ConfigError(str(e)) from e
        for n in notes:
            console.print(f"  [cyan]{a.name}:[/cyan] {n}")
    if "inference" in comp.slots:
        plan.model = harness_model(plan.profile, comp.slot_exports("inference"))


def _validate_resume(profile, home_dir: Path, session_id: str | None, sid: str):
    """Validate a resume request, returning the resolved `SessionRef` or None.

    `--session <id>` returns the transcript find_session resolved (so the caller
    can hand the harness its canonical id). `--resume` (continue-last) returns
    None: glove only confirms *some* transcript exists — the harness makes the
    final choice of which conversation to continue."""
    from .sessions import match_session

    refs = _conversations(profile, home_dir, sid)
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


def _conversations(profile, home_dir: Path, sid: str):
    """Transcripts in the harness home, plus observe's transcripts export (where
    they are written while `transcripts: true`), newest first."""
    from .exports import export_dirs
    from .sessions import list_sessions, sessions_dir

    dirs = [sessions_dir(profile, Path(home_dir))]
    if profile.transcript_subdir == profile.sessions_subdir:
        dirs.append(export_dirs(sid)["observe"] / "transcripts")
    refs = [r for d in dirs if d.is_dir() for r in list_sessions(d)]
    return sorted(refs, key=lambda r: r.mtime, reverse=True)


def _print_resume_hint(profile, home_dir: Path, sid: str, *, since: float) -> None:
    """After the TUI exits, show how to reopen the conversation THIS run wrote
    (identified by mtime; a fresh one quit before any message leaves none)."""
    refs = [r for r in _conversations(profile, home_dir, sid) if r.mtime >= since]
    if not refs:
        return
    newest = refs[0]
    console.print(f"\n[bold]conversation saved:[/bold] {newest.id}")
    console.print("  resume last:     [cyan]glove up --resume[/cyan]")
    console.print(f"  resume this one: [cyan]glove up --session {newest.id}[/cyan]")


def _print_summary(plan, home_files) -> None:
    console.print("\n[bold]mounts[/bold]")
    for m in plan.mounts:
        console.print(f"  {m.host_path}  →  {m.container_path}  ({m.mode})")
    if plan.policies:
        console.print(
            f"[bold]enforcer[/bold] ({plan.enforcer}): "
            f"{', '.join(sorted(plan.policies))} → {plan.policies_container_dir} [dim](ro)[/dim]"
        )
    for target, files in sorted(plan.system_files.items()):
        console.print(f"[bold]harness system config[/bold]: {', '.join(sorted(files))} → {target} [dim](ro)[/dim]")
    console.print("[bold]forwarders (network allow-list)[/bold]")
    if not plan.network.sidecars:
        console.print("  [dim](none — harness is fully offline)[/dim]")
    provider = plan.composition.slots.get("forwarder")
    for s in plan.network.sidecars:
        how = f"  [cyan]({provider.name}: {s.facts.get('summary', 'implemented')})[/cyan]" if s.impl else ""
        console.print(f"  {scoped(plan.session, s.role)}:{s.listen_port}  →  {s.target}{how}")
    g = plan.composition.grants or {}
    if g.get("observe"):
        root = plan.composition.export_dirs["observe"]
        console.print(f"[bold]observe export[/bold]: {root} [dim](no harness mount except transcripts/)[/dim]"
                      + (" — transcripts exported" if g["observe"].get("transcripts") else ""))
        f = g.get("filter") or {}
        console.print("[bold]filter grant[/bold]: " + (
            f"rules.json in {plan.composition.export_dirs['control']} (ro in every gate)" if f.get("granted")
            else "none — gates never read a rules file"))
    console.print("[bold]harness config seeded[/bold]")
    for f in home_files:
        console.print(f"  {f}")
    console.print(
        "[bold]persists on host[/bold] (container /home/agent is bind-mounted):\n"
        f"  {plan.home_dir}  [dim]— config, logs/, conversation transcripts, history[/dim]"
    )


def _print_extensions(plan) -> None:
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
    for line in adapter_call(plan.profile, "describe", comp, default=[]):
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


# --- check -------------------------------------------------------------------------


@app.command()
def check(
    directory: Path | None = _DIR_ARG,
    no_container: bool = typer.Option(False, "--no-container", help="skip container probes (host-only, fast)"),
) -> None:
    """Validate the session file, check its secrets exist (never reads them),
    and run doctor for its runtime, enforcer and extensions."""

    from .config import secret_exists
    from .doctor import extension_checks, run_doctor
    from .plan import secret_refs
    from .runtimes.base import Check

    try:
        sd, raw, sid, cfg = _open(directory, register=False)
    except (ConfigError, ValueError) as e:
        raise _fail(str(e)) from e
    checks: list[Check] = [Check("session file", "ok", f"{sd.file} (schema v{sdm.SCHEMA_VERSION})")]
    plan = None
    todo = sdm.placeholders_left(raw)
    if todo:
        checks.append(Check("placeholders", "fail", f"still {sdm.PLACEHOLDER}: {', '.join(todo)}"))
    else:
        try:
            plan = build_session_plan(cfg, home_dir=str(sd.home), cwd=str(sd.work),
                                      state_dir=str(sd.ext), session_dir=str(sd.root))
            checks.append(Check("plan", "ok", "extensions: " + ", ".join(a.name for a in plan.composition.active)))
            import yaml

            try:  # in memory: every render-time invariant, for this runtime
                n = len(yaml.safe_load(get_runtime(cfg.runtime).render(plan, sd.state).compose_yaml)["services"])
                checks.append(Check("render", "ok", f"{cfg.runtime}: {n} services"))
            except (ConfigError, ValueError, NotImplementedError) as e:
                checks.append(Check("render", "fail", str(e)))
            for label, ref in secret_refs(plan):
                ok, detail = secret_exists(ref)
                checks.append(Check(f"secret {label}", "ok" if ok else "fail", f"{ref}: {detail}"))
        except (ConfigError, ValueError) as e:
            checks.append(Check("plan", "fail", str(e)))
    drift = sdm.template_drift(sd)
    if drift is not None:
        checks.append(Check("template", "warn",
                            f"{drift[0]} changed since `glove new`; review with `glove new --diff`"))
    try:
        checks += run_doctor(runtime=cfg.runtime, enforcer=cfg.enforcer, include_container_probes=not no_container)
        checks += extension_checks(cfg.extensions, harness=cfg.harness,
                                   comp=plan.composition if plan is not None else None, session_dir=sd.root)
    except ValueError as e:
        checks.append(Check("doctor", "fail", str(e)))
    _print_checks(f"[bold]glove check[/bold]  {sid}  ({sd.root})", checks)


# --- down / rm / ls / ps / gc -----------------------------------------------------------


def _stop(sd: SessionDir, sid: str, provider: str | None, *, wipe: bool) -> None:
    from .session import teardown

    cfg, _ = sdm.read_effective(sd.effective)
    provider = provider or sdm.session_provider(sd, cfg)
    if cfg is not None and cfg.host_services:
        console.print("[bold]stopping host services…[/bold]")
        try:
            stop_host_services(cfg, sid, sd.state)
        except Exception as e:
            err.print(f"[yellow]warn:[/yellow] host-service teardown skipped: {e}")
    teardown(sid, provider=provider, wipe=wipe)
    if wipe:
        # the flow/exit record and status; session.json and transcripts stay
        net = reg.observe_dir(sid) / "net"
        gone = [f for f in (*net.glob("flows*.ndjson"), *net.glob("exit*.ndjson"), net / "status.json") if f.is_file()]
        for f in gone:
            f.unlink()
        if gone:
            console.print(f"[dim]removed {len(gone)} network-observability file(s) from {net}[/dim]")


@app.command()
def down(
    directory: Path | None = _DIR_ARG,
    provider: str | None = typer.Option(None),
    wipe: bool = typer.Option(False, "--wipe", help="also remove volumes and the network-observability record"),
) -> None:
    """Stop the session's containers and host services."""
    try:
        sd = sdm.find(directory)
    except SessionError as e:
        raise _fail(str(e)) from e
    sid = sd.read_id()
    if sid is None:
        raise _fail(f"{sd.root} has never been launched (no .glove/id)")
    _stop(sd, sid, provider, wipe=wipe)


def _remove_exports(sid: str) -> list[Path]:
    gone = []
    for p in (reg.observe_dir(sid), reg.control_dir(sid)):
        if p.is_dir():
            shutil.rmtree(p)
            gone.append(p)
    return gone


@app.command()
def rm(
    directory: Path | None = _DIR_ARG,
    all_: bool = typer.Option(False, "--all", help="also delete the directory itself (work/ included)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="do not ask"),
    provider: str | None = typer.Option(None),
) -> None:
    """`down --wipe`, then delete .glove/, the exports and the registry row.
    work/ and glove-session.yml stay unless --all."""
    try:
        sd = sdm.find(directory)
    except SessionError as e:
        raise _fail(str(e)) from e
    sid = sd.read_id()
    what = f"the whole directory {sd.root}" if all_ else f"{sd.state} (work/ and {sdm.SESSION_FILE} stay)"
    if not yes and not typer.confirm(f"Remove session {sid or '(never launched)'}: {what}?", default=False):
        raise typer.Exit(1)
    if sid is not None:
        _stop(sd, sid, provider, wipe=True)
        for p in _remove_exports(sid):
            console.print(f"[dim]removed {p}[/dim]")
        try:
            reg.remove({sid})
        except reg.RegistryError as e:
            err.print(f"[yellow]warn:[/yellow] {e}")
    if all_:
        shutil.rmtree(sd.root)
    elif sd.state.exists():
        sdm.remove_state(sd)
    console.print(f"[green]✓[/green] removed {what}")


def _row_state(e: reg.SessionEntry) -> str:
    sd = SessionDir(Path(e.dir))
    if not sd.root.is_dir():
        return "missing"
    return "ok" if sd.read_id() == e.id else "stale"


@app.command("ls")
def list_cmd() -> None:
    """Registered sessions: id, harness, template, state, directory."""
    try:
        entries = reg.load_registry()
    except reg.RegistryError as e:
        raise _fail(str(e)) from e
    if not entries:
        console.print("[dim]no sessions — create one with `glove new <template> <dir>`[/dim]")
        return
    colour = {"ok": "green", "missing": "red", "stale": "yellow"}
    for e in sorted(entries, key=lambda x: x.id):
        st = _row_state(e)
        observed = " [cyan]observe[/cyan]" if (e.grants or {}).get("observe") else ""
        console.print(f"[bold]{e.id}[/bold]  [cyan]{e.harness}[/cyan]  {e.template or '-'}  "
                      f"[{colour[st]}]{st}[/{colour[st]}]{observed}  {e.dir}")
    if any(_row_state(e) != "ok" for e in entries):
        console.print("[dim]missing/stale rows (and their exports) are removed by `glove gc`[/dim]")


@app.command("ps")
def ps_cmd(runtime: str | None = typer.Option(None, "--runtime", help="docker | podman")) -> None:
    """Running glove sessions (compose projects) and their directories."""
    rt = get_runtime(runtime or sdm.autodetect_provider())
    running = rt.ps()
    if not running:
        console.print("[dim]no running glove sessions[/dim]")
        return
    try:
        dirs = {e.id: e.dir for e in reg.load_registry()}
    except reg.RegistryError:
        dirs = {}
    for s in sorted(running, key=lambda x: x.project):
        console.print(f"[bold]{s.session}[/bold]  {dirs.get(s.session, '[dim](not registered)[/dim]')}  "
                      f"[dim]({len(s.services)} containers: {', '.join(sorted(s.services))})[/dim]")


@app.command()
def gc(yes: bool = typer.Option(False, "--yes", "-y", help="do not ask")) -> None:
    """Remove registry rows whose directory is gone (or no longer that session),
    with their exports under ~/.glove/observe and ~/.glove/control."""
    try:
        entries = reg.load_registry()
    except reg.RegistryError as e:
        raise _fail(str(e)) from e
    dead = {e.id for e in entries if _row_state(e) != "ok"}
    live = {e.id for e in entries} - dead
    orphans: list[Path] = []
    for root in (reg.glove_home() / "observe", reg.glove_home() / "control"):
        if root.is_dir():
            # only v3 session ids: anything else there is not glove v3's to remove
            orphans += [p for p in sorted(root.iterdir())
                        if p.is_dir() and sdm.ID_RE.match(p.name) and p.name not in live]
    if not dead and not orphans:
        console.print("[green]✓[/green] nothing to collect")
        return
    for sid in sorted(dead):
        console.print(f"  registry row {sid}")
    for p in orphans:
        console.print(f"  {p}")
    if not yes and not typer.confirm("Remove these?", default=False):
        raise typer.Exit(1)
    for p in orphans:
        shutil.rmtree(p)
    reg.remove(dead)
    console.print(f"[green]✓[/green] removed {len(dead)} row(s), {len(orphans)} export dir(s)")


# --- keychain / build / doctor / policy ---------------------------------------------------

keychain_app = typer.Typer(add_completion=False,
                           help="Secrets in the macOS Keychain (referenced as keychain:<service>).")
app.add_typer(keychain_app, name="keychain")


@keychain_app.command("set")
def keychain_set_cmd(service: str = typer.Argument(..., help="Keychain service name")) -> None:
    """Store (or replace) a secret, prompting for it — it never appears in argv or a file."""
    from .config import keychain_set

    try:
        rc = keychain_set(service)
    except ConfigError as e:
        raise _fail(str(e)) from e
    if rc != 0:
        raise typer.Exit(rc)
    console.print(f"[green]✓[/green] stored; reference it as [cyan]keychain:{service}[/cyan]")


@app.command()
def build(
    harness: str | None = typer.Argument(
        None, help=f"harness image to build ({', '.join(known_harnesses())}); "
                   "omit to build the forwarder only"
    ),
    provider: str | None = typer.Option(None),
    enforcer: str | None = typer.Option(None, "--enforcer", help="enforcer variant (srt, nono+srt → -srt image)"),
    rebuild: bool = typer.Option(False, "--rebuild", help="force rebuild"),
) -> None:
    """Build the forwarder and (optionally) a harness base image. Extension
    images and layers are built per session by `glove up`."""
    from .harness import get_profile
    from .session import build_forwarder, build_harness

    prov = provider or sdm.autodetect_provider()
    build_forwarder(prov, force=rebuild)
    if harness:
        build_harness(prov, get_profile(harness), enforcer=enforcer or "nono", force=rebuild)


@app.command()
def doctor(
    runtime: str | None = typer.Option(None, "--runtime", help=f"probe a runtime: {', '.join(known_runtimes())}"),
    enforcer: str | None = typer.Option(None, "--enforcer", help="probe an enforcer: nono | nono+srt | srt | none"),
    json_out: bool = typer.Option(False, "--json", help="machine-readable output"),
    no_container: bool = typer.Option(False, "--no-container", help="skip container probes (host-only, fast)"),
) -> None:
    """Probe host + runtime + enforcer readiness (`glove check` adds a session's extensions)."""
    import json as _json

    from .doctor import run_doctor, worst_status
    from .enforcers.base import default_enforcer

    rt = runtime or "docker"
    enf = enforcer or default_enforcer(rt)
    try:
        checks = run_doctor(runtime=rt, enforcer=enf, include_container_probes=not no_container)
    except ValueError as e:
        raise _fail(str(e)) from e
    if json_out:
        console.print_json(_json.dumps({"runtime": rt, "enforcer": enf, "checks": [c.to_dict() for c in checks]}))
    else:
        _print_checks(f"[bold]glove doctor[/bold]  runtime={rt}  enforcer={enf}", checks)
    raise typer.Exit(1 if worst_status(checks) == "fail" else 0)


@app.command()
def policy(directory: Path | None = _DIR_ARG) -> None:
    """Print the rendered ring-1 policies and the ring-0 hardening for review."""
    try:
        sd, _, sid, cfg = _open(directory, register=False)
        plan = build_session_plan(cfg, home_dir=str(sd.home), cwd=str(sd.work), state_dir=str(sd.ext),
                                  session_dir=str(sd.root))
    except (ConfigError, ValueError) as e:
        raise _fail(str(e)) from e

    h = plan.hardening
    console.print(f"[bold]{sid}[/bold]  runtime={cfg.runtime}  enforcer={cfg.enforcer}  "
                  f"extensions={', '.join(a.name for a in plan.composition.active)}\n")
    console.print("[bold]ring 0 — hardening[/bold]")
    console.print(f"  user={h.user or 'root (allow_root)'}  cap_drop={list(h.cap_drop)}  "
                  f"cap_add={list(h.cap_add) or '[]'}  no_new_privileges={h.no_new_privileges}")
    console.print(f"  read_only={h.read_only}  ipc={h.ipc}  pids={h.limits.pids}  "
                  f"mem={h.limits.memory}  cpus={h.limits.cpus}")
    console.print(f"  seccomp={h.seccomp_profile}")
    if h.systempaths_unconfined:
        console.print("  [yellow]systempaths=unconfined[/yellow] — masked /proc,/sys exposed to the container "
                      "(srt strong)")
    console.print(f"\n[bold]harness command[/bold]\n  {' '.join(plan.harness_command)}")
    _print_extensions(plan)
    hs = [x.name for x in cfg.host_services]
    if hs:
        console.print(f"  [dim]host services (run on host): {hs}[/dim]")
    if not plan.policies:
        console.print("\n[red]no ring-1 policies (enforcer: none — container only)[/red]")
    else:
        for fname in sorted(plan.policies):
            console.print(f"\n[bold]ring 1 — {fname}[/bold]")
            console.print(Syntax(plan.policies[fname].rstrip(), "json", theme="ansi_dark"))
    from .enforcers import get_enforcer

    enf = get_enforcer(cfg.enforcer)
    if hasattr(enf, "gaps"):
        console.print("\n[bold yellow]documented gaps[/bold yellow]")
        for g in enf.gaps(plan):
            console.print(f"  [yellow]![/yellow] {g}")


# --- extension CLIs (`cli:` in a manifest → `glove <name> …`) ------------------------


def _mount_extension_clis() -> None:
    """Mount every discoverable extension's Typer app at `glove <name>`. A broken
    manifest must not break the CLI: it is reported by `glove ext`/`check`."""
    from rich.markup import escape

    from .extensions import ExtensionError, discover, load_module

    try:  # a malformed config.yml too: the commands that read it report it
        manifests = discover()
    except (ExtensionError, ConfigError):
        return
    taken = {c.name for c in app.registered_commands} | {g.name for g in app.registered_groups}
    for name, m in sorted(manifests.items()):
        if m.cli is None or name in taken:
            continue
        try:
            sub = getattr(load_module(m.cli, name), "app", None)
        except Exception as e:  # an extension's own code: anything can go wrong
            err.print(f"[yellow]warn:[/yellow] extension {name!r} CLI ({m.cli}) failed to load: {escape(str(e))}")
            continue
        if isinstance(sub, typer.Typer):
            app.add_typer(sub, name=name, help=m.summary)


@app.command("ext")
def ext_cmd() -> None:
    """Every extension glove can load, with its origin and CLI."""
    from .extensions import ExtensionError, discover

    try:
        manifests = discover()
    except ExtensionError as e:
        raise _fail(str(e)) from e
    for name, m in sorted(manifests.items()):
        tags = [m.taint, *(["library"] if not m.selectable else []),
                *([f"provides {','.join(m.provides)}"] if m.provides else []),
                *([f"cli: glove {name} …"] if m.cli else [])]
        console.print(f"[cyan]{name}[/cyan] [dim]({'; '.join(tags)})[/dim] — {m.summary}")


@app.command()
def version() -> None:
    """Print the glove version."""
    console.print(__version__)


_mount_extension_clis()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
