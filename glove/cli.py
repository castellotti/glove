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

import collections
import shutil
import sys
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
from .harness import known_harnesses
from .harnessconfig import render_home
from .hostsvc import describe_host_services, start_host_services, stop_host_services
from .plan import build_session_plan
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


def _autodetect_provider() -> str:
    if shutil.which("docker"):
        return "docker"
    if shutil.which("podman"):
        return "podman"
    return "docker"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _foreign_subnets(raw: dict, sid: str) -> set[str]:
    """Subnets of the runtime's existing networks that are not this session's."""
    try:
        nets = get_runtime(raw.get("runtime") or "docker").network_subnets()
    except (ValueError, AttributeError, OSError):
        return set()
    return {x for name, subnets in nets.items() if not name.startswith(f"glove-{sid}-") for x in subnets}


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
        foreign = _foreign_subnets(raw, sid) if (check_runtime or not row.subnet) else set()
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
        cfg, env_id=sid, home_dir=str(sd.home), cwd=str(sd.work),
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
    # Extension state (e.g. SearXNG's settings) under .glove/ext/<name>/.
    from .extensions import materialize

    materialize(plan.composition)
    # Ring-1 policies are written before render so the read-only bind source
    # exists; they live in .glove/, never inside /work, never agent-writable.
    if plan.policies:
        enforcer_dir = sd.state / "enforcer"
        enforcer_dir.mkdir(parents=True, exist_ok=True)
        for fname, content in plan.policies.items():
            (enforcer_dir / fname).write_text(content)
        plan.policies_host_dir = str(enforcer_dir)
    if any(p.host_path is None for p in plan.protect):
        from .mounts import write_placeholders

        plan.placeholder_host_dir = str(write_placeholders(sd.state / "placeholders", plan.protect))
    if plan.observe is not None:
        from .observe import control_dir, ensure_net_dir, net_dir, rules_file_problem

        plan.net_host_dir = str(ensure_net_dir(net_dir(sid)))
        plan.control_host_dir = str(ensure_net_dir(control_dir(sid)))
        problem = rules_file_problem(Path(plan.control_host_dir))
        if problem:
            err.print(
                f"[bold red]⚠ rules.json:[/bold red] {problem} — the gate runs as you, so it will "
                "reject this file (status.json rules.ok: false) and enforce no rules until it is "
                "readable. A second writer must leave it readable by you: mode 0644, or owned by you.")
    rendered = get_runtime(cfg.runtime).render(plan, sd.state, overrides=overrides)
    if plan.observe is not None:
        from .observe import session_facts, write_session_facts

        write_session_facts(Path(plan.net_host_dir), session_facts(plan))
        if plan.observe.record == "full":
            err.print(
                "[bold red]⚠ observe.record: full[/bold red] — this session writes a browsing log to "
                f"{plan.net_host_dir}: the method and URL of every cleartext HTTP request"
                + (" and request headers (credentials redacted)" if plan.observe.record_headers else "")
                + ". HTTPS paths stay invisible (no TLS interception). This trades the session's "
                "privacy for visibility; `glove net status` and Layman badge it.")
    from .observe import session_grants

    reg.update(sid, grants=session_grants(plan))
    if plan.model is None:  # unreachable: `inference` is a required slot
        raise ConfigError("no inference provider")
    sd.compose.write_text(rendered.compose_yaml)
    # effective.yml tracks the current run (`glove down` stops its host
    # services; `glove plan` shows its resolutions); baseline.yml is written
    # once, so the widening check compares against the session's origin.
    _, resolved = sdm.read_effective(sd.effective)
    sdm.write_effective(sd.effective, cfg, resolved)
    if not sd.baseline.exists():
        sdm.write_effective(sd.baseline, cfg)
    home_files = render_home(cfg, plan.profile, sd.home, plan.model, mount_plan=plan.mount_plan,
                             comp=plan.composition)
    return plan, rendered.compose_yaml, home_files


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
    if resume and session is not None:
        raise _fail("pass either --resume (last) or --session <id> (specific), not both.")
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
    if resume and session is not None:
        raise _fail("pass either --resume (last) or --session <id> (specific), not both.")
    try:
        sd, _, sid, cfg = _open(directory, check_runtime=True)
        todo = sdm.placeholders_left(sdm.load_file(sd))
        if todo:
            raise SessionError(f"{sd.file}: set {', '.join(todo)} first (they still say {sdm.PLACEHOLDER})")
        if cfg.runtime not in ("docker", "podman"):
            raise ConfigError(f"runtime {cfg.runtime!r} is not implemented yet; use docker or podman")
        plan, _, _ = _materialize_plan(sd, sid, cfg, resume=resume, session=session, overrides=frozenset(iknow))
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
        sdm.write_effective(sd.effective, cfg, {"at": _now(), "model": asdict(plan.model)})
        render_home(cfg, plan.profile, sd.home, plan.model, mount_plan=plan.mount_plan, comp=plan.composition)

    import subprocess

    try:
        launch(cfg, plan, sd.compose, provider=cfg.provider, rebuild=rebuild, secrets=secrets, prepare=prepare)
    except ConfigError as e:
        raise _fail(str(e)) from e
    except subprocess.CalledProcessError as e:
        raise _fail(f"`{' '.join(e.cmd[:2])} …` failed (exit {e.returncode}); see its output above. "
                    "`glove down` removes what did start.") from e
    _print_resume_hint(plan.profile, sd.home, since=launched_at)


def _resolve_extensions(plan, provider: str, secrets: dict[str, str]) -> None:
    """Run each active extension's `resolve` hook (after sidecars are up) and
    refresh the model descriptor from the inference slot's resolved exports."""
    from .extensions import base_context
    from .harnessconfig import LLM_API_KEY_ENV, ModelDescriptor
    from .session import probe_http

    comp = plan.composition
    for a in comp.active:
        if a.hooks is None or not hasattr(a.hooks, "resolve"):
            continue
        ex = a.exports
        key = {LLM_API_KEY_ENV: secrets[LLM_API_KEY_ENV]} if LLM_API_KEY_ENV in secrets else None

        def probe(url, method="GET", body=None, auth=False, _ex=ex, _key=key):
            return probe_http(provider, plan, url, method=method, body=body, auth_env=_key if auth else None,
                              auth_header=_ex.get("auth_header", "Authorization"),
                              auth_scheme=_ex.get("auth_scheme", "Bearer"))

        try:
            a.exports, notes = a.hooks.resolve(base_context(comp, a), ex, probe)
        except ValueError as e:
            raise ConfigError(str(e)) from e
        for n in notes:
            console.print(f"  [cyan]{a.name}:[/cyan] {n}")
    if "inference" in comp.slots:
        plan.model = ModelDescriptor.from_exports(comp.slot_exports("inference"))


def _validate_resume(profile, home_dir: Path, session_id: str | None, sid: str):
    """Validate a resume request, returning the resolved `SessionRef` or None.

    `--session <id>` returns the transcript find_session resolved (so the caller
    can hand the harness its canonical id). `--resume` (continue-last) returns
    None: glove only confirms *some* transcript exists — the harness makes the
    final choice of which conversation to continue."""
    from .sessions import list_sessions, match_session, sessions_dir

    refs = list_sessions(sessions_dir(profile, Path(home_dir)))
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


def _print_resume_hint(profile, home_dir: Path, *, since: float) -> None:
    """After the TUI exits, show how to reopen the conversation THIS run wrote
    (identified by mtime; a fresh one quit before any message leaves none)."""
    from .sessions import list_sessions, sessions_dir

    refs = [r for r in list_sessions(sessions_dir(profile, Path(home_dir))) if r.mtime >= since]
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
    console.print("[bold]forwarders (network allow-list)[/bold]")
    if not plan.network.sidecars:
        console.print("  [dim](none — harness is fully offline)[/dim]")
    for s in plan.network.sidecars:
        gate = (
            f"  [cyan](netgate {s.gate.mode}, tool={s.gate.tool}, "
            f"scope={s.gate.scope or 'per-destination'})[/cyan]"
            if s.gate else ""
        )
        console.print(f"  glove-{plan.session}-{s.role}:{s.listen_port}  →  {s.target}{gate}")
    if plan.observe is not None and plan.net_host_dir:
        console.print(
            f"[bold]network observability[/bold] (record={plan.observe.record}): flows → "
            f"{plan.net_host_dir} [dim](collector only; no harness mount)[/dim]"
        )
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
    for ext, src in comp.pi_extensions:
        console.print(f"    pi extension ({ext}): {comp.pi_extension_dest(ext, src)}")
    for key, privs in comp.privileges.items():
        console.print(f"    [yellow]privilege exception[/yellow] {key}: {privs}")
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
    from rich.markup import escape

    from .config import secret_exists
    from .doctor import extension_checks, run_doctor, worst_status
    from .plan import secret_refs
    from .runtimes.base import Check

    try:
        sd, raw, sid, cfg = _open(directory, register=False)
    except (ConfigError, ValueError) as e:
        raise _fail(str(e)) from e
    checks: list[Check] = [Check("session file", "ok", f"{sd.file} (schema v{sdm.SCHEMA_VERSION})")]
    todo = sdm.placeholders_left(raw)
    if todo:
        checks.append(Check("placeholders", "fail", f"still {sdm.PLACEHOLDER}: {', '.join(todo)}"))
    else:
        try:
            plan = build_session_plan(cfg, env_id=sid, home_dir=str(sd.home), cwd=str(sd.work),
                                      state_dir=str(sd.ext), session_dir=str(sd.root))
            checks.append(Check("plan", "ok", "extensions: " + ", ".join(a.name for a in plan.composition.active)))
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
        checks += extension_checks(cfg.extensions, harness=cfg.harness)
    except ValueError as e:
        checks.append(Check("doctor", "fail", str(e)))
    glyph = {"ok": "[green]✓[/green]", "warn": "[yellow]![/yellow]", "fail": "[red]✗[/red]",
             "info": "[cyan]·[/cyan]", "skip": "[dim]-[/dim]"}
    console.print(f"[bold]glove check[/bold]  {sid}  ({sd.root})\n")
    for c in checks:
        console.print(f"  {glyph.get(c.status, '?')} [bold]{escape(c.name)}[/bold]  [dim]{escape(c.detail)}[/dim]")
    raise typer.Exit(1 if worst_status(checks) == "fail" else 0)


# --- down / rm / ls / ps / gc -----------------------------------------------------------


def _stop(sd: SessionDir, sid: str, provider: str, *, wipe: bool) -> None:
    from .session import teardown

    cfg, _ = sdm.read_effective(sd.effective)
    if cfg is not None and cfg.host_services:
        console.print("[bold]stopping host services…[/bold]")
        try:
            stop_host_services(cfg, sid, sd.state)
        except Exception as e:
            err.print(f"[yellow]warn:[/yellow] host-service teardown skipped: {e}")
    teardown(sid, provider=provider, wipe=wipe)
    if wipe:
        from .observe import net_dir, wipe_flow_record

        removed = wipe_flow_record(net_dir(sid))
        if removed:
            console.print(f"[dim]removed {removed} network-observability file(s) from {net_dir(sid)}[/dim]")


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
    _stop(sd, sid, provider or _autodetect_provider(), wipe=wipe)


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
        _stop(sd, sid, provider or _autodetect_provider(), wipe=True)
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
    rt = get_runtime(runtime or _autodetect_provider())
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
                   "omit to build the forwarder + netgate only"
    ),
    provider: str | None = typer.Option(None),
    enforcer: str | None = typer.Option(None, "--enforcer", help="build the enforcer variant (e.g. srt → -srt image)"),
    rebuild: bool = typer.Option(False, "--rebuild", help="force rebuild"),
) -> None:
    """Build the forwarder + netgate and (optionally) a harness base image.
    Extension layers are composed per session by `glove up`."""
    from .harness import get_profile
    from .observe import build_netgate
    from .session import build_forwarder, build_harness

    prov = provider or _autodetect_provider()
    build_forwarder(prov, force=rebuild)
    build_netgate(prov, force=rebuild, console=console)
    if harness:
        build_harness(prov, get_profile(harness), enforcer=enforcer or "nono", force=rebuild)


@app.command()
def doctor(
    runtime: str | None = typer.Option(None, "--runtime", help=f"probe a runtime: {', '.join(known_runtimes())}"),
    enforcer: str | None = typer.Option(None, "--enforcer", help="probe an enforcer: nono | srt | none"),
    json_out: bool = typer.Option(False, "--json", help="machine-readable output"),
    no_container: bool = typer.Option(False, "--no-container", help="skip container probes (host-only, fast)"),
) -> None:
    """Probe host + runtime + enforcer readiness (`glove check` adds a session's extensions)."""
    import json as _json

    from rich.markup import escape

    from .doctor import run_doctor, worst_status

    rt, enf = runtime or "docker", enforcer or "nono"
    try:
        checks = run_doctor(runtime=rt, enforcer=enf, include_container_probes=not no_container)
    except ValueError as e:
        raise _fail(str(e)) from e
    if json_out:
        console.print_json(_json.dumps({"runtime": rt, "enforcer": enf, "checks": [c.to_dict() for c in checks]}))
    else:
        glyph = {"ok": "[green]✓[/green]", "warn": "[yellow]![/yellow]", "fail": "[red]✗[/red]",
                 "info": "[cyan]·[/cyan]", "skip": "[dim]-[/dim]"}
        console.print(f"[bold]glove doctor[/bold]  runtime={rt}  enforcer={enf}\n")
        for c in checks:
            console.print(f"  {glyph.get(c.status, '?')} [bold]{escape(c.name)}[/bold]  [dim]{escape(c.detail)}[/dim]")
    raise typer.Exit(1 if worst_status(checks) == "fail" else 0)


@app.command()
def policy(directory: Path | None = _DIR_ARG) -> None:
    """Print the rendered ring-1 policies and the ring-0 hardening for review."""
    try:
        sd, _, sid, cfg = _open(directory, register=False)
        plan = build_session_plan(cfg, env_id=sid, home_dir=str(sd.home), cwd=str(sd.work), state_dir=str(sd.ext),
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


# --- net (network observability; moves to the observe/filter extensions in M5) ----------

net_app = typer.Typer(add_completion=False, help="Network observability: gate status, flow records, rules.")
app.add_typer(net_app, name="net")

_NET_DIR_OPT = typer.Option(None, "--dir", help="session directory (default: the nearest one)")


def _net_session(directory: Path | None) -> str:
    sd = sdm.find(directory)
    sid = sd.read_id()
    if sid is None:
        raise SessionError(f"{sd.root} has never been launched (no .glove/id)")
    return sid


@net_app.command("status")
def net_status(
    directory: Path | None = _NET_DIR_OPT,
    json_out: bool = typer.Option(False, "--json", help="machine-readable output"),
) -> None:
    """Gate health, record mode, services, upstream and resolver state."""
    import json as _json

    from .netview import render_status, summarize
    from .observe import net_dir

    try:
        sid = _net_session(directory)
    except ConfigError as e:
        raise _fail(str(e)) from e
    ndir = net_dir(sid)
    summary = summarize(ndir)
    if json_out:
        console.print_json(_json.dumps(summary))
        return
    for line in render_status(sid, ndir, summary):
        console.print(line, highlight=False)
    if not summary["observed"]:
        raise typer.Exit(1)


@net_app.command("flows")
def net_flows(
    directory: Path | None = _NET_DIR_OPT,
    follow: bool = typer.Option(False, "--follow", "-f", help="keep tailing (survives rotation)"),
    json_out: bool = typer.Option(False, "--json", help="print raw NDJSON records"),
    tail: int | None = typer.Option(None, "--tail", "-n", help="only the last N records"),
) -> None:
    """Print the session's flow records (rotated files first, then live)."""
    import json as _json

    from .netview import follow_records, format_record, iter_records
    from .observe import net_dir

    try:
        ndir = net_dir(_net_session(directory))
    except ConfigError as e:
        raise _fail(str(e)) from e
    if not ndir.is_dir():
        raise _fail(f"no net/ dir at {ndir} — is `observe.enabled` on for this session?")

    def emit(rec: dict) -> None:
        if json_out:
            print(_json.dumps(rec, separators=(",", ":")), flush=True)
        else:
            console.print(format_record(rec), highlight=False)

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


def _rules_target(directory: Path | None) -> tuple[str, Path]:
    """(session id, rules.json path). The id is both the rules file's `env`
    and its `session` (Layman handoff §3)."""
    from .observe import control_dir

    sid = _net_session(directory)
    return sid, control_dir(sid) / "rules.json"


@net_app.command("block")
def net_block(
    target: str = typer.Argument(..., help="host glob (e.g. '*.doubleclick.net'), IP, or CIDR"),
    port: int | None = typer.Option(None, "--port", help="only this destination port"),
    terminate: bool = typer.Option(False, "--terminate", help="also cut matching established flows"),
    allow: bool = typer.Option(False, "--allow", help="write an allow rule instead (e.g. under default block)"),
    note: str | None = typer.Option(None, "--note", help="free-text note shown in `glove net rules`"),
    directory: Path | None = _NET_DIR_OPT,
) -> None:
    """Append a rule to the session's rules.json (the file Layman writes too).

    Rules apply to new connections within ~1s; --terminate also cuts matching
    established ones. glove's built-in SSRF guard runs first and cannot be
    overridden by an allow rule."""
    from .netgate.policy import PolicyError
    from .netrules import block_rule, load, save

    try:
        sid, path = _rules_target(directory)
        data = load(path, sid, sid)
        rule = block_rule(target, port=port, terminate=terminate, note=note, action="allow" if allow else "block")
        data["rules"] = [*data["rules"], rule]
        save(path, data, sid, sid)
    except (ConfigError, PolicyError, OSError) as e:
        raise _fail(str(e)) from e
    console.print(f"[green]✓[/green] {rule['action']} {rule['match']} → {rule['id']}  [dim]{path}[/dim]")


@net_app.command("unblock")
def net_unblock(
    key: str = typer.Argument(..., help="rule id (r_…) or the exact host glob / IP / CIDR it matches"),
    directory: Path | None = _NET_DIR_OPT,
) -> None:
    """Remove rules by id or by the exact target they match."""
    from .netgate.policy import PolicyError
    from .netrules import load, remove, save

    try:
        sid, path = _rules_target(directory)
        data = load(path, sid, sid)
        gone = remove(data, key)
        if not gone:
            err.print(f"[yellow]no rule matches {key!r}[/yellow]")
            raise typer.Exit(1)
        save(path, data, sid, sid)
    except (ConfigError, PolicyError, OSError) as e:
        raise _fail(str(e)) from e
    for r in gone:
        console.print(f"[green]✓[/green] removed {r['id']} ({r['action']} {r['match']})")


def _rules_file_state(path: Path, st: dict) -> str:
    """Whether the gate has enforced or rejected the bytes now on disk, by
    SHA-256 (status.json `rules.sha256` / `rules.last_rejected.sha256`)."""
    from .netgate.policy import PolicyError, read_file, sha256_hex

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


@net_app.command("validate")
def net_validate(
    file: str = typer.Argument(..., help="rules.json to check, or - for stdin"),
    env: str | None = typer.Option(None, "--env", help="the gate's session id: the file's `env` must equal it"),
    session: str | None = typer.Option(None, "--session", help="the file's `session` must equal it (the session id)"),
    json_out: bool = typer.Option(False, "--json", help="one JSON object on stdout"),
) -> None:
    """Check a rules file with the gate's own validator. Pure: reads only FILE —
    no ~/.glove, no Docker, no network. Exit 0 when the gate would accept it,
    1 when it would reject it."""
    import json as _json

    from rich.markup import escape

    from .netgate.policy import PolicyError, parse_bytes, read_file, sha256_hex

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
        print(_json.dumps(result), flush=True)
    elif rs is not None:
        console.print(f"[green]✓[/green] valid: default {result['default']}, {result['active_count']} rule(s)  "
                      f"[dim]sha256 {result['sha256']}[/dim]", highlight=False)
    else:
        err.print(f"[red]✗ rejected:[/red] {escape(error)}", highlight=False)
    if rs is None:
        raise typer.Exit(1)


@net_app.command("rules")
def net_rules(
    directory: Path | None = _NET_DIR_OPT,
    json_out: bool = typer.Option(False, "--json", help="print the rules document"),
) -> None:
    """Show the effective rules, their provenance, and the gate's load result."""
    import json as _json

    from .netgate.policy import PolicyError
    from .netgate.writer import read_json_dict
    from .netrules import load
    from .observe import net_dir

    try:
        sid, path = _rules_target(directory)
    except ConfigError as e:
        raise _fail(str(e)) from e
    try:
        data, problem = load(path, sid, sid), None
    except PolicyError as e:
        data, problem = None, str(e)
    if json_out:
        console.print_json(_json.dumps(data or {"error": problem}))
        return
    status = read_json_dict(net_dir(sid) / "status.json") or {}
    console.print(f"[bold]{sid}[/bold]  [dim]{path}[/dim]")
    if problem:
        console.print(f"  [red]rules.json is invalid:[/red] {problem}")
        console.print("  [dim]the gate keeps its last known-good set until this is fixed[/dim]")
        raise typer.Exit(1)
    st = status.get("rules") or {}
    if st:
        state = "[green]loaded[/green]" if st.get("ok") else f"[red]REJECTED[/red] — {st.get('error')}"
        console.print(f"  gate: {state}  active={st.get('active_count')}  loaded_at={st.get('loaded_at')}")
        console.print(f"  this file: {_rules_file_state(path, st)}")
    console.print(f"  default: {data['default']}   updated_by: {data.get('updated_by')} at {data.get('updated_at')}")
    console.print("  [dim]then glove's built-in SSRF guard (always first, not overridable)[/dim]")
    rules = data["rules"]
    if not rules:
        console.print("  [dim](no rules)[/dim]")
    for i, r in enumerate(rules, 1):
        extra = ("  terminate" if r.get("terminate") else "") + (f"  # {r['note']}" if r.get("note") else "")
        console.print(f"  {i:>2}. {r['action']:<5} {r['match']}  [dim]{r['id']}[/dim]{extra}", highlight=False)


@app.command()
def version() -> None:
    """Print the glove version."""
    console.print(__version__)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
