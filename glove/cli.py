"""glove command-line interface.

A session is a directory holding ``glove-session.yml`` (see
``glove/sessiondir.py``). Every session command takes an optional directory
and otherwise uses the nearest session at or above the cwd:

    glove new <template|path|git-url> [dir]    materialize a session
    glove check | plan | up | down | rm         work with one session
    glove ls | ps | gc                          all sessions (~/.glove/registry.json)
    glove keychain set <service> [--stdin]      store a secret, prompting for it (or piped)
    glove downloads mark [dir]                  quarantine what the sidecars saved (macOS)
"""

from __future__ import annotations

import shutil
import time
from datetime import datetime
from pathlib import Path

import typer
from rich.syntax import Syntax

from . import registry as reg
from . import sessiondir as sdm
from .config import ConfigError
from .hardening import HardeningError
from .harnessconfig import render_home
from .naming import scoped
from .plan import build_session_plan, write_in_place, write_system_files
from .runtimes import get_runtime
from .sessiondir import SessionDir, SessionError
from .sessionops import (
    DIR_ARG,
    console,
    ensure_home,
    err,
    fail,
    mark_downloads,
    now,
    open_session,
    print_extensions,
    sync_registry,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Run agentic harnesses inside constrained Docker/Podman sandboxes. A session is a directory.",
    # Rich collapses single newlines, so each line is its own paragraph.
    epilog="\n\n".join([
        "[bold]Common[/bold] (in the session directory, or pass it; each command takes --help):",
        "[cyan]glove check && glove up[/cyan]  start the session, or reattach to it",
        "[cyan]glove playwright view --control[/cyan]  watch and drive its browser "
        "(playwright mode: novnc, allow_control: true); without --control, watch only",
        "[cyan]glove down[/cyan]  stop it",
    ]),
)

# `glove up` tries this many subnets when other sessions' networks keep taking
# the one it picked (see session.SubnetTaken).
SUBNET_ATTEMPTS = 3


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
            raise fail(str(e)) from e
        drift = sdm.template_drift(sd)
        if drift is None:
            console.print("[green]✓[/green] the template is unchanged since `glove new`")
            return
        console.print(f"[bold]template {drift[0]} changed since `glove new`[/bold] (your file ← template now)\n")
        console.print(Syntax(drift[1], "diff", theme="ansi_dark"))
        return
    try:
        ensure_home()
        reg.load_registry()  # refuse early on a v2 registry, before writing the directory
        sd, sid = sdm.materialize(template, directory)
        sync_registry(sd, sid, sdm.load_file(sd))
    except (SessionError, reg.RegistryError) as e:
        raise fail(str(e)) from e
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
    for o in plan.composition.outputs:
        # an older glove kept these in work/<name>/: the new mount hides that directory
        old = sd.work / o.name
        if old.is_dir() and not old.is_symlink() and any(old.iterdir()):
            err.print(f"[yellow]⚠ work/{o.name}/ has files that /work/{o.name} no longer shows: it is now "
                      f"{o.host}; move them there[/yellow]")
    if prev_cfg is not None:
        from .sessions import widening_warnings

        widened = widening_warnings(prev_cfg, cfg)
        if widened:
            err.print("[yellow]⚠ resuming with broader access than the original session; prior "
                      "conversation context will run with the new grants:[/yellow]")
            for w in widened:
                err.print(f"  [yellow]•[/yellow] {w}")
    ensure_home()
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
    from .mounts import make_bind_sources

    write_system_files(plan, sd.state / "harness")
    # a pinned dir, the config home or a file protected in it, or a tmpfs mount
    # point under the read-only home may not exist yet
    make_bind_sources(plan.protect, plan.home_dir, plan.hardening.tmpfs)
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
    # the dirs sidecars write (`glove down` quarantines them without re-planning)
    resolved["outputs"] = [o.name for o in plan.composition.outputs if not o.input]
    sdm.write_effective(sd.effective, cfg, resolved)
    if not sd.baseline.exists():
        sdm.write_effective(sd.baseline, cfg)
    home_files = render_home(cfg, plan, sd.home) if home else []
    return plan, rendered.compose_yaml, home_files


def _one_resume(resume: bool, session: str | None) -> None:
    if resume and session is not None:
        raise fail("pass either --resume (last) or --session <id> (specific), not both.")


_IKNOW = typer.Option([], "--i-know-what-i-am-doing", help="waive a hardening row by key (repeatable)")


@app.command("plan")
def plan_cmd(
    directory: Path | None = DIR_ARG,
    compose: bool = typer.Option(False, "--compose", help="also print the rendered compose project"),
    resume: bool = typer.Option(False, "--resume", "-r", help="render as `glove up --resume` would"),
    session: str | None = typer.Option(None, "--session", help="render as `glove up --session <id>` would"),
    iknow: list[str] = _IKNOW,
) -> None:
    """Render the session (writes .glove/, launches nothing) and show what it grants."""
    _one_resume(resume, session)
    try:
        sd, _, sid, cfg = open_session(directory)
        plan, compose_yaml, home_files = _materialize_plan(sd, sid, cfg, resume=resume, session=session,
                                                           overrides=frozenset(iknow))
    except (ConfigError, ValueError, HardeningError, OSError, NotImplementedError) as e:
        raise fail(str(e)) from e
    import json

    from .enforcers import OPTION_SECTIONS

    # the options of the enforcer's own sections not at their defaults (nono.browsers widens ring 1: /proc)
    changed = ", ".join(f"{e}.{k}: {json.dumps(v)}" for e, opts in cfg.enforcer_options.items()
                        if e in cfg.enforcer.split("+")
                        for k, v in opts.items() if v != OPTION_SECTIONS[e][k]["default"])
    console.print(
        f"[bold]session:[/bold] {sid}  [bold]dir:[/bold] {sd.root}  [bold]harness:[/bold] {cfg.harness}  "
        f"[bold]enforcer:[/bold] {cfg.enforcer}{f' ({changed})' if changed else ''}  "
        f"[bold]subnet:[/bold] {cfg.subnet or '-'}")
    console.print(f"[dim]compose project written to {sd.compose}[/dim]")
    if compose:
        console.print()
        console.print(Syntax(compose_yaml, "yaml", theme="ansi_dark"))
    print_extensions(plan)
    _, resolved = sdm.read_effective(sd.effective)
    if resolved.get("model"):
        m = resolved["model"]
        console.print(f"    [bold]resolved at last launch[/bold] ({resolved.get('at', '?')}): model {m.get('model')}, "
                      f"vision={m.get('vision')}, context={m.get('context_window')}")
    _print_summary(plan, home_files)


@app.command()
def up(
    directory: Path | None = DIR_ARG,
    rebuild: bool = typer.Option(False, "--rebuild", help="rebuild the images"),
    resume: bool = typer.Option(False, "--resume", "-r", help="reopen the most recent conversation"),
    session: str | None = typer.Option(None, "--session",
                                       help="reopen a conversation by id (full/partial UUID or path)"),
    iknow: list[str] = _IKNOW,
) -> None:
    """Build, start the sidecars, resolve launch-time settings, attach the harness."""
    import subprocess
    from functools import partial

    from .extsession import run_teardown
    from .plan import secret_env
    from .session import SubnetTaken, launch

    _one_resume(resume, session)
    secrets: dict[str, str] | None = None
    for attempt in range(1, SUBNET_ATTEMPTS + 1):
        # (again after SubnetTaken: _sync_registry re-allocates a subnet a foreign network took)
        sd, sid, cfg, plan = _plan_up(directory, resume, session, iknow)
        if secrets is None:  # the checks and the secrets don't depend on the subnet: once
            try:
                preflight(sd, cfg, plan)
                try:
                    # Resolve secret references (keychain:/env:) now, in memory, so a
                    # missing key fails before any container starts.
                    secrets = secret_env(plan)
                except BaseException:  # Ctrl-C and a hook's bug too
                    for w in run_teardown(sd, sid, cfg.provider, cfg.extensions):  # what a launch_env started
                        err.print(f"[yellow]warn:[/yellow] {w}")
                    raise
            except (ConfigError, ValueError, HardeningError, OSError, NotImplementedError,
                    subprocess.SubprocessError) as e:
                raise fail(str(e)) from e
        # Only transcripts written at/after launch belong to this run (see the hint).
        launched_at = time.time()
        try:
            launch(cfg, plan, sd.compose, provider=cfg.provider, rebuild=rebuild and attempt == 1, secrets=secrets,
                   prepare=partial(prepare_harness, sd, cfg, plan))
        except SubnetTaken as e:
            if attempt == SUBNET_ATTEMPTS:
                raise fail(f"{e} — gave up after {attempt} attempts") from e
            err.print(f"[yellow]⚠[/yellow] {e}; re-allocating and retrying")
            continue
        except ConfigError as e:
            raise fail(str(e)) from e
        except subprocess.CalledProcessError as e:
            raise fail(f"`{' '.join(e.cmd[:2])} …` failed (exit {e.returncode}); see its output above. "
                        "`glove down` removes what did start.") from e
        _print_resume_hint(plan.profile, sd.home, sid, since=launched_at)
        return


def _plan_up(directory, resume: bool, session: str | None, iknow: list[str]):
    """(session dir, id, Config, plan) for `glove up`, the harness home left for
    prepare_harness (it needs the resolved model)."""
    try:
        sd, _, sid, cfg = open_session(directory, check_runtime=True)
        todo = sdm.placeholders_left(sdm.load_file(sd))
        if todo:
            raise SessionError(f"{sd.file}: set {', '.join(todo)} first (they still say {sdm.PLACEHOLDER})")
        if cfg.runtime not in ("docker", "podman"):
            raise ConfigError(f"runtime {cfg.runtime!r} is not implemented yet; use docker or podman")
        plan, _, _ = _materialize_plan(sd, sid, cfg, resume=resume, session=session, home=False,
                                       overrides=frozenset(iknow))
    except (ConfigError, ValueError, HardeningError, OSError, NotImplementedError) as e:
        raise fail(str(e)) from e
    return sd, sid, cfg, plan


def preflight(sd, cfg, plan) -> None:
    """Before `glove up` starts anything: the extensions' own checks (e.g. a
    host Chrome for playwright's host mode) refuse the launch when one fails,
    and so does this session's harness still running. (The plan, the render
    and the secrets were checked on the way here; `glove check` adds the
    runtime and enforcer probes.)"""
    from .doctor import extension_checks
    from .session import clear_stale_harness

    failed = [c for c in extension_checks(cfg.extensions, harness=cfg.harness, comp=plan.composition,
                                          session_dir=sd.root) if c.status == "fail"]
    if failed:
        raise ConfigError("an extension check fails, so nothing was started:\n" +
                          "\n".join(f"  {c.name}: {c.detail}" for c in failed))
    clear_stale_harness(cfg.provider, plan.harness_service)


def prepare_harness(sd, cfg, plan) -> None:
    """`glove up` once the sidecars are up: launch-time resolution (e.g. llm
    `model: auto`) through a throwaway container on the harness network,
    recorded in effective.yml, then the final harness home."""
    from dataclasses import asdict

    _resolve_extensions(plan, cfg.provider)
    # keeps what plan time recorded (the extensions' resolutions)
    _, resolved = sdm.read_effective(sd.effective)
    sdm.write_effective(sd.effective, cfg, {**resolved, "at": now(), "model": asdict(plan.model)})
    render_home(cfg, plan, sd.home)


def _resolve_extensions(plan, provider: str) -> None:
    """Run each active extension's `resolve` hook (after sidecars are up) and
    refresh the model descriptor from the inference slot's resolved exports."""
    from functools import partial

    from .extensions import call_hook
    from .harnessconfig import harness_model
    from .session import probe_http, with_headers

    comp = plan.composition
    for a in comp.active:
        if "resolve" not in a.hooks:
            continue
        probe = with_headers(partial(probe_http, provider, plan), a.exports)
        exports, notes = call_hook(comp, a, "resolve", a.exports, probe)
        a.set_exports(exports)
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


# --- down / rm -----------------------------------------------------------


def _stop(sd: SessionDir, sid: str, provider: str | None, *, wipe: bool, mark: bool = True) -> None:
    from .extsession import run_teardown
    from .session import teardown

    cfg, _ = sdm.read_effective(sd.effective)
    provider = provider or sdm.session_provider(sd, cfg)
    for w in run_teardown(sd, sid, provider, cfg.extensions if cfg is not None else {}):
        err.print(f"[yellow]warn:[/yellow] {w}")
    teardown(sid, provider=provider, wipe=wipe)
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


@app.command()
def down(
    directory: Path | None = DIR_ARG,
    provider: str | None = typer.Option(None),
    wipe: bool = typer.Option(False, "--wipe", help="also remove volumes and the network-observability record"),
) -> None:
    """Stop the session's containers and host services."""
    try:
        sd = sdm.find(directory)
    except SessionError as e:
        raise fail(str(e)) from e
    sid = sd.read_id()
    if sid is None:
        raise fail(f"{sd.root} has never been launched (no .glove/id)")
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
    directory: Path | None = DIR_ARG,
    all_: bool = typer.Option(False, "--all", help="also delete the directory itself (work/ included)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="do not ask"),
    provider: str | None = typer.Option(None),
) -> None:
    """`down --wipe`, then delete .glove/, the exports and the registry row.
    work/ and glove-session.yml stay unless --all."""
    try:
        sd = sdm.find(directory)
    except SessionError as e:
        raise fail(str(e)) from e
    sid = sd.read_id()
    what = f"the whole directory {sd.root}" if all_ else f"{sd.state} (work/ and {sdm.SESSION_FILE} stay)"
    if not yes and not typer.confirm(f"Remove session {sid or '(never launched)'}: {what}?", default=False):
        raise typer.Exit(1)
    if sid is not None:
        _stop(sd, sid, provider, wipe=True, mark=not all_)  # --all deletes them
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


# --- commands (`commands/<name>/cli.py` → `glove <name>`) -------------------------------

COMMANDS_DIR = Path(__file__).resolve().parent.parent / "commands"


def _mount_commands() -> None:
    """Mount each in-tree command: its `cli.py`'s `command` (a function) as
    `glove <name>`, or its `app` (a Typer) as the group `glove <name> …`.
    Commands import only glove.api(.commands); core loads them by path."""
    from .extensions import load_module

    for d in sorted(p for p in COMMANDS_DIR.iterdir() if (p / "cli.py").is_file()):
        m = load_module(d / "cli.py", d.name, ns="glove_cmd")
        if hasattr(m, "command"):
            app.command(d.name)(m.command)
        else:
            app.add_typer(m.app, name=d.name)


_mount_commands()
_mount_extension_clis()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
