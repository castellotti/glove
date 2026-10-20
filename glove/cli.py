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

import time
from pathlib import Path

import typer

from . import sessiondir as sdm
from .config import ConfigError
from .hardening import HardeningError
from .harnessconfig import render_home
from .sessiondir import SessionError
from .sessionops import (
    DIR_ARG,
    IKNOW,
    console,
    conversations,
    err,
    fail,
    materialize_plan,
    now,
    one_resume,
    open_session,
    stop,
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


# --- plan / up ---------------------------------------------------------------------


@app.command()
def up(
    directory: Path | None = DIR_ARG,
    rebuild: bool = typer.Option(False, "--rebuild", help="rebuild the images"),
    resume: bool = typer.Option(False, "--resume", "-r", help="reopen the most recent conversation"),
    session: str | None = typer.Option(None, "--session",
                                       help="reopen a conversation by id (full/partial UUID or path)"),
    iknow: list[str] = IKNOW,
) -> None:
    """Build, start the sidecars, resolve launch-time settings, attach the harness."""
    import subprocess
    from functools import partial

    from .extsession import run_teardown
    from .plan import secret_env
    from .session import SubnetTaken, launch

    one_resume(resume, session)
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
        plan, _, _ = materialize_plan(sd, sid, cfg, resume=resume, session=session, home=False,
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


def _print_resume_hint(profile, home_dir: Path, sid: str, *, since: float) -> None:
    """After the TUI exits, show how to reopen the conversation THIS run wrote
    (identified by mtime; a fresh one quit before any message leaves none)."""
    refs = [r for r in conversations(profile, home_dir, sid) if r.mtime >= since]
    if not refs:
        return
    newest = refs[0]
    console.print(f"\n[bold]conversation saved:[/bold] {newest.id}")
    console.print("  resume last:     [cyan]glove up --resume[/cyan]")
    console.print(f"  resume this one: [cyan]glove up --session {newest.id}[/cyan]")


# --- down / rm -----------------------------------------------------------


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
    stop(sd, sid, provider, wipe=wipe)


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
