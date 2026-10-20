"""`glove up` — build, start the sidecars, resolve launch-time settings, attach the harness."""

from __future__ import annotations

import subprocess
import time
from dataclasses import asdict
from functools import partial
from pathlib import Path

import typer
from rich.markup import escape

from glove.api import ConfigError
from glove.api.commands import (
    DIR_ARG,
    IKNOW,
    PLACEHOLDER,
    HardeningError,
    SessionError,
    SubnetTaken,
    call_hook,
    clear_stale_harness,
    console,
    conversations,
    err,
    extension_checks,
    fail,
    harness_model,
    launch,
    materialize_plan,
    now,
    one_resume,
    open_session,
    placeholders_left,
    probe_http,
    read_effective,
    render_home,
    run_teardown,
    secret_env,
    with_headers,
    write_effective,
)

RANK = 3  # its place in `glove --help` (commands/README.md)

# `glove up` tries this many subnets when other sessions' networks keep taking
# the one it picked (see SubnetTaken).
SUBNET_ATTEMPTS = 3


def command(
    directory: Path | None = DIR_ARG,
    rebuild: bool = typer.Option(False, "--rebuild", help="rebuild the images"),
    resume: bool = typer.Option(False, "--resume", "-r", help="reopen the most recent conversation"),
    session: str | None = typer.Option(None, "--session",
                                       help="reopen a conversation by id (full/partial UUID or path)"),
    iknow: list[str] = IKNOW,
) -> None:
    """Build, start the sidecars, resolve launch-time settings, attach the harness."""
    one_resume(resume, session)
    secrets: dict[str, str] | None = None
    source = _source_stamp()
    for attempt in range(1, SUBNET_ATTEMPTS + 1):
        # (again after SubnetTaken: sync_registry re-allocates a subnet a foreign network took)
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
        sidecars: dict[str, str] = {}  # id → StartedAt as the harness starts (after the sidecars and prepare)
        try:
            launch(cfg, plan, sd.compose, provider=cfg.provider, rebuild=rebuild and attempt == 1, secrets=secrets,
                   prepare=partial(_prepare_then_snapshot, sd, cfg, plan, sidecars))
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
        _after_harness(cfg.provider, plan.project, sidecars, source)
        return


def _plan_up(directory, resume: bool, session: str | None, iknow: list[str]):
    """(session dir, id, Config, plan) for `glove up`, the harness home left for
    prepare_harness (it needs the resolved model)."""
    try:
        sd, raw, sid, cfg = open_session(directory, check_runtime=True)
        todo = placeholders_left(raw)
        if todo:
            raise SessionError(f"{sd.file}: set {', '.join(todo)} first (they still say {PLACEHOLDER})")
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
    _resolve_extensions(plan, cfg.provider)
    # keeps what plan time recorded (the extensions' resolutions)
    _, resolved = read_effective(sd.effective)
    write_effective(sd.effective, cfg, {**resolved, "at": now(), "model": asdict(plan.model)})
    render_home(cfg, plan, sd.home)


def _prepare_then_snapshot(sd, cfg, plan, sidecars: dict[str, str]) -> None:
    prepare_harness(sd, cfg, plan)
    sidecars.update(_started(cfg.provider, plan.project) or {})


def _resolve_extensions(plan, provider: str) -> None:
    """Run each active extension's `resolve` hook (after sidecars are up) and
    refresh the model descriptor from the inference slot's resolved exports."""
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
    try:
        refs = [r for r in conversations(profile, home_dir, sid) if r.mtime >= since]
    except Exception as e:  # never a traceback over the harness's own exit
        console.print(f"[dim]couldn't list the saved conversation ({escape(str(e))}); "
                      "`glove up --resume` still works[/dim]")
        return
    if not refs:
        return
    newest = refs[0]
    console.print(f"\n[bold]conversation saved:[/bold] {newest.id}")
    console.print("  resume last:     [cyan]glove up --resume[/cyan]")
    console.print(f"  resume this one: [cyan]glove up --session {newest.id}[/cyan]")


def _after_harness(provider: str, project: str, sidecars: dict[str, str], source: float | None) -> None:
    """What `up` adds once the harness has exited; never a traceback over its exit."""
    try:
        if _runtime_restarted(sidecars, _started(provider, project)):
            err.print("[yellow]⚠[/yellow] the container runtime restarted during the session: the sidecars are "
                      "back, the harness isn't — `glove up --resume`, or `glove down`")
        if source is not None and _source_stamp() != source:
            err.print("[yellow]⚠[/yellow] glove was updated while this session ran; run `glove down` with the new "
                      "version before the next `glove up`")
    except Exception as e:  # best effort
        err.print(f"[dim]after the harness: {escape(str(e))}[/dim]")


def _source_stamp() -> float | None:
    """The newest source file of a glove checkout (an editable install), None otherwise. One
    updated while `up` runs leaves this process's old modules lazily importing new ones."""
    root = Path(__file__).resolve().parents[2]
    if not (root / "pyproject.toml").is_file():
        return None
    newest = 0.0
    for d in ("glove", "commands", "extensions", "harnesses"):
        for f in (root / d).rglob("*.py"):
            try:
                newest = max(newest, f.stat().st_mtime)
            except OSError:  # removed meanwhile (a pull, a branch switch)
                continue
    return newest


def _started(provider: str, project: str) -> dict[str, str] | None:
    """Each running container of the project → its StartedAt, as the runtime says it;
    None when the runtime doesn't answer."""
    try:
        ids = subprocess.run([provider, "ps", "-q", "--filter", f"label=com.docker.compose.project={project}"],
                             capture_output=True, text=True, check=True, timeout=5).stdout.split()
        if not ids:
            return {}
        r = subprocess.run([provider, "inspect", "-f", "{{.Id}} {{.State.StartedAt}}", *ids], capture_output=True,
                           text=True, check=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return dict(line.split(" ", 1) for line in r.stdout.splitlines() if " " in line)


def _runtime_restarted(before: dict[str, str], after: dict[str, str] | None) -> bool:
    """The runtime restarted (taking the `--rm` harness with it) when, of two or more
    sidecars running as the harness started, none still has the start it had then and
    some are running again: they came back alone on their restart policy. Compared in
    the runtime's own words, so the VM's clock never meets the host's; one sidecar
    recreated (e.g. `glove playwright reload`) leaves the others as they were."""
    if len(before) < 2 or not after:
        return False
    return not any(after.get(cid) == started for cid, started in before.items())
