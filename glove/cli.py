"""glove command-line interface.

Identity is the pair `(invocation_dir, harness)` — the dir you run `glove` from
plus the harness — bound to a stable `env-id` in `~/.glove/registry.json`. All
config + state lives under `~/.glove/envs/<env-id>/`; nothing is written into
the invocation dir.

Subcommands: init, run (default), config, ls, down, build. The bare form
`glove <harness> [opts]` is rewritten to `glove run <harness> [opts]` by
`main()`.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.syntax import Syntax

from . import __version__
from .config import ConfigError, parse_add_dir_flag, resolve, split_csv
from .hardening import HardeningError
from .harness import known_harnesses
from .harnessconfig import render_home
from .hostsvc import (
    describe_host_services,
    print_host_setup,
    start_host_services,
    stop_host_services,
)
from .plan import build_session_plan
from .registry import (
    RegistryError,
    create_env,
    env_dir,
    envs_root,
    find_env_id,
    load_registry,
    record_home,
    session_dir,
    session_token,
)
from .runtimes import get_runtime, known_runtimes

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Run agentic harnesses inside constrained Docker/Podman sandboxes.",
)
console = Console()
err = Console(stderr=True)

SUBCOMMANDS = {"init", "run", "config", "down", "ls", "ps", "build", "doctor", "policy", "net", "version"}


def _autodetect_provider() -> str:
    if shutil.which("docker"):
        return "docker"
    if shutil.which("podman"):
        return "podman"
    return "docker"


def _env_config_path(env_id: str) -> Path:
    return env_dir(env_id) / "glove.yaml"


def _home_dir(cfg, sdir: Path) -> Path:
    """The harness config home: the session's own `home/`, or a power-user override.

    Per-session, not per-env: the rendered harness config embeds session-scoped
    values (notably the LLM `baseUrl`, which targets this session's own
    `glove-<token>-llm` sidecar). Two sessions of one env coexisting must not
    share one `home/`, or the second render clobbers the first's config.toml /
    models.json and points it at a sidecar that isn't on its network. Re-running
    the *same* session reuses its home, so history still persists per session.
    """
    if cfg.config_home_source:
        return Path(os.path.realpath(cfg.config_home_source))
    return sdir / "home"


def _record_home(env_id: str, home_dir: Path) -> None:
    """Write the resolved harness home back into the registry entry for `env_id`.

    The registry is the single canonical pointer external monitors use to find
    an env's transcript logs. Stored as an abs realpath (no unresolved symlinks,
    which would not resolve inside a consumer's container).
    """
    record_home(env_id, os.path.realpath(str(home_dir)))


def _register_forced_env(env_id: str, harness: str) -> None:
    """Register a genuinely new forced `--env X --config Y` one-off.

    Registration (not just `_record_home`) is what makes a session visible to
    external monitors (see `_record_home`, which no-ops for an unregistered env).
    Bind only a forced env-id that is absent from the registry, run from a cwd not
    already bound for this harness — preserving `--env`'s "select an existing env,
    ignoring cwd" semantics: an already-registered env-id or an already-bound cwd
    is left untouched. One registry read serves both checks (`create_env` reloads
    under its own lock, which is what actually guards concurrent writers).
    """
    cwd = os.getcwd()
    entries = load_registry()
    already_registered = any(e.env_id == env_id for e in entries)
    cwd_bound = any(
        e.dir == os.path.realpath(cwd) and e.harness == harness for e in entries
    )
    if not already_registered and not cwd_bound:
        create_env(cwd, harness, name=env_id)


@app.command()
def init(
    harness: str | None = typer.Argument(
        None, help=f"one of: {', '.join(known_harnesses())} (default: vibe)"
    ),
    name: str | None = typer.Option(
        None, "--name", help="force the env-id (default: derived from cwd)"
    ),
    from_file: Path | None = typer.Option(
        None, "--from", help="import an existing config (e.g. a legacy glove.yaml)"
    ),
) -> None:
    """Scaffold `~/.glove/envs/<env-id>/glove.yaml` bound to (cwd, harness).

    Never writes to the invocation dir. Auto-create-on-first-run is not enabled
    by default (a future `autocreate: true` config toggle may add it).
    """
    imported: dict = {}
    if from_file is not None:
        if not from_file.is_file():
            err.print(f"[red]error:[/red] --from file not found: {from_file}")
            raise typer.Exit(1)
        imported = yaml.safe_load(from_file.read_text()) or {}
        if not isinstance(imported, dict):
            err.print(f"[red]error:[/red] {from_file}: top-level config must be a mapping")
            raise typer.Exit(1)

    resolved_harness = harness or imported.get("harness") or "vibe"
    if resolved_harness not in known_harnesses():
        err.print(
            f"[red]error:[/red] unknown harness {resolved_harness!r}; "
            f"known: {', '.join(known_harnesses())}"
        )
        raise typer.Exit(1)

    cwd = os.getcwd()
    existing = None if name else find_env_id(cwd, resolved_harness)
    if existing is not None:
        env_id = existing
        console.print(f"[dim]reusing existing env[/dim] {env_id}")
    else:
        try:
            env_id = create_env(cwd, resolved_harness, name=name)
        except RegistryError as e:
            err.print(f"[red]error:[/red] {e}")
            raise typer.Exit(1) from e

    edir = env_dir(env_id)
    edir.mkdir(parents=True, exist_ok=True)
    cfg_path = edir / "glove.yaml"

    doc = dict(imported)
    doc["harness"] = resolved_harness
    doc["name"] = env_id
    # A legacy in-workdir home hack has no place under ~/.glove/envs; the env's
    # own home/ is the default. Drop it unless it points somewhere absolute.
    src = doc.get("config_home_source")
    if src in (".", "", None) or (src and not os.path.isabs(os.path.expanduser(src))):
        doc.pop("config_home_source", None)

    cfg_path.write_text(yaml.safe_dump(doc, sort_keys=False))
    console.print(
        f"[green]✓[/green] env [bold]{env_id}[/bold] "
        f"([dim]{resolved_harness} @ {os.path.realpath(cwd)}[/dim])"
    )
    console.print(f"  edit config: [cyan]{cfg_path}[/cyan]")
    console.print(f"  launch:      [cyan]glove {resolved_harness}[/cyan]")


@app.command()
def run(
    harness: str | None = typer.Argument(
        None, help=f"one of: {', '.join(known_harnesses())}"
    ),
    name: str | None = typer.Option(
        None, "--name", help="name this session (coexists with others; default: env-id)"
    ),
    provider: str | None = typer.Option(None, help="docker | podman (autodetect)"),
    runtime: str | None = typer.Option(
        None, "--runtime", help=f"ring-0 runtime: {', '.join(known_runtimes())}"
    ),
    enforcer: str | None = typer.Option(
        None, "--enforcer", help="ring-1 enforcer: nono | srt | none"
    ),
    browser: str | None = typer.Option(
        None, "--browser", help="browser provider: host-mcp | host-server | none"
    ),
    config: Path | None = typer.Option(None, "--config", help="YAML/JSON overlay"),
    env: str | None = typer.Option(
        None, "--env", help="select an env by id, ignoring cwd resolution"
    ),
    add_dir: list[str] = typer.Option(
        [], "--add-dir", help="extra host path PATH[:ro|:rw] (repeatable)"
    ),
    workdir: Path | None = typer.Option(None, "--workdir", help="the /work mount"),
    net: str | None = typer.Option(
        None, "--net", help="comma list: none|internal|internet|lan|docker:<n>|service"
    ),
    with_plugins: str | None = typer.Option(
        None, "--with", help="comma list of plugins to enable (replaces glove.yaml plugins)"
    ),
    allow_root: bool = typer.Option(False, "--allow-root", help="permit root/sudo"),
    allow_sensitive: bool = typer.Option(
        False, "--allow-sensitive", help="permit mounting / or $HOME"
    ),
    iknow: list[str] = typer.Option(
        [], "--i-know-what-i-am-doing", help="waive a hardening row by key (repeatable)"
    ),
    rebuild: bool = typer.Option(False, "--rebuild", help="rebuild the harness image"),
    resume: bool = typer.Option(
        False, "--resume", "-r", help="reopen the most recent session for this env"
    ),
    session: str | None = typer.Option(
        None, "--session",
        help="reopen a specific session by id (full/partial UUID or path)",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="write + print the compose project, don't launch"
    ),
) -> None:
    """Resolve the env for (cwd, harness), render its compose project, launch it."""
    if harness is None and env is None:
        err.print("[red]error:[/red] specify a harness (e.g. `glove vibe`) or --env ID")
        raise typer.Exit(1)

    if resume and session is not None:
        err.print(
            "[red]error:[/red] pass either --resume (last) or --session <id> "
            "(specific), not both."
        )
        raise typer.Exit(1)
    want_resume = resume or session is not None

    try:
        env_id = _resolve_run_env(env, harness, has_config=config is not None)
    except ConfigError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e

    env_cfg_path = _env_config_path(env_id)

    # The session names this run; its compose project is glove-<env>[-<session>]
    # so several sessions of one env can coexist.
    session_name = name or env_id
    token = session_token(env_id, session_name)

    rt = runtime or None
    prov = provider or (rt if rt in ("docker", "podman") else None) or _autodetect_provider()
    overrides = {
        "harness": harness,
        "provider": prov,
        "runtime": rt,
        "enforcer": enforcer or None,
        "workdir": str(workdir) if workdir else None,
        "name": token,
        "net": split_csv(net) if net else None,
        "plugins": split_csv(with_plugins) if with_plugins is not None else None,
        "allow_root": allow_root or None,
        "allow_sensitive": allow_sensitive or None,
        "rebuild": rebuild or None,
        "add_dirs": [parse_add_dir_flag(a) for a in add_dir] if add_dir else None,
    }

    sdir = session_dir(env_id, session_name)
    try:
        cfg = resolve(
            env_config_path=env_cfg_path, config_path=config, overrides=overrides
        )
        if cfg.runtime not in ("docker", "podman"):
            raise ConfigError(
                f"runtime {cfg.runtime!r} is not implemented yet; "
                "use docker or podman"
            )
        # The --browser flag selects the provider; build_session_plan expands the
        # browser plugin (host services, sidecar, env) via _apply_plugin_config,
        # so run/dry-run/policy-show all compose the same session.
        if browser is not None:
            cfg.browser = {**(cfg.browser or {}), "provider": browser}
        from .plan import legacy_warnings

        for w in legacy_warnings(cfg):
            err.print(f"[yellow]deprecation:[/yellow] {w}")
        home_dir = _home_dir(cfg, sdir)
        # Resume: pre-flight validate the transcript exists (clear glove-level
        # error beats the harness silently starting fresh) and capture the prior
        # security snapshot for the grant-widening warning — both before build.
        prev_cfg = None
        resume_id = session
        if want_resume:
            from .harness import get_profile

            ref = _validate_resume(get_profile(cfg.harness), home_dir, session, env_id)
            # Hand the harness the canonical id find_session resolved (a partial
            # UUID/path the user typed is not something the harness can open), not
            # the raw string. None ⇒ continue-last, which takes no id.
            if ref is not None:
                resume_id = ref.id
            prev_cfg = _load_baseline(sdir)
        plan = build_session_plan(
            cfg, env_id=env_id, home_dir=str(home_dir), cwd=os.getcwd(),
            resume=want_resume, session_id=resume_id,
        )
        # cfg is now fully expanded (plugin bridges, browser wiring); compare the
        # security-relevant grants against the resumed session's snapshot.
        if prev_cfg is not None:
            from .sessions import widening_warnings

            widened = widening_warnings(prev_cfg, cfg)
            if widened:
                err.print(
                    "[yellow]⚠ resuming with broader access than the original "
                    "session; prior conversation context will run with the new "
                    "grants:[/yellow]"
                )
                for w in widened:
                    err.print(f"  [yellow]•[/yellow] {w}")
        # Materialize under ~/.glove/envs/<env>/sessions/<session>/. Ring-1
        # policies are written *before* render so the read-only bind source
        # exists; they live outside /work and are never writable by the agent.
        sdir.mkdir(parents=True, exist_ok=True)
        if plan.policies:
            enforcer_dir = sdir / "enforcer"
            enforcer_dir.mkdir(parents=True, exist_ok=True)
            for fname, content in plan.policies.items():
                (enforcer_dir / fname).write_text(content)
            plan.policies_host_dir = str(enforcer_dir)
        # Network observability: net/ is a sibling of home/, bind-mounted into
        # the netgate collector only. The render refuses any harness mount that
        # overlaps it (validate_net_isolation).
        if plan.observe is not None:
            from .observe import control_dir, ensure_net_dir, net_dir

            plan.net_host_dir = str(ensure_net_dir(net_dir(sdir)))
            plan.control_host_dir = str(ensure_net_dir(control_dir(env_id, session_name)))
        rendered = get_runtime(cfg.runtime).render(
            plan, sdir, overrides=frozenset(iknow)
        )
        if plan.observe is not None:
            from .observe import session_facts, write_session_facts

            write_session_facts(Path(plan.net_host_dir), session_facts(plan))
        # Register the forced one-off now the effective harness is known: it can
        # arrive from --config, so cfg.harness — not the CLI arg — is authoritative.
        # After a successful render so an aborted run leaves no phantom row; a
        # forced-env-id clash raises RegistryError, caught by the handler below.
        if env is not None:
            _register_forced_env(env_id, cfg.harness)
        # Persist the run-time-resolved home into the registry as the single
        # source of truth for external monitors (Layman). This is the only place
        # the resolved home is known: config_home_source can arrive via --config
        # at run time. Recorded only after the session renders (not on an aborted
        # run), for every registered env including the default layout, as an abs
        # realpath so a consumer needs no special-casing or symlink resolution.
        # Path only — never config contents or secrets.
        _record_home(env_id, home_dir)
    except (ConfigError, ValueError, HardeningError, OSError) as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e

    # The seeded harness home lives under the session dir (see _home_dir);
    # nothing is written to the invocation dir.
    compose_path = sdir / "docker-compose.yml"
    compose_path.write_text(rendered.compose_yaml)
    effective_yaml = cfg.to_yaml(redact_secrets=True)
    # effective.yaml tracks the *current* run (used by `glove down` to tear down
    # this run's host services); baseline.yaml is written once at session creation
    # and never overwritten, so the grant-widening check always compares against
    # the original session, not a drifting previous run.
    (sdir / "glove.effective.yaml").write_text(effective_yaml)
    baseline = sdir / "glove.baseline.yaml"
    if not baseline.exists():
        baseline.write_text(effective_yaml)
    # Render with the session token (== the name of the network sidecars, and
    # what describe/start_host_services key on below), NOT env_id: a `--name`d
    # session's llm sidecar is glove-<env>-<name>-llm, so building the harness
    # baseUrl from env_id alone points Pi at a host that doesn't exist
    # ("Connection error").
    home_files = render_home(
        cfg, plan.profile, token, home_dir, mount_plan=plan.mount_plan
    )

    if dry_run:
        console.print(
            f"[bold]env:[/bold] {env_id}   "
            f"[bold]workdir→[/bold] {plan.working_dir}   "
            f"[bold]enforcer:[/bold] {cfg.enforcer}   "
            f"[bold]plugins:[/bold] {', '.join(cfg.plugins) or 'none'}"
        )
        console.print(f"[dim]written to {compose_path}[/dim]\n")
        console.print(Syntax(rendered.compose_yaml, "yaml", theme="ansi_dark"))
        _print_summary(plan, home_files)
        describe_host_services(cfg, token, sdir)
        print_host_setup(cfg)
        return

    # Start host-side helpers (SSH tunnel, Chrome, Playwright MCP) before the
    # harness, then print anything left for the operator to run by hand. Key them
    # by the session token (== compose project suffix) so `glove down` can find
    # and stop them per session, not just the default unnamed one.
    start_host_services(cfg, token, sdir)
    print_host_setup(cfg)
    # Non-dry-run launch lives in session.py; import lazily so --dry-run needs
    # no provider present.
    from .session import launch

    # Timestamp the launch so the post-exit hint reports only a transcript THIS
    # run actually wrote — not a stale one left in the pool by an earlier session
    # (all harnesses default to a new session, and a new one quit before any
    # message leaves no transcript at all, so "newest in the pool" is wrong).
    launched_at = time.time()
    launch(cfg, sdir, provider=cfg.provider, rebuild=cfg.rebuild)
    _print_resume_hint(plan.profile, home_dir, harness or cfg.harness, since=launched_at)


def _resolve_run_env(env: str | None, harness: str | None, *, has_config: bool) -> str:
    """Pick the env-id for a run: explicit --env, else (cwd, harness)."""
    if env is not None:
        if not _env_config_path(env).is_file() and not has_config:
            raise ConfigError(
                f"no env {env!r} under {envs_root()}; run `glove init` first"
            )
        # A forced `--env X --config Y` one-off needs no prior `glove init`. It is
        # still registered so its home is recorded and it stays visible to external
        # monitors — but that happens after config resolution (see
        # _register_forced_env, called from `run`), because the harness needed to
        # bind (dir, harness) can be supplied by `--config`, not just the CLI arg,
        # and is not known here. This function only picks the env-id.
        return env

    cwd = os.getcwd()
    existing = find_env_id(cwd, harness)
    if existing is not None:
        return existing
    if has_config:
        # One-off/explicit run: bind a fresh env so state still lives under
        # ~/.glove (never the cwd).
        return create_env(cwd, harness)
    raise ConfigError(
        f"no env for ({cwd}, {harness}); run `glove init {harness}` "
        "(or pass --config for a one-off)"
    )


def _validate_resume(profile, home_dir: Path, session_id: str | None, env_id: str):
    """Validate a resume request, returning the resolved `SessionRef` or None.

    `--session <id>` returns the transcript find_session resolved (so the caller
    can hand the harness its canonical id). `--resume` (continue-last) returns
    None: glove only confirms *some* transcript exists — it can't replicate the
    harness's own project/cwd scoping, so the harness makes the final choice of
    which session to continue. Raises ConfigError (rendered on the standard error
    path) when there is nothing matching to resume."""
    from .sessions import list_sessions, match_session, sessions_dir

    refs = list_sessions(sessions_dir(profile, Path(home_dir)))
    if not refs:
        raise ConfigError(
            f"no previous session to resume for env {env_id!r}; run without "
            "--resume/--session to start one."
        )
    if session_id is None:
        return None
    ref = match_session(refs, session_id)
    if ref is None:
        available = "\n".join(
            f"  {r.id}  [{_fmt_mtime(r.mtime)}]" for r in refs
        )
        raise ConfigError(
            f"no session matching {session_id!r} for env {env_id!r}. "
            f"available:\n{available}"
        )
    return ref


def _load_baseline(sdir: Path):
    """The session's *original* redacted config snapshot, or None if absent.

    Written once at session creation and never overwritten (see the run body), so
    the grant-widening check compares against the config the session was born
    under, not a previous run that may itself have drifted."""
    from .config import load_config

    snapshot = sdir / "glove.baseline.yaml"
    if not snapshot.is_file():
        return None
    try:
        return load_config(snapshot)
    except (ConfigError, ValueError):
        return None


def _fmt_mtime(mtime: float) -> str:
    from datetime import datetime

    return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")


def _print_resume_hint(profile, home_dir: Path, harness: str, *, since: float) -> None:
    """After the TUI exits, show how to reopen the session THIS run wrote.

    glove never sees the harness's internal session id, so it identifies the
    run's transcript by mtime: only files written at/after ``since`` (the launch
    time) belong to this run. If none were (a fresh session quit before any
    message persists nothing), report no id rather than a stale pool leftover —
    that leftover is an unrelated earlier session, and pointing ``--session`` at
    it would resume the wrong conversation."""
    from .sessions import list_sessions, sessions_dir

    refs = [r for r in list_sessions(sessions_dir(profile, Path(home_dir))) if r.mtime >= since]
    if not refs:
        return
    newest = refs[0]
    console.print(f"\n[bold]session saved:[/bold] {newest.id}")
    console.print(f"  resume last:     [cyan]glove {harness} <same args> --resume[/cyan]")
    console.print(
        f"  resume this one: [cyan]glove {harness} <same args> "
        f"--session {newest.id}[/cyan]"
    )


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
        console.print(
            f"  glove-{plan.session}-{s.role}:{s.listen_port}  →  {s.target}{gate}"
        )
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
        f"  {home_files[0].parent}  [dim]— config, logs/, session transcripts, history[/dim]"
    )


@app.command()
def config(
    harness: str | None = typer.Argument(
        None, help="harness, to resolve the env from cwd"
    ),
    env: str | None = typer.Option(None, "--env", help="select an env by id"),
    path: bool = typer.Option(False, "--path", help="print the config path only"),
    edit: bool = typer.Option(False, "--edit", help="open the config in $EDITOR"),
) -> None:
    """Locate (or open) an environment's `glove.yaml`."""
    try:
        env_id = _locate_env(env, harness)
    except ConfigError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e

    cfg_path = _env_config_path(env_id)
    if not cfg_path.is_file():
        err.print(f"[red]error:[/red] no config at {cfg_path}; run `glove init` first")
        raise typer.Exit(1)

    if edit:
        editor = os.environ.get("EDITOR", "vi")
        import subprocess

        subprocess.run([editor, str(cfg_path)], check=False)
        return
    if path:
        console.print(str(cfg_path))
        return
    console.print(f"[bold]{env_id}[/bold]  [dim]{cfg_path}[/dim]\n")
    console.print(Syntax(cfg_path.read_text(), "yaml", theme="ansi_dark"))


def _locate_env(env: str | None, harness: str | None) -> str:
    """Resolve an env-id from --env, (cwd, harness), or a unique cwd match."""
    if env is not None:
        return env
    cwd = os.getcwd()
    if harness is not None:
        existing = find_env_id(cwd, harness)
        if existing is None:
            raise ConfigError(f"no env for ({cwd}, {harness})")
        return existing
    cwd_real = os.path.realpath(cwd)
    matches = [e for e in load_registry() if e.dir == cwd_real]
    if not matches:
        raise ConfigError(f"no env registered for {cwd_real}")
    if len(matches) > 1:
        ids = ", ".join(m.env_id for m in matches)
        raise ConfigError(f"multiple envs for this dir ({ids}); pass a harness or --env")
    return matches[0].env_id


@app.command()
def down(
    env_id: str | None = typer.Argument(None, help="env-id to tear down"),
    name: str | None = typer.Option(
        None, "--name", help="tear down only this session (default: all sessions of the env)"
    ),
    provider: str | None = typer.Option(None),
    wipe: bool = typer.Option(False, "--wipe", help="also remove the config volume"),
) -> None:
    """Tear down an env's sessions (compose projects) and their host services.

    Every session of the env is torn down — including `--name`d ones, whose
    compose project is `glove-<env>-<name>` — unless `--name` narrows it to one.
    """
    from .config import load_config
    from .registry import sessions_root
    from .session import teardown

    if env_id is None:
        cwd_real = os.path.realpath(os.getcwd())
        matches = [e for e in load_registry() if e.dir == cwd_real]
        if len(matches) == 1:
            env_id = matches[0].env_id
        elif not matches:
            err.print(f"[red]error:[/red] no env registered for {cwd_real}; pass an env-id")
            raise typer.Exit(1)
        else:
            ids = ", ".join(m.env_id for m in matches)
            err.print(f"[red]error:[/red] multiple envs for this dir ({ids}); pass an env-id")
            raise typer.Exit(1)

    prov = provider or _autodetect_provider()
    # Session dirs are named by the bare session name (env-id for the default,
    # unnamed session; the --name value otherwise). Their compose project is
    # keyed by the session *token* (glove-<env>[-<name>]).
    sroot = sessions_root(env_id)
    if name is not None:
        session_names = [name]
    elif sroot.is_dir():
        session_names = sorted(p.name for p in sroot.iterdir() if p.is_dir())
    else:
        session_names = []
    # Fall back to the default session so a legacy/never-run env still tears down.
    if not session_names:
        session_names = [env_id]

    for sname in session_names:
        sdir = session_dir(env_id, sname)
        token = session_token(env_id, sname)
        effective = sdir / "glove.effective.yaml"
        if effective.exists():
            try:
                cfg = load_config(effective)
                token = cfg.resolved_name()
                console.print(f"[bold]stopping host services…[/bold] ({sname})")
                stop_host_services(cfg, token, sdir)
            except Exception as e:
                err.print(f"[yellow]warn:[/yellow] host-service teardown skipped for {sname}: {e}")
        teardown(token, provider=prov, wipe=wipe)


@app.command()
def build(
    harness: str | None = typer.Argument(
        None, help=f"harness image to build ({', '.join(known_harnesses())}); "
        "omit to build the forwarder + netgate only"
    ),
    provider: str | None = typer.Option(None),
    enforcer: str | None = typer.Option(
        None, "--enforcer", help="build the enforcer variant (e.g. srt → -srt image)"
    ),
    with_plugins: str | None = typer.Option(
        None, "--with", help="comma list of plugins to compose into the image"
    ),
    rebuild: bool = typer.Option(False, "--rebuild", help="force rebuild"),
) -> None:
    """Build the forwarder + netgate and (optionally) a harness image."""
    from .harness import get_profile
    from .observe import build_netgate
    from .session import build_forwarder, build_harness

    prov = provider or _autodetect_provider()
    plugins = split_csv(with_plugins) if with_plugins else None
    build_forwarder(prov, force=rebuild)
    build_netgate(prov, force=rebuild, console=console)
    if harness:
        build_harness(
            prov,
            get_profile(harness),
            plugins=plugins,
            enforcer=enforcer or "nono",
            force=rebuild,
        )


@app.command("ls")
def list_envs() -> None:
    """List environments: `env-id  harness  <-  invocation-dir  (workdir)`."""
    entries = load_registry()
    if not entries:
        console.print("[dim]no envs — run `glove init <harness>`[/dim]")
        return
    for e in sorted(entries, key=lambda x: x.env_id):
        workdir = ""
        cfg_path = _env_config_path(e.env_id)
        if cfg_path.is_file():
            try:
                data = yaml.safe_load(cfg_path.read_text()) or {}
                workdir = data.get("workdir", "") or ""
            except (yaml.YAMLError, OSError):
                pass
        wd = f"  [dim](work: {workdir})[/dim]" if workdir else ""
        console.print(
            f"[bold]{e.env_id}[/bold]  [cyan]{e.harness}[/cyan]  "
            f"[dim]<-[/dim]  {e.dir}{wd}"
        )


@app.command()
def doctor(
    env: str | None = typer.Option(None, "--env", help="read runtime/enforcer/browser from an env's config"),
    runtime: str | None = typer.Option(None, "--runtime", help=f"probe a runtime: {', '.join(known_runtimes())}"),
    enforcer: str | None = typer.Option(None, "--enforcer", help="probe an enforcer: nono | srt | none"),
    browser: str | None = typer.Option(None, "--browser", help="probe a browser provider: host-mcp | host-server"),
    json_out: bool = typer.Option(False, "--json", help="machine-readable output"),
    no_container: bool = typer.Option(
        False, "--no-container", help="skip container probes (host-only, fast)"
    ),
) -> None:
    """Probe host + runtime + enforcer + browser readiness."""
    import json as _json

    from .doctor import run_doctor, worst_status

    rt, enf, brw = runtime or "docker", enforcer or "nono", browser
    if env is not None:
        cfg_path = _env_config_path(env)
        if cfg_path.is_file():
            data = yaml.safe_load(cfg_path.read_text()) or {}
            rt = runtime or data.get("runtime", rt)
            enf = enforcer or data.get("enforcer", enf)
            # Probe the browser only when the browser plugin (or a legacy
            # `browser:` block) is enabled for this env. `plugins` accepts a
            # comma-string as well as a list (see config._coerce), so split
            # before the membership test to avoid a substring false-positive.
            plugins = data.get("plugins") or []
            if isinstance(plugins, str):
                plugins = split_csv(plugins)
            legacy = (data.get("browser") or {}).get("provider")
            if "browser" in plugins or legacy:
                opts = (data.get("plugin_options") or {}).get("browser") or {}
                brw = browser or legacy or opts.get("provider") or "host-mcp"

    try:
        checks = run_doctor(runtime=rt, enforcer=enf, browser=brw, include_container_probes=not no_container)
    except ValueError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e

    if json_out:
        console.print_json(
            _json.dumps({"runtime": rt, "enforcer": enf, "browser": brw, "checks": [c.to_dict() for c in checks]})
        )
    else:
        glyph = {"ok": "[green]✓[/green]", "warn": "[yellow]![/yellow]", "fail": "[red]✗[/red]",
                 "info": "[cyan]·[/cyan]", "skip": "[dim]-[/dim]"}
        from rich.markup import escape

        console.print(f"[bold]glove doctor[/bold]  runtime={rt}  enforcer={enf}\n")
        for c in checks:
            console.print(
                f"  {glyph.get(c.status, '?')} [bold]{escape(c.name)}[/bold]  "
                f"[dim]{escape(c.detail)}[/dim]"
            )
    raise typer.Exit(1 if worst_status(checks) == "fail" else 0)


policy_app = typer.Typer(add_completion=False, help="Inspect rendered ring-1 policies + ring-0 hardening.")
app.add_typer(policy_app, name="policy")


@policy_app.command("show")
def policy_show(
    harness: str | None = typer.Argument(None, help="harness, to resolve the env from cwd"),
    env: str | None = typer.Option(None, "--env", help="select an env by id"),
) -> None:
    """Print the rendered ring-1 policies and the ring-0 hardening for review."""
    try:
        env_id = _locate_env(env, harness)
    except ConfigError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e

    cfg = resolve(env_config_path=_env_config_path(env_id), overrides={})
    try:
        # policy_show inspects the default (unnamed) session; it renders no home,
        # so the path only labels the plan's read-only bind row.
        plan = build_session_plan(
            cfg,
            env_id=env_id,
            home_dir=str(_home_dir(cfg, session_dir(env_id, env_id))),
            cwd=os.getcwd(),
        )
    except (ConfigError, ValueError) as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e

    h = plan.hardening
    console.print(
        f"[bold]{env_id}[/bold]  runtime={cfg.runtime}  enforcer={cfg.enforcer}  "
        f"plugins={', '.join(cfg.plugins) or 'none'}\n"
    )
    console.print("[bold]ring 0 — hardening[/bold]")
    console.print(
        f"  user={h.user or 'root (allow_root)'}  cap_drop={list(h.cap_drop)}  "
        f"cap_add={list(h.cap_add) or '[]'}  no_new_privileges={h.no_new_privileges}"
    )
    console.print(
        f"  read_only={h.read_only}  ipc={h.ipc}  pids={h.limits.pids}  "
        f"mem={h.limits.memory}  cpus={h.limits.cpus}"
    )
    console.print(f"  seccomp={h.seccomp_profile}")
    if h.systempaths_unconfined:
        console.print("  [yellow]systempaths=unconfined[/yellow] — masked /proc,/sys "
                      "exposed to the container (srt strong)")
    console.print(f"\n[bold]harness command[/bold]\n  {' '.join(plan.harness_command)}")

    # Enabled plugins and exactly what each one grants (reviewable per §6-Q5).
    from .plugins import resolve_plugins

    enabled = resolve_plugins(cfg.plugins)  # cfg.plugins now includes bridged ones
    console.print("\n[bold]plugins[/bold]")
    if not enabled:
        console.print("  [dim](none — minimal base image)[/dim]")
    for p in enabled:
        console.print(f"  [cyan]{p.name}[/cyan] — {p.summary}")
        if p.requires_services:
            console.print(
                f"    egress: only via forwarder sidecar(s) {list(p.requires_services)} "
                "(network allow-list; shell tools stay --block-net)"
            )
        if p.pi_extensions and cfg.harness == "pi":
            console.print(f"    pi extension(s): {list(p.pi_extensions)}")
        layers = p.layers_for(cfg.harness)
        pkgs = {
            "apt": [x for lyr in layers for x in lyr.apt],
            "pip": [x for lyr in layers for x in lyr.pip],
            "npm": [x for lyr in layers for x in lyr.npm],
        }
        shown = ", ".join(f"{k}={v}" for k, v in pkgs.items() if v)
        if shown:
            console.print(f"    image layer: {shown}")
    hs = [h.name for h in cfg.host_services]
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


net_app = typer.Typer(
    add_completion=False,
    help="Network observability: gate status and flow records (net/ of a session).",
)
app.add_typer(net_app, name="net")


def _net_dir_for(env: str | None, session: str | None) -> tuple[str, str, Path]:
    """(env_id, session name, net dir) — `--session` is the session *name*
    (default: the env's default session), not a transcript id."""
    from .observe import net_dir

    env_id = _locate_env(env, None)
    sname = session or env_id
    return env_id, sname, net_dir(session_dir(env_id, sname))


@net_app.command("status")
def net_status(
    env: str | None = typer.Option(None, "--env", help="select an env by id"),
    session: str | None = typer.Option(None, "--session", help="session name (default: the env's default)"),
    json_out: bool = typer.Option(False, "--json", help="machine-readable output"),
) -> None:
    """Gate health, record mode, services, upstream and resolver state."""
    import json as _json

    from .netview import summarize

    try:
        env_id, sname, ndir = _net_dir_for(env, session)
    except ConfigError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e
    summary = summarize(ndir)
    if json_out:
        console.print_json(_json.dumps(summary))
        return
    from .netview import render_status

    for line in render_status(env_id, sname, ndir, summary):
        console.print(line, highlight=False)
    if not summary["observed"]:
        raise typer.Exit(1)


@net_app.command("flows")
def net_flows(
    env: str | None = typer.Option(None, "--env", help="select an env by id"),
    session: str | None = typer.Option(None, "--session", help="session name (default: the env's default)"),
    follow: bool = typer.Option(False, "--follow", "-f", help="keep tailing (survives rotation)"),
    json_out: bool = typer.Option(False, "--json", help="print raw NDJSON records"),
    tail: int | None = typer.Option(None, "--tail", "-n", help="only the last N records"),
) -> None:
    """Print the session's flow records (rotated files first, then live)."""
    import json as _json

    from .netview import follow_records, format_record, read_records

    try:
        _, _, ndir = _net_dir_for(env, session)
    except ConfigError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e
    if not ndir.is_dir():
        err.print(f"[red]error:[/red] no net/ dir at {ndir} — is `observe.enabled` on for this session?")
        raise typer.Exit(1)

    def emit(rec: dict) -> None:
        if json_out:
            print(_json.dumps(rec, separators=(",", ":")), flush=True)
        else:
            console.print(format_record(rec), highlight=False)

    records = read_records(ndir)
    if tail is not None:
        records = records[-tail:] if tail > 0 else []  # `--tail 0 --follow`: only new records
    for rec in records:
        emit(rec)
    if follow:
        try:
            for rec in follow_records(ndir, from_end=True):
                emit(rec)
        except KeyboardInterrupt:
            pass


def _rules_target(env: str | None, session: str | None) -> tuple[str, str, Path]:
    """(env_id, session token, rules.json path) for `glove net block|unblock|rules`."""
    from .observe import control_dir

    env_id = _locate_env(env, None)
    sname = session or env_id
    return env_id, session_token(env_id, sname), control_dir(env_id, sname) / "rules.json"


@net_app.command("block")
def net_block(
    target: str = typer.Argument(..., help="host glob (e.g. '*.doubleclick.net'), IP, or CIDR"),
    port: int | None = typer.Option(None, "--port", help="only this destination port"),
    terminate: bool = typer.Option(False, "--terminate", help="also cut matching established flows"),
    allow: bool = typer.Option(False, "--allow", help="write an allow rule instead (e.g. under default block)"),
    note: str | None = typer.Option(None, "--note", help="free-text note shown in `glove net rules`"),
    env: str | None = typer.Option(None, "--env", help="select an env by id"),
    session: str | None = typer.Option(None, "--session", help="session name (default: the env's default)"),
) -> None:
    """Append a rule to the session's rules.json (the file Layman writes too).

    Rules apply to new connections within ~1s; --terminate also cuts matching
    established ones. glove's built-in SSRF guard runs first and cannot be
    overridden by an allow rule."""
    from .netgate.policy import PolicyError
    from .netrules import block_rule, load, save

    try:
        env_id, token, path = _rules_target(env, session)
        data = load(path, env_id, token)
        rule = block_rule(target, port=port, terminate=terminate, note=note, action="allow" if allow else "block")
        data["rules"] = [*data.get("rules", []), rule]
        save(path, data, env_id, token)
    except (ConfigError, PolicyError, OSError) as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e
    console.print(f"[green]✓[/green] {rule['action']} {rule['match']} → {rule['id']}  [dim]{path}[/dim]")


@net_app.command("unblock")
def net_unblock(
    key: str = typer.Argument(..., help="rule id (r_…) or the exact host glob / IP / CIDR it matches"),
    env: str | None = typer.Option(None, "--env", help="select an env by id"),
    session: str | None = typer.Option(None, "--session", help="session name (default: the env's default)"),
) -> None:
    """Remove rules by id or by the exact target they match."""
    from .netgate.policy import PolicyError
    from .netrules import load, remove, save

    try:
        env_id, token, path = _rules_target(env, session)
        data = load(path, env_id, token)
        gone = remove(data, key)
        if not gone:
            err.print(f"[yellow]no rule matches {key!r}[/yellow]")
            raise typer.Exit(1)
        save(path, data, env_id, token)
    except (ConfigError, PolicyError, OSError) as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e
    for r in gone:
        console.print(f"[green]✓[/green] removed {r['id']} ({r['action']} {r['match']})")


@net_app.command("rules")
def net_rules(
    env: str | None = typer.Option(None, "--env", help="select an env by id"),
    session: str | None = typer.Option(None, "--session", help="session name (default: the env's default)"),
    json_out: bool = typer.Option(False, "--json", help="print the rules document"),
) -> None:
    """Show the effective rules, their provenance, and the gate's load result."""
    import json as _json

    from .netgate.policy import PolicyError
    from .netrules import load

    try:
        env_id, token, path = _rules_target(env, session)
        data = load(path, env_id, token)
        problem = None
    except PolicyError as e:
        data, problem = None, str(e)
    except ConfigError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e
    if json_out:
        console.print_json(_json.dumps(data or {"error": problem}))
        return
    from .netview import _load_json
    from .observe import net_dir

    status = _load_json(net_dir(session_dir(env_id, session or env_id)) / "status.json") or {}
    console.print(f"[bold]{env_id}[/bold] / session [bold]{session or env_id}[/bold]  [dim]{path}[/dim]")
    if problem:
        console.print(f"  [red]rules.json is invalid:[/red] {problem}")
        console.print("  [dim]the gate keeps its last known-good set until this is fixed[/dim]")
        raise typer.Exit(1)
    st = status.get("rules") or {}
    if st:
        state = "[green]loaded[/green]" if st.get("ok") else f"[red]REJECTED[/red] — {st.get('error')}"
        console.print(f"  gate: {state}  active={st.get('active_count')}  loaded_at={st.get('loaded_at')}")
    console.print(f"  default: {data['default']}   updated_by: {data.get('updated_by')} at {data.get('updated_at')}")
    console.print("  [dim]then glove's built-in SSRF guard (always first, not overridable)[/dim]")
    if not data["rules"]:
        console.print("  [dim](no rules)[/dim]")
    for i, r in enumerate(data["rules"], 1):
        extra = ("  terminate" if r.get("terminate") else "") + (f"  # {r['note']}" if r.get("note") else "")
        console.print(f"  {i:>2}. {r['action']:<5} {r['match']}  [dim]{r['id']}[/dim]{extra}", highlight=False)


@app.command("ps")
def list_sessions(
    runtime: str | None = typer.Option(None, "--runtime", help="docker | podman"),
) -> None:
    """List running glove sessions (compose projects)."""
    rt = get_runtime(runtime or _autodetect_provider())
    sessions = rt.ps()
    if not sessions:
        console.print("[dim]no running glove sessions[/dim]")
        return
    for s in sorted(sessions, key=lambda x: x.project):
        console.print(
            f"[bold]{s.project}[/bold]  [dim]({len(s.services)} services: "
            f"{', '.join(sorted(s.services))})[/dim]"
        )


@app.command()
def version() -> None:
    """Print the glove version."""
    console.print(__version__)


def main() -> None:
    """Entry point: rewrite `glove <harness> ...` → `glove run <harness> ...`."""
    argv = sys.argv[1:]
    if argv and not argv[0].startswith("-") and argv[0] not in SUBCOMMANDS | {"--help"}:
        sys.argv.insert(1, "run")
    app()


if __name__ == "__main__":
    main()
