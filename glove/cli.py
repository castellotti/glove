"""glove command-line interface (DESIGN.md A.1 + docs/plan-environments.md).

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
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.syntax import Syntax

from . import __version__
from .compose import render_compose
from .config import ConfigError, parse_add_dir_flag, resolve
from .harness import known_harnesses
from .harnessconfig import render_home
from .hostsvc import (
    describe_host_services,
    print_host_setup,
    start_host_services,
    stop_host_services,
)
from .registry import (
    create_env,
    env_dir,
    envs_root,
    find_env_id,
    load_registry,
    session_dir,
)
from .runtimes import get_runtime, known_runtimes

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Run agentic harnesses inside constrained Docker/Podman sandboxes.",
)
console = Console()
err = Console(stderr=True)

SUBCOMMANDS = {"init", "run", "config", "down", "ls", "ps", "build", "doctor", "version"}


def _autodetect_provider() -> str:
    if shutil.which("docker"):
        return "docker"
    if shutil.which("podman"):
        return "podman"
    return "docker"


def _env_config_path(env_id: str) -> Path:
    return env_dir(env_id) / "glove.yaml"


def _home_dir(cfg, edir: Path) -> Path:
    """The harness config home: the env's own `home/`, or a power-user override."""
    if cfg.config_home_source:
        return Path(os.path.realpath(cfg.config_home_source))
    return edir / "home"


@app.command()
def init(
    harness: Optional[str] = typer.Argument(
        None, help=f"one of: {', '.join(known_harnesses())} (default: vibe)"
    ),
    name: Optional[str] = typer.Option(
        None, "--name", help="force the env-id (default: derived from cwd)"
    ),
    from_file: Optional[Path] = typer.Option(
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
        env_id = create_env(cwd, resolved_harness, name=name)

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
    harness: Optional[str] = typer.Argument(
        None, help=f"one of: {', '.join(known_harnesses())}"
    ),
    name: Optional[str] = typer.Option(
        None, "--name", help="name this session (coexists with others; default: env-id)"
    ),
    provider: Optional[str] = typer.Option(None, help="docker | podman (autodetect)"),
    runtime: Optional[str] = typer.Option(
        None, "--runtime", help=f"ring-0 runtime: {', '.join(known_runtimes())}"
    ),
    enforcer: Optional[str] = typer.Option(
        None, "--enforcer", help="ring-1 enforcer: nono | srt | none"
    ),
    config: Optional[Path] = typer.Option(None, "--config", help="YAML/JSON overlay"),
    env: Optional[str] = typer.Option(
        None, "--env", help="select an env by id, ignoring cwd resolution"
    ),
    add_dir: list[str] = typer.Option(
        [], "--add-dir", help="extra host path PATH[:ro|:rw] (repeatable)"
    ),
    workdir: Optional[Path] = typer.Option(None, "--workdir", help="the /work mount"),
    net: Optional[str] = typer.Option(
        None, "--net", help="comma list: none|internal|internet|lan|docker:<n>|service"
    ),
    allow_root: bool = typer.Option(False, "--allow-root", help="permit root/sudo"),
    allow_sensitive: bool = typer.Option(
        False, "--allow-sensitive", help="permit mounting / or $HOME"
    ),
    iknow: list[str] = typer.Option(
        [], "--i-know-what-i-am-doing", help="waive a §3.2 hardening row by key (repeatable)"
    ),
    rebuild: bool = typer.Option(False, "--rebuild", help="rebuild the harness image"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="write + print the compose project, don't launch"
    ),
) -> None:
    """Resolve the env for (cwd, harness), render its compose project, launch it."""
    if harness is None and env is None:
        err.print("[red]error:[/red] specify a harness (e.g. `glove vibe`) or --env ID")
        raise typer.Exit(1)

    try:
        env_id = _resolve_run_env(env, harness, has_config=config is not None)
    except ConfigError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e

    edir = env_dir(env_id)
    env_cfg_path = _env_config_path(env_id)

    # The session names this run; its compose project is glove-<env>[-<session>]
    # so several sessions of one env can coexist (§7.1/§7.3).
    session_name = name or env_id
    session_token = env_id if session_name == env_id else f"{env_id}-{session_name}"

    rt = runtime or None
    prov = provider or (rt if rt in ("docker", "podman") else None) or _autodetect_provider()
    overrides = {
        "harness": harness,
        "provider": prov,
        "runtime": rt,
        "enforcer": enforcer or None,
        "workdir": str(workdir) if workdir else None,
        "name": session_token,
        "net": [p.strip() for p in net.split(",") if p.strip()] if net else None,
        "allow_root": allow_root or None,
        "allow_sensitive": allow_sensitive or None,
        "rebuild": rebuild or None,
        "add_dirs": [parse_add_dir_flag(a) for a in add_dir] if add_dir else None,
    }

    try:
        cfg = resolve(
            env_config_path=env_cfg_path, config_path=config, overrides=overrides
        )
        if cfg.runtime not in ("docker", "podman"):
            raise ConfigError(
                f"runtime {cfg.runtime!r} is not implemented yet (see PLAN §5/§9); "
                "use docker or podman"
            )
        home_dir = _home_dir(cfg, edir)
        result = render_compose(
            cfg,
            home_dir=str(home_dir),
            cwd=os.getcwd(),
            env_id=env_id,
            overrides=frozenset(iknow),
        )
    except (ConfigError, ValueError) as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e

    # Materialize under ~/.glove/envs/<env-id>/sessions/<session>/: compose +
    # effective config; the seeded harness home stays at the env level so
    # sessions of one env share config. Nothing is written to the invocation dir.
    sdir = session_dir(env_id, session_name)
    sdir.mkdir(parents=True, exist_ok=True)
    compose_path = sdir / "docker-compose.yml"
    compose_path.write_text(result.compose_yaml)
    (sdir / "glove.effective.yaml").write_text(cfg.to_yaml())
    home_files = render_home(cfg, result.profile, env_id, home_dir)

    if dry_run:
        console.print(
            f"[bold]env:[/bold] {env_id}   "
            f"[bold]workdir→[/bold] {result.mount_plan.working_dir}"
        )
        console.print(f"[dim]written to {compose_path}[/dim]\n")
        console.print(Syntax(result.compose_yaml, "yaml", theme="ansi_dark"))
        _print_summary(result, home_files)
        describe_host_services(cfg, env_id)
        print_host_setup(cfg)
        return

    # Start host-side helpers (SSH tunnel, Chrome, Playwright MCP) before the
    # harness, then print anything left for the operator to run by hand.
    start_host_services(cfg, env_id, sdir)
    print_host_setup(cfg)
    # Non-dry-run launch lives in session.py; import lazily so --dry-run needs
    # no provider present.
    from .session import launch

    launch(cfg, sdir, provider=cfg.provider, rebuild=cfg.rebuild)


def _resolve_run_env(env: str | None, harness: str | None, *, has_config: bool) -> str:
    """Pick the env-id for a run: explicit --env, else (cwd, harness)."""
    if env is not None:
        if not _env_config_path(env).is_file() and not has_config:
            raise ConfigError(
                f"no env {env!r} under {envs_root()}; run `glove init` first"
            )
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


def _print_summary(result, home_files) -> None:  # noqa: ANN001 - internal helper
    console.print("\n[bold]mounts[/bold]")
    for m in result.mount_plan.mounts:
        console.print(f"  {m.host_path}  →  {m.container_path}  ({m.mode})")
    console.print("[bold]forwarders (network allow-list)[/bold]")
    if not result.network_plan.sidecars:
        console.print("  [dim](none — harness is fully offline)[/dim]")
    for s in result.network_plan.sidecars:
        console.print(
            f"  glove-{result.session}-{s.role}:{s.listen_port}  →  {s.target}"
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
    harness: Optional[str] = typer.Argument(
        None, help="harness, to resolve the env from cwd"
    ),
    env: Optional[str] = typer.Option(None, "--env", help="select an env by id"),
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
    env_id: Optional[str] = typer.Argument(None, help="env-id to tear down"),
    provider: Optional[str] = typer.Option(None),
    wipe: bool = typer.Option(False, "--wipe", help="also remove the config volume"),
) -> None:
    """Tear down an env's compose project and its host services."""
    from .config import load_config
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

    sdir = session_dir(env_id, env_id)
    effective = sdir / "glove.effective.yaml"
    if effective.exists():
        try:
            cfg = load_config(effective)
            console.print("[bold]stopping host services…[/bold]")
            stop_host_services(cfg, env_id, sdir)
        except Exception as e:  # noqa: BLE001 - teardown must be best-effort
            err.print(f"[yellow]warn:[/yellow] host-service teardown skipped: {e}")

    teardown(env_id, provider=provider or _autodetect_provider(), wipe=wipe)


@app.command()
def build(
    harness: Optional[str] = typer.Argument(
        None, help=f"harness image to build ({', '.join(known_harnesses())}); "
        "omit to build the forwarder only"
    ),
    provider: Optional[str] = typer.Option(None),
    rebuild: bool = typer.Option(False, "--rebuild", help="force rebuild"),
) -> None:
    """Build the forwarder and (optionally) a harness image."""
    from .harness import get_profile
    from .session import build_forwarder, build_harness

    prov = provider or _autodetect_provider()
    build_forwarder(prov, force=rebuild)
    if harness:
        build_harness(prov, get_profile(harness), force=rebuild)


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
    env: Optional[str] = typer.Option(None, "--env", help="read runtime/enforcer from an env's config"),
    runtime: Optional[str] = typer.Option(None, "--runtime", help=f"probe a runtime: {', '.join(known_runtimes())}"),
    enforcer: Optional[str] = typer.Option(None, "--enforcer", help="probe an enforcer: nono | srt | none"),
    json_out: bool = typer.Option(False, "--json", help="machine-readable output"),
    no_container: bool = typer.Option(
        False, "--no-container", help="skip container probes (host-only, fast)"
    ),
) -> None:
    """Probe host + runtime + enforcer readiness (PLAN §3.3)."""
    import json as _json

    from .doctor import run_doctor, worst_status

    rt, enf = runtime or "docker", enforcer or "nono"
    if env is not None:
        cfg_path = _env_config_path(env)
        if cfg_path.is_file():
            data = yaml.safe_load(cfg_path.read_text()) or {}
            rt = runtime or data.get("runtime", rt)
            enf = enforcer or data.get("enforcer", enf)

    try:
        checks = run_doctor(runtime=rt, enforcer=enf, include_container_probes=not no_container)
    except ValueError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e

    if json_out:
        console.print_json(
            _json.dumps({"runtime": rt, "enforcer": enf, "checks": [c.to_dict() for c in checks]})
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


@app.command("ps")
def list_sessions(
    runtime: Optional[str] = typer.Option(None, "--runtime", help="docker | podman"),
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
