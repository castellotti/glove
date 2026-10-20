"""`glove plan` — render the session and show what it grants, launching nothing."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.syntax import Syntax

from glove.api import ConfigError, scoped
from glove.api.commands import (
    DIR_ARG,
    IKNOW,
    OPTION_SECTIONS,
    HardeningError,
    console,
    fail,
    materialize_plan,
    one_resume,
    open_session,
    print_extensions,
    read_effective,
)

RANK = 2  # its place in `glove --help` (commands/README.md)


def command(
    directory: Path | None = DIR_ARG,
    compose: bool = typer.Option(False, "--compose", help="also print the rendered compose project"),
    resume: bool = typer.Option(False, "--resume", "-r", help="render as `glove up --resume` would"),
    session: str | None = typer.Option(None, "--session", help="render as `glove up --session <id>` would"),
    iknow: list[str] = IKNOW,
) -> None:
    """Render the session (writes .glove/, launches nothing) and show what it grants."""
    one_resume(resume, session)
    try:
        sd, _, sid, cfg = open_session(directory)
        plan, compose_yaml, home_files = materialize_plan(sd, sid, cfg, resume=resume, session=session,
                                                          overrides=frozenset(iknow))
    except (ConfigError, ValueError, HardeningError, OSError, NotImplementedError) as e:
        raise fail(str(e)) from e
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
    _, resolved = read_effective(sd.effective)
    if resolved.get("model"):
        m = resolved["model"]
        console.print(f"    [bold]resolved at last launch[/bold] ({resolved.get('at', '?')}): model {m.get('model')}, "
                      f"vision={m.get('vision')}, context={m.get('context_window')}")
    _print_summary(plan, home_files)


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
