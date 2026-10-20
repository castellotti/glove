"""`glove policy` — the session's ring-0 hardening and ring-1 policies, for review."""

from __future__ import annotations

from pathlib import Path

from rich.syntax import Syntax

from glove.api import ConfigError
from glove.api.commands import (
    DIR_ARG,
    build_session_plan,
    console,
    fail,
    get_enforcer,
    open_session,
    print_extensions,
    session_bind_layer,
)

RANK = 15  # its place in `glove --help` (commands/README.md)


def command(directory: Path | None = DIR_ARG) -> None:
    """Print the rendered ring-1 policies and the ring-0 hardening for review."""
    try:
        sd, _, sid, cfg = open_session(directory, register=False)
        plan = build_session_plan(cfg, home_dir=str(sd.home), cwd=str(sd.work), state_dir=str(sd.ext),
                                  session_dir=str(sd.root), bind_layer=session_bind_layer(cfg))
    except (ConfigError, ValueError) as e:
        raise fail(str(e)) from e

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
    print_extensions(plan)
    if not plan.policies:
        console.print("\n[red]no ring-1 policies (enforcer: none — container only)[/red]")
    else:
        for fname in sorted(plan.policies):
            console.print(f"\n[bold]ring 1 — {fname}[/bold]")
            console.print(Syntax(plan.policies[fname].rstrip(), "json", theme="ansi_dark"))
    enf = get_enforcer(cfg.enforcer)
    if hasattr(enf, "gaps"):
        console.print("\n[bold yellow]documented gaps[/bold yellow]")
        for g in enf.gaps(plan):
            console.print(f"  [yellow]![/yellow] {g}")
