"""`glove doctor` — host, runtime and enforcer readiness."""

from __future__ import annotations

import json

import typer

from glove.api.commands import console, default_enforcer, fail, known_runtimes, print_checks, run_doctor, worst_status

RANK = 14  # its place in `glove --help` (commands/README.md)


def command(
    runtime: str | None = typer.Option(None, "--runtime", help=f"probe a runtime: {', '.join(known_runtimes())}"),
    enforcer: str | None = typer.Option(None, "--enforcer", help="probe an enforcer: nono | nono+srt | srt | none"),
    json_out: bool = typer.Option(False, "--json", help="machine-readable output"),
    no_container: bool = typer.Option(False, "--no-container", help="skip container probes (host-only, fast)"),
) -> None:
    """Probe host + runtime + enforcer readiness (`glove check` adds a session's extensions)."""
    rt = runtime or "docker"
    enf = enforcer or default_enforcer(rt)
    try:
        checks = run_doctor(runtime=rt, enforcer=enf, include_container_probes=not no_container)
    except ValueError as e:
        raise fail(str(e)) from e
    if json_out:
        console.print_json(json.dumps({"runtime": rt, "enforcer": enf, "checks": [c.to_dict() for c in checks]}))
    else:
        print_checks(f"[bold]glove doctor[/bold]  runtime={rt}  enforcer={enf}", checks)
    raise typer.Exit(1 if worst_status(checks) == "fail" else 0)
