"""`glove ps` — the running glove sessions."""

from __future__ import annotations

import typer

from glove.api.commands import RegistryError, autodetect_provider, console, get_runtime, load_registry


def command(runtime: str | None = typer.Option(None, "--runtime", help="docker | podman")) -> None:
    """Running glove sessions (compose projects) and their directories."""
    rt = get_runtime(runtime or autodetect_provider())
    running = rt.ps()
    if not running:
        console.print("[dim]no running glove sessions[/dim]")
        return
    try:
        dirs = {e.id: e.dir for e in load_registry()}
    except RegistryError:
        dirs = {}
    for s in sorted(running, key=lambda x: x.project):
        console.print(f"[bold]{s.session}[/bold]  {dirs.get(s.session, '[dim](not registered)[/dim]')}  "
                      f"[dim]({len(s.services)} containers: {', '.join(sorted(s.services))})[/dim]")
