"""`glove ls` — the registered sessions."""

from __future__ import annotations

from glove.api.commands import RegistryError, console, fail, load_registry, row_state

RANK = 7  # its place in `glove --help` (commands/README.md)


def command() -> None:
    """Registered sessions: id, harness, template, state, directory."""
    try:
        entries = load_registry()
    except RegistryError as e:
        raise fail(str(e)) from e
    if not entries:
        console.print("[dim]no sessions — create one with `glove new <template> <dir>`[/dim]")
        return
    colour = {"ok": "green", "missing": "red", "stale": "yellow"}
    for e in sorted(entries, key=lambda x: x.id):
        st = row_state(e)
        observed = " [cyan]observe[/cyan]" if (e.grants or {}).get("observe") else ""
        console.print(f"[bold]{e.id}[/bold]  [cyan]{e.harness}[/cyan]  {e.template or '-'}  "
                      f"[{colour[st]}]{st}[/{colour[st]}]{observed}  {e.dir}")
    if any(row_state(e) != "ok" for e in entries):
        console.print("[dim]missing/stale rows (and their exports) are removed by `glove gc`[/dim]")
