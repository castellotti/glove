"""glove command-line interface: the app, which mounts each command
(`commands/<name>/cli.py`; see commands/README.md) and each extension's CLI."""

from __future__ import annotations

from pathlib import Path

import typer

from .config import ConfigError
from .sessionops import err

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
    Commands import only glove.api(.commands); core loads them by path. One that
    fails to load is reported, and the others still work."""
    from rich.markup import escape

    from .extensions import load_module

    found = sorted(p for p in COMMANDS_DIR.iterdir() if (p / "cli.py").is_file()) if COMMANDS_DIR.is_dir() else []
    for d in found:
        try:
            m = load_module(d / "cli.py", d.name, ns="glove_cmd")
        except Exception as e:
            err.print(f"[yellow]warn:[/yellow] command {d.name!r} failed to load: {escape(str(e))}")
            continue
        if callable(getattr(m, "command", None)):
            app.command(d.name)(m.command)
        elif isinstance(getattr(m, "app", None), typer.Typer):
            app.add_typer(m.app, name=d.name)
        else:
            err.print(f"[yellow]warn:[/yellow] command {d.name!r}: {d / 'cli.py'} has neither `command` nor `app`")


_mount_commands()
_mount_extension_clis()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
