"""glove command-line interface: the app, which mounts each command
(`commands/<name>/cli.py`) and each extension's CLI.

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
