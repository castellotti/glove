"""glove command-line interface: the app, which mounts each command
(`commands/<name>/cli.py`; see commands/README.md) and each extension's CLI."""

from __future__ import annotations

from difflib import get_close_matches
from functools import cached_property
from pathlib import Path
from typing import Any

import typer
from rich.markup import escape
from typer.core import TyperCommand, TyperGroup

from .config import ConfigError
from .extensions import ExtensionError, Manifest, discover, load_module
from .registry import glove_home
from .sessionops import err, fail

# --- extension CLIs (`cli:` in a manifest → `glove <name> …`) ------------------------


class _Glove(TyperGroup):
    """glove's command group. An extension's CLI is listed from its manifest
    alone, and its `cli.py` is imported only when `glove <name> …` runs: an
    extension's code runs only when invoked, an untrusted out-of-tree one's never."""

    discover_error = ""

    @cached_property
    def extensions(self) -> dict[str, Manifest]:
        try:  # a malformed config.yml or manifest: `glove <unknown>` says so, the commands that read them too
            found = discover()
        except (ExtensionError, ConfigError) as e:
            self.discover_error = str(e)
            return {}
        return {n: m for n, m in sorted(found.items()) if m.cli is not None and n not in self.commands}

    def list_commands(self, ctx: typer.Context) -> list[str]:
        return [*super().list_commands(ctx), *self.extensions]

    def get_command(self, ctx: typer.Context, cmd_name: str) -> Any:
        if (cmd := super().get_command(ctx, cmd_name)) is not None or (m := self.extensions.get(cmd_name)) is None:
            return cmd  # a core command needs no discovery
        # a stand-in that `glove --help` lists; resolve_command loads the real one
        return TyperCommand(cmd_name, help=m.summary, hidden=not m.trusted)

    def resolve_command(self, ctx: typer.Context, args: list[str]) -> tuple[str | None, Any, list[str]]:
        if args and not args[0].startswith("-") and self.get_command(ctx, args[0]) is None:
            # suggest extension CLIs too, or say why there are none
            msg = f"No such command {args[0]!r}."
            names = [*self.commands, *(n for n, m in self.extensions.items() if m.trusted)]
            if near := get_close_matches(args[0], names):
                msg += f" Did you mean {', '.join(map(repr, near))}?"
            ctx.fail(msg + (f" (extension CLIs are unavailable: {self.discover_error})" if self.discover_error else ""))
        name, cmd, rest = super().resolve_command(ctx, args)
        if (m := self.extensions.get(name or "")) is not None:
            cmd = _extension_cli(m)
        return name, cmd, rest


def _extension_cli(m: Manifest) -> Any:
    """`m`'s Typer app as the group `glove <name> …`, imported for this run."""
    if not m.trusted:
        raise fail(f"extension {m.name!r} is out-of-tree and not trusted, so its CLI does not run; to trust "
                   f"it, list it under `trusted_extensions` in {escape(str(glove_home() / 'config.yml'))}")
    where = escape(str(m.cli))
    try:
        sub = getattr(load_module(m.cli, m.name), "app", None)
    except Exception as e:  # an extension's own code: anything can go wrong
        raise fail(f"extension {m.name!r} CLI ({where}) failed to load: {escape(str(e))}") from e
    if not isinstance(sub, typer.Typer):
        raise fail(f"extension {m.name!r}: {where} has no `app` (a typer.Typer)")
    holder = typer.Typer()
    holder.add_typer(sub, name=m.name, help=m.summary)
    return typer.main.get_group(holder).commands[m.name]


app = typer.Typer(
    cls=_Glove,
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


# --- commands (`commands/<name>/cli.py` → `glove <name>`) -------------------------------

COMMANDS_DIR = Path(__file__).resolve().parent.parent / "commands"


def _mount_commands() -> None:
    """Mount each in-tree command (`commands/<name>/cli.py`, loaded by path): its
    `command` (a function) as `glove <name>`, or its `app` (a Typer) as the group
    `glove <name> …`, in `--help` order (its RANK, then its name). One that fails
    to load is reported; the others still work."""
    loaded = []
    for d in (p for p in COMMANDS_DIR.iterdir() if (p / "cli.py").is_file()) if COMMANDS_DIR.is_dir() else ():
        try:
            loaded.append((d, load_module(d / "cli.py", d.name, ns="glove_cmd")))
        except Exception as e:
            err.print(f"[yellow]warn:[/yellow] command {d.name!r} failed to load: {escape(str(e))}")
    for d, m in sorted(loaded, key=lambda dm: (getattr(dm[1], "RANK", 100), dm[0].name)):
        if callable(getattr(m, "command", None)):
            app.command(d.name)(m.command)
        elif isinstance(getattr(m, "app", None), typer.Typer):
            app.add_typer(m.app, name=d.name)
        else:
            err.print(f"[yellow]warn:[/yellow] command {d.name!r}: {d / 'cli.py'} has neither `command` nor `app`")


_mount_commands()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
