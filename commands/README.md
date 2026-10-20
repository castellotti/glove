# Commands

Each `glove <name>` command lives in `commands/<name>/`, apart from the
extensions (`extensions/`, which add capabilities to sessions) and the harnesses
(`harnesses/`).

- `commands/<name>/cli.py` exports either `command` (a function, mounted as
  `glove <name>`; its docstring is the help) or `app` (a `typer.Typer`, mounted
  as the group `glove <name> …`).
- From core, a command imports only `glove.api` and `glove.api.commands` (the
  session machinery more than one command shares). It imports no extension
  and no other command. `tests/test_layering.py` enforces this, and
  `tests/test_api_surface.py` pins both APIs.
- Core loads commands by path (`glove/cli.py` `_mount_commands`) and never
  imports `commands` (the import-linter contract in `pyproject.toml`).
- A command's tests go in `commands/<name>/tests/` (`commands/conftest.py`
  holds the shared fixtures). A test that invokes `glove.cli.app` patches the
  module glove mounted, `command_module("<name>")` from `tests/helpers.py`
  (`glove_cmd.<name>.cli`); one that calls the module directly may load its
  own copy with
  `load_module(COMMANDS_DIR / "<name>" / "cli.py", "<name>", ns="glove_cmd")`
  (a second copy: the mounted command does not see what is patched on it).
- Code used by two or more commands moves into core (`glove/sessionops.py`)
  and is re-exported from `glove.api.commands` (CLAUDE.md P1). Code only one
  command uses stays in its directory; the core names it calls are re-exported
  from `glove.api.commands` too.
