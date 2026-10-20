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
- A command's tests go in `commands/<name>/tests/`. They load the module with
  `load_module(COMMANDS_DIR / "<name>" / "cli.py", "<name>", ns="glove_cmd")`.
- Code used by two or more commands moves into core and is re-exported from
  `glove.api.commands` (CLAUDE.md P1). Code only one command uses stays in its
  directory.
