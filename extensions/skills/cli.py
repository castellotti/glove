"""`glove skills status|refresh|reload` — the credentials of the plugins' relays.

- `status`: each relay's checks (`relay.check`), run through the relay as the
  agent's calls are, from inside its sidecar: `ok`, or the exit code (the
  output is withheld: it may carry identifiers).
- `refresh <plugin>`: a new value for each of the relay's Keychain secrets,
  printed by its `refresh:` hook (run here, on the host, with the service name)
  or typed at a prompt, then `reload`.
- `reload <plugin>`: the secrets resolved again and only that relay's sidecar
  recreated; the harness and the agent's conversation keep running. The rest
  of the relay (commands, hosts, allow) is what the last `glove up` rendered.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from glove.api import (
    ConfigError,
    ExtSession,
    ext_session,
    keychain_service,
    keychain_set,
    reload_sidecar,
    resolve_secret,
)

app = typer.Typer(add_completion=False, help="The credentials of the plugins' relays: check, refresh, reload.")
console = Console(highlight=False)
err = Console(stderr=True)

DIR_OPT = typer.Option(None, "--dir", help="session directory (default: the nearest one)")
PLUGIN = typer.Argument(..., help="the plugin's name (skills.plugins.<name>)")


def _fail(msg: str) -> typer.Exit:
    err.print(f"[red]error:[/red] {msg}")
    return typer.Exit(1)


def _session(directory: Path | None) -> ExtSession:
    try:
        return ext_session("skills", directory)
    except ConfigError as e:
        raise _fail(str(e)) from e


def _relays(s: ExtSession, only: str | None = None) -> list[Any]:
    try:
        found = s.hooks.relays(s.context(), only)
    except ValueError as e:
        raise _fail(str(e)) from e
    if only is not None and not found:
        raise _fail(f"no plugin {only!r} with a relay (skills.plugins.{only}.relay)")
    return found


def _check(s: ExtSession, relay, argv: list[str]) -> int:
    cmd = [s.runtime, "exec", s.container(relay.service), *relay.check_argv(argv)]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=s.hooks.CHECK_TIMEOUT + 10, check=False).returncode
    except subprocess.TimeoutExpired:
        return 124


@app.command("status")
def status(plugin: str | None = typer.Argument(None, help="one plugin (default: every relay)"),
           directory: Path | None = DIR_OPT) -> None:
    """Run each relay's checks: `ok`, or how it failed (output withheld)."""
    s = _session(directory)
    relays = _relays(s, plugin)
    if not relays:
        console.print("no plugin has a relay")
        return
    failed = 0
    for relay in relays:
        if not s.running(relay.service):
            console.print(f"[red]✗[/red] {relay.name}: {s.container(relay.service)} is not running (`glove up`)")
            failed += 1
            continue
        if not relay.checks:
            console.print(f"[dim]·[/dim] {relay.name}: running, no checks (skills.plugins.{relay.name}.relay.check)")
        for argv, _ in relay.checks:
            rc = _check(s, relay, argv)
            mark = "[green]ok[/green]" if rc == 0 else f"[red]failed (exit {rc})[/red]"
            console.print(f"{relay.name}: {' '.join(argv)} — {mark}")
            failed += rc != 0
    if failed:
        console.print("[dim]an expired credential: `glove skills refresh <plugin>`[/dim]")
        raise typer.Exit(1)


@app.command("reload")
def reload(plugin: str = PLUGIN, directory: Path | None = DIR_OPT) -> None:
    """Resolve the relay's secrets again and recreate only its sidecar."""
    s = _session(directory)
    _reload(s, _relays(s, plugin)[0])


def _reload(s: ExtSession, relay) -> None:
    if not s.running(relay.service):
        raise _fail(f"{s.container(relay.service)} is not running; `glove up` starts it with the current secrets")
    if not rendered_as(s.rendered(relay.service), relay):
        raise _fail(f"skills.plugins.{relay.name}.relay changed since the last `glove up`; `glove up` applies it "
                    "(a reload only re-resolves the secrets)")
    try:
        env = s.hooks.relay_env(relay, resolve_secret)
        reload_sidecar(s, relay.service, env)
    except (ConfigError, ValueError) as e:
        raise _fail(str(e)) from e
    console.print(f"[green]✓[/green] {s.container(relay.service)} reloaded")


def rendered_as(service: dict, relay) -> bool:
    """Whether the relay's sidecar as the last `glove up` rendered it is this
    relay as it is now: its secrets go by name into that, and a command added
    or moved since renames them (one command's secret would reach another's)."""
    env = service.get("environment") or {}
    return (json.loads(env.get("RELAY_SETTINGS") or "null") == relay.settings
            and {k for k, v in env.items() if v is None} == set(relay.secrets))


@app.command("refresh")
def refresh(
    plugin: str = PLUGIN,
    secret: str | None = typer.Option(None, "--secret", help="only this Keychain service"),
    no_reload: bool = typer.Option(False, "--no-reload", help="store the new values, recreate nothing"),
    directory: Path | None = DIR_OPT,
) -> None:
    """Store new values for the relay's Keychain secrets (its refresh hooks,
    else a prompt), then reload it."""
    s = _session(directory)
    relay = _relays(s, plugin)[0]
    refs = {ref: hook for ref, hook in relay.refresh.items() if keychain_service(ref)}
    if secret is not None:
        if f"keychain:{secret}" not in refs:
            raise _fail(f"{plugin}'s relay has no secret keychain:{secret} (it has {', '.join(sorted(refs))})")
        refs = {f"keychain:{secret}": refs[f"keychain:{secret}"]}
    if not refs:
        raise _fail(f"{plugin}'s relay has no keychain: secret to refresh")
    for ref, hook in sorted(refs.items()):
        service = keychain_service(ref)
        if hook is None:
            if not sys.stdin.isatty():
                raise _fail(f"{service} has no refresh hook; run this in a terminal to type it")
            console.print(f"[bold]{service}[/bold]: a new value (no refresh hook)")
            value = None
        else:
            console.print(f"[bold]{service}[/bold]: running {hook.relative_to(s.root)}")
            # stdout is the secret (kept in memory); stderr is the hook's own talk
            r = subprocess.run([str(hook), service], cwd=s.root, stdout=subprocess.PIPE, text=True, check=False)
            value = r.stdout.strip()
            if r.returncode != 0 or not value:
                raise _fail(f"{hook.name} {'exited ' + str(r.returncode) if r.returncode else 'printed nothing'}; "
                            f"{service} is unchanged")
        try:
            rc = keychain_set(service, value)
        except ConfigError as e:
            raise _fail(f"{service}: {e}") from e
        if rc != 0:
            raise _fail(f"storing {service} failed (exit {rc})")
        console.print(f"[green]✓[/green] {service} stored")
    if not no_reload:
        if s.running(relay.service):
            _reload(s, relay)
        else:
            console.print(f"[dim]{s.container(relay.service)} is not running: the next `glove up` uses the new "
                          "values[/dim]")
