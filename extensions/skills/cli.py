"""`glove skills status|refresh|reload` — the credentials of the plugins' relays.

- `status`: each relay's checks (`relay.check`), run through the relay as the
  agent's calls are, from inside its sidecar: `ok`, or the exit code (the
  output is withheld: it may carry identifiers).
- `refresh <plugin> [<secret>…]`: a new value for the relay's Keychain secrets
  (all, or the ones named: a service, or the env var or file key that uses it),
  from its `refresh:` hook (run here, on the host, with the service name), from
  `glove playwright login` when that captures it, or typed at a prompt (Enter
  keeps what is stored); then `reload`.
- `reload <plugin>`: the secrets resolved again and only that relay's sidecar
  recreated; the harness and the agent's conversation keep running. The rest
  of the relay (commands, hosts, allow) is what the last `glove up` rendered.
"""

from __future__ import annotations

import getpass
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from glove.api import (
    ConfigError,
    ExtensionError,
    ExtSession,
    ext_session,
    keychain_service,
    keychain_set,
    reload_sidecar,
    resolve_secret,
    secret_exists,
)

app = typer.Typer(add_completion=False, help="The credentials of the plugins' relays: check, refresh, reload.")
console = Console(highlight=False)
err = Console(stderr=True)

DIR_OPT = typer.Option(None, "--dir", help="session directory (default: the nearest one)")
KEEP, SKIP = "a new value; Enter keeps the stored one", "missing: a value; Enter skips it"
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
    names: list[str] = typer.Argument(None, metavar="[SECRET]...",
                                      help="only these: a Keychain service, or the env var or file key using it"),
    secret: list[str] = typer.Option([], "--secret", help="only this Keychain service (repeatable)"),
    no_reload: bool = typer.Option(False, "--no-reload", help="store the new values, recreate nothing"),
    directory: Path | None = DIR_OPT,
) -> None:
    """Store new values for the relay's Keychain secrets (its refresh hooks,
    `glove playwright login`, else a prompt where Enter keeps the stored one),
    then reload it."""
    s = _session(directory)
    relay = _relays(s, plugin)[0]
    uses = secret_uses(relay)
    refs = {ref: hook for ref, hook in relay.refresh.items() if keychain_service(ref)}
    if not refs:
        raise _fail(f"{plugin}'s relay has no keychain: secret to refresh")
    wanted = [*(names or []), *secret]
    if wanted:
        refs = {ref: refs[ref] for ref in pick(refs, uses, wanted)}
    login = _login_captures(s.root)
    console.print(f"[bold]{plugin}[/bold]'s Keychain secrets:")
    plan = []
    for ref, hook in sorted(refs.items()):
        service = keychain_service(ref)
        stored = secret_exists(ref)[0]
        how = (f"hook {hook.relative_to(s.root)}" if hook else "`glove playwright login`" if service in login
               else "typed")
        plan.append((service, hook, stored))
        console.print(f"  {service}  {'[green]stored[/green]' if stored else '[yellow]missing[/yellow]'}  "
                      f"[dim]{how}; {', '.join(label for _, label in uses.get(ref, []))}[/dim]")
    if not wanted and len(refs) > 1:
        console.print(f"[dim]only some: `glove skills refresh {plugin} <secret>…`; Enter at a question skips "
                      "that secret[/dim]")
    changed: list[str] = []
    try:
        _refresh_each(s, plan, login, changed, named=bool(wanted), no_reload=no_reload)
    except (typer.Exit, KeyboardInterrupt):
        if changed:  # stored before the failure: the running relay still has the old values
            err.print(f"stored before stopping: {', '.join(changed)}; `glove skills reload {plugin}` applies them")
        raise
    if not changed:
        console.print("nothing changed")
    elif not no_reload:
        if s.running(relay.service):
            _reload(s, relay)
        else:
            console.print(f"[dim]{s.container(relay.service)} is not running: the next `glove up` uses the new "
                          "values[/dim]")


def _refresh_each(s: ExtSession, plan: list, login: set[str], changed: list[str], *, named: bool,
                  no_reload: bool) -> None:
    """Each secret from its hook, a prompt (Enter keeps it) or, together at
    the end, `glove playwright login`. Refreshing every secret confirms each
    hook and the sign-in (Enter: no); a named one that can't be refreshed
    here is an error. What is stored goes in `changed`."""
    tty = sys.stdin.isatty()
    ask = tty and not named
    signin = []
    for service, hook, stored in plan:
        if hook is not None:
            if ask and not typer.confirm(f"{service}: run {hook.name}?", default=False):
                continue
            changed.append(_from_hook(s, service, hook))
        elif service in login:
            signin.append(service)
        elif not tty:
            if named:
                raise _fail(f"{service} has no refresh hook; run this in a terminal to type it")
            console.print(f"[dim]{service}: skipped (no refresh hook, and no terminal to type it)[/dim]")
        elif value := getpass.getpass(f"{service} ({KEEP if stored else SKIP}): ").strip():
            changed.append(_store(service, value))
        else:
            console.print(f"[dim]{service}: {'kept' if stored else 'skipped'}[/dim]")
    if not signin:
        return
    names = ", ".join(signin)
    if not tty:
        if named:
            raise _fail(f"{names}: `glove playwright login` needs a terminal")
        console.print(f"[dim]{names}: skipped (`glove playwright login` needs a terminal)[/dim]")
        return
    if ask and not typer.confirm(f"{names}: sign in with `glove playwright login`?", default=False):
        return
    argv = [sys.executable, "-m", "glove.cli", "playwright", "login", "--dir", str(s.root),
            *(["--no-reload"] if no_reload else [])]
    if subprocess.run(argv, check=False).returncode != 0:
        raise _fail(f"`glove playwright login` failed; {names} unchanged")
    console.print("[dim]`glove playwright login` stores every login.capture: another plugin's relay using one "
                  "takes `glove skills reload <plugin>`[/dim]")
    changed += signin


def secret_uses(relay) -> dict[str, list[tuple[str, str]]]:
    """Each secret reference's uses, as (name, label): `VAR (script)`, `key
    in ~/file (script)`."""
    uses: dict[str, list[tuple[str, str]]] = {}
    for cmd, c in relay.settings["commands"].items():
        for var, side in c["secret_env"].items():
            uses.setdefault(relay.secrets[side], []).append((var, f"{var} ({cmd})"))
        for rel, side in c["files"].items():
            for key, ref in relay.secrets[side]["secrets"].items():
                uses.setdefault(ref, []).append((key, f"{key} in ~/{rel} ({cmd})"))
    return uses


def pick(refs: dict[str, Any], uses: dict[str, list[tuple[str, str]]], wanted: list[str]) -> list[str]:
    """The references `wanted` names: each a Keychain service, or the env var
    or file key that uses one."""
    out = []
    for name in wanted:
        found = [ref for ref in refs if keychain_service(ref) == name
                 or name in (n for n, _ in uses.get(ref, []))]
        if not found:
            raise _fail(f"no Keychain secret {name!r} in this relay (it has "
                        f"{', '.join(sorted(keychain_service(r) for r in refs))})")
        out += [ref for ref in found if ref not in out]
    return out


def _from_hook(s: ExtSession, service: str, hook: Path) -> str:
    console.print(f"[bold]{service}[/bold]: running {hook.relative_to(s.root)}")
    # stdout is the secret (kept in memory); stderr is the hook's own talk
    r = subprocess.run([str(hook), service], cwd=s.root, stdout=subprocess.PIPE, text=True, check=False)
    value = r.stdout.strip()
    if r.returncode != 0 or not value:
        raise _fail(f"{hook.name} {'exited ' + str(r.returncode) if r.returncode else 'printed nothing'}; "
                    f"{service} is unchanged")
    return _store(service, value)


def _store(service: str, value: str) -> str:
    try:
        rc = keychain_set(service, value)
    except ConfigError as e:
        raise _fail(f"{service}: {e}") from e
    if rc != 0:
        raise _fail(f"storing {service} failed (exit {rc})")
    console.print(f"[green]✓[/green] {service} stored")
    return service


def _login_captures(root: Path) -> set[str]:
    """The Keychain services `glove playwright login` stores (its
    `login.capture`), when the session enables playwright."""
    try:
        pw = ext_session("playwright", root, launched=False)
        spec = pw.hooks.login_spec(pw.settings)
    except ExtensionError:  # not enabled
        return set()
    except Exception as e:  # its settings or code: the other secrets still refresh
        err.print(f"[yellow]warning:[/yellow] playwright.login not read ({e}); its captures are typed instead")
        return set()
    return {c.service for c in spec.captures} if spec else set()
