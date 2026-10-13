"""The `skills` relay's policy: which of a plugin's scripts the sidecar runs for
the harness, and how (loaded by path by relay's relayd.py, one sidecar per
plugin).

Everything comes from data, `RELAY_SETTINGS` (rendered by hooks.py from the
plugin's `relay:` block), so nothing here knows a service:

- `commands`: the relayed scripts, by their path in the plugin
  (`scripts/x.py`). Each has its own environment, built from nothing: its
  plain `env`, its secrets (read from this sidecar's environment, where glove
  put them at `compose up`), its own HOME on this sidecar's tmpfs with its
  `files` (rendered on the host, never written there), and a proxy that is its
  own egress fence: only its `hosts`.
- `allow`: the first argument must be one of them (`*`: any). Not "the first
  that is not a flag": a global option's value (`--profile status mint`) would
  pass for the subcommand. Anything else is refused, so a script's minting or
  posting subcommands run only when the operator lists them.
- `out_flags`/`in_flags`: the value of such a flag is a path under /work (an
  output; an input is opened here and handed over as /dev/fd/N). Any other
  argument that names an existing file, or looks like a path, must resolve
  under /work too (a link in /work to this sidecar's files is refused).

The scripts are bound read-only at the path the harness sees them
(/opt/glove/plugins/<name>); a Python one runs on this image's Python (stdlib
only), anything else by its own shebang.
"""

from __future__ import annotations

import json
import os


class Refused(Exception):
    """This invocation is not relayed."""


SETTINGS = json.loads(os.environ.get("RELAY_SETTINGS") or "{}")
SPECS: dict[str, dict] = SETTINGS.get("commands") or {}  # command → its spec (hooks.py `_relay`)
COMMANDS = frozenset(SPECS)
# relayd: one fence per command, each with only its own hosts (`*.x` → `.x`)
HOSTS = {cmd: tuple(f".{h[2:]}" if h.startswith("*.") else h for h in spec.get("hosts") or ())
         for cmd, spec in SPECS.items()}
ENVS: dict[str, dict[str, str]] = {}  # command → its environment (setup)
# one HOME per command, on this sidecar's tmpfs; a dot name, so that a plain
# word argument (`home`) never names it from a relay's cwd, /tmp
HOMES = "/tmp/.relay-homes"
HELP = frozenset({"-h", "--help"})


def setup(ctx: dict) -> dict[str, str]:
    """Each command's environment, and its HOME with its files (mode 0600)."""
    root = SETTINGS["root"]
    base = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1", "CLAUDE_PLUGIN_ROOT": root}
    if ctx["work"]:
        base["CLAUDE_PLUGIN_DATA"] = SETTINGS["data"]
    for i, (cmd, spec) in enumerate(sorted(SPECS.items())):
        home = f"{HOMES}/{i}"
        os.makedirs(f"{home}/tmp", mode=0o700, exist_ok=True)
        for rel, var in (spec.get("files") or {}).items():
            path = os.path.join(home, rel)
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(_secret(var))
        env = {**base, "HOME": home, "TMPDIR": f"{home}/tmp", **(spec.get("env") or {}),
               **{k: _secret(var) for k, var in (spec.get("secret_env") or {}).items()}}
        if proxy := ctx["proxies"].get(cmd):
            env |= {"HTTPS_PROXY": proxy, "https_proxy": proxy, "HTTP_PROXY": proxy, "http_proxy": proxy,
                    "NO_PROXY": "", "no_proxy": ""}
        ENVS[cmd] = env
    return base


def _secret(var: str) -> str:
    value = os.environ.get(var, "")
    if not value:
        raise SystemExit(f"relayd: {var} is empty (glove resolves it at `compose up`)")
    return value


def prepare(req, env: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    cmd, args = req.argv[0], req.argv[1:]
    spec = SPECS[cmd]
    allow = spec.get("allow") or []
    if "*" not in allow and not (args and set(args) <= HELP):
        if not args or args[0].startswith("-"):
            raise Refused(f"{cmd}: its first argument is the subcommand, one of: {', '.join(allow)}")
        if args[0] not in allow:
            raise Refused(f"{cmd} {args[0]} is not allowed here (allowed: {', '.join(allow)}); credentials are "
                          "managed by the operator (glove skills status)")
    in_flags = set(spec.get("in_flags") or ())
    path_flags = in_flags | set(spec.get("out_flags") or ())
    argv: list[str] = []
    pending: str | None = None  # the flag whose value is next
    for a in args:
        if pending is not None:
            argv.append(_path(req, a, pending in in_flags))
            pending = None
            continue
        flag, eq, value = a.partition("=")
        short = a[:2] if a[:1] == "-" and a[1:2] != "-" and len(a) > 2 else None  # -o<path>
        if flag in path_flags:
            if eq:
                argv.append(f"{flag}={_path(req, value, flag in in_flags)}")
            else:
                argv.append(a)
                pending = flag
        elif short in path_flags:
            argv.append(short + _path(req, a[2:], short in in_flags))
        else:
            for v in {a, value, a[2:] if short else a}:
                _plain(req, v)
            argv.append(a)
    if pending is not None:
        raise Refused(f"{pending} needs a path under /work")
    script = f"{SETTINGS['root']}/{cmd}"
    run = ["python3", "-s", script] if spec.get("python") else [script]
    return [*run, *argv], dict(ENVS[cmd])


def _path(req, value: str, is_input: bool) -> str:
    """An `in_flags`/`out_flags` value: inside /work (an input is opened here,
    so what is checked is what the script reads)."""
    return req.file(value) if is_input else req.directory(value)


def _plain(req, value: str) -> None:
    """Any other argument that names a path (absolute, `~`, with `..`, or an
    existing file or link from the cwd) must resolve under /work: a script's
    positional file argument could otherwise read this sidecar's own files (the
    homes hold the credentials), directly or through a link the agent made in
    /work. (A link swapped in after this check is a race an `in_flags` file
    never has: the relay opens that one itself.)"""
    if not value or value.startswith("-"):
        return
    path = value if value.startswith("/") else os.path.join(req.cwd, value)
    if not (value.startswith(("/", "~")) or ".." in value.split("/") or os.path.lexists(path)):
        return
    real = os.path.realpath(path)
    if value.startswith("~") or not req.work or not (real == req.work or real.startswith(req.work.rstrip("/") + "/")):
        raise Refused(f"{value}: a path must be under /work (pass a file through /work)")
