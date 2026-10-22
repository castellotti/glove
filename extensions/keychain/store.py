"""Writing a `keychain:<service>` secret to the OS credential store that core
reads it from (`glove.api.keychain_tool`): never in argv or a file."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys

from glove.api import KEYCHAIN_PARTS, NO_STORE, ConfigError, keychain_tool, secret_service_attrs

# Each tool takes a bounded value per write: `security -i` reads a command line
# of at most ~4 KB and runs the overflow as commands of its own, echoing them
# (the secret's tail included); `secret-tool store` keeps the first 8 KB of
# stdin and exits 0. A longer value is stored in parts (`<service>.part<i>`),
# with a head `glove-parts:<n>:<sha256>` under the service itself, which core
# joins and checks when reading.
_LINE_MAX = 3800
_STDIN_MAX = 8000
_VALUE_MAX = 4 << 20


def _quote(word: str) -> str:
    return '"' + word.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _run(argv: list[str], value: str | None = None) -> int:
    """The tool's exit code. Given a value, `security -i`'s output is withheld
    (it echoes a command it could not run, the secret included); secret-tool's
    error is raised (it never echoes the secret)."""
    if value is None:  # prompted, on the terminal
        return subprocess.run(argv, check=False).returncode
    r = subprocess.run(argv, input=value, encoding="utf-8", capture_output=True, check=False)
    if r.returncode and argv[0] == "secret-tool":
        raise ConfigError(f"{r.stderr.strip() or f'secret-tool: exit {r.returncode}'}; {NO_STORE}")
    return r.returncode


def keychain_set(service: str, secret: str | None = None) -> int:
    """Store (or replace) a secret. Prompted for (None): the tool reads it
    from the terminal, with no echo. Given: on the tool's stdin, one line, in
    parts if it is long. Returns the tool's exit code."""
    if not service or service.startswith("-"):
        raise ConfigError(f"invalid Keychain service name {service!r}")
    tool = keychain_tool()
    user = os.environ.get("USER") or "glove"
    if tool == "security":
        def add(svc: str) -> list[str]:  # `-w` last: security prompts for it
            return ["security", "add-generic-password", "-U", "-a", user, "-s", svc, "-w"]

        def store(svc: str, value: str) -> int:
            return _run(["security", "-i"], " ".join(_quote(w) for w in [*add(svc)[1:], value]) + "\n")

        def width(c: str) -> int:  # quoted, ASCII
            return 2 if c in '"\\' else 1

        def drop(svc: str) -> list[str]:
            return ["security", "delete-generic-password", "-s", svc]

        budget = _LINE_MAX - len(" ".join(_quote(w) for w in add(f"{service}.part{1 << 20}")[1:])) - 3
    else:
        def add(svc: str) -> list[str]:  # stdin a terminal: secret-tool prompts
            return ["secret-tool", "store", "--label", f"glove: {svc}", *secret_service_attrs(svc)]

        def store(svc: str, value: str) -> int:
            return _run(add(svc), value)

        def width(c: str) -> int:
            return len(c.encode())

        def drop(svc: str) -> list[str]:
            return ["secret-tool", "clear", *secret_service_attrs(svc)]

        budget = _STDIN_MAX

    if secret is None:
        # secret-tool would store whatever is piped, cut at 8 KB
        if not sys.stdin.isatty():
            raise ConfigError("no terminal to prompt on: give the secret instead (`glove keychain set --stdin`)")
        if rc := _run(add(service)):
            return rc
        parts = [secret]
    else:
        if not secret or any(c in w for w in (secret, service, user) for c in "\n\r\0"):
            raise ConfigError("the secret (and the service name) must be one non-empty line")
        if tool == "security" and not secret.isascii():  # `security -w` would read it back hex-encoded
            raise ConfigError("the secret must be ASCII")
        if secret.startswith(KEYCHAIN_PARTS) or len(secret) > _VALUE_MAX:
            raise ConfigError(f"the secret must not start with {KEYCHAIN_PARTS!r} and is at most "
                              f"{_VALUE_MAX >> 20} MB")
        parts, start, size = [], 0, 0
        for i, c in enumerate(secret):
            n = width(c)
            if size + n > budget:
                parts.append(secret[start:i])
                start, size = i, 0
            size += n
        parts.append(secret[start:])
        if len(parts) > 1:
            for i, value in enumerate(parts, 1):
                if rc := store(f"{service}.part{i}", value):
                    return rc
            head = f"{KEYCHAIN_PARTS}{len(parts)}:{hashlib.sha256(secret.encode()).hexdigest()}"
            if rc := store(service, head):
                return rc
        elif rc := store(service, secret):
            return rc
    # a shorter value leaves no stale parts behind (bounded: never more parts
    # than the largest value has); both tools fail on a missing item
    for i in range(len(parts) + 1 if len(parts) > 1 else 1, _VALUE_MAX // budget + 2):
        if subprocess.run(drop(f"{service}.part{i}"), capture_output=True, check=False).returncode != 0:
            break
    return 0
