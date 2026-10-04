"""ssh hooks.

`contribute()` validates `hosts` and turns each into an endpoint: a forwarder
`glove-<id>-ssh-<name>` that listens on `sshnet` (the relay sidecar's only
network) and dials exactly that host over the `lan` network. The harness never
gets one (`harness: false`): only the sidecar reaches the host, and with observe
each forwarder is a gate (`client: ssh`, `scope: lan`).

`materialize()` copies the `known_hosts` file the user named (inside the session
directory) into the extension's state, which the sidecar binds read-only.

`launch_env()` resolves the key reference in memory at `glove up` and hands it
to the sidecar's environment for that `compose up` only (RELAY_SSH_KEY; the
sidecar is read-only, so not a compose secret). The sidecar loads it into an
ssh-agent and nothing else sees it.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

NAME = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
USER = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$")


def hosts(settings: dict[str, Any]) -> list[dict[str, Any]]:
    """`hosts`, validated: [{name, host, port, user}]."""
    out = []
    for i, h in enumerate(settings.get("hosts") or []):
        where = f"ssh.hosts[{i}]"
        if not isinstance(h, dict) or set(h) - {"name", "to", "user"} or not {"name", "to", "user"} <= set(h):
            raise ValueError(f"{where}: want {{name: <name>, to: <host>:<port>, user: <user>}}")
        name, to, user = str(h["name"]), str(h["to"]), str(h["user"])
        host, _, port = to.rpartition(":")
        if not NAME.match(name):
            raise ValueError(f"{where}: name must match {NAME.pattern}, got {name!r}")
        if not HOST.match(host) or not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError(f"{where}: `to` must be <host>:<port>, got {to!r}")
        if not USER.match(user):
            raise ValueError(f"{where}: user must match {USER.pattern}, got {user!r}")
        if any(x["name"] == name for x in out):
            raise ValueError(f"{where}: host name {name!r} is used twice")
        out.append({"name": name, "host": host, "port": int(port), "user": user})
    if not out:
        raise ValueError("ssh.hosts: name at least one host")
    return out


def _known_hosts(ctx: dict[str, Any]) -> Path:
    rel = ctx["settings"]["known_hosts"]
    sd = ctx.get("session_dir")
    if sd is None:
        raise ValueError("ssh.known_hosts needs the session directory")
    path = (Path(sd) / rel).resolve()
    if not path.is_relative_to(Path(sd).resolve()) or not path.is_file():
        raise ValueError(f"ssh.known_hosts: {rel!r} is not a file in the session directory "
                         "(e.g. `ssh-keyscan -p <port> <host> > local/known_hosts`, then check the keys)")
    return path


def contribute(ctx: dict[str, Any]) -> dict[str, Any]:
    if ctx.get("session_dir") is not None:
        _known_hosts(ctx)  # fail at `glove check`, not at launch
    endpoints = {}
    for h in hosts(ctx["settings"]):
        endpoints[f"ssh-{h['name']}"] = {
            "harness": False,
            "port": 22,  # whatever the host's port: the policy always dials :22
            "target": {"address": f"{h['host']}:{h['port']}", "via": "lan"},
            "listen_networks": ["sshnet"],
            "observe": {"client": "ssh", "tool": "ssh", "scope": "lan"},
        }
    return {"endpoints": endpoints}


def materialize(ctx: dict[str, Any]) -> None:
    shutil.copyfile(_known_hosts(ctx), Path(ctx["state_dir"]) / "known_hosts")


def launch_env(ctx: dict[str, Any], resolve_secret) -> dict[str, Any]:
    key = resolve_secret(ctx["settings"]["key"]).strip()
    if not key:
        raise ValueError("ssh.key resolves to an empty value")
    return {"env": {"RELAY_SSH_KEY": key}}
