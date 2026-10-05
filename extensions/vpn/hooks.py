"""`vpn` extension hooks: the WireGuard register hook and tunnel diagnosis.

`launch_env()` runs on the host at `glove up`. With `register_hook` set it runs
that executable (it must live in the session's `local/`, which is never
mounted into the harness) with the account username and password on stdin, one
per line, and reads `WIREGUARD_*=value` lines from its stdout:

    WIREGUARD_PRIVATE_KEY  → the gluetun compose secret (memory only)
    WIREGUARD_PUBLIC_KEY, WIREGUARD_ENDPOINT_IP, WIREGUARD_ENDPOINT_PORT,
    WIREGUARD_ADDRESSES    → gluetun's environment for this `compose up`

Progress goes to the hook's stderr (shown). Nothing it prints is written to a
file by glove. This is the contract of the v2 `VPN_WG_REGISTER` hook.

`diagnose()` explains a failed tunnel check: WireGuard is silent, so a dead
handshake is told apart by tun0's received-bytes counter.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

WG_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=\Z")
HOOK_KEYS = ("WIREGUARD_PRIVATE_KEY", "WIREGUARD_PUBLIC_KEY", "WIREGUARD_ENDPOINT_IP", "WIREGUARD_ENDPOINT_PORT",
             "WIREGUARD_ADDRESSES")


class VpnError(ValueError):
    pass


def contribute(ctx: dict[str, Any]) -> dict[str, Any]:
    s = ctx["settings"]
    if s.get("register_hook"):
        if s.get("type") != "wireguard":
            raise VpnError("vpn.register_hook registers a WireGuard key: it needs `type: wireguard`")
        if s.get("provider") != "custom":
            raise VpnError("vpn.register_hook yields a custom WireGuard server: set `provider: custom`")
        if s.get("wireguard_key"):
            raise VpnError("vpn: set either `wireguard_key` or `register_hook`, not both")
        if not s.get("register_user") or not s.get("register_pass"):
            raise VpnError("vpn.register_hook needs `register_user` and `register_pass` (keychain:<service> refs)")
        if not str(s["register_hook"]).startswith("local/"):
            raise VpnError("vpn.register_hook must be in the session's local/ directory (never mounted into the "
                           f"harness), e.g. local/register.sh — got {s['register_hook']!r}")
    return {}


def hook_path(session_dir: Path, rel: str) -> Path:
    """The hook's real path; it must resolve inside `<session>/local/`, so a
    symlink cannot point it at something the agent can write (work/)."""
    local = (session_dir / "local").resolve()
    path = (session_dir / rel).resolve()
    if not path.is_relative_to(local):
        raise VpnError(f"vpn.register_hook {rel!r} resolves outside the session's local/ directory ({path})")
    if not path.is_file() or not os.access(path, os.X_OK):
        raise VpnError(f"vpn.register_hook {path} is not an executable file")
    return path


def parse_hook_output(out: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        key, sep, value = line.partition("=")
        if not sep or key not in HOOK_KEYS:
            raise VpnError(f"the register hook printed an unexpected line (key {key!r}); it may print only "
                           f"{', '.join(HOOK_KEYS)}=value lines on stdout")
        values[key] = value
    missing = [k for k in HOOK_KEYS if not values.get(k)]
    if missing:
        raise VpnError(f"the register hook did not print {', '.join(missing)}")
    if not WG_KEY.match(values["WIREGUARD_PRIVATE_KEY"]):
        raise VpnError("the register hook's WIREGUARD_PRIVATE_KEY is not a WireGuard key (44-char base64)")
    if not values["WIREGUARD_ENDPOINT_PORT"].isdigit():
        raise VpnError("the register hook's WIREGUARD_ENDPOINT_PORT is not a port number")
    return values


def launch_env(ctx: dict[str, Any], resolve_secret) -> dict[str, Any]:
    s = ctx["settings"]
    if not s.get("register_hook"):
        return {}
    if ctx.get("session_dir") is None:
        raise VpnError("vpn.register_hook needs the session directory")
    hook = hook_path(Path(ctx["session_dir"]), str(s["register_hook"]))
    stdin = f"{resolve_secret(s['register_user'])}\n{resolve_secret(s['register_pass'])}\n"
    print(f"vpn: registering a fresh WireGuard key ({hook.name})…", flush=True)
    try:
        r = subprocess.run([str(hook)], input=stdin, stdout=subprocess.PIPE, text=True, timeout=180,
                           cwd=hook.parent, check=False)
    except subprocess.TimeoutExpired as e:
        raise VpnError(f"the register hook {hook} timed out") from e
    finally:
        del stdin
    if r.returncode != 0:
        raise VpnError(f"the register hook {hook} failed (exit {r.returncode})")
    values = parse_hook_output(r.stdout)
    key = values.pop("WIREGUARD_PRIVATE_KEY")
    return {"secrets": {"wireguard_private_key": key}, "env": values}


def diagnose(ctx: dict[str, Any], check: dict[str, Any], run) -> str | None:
    if check.get("service") != "gluetun":
        return None
    rc, rx = run("gluetun", ["cat", "/sys/class/net/tun0/statistics/rx_bytes"])
    if rc != 0 or not rx.strip().isdigit():
        return "gluetun has no tunnel interface: see its log lines above (credentials, provider or server)."
    if int(rx) == 0:
        hint = ("no WireGuard handshake: the VPN server never answered (tun0 received 0 bytes). "
                "The key was likely revoked or the server changed")
        if ctx["settings"].get("register_hook"):
            return hint + "; `glove up` registers a new key each time, so check the hook and the account."
        return (hint + ": check the key/device with your VPN provider and store a new key with "
                "`glove keychain set <service>`. Also possible: this network blocks outbound UDP to the endpoint.")
    return f"the tunnel passes traffic (tun0 received {rx} bytes) but the check still failed."
