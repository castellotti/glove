"""The ssh relay's policy: `ssh <host> <command>` to the hosts the session
names, run by relay's relayd.py in the sidecar that holds the key.

- The key lives in an ssh-agent in the sidecar (loaded from RELAY_SSH_KEY at
  start; PEM, or base64 of it as `glove keychain set` stores one line). ssh
  reads it through the agent; no key file exists anywhere.
- The destination must be one of `hosts` (`<name>` or `<user>@<name>` with its
  user). ssh dials that host's forwarder (`glove-<id>-ssh-<name>`), the
  sidecar's only route, and checks the host key strictly against the session's
  `known_hosts` under the host's real name (HostKeyAlias).
- Options are an allowlist (`-q`, `-v`, `-T`, `-n`, `-4`, `-6`, `-C`, a few
  `-o` keys): no port forwarding, jump hosts, ProxyCommand, agent or X11
  forwarding, config files, identities, control sockets or local commands, and
  no TTY (relayed commands get no stdin either). Everything after the host is
  the remote command, as with ssh.
"""

from __future__ import annotations

import base64
import glob
import os
import re
import subprocess

COMMANDS = frozenset({"ssh"})
HOSTS = ()  # raw TCP over the per-host forwarders: no proxy, no fence

AGENT = "/tmp/relay-agent.sock"
KNOWN_HOSTS = "/opt/glove/ssh/known_hosts"
FLAGS = frozenset({"-q", "-v", "-vv", "-vvv", "-T", "-n", "-4", "-6", "-C"})
OPTIONS = {  # -o key → allowed value pattern
    "connecttimeout": re.compile(r"\d{1,3}"),
    "serveraliveinterval": re.compile(r"\d{1,4}"),
    "serveralivecountmax": re.compile(r"\d{1,2}"),
    "batchmode": re.compile(r"yes"),
    "loglevel": re.compile(r"(?i)quiet|fatal|error|info|verbose|debug[123]?"),
}
# fixed, and first in argv: ssh keeps the first value it sees for a key, so an
# allowed `-o` can never override one of these
FORCED = [
    "-F", "/dev/null",
    "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
    "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no",
    "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
    "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
    "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no",
    "-o", "ControlPath=none", "-o", "Tunnel=no", "-o", "RequestTTY=no", "-o", f"IdentityAgent={AGENT}",
]


class Refused(Exception):
    """This invocation is not relayed."""


def _key(raw: str) -> bytes:
    raw = raw.strip()
    if not raw.startswith("-----BEGIN"):
        try:
            raw = base64.b64decode(raw, validate=True).decode()
        except ValueError:
            raise SystemExit("relayd: RELAY_SSH_KEY is neither a PEM private key nor base64 of one") from None
    return (raw.strip() + "\n").encode()


def _passwd() -> dict[str, str]:
    """ssh refuses to run for a uid with no passwd entry, and the rootfs is
    read-only: nss_wrapper serves this uid's entry from /tmp."""
    lib = next(iter(glob.glob("/usr/lib/*/libnss_wrapper.so")), None)
    if lib is None:
        raise SystemExit("relayd: libnss_wrapper is missing from the image")
    uid, gid = os.getuid(), os.getgid()
    with open("/tmp/relay-passwd", "w") as f:
        f.write(f"relay:x:{uid}:{gid}:relay:/tmp/relay-home:/bin/sh\n")
    with open("/tmp/relay-group", "w") as f:
        f.write(f"relay:x:{gid}:\n")
    return {"LD_PRELOAD": lib, "NSS_WRAPPER_PASSWD": "/tmp/relay-passwd", "NSS_WRAPPER_GROUP": "/tmp/relay-group"}


def setup(ctx: dict) -> dict[str, str]:
    key = os.environ.get("RELAY_SSH_KEY", "")
    if not key.strip():
        raise SystemExit("relayd: the ssh key is empty")
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp/relay-home", "LANG": "C.UTF-8",
           "SSH_AUTH_SOCK": AGENT, **_passwd()}
    os.makedirs(env["HOME"], mode=0o700, exist_ok=True)
    subprocess.run(["ssh-agent", "-a", AGENT], env=env, check=True, capture_output=True)
    r = subprocess.run(["ssh-add", "-q", "-"], env=env, input=_key(key), capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"relayd: ssh-add refused the key: {r.stderr.decode(errors='replace').strip()}")
    return env


def _hosts(req) -> dict[str, dict]:
    """RELAY_SETTINGS' `hosts` ({name, to, user}; hooks.py validated `to` at plan
    time) and `forwarders` (endpoint `ssh-<name>` → {host, port}) → name →
    {host, port, user, forwarder}."""
    out = {}
    for h in req.settings.get("hosts") or []:
        host, _, port = str(h["to"]).rpartition(":")
        out[str(h["name"])] = {"host": host, "port": int(port), "user": str(h["user"]),
                               "forwarder": req.settings["forwarders"][f"ssh-{h['name']}"]}
    return out


def prepare(req, env: dict[str, str]) -> list[str]:
    args = req.argv[1:]
    hosts = _hosts(req)
    opts: list[str] = []
    i = 0
    while i < len(args) and args[i].startswith("-"):
        tok = args[i]
        if tok in FLAGS:
            opts.append(tok)
        elif tok.startswith("-o"):
            if tok == "-o":
                i += 1
                value = args[i] if i < len(args) else ""
            else:
                value = tok[2:]
            k, sep, v = value.replace(" ", "=", 1).partition("=")
            pat = OPTIONS.get(k.lower())
            if not sep or pat is None or not pat.fullmatch(v):
                raise Refused(f"ssh -o {value!r} is not relayed (allowed: {', '.join(sorted(OPTIONS))})")
            opts += ["-o", f"{k}={v}"]
        elif tok == "--":
            i += 1
            break
        else:
            raise Refused(f"ssh {tok} is not relayed (no forwarding, jump hosts, config, identities or TTY; "
                          f"allowed: {' '.join(sorted(FLAGS))}, -o for {', '.join(sorted(OPTIONS))})")
        i += 1
    if i >= len(args):
        raise Refused(f"name a host: one of {sorted(hosts)}")
    dest, command = args[i], args[i + 1:]
    user, _, name = dest.rpartition("@")
    h = hosts.get(name)
    if h is None:
        raise Refused(f"{name!r} is not a host of this session (hosts: {', '.join(sorted(hosts)) or 'none'})")
    if user and user != h["user"]:
        raise Refused(f"{name} is reached as {h['user']}, not {user!r}")
    if not command:
        raise Refused("relayed ssh runs a command (`ssh <host> <command>`); there is no interactive shell")
    # ssh dials the host's forwarder; the host key is looked up under the
    # host's own known_hosts name (`[host]:port` off 22)
    alias = h["host"] if h["port"] == 22 else f"[{h['host']}]:{h['port']}"
    fwd = h["forwarder"]
    return ["ssh", *FORCED, "-o", f"HostKeyAlias={alias}", *opts, "-p", str(fwd["port"]), "-l", h["user"],
            "--", fwd["host"], *command]
