"""Live checks of the ssh relay (driven by test_ssh.sh).

    uv run python tests/integration/ssh_live.py <session-dir> <host-name> <user>

Starts the session the way `glove up` does (the stub as the model), then drives
the agent's own shell tool, so every command runs where an agent's would:
  1. the channel is there, and the key is nowhere in the harness;
  2. `ssh <name> <command>` reaches the LAN host through the sidecar (as the
     configured user, the host key checked against the session's known_hosts);
  3. what the policy refuses: other hosts and users, port forwarding, jump
     hosts, ProxyCommand, identities, config files, agent forwarding, a TTY, no
     command;
  4. a shell command still cannot reach the host (or anything), and the sidecar
     reaches the host only through its forwarder;
  5. with observe: the forwarder's flows are `client: ssh`, `scope: lan`; with
     a host `public` (SSH_LAN_ONLY=1), its gate refuses it: `builtin:lan-only`.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
import time
from contextlib import contextmanager

from live_common import check, inspect, live_session, summary


@contextmanager
def public_lan_name(s):
    """Make `public.lan` resolve to a public address (TEST-NET-3) at the
    `public` host's gate: a container known by that name on a network of its
    own, joined to the gate."""
    net = f"glove-test-public-{s.sid}"
    gate = f"glove-{s.sid}-ssh-public"
    image = inspect(s.rt, gate)["Config"]["Image"]
    for stale in subprocess.run([s.rt, "network", "ls", "--format", "{{.Name}}", "--filter", "name=glove-test-public-"],
                                capture_output=True, text=True).stdout.split():  # a crashed run's holds the subnet
        subprocess.run([s.rt, "rm", "-f", stale], capture_output=True)
        subprocess.run([s.rt, "network", "rm", stale], capture_output=True)
    try:
        subprocess.run([s.rt, "network", "create", "--subnet", "203.0.113.0/24", net], check=True, capture_output=True)
        subprocess.run([s.rt, "run", "-d", "--name", net, "--network", net, "--network-alias", "public.lan",
                        "--entrypoint", "sleep", image, "300"], check=True, capture_output=True)
        subprocess.run([s.rt, "network", "connect", net, gate], check=True, capture_output=True)
        yield
    finally:
        subprocess.run([s.rt, "network", "disconnect", "-f", net, gate], capture_output=True)
        subprocess.run([s.rt, "rm", "-f", net], capture_output=True)
        subprocess.run([s.rt, "network", "rm", net], capture_output=True)


def main(directory: str, name: str, user: str) -> int:
    with live_session(directory, logs="ssh") as s:
        sid, cfg, plan, run, sh = s.sid, s.cfg, s.plan, s.run, s.sh
        key = s.secrets["RELAY_SSH_KEY"]
        # what would betray the key: its stored form, and a line from the middle of its PEM body
        pem = key if key.startswith("-----BEGIN") else base64.b64decode(key).decode()
        needles = [key[:40], pem.strip().splitlines()[2][:40]]
        host = next(h for h in cfg.extensions["ssh"]["hosts"] if h["name"] == name)["to"].rpartition(":")[0]

        print("== the harness side")
        r = run("bash", "-c", "test -p /run/glove/ssh/door && echo DOOR; env; cat /proc/1/environ | tr '\\0' '\\n'; "
                "find /run /tmp /home/agent -type f -size -64k -exec cat {} + 2>/dev/null", entry="/usr/bin/env")
        check("the channel's door is in the harness", "DOOR" in r.stdout, r.stderr[-300:])
        check("the key is not in the harness (env, pid 1, files under /run /tmp /home)",
              not any(n in r.stdout for n in needles), "key material found")

        print("== works through the sidecar")
        out = sh(f"ssh {name} 'echo relay-ok-$(id -un); uname -s'; echo rc=$?")
        check(f"ssh {name} <command> (as {user})", f"relay-ok-{user}" in out and "rc=0" in out, out)
        out = sh(f"ssh -q -o ConnectTimeout=5 -- {user}@{name} echo with-args; echo rc=$?")
        check("ssh -q -o ConnectTimeout=5 -- user@host <command>", "with-args" in out and "rc=0" in out, out)
        out = sh(f"ssh {name} 'exit 3'; echo rc=$?")
        check("the remote exit code comes back", "rc=3" in out, out)

        print("== refused by the policy")
        for cmd, want in [
            (f"ssh -L 8080:localhost:80 {name} true", "not relayed"),
            (f"ssh -R 9000:localhost:22 {name} true", "not relayed"),
            (f"ssh -D 1080 {name} true", "not relayed"),
            (f"ssh -J other {name} true", "not relayed"),
            (f"ssh -W localhost:22 {name}", "not relayed"),
            (f"ssh -o ProxyCommand=sh {name} true", "not relayed"),
            (f"ssh -oLocalCommand=id {name} true", "not relayed"),
            (f"ssh -i /work/k {name} true", "not relayed"),
            (f"ssh -F /work/cfg {name} true", "not relayed"),
            (f"ssh -A {name} true", "not relayed"),
            (f"ssh -t {name} true", "not relayed"),
            ("ssh other-host true", "not a host of this session"),
            (f"ssh root@{name} true", f"reached as {user}"),
            (f"ssh {name}", "runs a command"),
            ("/opt/glove/bin/glove-relay ssh bash -c id", "runs only"),
        ]:
            out = sh(f"{cmd}; echo rc=$?")
            check(f"refused: {cmd}", want in out and "rc=126" in out, out[-300:])

        print("== no other route")
        out = sh(f"timeout 5 bash -c 'echo > /dev/tcp/{host}/22' 2>/dev/null; echo net=$?")
        check("a shell command cannot reach the host itself", re.search(r"net=[1-9]", out) is not None, out)
        code = ("import socket,sys\n"
                "for t in sys.argv[1:]:\n"
                "  h,p=t.rsplit(':',1)\n"
                "  try:\n    socket.create_connection((h,int(p)),3).close(); print(t,'open')\n"
                "  except OSError as e: print(t,'closed')\n")
        r = subprocess.run([s.rt, "exec", f"glove-{sid}-ssh", "python3", "-c", code, f"{host}:22", "1.1.1.1:443",
                            f"glove-{sid}-ssh-{name}:22"], capture_output=True, text=True, timeout=60)
        check("the sidecar reaches the host only through its forwarder",
              f"{host}:22 closed" in r.stdout and "1.1.1.1:443 closed" in r.stdout
              and f"glove-{sid}-ssh-{name}:22 open" in r.stdout, r.stdout + r.stderr[-200:])

        if plan.composition.by_name("observe"):
            print("== observe")
            time.sleep(2)
            fl = [r for r in s.flows() if r.get("service") == f"ssh-{name}"]
            check(f"flows: ssh-{name}, client ssh, tool ssh, scope lan",
                  bool(fl) and all((r.get("client"), r.get("tool"), r.get("scope")) == ("ssh", "ssh", "lan")
                                   for r in fl), json.dumps([{k: r.get(k) for k in ("client", "tool", "scope")}
                                                             for r in fl[:3]]))
            print(f"    ({len(fl)} flows to the host)")
            facts = json.loads((s.net / "session.json").read_text())
            ssh = {e["service"]: (e["scope"], e["next"]) for e in facts["services"] if e["service"].startswith("ssh-")}
            check("session.json: every ssh-* gate is scope lan, next []",
                  bool(ssh) and all(v == ("lan", []) for v in ssh.values()), json.dumps(ssh))
            if any(h["name"] == "public" for h in cfg.extensions["ssh"]["hosts"]):
                with public_lan_name(s):
                    out = sh("ssh public true; echo rc=$?")
                print("    the refused ssh's output: " + out.strip()[-300:].replace("\n", " | "))
                time.sleep(2)
                fl = [r for r in s.flows(("close",)) if r.get("service") == "ssh-public"]
                want = {"verdict": "block", "rule": "builtin:lan-only", "close_reason": "blocked", "scope": "lan",
                        "bytes": {"up": 0, "down": 0}}
                got = [{k: r.get(k) for k in want} | {"ip": r["dest"].get("ip"),
                                                      "resolution": r["dest"].get("resolution")} for r in fl]
                check("public.lan, resolving public, is refused: builtin:lan-only, zero bytes, dest.ip null",
                      "rc=0" not in out and bool(got) and all(
                          {k: g[k] for k in want} == want and g["ip"] is None for g in got), json.dumps(got))
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
