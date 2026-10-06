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
  5. with observe: the forwarder's flows are `client: ssh`, `scope: lan`.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
import time

from live_common import check, live_session, summary


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
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
