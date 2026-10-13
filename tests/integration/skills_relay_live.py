"""Live `skills` relay, driven by test_skills_relay.sh.

    uv run python tests/integration/skills_relay_live.py <session-dir>

The session's plugin `demo` relays scripts/api.py (hosts: httpbin.org; allow:
whoami, other, home, fetch; `-o` an output flag) with API_TOKEN from a
throwaway Keychain item, first `expired-1`, and local/mint.sh as its refresh
hook (it prints `good-2`). Every harness command is the agent's own tool call,
under the session's enforcer. It checks:
  1. the baked script is a shim, and no shell command sees the token;
  2. an expired token: the script says so, `glove skills status` fails;
  3. `glove skills refresh demo` stores the hook's value and recreates only the
     relay sidecar; a harness container started before it reaches the new one;
  4. the script authenticates with the new token (the echo's hash), its plain
     env and its rendered home file (0600) included;
  5. the relay refuses a subcommand it does not allow and an output outside
     /work; the script's fence refuses a host the relay does not name; an
     output inside /work lands there;
  6. the token is in no file of the session.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys

from live_common import check, glove, live_session, summary

API = "/opt/glove/plugins/demo/scripts/api.py"


def tag(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def main(directory: str) -> int:
    with live_session(directory, logs="skill-demo") as s:
        def sh(cmd: str) -> str:
            out = s.sh(cmd)
            print(f"    $ {cmd[:100]}\n      {out[-300:]}", flush=True)
            return out

        def skills(*args: str) -> subprocess.CompletedProcess:
            r = glove("skills", *args, "--dir", str(s.sd.root))
            print(f"    $ glove skills {' '.join(args)} → {r.returncode}\n      {(r.stdout + r.stderr)[-300:]}")
            return r

        print("== the harness side")
        out = sh(f"head -3 {API}; echo n=$(env | grep -c API_TOKEN)")
        check("the baked script is a shim to the relay", "glove-relay skill-demo scripts/api.py" in out, out[-200:])
        check("no shell command sees the token", "n=0" in out, out[-80:])

        print("== an expired token")
        out = sh(f"{API} whoami; echo rc=$?")
        check("the script reports it (exit 1)", "401 invalid_auth" in out and "rc=1" in out, out[-200:])
        r = skills("status")
        check("`glove skills status` fails its check", r.returncode == 1 and "failed (exit 1)" in r.stdout,
              r.stdout[-200:])

        print("== refresh, with the harness running")
        before = subprocess.run([*s.base, "run", "-d", "--rm", "--entrypoint", "sleep", s.plan.harness_service,
                                 "600"], env=s.env, capture_output=True, text=True).stdout.strip().splitlines()[-1]
        r = skills("refresh", "demo")
        check("refresh runs the hook, stores the value and reloads the relay",
              r.returncode == 0 and "stored" in r.stdout and "reloaded" in r.stdout, (r.stdout + r.stderr)[-300:])
        r = subprocess.run([s.rt, "exec", before, API, "whoami"], capture_output=True, text=True)
        check("a harness container from before the reload reaches the new relay",
              f"token={tag('good-2')}" in r.stdout, (r.stdout + r.stderr)[-200:])
        subprocess.run([s.rt, "rm", "-f", before], capture_output=True)
        r = skills("status")
        check("`glove skills status` passes now", r.returncode == 0 and "ok" in r.stdout, r.stdout[-200:])

        print("== the relayed script")
        out = sh(f"{API} whoami")
        check("it authenticates with the new token, its plain env set",
              f"WHOAMI authenticated=True token={tag('good-2')} mode=test" in out, out[-200:])
        out = sh(f"{API} home")
        check("its home file is rendered from the template, 0600", f"HOME ws={tag('good-2')} mode=0o600" in out,
              out[-200:])
        out = sh(f"{API} save 2>&1; echo rc=$?")
        check("a subcommand it does not allow is refused",
              "refused: scripts/api.py save is not allowed here" in out and "rc=126" in out, out[-200:])
        out = sh(f"{API} fetch -o /etc/x 2>&1; echo rc=$?")
        check("an output outside /work is refused", "a destination must be under /work" in out, out[-200:])
        out = sh(f"cd /work && {API} fetch -o out.txt && cat /work/out.txt")
        check("an output inside /work lands there", f"FETCHED {tag('good-2')}" in out, out[-200:])
        out = sh(f"{API} other")
        check("its fence refuses a host the relay does not name", "OTHER blocked" in out, out[-200:])

        print("== no secret in a file")
        hits = subprocess.run(["grep", "-rl", "good-2", str(s.sd.root / ".glove")], capture_output=True, text=True)
        check("the token is in no file of the session's state", not hits.stdout.strip(), hits.stdout[-200:])
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
