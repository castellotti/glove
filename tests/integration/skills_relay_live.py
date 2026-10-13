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
With CORPORATE=1 "the API" is a stand-in behind `corporate`, over TLS from
the session's corporate_ca (the GHES stub's bearer echo, started once the
session is up), and before that `glove check` finds the relay's host admitted,
and warns on a copy of the session whose egress does not admit it; the
stand-in must have seen only the right token.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml
from live_common import check, glove, live_session, stand_in, summary

API = "/opt/glove/plugins/demo/scripts/api.py"
STUB = Path(__file__).resolve().parent / "stubs" / "ghes_stub.py"
CORPORATE = bool(os.environ.get("CORPORATE"))


def tag(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def check_egress(directory: str) -> None:
    print("== glove check: the relay's host and the corporate egress")
    r = glove("check", "--no-container", directory)
    out = " ".join((r.stdout + r.stderr).split())  # a long line wraps in the table
    check("`glove check`: corporate admits the relay's host", "skills egress" in out and
          "corporate admits api.corp.test" in out and "does not admit" not in out, out[-600:])
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "s"
        shutil.copytree(directory, copy, ignore=shutil.ignore_patterns(".glove"))
        spec = copy / "glove-session.yml"
        spec.write_text(spec.read_text().replace("allow_domains: [api.corp.test]", "allow_domains: [x.corp.test]"))
        r = glove("check", "--no-container", str(copy))
        out = " ".join((r.stdout + r.stderr).split())
        check("`glove check` warns when corporate does not admit it", "add 'api.corp.test' to" in out, out[-600:])


@contextlib.contextmanager
def api_stand_in(s):
    """The stand-in API behind `corporate` (CORPORATE=1), else nothing."""
    if not CORPORATE:
        yield None
        return
    image = yaml.safe_load(s.sd.compose.read_text())["services"][f"{s.prefix}-skill-demo"]["image"]
    fx = os.environ["RELAY_FIXTURE"]
    with stand_in(s, image, ["python3", "/stub.py", "443", "/fx/stub.pem", "/fx/stub.key", "/nonexistent"],
                  subnet=os.environ["RELAY_SUBNET"], aliases=["api.corp.test"],
                  mounts=[(str(STUB), "/stub.py"), (fx, "/fx")],
                  extra=["-e", "GHES_TOKENS=" + json.dumps({"api.corp.test": "good-2"})]) as stub:
        yield stub


def main(directory: str) -> int:
    if CORPORATE:
        check_egress(directory)
    with live_session(directory, logs="skill-demo") as s, api_stand_in(s) as stub:
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
    if stub is not None:
        print("== what the stand-in saw")
        check("the stand-in API got the right token over the corporate egress and CA",
              "GET api.corp.test /bearer auth=ok" in stub.log, stub.log[-300:])
        check("it never got a wrong one", "auth=wrong" not in stub.log, stub.log[-300:])
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
