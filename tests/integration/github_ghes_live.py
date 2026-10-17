"""Live `github` with GitHub Enterprise hosts, driven by test_github_ghes.sh.

    uv run python tests/integration/github_ghes_live.py <session-dir>

The session serves ghes.test (GHES_TOKEN_A) and ghes2.test (GHES_TOKEN_B), no
github.com, git verbs fetch/clone/ls-remote, behind the `corporate` egress
admitting just those names, with the stand-in's CA as corporate_ca. Once the
session is up this starts the stand-in (stubs/ghes_stub.py, in the relay
image, $GHES_FIXTURE's certificate and repository) on a network of its own and
joins the corporate proxy to it. Every harness command is the agent's own tool
call, under the session's enforcer. It checks:
  1. `glove check` finds both hosts and their subdomains admitted by the egress;
  2. no shell command sees a token;
  3. gh reaches the default host (the first) and the other by --hostname,
     each with its own token, over TLS from the session's CA; github.com is
     refused;
  4. git ls-remote, clone and pull work against each host with its own token
     (the stand-in refuses a wrong one); push is refused (not in `git`), and
     so is a github.com remote;
  5. the stand-in saw only right tokens;
  6. no token is in a file of the session's state.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import functools
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml
from live_common import check, glove, live_session, stand_in, summary

STUB = Path(__file__).resolve().parent / "stubs" / "ghes_stub.py"


def main(directory: str) -> int:
    tokens = {"ghes.test": os.environ["GHES_TOKEN_A"], "ghes2.test": os.environ["GHES_TOKEN_B"]}
    fixture = os.environ["GHES_FIXTURE"]
    r = glove("check", "--no-container", directory)
    out = r.stdout + r.stderr
    check("`glove check`: the corporate egress admits both hosts and their subdomains",
          "github egress" in out and "corporate admits" in out and "does not admit" not in out, out[-600:])
    with live_session(directory, logs="gh") as s:
        sh = functools.partial(s.sh, echo=True)

        image = yaml.safe_load(s.sd.compose.read_text())["services"][f"{s.prefix}-gh"]["image"]
        with stand_in(s, image, ["python3", "/stub.py", "443", "/fx/stub.pem", "/fx/stub.key", "/fx/repo.git"],
                      subnet=os.environ["GHES_SUBNET"], aliases=["ghes.test", "ghes2.test"],
                      mounts=[(str(STUB), "/stub.py"), (fixture, "/fx")],
                      extra=["-e", "GHES_TOKENS=" + json.dumps(tokens),
                             "-e", "GIT_CONFIG_PARAMETERS='safe.directory=*'"]) as stub:
            _checks(s, sh, tokens)
        stub_log = stub.log
        print("== what the stand-in saw")
        for line in ("GET ghes.test /api/v3/user auth=ok", "GET ghes2.test /api/v3/user auth=ok",
                     "GET ghes2.test /o/r.git/info/refs auth=ok", "POST ghes.test /o/r.git/git-upload-pack auth=ok"):
            check(f"the stand-in logged `{line}`", line in stub_log)
        check("it never got a wrong token", "auth=wrong" not in stub_log)
        print("== no token in a file")
        hits = subprocess.run(["grep", "-rlE", "|".join(tokens.values()), str(s.sd.root)], capture_output=True,
                              text=True)
        check("no token in any file of the session", not hits.stdout.strip(), hits.stdout[-200:])
    return summary()


def _checks(s, sh, tokens: dict[str, str]) -> None:
    print("== the harness side")
    out = sh("echo n=$(env | grep -cE 'ghes-tok-[a-z]-[0-9]')")  # a pattern: the transcript never holds a token
    check("no shell command sees a token", "n=0" in out, out[-80:])

    print("== gh")
    out = sh("gh api user 2>&1")
    check("gh reaches the default host (the first) with its token, over the session's CA",
          '"login":"user-ghes.test"' in out.replace(" ", "").replace("\\\"", "\""), out[-200:])
    out = sh("gh api user --hostname ghes2.test 2>&1")
    check("gh reaches the other host by --hostname with its own token",
          '"login":"user-ghes2.test"' in out.replace(" ", "").replace("\\\"", "\""), out[-200:])
    out = sh("gh api user --hostname github.com 2>&1; echo rc=$?")
    check("github.com is not served", "serves ghes.test, ghes2.test only" in out and "rc=0" not in out, out[-200:])

    print("== git")
    out = sh("git ls-remote https://ghes2.test/o/r.git 2>&1")
    check("git ls-remote reaches the second host with its token", "refs/heads/main" in out, out[-200:])
    out = sh("cd /work && git clone https://ghes.test/o/r.git r 2>&1; cat /work/r/README")
    check("git clone from the first host lands in /work", "hello from ghes" in out, out[-200:])
    out = sh("cd /work/r && git pull 2>&1")
    check("git pull (a relayed fetch, then a local merge)", "Already up to date" in out, out[-200:])
    out = sh("cd /work/r && git push origin HEAD:refs/heads/x 2>&1; echo rc=$?")
    check("git push is refused (not in github.git)",
          "only git fetch, clone, ls-remote (and pull) are relayed in this session" in out, out[-200:])
    out = sh("git clone https://github.com/cli/cli /work/x 2>&1")
    check("a github.com remote is refused", "the host one of ghes.test, ghes2.test" in out, out[-200:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
