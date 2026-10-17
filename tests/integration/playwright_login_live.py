"""Live `glove playwright login` + `storage_state`, driven by test_playwright_login.sh.

    uv run python tests/integration/playwright_login_live.py <session-dir>

The session: the `corporate` egress admitting the stand-in's names (and its
subnet), `playwright` headless with `storage_state: keychain:$PWL_STATE` (an
empty state at first) and a `login` that keeps corp.test's cookies and
captures chat.test's cookie `d` ($PWL_D) and its localStorage token
($PWL_XOXC). Once the session is up this starts the stand-in sign-on site
(stubs/login_site.js, in the session's playwright image) on a network of its
own, joins the corporate proxy to it, and publishes it on the host's loopback
for the login browser. Every browser call is the agent's own tool call. It checks:
  1. with the empty state, the agent's browser is not signed in;
  2. `glove playwright login` (a real host Chrome, headless, CDP over a pipe)
     signs in and stores: the state with corp.test's cookies only (the
     HttpOnly SSO cookie for the parent domain included; the tracker's and
     chat.test's left out), and the two captures; nothing of them printed;
     the login profile is gone;
  3. `glove playwright reload` recreates the sidecar; the agent's browser is
     then signed in, through the gate;
  4. a javascript: URL runs none of the agent's script in the signed-in page
     (the sidecar Chromium's policy); the state file is out of the agent's
     reach (file://), on the sidecar's
     tmpfs 0600, and in no process's environment but the container init's;
  5. `glove playwright status` reports the expiry, no value;
  6. no value in a file of the session, or in what the model saw.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml
from live_common import check, container_log, glove, live_session, stand_in, summary, tool_result, wait_for

from glove.config import resolve_secret

STUB = Path(__file__).resolve().parent / "stubs" / "login_site.js"
WHOAMI = "http://wiki.corp.test/whoami"
VALUES = ("sso-tok-", "pref-tok-", "xoxd-1-test", "xoxc-1-test", "tracker-1")


def main(directory: str) -> int:
    services = {k: os.environ[k] for k in ("PWL_STATE", "PWL_D", "PWL_XOXC")}
    seen = []  # everything the model saw
    with live_session(directory, logs="pw") as s:
        def browse(url: str) -> str:
            raw = s.call(f"{s.tools['browser']}browser_navigate", {"url": url})
            if "TOOL RESULT" not in raw:
                print("    (no tool result; the run said:)\n" + "".join(f"      {ln}\n" for ln in raw.splitlines()[-40:]))
            out = tool_result(raw, 1500)
            seen.append(out)
            print(f"    navigate {url}\n      {out[:400]!r}", flush=True)
            return out

        image = yaml.safe_load(s.sd.compose.read_text())["services"][f"{s.prefix}-pw"]["image"]
        with stand_in(s, image, ["node", "/stub.js", "80"], subnet=os.environ["PWL_SUBNET"],
                      aliases=["idp.corp.test", "wiki.corp.test", "app.chat.test", "tracker.test"],
                      mounts=[(str(STUB), "/stub.js")],
                      extra=["-p", "127.0.0.1::80", "--sysctl", "net.ipv4.ip_unprivileged_port_start=0"]) as stub:
            port = subprocess.run([s.rt, "port", stub.name, "80"], capture_output=True, text=True,
                                  check=True).stdout.split()[0].rsplit(":", 1)[1]
            _checks(s, browse, seen, stub.name, port, services)
        stub_log = stub.log
        check("the agent's signed-in visit went through the gate with corp.test's cookies only",
              "GET wiki.corp.test /whoami cookies=pref,sso\n" in stub_log and "whoami sso=login-1" in stub_log)
        print("== no value in a file, or in what the model saw")
        hits = subprocess.run(["grep", "-rlE", "|".join(VALUES), str(s.sd.root)], capture_output=True, text=True)
        check("no value in any file of the session", not hits.stdout.strip(), hits.stdout[-200:])
        check("no value in what the model saw", not any(v in out for out in seen for v in VALUES))
    return summary()


def _checks(s, browse, seen: list[str], stub: str, port: str, services: dict[str, str]) -> None:
    pw = f"{s.prefix}-pw"
    print("== before the login: the stored state is empty")
    check("the agent's browser is not signed in", "not signed in" in browse(WHOAMI))

    print("== glove playwright login (a headless host Chrome, CDP over a pipe)")
    login = subprocess.Popen(
        [sys.executable, "-m", "glove.cli", "playwright", "login", "--dir", str(s.sd.root), "--no-reload",
         "--headless", f"--chrome-arg=--host-resolver-rules=MAP *.test 127.0.0.1:{port}",
         "--chrome-arg=--no-proxy-server", "--chrome-arg=--disable-features=HttpsUpgrades"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    signed_in = wait_for(lambda: "done login=1" in container_log(s.rt, stub), timeout=60)
    check("the login browser reached the sign-on site and back", bool(signed_in))
    out, _ = login.communicate("\n", timeout=60)
    print("".join(f"    | {ln}\n" for ln in out.splitlines()))
    flat = " ".join(out.split())
    check("login stored the state and both captures", login.returncode == 0 and all(
        f"✓ {svc}:" in flat for svc in services.values()), flat[-400:])
    check("the state holds corp.test's cookies only (the tracker's and chat.test's left out)",
          "2 cookie(s) for corp.test" in flat and "tracker.test (1)" in flat and "chat.test (1)" in flat, flat[-300:])
    check("login printed no value", not any(v in out for v in VALUES))
    check("the login profile is gone", not (s.sd.ext / "playwright" / "login-profile").exists())
    state = json.loads(resolve_secret(f"keychain:{services['PWL_STATE']}"))
    sso = next((c for c in state["cookies"] if c.get("name") == "sso"), {})
    check("the stored SSO cookie: HttpOnly, for the parent domain",
          sso.get("name") == "sso" and sso.get("value") == "sso-tok-1" and sso.get("domain") == ".corp.test"
          and sso.get("httpOnly") is True and sso.get("expires", 0) > time.time())
    check("the captured cookie value", resolve_secret(f"keychain:{services['PWL_D']}") == "xoxd-1-test")
    check("the captured localStorage token (narrowed by match)",
          resolve_secret(f"keychain:{services['PWL_XOXC']}") == "xoxc-1-test")

    print("== glove playwright reload")
    check("without a reload the running browser keeps its session (none)", "not signed in" in browse(WHOAMI))
    r = glove("playwright", "reload", "--dir", str(s.sd.root), timeout=180)
    check("reload recreated the sidecar", r.returncode == 0 and "recreated" in r.stdout, (r.stdout + r.stderr)[-300:])
    check("the agent's browser is signed in now, through the gate", "signed in as user-1" in browse(WHOAMI))

    b = s.tools["browser"]  # one turn: the probe runs in the signed-in page
    res = s.seq((f"{b}browser_navigate", {"url": WHOAMI}),
                (f"{b}browser_navigate",
                 {"url": "javascript:void(document.title='PROBE'+document.cookie+JSON.stringify(localStorage))"}),
                (f"{b}browser_tabs", {"action": "list"}))
    seen.extend(res)
    print("".join(f"    | {r[:240]}\n" for r in res))
    check("a javascript: URL runs no script of the agent's in the signed-in page (Chromium policy)",
          "signed in as user-1" in res[2] and "PROBE" not in res[2] and not any("pref-tok" in r for r in res),
          res[2][:300])

    print("== the state in the sidecar")
    out = browse("file:///tmp/glove-state/storage-state.json")
    check("file:// to the state file is refused", "sso-tok" not in out and "cookies" not in out, out[-200:])
    # (`exec` gets the container's env: the probe runs without it, under env -i)
    r = subprocess.run([s.rt, "exec", pw, "env", "-i", "PATH=/usr/bin:/bin", "sh", "-c", "stat -c %a /tmp/glove-state/storage-state.json; "
                        "for p in /proc/[0-9]*; do tr '\\0' '\\n' < $p/environ 2>/dev/null | "
                        "grep -q '^PW_STORAGE_STATE=' && echo \"env:$(cat $p/comm)\"; done"],
                       capture_output=True, text=True)
    holders = {ln.removeprefix("env:") for ln in r.stdout.split() if ln.startswith("env:")}
    check("the state file is 0600 on the tmpfs", r.stdout.split()[:1] == ["600"], r.stdout[-200:])
    check("only the container's init holds PW_STORAGE_STATE (not the MCP, not the browser)",
          holders <= {"docker-init", "podman-init", "catatonit", "tini"}, str(sorted(holders)))

    print("== glove playwright status")
    r = glove("playwright", "status", "--dir", str(s.sd.root))
    flat = " ".join(r.stdout.split())
    check("status reports the state's expiry, no value",
          "2 cookie(s)" in flat and "expires at" in flat and not any(v in r.stdout for v in VALUES), flat[-300:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
