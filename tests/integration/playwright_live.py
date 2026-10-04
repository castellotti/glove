"""Live playwright (v3 M7) for a session directory, through glove's own launch path.

    STUB_LOG=<stub log> uv run python tests/integration/playwright_live.py <session-dir>

The session must have an egress provider, `playwright` (headless or novnc),
optionally observe + filter, and its llm pointed at the tool-driving stub
(tests/integration/stubs/llm_stub.py). It checks, against real containers:
  1. the browser sidecar is hardened (no ports, cap-less, read-only, the
     chromium-userns seccomp profile when the sandbox is on) and only on
     browser-net; Chromium's sandbox really is on;
  2. inside it: no DNS, no direct route, no default route, no harness endpoint;
     from the harness network the sidecar is unreachable, the forwarder is not;
  3. the harness (Pi or Vibe, stub-driven) browses example.com through it, and
     is offered the allowlisted tools only (never browser_run_code_unsafe);
     a shell command cannot reach the MCP (ring 1);
  4. with observe: the browser's destinations are flows `client: playwright,
     tool: browser`; with filter: a blocked site and the SSRF guard's refusal;
  5. novnc: VNC/websockify on the sidecar's loopback only; `glove playwright
     view` serves noVNC on 127.0.0.1 and refuses foreign Host/Origin; input is
     refused server-side unless allow_control and the full password; the
     clipboard is off;
  then tears down. Prints PASS/FAIL per check; exit 0 only if all pass.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from glove import registry
from glove.cli import _materialize_plan, _open, _resolve_extensions
from glove.extensions import image_tag
from glove.harnessconfig import render_home
from glove.plan import secret_env
from glove.session import _compose_base, ensure_images, start_sidecars

HERE = Path(__file__).parent
results: list[tuple[str, bool]] = []
CLICK_PAGE = ("data:text/html,<title>WAITING</title><body style='margin:0;height:100vh;background:%23eee' "
              "onmousedown=\"document.title='CLICKED'\"></body>")


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'} {name}" + (f"  ({detail})" if detail else ""), flush=True)


def inspect(rt: str, name: str) -> dict:
    out = subprocess.run([rt, "inspect", name], capture_output=True, text=True).stdout
    return (json.loads(out) or [{}])[0] if out.strip() else {}


def flows(net: Path) -> list[dict]:
    recs = []
    for f in sorted(net.glob("flows*.ndjson")):
        for line in f.read_text().splitlines():
            try:
                recs.append(json.loads(line))
            except ValueError:
                pass
    return [r for r in recs if r.get("type") == "flow"]


def wait_for(fn, timeout=30.0, step=1.0):
    end = time.time() + timeout
    while True:
        v = fn()
        if v or time.time() > end:
            return v
        time.sleep(step)


def main(directory: str) -> int:
    sd, _, sid, cfg = _open(Path(directory))
    rt = cfg.provider
    s = f"glove-{sid}"
    net = Path(os.path.realpath(registry.observe_dir(sid))) / "net"
    base = None
    env = dict(os.environ)
    try:
        plan, _, _ = _materialize_plan(sd, sid, cfg)
        env = {**os.environ, **secret_env(plan)}
        base = _compose_base(rt, plan.project, sd.compose)
        t = time.time()
        ensure_images(cfg, plan, rt)
        print(f"  (images ready in {time.time() - t:.0f}s)", flush=True)
        start_sidecars(plan, sd.compose, provider=rt, env=env)
        comp = plan.composition
        pws = comp.by_name("playwright").settings
        mode, observed = pws["mode"], comp.by_name("observe") is not None
        check(f"sidecars up + verify passed (mode {mode}, egress {comp.slots['egress'].name})", True)
        _resolve_extensions(plan, rt, secret_env(plan))
        render_home(cfg, plan.profile, sd.home, plan.model, mount_plan=plan.mount_plan, comp=comp)
        pw_image = image_tag(comp.by_name("playwright"), "pw")

        def exec_pw(script: str) -> subprocess.CompletedProcess:
            return subprocess.run([rt, "exec", f"{s}-pw", "bash", "-c", script], capture_output=True, text=True)

        def mcp(steps: list, network: str = f"{s}-net", host: str = f"{s}-browser") -> str:
            r = subprocess.run([rt, "run", "--rm", "--network", network, "--cap-drop", "ALL", "--read-only",
                                "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{HERE}:/t:ro",
                                "--entrypoint", "python3", pw_image, "/t/mcp_client.py",
                                f"http://{host}:8931/mcp", f"{host}:8931", json.dumps(steps)],
                               capture_output=True, text=True, timeout=300)
            return (r.stdout + r.stderr).strip()

        def agent(tool: str, args: dict) -> str:
            cmd = [*plan.harness_command, "-p", f"CALL {tool} {json.dumps(args)}"]
            r = subprocess.run([*base, "run", "--rm", "-T", plan.harness_service, *cmd], env=env,
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
            return (r.stdout.strip() or r.stderr.strip())[-600:]

        print("== the browser sidecar")
        pw = inspect(rt, f"{s}-pw")
        hc = pw.get("HostConfig", {})
        check("no published ports", not (hc.get("PortBindings") or {}) and not (pw.get("NetworkSettings", {})
                                                                               .get("Ports") or {}))
        caps = exec_pw("grep -E '^Cap(Eff|Prm|Bnd):' /proc/1/status | awk '{print $2}' | sort -u").stdout.split()
        check("no capabilities (effective, permitted, bounding), read-only rootfs, no-new-privileges",
              caps == ["0000000000000000"] and hc.get("ReadonlyRootfs") is True
              and any("no-new-privileges" in o for o in hc.get("SecurityOpt") or []), " ".join(caps))
        nets = sorted(pw.get("NetworkSettings", {}).get("Networks", {}))
        check("only on browser-net", nets == [f"{s}-browser-net"], ", ".join(nets))
        if pws["chromium_sandbox"] == "on":
            r = exec_pw("glove-pw-start --probe-sandbox")
            check("Chromium's sandbox is on (chromium-userns seccomp)", "sandbox ok" in r.stdout,
                  (r.stdout + r.stderr).strip()[-120:])
        r = exec_pw("getent hosts example.com; echo rc=$?")
        check("no DNS in the sidecar", "rc=0" not in r.stdout, r.stdout.strip()[-60:])
        r = exec_pw("timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>&1; echo rc=$?")
        check("no direct route (1.1.1.1:443)", "rc=0" not in r.stdout, r.stdout.strip()[-80:])
        r = exec_pw("awk 'NR>1 && $2==\"00000000\"' /proc/net/route | wc -l")
        check("no default route", r.stdout.strip() == "0", f"{r.stdout.strip()} default route(s)")
        r = exec_pw(f"timeout 5 bash -c 'exec 3<>/dev/tcp/{s}-llm/8080' 2>&1; echo rc=$?")
        check("the harness's llm endpoint is unreachable from the browser", "rc=0" not in r.stdout,
              r.stdout.strip()[-80:])

        print("== from the harness network")
        out = mcp([["tools/list", {}]], host=f"{s}-pw")
        check("the sidecar itself is unreachable", "server:" not in out, out[-100:])
        out = mcp([["tools/list", {}]])
        check("the `browser` forwarder serves the MCP", "server: Playwright" in out, out.splitlines()[0][:60])
        out = mcp([["tools/list", {}]]).replace("tools:", "")
        check("(the MCP itself still lists browser_run_code_unsafe: clients filter it)",
              "browser_run_code_unsafe" in out)

        print(f"== the agent ({cfg.harness}) browses")
        log = Path(os.environ["STUB_LOG"]) if os.environ.get("STUB_LOG") else None
        mark = len(log.read_text()) if log else 0
        prefix = {"vibe": "playwright_", "claude-code": "mcp__playwright__"}.get(cfg.harness, "")
        ans = agent(f"{prefix}browser_navigate", {"url": "https://example.com"})
        check("browser_navigate https://example.com", "Page URL: https://example.com" in ans,
              ans[-160:].replace("\n", " "))
        offered = set()
        if log:
            for line in log.read_text()[mark:].splitlines():
                m = re.match(r"stub: chat .* tools=(.*)$", line)
                if m:
                    offered |= set(m.group(1).split(","))
                m = re.match(r"stub: tools=(\[.*\])$", line)  # the anthropic stub
                if m:
                    offered |= set(json.loads(m.group(1).replace("'", '"')))
        browser_tools = sorted(t for t in offered if "browser_" in t)
        check("offered the allowlisted browser tools only",
              f"{prefix}browser_navigate" in offered and len(browser_tools) == len(pws["tools"])
              and not any("run_code" in t or "evaluate" in t for t in offered), ", ".join(browser_tools)[:160])
        if cfg.harness == "claude-code":
            # a tool outside the allowlist is denied by a managed rule: never offered, so no prompt
            ans = agent(f"{prefix}browser_evaluate", {"function": "() => document.title"})
            check("a denied tool (browser_evaluate) is not even offered", "Example Domain" not in ans
                  and "no such tool available" in ans.lower(),
                  ans[-160:].replace("\n", " "))
        if cfg.harness in ("pi", "claude-code"):
            bash = "Bash" if cfg.harness == "claude-code" else "bash"
            ans = agent(bash, {"command": f"timeout 5 bash -c 'exec 3<>/dev/tcp/{s}-browser/8931' 2>&1; "
                                            "echo rc=$?"})
            check("a shell command cannot reach the MCP (ring 1)", "rc=0" not in ans, ans[-100:])

        if observed:
            print("== observe")
            recs = wait_for(lambda: [r for r in flows(net) if r.get("service") == "browser-egress"
                                     and (r.get("dest") or {}).get("host") == "example.com"], 20)
            f = recs[-1] if recs else {}
            check("flow: browser-egress → example.com, client playwright, tool browser",
                  (f.get("client"), f.get("tool")) == ("playwright", "browser"),
                  json.dumps({k: f.get(k) for k in ("client", "tool", "route", "verdict")}))
            hop = [r for r in flows(net) if r.get("service") == "browser"]
            check("flow: the harness → MCP hop, client harness", bool(hop) and hop[-1].get("client") == "harness"
                  and hop[-1].get("tool") == "browser", f"{len(hop)} flows")
            ans = agent(f"{prefix}browser_navigate", {"url": "http://169.254.169.254/latest/meta-data/"})
            meta = wait_for(lambda: [r for r in flows(net) if r.get("service") == "browser-egress"
                                     and (r.get("dest") or {}).get("host") == "169.254.169.254"], 15)
            m = meta[-1] if meta else {}
            check("SSRF guard: cloud metadata refused at the gate", bool(meta) and m.get("verdict") != "allow"
                  or bool(meta) and m.get("close_reason") not in (None, "eof", "done"),
                  json.dumps({k: m.get(k) for k in ("verdict", "close_reason", "rule")}))
            hosts = sorted({(r.get("dest") or {}).get("host") for r in flows(net)
                            if r.get("service") == "browser-egress"} - {None})
            print(f"    (browser destinations seen: {', '.join(hosts)})")
        if comp.by_name("filter") is not None:
            print("== filter")
            out = subprocess.run([sys.executable, "-m", "glove.cli", "filter", "block", "example.org"], cwd=sd.root,
                                 capture_output=True, text=True)
            check("`glove filter block example.org`", out.returncode == 0, (out.stdout + out.stderr).strip()[-80:])
            time.sleep(4)
            ans = agent(f"{prefix}browser_navigate", {"url": "https://example.org"})
            blocked = wait_for(lambda: [r for r in flows(net) if r.get("verdict") == "block"
                                        and (r.get("dest") or {}).get("host") == "example.org"], 15)
            check("the browser's request is blocked at the gate", bool(blocked) and "Example Domain" not in ans,
                  ans[-120:].replace("\n", " "))

        if mode == "novnc":
            print("== novnc")
            r = exec_pw("awk 'NR>1 && $4==\"0A\" {print $2}' /proc/net/tcp")
            listen = set(r.stdout.split())
            check("VNC (5900) and websockify (6080) on 127.0.0.1 only; the MCP on 0.0.0.0",
                  {"0100007F:170C", "0100007F:17C0", "00000000:22E3"} <= listen
                  and not any(a.endswith((":170C", ":17C0")) and not a.startswith("0100007F") for a in listen),
                  " ".join(sorted(listen)))
            r = exec_pw("DISPLAY=:1 vncconfig -get AcceptCutText; DISPLAY=:1 vncconfig -get SendCutText; "
                        "DISPLAY=:1 vncconfig -get AcceptPointerEvents")
            want_in = "1" if pws["allow_control"] else "0"
            check("server-side: clipboard off, pointer input " + ("on" if want_in == "1" else "off"),
                  r.stdout.split() == ["0", "0", want_in], " ".join(r.stdout.split()))
            view = subprocess.Popen([sys.executable, "-m", "glove.cli", "playwright", "view", "--no-open"],
                                    cwd=sd.root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                url = ""
                for line in view.stdout:  # the URL carries the password: never printed here
                    if line.startswith("open: "):
                        url = line.split(" ", 1)[1].strip()
                        break
                port = int(re.search(r"127\.0\.0\.1:(\d+)/", url).group(1)) if url else 0

                def get(path, **headers):
                    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
                    try:
                        return urllib.request.urlopen(req, timeout=20).status
                    except urllib.error.HTTPError as e:
                        return e.code
                    except OSError:
                        return 0

                check("`glove playwright view` serves noVNC on 127.0.0.1", bool(port) and get("/vnc.html") == 200,
                      f"port {port}")
                check("a foreign Origin is refused (403)", get("/vnc.html", Origin="https://evil.example") == 403)
                check("a foreign Host (DNS rebinding) is refused (403)",
                      get("/vnc.html", Host=f"evil.example:{port}") == 403)
            finally:
                view.terminate()
                view.wait(10)
            gone = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"], capture_output=True, text=True)
            check("the listener is gone when the command exits", not gone.stdout.strip())

            def click(secret: str) -> tuple[str, str]:
                w, h = (int(x) for x in pws["viewport"].split("x"))
                client = subprocess.Popen(
                    [rt, "run", "--rm", "--network", f"{s}-net", "--cap-drop", "ALL", "--read-only",
                     "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{HERE}:/t:ro", "--entrypoint", "python3",
                     pw_image, "/t/mcp_client.py", f"http://{s}-browser:8931/mcp", f"{s}-browser:8931",
                     json.dumps([["browser_navigate", {"url": CLICK_PAGE}], ["sleep", {"s": 12}],
                                 ["browser_snapshot", {}]])],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                time.sleep(8)
                rfb = subprocess.run(["uv", "run", "--quiet", "--no-project", "--with", "pycryptodome", "python",
                                      str(HERE / "rfb_click.py"), rt, f"{s}-pw", secret, str(w // 2), str(h * 2 // 3)],
                                     capture_output=True, text=True, timeout=120)
                out, _ = client.communicate(timeout=120)
                title = re.findall(r"Page Title: (\w+)", out)
                return (rfb.stdout + rfb.stderr).strip()[-80:], (title[-1] if title else out[-120:])

            auth, title = click("view")
            check("view-only password: authenticated, the click does NOT land", auth == "auth ok"
                  and title == "WAITING", f"{auth}; title {title}")
            auth, title = click("full")
            want = "CLICKED" if pws["allow_control"] else "WAITING"
            check(f"full password, allow_control {pws['allow_control']}: the click "
                  + ("lands" if want == "CLICKED" else "does NOT land"), auth == "auth ok" and title == want,
                  f"{auth}; title {title}")
    except Exception as e:  # report, then tear down
        check(f"live run ({type(e).__name__})", False, str(e)[-600:])
    finally:
        if base is not None and not os.environ.get("KEEP"):
            subprocess.run([*base, "down", "--volumes"], env=env, capture_output=True)
    failed = [n for n, ok in results if not ok]
    print(f"== RESULT: {len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
