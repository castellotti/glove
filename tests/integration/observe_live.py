"""Live observe + filter (v3 M5) for a session directory, through glove's own launch path.

    uv run python tests/integration/observe_live.py <session-dir>

The session must have an egress provider, search, webfetch, observe and filter,
and its llm pointed at the tool-driving stub (tests/integration/stubs/llm_stub.py).
It checks, against real containers:
  1. every endpoint's forwarder is a netgate (none is socat); the collector has
     no network; with filter, every gate and the collector mount control/ read-only;
  2. SearXNG is off the egress network and reaches it only through its gate;
  3. Pi's web_search / web_fetch (stub-driven tool calls) are recorded as flows
     with the right service, tool, client and route; transcripts are exported;
     the harness sees no export but its transcripts;
  4. filter: `glove filter block example.com` is enforced within seconds (the
     gates report the file's sha256), and the next web_fetch is refused and
     recorded `verdict: block` with the rule id;
  5. revocation: without `filter:` the next launch removes control/<id>/, keeps
     rules.json as .glove/ext/filter/rules.revoked.json, and the gates are
     re-created with no control mount and no --rules;
  then tears down. Prints PASS/FAIL per check; exit 0 only if all pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from glove import registry
from glove.cli import _materialize_plan, _open, _resolve_extensions
from glove.harnessconfig import render_home
from glove.plan import secret_env
from glove.session import _compose_base, ensure_images, start_sidecars

results: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'} {name}" + (f"  ({detail})" if detail else ""), flush=True)


def inspect(rt: str, name: str) -> dict:
    out = subprocess.run([rt, "inspect", name], capture_output=True, text=True).stdout
    return (json.loads(out) or [{}])[0] if out.strip() else {}


def flows(net: Path, phases=("close",)) -> list[dict]:
    recs = []
    for f in sorted(net.glob("flows*.ndjson")):
        for line in f.read_text().splitlines():
            try:
                recs.append(json.loads(line))
            except ValueError:
                pass
    return [r for r in recs if r.get("type") == "flow" and r.get("phase") in phases]


def wait_for(fn, timeout=30.0, step=1.0):
    end = time.time() + timeout
    while True:
        v = fn()
        if v or time.time() > end:
            return v
        time.sleep(step)


def launch(sd, sid, cfg):
    plan, _, _ = _materialize_plan(sd, sid, cfg)
    env = {**os.environ, **secret_env(plan)}
    ensure_images(cfg, plan, cfg.provider)
    start_sidecars(plan, sd.compose, provider=cfg.provider, env=env)  # compose-downs itself on failure
    return plan, env


def pi(plan, base, env, tool, args) -> str:
    cmd = [*plan.harness_command, "-p", f"CALL {tool} {json.dumps(args)}"]
    r = subprocess.run([*base, "run", "--rm", "-T", plan.harness_service, *cmd], env=env,
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=240)
    return (r.stdout.strip() or r.stderr.strip())[-400:]


def glove_cli(*args, cwd) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "glove.cli", *args], cwd=cwd, capture_output=True, text=True)


def main(directory: str) -> int:
    sd, _, sid, cfg = _open(Path(directory))
    rt = cfg.provider
    s = f"glove-{sid}"
    obs, ctl = Path(os.path.realpath(registry.observe_dir(sid))), Path(os.path.realpath(registry.control_dir(sid)))
    net = obs / "net"
    base = None
    env = dict(os.environ)
    try:
        plan, env = launch(sd, sid, cfg)
        base = _compose_base(rt, plan.project, sd.compose)
        comp = plan.composition
        check("sidecars up + verify passed", True, f"egress {comp.slots['egress'].name}")
        _resolve_extensions(plan, rt, {k: v for k, v in env.items() if k.startswith("GLOVE_")})
        render_home(cfg, plan, sd.home)

        print("== topology")
        roles = [x.role for x in plan.network.sidecars]
        images = {r: inspect(rt, f"{s}-{r}").get("Config", {}).get("Image", "") for r in roles}
        check("every forwarder is a netgate", all("ext-gate-netgate" in i for i in images.values()),
              ", ".join(f"{r}" for r in roles))
        col = inspect(rt, f"{s}-netgate")
        check("the collector has no network", col.get("HostConfig", {}).get("NetworkMode") == "none")
        gates = [f"{s}-{r}" for r in roles] + [f"{s}-netgate"]
        def ctl_mounts(g):  # by target: podman and docker report the source path differently
            return [m for m in inspect(rt, g).get("Mounts", []) if m.get("Destination") == "/etc/glove/netgate-control"]

        ro = [len(ms) == 1 and ms[0].get("RW") is False for ms in map(ctl_mounts, gates)]
        check("filter: every gate and the collector mount control/ read-only", all(ro), f"{sum(ro)}/{len(ro)}")
        sx = inspect(rt, f"{s}-searxng").get("NetworkSettings", {}).get("Networks", {})
        check("SearXNG is off the egress network", f"{s}-egress" not in sx, ", ".join(sorted(sx)))
        r = subprocess.run([rt, "exec", f"{s}-searxng", "python3", "-c",
                            f"import socket; socket.create_connection(('{comp.slot_exports('egress')['proxy_host']}',"
                            f" {comp.slot_exports('egress')['proxy_port']}), 3)"], capture_output=True, text=True)
        check("SearXNG cannot reach the egress proxy directly", r.returncode != 0,
              (r.stderr.strip().splitlines() or ["?"])[-1][-80:])
        # the harness runs per call (`compose run --rm`): read its binds from the project
        import yaml

        hv = yaml.safe_load(sd.compose.read_text())["services"][plan.harness_service]["volumes"]
        mounts = [os.path.realpath(v["source"]) for v in hv if v.get("type") == "bind"]

        print("== Pi tool calls → flows")
        ans = pi(plan, base, env, "web_search", {"query": "wikipedia"})
        check("Pi web_search through its gates", "TOOL RESULT" in ans, ans[-120:])
        ans = pi(plan, base, env, "web_fetch", {"url": "https://example.com"})
        check("Pi web_fetch through its gate", "documentation examples" in ans, ans[-120:])
        recs = wait_for(lambda: [r for r in flows(net) if r.get("service") == "proxy"
                                 and (r.get("dest") or {}).get("host") == "example.com"], 20)
        f = recs[-1] if recs else {}
        check("flow: proxy → example.com:443, web_fetch, client harness, allow",
              (f.get("tool"), f.get("client"), (f.get("dest") or {}).get("port"), f.get("verdict")) ==
              ("web_fetch", "harness", 443, "allow"), json.dumps({k: f.get(k) for k in ("tool", "client", "route")}))
        # SearXNG pools its connections: they may still be open (no close yet)
        if comp.slot_exports("egress").get("resolver") not in (None, "none"):
            res = (f.get("dest") or {})
            check("flow: the destination resolved in-tunnel", res.get("resolution") == "in-tunnel" and bool(res.get("ip")),
                  f"{res.get('resolution')} {res.get('ip')}")
        fx = [r for r in flows(net, ("open", "update", "close")) if r.get("service") == "searxng-egress"]
        check("flow: SearXNG's engine requests via its gate, client searxng",
              bool(fx) and all(r.get("client") == "searxng" for r in fx), f"{len(fx)} flows")
        llm = [r for r in flows(net) if r.get("service") == "llm"]
        check("flow: the model calls, tool llm, client harness",
              bool(llm) and llm[-1].get("tool") == "llm" and llm[-1].get("client") == "harness", f"{len(llm)} flows")
        st = json.loads((net / "status.json").read_text()) if (net / "status.json").exists() else {}
        check("status.json: gates running, rules loaded", bool(st) and (st.get("rules") or {}).get("ok") is True,
              f"rules={json.dumps(st.get('rules', {}))[:80]}")
        facts = json.loads((net / "session.json").read_text())
        check("session.json grants: observe + filter", facts["grants"]["observe"] == {"net": True, "transcripts": True}
              and facts["grants"]["filter"]["granted"] is True, json.dumps(facts["grants"]))
        tr = list((obs / "transcripts").rglob("*.jsonl"))
        check("transcripts exported to the observe dir", bool(tr), f"{len(tr)} file(s)")
        check("the harness mounts no export but transcripts/",
              not any(m.startswith(str(ctl)) or m.startswith(str(net)) or m == str(obs) for m in mounts)
              and str(obs / "transcripts") in mounts)
        status = glove_cli("observe", "status", cwd=sd.root)
        check("`glove observe status`", status.returncode == 0 and "running" in status.stdout,
              (status.stdout.strip().splitlines() or ["?"])[0][:80])

        print("== filter: a rule written by the CLI is enforced")
        out = glove_cli("filter", "block", "example.com", cwd=sd.root)
        check("`glove filter block example.com`", out.returncode == 0, out.stdout.strip()[-100:] or out.stderr[-200:])
        digest = hashlib.sha256((ctl / "rules.json").read_bytes()).hexdigest()
        seen = wait_for(lambda: (json.loads((net / "status.json").read_text()).get("rules") or {}).get("sha256")
                        == digest, 15)
        check("the gates confirm the file (status.json rules.sha256)", bool(seen))
        ans = pi(plan, base, env, "web_fetch", {"url": "https://example.com"})
        check("Pi web_fetch example.com is now refused", "TOOL RESULT" in ans and "network policy" in ans, ans[-140:])
        blocked = wait_for(lambda: [r for r in flows(net) if r.get("verdict") == "block"
                                    and (r.get("dest") or {}).get("host") == "example.com"], 15)
        rid = json.loads((ctl / "rules.json").read_text())["rules"][0]["id"]
        check("flow: verdict block with the rule id", bool(blocked) and blocked[-1].get("rule") == rid,
              f"rule {blocked[-1].get('rule') if blocked else '?'}")

        print("== revocation: filter removed from the session file")
        text = sd.file.read_text()
        sd.file.write_text(re.sub(r"(?m)^  filter: \{\}\n", "", text))
        sd2, _, _, cfg2 = _open(sd.root)
        plan2, env = launch(sd2, sid, cfg2)
        check("control/<id>/ removed", not ctl.exists())
        check("rules.json kept as .glove/ext/filter/rules.revoked.json",
              (sd.ext / "filter" / "rules.revoked.json").is_file())
        facts = json.loads((net / "session.json").read_text())
        check("session.json grants.filter.granted: false", facts["grants"]["filter"] == {"granted": False})
        cmds = [inspect(rt, g).get("Config", {}).get("Cmd") or [] for g in gates]
        check("gates re-created without --rules or a control mount",
              all("--rules" not in c for c in cmds) and not any(ctl_mounts(g) for g in gates))
        gone = wait_for(lambda: "rules" not in json.loads((net / "status.json").read_text()), 20)
        check("status.json carries no `rules` (no gate reads a rules file)", bool(gone))
        ans = pi(plan2, base, env, "web_fetch", {"url": "https://example.com"})
        check("web_fetch example.com works again (no rules read)", "documentation examples" in ans, ans[-120:])
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
