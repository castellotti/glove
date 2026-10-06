"""Live observe + filter (v3 M5) for a session directory, through glove's own launch path.

    uv run python tests/integration/observe_live.py <session-dir>

The session must have an egress provider, search, webfetch, observe and filter,
and its llm pointed at the tool-driving stub (tests/integration/stubs/llm_stub.py).
It checks, against real containers:
  1. every endpoint's forwarder is a netgate (none is socat); the collector has
     no network; with filter, every gate and the collector mount control/ read-only;
  2. SearXNG is off the egress network and reaches it only through its gate;
  3. Pi's web_search / web_fetch (stub-driven tool calls) are recorded as flows
     with the right service, tool, client and route, and each model call as two
     flows (`llm` client harness, `llm-upstream` client llm); transcripts are exported;
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
from pathlib import Path

import yaml
from live_common import check, glove, inspect, live_session, summary, wait_for

from glove import registry


def main(directory: str) -> int:
    with live_session(directory) as live:
        sd, sid, plan, rt = live.sd, live.sid, live.plan, live.rt
        s, net = live.prefix, live.net
        obs, ctl = net.parent, Path(os.path.realpath(registry.control_dir(sid)))
        comp = plan.composition
        check("sidecars up + verify passed", True, f"egress {comp.slots['egress'].name}")

        def flows(phases=("close",)) -> list[dict]:
            return live.flows(phases)

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
        hv = yaml.safe_load(sd.compose.read_text())["services"][plan.harness_service]["volumes"]
        mounts = [os.path.realpath(v["source"]) for v in hv if v.get("type") == "bind"]

        print("== Pi tool calls → flows")
        ans = live.call("web_search", {"query": "wikipedia"})
        check("Pi web_search through its gates", "TOOL RESULT" in ans, ans[-120:])
        ans = live.call("web_fetch", {"url": "https://example.com"})
        check("Pi web_fetch through its gate", "documentation examples" in ans, ans[-120:])
        recs = wait_for(lambda: [r for r in flows() if r.get("service") == "proxy"
                                 and (r.get("dest") or {}).get("host") == "example.com"], 20)
        f = recs[-1] if recs else {}
        check("flow: proxy → example.com:443, web_fetch, client harness, allow",
              (f.get("tool"), f.get("client"), (f.get("dest") or {}).get("port"), f.get("verdict")) ==
              ("web_fetch", "harness", 443, "allow"), json.dumps({k: f.get(k) for k in ("tool", "client", "route")}))
        # SearXNG pools its connections: they may still be open (no close yet)
        if comp.slot_exports("egress").get("resolver") not in (None, "none"):
            res = (f.get("dest") or {})
            check("flow: the destination resolved in-tunnel",
                  res.get("resolution") == "in-tunnel" and bool(res.get("ip")),
                  f"{res.get('resolution')} {res.get('ip')}")
        fx = [r for r in flows(("open", "update", "close")) if r.get("service") == "searxng-egress"]
        check("flow: SearXNG's engine requests via its gate, client searxng",
              bool(fx) and all(r.get("client") == "searxng" for r in fx), f"{len(fx)} flows")
        # each model call is two flows: the harness → llm-auth hop, and llm-auth's (with the key) onward
        recs = flows()
        for svc, client in (("llm", "harness"), ("llm-upstream", "llm")):
            llm = [r for r in recs if r.get("service") == svc]
            check(f"flow: the model calls via {svc}, tool llm, client {client}",
                  bool(llm) and llm[-1].get("tool") == "llm" and llm[-1].get("client") == client, f"{len(llm)} flows")
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
        status = glove("observe", "status", cwd=sd.root)
        check("`glove observe status`", status.returncode == 0 and "running" in status.stdout,
              (status.stdout.strip().splitlines() or ["?"])[0][:80])

        print("== filter: a rule written by the CLI is enforced")
        out = glove("filter", "block", "example.com", cwd=sd.root)
        check("`glove filter block example.com`", out.returncode == 0, out.stdout.strip()[-100:] or out.stderr[-200:])
        digest = hashlib.sha256((ctl / "rules.json").read_bytes()).hexdigest()
        seen = wait_for(lambda: (json.loads((net / "status.json").read_text()).get("rules") or {}).get("sha256")
                        == digest, 15)
        check("the gates confirm the file (status.json rules.sha256)", bool(seen))
        ans = live.call("web_fetch", {"url": "https://example.com"})
        check("Pi web_fetch example.com is now refused", "TOOL RESULT" in ans and "network policy" in ans, ans[-140:])
        blocked = wait_for(lambda: [r for r in flows() if r.get("verdict") == "block"
                                    and (r.get("dest") or {}).get("host") == "example.com"], 15)
        rid = json.loads((ctl / "rules.json").read_text())["rules"][0]["id"]
        check("flow: verdict block with the rule id", bool(blocked) and blocked[-1].get("rule") == rid,
              f"rule {blocked[-1].get('rule') if blocked else '?'}")

        print("== revocation: filter removed from the session file")
        text = sd.file.read_text()
        sd.file.write_text(re.sub(r"(?m)^  filter: \{\}\n", "", text))
        live.relaunch()
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
        ans = live.call("web_fetch", {"url": "https://example.com"})
        check("web_fetch example.com works again (no rules read)", "documentation examples" in ans, ans[-120:])
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
