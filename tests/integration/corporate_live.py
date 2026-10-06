"""Live corporate egress (v3 M5) for a session directory, through glove's launch path.

    uv run python tests/integration/corporate_live.py <session-dir>

The session's `corporate:` allowlist stands a public host in for a corporate
one (the real corporate VPN check is the user's): example.org allowed,
example.com not; `allow_cidrs` covers the runtime's host-gateway range, which
must stay refused anyway. With observe on and the llm at the tool-driving stub:
  1. verify passes: the gate is up, https://example.com is refused through it
     (the negative check), and `probe_url` answers;
  2. Pi's web_fetch reaches the allowed host and is refused everything else,
     with the gate's reason; flows carry `route: corporate`;
  3. the host gateway, cloud metadata and the session's own network are
     refused by the gate even though an allowed CIDR covers the gateway;
  4. a raw TCP endpoint (`tcp:`) reaches its host from the harness network;
  then tears down. Prints PASS/FAIL per check; exit 0 only if all pass.
"""

from __future__ import annotations

import json
import subprocess
import sys

from live_common import check, live_session, summary

from glove.verify import probe


def main(directory: str) -> int:
    with live_session(directory) as live:
        cfg, plan = live.cfg, live.plan
        rt, s = live.rt, live.prefix
        names = [c["name"] for _, c in plan.composition.verify]
        check("sidecars up + verify passed (incl. example.com refused, probe_url answers)",
              {"proxy-up", "internet-refused", "probe"} <= set(names), ", ".join(names))

        print("== Pi web_fetch through the corporate gate")

        def fetch(url: str) -> str:
            out = live.call("web_fetch", {"url": url}, timeout=240)
            print(f"    {url}: {out.strip()[-300:]}")
            return out

        check("an allowed host is reached", "documentation examples" in fetch("https://example.org/"))
        out = fetch("https://example.com/")
        check("the general internet is refused, with the gate's reason",
              "network policy" in out and "default policy" in out)
        out = fetch("https://en.wikipedia.org/wiki/Main_Page")
        check("another public site is refused too", "network policy" in out)

        print("== refused whatever the allowlist says (from the egress network, via the gate)")
        proxy = plan.composition.slot_exports("egress")["proxy_url"]
        gw = subprocess.run([rt, "exec", f"{s}-corporate-proxy", "python", "-c",
                             "import socket;print(socket.gethostbyname('host.docker.internal'))"],
                            capture_output=True, text=True).stdout.strip()
        subnet = cfg.subnet.rsplit(".", 1)[0] + ".10"
        for label, url in (("the host gateway " + gw, f"http://{gw}/"), ("cloud metadata", "http://169.254.169.254/"),
                           ("host.docker.internal", "http://host.docker.internal/"),
                           ("this session's own network", f"http://{subnet}/")):
            _, code = probe(rt, plan, "egress", 'curl -s -o /dev/null -m 15 -w "%{http_code}" -x "$X" "$U"',
                             {"X": proxy, "U": url})
            check(f"{label} refused (403)", code.strip() == "403", f"HTTP {code.strip() or '?'}")

        print("== raw TCP endpoint")
        _, code = probe(rt, plan, "net", 'curl -s -o /dev/null -m 20 -w "%{http_code}" -H "Host: example.org" "$U"',
                         {"U": f"http://{s}-web80:80/"})
        check("tcp endpoint glove-<id>-web80:80 reaches example.org:80", code.strip() == "200", f"HTTP {code}")

        print("== flows")
        closes = [r for r in live.flows() if r.get("phase") == "close" and r.get("service") == "proxy"]
        by_host = {(r.get("dest") or {}).get("host"): r for r in closes}
        org = by_host.get("example.org") or {}
        check("flow to the allowed host: route corporate, allow",
              (org.get("route") or {}).get("kind") == "corporate" and org.get("verdict") == "allow",
              json.dumps(org.get("route")))
        com = by_host.get("example.com") or {}
        check("flow to example.com recorded (refused upstream by the corporate gate)", bool(com),
              f"close_reason={com.get('close_reason')}")
    return summary()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
