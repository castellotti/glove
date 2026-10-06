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
import os
import subprocess
import sys
from pathlib import Path

from glove import registry
from glove.cli import _materialize_plan, _open, _resolve_extensions
from glove.harnessconfig import render_home
from glove.plan import secret_env
from glove.session import _compose_base, ensure_images, start_sidecars
from glove.verify import probe

results: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'} {name}" + (f"  ({detail})" if detail else ""), flush=True)


def main(directory: str) -> int:
    sd, _, sid, cfg = _open(Path(directory))
    rt = cfg.provider
    s = f"glove-{sid}"
    base = None
    env = dict(os.environ)
    try:
        plan, _, _ = _materialize_plan(sd, sid, cfg)
        env = {**os.environ, **secret_env(plan)}
        base = _compose_base(rt, plan.project, sd.compose)
        ensure_images(cfg, plan, rt)
        start_sidecars(plan, sd.compose, provider=rt, env=env)
        names = [c["name"] for _, c in plan.composition.verify]
        check("sidecars up + verify passed (incl. example.com refused, probe_url answers)",
              {"proxy-up", "internet-refused", "probe"} <= set(names), ", ".join(names))
        _resolve_extensions(plan, rt, {k: v for k, v in env.items() if k.startswith("GLOVE_")})
        render_home(cfg, plan, sd.home)

        print("== Pi web_fetch through the corporate gate")

        def fetch(url: str) -> str:
            cmd = [*plan.harness_command, "-p", f"CALL web_fetch {json.dumps({'url': url})}"]
            r = subprocess.run([*base, "run", "--rm", "-T", plan.harness_service, *cmd], env=env,
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=240)
            out = (r.stdout.strip() or r.stderr.strip())[-300:]
            print(f"    {url}: {out}")
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
            rc, code = probe(rt, plan, "egress", 'curl -s -o /dev/null -m 15 -w "%{http_code}" -x "$X" "$U"',
                             {"X": proxy, "U": url})
            check(f"{label} refused (403)", code.strip() == "403", f"HTTP {code.strip() or '?'}")

        print("== raw TCP endpoint")
        rc, code = probe(rt, plan, "net", 'curl -s -o /dev/null -m 20 -w "%{http_code}" -H "Host: example.org" "$U"',
                         {"U": f"http://{s}-web80:80/"})
        check("tcp endpoint glove-<id>-web80:80 reaches example.org:80", code.strip() == "200", f"HTTP {code}")

        print("== flows")
        net = registry.observe_dir(sid) / "net"
        recs = [json.loads(line) for f in sorted(net.glob("flows*.ndjson")) for line in f.read_text().splitlines()
                if line.strip()]
        closes = [r for r in recs if r.get("type") == "flow" and r.get("phase") == "close" and r.get("service") == "proxy"]
        by_host = {(r.get("dest") or {}).get("host"): r for r in closes}
        org = by_host.get("example.org") or {}
        check("flow to the allowed host: route corporate, allow",
              (org.get("route") or {}).get("kind") == "corporate" and org.get("verdict") == "allow",
              json.dumps(org.get("route")))
        com = by_host.get("example.com") or {}
        check("flow to example.com recorded (refused upstream by the corporate gate)", bool(com),
              f"close_reason={com.get('close_reason')}")
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
