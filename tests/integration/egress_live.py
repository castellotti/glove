"""Live egress checks for a session directory, through glove's own launch path.

    uv run python tests/integration/egress_live.py <session-dir> [--keep]

With GLOVE_HOME set and the session's llm pointed at the tool-driving stub
(tests/integration/stubs/llm_stub.py), it:
  1. renders the session as `glove up` does, builds images, starts every
     sidecar and runs the extensions' verify checks (`session.start_sidecars`:
     container-healthy / tcp-open / http-ok / exit-ip-differs);
  2. checks the topology: only the egress provider's containers are on the
     session's wan network; SearXNG (egress consumer) has no direct internet;
     a container on the harness network has no internet at all;
  3. uses the harness endpoints from the harness network: `search` returns
     SearXNG results, `proxy` reaches the internet (exit IP ≠ host IP unless
     the route is direct);
  4. runs Pi non-interactively (nono-wrapped, hardened) with the stub driving
     `web_search` and `web_fetch` tool calls, so the real tool path is used —
     and `web_fetch` must refuse this machine and LAN addresses;
  5. tears the project down (unless --keep).
Prints PASS/FAIL per check; exit 0 only if all pass. Secrets are resolved in
memory exactly as `glove up` does; nothing here prints them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from glove.cli import _materialize_plan, _open, _resolve_extensions
from glove.harnessconfig import render_home
from glove.plan import secret_env
from glove.session import _compose_base, ensure_images, start_sidecars
from glove.verify import ECHO_URL, host_public_ip, probe

results: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'} {name}" + (f"  ({detail})" if detail else ""), flush=True)


def main(directory: str, keep: bool) -> int:
    sd, _, sid, cfg = _open(Path(directory))
    plan, _, _ = _materialize_plan(sd, sid, cfg)
    comp = plan.composition
    egress = comp.slots["egress"]
    route = egress.exports["route"]
    rt = cfg.provider
    print(f"== session {sid} ({rt}); egress {egress.name} (route {route}); subnet {cfg.subnet}")
    env = {**os.environ, **secret_env(plan)}
    base = _compose_base(rt, plan.project, sd.compose)
    s = f"glove-{plan.session}"
    try:
        ensure_images(cfg, plan, rt)
        start_sidecars(plan, sd.compose, provider=rt, env=env)
        check("sidecars up + verify passed", True)
        _resolve_extensions(plan, rt, {k: v for k, v in env.items() if k.startswith("GLOVE_")})
        render_home(cfg, plan.profile, sd.home, plan.model, mount_plan=plan.mount_plan, comp=comp)

        print("== topology")
        doc = json.loads(subprocess.run([rt, "network", "inspect", f"{s}-wan"], capture_output=True,
                                        text=True, check=True).stdout)[0]
        on_wan = sorted(c["Name"] if "Name" in c else c.get("name", "")
                        for c in (doc.get("Containers") or doc.get("containers") or {}).values())
        if not on_wan:  # podman's inspect lists no containers: ask each container instead
            names = subprocess.run([rt, "ps", "--format", "{{.Names}}", "--filter", f"name={s}-"],
                                   capture_output=True, text=True).stdout.split()
            on_wan = sorted(n for n in names if f"{s}-wan" in subprocess.run(
                [rt, "inspect", "--format", "{{json .NetworkSettings.Networks}}", n],
                capture_output=True, text=True).stdout)
        provider_svcs = sorted(f"{s}-{short}" for a, d in comp.fragments if a is egress
                               for short, svc in (d.get("services") or {}).items()
                               if "wan" in (svc.get("networks") or []))
        check("only the egress provider is on wan", on_wan == provider_svcs, f"wan: {on_wan}")
        if comp.by_name("search"):
            r = subprocess.run([rt, "exec", f"{s}-searxng", "python3", "-c",
                                "import urllib.request as u; u.urlopen('https://example.com', timeout=8)"],
                               capture_output=True, text=True)
            check("searxng has no direct internet", r.returncode != 0, (r.stderr.strip().splitlines() or ["?"])[-1])
        rc, out = probe(rt, plan, "net", 'curl -sS -m 8 -o /dev/null https://example.com', {})
        check("harness network has no internet", rc != 0, out.splitlines()[-1] if out else "")

        print("== harness endpoints (from the harness network)")
        if comp.by_name("search"):
            rc, out = probe(rt, plan, "net", 'curl -sS -m 60 "$U" | grep -o \'"url": *"http\' | wc -l',
                            {"U": f"http://{s}-search:8080/search?q=wikipedia&format=json"}, timeout=90)
            hits = int(out) if rc == 0 and out.strip().isdigit() else -1
            check("search endpoint returns SearXNG results", hits > 0, f"{hits} results")
        if comp.by_name("webfetch"):
            real = host_public_ip(ECHO_URL)
            rc, out = probe(rt, plan, "net", 'curl -fsS -m 30 -x "$X" "$U"',
                            {"X": f"http://{s}-proxy:8888", "U": ECHO_URL}, timeout=60)
            exit_ip = out.strip() if rc == 0 else ""
            want = (exit_ip == real) if route == "direct" else (bool(exit_ip) and exit_ip != real)
            check(f"proxy endpoint reaches the internet ({'exit = host' if route == 'direct' else 'exit ≠ host'})",
                  bool(real) and want, f"host {real or '?'}, exit {exit_ip or '?'}")

        print("== Pi tool calls (stub-driven, nono-wrapped harness)")
        calls = []
        if comp.by_name("search"):
            calls.append(("web_search", {"query": "wikipedia"}, "TOOL RESULT"))
        if comp.by_name("webfetch"):
            calls.append(("web_fetch", {"url": "https://example.com"}, "documentation examples"))
            # never a way into this machine or its LAN (the guard runs before the proxy)
            calls.append(("web_fetch", {"url": "http://host.docker.internal:8080/"}, "Refused"))
            calls.append(("web_fetch", {"url": "http://192.168.1.1/"}, "Refused"))
            # …not even through a public redirect (needs httpbin.org reachable via the egress)
            calls.append(("web_fetch", {"url": "https://httpbin.org/redirect-to?url=http%3A%2F%2F127.0.0.1%2F"},
                          "Refused a redirect"))
        for tool, args, want in calls:
            cmd = [*plan.harness_command, "-p", f"CALL {tool} {json.dumps(args)}"]
            r = subprocess.run([*base, "run", "--rm", "-T", plan.harness_service, *cmd], env=env,
                               stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=240)
            answer = (r.stdout.strip() or r.stderr.strip())[-400:]
            print(f"    {tool}: {answer}")
            label = f"Pi {tool} refuses {args['url']}" if want.startswith("Refused") else f"Pi {tool} through the egress"
            check(label, "TOOL RESULT" in answer and want in answer)
    except Exception as e:  # report, then tear down
        check(f"launch ({type(e).__name__})", False, str(e)[-600:])
    finally:
        if not keep:
            subprocess.run([*base, "down", "--volumes"], env=env, capture_output=True)
    failed = [n for n, ok in results if not ok]
    print(f"== RESULT: {len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--keep"]
    sys.exit(main(args[0], "--keep" in sys.argv))
