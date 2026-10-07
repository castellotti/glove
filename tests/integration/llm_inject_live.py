"""Live checks that the LLM key never enters the harness (driven by test_llm_inject.sh).

    uv run python tests/integration/llm_inject_live.py <session-dir> [<stub-log>]

The session's llm has a fake key (GLOVE_TEST_LLM_KEY, see lib_session.sh
stub_llm), and its server answers only requests carrying it: the host stub
(its log `<stub-log>`), or, for a subscription token (`auth: oauth`, no
stub log), a stand-in for the provider itself (`stand_in`). Started the way
`glove up` does, then:
  1. the plan: the harness env holds the placeholder, nothing passes the key;
  2. the key is in no file under the session dir or GLOVE_HOME, in no
     container's config but llm-auth's (a harness container included: `inspect`
     and its /proc/1/environ), and not in a tool command's env;
  3. llm-auth is hardened (read-only, no capabilities in its process, non-root, no-new-privileges)
     and on its own network only; the harness can't reach it or llm-upstream;
  4. a turn answers, and every request the server saw carried the real key;
  5. a path off the allowlist is a 403 from llm-auth (its log names it, never
     the key).
With `auth: oauth` also:
  6. llm-auth serves TLS by the provider's name, verified with the session CA
     (the harness's NODE_EXTRA_CA_CERTS, in the read-only `llm-ca` channel): an
     account path is allowed, another is a 403; no key file is left in
     llm-auth; a tool command can't write the channel;
  7. the TUI draws within TUI_START seconds; the session has observe on, and
     both hops of a model call are flows to the provider's name (their SNI).
test_observe.sh checks the two flows each model call makes (`llm`, client
harness; `llm-upstream`, client llm) for an API key.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from live_common import LiveSession, check, container_log, inspect, live_session, summary, wait_for

from glove.harnessconfig import INJECTED_KEY

KEY = os.environ["GLOVE_TEST_LLM_KEY"]
STUBS = Path(__file__).parent / "stubs"
STAND_IN = "api-stub"
WRITE_CA = "touch /run/glove/llm-ca/x; echo RC=$?"
TUI_START = 5.0  # seconds (measured 0.7 s; through a base URL Claude Code took 18.6 s, round 3)


def refused(out: str) -> bool:
    """`WRITE_CA`'s output says the write failed."""
    return re.search(r"RC=[1-9]", out) is not None


def files_holding(roots: list[Path], needle: bytes) -> list[str]:
    """Regular files under `roots` whose bytes contain `needle`."""
    hits = []
    for root in roots:
        for dirpath, _, names in os.walk(root):
            for n in names:
                p = Path(dirpath) / n
                try:
                    if p.is_file() and not p.is_symlink() and needle in p.read_bytes():
                        hits.append(str(p))
                except OSError:
                    pass
    return hits


def stand_in(s: LiveSession, doc: dict) -> None:
    """A compose patch: the anthropic stub, serving TLS as the provider's name
    with a CA of its own, on the session's `llm` network under that name, so
    `llm-upstream` (which dials the name) reaches it; and llm-auth trusting that
    CA alone (`SSL_CERT_FILE`, from a volume they share). A real session has
    neither."""
    name = s.plan.composition.slot_exports("inference")["inject"]["tls_name"]
    services, stub, ca = doc["services"], f"{s.prefix}-{STAND_IN}", f"{s.prefix}-stub-ca"
    auth = services[f"{s.prefix}-llm-auth"]
    doc["volumes"][ca] = {**doc["volumes"][f"{s.prefix}-chan-llm-ca"], "name": ca}  # as a channel: the session's
    services[stub] = {
        "image": auth["image"], "container_name": stub, "user": auth["user"],
        "entrypoint": ["python3", "/stubs/anthropic_stub.py", "443", name, "/pki"],
        "environment": {"GLOVE_TEST_LLM_KEY": None},  # from this process's env, as the provider holds it
        "volumes": [{"type": "bind", "source": str(STUBS), "target": "/stubs", "read_only": True},
                    {"type": "volume", "source": ca, "target": "/pki"}],
        "read_only": True, "tmpfs": ["/tmp"],
        "sysctls": {"net.ipv4.ip_unprivileged_port_start": 0},  # :443, non-root (Podman's default is 1024)
        "networks": {f"{s.prefix}-llm": {"aliases": [name]}},
        "healthcheck": {"test": ["CMD", "test", "-s", "/pki/ca.pem"], "interval": "1s", "retries": 30},
    }
    if "userns_mode" in auth:  # rootless Podman's keep-id: the volume's owner as the session sees it
        services[stub]["userns_mode"] = auth["userns_mode"]
    auth["environment"]["SSL_CERT_FILE"] = "/stub-ca/ca.pem"
    auth["volumes"].append({"type": "volume", "source": ca, "target": "/stub-ca", "read_only": True})
    auth["depends_on"] = {stub: {"condition": "service_healthy"}}


def main(directory: str, stub_log: str | None) -> int:
    oauth = stub_log is None
    with live_session(directory, logs="llm-auth", patch=stand_in if oauth else None) as s:
        rt, plan, prefix = s.rt, s.plan, s.prefix
        auth = f"{prefix}-llm-auth"
        base = urlsplit(plan.model.base_url)
        root = f"{base.scheme}://{base.netloc}"
        upstream_port = plan.composition.slot_exports("inference")["inject"]["upstream"].rsplit(":", 1)[1]
        print("== the plan")
        check("the key is injected (the model descriptor says so)", plan.model.api_key_injected)
        check(f"the harness env has the placeholder in {plan.model.api_key_env}",
              plan.environment.get(plan.model.api_key_env) == INJECTED_KEY, str(plan.model.api_key_env))
        check("nothing passes the key into the harness", plan.model.api_key_env not in plan.passthrough_env
              and KEY not in plan.environment.values(), str(plan.passthrough_env))
        if oauth:
            check("the harness keeps the provider's name and trusts the session CA",
                  root == "https://api.anthropic.com"
                  and plan.environment.get("NODE_EXTRA_CA_CERTS") == "/run/glove/llm-ca/ca.pem",
                  f"{root} {plan.environment.get('NODE_EXTRA_CA_CERTS')}")

        print("== where the key is")
        hits = files_holding([s.sd.root, Path(os.environ["GLOVE_HOME"])], KEY.encode())
        check("no file under the session dir or GLOVE_HOME holds it", not hits, ", ".join(hits[:5]))
        # a harness container, as `glove up` runs one, kept alive to inspect and probe from
        probe = f"{prefix}-injectprobe"
        run = subprocess.Popen([*s.base, "run", "--rm", "-T", "--name", probe, "--entrypoint", "sleep",
                                plan.harness_service, "120"], env=s.env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def in_probe(script: str) -> str:
            r = subprocess.run([rt, "exec", probe, "bash", "-c", script], capture_output=True, text=True, timeout=60)
            return r.stdout + r.stderr

        def status(method: str, path: str) -> str:
            """The HTTP status of `path` from the harness, the way it calls
            its model (the placeholder; its CA, if any, verifying the name)."""
            return in_probe(
                f"curl -sS -m 20 -o /dev/null -w '%{{http_code}}' -X {method} "
                "${NODE_EXTRA_CA_CERTS:+--cacert \"$NODE_EXTRA_CA_CERTS\"} "
                f"-H 'Authorization: Bearer {INJECTED_KEY}' '{root}{path}'")

        try:
            up = wait_for(lambda: inspect(rt, probe).get("State", {}).get("Running"), 60)
            check("a harness container runs", bool(up))
            names = s.containers()
            docs = json.loads(subprocess.run([rt, "inspect", *names], capture_output=True, text=True).stdout or "[]")
            by_name = {d.get("Name", "").lstrip("/"): d for d in docs}
            holding = sorted(n for n, d in by_name.items() if n != f"{prefix}-{STAND_IN}"  # the provider's own
                             and any(KEY in e for e in d.get("Config", {}).get("Env") or []))
            check(f"of {len(names)} containers only llm-auth has the key in its config", holding == [auth],
                  ", ".join(holding))
            env1 = subprocess.run([rt, "exec", probe, "cat", "/proc/1/environ"], capture_output=True).stdout
            check("the harness's /proc/1/environ has the placeholder, not the key",
                  KEY.encode() not in env1 and f"={INJECTED_KEY}".encode() in env1, f"{len(env1)} bytes")
            out = in_probe(
                f"for t in {auth}:8080 {prefix}-llm-upstream:{upstream_port}; do "
                f"timeout 5 bash -c \"exec 3<>/dev/tcp/${{t%:*}}/${{t#*:}}\" 2>/dev/null; echo \"$t=$?\"; done")
            check("the harness reaches neither llm-auth nor llm-upstream",
                  re.search(r"llm-auth:8080=[1-9]", out) is not None
                  and re.search(r"llm-upstream:\d+=[1-9]", out) is not None, out[-200:])
            out = status("GET", "/v1/files")
            check("a path off the allowlist is a 403", out == "403", out[-200:])
            if oauth:
                out = status("GET", "/api/oauth/profile")
                check("by the provider's name, verified with the session CA: an account path answers",
                      out == "200", out[-200:])
                out = status("GET", "/api/oauth/account/settings")
                check("an account path off the allowlist is a 403", out == "403", out[-200:])
                out = in_probe(WRITE_CA)
                check("the harness can't write the llm-ca channel", refused(out), out[-200:])
        finally:
            subprocess.run([rt, "rm", "-f", probe], capture_output=True)
            run.wait(30)
        # counted in the tool (the stub returns only a result's first 300 chars);
        # the suffix is the LLM key's alone (FAKE_API_KEY's differs)
        out = s.sh(f"echo HAS=$(env | grep -cF -- '{KEY[-12:]}') PATH=$(env | grep -c ^PATH=)")
        check("a tool command's env lacks it", "HAS=0 PATH=1" in out and KEY not in out, out[-200:])
        if oauth:
            out = s.sh(WRITE_CA)
            check("a tool command can't write the llm-ca channel", refused(out), out[-200:])

        print("== llm-auth")
        a = by_name.get(auth, {})
        hc = a.get("HostConfig", {})
        user = a.get("Config", {}).get("User", "")
        # the process's capability sets, not the runtime's report of them
        # (Docker says CapDrop [ALL], Podman lists what it dropped)
        proc = subprocess.run([rt, "exec", auth, "cat", "/proc/1/status"], capture_output=True, text=True).stdout
        caps = dict(re.findall(r"^(Cap(?:Prm|Eff|Bnd)):\s*(\w+)", proc, re.M))
        check("read-only rootfs, no capabilities, no-new-privileges, non-root",
              hc.get("ReadonlyRootfs") is True and len(caps) == 3 and not any(int(v, 16) for v in caps.values())
              and any("no-new-privileges" in o for o in hc.get("SecurityOpt") or [])
              and user not in ("", "0", "root") and not user.startswith("0:"),
              f"ro={hc.get('ReadonlyRootfs')} caps={caps} user={user!r}")
        nets = sorted(a.get("NetworkSettings", {}).get("Networks", {}))
        check("on the llmauth network only", nets == [f"{prefix}-llmauth"], ", ".join(nets))
        if oauth:
            out = subprocess.run([rt, "exec", auth, "sh", "-c", "find /tmp /run/glove/llm-ca -mindepth 1"],
                                 capture_output=True, text=True).stdout.split()
            check("no key is left: its tmpfs is empty, the channel holds ca.pem only",
                  out == ["/run/glove/llm-ca/ca.pem"], " ".join(out))

        print("== a turn")
        out = s.ask("Say hello.")
        check("a turn answers through llm-auth", "hello from the glove" in out, out[-300:])

        server_log = container_log(rt, f"{prefix}-{STAND_IN}") if oauth else Path(stub_log).read_text()
        kinds = re.findall(r" key=(\w+)", server_log)
        check("every request the server saw carried the real key", bool(kinds) and set(kinds) == {"real"},
              f"{len(kinds)} requests: {sorted(set(kinds))}")

        wait_for(lambda: "GET /v1/files 403" in container_log(rt, auth), 10, 0.2)
        log = container_log(rt, auth)
        check("llm-auth logs the refusal and the turn, never the key",
              "GET /v1/files 403" in log and " 200" in log and KEY not in log and INJECTED_KEY not in log,
              log[-300:])

        if oauth:
            print("== the TUI and the flows")
            tui = s.tui(30, 100)
            tui.wait_drawn(timeout=60)
            tui.kill()
            check(f"the TUI draws within {TUI_START:.0f}s", tui.waited is not None and tui.waited < TUI_START,
                  f"{tui.waited}")
            host = base.hostname
            closed = s.flows(("close",))
            for svc, client in (("llm", "harness"), ("llm-upstream", "llm")):
                recs = [r for r in closed if r.get("service") == svc]
                hosts = {(r.get("dest") or {}).get("host") for r in recs}
                check(f"flows via {svc} (client {client}) are to {host} (the SNI)",
                      bool(recs) and hosts == {host} and {r.get("client") for r in recs} == {client},
                      f"{len(recs)} flows: {sorted(map(str, hosts))}")
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
