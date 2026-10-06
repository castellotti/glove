"""Live checks that the LLM key never enters the harness (driven by test_llm_inject.sh).

    uv run python tests/integration/llm_inject_live.py <session-dir> <stub-log>

The session's llm is the host stub with a fake key (GLOVE_TEST_LLM_KEY, see
lib_session.sh stub_llm); the stub answers only requests carrying it. Started
the way `glove up` does, then:
  1. the plan: the harness env holds the placeholder, nothing passes the key;
  2. the key is in no file under the session dir or GLOVE_HOME, in no
     container's config but llm-auth's (a harness container included: `inspect`
     and its /proc/1/environ), and not in a tool command's env;
  3. llm-auth is hardened (read-only, no capabilities in its process, non-root, no-new-privileges)
     and on its own network only; the harness can't reach it or llm-upstream;
  4. a turn answers, and every request the stub saw carried the real key;
  5. a path off the allowlist is a 403 from llm-auth (its log names it, never
     the key).
test_observe.sh checks the two flows each model call makes (`llm`, client
harness; `llm-upstream`, client llm).
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from live_common import check, inspect, live_session, summary, wait_for

from glove.harnessconfig import INJECTED_KEY

KEY = os.environ["GLOVE_TEST_LLM_KEY"]


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


def main(directory: str, stub_log: str) -> int:
    with live_session(directory, logs="llm-auth") as s:
        rt, plan, prefix = s.rt, s.plan, s.prefix
        auth = f"{prefix}-llm-auth"
        port = re.search(r":(\d+)", plan.model.base_url.removeprefix("http://")).group(1)
        print("== the plan")
        check("the key is injected (the model descriptor says so)", plan.model.api_key_injected)
        check(f"the harness env has the placeholder in {plan.model.api_key_env}",
              plan.environment.get(plan.model.api_key_env) == INJECTED_KEY, str(plan.model.api_key_env))
        check("nothing passes the key into the harness", plan.model.api_key_env not in plan.passthrough_env
              and KEY not in plan.environment.values(), str(plan.passthrough_env))

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

        try:
            up = wait_for(lambda: inspect(rt, probe).get("State", {}).get("Running"), 60)
            check("a harness container runs", bool(up))
            names = s.containers()
            docs = json.loads(subprocess.run([rt, "inspect", *names], capture_output=True, text=True).stdout or "[]")
            by_name = {d.get("Name", "").lstrip("/"): d for d in docs}
            holding = sorted(n for n, d in by_name.items()
                             if any(KEY in e for e in d.get("Config", {}).get("Env") or []))
            check(f"of {len(names)} containers only llm-auth has the key in its config", holding == [auth],
                  ", ".join(holding))
            env1 = subprocess.run([rt, "exec", probe, "cat", "/proc/1/environ"], capture_output=True).stdout
            check("the harness's /proc/1/environ has the placeholder, not the key",
                  KEY.encode() not in env1 and f"={INJECTED_KEY}".encode() in env1, f"{len(env1)} bytes")
            out = in_probe(
                f"for t in {auth}:8080 {prefix}-llm-upstream:{port}; do "
                f"timeout 5 bash -c \"exec 3<>/dev/tcp/${{t%:*}}/${{t#*:}}\" 2>/dev/null; echo \"$t=$?\"; done")
            check("the harness reaches neither llm-auth nor llm-upstream",
                  re.search(r"llm-auth:8080=[1-9]", out) is not None
                  and re.search(r"llm-upstream:\d+=[1-9]", out) is not None, out[-200:])
            out = in_probe(
                f"exec 3<>/dev/tcp/{prefix}-llm/{port}; "
                "printf 'GET /v1/files HTTP/1.1\\r\\nHost: x\\r\\nAuthorization: Bearer glove-injected\\r\\n"
                "Connection: close\\r\\n\\r\\n' >&3; head -1 <&3")
            check("a path off the allowlist is a 403", out.startswith("HTTP/1.1 403"), out[-200:])
        finally:
            subprocess.run([rt, "rm", "-f", probe], capture_output=True)
            run.wait(30)
        # counted in the tool (the stub returns only a result's first 300 chars);
        # the suffix is the LLM key's alone (FAKE_API_KEY's differs)
        out = s.sh(f"echo HAS=$(env | grep -cF -- '{KEY[-12:]}') PATH=$(env | grep -c ^PATH=)")
        check("a tool command's env lacks it", "HAS=0 PATH=1" in out and KEY not in out, out[-200:])

        print("== llm-auth")
        a = by_name.get(auth, {})
        hc = a.get("HostConfig", {})
        user = a.get("Config", {}).get("User", "")
        # the process's capability sets, not the runtime's report of them
        # (Docker says CapDrop [ALL], Podman lists what it dropped)
        status = subprocess.run([rt, "exec", auth, "cat", "/proc/1/status"], capture_output=True, text=True).stdout
        caps = dict(re.findall(r"^(Cap(?:Prm|Eff|Bnd)):\s*(\w+)", status, re.M))
        check("read-only rootfs, no capabilities, no-new-privileges, non-root",
              hc.get("ReadonlyRootfs") is True and len(caps) == 3 and not any(int(v, 16) for v in caps.values())
              and any("no-new-privileges" in o for o in hc.get("SecurityOpt") or [])
              and user not in ("", "0", "root") and not user.startswith("0:"),
              f"ro={hc.get('ReadonlyRootfs')} caps={caps} user={user!r}")
        nets = sorted(a.get("NetworkSettings", {}).get("Networks", {}))
        check("on the llmauth network only", nets == [f"{prefix}-llmauth"], ", ".join(nets))

        print("== a turn")
        out = s.ask("Say hello.")
        check("a turn answers through llm-auth", "hello from the glove" in out, out[-300:])
        kinds = re.findall(r" key=(\w+)", Path(stub_log).read_text())
        check("every request the stub saw carried the real key", bool(kinds) and set(kinds) == {"real"},
              f"{len(kinds)} requests: {sorted(set(kinds))}")

        def logs() -> str:
            r = subprocess.run([rt, "logs", auth], capture_output=True, text=True)
            return r.stdout + r.stderr

        wait_for(lambda: "GET /v1/files 403" in logs(), 10, 0.2)
        log = logs()
        check("llm-auth logs the refusal and the turn, never the key",
              "GET /v1/files 403" in log and " 200" in log and KEY not in log and INJECTED_KEY not in log,
              log[-300:])
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
