"""Live checks of the Claude Code harness's guard rails (driven by test_cc_nono.sh).

    uv run python tests/integration/cc_live.py <session-dir> <stub-log>

Starts the session the way `glove up` does (host anthropic stub as the model),
then in the harness service:
  1. glove-cc-prefix fails closed: no wrapper file, or not exactly one argument;
  2. /etc/claude-code (the managed settings) is read-only to the harness;
  3. `claude -p "CALL <tool> …"` through the stub: the Bash tool runs under the
     tool wrapper even though the agent's own settings blank the prefix; Read
     and Write into the config home are denied; a project's hooks and
     `.mcp.json` stdio servers never run;
  4. the transcript lands in projects/ (what observe exports for Layman), and the
     stub saw only the paths Claude Code needs.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from glove.cli import _materialize_plan, _open, _resolve_extensions
from glove.harnessconfig import render_home
from glove.plan import secret_env
from glove.session import _compose_base, ensure_images, start_sidecars

RESULTS: list[bool] = []
# What Claude Code may ask its inference host for (anything else is a leak).
STUB_PATHS = re.compile(r"^(POST /v1/messages(/count_tokens)?|GET /v1/models|HEAD /api/hello|HEAD /)(\?.*)?$")


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}: {name}" + (f"  [{detail}]" if detail and not ok else ""), flush=True)


def main(directory: str, stub_log: str) -> int:
    sd, _, sid, cfg = _open(Path(directory))
    rt = cfg.provider
    base = None
    env = dict(os.environ)
    try:
        plan, _, _ = _materialize_plan(sd, sid, cfg)
        env = {**os.environ, **secret_env(plan)}
        base = _compose_base(rt, plan.project, sd.compose)
        print(f"== session {sid} ({cfg.harness}, enforcer {plan.enforcer}, runtime {rt})")
        ensure_images(cfg, plan, rt)
        start_sidecars(plan, sd.compose, provider=rt, env=env)
        _resolve_extensions(plan, rt, secret_env(plan))
        render_home(cfg, plan.profile, sd.home, plan.model, mount_plan=plan.mount_plan, comp=plan.composition)
        managed = json.loads((sd.state / "harness" / "claude-code" / "managed-settings.json").read_text())
        check("managed settings set the shell prefix", managed["env"].get("CLAUDE_CODE_SHELL_PREFIX")
              == "/opt/glove/bin/glove-cc-prefix")
        check("the agent's settings.json blanks the prefix (the attack this run makes)",
              json.loads((sd.home / ".claude" / "settings.json").read_text())["env"]["CLAUDE_CODE_SHELL_PREFIX"] == "")

        def run(*argv: str, entry: str | None = None, extra: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
            return subprocess.run([*base, "run", "--rm", "-T", *extra, *(["--entrypoint", entry] if entry else []),
                                   plan.harness_service, *argv], env=env, stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=300)

        print("== glove-cc-prefix fails closed")
        r = subprocess.run([rt, "run", "--rm", "--entrypoint", "/opt/glove/bin/glove-cc-prefix", plan.image,
                            "echo SHOULD-NOT-RUN"], capture_output=True, text=True, timeout=120)
        check("no tool wrapper → 126, command not run", r.returncode == 126 and "SHOULD-NOT-RUN" not in r.stdout
              and "fail closed" in r.stderr, f"{r.returncode} {r.stdout} {r.stderr}")
        r = run("a", "b", entry="/opt/glove/bin/glove-cc-prefix")
        check("two arguments → 126", r.returncode == 126, f"{r.returncode} {r.stderr[-200:]}")
        r = run("echo evil=$(env | grep -c -e ^NONO_EVIL= -e ^SRT_EVIL=)", entry="/opt/glove/bin/glove-cc-prefix",
                extra=("-e", "NONO_EVIL=1", "-e", "SRT_EVIL=1"))
        check("wrapped: runs, an injected NONO_*/SRT_* is dropped", r.returncode == 0 and "evil=0" in r.stdout,
              f"{r.returncode} {r.stdout[-200:]} {r.stderr[-300:]}")

        print("== the managed settings are read-only")
        r = run("bash", "-c", "echo '{}' > /etc/claude-code/managed-settings.json; echo rc=$?",
                entry="/usr/bin/env")
        check("the harness cannot rewrite /etc/claude-code", "rc=0" not in r.stdout, r.stdout + r.stderr[-200:])

        def agent(call: str) -> str:
            r = run(*plan.harness_command, "-p", call)
            return (r.stdout + r.stderr)[-1500:]

        print("== the agent (claude -p through the stub)")
        cmd = ("cat /home/agent/.claude/settings.json >/dev/null 2>&1 && echo HOME-READ || echo HOME-DENIED; "
               "echo keys=$(env | grep -c -e ANTHROPIC_API_KEY -e CLAUDE_CODE_OAUTH_TOKEN); "
               "curl -sS -m 4 http://example.com >/dev/null 2>&1; echo net=$?")
        out = agent(f"CALL Bash {json.dumps({'command': cmd})}")
        check("Bash runs wrapped despite the blanked prefix: config home denied",
              "HOME-DENIED" in out and "HOME-READ" not in out, out.replace("\n", " ")[-300:])
        check("… the key is not in its env", "keys=0" in out, out.replace("\n", " ")[-300:])
        check("… no network", re.search(r"net=[1-9]", out) is not None, out.replace("\n", " ")[-300:])
        out = agent(f"CALL Read {json.dumps({'file_path': '/work/.mcp.json'})}")
        check("control: Read in /work works", "MCP-RAN" in out, out.replace("\n", " ")[-300:])
        agent(f"CALL Write {json.dumps({'file_path': '/work/ok.md', 'content': 'x'})}")
        check("control: Write in /work works", (sd.root / "work" / "ok.md").exists())
        out = agent(f"CALL Read {json.dumps({'file_path': '/home/agent/.claude/settings.json'})}")
        check("Read of the config home is denied", "includeCoAuthoredBy" not in out, out.replace("\n", " ")[-300:])
        out = agent(f"CALL Write {json.dumps({'file_path': '/home/agent/.claude/pwn.md', 'content': 'x'})}")
        check("Write into the config home is denied", not (sd.home / ".claude" / "pwn.md").exists(),
              out.replace("\n", " ")[-300:])
        out = agent(f"CALL Bash {json.dumps({'command': 'echo after-hooks'})}")
        check("a project's hooks never ran", not (sd.root / "work" / "HOOK-RAN").exists()
              and "after-hooks" in out, out.replace("\n", " ")[-300:])
        check("a project's .mcp.json stdio server never started", not (sd.root / "work" / "MCP-RAN").exists())

        print("== transcripts and traffic")
        jsonl = list((sd.home / ".claude" / "projects").glob("*/*.jsonl"))
        check("transcripts in projects/<cwd>/<uuid>.jsonl (observe's export dir)", bool(jsonl),
              str(list((sd.home / ".claude").rglob("*"))[:20]))
        seen = [ln.split(" headers=")[0].removeprefix("stub: ") for ln in Path(stub_log).read_text().splitlines()
                if ln.startswith("stub: ") and " headers=" in ln]
        odd = sorted({s for s in seen if not STUB_PATHS.match(s)})
        check("the stub saw only Claude Code's inference paths", bool(seen) and not odd, str(odd or seen[:5]))
    finally:
        if base:
            subprocess.run([*base, "down", "--volumes"], env=env, capture_output=True)
    print(f"== RESULT: {sum(RESULTS)} passed, {len(RESULTS) - sum(RESULTS)} failed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
