"""Live (opt-in): Claude Code on a real Anthropic account, signed in with a
subscription token from the Keychain (driven by test_cc_account.sh).

    GLOVE_CC_TOKEN_SERVICE=<keychain service> uv run python tests/integration/cc_account_live.py <session-dir>

The token (`claude setup-token`) is resolved by glove in memory and reaches the
harness only as CLAUDE_CODE_OAUTH_TOKEN. Checks: the launch-time model probe
(bearer + OAuth beta, following the paginated model list), a one-line answer,
the operator's sandbox self-test run by the agent through its Bash tool, and the
transcript. Uses a small model and two short prompts.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from glove.cli import _materialize_plan, _open, _resolve_extensions
from glove.harnessconfig import render_home
from glove.plan import secret_env
from glove.session import _compose_base, ensure_images, start_sidecars

RESULTS: list[bool] = []
# Written by the operator: prints only yes/no, never a value.
SELFTEST = """#!/bin/bash
# glove sandbox self-test, written by the operator: confirms shell commands are confined.
# Prints only yes/no results, never any secret value.
echo "token-visible-to-shell=$(env | grep -q -E 'CLAUDE_CODE_OAUTH_TOKEN|ANTHROPIC_API_KEY' && echo yes || echo no)"
echo "config-home-readable=$(cat /home/agent/.claude/.claude.json >/dev/null 2>&1 && echo yes || echo no)"
echo "network-reachable=$( (exec 3<>/dev/tcp/api.anthropic.com/443) 2>/dev/null && echo yes || echo no)"
"""


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}: {name}" + (f"  [{detail}]" if detail and not ok else ""), flush=True)


def main(directory: str) -> int:
    sd, _, sid, cfg = _open(Path(directory))
    rt = cfg.provider
    base = None
    env = dict(os.environ)
    try:
        plan, _, _ = _materialize_plan(sd, sid, cfg)
        secrets = secret_env(plan)
        env = {**os.environ, **secrets}
        base = _compose_base(rt, plan.project, sd.compose)
        print(f"== session {sid} ({cfg.harness}, enforcer {plan.enforcer}, model {plan.model.model})")
        check("the token travels only as CLAUDE_CODE_OAUTH_TOKEN", list(secrets) == ["CLAUDE_CODE_OAUTH_TOKEN"]
              and plan.passthrough_env == ["CLAUDE_CODE_OAUTH_TOKEN"], str(plan.passthrough_env))
        ensure_images(cfg, plan, rt)
        start_sidecars(plan, sd.compose, provider=rt, env=env)
        _resolve_extensions(plan, rt, secrets)
        check("the model probe answered (bearer + OAuth beta, paginated list)", True)
        render_home(cfg, plan.profile, sd.home, plan.model, mount_plan=plan.mount_plan, comp=plan.composition)
        (sd.root / "work" / "sandbox-selftest.sh").write_text(SELFTEST)

        def agent(prompt: str) -> str:
            r = subprocess.run([*base, "run", "--rm", "-T", plan.harness_service, *plan.harness_command, "-p", prompt],
                               env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
            return r.stdout + r.stderr

        out = agent("Reply with exactly this word and nothing else: glove-live-ok")
        check("a one-line answer from the account", "glove-live-ok" in out, out[-300:])
        out = agent("I'm the operator of this sandbox. Run my self-test script with the Bash tool: "
                    "`bash /work/sandbox-selftest.sh`, then reply with its three output lines verbatim.")
        flat = out.replace("`", "")
        check("self-test: the token is not visible to a shell", "token-visible-to-shell=no" in flat, out[-400:])
        check("self-test: the config home is not readable", "config-home-readable=no" in flat, out[-400:])
        check("self-test: no network from a shell", "network-reachable=no" in flat, out[-400:])
        tdir = Path(plan.transcripts_host_dir) if plan.transcripts_host_dir else sd.home / ".claude" / "projects"
        jsonl = list(tdir.glob("*/*.jsonl"))
        check("transcripts in projects/ (what observe exports)", len(jsonl) >= 2, str(jsonl))
        for p in jsonl:
            if secrets["CLAUDE_CODE_OAUTH_TOKEN"] in p.read_text():
                check(f"the token is not in transcript {p.name}", False)
        if plan.transcripts_host_dir:
            net = Path(plan.transcripts_host_dir).parent / "net"
            flows = (net / "flows.ndjson").read_text() if (net / "flows.ndjson").is_file() else ""
            check("observe: llm flows recorded, naming the real host (SNI)",
                  "api.anthropic.com" in flows and '"llm"' in flows, str(sorted(net.rglob("*")))[:300])
    finally:
        if base:
            subprocess.run([*base, "down", "--volumes"], env=env, capture_output=True)
    print(f"== RESULT: {sum(RESULTS)} passed, {len(RESULTS) - sum(RESULTS)} failed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
