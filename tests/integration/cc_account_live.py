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

import sys
from pathlib import Path

from live_common import check, live_session, summary

# Written by the operator: prints only yes/no, never a value.
SELFTEST = """#!/bin/bash
# glove sandbox self-test, written by the operator: confirms shell commands are confined.
# Prints only yes/no results, never any secret value.
echo "token-visible-to-shell=$(env | grep -q -E 'CLAUDE_CODE_OAUTH_TOKEN|ANTHROPIC_API_KEY' && echo yes || echo no)"
echo "config-home-readable=$(cat /home/agent/.claude/.claude.json >/dev/null 2>&1 && echo yes || echo no)"
echo "network-reachable=$( (exec 3<>/dev/tcp/api.anthropic.com/443) 2>/dev/null && echo yes || echo no)"
"""


def main(directory: str) -> int:
    with live_session(directory) as s:
        sd, plan, secrets = s.sd, s.plan, s.secrets
        check("the token travels only as CLAUDE_CODE_OAUTH_TOKEN", list(secrets) == ["CLAUDE_CODE_OAUTH_TOKEN"]
              and plan.passthrough_env == ["CLAUDE_CODE_OAUTH_TOKEN"], str(plan.passthrough_env))
        check(f"the model probe answered (bearer + OAuth beta, paginated list): {plan.model.model}", True)
        (sd.root / "work" / "sandbox-selftest.sh").write_text(SELFTEST)

        out = s.ask("Reply with exactly this word and nothing else: glove-live-ok")
        check("a one-line answer from the account", "glove-live-ok" in out, out[-300:])
        out = s.ask("I'm the operator of this sandbox. Run my self-test script with the Bash tool: "
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
            llm = [r for r in s.flows() if r.get("service") == "llm"]
            check("observe: llm flows recorded, naming the real host (SNI)",
                  any((r.get("dest") or {}).get("host") == "api.anthropic.com" for r in llm),
                  str(sorted(s.net.rglob("*")))[:300])
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
