"""Live `skills` (a Claude Code plugin for every harness), driven by test_skills.sh.

    STUB_LOG=<stub log> uv run python tests/integration/skills_live.py <session-dir>

The session has `skills: {plugins: {demo: …}}` (the fixture plugin in its
skills/, `skills: [greet]`; on Claude Code also `mcp: true`) and its llm on the
tool-driving stub. Every command is the agent's own tool call, under the
session's enforcer. It checks:
  1. the plugin's scripts run by the paths the skill names: a stdlib script,
     one with a dependency and one with a compiled dependency (each on its
     baked interpreter), an explicit `uv run --script` (offline, from the
     baked wheelhouse), and its `bin/` command on PATH;
  2. the baked skill has `${CLAUDE_PLUGIN_ROOT}` resolved; the unselected skill
     is not in the image; the plugin is read-only; the data dir is writable;
  3. the harness loads the skill (Pi: in its system prompt; Vibe: its `skill`
     tool; Claude Code: the skill link it loads with --add-dir);
  4. Claude Code and Vibe: the plugin's stdio MCP server answers, with its env
     resolved, under the tool wrapper (it can't reach the llm forwarder);
  5. the shell still has no network (uv cannot reach an index).
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import functools
import os
import sys
from pathlib import Path

from live_common import check, live_session, summary, tool_result

ROOT = "/opt/glove/plugins/demo"


def main(directory: str) -> int:
    with live_session(directory) as s:
        harness = s.cfg.harness

        sh = functools.partial(s.sh, echo=True)

        print("== the plugin's scripts")
        out = sh(f"{ROOT}/scripts/hello.py")
        check("a stdlib PEP 723 script runs (its uv shebang: the baked Python)", "HELLO python=3.12" in out, out[-120:])
        out = sh(f"{ROOT}/scripts/withdep.py")
        check("a script with a dependency runs (its baked env)", "SIX 1.17.0" in out, out[-120:])
        out = sh(f"{ROOT}/scripts/native.py")
        check("a dependency with a compiled extension loads (its baked env)", "NATIVE 1" in out, out[-160:])
        out = sh(f"cd /tmp && uv run --script {ROOT}/scripts/withdep.py")
        check("an explicit `uv run --script` installs from the wheelhouse", "SIX 1.17.0" in out, out[-120:])
        out = sh("demo")
        check("bin/ is on PATH", "DEMO-BIN" in out, out[-120:])

        print("== the baked copy")
        out = sh(f"cat {ROOT}/skills/greet/SKILL.md; ls {ROOT}/skills | tr '\\n' ,; echo")
        check("${CLAUDE_PLUGIN_ROOT} and ${CLAUDE_PLUGIN_DATA} are resolved",
              f"{ROOT}/scripts/hello.py" in out and "/work/.glove-plugin-data/demo" in out and "${" not in out,
              out[-200:])
        check("the unselected skill is not in the image", "greet," in out and "other" not in out, out[-60:])
        out = sh(f"touch {ROOT}/x 2>&1; echo rc=$?; touch /work/.glove-plugin-data/demo/x && echo data-ok")
        check("the plugin is read-only", "rc=0" not in out, out[-120:])
        check("its data dir is writable", "data-ok" in out, out[-120:])

        print("== the harness loads the skill")
        if harness == "pi":
            log = Path(os.environ["STUB_LOG"]).read_text() if os.environ.get("STUB_LOG") else ""
            seen = {x for line in log.splitlines() if line.startswith("stub: skills=")
                    for x in line.split("=", 1)[1].split(",")}
            check("Pi lists the skill in its system prompt", f"{ROOT}/skills/greet" in seen, ", ".join(sorted(seen)))
        elif harness == "vibe":
            out = tool_result(s.call("skill", {"name": "greet"}))
            check("Vibe's skill tool loads it, paths resolved", "PROBE-GREET-BODY" in out and ROOT in out, out[-200:])
        if harness == "claude-code":
            log = Path(os.environ["STUB_LOG"]).read_text() if os.environ.get("STUB_LOG") else ""
            seen = {x for line in log.splitlines() if line.startswith("stub: skills=")
                    for x in line.split("=", 1)[1].split(",")}
            check("Claude Code lists the skill for its Skill tool (--add-dir)", "greet" in seen, ", ".join(sorted(seen)))
            out = s.call("Skill", {"skill": "greet"})
            print(f"      skill: {tool_result(out, 300)}")
            check("its Skill tool loads it", "Launching skill: greet" in tool_result(out), tool_result(out, 200))
        if harness != "pi":
            print("== the plugin's stdio MCP server (under the tool wrapper)")
            llm = next(e for e in s.plan.composition.endpoints if e.name == "llm")
            target = f"{llm.host(s.sid)}:{llm.port}"
            echo = "mcp__demo__echo" if harness == "claude-code" else "mcp_demo.echo"
            out = tool_result(s.call(echo, {"message": target}))
            check("it answers, its env resolved",
                  f"ECHO {target} root={ROOT} data=/work/.glove-plugin-data/demo" in out, out[-200:])
            check("it has no network (not even the harness's llm forwarder)", "net=closed" in out, out[-60:])

        print("== still offline")
        out = sh("cd /tmp && uv run --no-project --with requests -- python -c 'print(\"NET\" + \"-OK\")' 2>&1 | tail -2")
        check("uv reaches no index (a package not in the wheelhouse)", "NET-OK" not in out, out[-160:])
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
