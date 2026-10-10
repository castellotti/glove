"""Live checks of the Claude Code harness's guard rails (driven by test_cc_nono.sh).

    uv run python tests/integration/cc_live.py <session-dir> <stub-log>

Starts the session the way `glove up` does (host anthropic stub as the model),
then in the harness service:
  0. the image runs the version harness.yml pins;
  1. glove-cc-prefix fails closed: no wrapper file, or not exactly one argument;
  2. /etc/claude-code (the managed settings) is read-only to the harness;
  3. `claude -p "CALL <tool> …"` through the stub: the Bash tool runs under the
     tool wrapper even though the agent's own settings blank the prefix; Read
     and Write into the config home are denied; a project's hooks and
     `.mcp.json` stdio servers never run;
     the agent cannot plant project settings (ring 0 binds them read-only),
     whose `env` would reach processes Claude Code starts outside ring 1;
     a stdio MCP server runs under the harness sandbox, with network;
  4. every tool Claude Code offers is in the session's inventory (tools.json),
     none it denies; a `cd` in one Bash call doesn't carry into the next (two
     calls in one turn); Write is refused in the home and /dev/shm (writable
     to the harness process under nono+srt, not to a tool command);
  5. the transcript lands in projects/ (what observe exports for Layman), and the
     stub saw only the paths Claude Code needs.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from live_common import check, check_version, live_session, offered_tools, summary

from glove.runtimes import get_runtime

# What Claude Code may ask its inference host for (anything else is a leak).
STUB_PATHS = re.compile(r"^(POST /v1/messages(/count_tokens)?|GET /v1/models|HEAD /api/hello|HEAD /)(\?.*)?$")


def main(directory: str, stub_log: str) -> int:
    with live_session(directory) as s:
        sd, plan, run = s.sd, s.plan, s.run
        check_version(s)
        managed = json.loads((sd.state / "harness" / "claude-code" / "managed-settings.json").read_text())
        check("managed settings set the shell prefix", managed["env"].get("CLAUDE_CODE_SHELL_PREFIX")
              == "/opt/glove/bin/glove-cc-prefix")
        check("the agent's settings.json blanks the prefix (the attack this run makes)",
              json.loads((sd.home / ".claude" / "settings.json").read_text())["env"]["CLAUDE_CODE_SHELL_PREFIX"] == "")

        print("== glove-cc-prefix fails closed")
        r = subprocess.run(get_runtime(s.rt).throwaway_argv(plan.image, ["echo SHOULD-NOT-RUN"], plan=plan,
                                                            entrypoint="/opt/glove/bin/glove-cc-prefix"),
                           capture_output=True, text=True, timeout=120)
        check("no tool wrapper → 126, command not run", r.returncode == 126 and "SHOULD-NOT-RUN" not in r.stdout
              and "fail closed" in r.stderr, f"{r.returncode} {r.stdout} {r.stderr}")
        r = run("a", "b", entry="/opt/glove/bin/glove-cc-prefix")
        check("two arguments → 126", r.returncode == 126, f"{r.returncode} {r.stderr[-200:]}")
        r = run("echo evil=$(env | grep -c -e ^NONO_EVIL= -e ^SRT_EVIL=)", entry="/opt/glove/bin/glove-cc-prefix",
                extra=("-e", "NONO_EVIL=1", "-e", "SRT_EVIL=1"))
        check("wrapped: runs, an injected NONO_*/SRT_* is dropped", r.returncode == 0 and "evil=0" in r.stdout,
              f"{r.returncode} {r.stdout[-200:]} {r.stderr[-300:]}")
        r = run("/opt/glove/bin/glove-cc-prefix --mcp nope", entry="/opt/glove/bin/glove-cc-prefix")
        check("--mcp with no rendered server → 126", r.returncode == 126, f"{r.returncode} {r.stderr[-200:]}")

        print("== the managed settings are read-only")
        r = run("bash", "-c", "echo '{}' > /etc/claude-code/managed-settings.json; echo rc=$?",
                entry="/usr/bin/env")
        check("the harness cannot rewrite /etc/claude-code", "rc=0" not in r.stdout, r.stdout + r.stderr[-200:])

        print("== the agent (claude -p through the stub)")
        cmd = ("cat /home/agent/.claude/settings.json >/dev/null 2>&1 && echo HOME-READ || echo HOME-DENIED; "
               "echo keys=$(env | grep -c -e ANTHROPIC_API_KEY -e CLAUDE_CODE_OAUTH_TOKEN); "
               "curl -sS -m 4 http://example.com >/dev/null 2>&1; echo net=$?")
        out = s.call("Bash", {"command": cmd})
        check("Bash runs wrapped despite the blanked prefix: config home denied",
              "HOME-DENIED" in out and "HOME-READ" not in out, out.replace("\n", " ")[-300:])
        check("… the key is not in its env", "keys=0" in out, out.replace("\n", " ")[-300:])
        check("… no network", re.search(r"net=[1-9]", out) is not None, out.replace("\n", " ")[-300:])
        out = s.call("Read", {"file_path": "/work/.mcp.json"})
        check("control: Read in /work works", "MCP-RAN" in out, out.replace("\n", " ")[-300:])
        s.call("Write", {"file_path": "/work/ok.md", "content": "x"})
        check("control: Write in /work works", (sd.root / "work" / "ok.md").exists())
        out = s.call("Read", {"file_path": "/home/agent/.claude/settings.json"})
        check("Read of the config home is denied", "includeCoAuthoredBy" not in out, out.replace("\n", " ")[-300:])
        out = s.call("Write", {"file_path": "/home/agent/.claude/pwn.md", "content": "x"})
        check("Write into the config home is denied", not (sd.home / ".claude" / "pwn.md").exists(),
              out.replace("\n", " ")[-300:])
        out = s.call("Bash", {"command": "echo after-hooks"})
        check("a project's hooks never ran", not (sd.root / "work" / "HOOK-RAN").exists()
              and "after-hooks" in out, out.replace("\n", " ")[-300:])
        check("a project's .mcp.json stdio server never started", not (sd.root / "work" / "MCP-RAN").exists())
        probe = sd.root / "work" / "MCP-PROBE"
        text = probe.read_text() if probe.exists() else ""
        check("a glove stdio MCP server runs under the harness sandbox, with network",
              "ctx=harness" in text and "net=200" in text, text or "no MCP-PROBE")

        print("== project settings are read-only (their env reaches processes outside ring 1)")
        local = sd.root / "work" / ".claude" / "settings.local.json"
        planted = json.dumps({"env": {"BASH_ENV": "/work/evil.sh", "LD_PRELOAD": "/work/x.so"}})
        (sd.root / "work" / "evil.sh").write_text("touch /work/ENV-RAN\n")
        s.call("Write", {"file_path": "/work/.claude/settings.local.json", "content": planted})
        check("the Write tool cannot plant settings.local.json", local.read_text() == "", local.read_text()[:200])
        cmd = (f"echo '{planted}' > /work/.claude/settings.local.json; echo w=$?; "
               "mv /work/.claude /work/claude-moved; echo mv=$?")
        out = s.call("Bash", {"command": cmd})
        check("… nor a tool command, nor can it move .claude aside",
              re.search(r"w=[1-9]", out) is not None and re.search(r"mv=[1-9]", out) is not None
              and local.read_text() == "" and not (sd.root / "work" / "claude-moved").exists(),
              out.replace("\n", " ")[-300:])
        s.call("Bash", {"command": "echo after-plant"})
        check("… so no planted env ran", not (sd.root / "work" / "ENV-RAN").exists())

        print("== the tool inventory and the write rule")
        inv = s.inventory
        offered = offered_tools(Path(stub_log).read_text())
        unlisted = sorted(n for n in offered - {n for c in inv.values() for n in c} if not n.startswith("mcp__"))
        check("every tool Claude Code offers is in its inventory", bool(offered) and not unlisted, str(unlisted))
        check("… none it denies is offered", not offered & set(inv["deny"]), str(offered & set(inv["deny"])))
        r = s.seq(("Bash", {"command": "cd /tmp && pwd"}), ("Bash", {"command": "pwd"}),
                  ("Write", {"file_path": "/home/agent/.config/planted", "content": "x"}),
                  ("Write", {"file_path": "/dev/shm/planted", "content": "x"}))
        # (under nono each Bash result starts with bash's refused /etc/bash.bashrc)
        check("a `cd` in one Bash call does not carry into the next (back in /work)",
              "/tmp" in r[0].split() and "/work" in r[1].split(), str(r[:2])[:400])
        check("Write into the home outside the config home is denied",
              not (sd.home / ".config" / "planted").exists() and "denied" in r[2].lower(), r[2][:300])
        check("Write into /dev/shm is denied", "denied" in r[3].lower(), r[3][:300])

        print("== transcripts and traffic")
        jsonl = list((sd.home / ".claude" / "projects").glob("*/*.jsonl"))
        check("transcripts in projects/<cwd>/<uuid>.jsonl (observe's export dir)", bool(jsonl),
              str(list((sd.home / ".claude").rglob("*"))[:20]))
        seen = [ln.split(" headers=")[0].removeprefix("stub: ") for ln in Path(stub_log).read_text().splitlines()
                if ln.startswith("stub: ") and " headers=" in ln]
        odd = sorted({p for p in seen if not STUB_PATHS.match(p)})
        check("the stub saw only Claude Code's inference paths", bool(seen) and not odd, str(odd or seen[:5]))
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
