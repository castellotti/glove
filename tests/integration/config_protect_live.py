"""Live checks that the harness's own config is the operator's, under any
enforcer and runtime (driven by test_config_protect.sh).

    uv run python tests/integration/config_protect_live.py <session-dir>

With the project config an agent could plant in /work already there (a Vibe
hook shadowing glove's, a Pi project extension: each would touch a marker):
  1. in the harness service, every read-only ring-0 bind (`protected_home`,
     `trusted_files`, `masked_files`, the /work paths the host trusts) refuses
     a write, and the config home cannot be renamed away; Vibe's masked
     project dirs are empty though the host's are not;
  2. the agent's own file-write tool cannot overwrite a config file glove
     rendered;
  3. a tool call still runs, wrapped (no secret-shaped env), and the planted
     code never ran; Claude Code still writes its own state (.claude.json);
  4. Vibe's TUI: a command its pre_tool hook denies (strict) shows the denial.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

from live_common import check, live_session, summary, tool_result
from nono_srt_live import PLANTED, PLANTS, lines

from glove.mounts import CONTAINER_HOME


def main(directory: str) -> int:
    with live_session(directory) as s:
        plan, h = s.plan, s.cfg.harness
        work, home = s.sd.root / "work", plan.profile.config_home_path
        masked = [m.rstrip("/") for m in plan.profile.masked_files]
        plants = {**PLANTS.get(h, {}), "AGENTS.md": "# project notes\n", **{f"{m}/.glove-probe": "x\n" for m in masked}}
        for rel, text in plants.items():
            (work / rel).parent.mkdir(parents=True, exist_ok=True)
            (work / rel).write_text(text)

        print("== the read-only binds (in the harness service)")
        ro = [p for p in plan.protect if p.read_only]
        probe = "".join(f"{': >>' if p.kind == 'file' else 'touch'} {shlex.quote(p.container_path)}"
                        f"{'' if p.kind == 'file' else '/x'} 2>/dev/null; echo \"W{i}=$?\"\n" for i, p in enumerate(ro))
        probe += f"mv {home} {home}.x 2>/dev/null; echo MV=$?\n"
        probe += "".join(f"echo M{i}=$(ls -A /work/{shlex.quote(m)} | wc -l)\n" for i, m in enumerate(masked))
        r = s.run("-c", probe, entry="bash")
        w = lines(r.stdout + r.stderr)
        in_home = sum(p.container_path.startswith(CONTAINER_HOME + "/") for p in ro)
        check(f"{len(ro)} read-only binds ({in_home} in the home) refuse a write",
              in_home > 0 and all(w.get(f"W{i}") not in (None, "0") for i in range(len(ro))),
              str({p.container_path: w.get(f"W{i}") for i, p in enumerate(ro) if w.get(f"W{i}") in (None, "0")}))
        check(f"{home} cannot be renamed", w.get("MV") not in (None, "0"), str(w.get("MV")))
        for i, m in enumerate(masked):
            check(f"the masked /work/{m} is empty (the host's is not)",
                  w.get(f"M{i}") == "0", str(w.get(f"M{i}")))

        print(f"== the agent's own tools ({h} -p, a model tool call)")
        rendered = next(p for p in ro if p.kind == "file" and p.host_path
                        and p.container_path.startswith(CONTAINER_HOME + "/"))
        before = Path(rendered.host_path).read_text()
        state = s.sd.home / ".claude" / ".claude.json"  # CC rewrites it on its first run
        mark = state.stat().st_mtime if state.exists() else 0
        tool, path_arg, content_arg = s.tools["write"]
        tail = tool_result(s.call(tool, {path_arg: rendered.container_path, content_arg: "{}\n"}), 300)
        check(f"{tool} cannot overwrite {rendered.container_path}",
              Path(rendered.host_path).read_text() == before, tail)
        ans = s.sh("echo tool-ran-$((6*7)); echo key=$(env | grep -c '^FAKE_API_KEY=')")
        check("a tool call runs with the project config planted", "tool-ran-42" in ans, ans[-300:])
        check("still wrapped (no secret-shaped env)", "key=0" in ans, ans[-300:])
        check("the planted code never ran", not (work / PLANTED).exists())
        if h == "claude-code":
            check("Claude Code still writes its state (.claude.json)",
                  state.exists() and state.stat().st_mtime > mark)

        if h == "vibe":
            print("== Vibe's TUI: a strict pre_tool denial is shown")
            tui = s.tui(40, 140)
            tui.wait_drawn(settle=3)
            tui.send(b'CALL bash {"command": "NONO_PROBE=1 echo hi"}', 1)
            tui.send(b"\r")
            shown = tui.pump_until(r"NONO_\*\s+env\s+overrides\s+are\s+not\s+allowed", 60)  # wrapped
            tui.kill()
            check("the hook's denial (NONO_* override) shows in the TUI", tui.waited is not None,
                  " ".join(tui.text(shown).split())[-300:])
            if tui.waited:
                print(f"  (shown after {tui.waited:.1f}s)")
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
