"""Live checks that the harness's own config is the operator's, under any
enforcer and runtime (driven by test_config_protect.sh).

    uv run python tests/integration/config_protect_live.py <session-dir>

With the project config an agent could plant in /work already there (a Vibe
hook shadowing glove's, a Pi project extension: each would touch a marker):
  1. in the harness service, every read-only ring-0 bind (`protect:` in
     harness.yml, the /work paths the host trusts) refuses
     a write, and the config home cannot be renamed away; the masked project
     paths (Vibe's dirs, Pi's .pi/) are empty though the host's
     are not; the home outside the
     config home is read-only (EROFS: a new file or dir at its top level, in
     ~/.config, ~/.agents, ~/.local/bin, above the config home) while the
     config home itself is writable;
  2. the agent's own file-write tool cannot overwrite a config file glove
     rendered;
  3. a tool call still runs, wrapped (no secret-shaped env in any case, set by
     the session or not by glove, a plain name kept), and the planted code
     never ran; Claude Code still writes its own state (.claude.json);
  4. the harness's own writes: its sessions dir holds the turns (Pi: not the
     project's planted sessionDir; its auth.json is a read-only bind), and
     `--continue` resumes the latest session (a session file grows);
  5. Vibe's TUI: a command its pre_tool hook denies (strict) shows the denial;
     Pi's TUI: no "project is not trusted" warning.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import posixpath
import shlex
import sys
from pathlib import Path

from live_common import check, check_version, live_session, summary, tool_result
from nono_srt_live import PLANTED, PLANTED_SESSIONS, PLANTS, lines

from glove.mounts import CONTAINER_HOME
from glove.sessions import sessions_dir

REPLY = "hello from the glove "  # both stubs' answer to a plain prompt starts so


def outside(config_home: str) -> list[str]:
    """Files a harness never writes, outside its config home: new at the home's
    top level, in dirs other tools load from, and above the config home."""
    paths = [f"{CONTAINER_HOME}/{rel}" for rel in (".glove-new", ".glove-newdir/x", ".config/glove-probe",
                                                    ".agents/glove-probe", ".local/bin/glove-probe")]
    if (parent := posixpath.dirname(config_home)) != CONTAINER_HOME:
        paths.append(f"{parent}/glove-probe")
    return paths


def files(root: Path) -> dict[Path, int]:
    """Every file under `root` and its size."""
    return {f: f.stat().st_size for f in root.rglob("*") if f.is_file()} if root.is_dir() else {}


def main(directory: str) -> int:
    with live_session(directory) as s:
        plan, h = s.plan, s.cfg.harness
        work, home = s.sd.root / "work", plan.profile.config_home_path
        check_version(s)
        masked = [e.path.rstrip("/") for e in plan.profile.protect if not e.home and e.source == "empty"]
        dirs = {e.path.rstrip("/") for e in plan.profile.protect if e.source == "empty" and e.path.endswith("/")}
        plants = {"AGENTS.md": "# project notes\n", **{f"{m}/.glove-probe" if m in dirs else m: "x\n" for m in masked},
                  **PLANTS.get(h, {})}
        for rel, text in plants.items():
            (work / rel).parent.mkdir(parents=True, exist_ok=True)
            (work / rel).write_text(text)

        print("== the read-only binds (in the harness service)")
        ro = [p for p in plan.protect if p.read_only]
        probe = "".join(f"{': >>' if p.kind == 'file' else 'touch'} {shlex.quote(p.container_path)}"
                        f"{'' if p.kind == 'file' else '/x'} 2>/dev/null; echo \"W{i}=$?\"\n" for i, p in enumerate(ro))
        probe += f"mv {home} {home}.x 2>/dev/null; echo MV=$?\n"
        probe += "".join(f"echo M{i}=$({'ls -A' if m in dirs else 'cat'} /work/{shlex.quote(m)} | wc -c)\n"
                         for i, m in enumerate(masked))
        out = outside(home)
        probe += "".join(f"{{ mkdir -p {shlex.quote(posixpath.dirname(f))} && touch {shlex.quote(f)}; }} 2>&1 "
                         f"| grep -q 'Read-only file system'; echo O{i}=$?\n"
                         for i, f in enumerate(out))
        probe += f"touch {home}/.glove-probe && rm {home}/.glove-probe; echo CW=$?\n"
        r = s.run("-c", probe, entry="bash")
        w = lines(r.stdout + r.stderr)
        in_home = sum(p.container_path.startswith(CONTAINER_HOME + "/") for p in ro)
        check(f"{len(ro)} read-only binds ({in_home} in the home) refuse a write",
              in_home > 0 and all(w.get(f"W{i}") not in (None, "0") for i in range(len(ro))),
              str({p.container_path: w.get(f"W{i}") for i, p in enumerate(ro) if w.get(f"W{i}") in (None, "0")}))
        check(f"{home} cannot be renamed", w.get("MV") not in (None, "0"), str(w.get("MV")))
        check(f"{len(out)} new paths outside {home} are read-only (EROFS)",
              all(w.get(f"O{i}") == "0" for i in range(len(out))),
              str([f for i, f in enumerate(out) if w.get(f"O{i}") != "0"]))
        check(f"{home} itself is writable", w.get("CW") == "0", str(w.get("CW")))
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
        ans = s.sh(f"echo tool-ran-$((6*7)); {s.secret_probe()}")
        check("a tool call runs with the project config planted", "tool-ran-42" in ans, ans[-300:])
        check("still wrapped (no secret-shaped env in any case, a plain name kept)", s.secret_free(ans), ans[-300:])
        check("the planted code never ran", not (work / PLANTED).exists())
        if h == "claude-code":
            check("Claude Code still writes its state (.claude.json)",
                  state.exists() and state.stat().st_mtime > mark)

        print(f"== the harness's own writes ({h}'s sessions, --continue)")
        sessions = (Path(plan.transcripts_host_dir) if plan.transcripts_host_dir
                    else sessions_dir(plan.profile, s.sd.home))
        seen = files(sessions)
        check(f"the turns are in its sessions dir ({sessions.name}/)", bool(seen), str(sessions))
        if h == "pi":
            check("not in the project's planted sessionDir", not (work / PLANTED_SESSIONS).exists())
            check("auth.json is a read-only bind",
                  any(p.container_path == f"{home}/auth.json" and p.read_only for p in ro))
        r = s.run(*plan.harness_command, *plan.profile.resume_args(None), "-p", "again")
        after = files(sessions)
        check("--continue answers", r.returncode == 0 and REPLY in r.stdout, (r.stdout + r.stderr)[-300:])
        check("and resumed the latest session (a session file grew)",
              any(after.get(f, 0) > n for f, n in seen.items()),
              f"{len(seen)} files before, {len(after)} after")

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
        if h == "pi":
            print("== Pi's TUI: no \"project is not trusted\" warning (the planted .pi/ is masked)")
            tui = s.tui(40, 140)
            drawn = tui.text(tui.wait_drawn(settle=5))
            tui.kill()
            check("Pi's TUI is up and shows no trust warning", tui.waited is not None and "not trusted" not in drawn,
                  " ".join(drawn.split())[-300:])
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
