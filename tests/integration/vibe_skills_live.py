"""Live checks of Vibe's `harness_config.project_skills` opt-in (driven by
test_vibe_skills.sh).

    uv run python tests/integration/vibe_skills_live.py <session-dir>

With a project skill in .vibe/skills/ and .agents/skills/, a prompt in
.vibe/prompts/ and a hook in .vibe/hooks.toml (it would touch a marker):
  1. off (the default): .vibe/ and .agents/ are empty to the harness, and the
     skill tool finds no project skill;
  2. on (the session file changed, relaunched): both skills load; .vibe/ shows
     only skills/ (no prompts, no hooks.toml), the skills are read-only, and the
     planted hook never ran.
Prints PASS/FAIL per check; exits non-zero on any failure.
"""

from __future__ import annotations

import sys

from live_common import check, live_session, summary
from nono_srt_live import PLANTED, PLANTS, lines

SKILL = "---\nname: {n}\ndescription: a glove probe skill\n---\nPROBE-SKILL-BODY-{n}\n"
SKILLS = {"glove-vibe": ".vibe/skills/glove-vibe", "glove-agents": ".agents/skills/glove-agents"}
LIST = ("echo VIBE=$(ls -A /work/.vibe | tr '\\n' ,); echo AGENTS=$(ls -A /work/.agents | tr '\\n' ,); "
        "touch /work/.vibe/skills/x 2>/dev/null; echo TOUCH=$?")


def main(directory: str) -> int:
    with live_session(directory) as s:
        work = s.sd.root / "work"
        for name, rel in SKILLS.items():
            (work / rel).mkdir(parents=True, exist_ok=True)
            (work / rel / "SKILL.md").write_text(SKILL.format(n=name))
        (work / ".vibe" / "prompts").mkdir(exist_ok=True)
        (work / ".vibe" / "prompts" / "glove.md").write_text("a planted prompt\n")
        (work / ".vibe" / "hooks.toml").write_text(PLANTS["vibe"][".vibe/hooks.toml"])

        def loaded() -> dict[str, str]:  # both skills, in one turn
            return dict(zip(SKILLS, s.seq(*(("skill", {"name": n}) for n in SKILLS)), strict=True))

        print("== off (the default)")
        w = lines(s.run("-c", LIST, entry="bash").stdout)
        check(".vibe/ and .agents/ are empty", (w.get("VIBE"), w.get("AGENTS")) == ("", ""), str(w))
        for n, r in loaded().items():
            check(f"the project skill {n} is not found", f"PROBE-SKILL-BODY-{n}" not in r, r)

        print("== on (harness_config.project_skills: true)")
        s.reconfigure("harness_config: {project_skills: true}")
        w = lines(s.run("-c", LIST, entry="bash").stdout)
        check(".vibe/ and .agents/ show only skills/", (w.get("VIBE"), w.get("AGENTS")) == ("skills,", "skills,"),
              str(w))
        check("the skills are read-only", w.get("TOUCH") not in (None, "0"), str(w.get("TOUCH")))
        for n, r in loaded().items():
            check(f"the project skill {n} loads", f"PROBE-SKILL-BODY-{n}" in r, r)
        check("the planted hook never ran", not (work / PLANTED).exists())
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
