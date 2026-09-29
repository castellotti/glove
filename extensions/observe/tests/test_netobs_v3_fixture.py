"""tests/fixtures/netobs-v3/ (the Layman handoff §9 grant states) stays what
generate.py produces from glove's own code paths, and says what each state
means."""

from __future__ import annotations

import filecmp
import json
from pathlib import Path

from extensions.gate.netgate.policy import parse_bytes
from extensions.observe.tests.fixtures.generate import OUT, SCENARIOS, generate


def _dirs_equal(a: Path, b: Path) -> list[str]:
    cmp = filecmp.dircmp(a, b)
    diffs = [*cmp.left_only, *cmp.right_only, *cmp.diff_files]
    for sub in cmp.common_dirs:
        diffs += _dirs_equal(a / sub, b / sub)
    return diffs


def test_the_checked_in_fixture_is_current(tmp_path):
    generate(tmp_path / "v3")
    assert _dirs_equal(OUT, tmp_path / "v3") == [], "run extensions/observe/tests/fixtures/generate.py"


def _home(name: str) -> tuple[Path, dict]:
    home = OUT / name / "home"
    row = json.loads((home / "registry.json").read_text())["sessions"][0]
    return home, row


def test_every_scenario_says_what_it_is():
    assert sorted(p.name for p in OUT.iterdir()) == sorted(SCENARIOS)
    for name in SCENARIOS:
        home, row = _home(name)
        sid = row["id"]
        obs, ctl = home / "observe" / sid, home / "control" / sid
        grants = row["grants"]
        if name == "not-observable":
            assert grants == {"observe": None, "filter": None} and not obs.exists() and not ctl.exists()
            continue
        facts = json.loads((obs / "net" / "session.json").read_text())
        assert facts["grants"] == grants and facts["env"] == facts["session"] == sid
        assert (obs / "transcripts").is_dir() == (name != "observe-no-transcripts")
        assert grants["observe"] == {"net": True, "transcripts": name != "observe-no-transcripts"}
        if name == "observe-filter":
            assert grants["filter"]["granted"] is True and grants["filter"]["since"]
            raw = (ctl / "rules.json").read_bytes()
            parse_bytes(raw, env=sid, session=sid)  # the gate accepts it
            st = json.loads((obs / "net" / "status.json").read_text())["rules"]
            import hashlib

            assert st["ok"] is True and st["sha256"] == hashlib.sha256(raw).hexdigest()
        else:
            assert grants["filter"] == {"granted": False} and not ctl.exists()
            # no gate reads a rules file: status.json carries no `rules` (handoff §5)
            assert "rules" not in json.loads((obs / "net" / "status.json").read_text())
        if name == "orphaned":
            assert not Path(row["dir"]).exists()
