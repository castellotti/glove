"""tests/fixtures/netobs-v3/ (the Layman handoff §9 grant states) stays what
generate.py produces from glove's own code paths, and says what each state
means."""

from __future__ import annotations

import filecmp
import json
from pathlib import Path

from extensions.gate.netgate.policy import parse_bytes
from extensions.observe.tests.fixtures.generate import OUT, SCENARIOS, generate


def _files(root: Path) -> set[Path]:
    """Files under `root`, relative to it. Folders count only through their
    files: git can't carry an empty one (generate.py's empty control/ roots),
    so a checkout may or may not have them."""
    return {p.relative_to(root) for p in root.rglob("*") if p.is_file()}


def _dirs_equal(a: Path, b: Path) -> list[str]:
    fa, fb = _files(a), _files(b)
    diffs = fa ^ fb
    diffs |= {f for f in fa & fb if not filecmp.cmp(a / f, b / f, shallow=False)}
    return sorted(map(str, diffs))


def test_the_checked_in_fixture_is_current(tmp_path):
    generate(tmp_path / "v3")
    assert _dirs_equal(OUT, tmp_path / "v3") == [], "run extensions/observe/tests/fixtures/generate.py"


def _home(name: str) -> tuple[Path, dict]:
    home = OUT / name / "home"
    row = json.loads((home / "registry.json").read_text())["sessions"][0]
    return home, row


def test_every_scenario_says_what_it_is():
    assert sorted(p.name for p in OUT.iterdir() if _files(p)) == sorted(SCENARIOS)
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
        if name == "claude-code":
            assert row["harness"] == facts["harness"] == "claude-code"
            tx = obs / "transcripts"
            assert sorted(p.relative_to(tx).as_posix() for p in tx.rglob("*.jsonl")) == [
                "-work/7c1d2e3f-0000-4000-8000-0f1a2b3c4d5e.jsonl",
                "-work/7c1d2e3f-0000-4000-8000-0f1a2b3c4d5e/subagents/agent-a1b2c3.jsonl"]
            flows = [json.loads(ln) for ln in (obs / "net" / "flows.ndjson").read_text().splitlines()]
            assert {(f["service"], f["client"]) for f in flows} == {("webfetch-mcp", "harness"),
                                                                    ("webfetch-egress", "webfetch")}
            served = {f["service"] for f in facts["services"]}
            assert {"webfetch-mcp", "webfetch-egress", "llm"} <= served and "proxy" not in served
