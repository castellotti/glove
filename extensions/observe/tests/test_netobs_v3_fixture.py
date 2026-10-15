"""tests/fixtures/netobs-v3/ (the Layman handoff §9 grant states) stays what
generate.py produces from glove's own code paths, and says what each state
means."""

from __future__ import annotations

import filecmp
import json
from pathlib import Path

import pytest

from extensions.gate.netgate.__main__ import _parse_upstream
from extensions.gate.netgate.policy import parse_bytes
from extensions.observe.netview import read_records
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
            flows = read_records(obs / "net")
            assert {(f["service"], f["client"], f["tool"]) for f in flows} == {("proxy", "harness", "web_fetch")}
            served = {f["service"] for f in facts["services"]}
            assert {"proxy", "llm"} <= served and "webfetch-mcp" not in served


def _net(name: str) -> tuple[Path, dict, dict[str, dict], list[dict]]:
    """(transcripts dir, session.json, its services by name, flows read as observe reads them)."""
    home, row = _home(name)
    obs = home / "observe" / row["id"]
    facts = json.loads((obs / "net" / "session.json").read_text())
    return obs / "transcripts", facts, {s["service"]: s for s in facts["services"]}, read_records(obs / "net")


@pytest.mark.parametrize("name", [n for n in SCENARIOS if n != "not-observable"])
def test_every_flow_is_labelled_as_its_service_says(name):
    _, _, services, flows = _net(name)
    for f in flows:
        s = services[f["service"]]
        assert (f["tool"], f["client"], f["route"]) == (s["tool"], s["client"], s["route"])
        assert f["proto"] == ("tcp" if s["mode"] == "tcp" else "http-connect")
        assert (f["verdict"] == "block") == (f["close_reason"] == "blocked") == (f["rule"] is not None)
        assert f["run"] == f"g_{f['service']}"  # one run per gate
        if f["proto"] == "tcp":  # dialled where the route says (an SNI may rename the host)
            assert f["dest"]["port"] == _parse_upstream(s["upstream"], "tcp")[1]
    # a harness hop's flow spans the egress flow it caused (`next`): joinable by time
    for outer in flows:
        for inner in (f for f in flows if f["service"] in services[outer["service"]]["next"]):
            if inner["t_open"] < outer["t_close"] and outer["t_open"] < inner["t_close"]:
                assert outer["t_open"] < inner["t_open"] and inner["t_close"] < outer["t_close"]


def _pairs(flows: list[dict]) -> set[tuple]:
    return {(f["service"], f["client"], f["dest"]["host"], f["dest"]["port"], f["scope"]) for f in flows}


@pytest.mark.parametrize(("name", "harness", "host"), [
    ("llm-auth", "pi", "glove-llm-auth-0f1a2b-llm-auth"),  # plain HTTP to the sidecar
    ("llm-auth-oauth", "claude-code", "api.anthropic.com"),  # TLS by the provider's name
])
def test_llm_auth_shows_the_harness_hop_and_the_call_it_causes(name, harness, host):
    _, facts, services, flows = _net(name)
    assert facts["harness"] == harness
    assert services["llm"]["next"] == ["llm-upstream"] and services["llm-upstream"]["harness"] is False
    assert _pairs(flows) == {("llm", "harness", host, 8080, "cloud"),
                             ("llm-upstream", "llm", "api.anthropic.com", 443, "cloud")}
    assert [f["service"] for f in flows] == ["llm-upstream", "llm"] * 2


def test_github_flows_leave_through_its_own_egress_gate():
    tx, _, services, flows = _net("github")
    assert services["github-egress"]["harness"] is False
    assert _pairs(flows) == {("github-egress", "github", "api.github.com", 443, "direct"),
                             ("github-egress", "github", "github.com", 443, "direct")}
    assert {f["tool"] for f in flows} == {"gh"}
    text = "".join(p.read_text() for p in tx.rglob("*.jsonl"))
    assert "gh pr list" in text and "git clone" in text


def test_ssh_shows_an_allowed_host_and_a_lan_only_refusal():
    _, _, services, flows = _net("ssh")
    assert {k: (s["harness"], s["scope"], s["next"]) for k, s in services.items() if k.startswith("ssh-")} == {
        "ssh-build": (False, "lan", []), "ssh-db": (False, "lan", [])}
    build, db = flows
    assert (build["service"], build["verdict"], build["dest"]["ip"]) == ("ssh-build", "allow", "192.168.1.20")
    assert (db["service"], db["verdict"], db["rule"]) == ("ssh-db", "block", "builtin:lan-only")
    assert db["bytes"] == {"up": 0, "down": 0}  # never dialled
    assert not list((OUT / "ssh").rglob("known_hosts"))  # the session dir's, not ~/.glove's


def test_downloads_pairs_each_mcp_hop_with_its_egress_flow():
    tx, facts, services, flows = _net("downloads")
    assert facts["harness"] == "vibe"
    assert services["webfetch-mcp"]["next"] == ["webfetch-egress"]
    assert services["webdownload-mcp"]["next"] == ["webdownload-egress"]
    assert [(f["service"], f["tool"]) for f in flows] == [
        ("webfetch-egress", "web_fetch"), ("webfetch-mcp", "web_fetch"),
        ("webdownload-egress", "web_download"), ("webdownload-mcp", "web_download")]
    assert sorted(p.relative_to(tx).as_posix() for p in tx.rglob("*") if p.is_file()) == [
        "session_20261001_120000_0f1a2b3c/messages.jsonl", "session_20261001_120000_0f1a2b3c/meta.json"]
    assert "sha256: " in (tx / "session_20261001_120000_0f1a2b3c" / "messages.jsonl").read_text()
