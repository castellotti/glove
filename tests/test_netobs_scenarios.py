"""The per-state scenarios in tests/fixtures/netobs-scenarios/ stay valid against
the handoff and keep showing the state each is named for (followup item 7).
Also pins the original fixture, tests/fixtures/netobs/, byte-for-byte: Layman's
drift guard compares its copy against it."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

import pytest
from test_netgate_invariants import ADDITIVE_FLOW_KEYS, HANDOFF, _jsonc_blocks, _shape
from test_netobs_fixture import ENUMS

from glove.netgate.policy import PolicyError, parse_bytes, sha256_hex
from glove.netgate.writer import rotated_files, rotation_key
from glove.netview import ended_runs, iter_records

FIXTURES = Path(__file__).parent / "fixtures"
SCENARIOS = FIXTURES / "netobs-scenarios"
NAMES = sorted(p.name for p in SCENARIOS.iterdir() if p.is_dir())
GATE_KEYS = ["v", "type", "event", "role", "run", "service", "env", "session", "t"]

# tests/fixtures/netobs/ as of 7d8b2c9 (the copy Layman tests against). Never regenerate it.
ORIGINAL = {
    "exit.ndjson": "297c6bf50ee1c38d2962c2b05184bd5651747e822d806f7845942b199f1c2381",
    "flows.ndjson": "ac1fa9a86ee1990412a406d01d779af2c52d2c4585055072a25297175a0ed3d9",
    "generate.py": "1a12dda37bed91064cfada6bf9d5cb45629d9aa52b0d2a24ed41f2086fd6a85b",
    "rules.json": "aeeb213418a98261dd1bb3feec0edf09b51615afd012badf0f19b562a00ae225",
    "session.json": "89057681a02699da5b9a3fc859b9afe6fca7d4070771b4e590cfdf3c6e470ef6",
    "status.json": "c46bdda411a55800430f55af8f1fd5897a4cd3165d2389f5b088426a5f9704ad",
}


def test_the_original_fixture_is_byte_identical_to_7d8b2c9():
    got = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (FIXTURES / "netobs").iterdir()
           if p.is_file()}
    assert got == ORIGINAL


def _records(name: str) -> list[dict]:
    return list(iter_records(SCENARIOS / name, kind=("flow", "gate")))


def _flows(name: str) -> dict[str, list[dict]]:
    by_id: dict[str, list[dict]] = defaultdict(list)
    for r in _records(name):
        if r["type"] == "flow":
            by_id[r["id"]].append(r)
    return by_id


def _last(name: str) -> list[dict]:
    return [recs[-1] for recs in _flows(name).values()]


def _status(name: str) -> dict:
    return json.loads((SCENARIOS / name / "status.json").read_text())


def _named(text: str) -> set[str]:
    """Scenario names in `*(…scenario: `a`, `b`…)*` markers."""
    return {n for m in re.findall(r"\*\(([^)]*scenario[^)]*)\)\*", text) for n in re.findall(r"`([a-z-]+)`", m)}


def test_there_is_a_scenario_for_every_state_the_handoff_names():
    text = HANDOFF.read_text()
    table = text[text.index("### 6.1 States"):text.index("**Correlation with the transcript")]
    rows = [r for r in table.splitlines() if r.startswith("| ") and not r.startswith("| State") and "---" not in r]
    assert rows
    for row in rows:
        assert _named(row) or "*(fixture" in row, f"no fixture or scenario for: {row[:60]}"
        assert _named(row) <= set(NAMES), row[:60]
    # every scenario is either a §6.1 state or behaviour §2 describes
    assert set(NAMES) - _named(table) <= {"search", "sni-refined", "rotation"}


@pytest.mark.parametrize("name", NAMES)
def test_every_record_matches_the_handoff(name):
    spec_flow = _jsonc_blocks("## 2. Flow schema")[0]
    recs = _records(name)
    assert recs and all(r["v"] == 1 for r in recs)
    for r in recs:
        if r["type"] == "flow":
            assert list(r) == [*spec_flow, *ADDITIVE_FLOW_KEYS], r["id"]
            assert {k: _shape(v) for k, v in r.items() if k in spec_flow and k != "request"} == {
                k: v for k, v in _shape(spec_flow).items() if k != "request"}
            assert r["request"] is None or set(r["request"]) <= {"method", "url", "headers"}
            for key, allowed in ENUMS.items():
                assert r[key] in allowed, (key, r[key])
            assert r["dest"]["resolution"] in {"in-tunnel", "literal", "unavailable", "disabled"}
            assert r["env"] == r["session"] == "pi-search" and r["run"].startswith("g_")
        else:
            assert r["type"] == "gate", r
            assert list(r) == GATE_KEYS + (["inferred"] if "inferred" in r else []), r
            assert r["event"] in {"start", "stop"} and r["role"] in {"forward", "collect"}
            assert (r["service"] is None) == (r["role"] == "collect")
    starts = {(r["service"], r["run"]) for r in recs if r["type"] == "gate" and r["event"] == "start"}
    assert {(r["service"], r["run"]) for r in recs if r["type"] == "flow"} <= starts  # every run announced
    assert recs[0]["type"] == "gate" and recs[0]["role"] == "collect" and recs[0]["event"] == "start"


@pytest.mark.parametrize("name", NAMES)
def test_status_session_and_rules_match_the_handoff(name):
    d = SCENARIOS / name
    status = _status(name)
    for key, sub in _shape(_jsonc_blocks("### `status.json`")[0]).items():
        assert key in status
        if isinstance(sub, dict):
            assert set(sub) <= set(status[key])
    rules = status["rules"]
    assert {"sha256", "last_rejected"} <= set(rules)
    session = json.loads((d / "session.json").read_text())
    assert session["env"] == session["session"] == "pi-search" and session["services"]
    rules_file = d / "rules.json"
    if not rules_file.exists():
        assert rules["sha256"] is None and rules["ok"] is True and rules["active_count"] == 0
        return
    raw = rules_file.read_bytes()
    try:
        parse_bytes(raw, env="pi-search", session="pi-search")
        accepted = True
    except PolicyError:
        accepted = False
    # the confirmation rule the handoff gives writers: enforced iff sha256, rejected iff last_rejected.sha256
    assert (rules["sha256"] == sha256_hex(raw)) == accepted
    assert ((rules["last_rejected"] or {}).get("sha256") == sha256_hex(raw)) == (not accepted)


@pytest.mark.parametrize("name", NAMES)
def test_rotated_names_are_glove_names(name):
    for p in (SCENARIOS / name).glob("flows-*.ndjson"):
        assert rotation_key(p.name, "flows") is not None, p.name


# --- each scenario still shows its state ---------------------------------------------


def test_default_block():
    closes = {r["dest"]["host"]: r for r in _last("default-block")}
    assert closes["arxiv.org"]["verdict"] == "block" and closes["arxiv.org"]["rule"] is None
    assert closes["arxiv.org"]["close_reason"] == "blocked"
    assert closes["en.wikipedia.org"]["verdict"] == "allow"
    rules = json.loads((SCENARIOS / "default-block" / "rules.json").read_text())
    assert rules["default"] == "block"


def test_direct():
    last = _last("direct")
    assert {r["scope"] for r in last} == {"direct", "local"}
    assert all(r["route"]["kind"] == "direct" for r in last)
    session = json.loads((SCENARIOS / "direct" / "session.json").read_text())
    assert session["upstream_kind"] == "direct" and _status("direct")["upstream"]["kind"] == "direct"


def test_rules_rejected():
    rules = _status("rules-rejected")["rules"]
    assert rules["ok"] is False and "unknown top-level keys" in rules["error"]
    assert rules["active_count"] == 1 and rules["sha256"] and rules["last_rejected"]["error"] == rules["error"]
    blocked = [r for r in _last("rules-rejected") if r["verdict"] == "block"]
    assert blocked and blocked[0]["rule"].startswith("r_")  # the last good set is still enforced


def test_terminate():
    (flow,) = _flows("terminate").values()
    assert flow[0]["phase"] == "open" and any(r["phase"] == "update" for r in flow)
    close = flow[-1]
    assert close["phase"] == "close" and close["verdict"] == "block" and close["close_reason"] == "blocked"
    rules = json.loads((SCENARIOS / "terminate" / "rules.json").read_text())["rules"]
    assert close["rule"] == rules[0]["id"] and rules[0]["terminate"] is True
    assert all(r["verdict"] == "allow" for r in flow[:-1])  # allowed until the rule arrived


def test_resolver_down():
    assert _status("resolver-down")["resolver"]["healthy"] is False
    last = _last("resolver-down")
    assert last and all(r["dest"]["resolution"] == "unavailable" and r["dest"]["ip"] is None for r in last)
    assert all(r["verdict"] == "allow" for r in last)


def test_telemetry_dropped():
    assert _status("telemetry-dropped")["telemetry"]["dropped"] > 0
    flows = _flows("telemetry-dropped")
    assert any(recs[0]["phase"] == "close" for recs in flows.values())  # its open was dropped
    assert any(recs[-1]["phase"] != "close" for recs in flows.values())  # its close was dropped


def test_record_full():
    assert _status("record-full")["record"] == "full"
    reqs = [r["request"] for r in _last("record-full")]
    get = next(q for q in reqs if q["method"] == "GET")
    assert get["url"].startswith("http://example.org") and get["headers"]["Authorization"] == "[redacted]"
    assert get["headers"]["Cookie"] == "[redacted]"
    assert next(q for q in reqs if q["method"] == "CONNECT")["url"] is None


def test_exit_none():
    session = json.loads((SCENARIOS / "exit-none" / "session.json").read_text())
    assert session["exit_identity"] == "none" and not (SCENARIOS / "exit-none" / "exit.ndjson").exists()


def test_exit_unhealthy():
    exits = [json.loads(x) for x in (SCENARIOS / "exit-unhealthy" / "exit.ndjson").read_text().splitlines()]
    assert [e["healthy"] for e in exits] == [True, False]
    assert exits[-1]["ip"] is None and exits[-1]["country"] is None


def test_pooled():
    flows = _flows("pooled")
    llm = next(recs for recs in flows.values() if recs[0]["service"] == "llm")
    assert llm[-1]["phase"] != "close"
    ups = [r["bytes"]["down"] for r in llm[1:]]
    assert len(set(ups)) == len(ups)  # an update only when bytes changed
    from glove.netview import _parse_ts

    latest = max(_parse_ts(r["t"]) for recs in flows.values() for r in recs)
    assert latest - _parse_ts(llm[-1]["t"]) > 3.0  # idle while other traffic ran


def test_sni_refined():
    (flow,) = _flows("sni-refined").values()
    assert flow[0]["dest"]["host"] == "host.docker.internal" and flow[-1]["dest"]["host"] == "llm.operator.lan"
    assert flow[0]["proto"] == "tcp" and flow[-1]["phase"] == "close"


def test_rotation():
    d = SCENARIOS / "rotation"
    rotated = [p.name for p in rotated_files(d, "flows")]
    assert len(rotated) >= 2
    keys = [rotation_key(n, "flows") for n in rotated]
    assert any(k[1] >= 1 for k in keys)  # a same-millisecond collision
    assert keys == sorted(keys)
    collided = next(n for n, k in zip(rotated, keys, strict=True) if k[1] == 1)
    assert sorted([collided, collided.replace("-1.ndjson", ".ndjson")])[0] == collided  # sorts first by name
    where: dict[str, list[str]] = defaultdict(list)
    for f in [*rotated, "flows.ndjson"]:
        for line in (d / f).read_text().splitlines():
            r = json.loads(line)
            if r["type"] == "flow":
                where[r["id"]].append((f, r["phase"]))
    straddles = [w for w in where.values() if w[0][0] != w[-1][0]]
    assert any(w[0] == (rotated[0], "open") and w[-1] == ("flows.ndjson", "close") for w in straddles)


def test_empty():
    empties = [r for r in _last("empty") if r["dest"]["host"] is None]
    assert {r["close_reason"] for r in empties} == {"eof", "timeout"}
    assert all(r["verdict"] == "allow" and r["scope"] == "local" for r in empties)


def test_search():
    flows = _flows("search")
    search = next(recs for recs in flows.values() if recs[0]["service"] == "search")
    fan = [recs for recs in flows.values() if recs[0]["service"] == "fanout"]
    assert search[0]["tool"] == "web_search" and search[0]["dest"]["host"] == "searxng"
    assert len(fan) == 4 and all(r[0]["client"] == "searxng" and r[0]["tool"] == "search-engine-fanout" for r in fan)
    assert all(search[0]["t"] <= r[0]["t"] and r[-1]["t"] <= search[-1]["t"] for r in fan)  # inside the search


def test_stopped():
    recs = _records("stopped")
    assert _status("stopped")["state"] == "stopped"
    assert [(r["event"], r["role"]) for r in recs if r["type"] == "gate"][-1] == ("stop", "collect")
    assert all(recs[-1]["phase"] == "close" for recs in _flows("stopped").values())
    assert "gate_shutdown" in {r["close_reason"] for r in _last("stopped")}


def test_gate_lost():
    recs = _records("gate-lost")
    stop = [r for r in recs if r["type"] == "gate" and r["event"] == "stop"]
    assert len(stop) == 1 and stop[0]["inferred"] is True and stop[0]["role"] == "forward"
    (flow,) = _flows("gate-lost").values()
    assert flow[-1]["phase"] != "close" and flow[-1]["run"] in ended_runs(recs)
