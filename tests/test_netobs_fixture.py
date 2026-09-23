"""The checked-in sample net/ (tests/fixtures/netobs/) stays valid against the
normative handoff schema, so Layman can build and round-trip-test against it."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from test_netgate_invariants import _jsonc_blocks, _shape

FIXTURE = Path(__file__).parent / "fixtures" / "netobs"

ENUMS = {
    "phase": {"open", "update", "close"},
    "client": {"harness", "searxng", "playwright", "unknown"},
    "proto": {"http-connect", "http", "tcp", "socks5"},
    "scope": {"tunnelled", "local", "direct"},
    "verdict": {"allow", "block"},
    "close_reason": {None, "eof", "reset", "blocked", "timeout", "upstream_unreachable", "gate_shutdown"},
}


def _flows() -> list[dict]:
    return [json.loads(line) for line in (FIXTURE / "flows.ndjson").read_text().splitlines() if line]


def test_every_record_has_exactly_the_handoff_shape():
    spec = _shape(_jsonc_blocks("## 2. Flow schema")[0])
    for rec in _flows():
        assert _shape(rec) == spec, rec["id"]
        for key, allowed in ENUMS.items():
            assert rec[key] in allowed, (key, rec[key])
        assert rec["dest"]["resolution"] in {"in-tunnel", "literal", "unavailable", "disabled"}
        assert rec["route"]["kind"] in {"vpn", "tor", "direct", "tcp"}


def test_flows_are_complete_and_bytes_cumulative():
    by_id: dict[str, list[dict]] = defaultdict(list)
    for rec in _flows():
        by_id[rec["id"]].append(rec)
    for fid, recs in by_id.items():
        phases = [r["phase"] for r in recs]
        assert phases[0] == "open" and phases[-1] == "close" and phases.count("close") == 1, fid
        ups = [r["bytes"]["up"] for r in recs]
        downs = [r["bytes"]["down"] for r in recs]
        assert ups == sorted(ups) and downs == sorted(downs), fid
        close = recs[-1]
        assert close["t_close"] is not None and close["close_reason"] is not None
        assert (close["verdict"] == "block") == (close["close_reason"] == "blocked"), fid
        assert (close["rule"] is not None) == (close["verdict"] == "block"), fid


def test_fixture_covers_every_state_a_ui_must_render():
    closes = [r for r in _flows() if r["phase"] == "close"]
    reasons = {r["close_reason"] for r in closes}
    assert {"eof", "blocked", "upstream_unreachable", "gate_shutdown"} <= reasons
    assert {r["rule"] for r in closes if r["rule"]} == {"builtin:ssrf-guard", "builtin:malformed-request"}
    assert {r["scope"] for r in closes} == {"local", "tunnelled"}
    assert {r["proto"] for r in closes} == {"tcp", "http-connect", "http"}
    assert any(r["dest"]["host"] is None for r in closes)  # the "render as the service endpoint" case
    assert any(r["phase"] == "update" for r in _flows())


def test_status_and_session_samples():
    status = json.loads((FIXTURE / "status.json").read_text())
    for key, sub in _shape(_jsonc_blocks("### `status.json`")[0]).items():
        assert key in status
        if isinstance(sub, dict):
            assert set(sub) <= set(status[key])
    session = json.loads((FIXTURE / "session.json").read_text())
    assert {s["service"] for s in session["services"]} == {"llm", "search", "proxy", "browser"}
    assert any(not s["observed"] for s in session["services"])
