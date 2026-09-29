"""The observe (read) / filter (write) split, §5.2 — invariants.

Observe-only gates must not mount control/, must not receive --rules, and glove
must not create ~/.glove/control/<id>/. Guard exceptions (corporate's
allowlist) come only from the session file, never from rules.json."""

from __future__ import annotations

import json
import os

import yaml

from extensions.gate.netgate.policy import PolicyError, parse_bytes
from extensions.observe.tests.test_observe import gates, render

CONTROL = "/etc/glove/netgate-control"


def _control_mounts(svc: dict) -> list[dict]:
    return [v for v in svc.get("volumes", []) if v.get("target") == CONTROL or "control" in str(v.get("source"))]


def test_observe_only_gates_never_see_rules(tmp_path):
    _, doc, text = render(tmp_path)
    g = gates(doc)
    assert len(g) == 5  # llm, search, proxy, searxng-egress + the collector
    for name, svc in g.items():
        assert "--rules" not in svc["command"], name
        assert not _control_mounts(svc), name
    assert "netgate-control" not in text
    assert os.path.join(os.environ["GLOVE_HOME"], "control") not in text


def test_observe_only_never_creates_the_control_dir(tmp_path, monkeypatch):
    from extensions.observe.tests.test_observe import _session

    ghome = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(ghome))
    d, sid = _session(tmp_path, monkeypatch, "  observe: {}\n")
    assert not (ghome / "control" / sid).exists()
    compose = yaml.safe_load((d / ".glove" / "compose.yml").read_text())
    assert all(not _control_mounts(s) for s in compose["services"].values())


def test_with_filter_every_gate_and_the_collector_read_rules_read_only(tmp_path):
    _, doc, _ = render(tmp_path, exts={"direct": {}, "search": {}, "webfetch": {}, "filter": {}})
    for name, svc in gates(doc).items():
        mounts = _control_mounts(svc)
        assert len(mounts) == 1 and mounts[0]["read_only"] is True, name
        assert "--rules" in svc["command"], name


def test_only_the_forwarder_provider_may_bind_the_control_root(tmp_path):
    """An extension other than the forwarder provider (or filter) gets no
    `exports.control` and cannot bind the path by hand."""
    import pytest

    from glove.compose import _volumes
    from glove.extensions import ExtensionError

    plan, _, _ = render(tmp_path, exts={"direct": {}, "webfetch": {}, "filter": {}})
    comp = plan.composition
    direct = comp.by_name("direct")
    assert comp.export_access(direct) == {}
    assert comp.export_access(comp.by_name("observe")) == {"observe": False, "control": True}
    ctl = str(comp.export_dirs["control"])
    with pytest.raises(ExtensionError, match="export root it owns"):
        _volumes(comp, direct, "x", [{"type": "bind", "source": ctl, "target": "/c", "read_only": True}], set())
    with pytest.raises(ExtensionError, match="binds read-only"):
        _volumes(comp, comp.by_name("observe"), "x", [{"type": "bind", "source": ctl, "target": "/c"}], set())


def test_rules_json_cannot_carry_guard_exceptions():
    """rules.json v1 has no key for guard exceptions: any such key rejects the
    whole file (the gate keeps its last known-good set)."""
    base = {"v": 1, "env": "e", "session": "e", "default": "allow", "rules": []}
    for extra in ({"guard_exceptions": ["10.0.0.0/8"]}, {"allow_cidrs": ["10.0.0.0/8"]},
                  {"guard": {"hosts": ["*.corp"]}}):
        try:
            parse_bytes(json.dumps({**base, **extra}).encode(), env="e", session="e")
        except PolicyError as e:
            assert "unknown top-level keys" in str(e)
        else:  # pragma: no cover
            raise AssertionError(f"accepted {extra}")
