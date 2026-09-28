"""`search` (harness side, v3 M2): endpoint, env and per-harness wiring."""

from __future__ import annotations

import pytest
from helpers import make_cfg

from glove.extensions import ExtensionError
from glove.plan import build_session_plan


def _plan(tmp_path, harness, **settings):
    work = tmp_path / harness
    work.mkdir()
    cfg = make_cfg(harness=harness, name="s", workdir=str(work), extensions={"search": settings})
    return build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def test_pi_wiring(tmp_path):
    plan = _plan(tmp_path, "pi", host_port=8888)
    assert plan.environment["SEARXNG_URL"] == "http://glove-s-search:8080"
    assert "/opt/glove/ext/search/pi-extension" in plan.command
    fwd = next(s for s in plan.network.sidecars if s.role == "search")
    assert fwd.target == "host.docker.internal:8888" and fwd.listen_port == 8080


def test_vibe_wiring(tmp_path):
    plan = _plan(tmp_path, "vibe", host_port=8888)
    assert plan.composition.vibe_mcp == [{
        "name": "searxng", "transport": "stdio", "command": "python3",
        "args": ["/opt/glove/ext/search/searxng_mcp.py"], "env": {"SEARXNG_URL": "http://glove-s-search:8080"},
    }]
    assert "/opt/glove/ext/search/searxng_mcp.py" in plan.derived_dockerfile


def test_host_port_is_required(tmp_path):
    with pytest.raises(ExtensionError, match="host_port' is required"):
        _plan(tmp_path, "pi")
