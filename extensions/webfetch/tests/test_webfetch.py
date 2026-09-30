"""`webfetch` (v3 M4): Pi's web_fetch through the egress provider."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from helpers import make_cfg

from glove.extensions import ExtensionError
from glove.plan import build_session_plan


def _plan(tmp_path, exts, harness="pi"):
    cfg = make_cfg(harness=harness, name="s", workdir=str(tmp_path), extensions=exts)
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def test_proxy_endpoint_targets_the_egress_proxy(tmp_path):
    plan = _plan(tmp_path, {"tor": {}, "webfetch": {}})
    assert plan.environment["GLOVE_FETCH_PROXY"] == "http://glove-s-proxy:8888"
    fwd = next(s for s in plan.network.sidecars if s.role == "proxy")
    assert fwd.target == "glove-s-privoxy:8118" and fwd.harness and fwd.networks == ("glove-s-egress",)
    assert "/opt/glove/ext/webfetch/pi-extension" in plan.command


def test_requires_egress_and_pi(tmp_path):
    with pytest.raises(ExtensionError, match="requires the 'egress' slot"):
        _plan(tmp_path, {"webfetch": {}})
    with pytest.raises(ExtensionError, match="Pi extension"):
        _plan(tmp_path, {"direct": {}, "webfetch": {}}, harness="vibe")


def test_npm_dependencies_are_pinned_exactly():
    pkg = json.loads((Path(__file__).parents[1] / "pi-extension" / "package.json").read_text())
    for name, version in pkg["dependencies"].items():
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), (name, version)
