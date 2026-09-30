"""`direct` (v3 M4): an untunnelled egress provider."""

from __future__ import annotations

import pytest
import yaml
from helpers import make_cfg, render

from glove.extensions import ExtensionError


def _render(tmp_path, exts):
    cfg = make_cfg(name="s", workdir=str(tmp_path), extensions=exts)
    return render(cfg, tmp_path)


def test_fills_the_egress_slot_with_a_plain_proxy(tmp_path):
    plan, text = _render(tmp_path, {"direct": {}})
    comp = plan.composition
    ex = comp.slot_exports("egress")
    assert ex["route"] == "direct" and ex["proxy_url"] == "http://glove-s-direct-proxy:8888"
    svc = yaml.safe_load(text)["services"]["glove-s-direct-proxy"]
    assert set(svc["networks"]) == {"glove-s-egress", "glove-s-wan"}
    assert svc["image"].startswith("glove/ext-direct-proxy:")
    assert svc["user"] == "501:20" and svc["read_only"] is True and "cap_add" not in svc
    assert [(e, v["kind"]) for e, v in comp.verify] == [("direct", "http-ok")]
    assert comp.verify[0][1]["proxy"] == ex["proxy_url"]


def test_one_egress_provider_only(tmp_path):
    with pytest.raises(ExtensionError, match="exclusive 'egress' slot"):
        _render(tmp_path, {"direct": {}, "tor": {}})


@pytest.mark.parametrize(("host", "refused"), [
    ("example.com", False), ("en.wikipedia.org", False), ("8.8.8.8", False), ("172.32.0.1", False),
    ("localhost", True), ("host.docker.internal", True), ("printer.local", True), ("router.lan", True),
    ("glove-s-searxng", True), ("127.0.0.1", True), ("10.1.2.3", True), ("192.168.1.1", True),
    ("172.16.0.1", True), ("172.31.255.1", True), ("169.254.169.254", True), ("100.64.0.1", True),
    ("224.0.0.1", True), ("[::1]", True), ("[fd00::1]", True), ("[fe80::1]", True),
])
def test_tinyproxy_filter_refuses_local_shapes(host, refused):
    import re
    from pathlib import Path

    image = Path(__file__).parents[1] / "image"
    patterns = [p for p in (image / "tinyproxy.filter").read_text().splitlines() if p.strip()]
    assert any(re.search(p, host, re.I) for p in patterns) is refused
    conf = (image / "tinyproxy.conf").read_text()
    assert 'Filter "/etc/glove/tinyproxy.filter"' in conf and "FilterDefaultDeny No" in conf
