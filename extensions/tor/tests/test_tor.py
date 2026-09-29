"""`tor` (v3 M4): tor + privoxy egress."""

from __future__ import annotations

import pytest
import yaml
from helpers import make_cfg, render

from glove.extensions import ExtensionError


def _render(tmp_path, **settings):
    cfg = make_cfg(name="s", workdir=str(tmp_path), extensions={"tor": settings})
    plan, text = render(cfg, tmp_path)
    return plan, yaml.safe_load(text)


def test_topology(tmp_path):
    plan, doc = _render(tmp_path)
    svcs = doc["services"]
    tor, privoxy = svcs["glove-s-tor"], svcs["glove-s-privoxy"]
    # only tor reaches the internet; its SOCKS port is on the private torlink
    assert set(tor["networks"]) == {"glove-s-wan", "glove-s-torlink"}
    assert tor["networks"]["glove-s-torlink"] == {"aliases": ["tor"]}
    assert set(privoxy["networks"]) == {"glove-s-egress", "glove-s-torlink"}
    assert doc["networks"]["glove-s-torlink"]["internal"] is True
    for svc in (tor, privoxy):
        assert svc["user"] == "501:20" and svc["read_only"] is True and "cap_add" not in svc
    ex = plan.composition.slot_exports("egress")
    assert ex["route"] == "tor" and ex["proxy_url"] == "http://glove-s-privoxy:8118"
    kinds = [v["kind"] for _, v in plan.composition.verify]
    assert kinds == ["tcp-open", "exit-ip-differs"]


def test_exit_nodes_go_on_the_command_line(tmp_path):
    _, doc = _render(tmp_path, exit_nodes=["{se}", "{ch}"], strict_nodes=True)
    assert doc["services"]["glove-s-tor"]["command"][-4:] == ["ExitNodes", "{se},{ch}", "StrictNodes", "1"]
    _, doc = _render(tmp_path)
    assert doc["services"]["glove-s-tor"]["command"] == ["tor", "-f", "/etc/glove/torrc"]


def test_tor_and_vpn_cannot_both_be_active(tmp_path):
    cfg = make_cfg(name="s", workdir=str(tmp_path),
                   extensions={"tor": {}, "vpn": {"provider": "x", "wireguard_key": "keychain:k"}})
    with pytest.raises(ExtensionError, match="exclusive 'egress' slot"):
        render(cfg, tmp_path)
