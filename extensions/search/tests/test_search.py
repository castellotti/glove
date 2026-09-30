"""`search` (v3 M4): SearXNG + valkey sidecars behind the egress slot."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
import yaml
from helpers import make_cfg, render

from glove.extensions import ExtensionError, load_module, materialize
from glove.plan import build_session_plan


def _plan(tmp_path, harness="pi", egress=("direct", {}), **settings):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    exts = {egress[0]: egress[1], "search": settings} if egress else {"search": settings}
    cfg = make_cfg(harness=harness, name="s", workdir=str(work), extensions=exts, subnet="172.31.3.0/24")
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def test_requires_an_egress_provider(tmp_path):
    with pytest.raises(ExtensionError, match="requires the 'egress' slot"):
        _plan(tmp_path, egress=None)


def test_pi_wiring(tmp_path):
    plan = _plan(tmp_path)
    assert plan.environment["SEARXNG_URL"] == "http://glove-s-search:8080"
    assert "/opt/glove/ext/search/pi-extension" in plan.command
    fwd = next(s for s in plan.network.sidecars if s.role == "search")
    assert fwd.target == "glove-s-searxng:8080" and fwd.listen_port == 8080
    # the harness forwarder reaches SearXNG on its private net, not on egress
    assert fwd.networks == ("glove-s-searchnet",)


def test_vibe_wiring(tmp_path):
    plan = _plan(tmp_path, "vibe")
    assert plan.composition.vibe_mcp == [{
        "name": "searxng", "transport": "stdio", "command": "python3",
        "args": ["/opt/glove/ext/search/searxng_mcp.py"], "env": {"SEARXNG_URL": "http://glove-s-search:8080"},
    }]
    assert "/opt/glove/ext/search/searxng_mcp.py" in plan.derived_dockerfile


def test_sidecars_networks_and_mounts(tmp_path):
    cfg = make_cfg(name="s", workdir=str(tmp_path), extensions={"direct": {}, "search": {}})
    _, text = render(cfg, tmp_path)
    svcs = yaml.safe_load(text)["services"]
    sx, vk = svcs["glove-s-searxng"], svcs["glove-s-valkey"]
    assert set(sx["networks"]) == {"glove-s-egress", "glove-s-searchnet"}
    assert set(vk["networks"]) == {"glove-s-searchnet"}  # valkey never on egress
    bind = next(v for v in sx["volumes"] if v["type"] == "bind")
    assert bind["target"] == "/etc/searxng" and bind["read_only"] is True
    assert bind["source"].endswith("ext/search/searxng")
    for svc in (sx, vk):
        assert "@sha256:" in svc["image"] and svc["read_only"] is True and svc["cap_drop"] == ["ALL"]


def _settings(tmp_path, egress=("direct", {}), **settings):
    plan = _plan(tmp_path, egress=egress, **settings)
    materialize(plan.composition)
    d = tmp_path / "x" / "search"
    return yaml.safe_load((d / "searxng" / "settings.yml").read_text()), d


def test_materialize_renders_settings_through_the_egress_proxy(tmp_path):
    doc, d = _settings(tmp_path)
    assert doc["outgoing"]["proxies"] == {"all://": ["http://glove-s-direct-proxy:8888"]}
    assert doc["outgoing"]["using_tor_proxy"] is False
    assert doc["valkey"]["url"] == "valkey://glove-s-valkey:6379/0"
    key = (d / "secret_key").read_text()
    assert doc["server"]["secret_key"] == key and len(key) == 64
    assert stat.S_IMODE((d / "secret_key").stat().st_mode) == 0o600
    assert "google" in doc["use_default_settings"]["engines"]["remove"]  # security_mode group
    # the key is generated once per session
    doc2, _ = _settings(tmp_path)
    assert doc2["server"]["secret_key"] == key


def test_tor_route_uses_the_tor_base_and_privoxy(tmp_path):
    doc, _ = _settings(tmp_path, egress=("tor", {}))
    assert doc["outgoing"]["proxies"] == {"all://": ["http://glove-s-privoxy:8118"]}
    # SearXNG's Tor mode needs socks5h://; the longer timeouts come from tor.yml
    assert doc["outgoing"]["using_tor_proxy"] is False
    assert doc["outgoing"]["request_timeout"] == 13.0
    assert any(e["name"] == "duckduckgo" and e["disabled"] for e in doc["engines"])


def test_groups_and_engine_overrides():
    hooks = load_module(Path(__file__).parents[1] / "hooks.py", "search")
    all_on = dict.fromkeys(hooks.GROUPS, True)
    removed = hooks.remove_list(all_on, {"google": "enable", "qwant": "disable"})
    assert "google" not in removed and "qwant" in removed and "bing" in removed
    assert hooks.remove_list(dict.fromkeys(hooks.GROUPS, False), {}) == []
    with pytest.raises(ValueError, match=r"enable\|disable"):
        hooks.remove_list(all_on, {"google": "yes"})
    with pytest.raises(ValueError, match="unknown group"):
        hooks.remove_list({"nope": True}, {})


def test_bad_engine_override_fails_at_plan_time(tmp_path):
    with pytest.raises(ValueError, match="enable\\|disable"):
        _plan(tmp_path, engines={"google": "maybe"})
