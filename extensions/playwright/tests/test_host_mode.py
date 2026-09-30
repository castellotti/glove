"""`playwright` host mode: pinned MCP, per-session profile and ports, refusals, wiring."""

from __future__ import annotations

import json

import pytest
from helpers import make_cfg

from glove.extensions import ExtensionError, materialize
from glove.plan import build_session_plan


def _plan(tmp_path, harness="pi", extra=None, **settings):
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness=harness, name="s", workdir=str(work),
                   extensions={"playwright": {"mode": "host", **settings}, **(extra or {})})
    return cfg, build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "ext"))


def _ports(cfg):
    hs = {h.name: h for h in cfg.host_services}
    return hs["playwright-mcp"].ready_port, hs["playwright-chrome"].ready_port


def test_host_services_are_pinned_and_per_session(tmp_path):
    cfg, plan = _plan(tmp_path)
    hs = {h.name: h for h in cfg.host_services}
    assert set(hs) == {"playwright-chrome", "playwright-mcp"}
    mcp_port, cdp_port = _ports(cfg)
    assert mcp_port != cdp_port and not {mcp_port, cdp_port} & {8931, 9222}  # free ports, per session
    mcp = hs["playwright-mcp"].command
    assert "npx -y playwright-core@1.63.0 mcp " in mcp
    assert "@latest" not in mcp and "@playwright/mcp" not in mcp
    assert f"--port {mcp_port} --allowed-hosts glove-s-browser:{mcp_port} " in mcp
    assert f"--cdp-endpoint http://127.0.0.1:{cdp_port} " in mcp
    assert f"--output-dir {tmp_path / 'ext' / 'playwright' / 'output'}" in mcp
    chrome = hs["playwright-chrome"]
    assert f"--remote-debugging-port={cdp_port} " in chrome.command
    assert f"--user-data-dir={tmp_path / 'ext' / 'playwright' / 'host-profile'}" in chrome.command
    assert chrome.keep is False
    assert "images" not in plan.derived_dockerfile if plan.derived_dockerfile else True


def test_ports_are_recorded_and_reused(tmp_path):
    cfg, plan = _plan(tmp_path)
    first = _ports(cfg)
    materialize(plan.composition)
    saved = json.loads((tmp_path / "ext" / "playwright" / "host-ports.json").read_text())
    assert (saved["mcp"], saved["cdp"]) == first
    cfg2, _ = _plan(tmp_path)
    assert _ports(cfg2) == first  # a kept Chrome is found again on the next launch


def test_ports_can_be_pinned(tmp_path):
    cfg, _ = _plan(tmp_path, port=8931, cdp_port=9222)
    assert _ports(cfg) == (8931, 9222)


def test_keep_browser_opt_in(tmp_path):
    cfg, _ = _plan(tmp_path, keep_browser=True)
    assert next(h for h in cfg.host_services if h.name == "playwright-chrome").keep is True


def test_harness_wiring(tmp_path):
    cfg, plan = _plan(tmp_path, tools=["browser_navigate", "browser_snapshot"])
    env = plan.environment
    assert env["BROWSER_MCP_URL"] == "http://glove-s-browser:8931/mcp"
    assert env["BROWSER_MCP_TOOLS"] == "browser_navigate,browser_snapshot"
    assert env["BROWSER_MODE"] == "host"
    fwd = next(s for s in plan.network.sidecars if s.role == "browser")
    assert fwd.target == f"host.docker.internal:{_ports(cfg)[0]}" and fwd.host_gateway
    assert "/opt/glove/ext/playwright/pi-extension" in plan.command
    assert not plan.composition.fragments[0][1].get("services")  # no sidecar
    assert "REAL Chrome on the operator's own desktop" in dict(plan.composition.rendered_briefs())["playwright"]


def test_vibe_refused_without_ack(tmp_path):
    with pytest.raises(ExtensionError, match="browser_run_code_unsafe"):
        _plan(tmp_path, harness="vibe")
    _, plan = _plan(tmp_path / "ok", harness="vibe", i_accept_host_rce=True)
    pw = next(s for s in plan.composition.vibe_mcp if s["name"] == "playwright")
    assert pw["url"] == "http://glove-s-browser:8931/mcp" and "browser_run_code_unsafe" not in pw["enabled_tools"]


@pytest.mark.parametrize("egress", ["vpn", "tor"])
def test_host_mode_refused_behind_an_anonymising_egress(tmp_path, egress):
    settings = {"vpn": {"provider": "mullvad", "wireguard_key": "env:WG_KEY"}, "tor": {}}[egress]
    with pytest.raises(ExtensionError, match="bypasses the session's vpn/tor egress"):
        _plan(tmp_path, extra={egress: settings})
    _plan(tmp_path / "direct", extra={"direct": {}})  # no anonymity to lose


def test_pi_extension_never_exposes_run_code_in_host_mode():
    from glove.extensions import IN_TREE_DIR

    src = (IN_TREE_DIR / "playwright" / "pi-extension" / "index.ts").read_text()
    assert 'process.env.BROWSER_MODE === "host"' in src
    assert 'ALLOW.delete("browser_run_code_unsafe")' in src
