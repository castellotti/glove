"""`playwright` host mode: pinned MCP, per-session profile, Vibe refusal, wiring."""

from __future__ import annotations

import pytest
from helpers import make_cfg

from glove.extensions import ExtensionError
from glove.plan import build_session_plan


def _plan(tmp_path, harness="pi", **settings):
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness=harness, name="s", workdir=str(work), extensions={"playwright": settings})
    return cfg, build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "ext"))


def test_host_services_are_pinned_and_per_session(tmp_path):
    cfg, _ = _plan(tmp_path)
    hs = {h.name: h for h in cfg.host_services}
    assert set(hs) == {"playwright-chrome", "playwright-mcp"}
    mcp = hs["playwright-mcp"].command
    assert "npx -y playwright-core@1.63.0 mcp " in mcp
    assert "@latest" not in mcp and "@playwright/mcp" not in mcp
    assert "--allowed-hosts glove-s-browser:8931" in mcp
    assert f"--output-dir {tmp_path / 'ext' / 'playwright' / 'output'}" in mcp
    chrome = hs["playwright-chrome"]
    assert f"--user-data-dir={tmp_path / 'ext' / 'playwright' / 'host-profile'}" in chrome.command
    assert chrome.keep is False  # a kept Chrome would serve the next session on :9222


def test_keep_browser_opt_in(tmp_path):
    cfg, _ = _plan(tmp_path, keep_browser=True)
    assert next(h for h in cfg.host_services if h.name == "playwright-chrome").keep is True


def test_harness_wiring(tmp_path):
    _, plan = _plan(tmp_path, tools=["browser_navigate", "browser_snapshot"])
    env = plan.environment
    assert env["BROWSER_MCP_URL"] == "http://glove-s-browser:8931/mcp"
    assert env["BROWSER_MCP_TOOLS"] == "browser_navigate,browser_snapshot"
    assert env["BROWSER_MODE"] == "host"
    fwd = next(s for s in plan.network.sidecars if s.role == "browser")
    assert fwd.target == "host.docker.internal:8931" and fwd.host_gateway
    assert "/opt/glove/ext/playwright/pi-extension" in plan.command


def test_vibe_refused_without_ack(tmp_path):
    with pytest.raises(ExtensionError, match="browser_run_code_unsafe"):
        _plan(tmp_path, harness="vibe")
    _, plan = _plan(tmp_path / "ok", harness="vibe", i_accept_host_rce=True)
    assert {"name": "playwright", "transport": "http", "url": "http://glove-s-browser:8931/mcp"} in \
        plan.composition.vibe_mcp


def test_pi_extension_never_exposes_run_code_in_host_mode():
    from glove.extensions import IN_TREE_DIR

    src = (IN_TREE_DIR / "playwright" / "pi-extension" / "index.ts").read_text()
    assert 'process.env.BROWSER_MODE === "host"' in src
    assert 'ALLOW.delete("browser_run_code_unsafe")' in src
