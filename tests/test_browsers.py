"""Browser provider tests — wiring generation + merge, no browser needed."""

from __future__ import annotations

import pytest

from glove.browsers import apply_browser, get_provider, known_providers, provider_name
from glove.browsers.host_server import _minor
from glove.config import Config, Service


def test_registry():
    assert set(known_providers()) >= {"host-mcp", "host-server", "sidecar-desktop", "vm-desktop", "none"}
    assert get_provider("host-mcp").name == "host-mcp"
    assert get_provider("host-server").name == "host-server"


def test_stub_provider_raises():
    with pytest.raises(ValueError):
        get_provider("sidecar-desktop")


def test_host_mcp_wiring():
    cfg = Config(harness="pi", browser={"provider": "host-mcp", "port": 8931})
    w = get_provider("host-mcp").wiring(cfg, "s")
    assert [s.name for s in w.services] == ["browser"]
    assert w.services[0].to == "host.docker.internal:8931"
    assert {h.name for h in w.host_services} == {"chrome", "playwright"}
    assert w.env["BROWSER_MCP_URL"] == "http://glove-s-browser:8931/mcp"
    pw = next(h for h in w.host_services if h.name == "playwright")
    assert "@playwright/mcp" in pw.command
    assert "--allowed-hosts glove-s-browser:8931" in pw.command  # pinned to sidecar


def test_host_server_wiring_random_wspath():
    cfg = Config(harness="pi", browser={"provider": "host-server"})
    w = get_provider("host-server").wiring(cfg, "s")
    assert w.services[0].to == "host.docker.internal:3000"
    endpoint = w.env["PLAYWRIGHT_WS_ENDPOINT"]
    assert endpoint.startswith("ws://glove-s-browser:3000/pw-")
    pw = next(h for h in w.host_services if h.name == "playwright")
    assert "run-server" in pw.command


def test_apply_browser_merges_and_enables_service_net():
    cfg = Config(harness="pi", net=["none"], browser={"provider": "host-mcp"})
    apply_browser(cfg, "s")
    assert "service" in cfg.net  # forwarder sidecars now render
    assert any(s.name == "browser" for s in cfg.services)
    assert {h.name for h in cfg.host_services} == {"chrome", "playwright"}
    assert cfg.env["BROWSER_MCP_URL"] == "http://glove-s-browser:8931/mcp"


def test_apply_browser_manual_service_wins():
    # v1 backward compat: a hand-configured browser service is not duplicated.
    cfg = Config(harness="pi", browser={"provider": "host-mcp"})
    cfg.services = [Service(name="browser", to="host.docker.internal:8932", port=8932)]
    apply_browser(cfg, "s")
    browsers = [s for s in cfg.services if s.name == "browser"]
    assert len(browsers) == 1
    assert browsers[0].port == 8932  # manual kept


def test_apply_browser_none_noop():
    cfg = Config(harness="pi")
    before = list(cfg.services)
    apply_browser(cfg, "s")
    assert cfg.services == before
    assert provider_name(cfg) is None


def test_host_server_wspath_stable_after_apply():
    cfg = Config(harness="pi", browser={"provider": "host-server"})
    apply_browser(cfg, "s")
    ws1 = cfg.env["PLAYWRIGHT_WS_ENDPOINT"]
    # a second wiring call reuses the persisted ws-path
    ws2 = get_provider("host-server").wiring(cfg, "s").env["PLAYWRIGHT_WS_ENDPOINT"]
    assert ws1 == ws2


def test_chrome_for_testing_path_picks_newest(monkeypatch):
    import glove.browsers.host_mcp as hm

    fake = {
        hm._CFT_GLOBS[0]: [
            "/x/ms-playwright/chromium-1200/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            "/x/ms-playwright/chromium-1243/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        ],
        hm._CFT_GLOBS[1]: [],
    }
    monkeypatch.setattr(hm.os.path, "expanduser", lambda p: p)
    monkeypatch.setattr(hm.glob, "glob", lambda p: fake.get(p, []))
    assert "chromium-1243" in hm.chrome_for_testing_path()


def test_host_mcp_doctor_guides_to_chrome_for_testing(monkeypatch):
    import glove.browsers.host_mcp as hm

    # No system Chrome, but Chrome for Testing present → ok + actionable guidance.
    monkeypatch.setattr(hm.os.path, "exists", lambda p: False)
    monkeypatch.setattr(hm, "chrome_for_testing_path", lambda: "/cache/.../Google Chrome for Testing")
    checks = get_provider("host-mcp").doctor(Config(harness="pi"))
    backend = next(c for c in checks if c.name == "browser host-mcp: browser")
    assert backend.status == "ok"
    assert "--executable-path" in backend.detail


def test_host_mcp_doctor_warns_when_no_browser(monkeypatch):
    import glove.browsers.host_mcp as hm

    monkeypatch.setattr(hm.os.path, "exists", lambda p: False)
    monkeypatch.setattr(hm, "chrome_for_testing_path", lambda: None)
    checks = get_provider("host-mcp").doctor(Config(harness="pi"))
    backend = next(c for c in checks if c.name == "browser host-mcp: browser")
    assert backend.status == "warn"
    assert "playwright install" in backend.detail


def test_minor_version_parse():
    assert _minor("Version 1.55.0") == "1.55"
    assert _minor("1.55.1") == "1.55"
    assert _minor("nope") is None
