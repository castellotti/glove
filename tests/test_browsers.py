"""Browser provider tests — wiring generation + merge, no browser needed."""

from __future__ import annotations

import pytest

from glove.config import Config, Service
from glove.harnessconfig import service_base
from glove.plugins.browser import apply_browser, get_provider, known_providers, provider_name
from glove.plugins.browser.host_server import _minor


@pytest.fixture(autouse=True)
def _clear_chrome_cache():
    """discover_chrome() is process-cached; drop it so per-test monkeypatching
    of the discovery internals isn't shadowed by an earlier test's scan."""
    from glove.plugins.browser.chrome import discover_chrome

    discover_chrome.cache_clear()
    yield
    discover_chrome.cache_clear()


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
    # The provider declares the `browser` service; BROWSER_MCP_URL is derived
    # from it once, at plan time (not duplicated in the wiring env).
    assert "BROWSER_MCP_URL" not in w.env
    svc = w.services[0]
    assert f"http://glove-s-{svc.name}:{svc.port}/mcp" == "http://glove-s-browser:8931/mcp"
    pw = next(h for h in w.host_services if h.name == "playwright")
    assert "--allowed-hosts glove-s-browser:8931" in pw.command  # pinned to sidecar


def test_host_mcp_is_version_pinned():
    from glove.plugins.browser.host_mcp import PLAYWRIGHT_MCP_VERSION

    cfg = Config(harness="pi", browser={"provider": "host-mcp"})
    pw = next(h for h in get_provider("host-mcp").wiring(cfg, "s").host_services if h.name == "playwright")
    assert f"playwright-core@{PLAYWRIGHT_MCP_VERSION} mcp " in pw.command
    assert "@latest" not in pw.command
    assert "@playwright/mcp" not in pw.command


def test_host_server_uses_path_flag():
    # run-server has `--path`; `--ws-path` does not exist and the server would
    # not start. The path is the random ws-path with a leading slash.
    cfg = Config(harness="pi", browser={"provider": "host-server", "ws_path": "pw-abc"})
    w = get_provider("host-server").wiring(cfg, "s")
    pw = next(h for h in w.host_services if h.name == "playwright")
    assert "--path /pw-abc" in pw.command
    assert "--ws-path" not in pw.command
    assert w.env["PLAYWRIGHT_WS_ENDPOINT"].endswith(":3000/pw-abc")


@pytest.mark.parametrize("provider", ["host-mcp", "host-server"])
def test_host_chrome_profile_is_per_session_and_not_kept(provider):
    cfg = Config(harness="pi", browser={"provider": provider})
    chrome = next(h for h in get_provider(provider).wiring(cfg, "s").host_services if h.name == "chrome")
    assert "--user-data-dir={chrome_profile}" in chrome.command  # per-session token (hostsvc)
    # A kept Chrome would own :9222 and be reused by the next session (profile
    # and all), so it is stopped on `glove down` unless the operator opts in.
    assert chrome.keep is False
    cfg = Config(harness="pi", browser={"provider": provider, "keep_browser": True})
    chrome = next(h for h in get_provider(provider).wiring(cfg, "s").host_services if h.name == "chrome")
    assert chrome.keep is True


def test_vibe_host_mcp_refused_without_ack():
    from glove.config import ConfigError

    cfg = Config(harness="vibe", browser={"provider": "host-mcp"})
    with pytest.raises(ConfigError, match="browser_run_code_unsafe"):
        get_provider("host-mcp").wiring(cfg, "s")
    with pytest.raises(ConfigError):
        apply_browser(Config(harness="vibe", browser={"provider": "host-mcp"}), "s")
    ok = Config(harness="vibe", browser={"provider": "host-mcp", "i_accept_host_rce": True})
    assert get_provider("host-mcp").wiring(ok, "s").services


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
    # BROWSER_MCP_URL is not injected into cfg.env by the provider; it's derived
    # from the declared `browser` service at plan time (single construction site).
    assert "BROWSER_MCP_URL" not in cfg.env
    assert f"{service_base(cfg, 's', 'browser')}/mcp" == "http://glove-s-browser:8931/mcp"


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
    import glove.plugins.browser.chrome as chrome

    suffix = "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
    fake = {
        chrome._CFT_GLOBS[0]: [
            f"/x/ms-playwright/chromium-1200/{suffix}",
            f"/x/ms-playwright/chromium-1243/{suffix}",
        ],
        chrome._CFT_GLOBS[1]: [],
    }
    monkeypatch.setattr(chrome.os.path, "expanduser", lambda p: p)
    monkeypatch.setattr(chrome.glob, "glob", lambda p: fake.get(p, []))
    assert "chromium-1243" in chrome.chrome_for_testing_path()


def test_host_mcp_doctor_guides_to_chrome_for_testing(monkeypatch):
    import glove.plugins.browser.chrome as chrome

    # No system Chrome, but Chrome for Testing present → ok + actionable guidance.
    monkeypatch.setattr(chrome.os.path, "exists", lambda p: False)
    monkeypatch.setattr(chrome, "chrome_for_testing_path", lambda: "/cache/.../Google Chrome for Testing")
    checks = get_provider("host-mcp").doctor(Config(harness="pi"))
    backend = next(c for c in checks if c.name == "browser host-mcp: browser")
    assert backend.status == "ok"
    assert "--executable-path" in backend.detail


def test_host_mcp_doctor_warns_when_no_browser(monkeypatch):
    import glove.plugins.browser.chrome as chrome

    monkeypatch.setattr(chrome.os.path, "exists", lambda p: False)
    monkeypatch.setattr(chrome, "chrome_for_testing_path", lambda: None)
    checks = get_provider("host-mcp").doctor(Config(harness="pi"))
    backend = next(c for c in checks if c.name == "browser host-mcp: browser")
    assert backend.status == "warn"
    assert "playwright install" in backend.detail


def test_minor_version_parse():
    assert _minor("Version 1.55.0") == "1.55"
    assert _minor("1.55.1") == "1.55"
    assert _minor("nope") is None
