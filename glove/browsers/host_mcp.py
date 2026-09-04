"""`host-mcp` browser provider — v1-proven, the v2 default.

Headed Chrome runs on the host; a Playwright MCP attaches to it via CDP and
listens on a loopback port; a forwarder sidecar bridges
``glove-<session>-browser:<port>`` → ``host.docker.internal:<port>``. Pi's baked
`browser` extension (reads ``BROWSER_MCP_URL``) and Vibe's auto-derived MCP
server both speak to that endpoint. `--allowed-hosts` is pinned to the sidecar
name and `--output-dir` points at a glove-managed host dir under the session
state (never the project working tree).
"""

from __future__ import annotations

import glob
import os
import shutil
from typing import TYPE_CHECKING

from ..config import HostService, Service
from .base import BrowserWiring, headed_chrome_service

if TYPE_CHECKING:
    from ..config import Config
    from ..runtimes.base import Check

DEFAULT_PORT = 8931


class HostMcpProvider:
    name = "host-mcp"

    def _port(self, cfg: Config) -> int:
        return int((cfg.browser or {}).get("port") or DEFAULT_PORT)

    def wiring(self, cfg: Config, session: str) -> BrowserWiring:
        port = self._port(cfg)
        sidecar = f"glove-{session}-browser"
        browser = Service(name="browser", to=f"host.docker.internal:{port}", port=port)
        playwright = HostService(
            name="playwright",
            command=(
                f"npx @playwright/mcp@latest --host 127.0.0.1 --port {port} "
                f"--allowed-hosts {sidecar}:{port} "
                "--cdp-endpoint http://127.0.0.1:9222 --shared-browser-context "
                "--output-dir {media_dir}"
            ),
            ready_port=port,
        )
        note = (
            "- Your `browser_*` tools drive a REAL Chromium on the operator's host "
            "(which has internet); that browser is the only way you reach the web. "
            "`browser_take_screenshot` returns the image to you directly — you do "
            "not need to read it from disk."
        )
        # No env here: BROWSER_MCP_URL is derived once, at plan time, from the
        # `browser` service declared above (see plan._service_env), so the
        # endpoint string has a single construction site.
        return BrowserWiring(
            services=[browser],
            host_services=[headed_chrome_service(), playwright],
            context_note=note,
        )

    def doctor(self, cfg: Config) -> list[Check]:
        from ..runtimes.base import Check

        checks = []
        for tool in ("node", "npx"):
            p = shutil.which(tool)
            checks.append(Check(
                f"browser host-mcp: {tool}", "ok" if p else "warn",
                p or "absent — needed for @playwright/mcp",
            ))
        checks.append(_browser_backend_check())
        return checks


# Well-known system Google Chrome / Chromium install locations, by platform. The
# headed browser glove drives on the host is discovered here (falling back to
# Chrome for Testing) so the browser feature works on macOS, Linux and Windows
# without a hardcoded path.
_SYSTEM_CHROME = (
    # macOS
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    # Linux
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/opt/google/chrome/chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    # Windows
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "C:/Program Files/Chromium/Application/chrome.exe",
)

# The Chrome for Testing binary (Playwright's managed Chromium build) shipped in
# the ms-playwright cache; the standard headed browser for a no-system-Chrome host.
_CFT_GLOBS = (
    # macOS (chrome-mac / chrome-mac-arm64)
    "~/Library/Caches/ms-playwright/chromium-*/chrome-mac*/*.app/Contents/MacOS/Google Chrome for Testing",
    # Linux
    "~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome",
    # Windows (%USERPROFILE%\AppData\Local\ms-playwright)
    "~/AppData/Local/ms-playwright/chromium-*/chrome-win*/chrome.exe",
)


def chrome_for_testing_path() -> str | None:
    """Newest Playwright-managed Chrome for Testing binary on this host, or None."""
    hits: list[str] = []
    for pat in _CFT_GLOBS:
        hits += glob.glob(os.path.expanduser(pat))
    return sorted(hits)[-1] if hits else None


def chrome_executable() -> str | None:
    """Best headed browser on this host, or None.

    Prefers a system Google Chrome / Chromium, then Playwright's Chrome for
    Testing. All three speak CDP on ``--remote-debugging-port``, which is what
    both browser providers attach to.
    """
    for path in _SYSTEM_CHROME:
        if os.path.exists(path):
            return path
    return chrome_for_testing_path()


def _browser_backend_check():
    """One check line for the browser backend, with actionable guidance.

    ``@playwright/mcp``'s ``--browser`` only accepts channels
    (chrome/msedge/firefox/webkit) and defaults to the ``chrome`` channel = a
    system Google Chrome. When that is absent, the friction-free path is to point
    ``--executable-path`` at Playwright's own Chrome for Testing; surface it.
    """
    from ..runtimes.base import Check

    system_chrome = next((p for p in _SYSTEM_CHROME if os.path.exists(p)), None)
    if system_chrome:
        return Check("browser host-mcp: browser", "ok", f"system Chrome/Chromium ({system_chrome})")
    cft = chrome_for_testing_path()
    if cft:
        return Check(
            "browser host-mcp: browser",
            "ok",
            "no system Google Chrome — use Chrome for Testing via "
            f"--executable-path '{cft}' (see docs/pi-remote-llm.md)",
        )
    return Check(
        "browser host-mcp: browser",
        "warn",
        "no Google Chrome and no Playwright browser found — run "
        "`npx playwright install chromium` (see docs/pi-remote-llm.md)",
    )
