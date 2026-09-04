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
        return BrowserWiring(
            services=[browser],
            host_services=[headed_chrome_service(), playwright],
            env={"BROWSER_MCP_URL": f"http://{sidecar}:{port}/mcp"},
            context_note=note,
        )

    def doctor(self, cfg: Config) -> list[Check]:
        from ..runtimes.base import Check

        checks = []
        for tool in ("node", "npx"):
            p = shutil.which(tool)
            checks.append(Check(f"browser host-mcp: {tool}", "ok" if p else "warn", p or "absent — needed for @playwright/mcp"))
        checks.append(_browser_backend_check())
        return checks


# The Chrome for Testing binary (Playwright's managed Chromium build) shipped in
# the ms-playwright cache; the standard headed browser for a no-system-Chrome host.
_CFT_GLOBS = (
    # macOS (chrome-mac / chrome-mac-arm64)
    "~/Library/Caches/ms-playwright/chromium-*/chrome-mac*/*.app/Contents/MacOS/Google Chrome for Testing",
    # Linux
    "~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome",
)


def chrome_for_testing_path() -> str | None:
    """Newest Playwright-managed Chrome for Testing binary on this host, or None."""
    hits: list[str] = []
    for pat in _CFT_GLOBS:
        hits += glob.glob(os.path.expanduser(pat))
    return sorted(hits)[-1] if hits else None


def _browser_backend_check():
    """One check line for the browser backend, with actionable guidance.

    ``@playwright/mcp``'s ``--browser`` only accepts channels
    (chrome/msedge/firefox/webkit) and defaults to the ``chrome`` channel = a
    system Google Chrome. When that is absent, the friction-free path is to point
    ``--executable-path`` at Playwright's own Chrome for Testing; surface it.
    """
    from ..runtimes.base import Check

    system_chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if os.path.exists(system_chrome):
        return Check("browser host-mcp: browser", "ok", f"system Google Chrome ({system_chrome})")
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
