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

import shutil
from typing import TYPE_CHECKING

from ..config import HostService, Service
from .base import BrowserWiring, headed_chrome_service
from .chrome import discover_chrome

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


def _browser_backend_check():
    """One check line for the browser backend, with actionable guidance.

    ``@playwright/mcp``'s ``--browser`` only accepts channels
    (chrome/msedge/firefox/webkit) and defaults to the ``chrome`` channel = a
    system Google Chrome. When that is absent, the friction-free path is to point
    ``--executable-path`` at Playwright's own Chrome for Testing; surface it.
    """
    from ..runtimes.base import Check

    path, kind = discover_chrome()
    if kind == "system":
        return Check("browser host-mcp: browser", "ok", f"system Chrome/Chromium ({path})")
    if kind == "cft":
        return Check(
            "browser host-mcp: browser",
            "ok",
            "no system Google Chrome — use Chrome for Testing via "
            f"--executable-path '{path}' (see docs/pi-remote-llm.md)",
        )
    return Check(
        "browser host-mcp: browser",
        "warn",
        "no Google Chrome and no Playwright browser found — run "
        "`npx playwright install chromium` (see docs/pi-remote-llm.md)",
    )
