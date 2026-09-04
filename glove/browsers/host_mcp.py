"""`host-mcp` browser provider — v1-proven, the v2 default.

Headed Chrome runs on the host; a Playwright MCP attaches to it via CDP and
listens on a loopback port; a forwarder sidecar bridges
``glove-<session>-browser:<port>`` → ``host.docker.internal:<port>``. Pi's baked
`browser` extension (reads ``BROWSER_MCP_URL``) and Vibe's auto-derived MCP
server both speak to that endpoint. `--allowed-hosts` is pinned to the sidecar
name and `--output-dir` lands screenshots in the collection media dir (v1
behavior).
"""

from __future__ import annotations

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
            "`browser_take_screenshot` with NO custom filename saves into your "
            "collection's media dir under /work."
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
        chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        import os

        checks.append(Check("browser host-mcp: Chrome", "ok" if os.path.exists(chrome) else "warn",
                            chrome if os.path.exists(chrome) else "Google Chrome not found at the default path"))
        return checks
