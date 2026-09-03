"""`host-server` browser provider (PLAN §6) — Playwright server on the host.

``npx playwright run-server --host 127.0.0.1 --port <port> --ws-path <random>``
runs on the host; a forwarder bridges ``glove-<session>-browser:<port>`` → the
host. The agent's own code connects with
``chromium.connect("ws://glove-<session>-browser:<port>/<ws-path>")`` (endpoint
in ``$PLAYWRIGHT_WS_ENDPOINT``). Unlike host-mcp this needs the **playwright
package in the harness image**, and the client/server Playwright *minor* versions
must match — checked by ``doctor``. The ws-path is random per session so the
endpoint is unguessable even if the port is known.
"""

from __future__ import annotations

import re
import secrets
import shutil
import subprocess
from typing import TYPE_CHECKING

from ..config import HostService, Service
from .base import BrowserWiring, headed_chrome_service

if TYPE_CHECKING:
    from ..config import Config
    from ..runtimes.base import Check

DEFAULT_PORT = 3000
# Pin the Playwright version baked into the harness image; the host server must
# match this minor (client/server compatibility). Bump both together.
PLAYWRIGHT_VERSION = "1.55.0"


def _minor(v: str) -> str | None:
    m = re.search(r"(\d+)\.(\d+)", v)
    return f"{m.group(1)}.{m.group(2)}" if m else None


class HostServerProvider:
    name = "host-server"

    def _port(self, cfg: Config) -> int:
        return int((cfg.browser or {}).get("port") or DEFAULT_PORT)

    def wiring(self, cfg: Config, session: str) -> BrowserWiring:
        port = self._port(cfg)
        sidecar = f"glove-{session}-browser"
        ws_path = (cfg.browser or {}).get("ws_path") or f"pw-{secrets.token_hex(16)}"
        browser = Service(name="browser", to=f"host.docker.internal:{port}", port=port)
        server = HostService(
            name="playwright",
            command=(
                f"npx playwright@{PLAYWRIGHT_VERSION} run-server "
                f"--host 127.0.0.1 --port {port} --ws-path {ws_path}"
            ),
            ready_port=port,
        )
        endpoint = f"ws://{sidecar}:{port}/{ws_path}"
        note = (
            "- The web is reachable via a Playwright server on the operator's host. "
            f"Connect from your own code with `chromium.connect(process.env.PLAYWRIGHT_WS_ENDPOINT)` "
            f"(= `{endpoint}`). Only the browser tool path may reach it; shell `curl` cannot."
        )
        return BrowserWiring(
            services=[browser],
            host_services=[headed_chrome_service(), server],
            env={"PLAYWRIGHT_WS_ENDPOINT": endpoint},
            context_note=note,
        )

    def doctor(self, cfg: Config) -> list[Check]:
        from ..runtimes.base import Check

        checks: list[Check] = []
        npx = shutil.which("npx")
        checks.append(Check("browser host-server: npx", "ok" if npx else "warn", npx or "absent"))
        if npx:
            proc = subprocess.run(["npx", "playwright", "--version"], capture_output=True, text=True)
            host_v = proc.stdout.strip() or proc.stderr.strip()
            host_minor = _minor(host_v)
            want_minor = _minor(PLAYWRIGHT_VERSION)
            if host_minor and host_minor == want_minor:
                checks.append(Check("browser host-server: playwright version", "ok", f"host {host_v} matches image {PLAYWRIGHT_VERSION}"))
            elif host_minor:
                checks.append(Check("browser host-server: playwright version", "fail",
                                    f"host {host_v} != image {PLAYWRIGHT_VERSION} (minor must match for connect())"))
            else:
                checks.append(Check("browser host-server: playwright version", "warn",
                                    f"host playwright not found; install playwright@{PLAYWRIGHT_VERSION}"))
        checks.append(Check("browser host-server: image", "info",
                            f"harness image must include playwright@{PLAYWRIGHT_VERSION} (pip/npm)"))
        return checks
