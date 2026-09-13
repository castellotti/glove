"""``browser`` plugin — drive a real Chromium on the host via Playwright.

Self-contained: the provider layer (`registry.py`, `base.py`, `host_mcp.py`,
`host_server.py`, `chrome.py`) that expands a `browser` provider block into host
services + a forwarder sidecar + harness env lives here, alongside the Pi
extension (`pi-extension/`, an MCP client Pi loads via `-e`) and the manifest.

Vibe has a native MCP client, so it reaches the same Playwright MCP endpoint via
an MCP server entry (`vibe_mcp`); Pi has none, so it loads the extension. Either
way the browser sidecar is reachable only by the harness's browser tool — shell
commands are `--block-net` under ring 1.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..base import ImageLayer, Plugin
from .base import BrowserProvider, BrowserWiring
from .registry import apply_browser, get_provider, known_providers, provider_name

if TYPE_CHECKING:
    from ...config import Config

_HERE = Path(__file__).parent
_PI_EXT_SRC = str(_HERE / "pi-extension")
PI_EXTENSION_PATH = "/opt/glove/pi-extensions/browser"


def _vibe_mcp(cfg: Config, session: str) -> list[dict[str, Any]]:
    """Vibe MCP server for the Playwright endpoint bridged in by the `browser`
    sidecar. Vibe's "http" transport speaks Streamable HTTP → the `/mcp` path."""
    from ...harnessconfig import service_base

    base = service_base(cfg, session, "browser")
    if not base:
        return []
    return [{"name": "playwright", "transport": "http", "url": f"{base}/mcp"}]


BROWSER = Plugin(
    name="browser",
    summary="drive a real Chromium on the host (Playwright)",
    image={
        # Pi: the MCP-client extension + its npm deps. Vibe uses its native MCP
        # client, so it needs no image contribution.
        "pi": ImageLayer(
            copy=((_PI_EXT_SRC, PI_EXTENSION_PATH),),
            run=(f"cd {PI_EXTENSION_PATH} && npm install --no-audit --no-fund",),
        ),
    },
    pi_extensions=(PI_EXTENSION_PATH,),
    requires_services=("browser",),
    vibe_mcp=_vibe_mcp,
)


__all__ = [
    "BROWSER",
    "BrowserProvider",
    "BrowserWiring",
    "apply_browser",
    "get_provider",
    "known_providers",
    "provider_name",
]
