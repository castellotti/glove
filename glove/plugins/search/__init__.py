"""``search`` plugin — web search via a private SearXNG instance.

A *client* of an external SearXNG the operator runs and bridges in with a
`search` forwarder sidecar; inert (and absent from the image) unless enabled.
This is the sandbox's replacement egress path for search — Vibe's native
`web_search`/`web_fetch` stay blocked by the ring-1 hook.

Per-harness wiring:
- **Pi** has no MCP client, so it loads a native extension (``-e``) that calls
  SearXNG directly, reading ``SEARXNG_URL`` from the container env.
- **Vibe** has a native MCP client, so it runs a small stdio MCP server
  (``searxng_mcp.py``) that exposes ``web_search``.

Both only ever talk to the ``search`` sidecar (``glove-<session>-search:<port>``),
never the open internet.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..base import ImageLayer, Plugin

if TYPE_CHECKING:
    from ...config import Config

_HERE = Path(__file__).parent
_PI_EXT_SRC = str(_HERE / "pi-extension")
_MCP_SRC = str(_HERE / "searxng_mcp.py")

PI_EXTENSION_PATH = "/opt/glove/pi-extensions/searxng"
MCP_PATH = "/opt/glove/searxng_mcp.py"


def _vibe_mcp(cfg: Config, session: str) -> list[dict[str, Any]]:
    """Vibe stdio MCP server for SearXNG, pointed at the `search` sidecar."""
    from ...harnessconfig import service_base

    base = service_base(cfg, session, "search")
    if not base:
        return []
    return [
        {
            "name": "searxng",
            "transport": "stdio",
            "command": "python3",
            "args": [MCP_PATH],
            "env": {"SEARXNG_URL": base},
        }
    ]


SEARCH = Plugin(
    name="search",
    summary="web search via a private SearXNG instance",
    image={
        # Pi: the native extension + its npm deps (jiti resolves them at runtime).
        "pi": ImageLayer(
            copy=((_PI_EXT_SRC, PI_EXTENSION_PATH),),
            run=(f"cd {PI_EXTENSION_PATH} && npm install --no-audit --no-fund",),
        ),
        # Vibe: the stdio MCP server + the v1 `mcp` SDK it imports.
        "vibe": ImageLayer(
            copy=((_MCP_SRC, MCP_PATH),),
            pip=("mcp<2",),
        ),
    },
    pi_extensions=(PI_EXTENSION_PATH,),
    requires_services=("search",),
    env_from_services={"SEARXNG_URL": "search"},
    vibe_mcp=_vibe_mcp,
)
