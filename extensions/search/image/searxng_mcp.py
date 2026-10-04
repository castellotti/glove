#!/usr/bin/env python3
"""MCP server exposing `web_search` backed by the session's private SearXNG.

Runs in the `search-mcp` sidecar and serves streamable HTTP on :8000 (stateless,
plain JSON responses), which the harness reaches through the `search-mcp`
forwarder. It only ever talks to SearXNG on the extension's internal network,
never the open internet. Requests must name the forwarder as their Host
(`MCP_ALLOWED_HOST`): anything else is refused, as with the Playwright MCP.
Mirrors Pi's web_search extension: it rate-limits and NEVER auto-retries on
429 — the shared exit IP is easily throttled.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

SEARXNG_URL = os.environ.get("SEARXNG_URL", "http://localhost:8080").rstrip("/")
MIN_INTERVAL = float(os.environ.get("SEARXNG_MIN_INTERVAL", "2.0"))
ALLOWED_HOST = os.environ.get("MCP_ALLOWED_HOST", "")

mcp = FastMCP(
    "searxng", host="0.0.0.0", port=8000, stateless_http=True, json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True, allowed_hosts=[ALLOWED_HOST] if ALLOWED_HOST else [],
        allowed_origins=[]),
)
_last_call = 0.0


@mcp.tool()
def web_search(
    query: str,
    categories: str = "",
    time_range: str = "",
    language: str = "en",
    max_results: int = 10,
) -> str:
    """Search the web via a private SearXNG metasearch instance.

    Returns ranked results as `N. title / url / snippet`. `categories` is a
    comma list (general,news,science,images,videos,…); `time_range` is
    day|month|year. Routed through the sandbox's private search bridge.
    """
    global _last_call
    gap = time.time() - _last_call
    if gap < MIN_INTERVAL:
        time.sleep(MIN_INTERVAL - gap)

    params = {"q": query, "format": "json", "language": language}
    if categories:
        params["categories"] = categories
    if time_range:
        params["time_range"] = time_range
    url = f"{SEARXNG_URL}/search?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "glove-searxng-mcp"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return (
                "SearXNG rate-limited (HTTP 429). Do NOT retry immediately — "
                "wait and lower query cadence, or ask the operator."
            )
        return f"SearXNG error: HTTP {e.code}"
    except Exception as e:
        return f"SearXNG unreachable at {SEARXNG_URL}: {e}"
    finally:
        _last_call = time.time()

    results = (data.get("results") or [])[:max_results]
    if not results:
        return f"No results for: {query}"
    blocks = [
        f"{i}. {r.get('title', '')}\n   {r.get('url', '')}\n   {r.get('content', '')}"
        for i, r in enumerate(results, 1)
    ]
    engines = sorted({r.get("engine") for r in results if r.get("engine")})
    footer = f"\n\n[engines: {', '.join(engines)} | {len(results)} shown]"
    return "\n\n".join(blocks) + footer


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
