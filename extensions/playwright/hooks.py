"""`playwright` hooks: host-mode wiring (headed Chrome + pinned Playwright MCP).

Both run on the host in tmux (glove/hostsvc.py). The Chrome profile and MCP
output live in this session's extension state, never shared across sessions.
"""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path
from typing import Any

# One pin for host mode (and, in M7, the sidecar image): `playwright-core mcp`
# ships the MCP, driver and browser build together (since 1.62).
PLAYWRIGHT_VERSION = "1.63.0"
PLAYWRIGHT_MCP = f"playwright-core@{PLAYWRIGHT_VERSION}"


def _chrome():
    path = Path(__file__).parent / "host" / "chrome.py"
    spec = importlib.util.spec_from_file_location("glove_ext_playwright_chrome", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def contribute(ctx: dict[str, Any]) -> dict[str, Any]:
    s = ctx["settings"]
    state = Path(ctx["state"])
    chrome = _chrome()
    exe = chrome.chrome_executable() or chrome.DEFAULT_CHROME
    host = f"glove-{ctx['session']['id']}-browser"
    return {"host_services": [
        {
            "name": "chrome",
            "command": (f'"{exe}" --remote-debugging-port={s["cdp_port"]} --user-data-dir={state / "host-profile"} '
                        "--no-first-run --no-default-browser-check"),
            "ready_port": s["cdp_port"],
            "keep": s["keep_browser"],
        },
        {
            "name": "mcp",
            "command": (f"npx -y {PLAYWRIGHT_MCP} mcp --host 127.0.0.1 --port {s['port']} "
                        f"--allowed-hosts {host}:{s['port']} --cdp-endpoint http://127.0.0.1:{s['cdp_port']} "
                        f"--shared-browser-context --output-dir {state / 'output'}"),
            "ready_port": s["port"],
        },
    ]}


def doctor(ctx: dict[str, Any]) -> list[tuple[str, str, str]]:
    checks = []
    for tool in ("node", "npx"):
        p = shutil.which(tool)
        detail = p or f"absent — needed for {PLAYWRIGHT_MCP} mcp"
        checks.append((f"playwright host: {tool}", "ok" if p else "warn", detail))
    path, kind = _chrome().discover_chrome()
    if kind == "system":
        checks.append(("playwright host: browser", "ok", f"system Chrome/Chromium ({path})"))
    elif kind == "cft":
        checks.append(("playwright host: browser", "ok", f"Chrome for Testing ({path})"))
    else:
        checks.append(("playwright host: browser", "warn",
                       "no Chrome/Chromium found — run `npx playwright install chromium`"))
    return checks
