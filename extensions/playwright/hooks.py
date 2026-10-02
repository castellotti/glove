"""`playwright` hooks: the sidecar's MCP config, and host-mode wiring.

Sidecar modes (headless, novnc): `materialize` renders the MCP config the
sidecar reads (read-only) and creates its output/profile dirs. Host mode:
headed Chrome + the pinned Playwright MCP run on the host in tmux
(glove/hostsvc.py) on per-session loopback ports, and the `browser` endpoint
forwards to that MCP. The Chrome profile and MCP output live in this
session's extension state, never shared across sessions.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import socket
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
# The one Playwright pin: the sidecar image installs it from its lockfile and
# host mode runs the same version (`playwright-core mcp` ships the MCP, driver
# and browser build together since 1.62).
PLAYWRIGHT_VERSION = json.loads((HERE / "image" / "package.json").read_text())["dependencies"]["playwright-core"]
PLAYWRIGHT_MCP = f"playwright-core@{PLAYWRIGHT_VERSION}"
PORTS_FILE = "host-ports.json"
# A second layer under the network one: no UDP (WebRTC) around the proxy.
CHROMIUM_ARGS = ["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
# `ca`: staged into this extension's state, bound read-only into the sidecar.
CA_FILE = "corporate-ca.pem"


def _chrome():
    path = HERE / "host" / "chrome.py"
    spec = importlib.util.spec_from_file_location("glove_ext_playwright_chrome", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def host_ports(ctx: dict[str, Any]) -> dict[str, int]:
    """This session's host MCP and CDP ports: the settings when given, else the
    ones recorded at the first launch, else two free loopback ports (recorded by
    `materialize`). Stable per session, so a kept Chrome is found again."""
    s = ctx["settings"]
    recorded = Path(ctx["state"]) / PORTS_FILE
    try:
        saved = json.loads(recorded.read_text())
    except (OSError, ValueError):
        saved = {}
    mcp = s["port"] or saved.get("mcp") or _free_port()
    cdp = s["cdp_port"] or saved.get("cdp") or _free_port()
    while cdp == mcp:
        cdp = _free_port()
    return {"mcp": int(mcp), "cdp": int(cdp)}


def corporate_ca(ctx: dict[str, Any]) -> Path | None:
    """The `ca` setting as a validated host path (sidecar modes only: host mode
    runs the host's Chrome, which already has the host's trust store). The same
    checks as the harness's `corporate_ca` (glove/cafile.py)."""
    from glove.cafile import resolve_ca_file

    s = ctx["settings"]
    if not s.get("ca") or s["mode"] == "host":
        return None
    return resolve_ca_file("playwright.ca", s["ca"], ctx.get("session_dir"))


def contribute(ctx: dict[str, Any]) -> dict[str, Any]:
    s = ctx["settings"]
    if s["mode"] != "host":
        corporate_ca(ctx)  # fail at plan time (`glove check`), not at `up`
        return {}
    ports = host_ports(ctx)
    state = Path(ctx["state"])
    exe = _chrome().chrome_executable() or _chrome().DEFAULT_CHROME
    host = f"glove-{ctx['session']['id']}-browser"
    return {
        "exports": {"host_ports": ports},
        "endpoints": {
            "browser": {"port": 8931, "target": {"host_port": ports["mcp"]}, "observe": {"tool": "browser"}},
        },
        "host_services": [
            {
                "name": "chrome",
                "command": (f'"{exe}" --remote-debugging-port={ports["cdp"]} '
                            f"--user-data-dir={state / 'host-profile'} --no-first-run --no-default-browser-check"),
                "ready_port": ports["cdp"],
                "keep": s["keep_browser"],
            },
            {
                "name": "mcp",
                "command": (f"npx -y {PLAYWRIGHT_MCP} mcp --host 127.0.0.1 --port {ports['mcp']} "
                            f"--allowed-hosts {host}:{ports['mcp']} --cdp-endpoint http://127.0.0.1:{ports['cdp']} "
                            f"--shared-browser-context --output-dir {state / 'output'}"),
                "ready_port": ports["mcp"],
            },
        ],
    }


def mcp_config(settings: dict[str, Any]) -> dict[str, Any]:
    """The sidecar MCP's config file: what the agent cannot choose."""
    args = list(CHROMIUM_ARGS)
    if settings["mode"] == "novnc":  # headed: fill the VNC display
        w, h = settings["viewport"].split("x")
        args += [f"--window-size={w},{h}", "--window-position=0,0"]
    return {"browser": {"contextOptions": {"timezoneId": settings["timezone"], "locale": settings["locale"]},
                        "launchOptions": {"args": args}}}


def materialize(ctx: dict[str, Any]) -> None:
    s = ctx["settings"]
    state = Path(ctx["state_dir"])
    (state / "output").mkdir(mode=0o700, exist_ok=True)
    if s["mode"] == "host":
        ports = ctx["slot"]["browser"]["host_ports"]
        (state / PORTS_FILE).write_text(json.dumps(ports) + "\n")
        return
    (state / "mcp.json").write_text(json.dumps(mcp_config(s), indent=1) + "\n")
    ca = corporate_ca(ctx)
    if ca is not None:  # the fragment may bind only from this state dir
        shutil.copyfile(ca, state / CA_FILE)
        (state / CA_FILE).chmod(0o644)
    if s["profile"] == "session":
        (state / "profile").mkdir(mode=0o700, exist_ok=True)
    for setting, sub in (("downloads", "browser-output"), ("uploads", "browser-uploads")):
        if s[setting] == "work":
            if not ctx["work"]:
                raise ValueError(f"playwright.{setting}: work needs the session's work dir")
            Path(ctx["work"], sub).mkdir(exist_ok=True)


def doctor(ctx: dict[str, Any]) -> list[tuple[str, str, str]]:
    if ctx["settings"]["mode"] != "host":
        return []
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
