"""`playwright` hooks: the sidecar's MCP config, and host-mode wiring.

Sidecar modes (headless, novnc): `materialize` renders the MCP config the
sidecar reads (read-only) and creates its output, profile and staging dirs. Host mode:
headed Chrome + the pinned Playwright MCP run on the host in tmux
(glove/hostsvc.py) on per-session loopback ports, and the `browser` endpoint
forwards to that MCP. The Chrome profile and MCP output live in this
session's extension state, never shared across sessions.
"""

from __future__ import annotations

import functools
import json
import re
import shutil
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
# Where Chromium stages a download (`<state>/downloading`, on disk) before the
# MCP copies it into the output dir: Playwright's default is under /tmp, a
# tmpfs that counts against the sidecar's memory.
STAGING = "/data/staging"


@functools.cache
def host_module(name: str):
    """A module of host/ (leaf modules: chrome, login, cdp)."""
    from glove.extensions import load_module

    return load_module(HERE / "host" / f"{name}.py", "playwright")


# With a stored session in the browser, the tools that read (or replace) its
# cookies and storage would hand them to the model: refused in `tools`. So are
# a request's details (its Cookie header), a trace (every request's headers,
# in the output dir: /work's with `downloads: work`) and routes (a body the
# agent writes, served as a signed-in origin's page, runs script there).
STATE_TOOLS = re.compile(r"browser_(cookie_\w+|localstorage_\w+|sessionstorage_\w+|storage_state|"
                         r"set_storage_state|evaluate|run_code_unsafe|network_request|start_tracing|"
                         r"route|unroute|route_list)")
# an env string tops out at 128 KB (Linux MAX_ARG_STRLEN)
STATE_ENV_MAX = 120_000


def login_spec(settings: dict[str, Any]):
    """`login` and `storage_state` checked (host/login.py), or None."""
    return host_module("login").spec(settings.get("login"), settings.get("storage_state"))


def check_storage_state(settings: dict[str, Any]) -> None:
    if not settings.get("storage_state"):
        return
    if settings["mode"] == "host":
        raise ValueError("playwright.storage_state: mode host runs your own Chrome, which has its own sessions; "
                         "storage_state seeds the sidecar's browser (mode headless or novnc)")
    if settings["profile"] != "ephemeral":
        raise ValueError("playwright.storage_state needs profile: ephemeral (a persistent profile ignores it, and "
                         "keeps its own sessions)")
    if settings["uploads"] == "work":
        # the MCP checks an upload's path as a string: a link the agent puts in
        # /work/browser-uploads could name the state file on the sidecar's tmpfs
        raise ValueError("playwright.storage_state: uploads: work could send the stored session itself to a page "
                         "(a link in /work/browser-uploads resolves inside the sidecar); use uploads: none")
    if bad := [t for t in settings["tools"] if STATE_TOOLS.fullmatch(t)]:
        raise ValueError(f"playwright.tools: {', '.join(bad)} would hand the stored session's cookies or storage "
                         "to the model; with storage_state they are refused")


def load_state(ref: str, resolve_secret) -> dict[str, Any]:
    """The stored session, checked to be a Playwright storage state."""
    try:
        state = json.loads(resolve_secret(ref))
    except ValueError:
        state = None
    if not isinstance(state, dict) or not isinstance(state.get("cookies"), list) or \
            not all(isinstance(c, dict) for c in state["cookies"]):
        raise ValueError(f"playwright.storage_state: {ref} holds no storage state; store one with "
                         "`glove playwright login`")
    return state


def state_env(ref: str, resolve_secret) -> dict[str, str]:
    """PW_STORAGE_STATE for the sidecar: the stored session, checked, gzip+base64."""
    import base64
    import gzip

    state = load_state(ref, resolve_secret)
    packed = base64.b64encode(gzip.compress(json.dumps(state, separators=(",", ":")).encode(), mtime=0)).decode()
    if len(packed) > STATE_ENV_MAX:
        raise ValueError(f"playwright.storage_state: {ref} is too large to hand over ({len(packed)} bytes packed); "
                         "narrow login.domains")
    return {"PW_STORAGE_STATE": packed}


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
    login = login_spec(s)  # fail at plan time (`glove check`), not at `up` or `login`
    check_storage_state(s)
    if s["mode"] != "host":
        corporate_ca(ctx)
        if not s.get("storage_state") or login is None:
            return {}
        # the signed-in hosts, for `glove check` against a filtering egress
        start = urlsplit(login.start_url).hostname or ""
        return {"egress_hosts": sorted({start, *login.domains} - {""})}
    ports = host_ports(ctx)
    state = Path(ctx["state"])
    chrome = host_module("chrome")
    exe = chrome.chrome_executable() or chrome.DEFAULT_CHROME
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
    # One browser context for every MCP client: a harness that restarts (a new MCP
    # session) while its old session was never closed reuses it. Without it a
    # session profile refuses the second launch ("Browser is already in use for
    # /data/profile") and an ephemeral one leaks a context per restart.
    return {"sharedBrowserContext": True,
            "browser": {"contextOptions": {"timezoneId": settings["timezone"], "locale": settings["locale"]},
                        "launchOptions": {"args": args, "downloadsPath": STAGING}}}


def chromium_policy(settings: dict[str, Any]) -> dict[str, Any]:
    """The sidecar Chromium's managed policy. A `javascript:` URL the agent
    navigates to runs its script in the current page (whose title, and so
    whatever the script puts there, the MCP returns): the same reach as
    `browser_evaluate`, so blocked unless that tool is allowed. The page's
    own handlers and links are unaffected."""
    return {} if "browser_evaluate" in settings["tools"] else {"URLBlocklist": ["javascript://*"]}


def materialize(ctx: dict[str, Any]) -> None:
    s = ctx["settings"]
    state = Path(ctx["state_dir"])
    (state / "output").mkdir(mode=0o700, exist_ok=True)
    if s["mode"] == "host":
        ports = ctx["slot"]["browser"]["host_ports"]
        (state / PORTS_FILE).write_text(json.dumps(ports) + "\n")
        return
    (state / "mcp.json").write_text(json.dumps(mcp_config(s), indent=1) + "\n")
    (state / "chromium-policy.json").write_text(json.dumps(chromium_policy(s)) + "\n")
    ca = corporate_ca(ctx)
    if ca is not None:  # the fragment may bind only from this state dir
        shutil.copyfile(ca, state / CA_FILE)
        (state / CA_FILE).chmod(0o644)
    if s["profile"] == "session":
        (state / "profile").mkdir(mode=0o700, exist_ok=True)
    # emptied by the sidecar as it starts (glove-pw-start), never here: a
    # sidecar from the last launch may still be running and using it
    (state / "downloading").mkdir(mode=0o700, exist_ok=True)


def launch_env(ctx: dict[str, Any], resolve_secret) -> dict[str, Any]:
    s = ctx["settings"]
    return {"env": state_env(s["storage_state"], resolve_secret)} if s.get("storage_state") else {}


def doctor(ctx: dict[str, Any]) -> list[tuple[str, str, str]]:
    checks = []
    if ctx["settings"].get("login"):
        path = host_module("chrome").chrome_executable()
        checks.append(("playwright login: browser", "ok" if path else "warn",
                       path or "no Chrome/Chromium found for `glove playwright login`"))
    if ctx["settings"]["mode"] != "host":
        return checks
    for tool in ("node", "npx"):
        p = shutil.which(tool)
        detail = p or f"absent — needed for {PLAYWRIGHT_MCP} mcp"
        checks.append((f"playwright host: {tool}", "ok" if p else "warn", detail))
    path, kind = host_module("chrome").discover_chrome()
    if kind == "system":
        checks.append(("playwright host: browser", "ok", f"system Chrome/Chromium ({path})"))
    elif kind == "cft":
        checks.append(("playwright host: browser", "ok", f"Chrome for Testing ({path})"))
    else:
        checks.append(("playwright host: browser", "warn",
                       "no Chrome/Chromium found — run `npx playwright install chromium`"))
    return checks
