"""`playwright` hooks: the sidecar's MCP config, and host-mode wiring.

Sidecar modes (headless, novnc): `materialize` renders the MCP config the
sidecar reads (read-only) and creates its output, profile and staging dirs. Host mode:
headed Chrome + the pinned Playwright MCP run on the host in tmux
(host/services.py: `launch_env` starts them, `teardown` stops them) on
per-session loopback ports, and the `browser` endpoint forwards to that
MCP. The Chrome profile and MCP output live in this session's extension
state, never shared across sessions.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from glove.api import HookContext, hook, scoped

from . import capture
from .host import chrome
from .host import login as lg
from .host import services as hs

HERE = Path(__file__).parent
# The one Playwright pin: the sidecar image installs it from its lockfile and
# host mode runs the same version (`playwright-core mcp` ships the MCP, driver
# and browser build together since 1.62).
PLAYWRIGHT_VERSION = json.loads((HERE / "image" / "package.json").read_text())["dependencies"]["playwright-core"]
PLAYWRIGHT_MCP = f"playwright-core@{PLAYWRIGHT_VERSION}"
PORTS_FILE = "host-ports.json"
SERVICES = ("chrome", "mcp")  # host_services', by name: `teardown` stops them without building them
# A second layer under the network one: no UDP (WebRTC) around the proxy.
CHROMIUM_ARGS = ["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
# Where Chromium stages a download (`<state>/downloading`, on disk) before the
# MCP copies it into the output dir (and then deletes it: image/glove-pw-staged.js):
# Playwright's default is under /tmp, a tmpfs that counts against the sidecar's memory.
STAGING = "/data/staging"
# novnc: raises the page each tool call acts on (image/glove-pw-front.js)
FRONT_PAGE = "/opt/glove/pw/glove-pw-front.js"


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
    return lg.spec(settings.get("login"), settings.get("storage_state"))


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


def host_ports(ctx: HookContext) -> dict[str, int]:
    """This session's host MCP and CDP ports: the settings when given, else the
    ones recorded at the first launch, else two free loopback ports (recorded by
    `materialize`). Stable per session, so a kept Chrome is found again."""
    s = ctx.settings
    recorded = ctx.state_dir / PORTS_FILE
    try:
        saved = json.loads(recorded.read_text())
    except (OSError, ValueError):
        saved = {}
    mcp = s["port"] or saved.get("mcp") or _free_port()
    cdp = s["cdp_port"] or saved.get("cdp") or _free_port()
    while cdp == mcp:
        cdp = _free_port()
    return {"mcp": int(mcp), "cdp": int(cdp)}


@hook
def contribute(ctx: HookContext) -> dict[str, Any]:
    s = ctx.settings
    login = login_spec(s)  # fail at plan time (`glove check`), not at `up` or `login`
    check_storage_state(s)
    capture.spec(s)
    if s["mode"] != "host":
        if not s.get("storage_state") or login is None:
            return {}
        # the signed-in hosts, for `glove check` against a filtering egress
        start = urlsplit(login.start_url).hostname or ""
        return {"egress_hosts": sorted({start, *login.domains} - {""})}
    ports = host_ports(ctx)
    # what `glove up` will run outside the sandbox: shown by `glove plan`/`policy`, kept in effective.yml
    ran = {f"runs on the host ({svc.name})": svc.command for svc in host_services(ctx, ports)}
    return {
        "exports": {"host_ports": ports, "resolved": ran},
        "endpoints": {
            "browser": {"port": 8931, "target": {"host_port": ports["mcp"]}, "observe": {"tool": "browser"}},
        },
    }


def host_services(ctx: HookContext, ports: dict[str, int]) -> list[hs.Service]:
    """Host mode's Chrome and the pinned MCP attached to it, on this session's ports."""
    state = ctx.state_dir
    exe = chrome.chrome_executable() or chrome.DEFAULT_CHROME
    host = scoped(ctx.session["id"], "browser")
    return [
        hs.Service("chrome", f'"{exe}" --remote-debugging-port={ports["cdp"]} --user-data-dir={state / "host-profile"} '
                             "--no-first-run --no-default-browser-check",
                   ports["cdp"]),
        hs.Service("mcp", f"npx -y {PLAYWRIGHT_MCP} mcp --host 127.0.0.1 --port {ports['mcp']} "
                          f"--allowed-hosts {host}:{ports['mcp']} --cdp-endpoint http://127.0.0.1:{ports['cdp']} "
                          f"--shared-browser-context --output-dir {state / 'output'}",
                   ports["mcp"]),
    ]


def mcp_config(settings: dict[str, Any]) -> dict[str, Any]:
    """The sidecar MCP's config file: what the agent cannot choose."""
    args = list(CHROMIUM_ARGS)
    browser: dict[str, Any] = {}
    if settings["mode"] == "novnc":  # headed: fill the VNC display
        w, h = settings["viewport"].split("x")
        args += [f"--window-size={w},{h}", "--window-position=0,0"]
        browser["initPage"] = [FRONT_PAGE]  # the operator sees the page the agent acts on
    # One browser for every MCP client: a harness that restarts (a new MCP session)
    # while its old session was never closed reuses it. A session profile's
    # clients share its one context (without this the second launch is refused:
    # "Browser is already in use for /data/profile"); an ephemeral profile's each
    # get their own, closed with the client (headed: a window each).
    return {"sharedBrowserContext": True,
            "browser": {"contextOptions": {"timezoneId": settings["timezone"], "locale": settings["locale"]},
                        "launchOptions": {"args": args, "downloadsPath": STAGING}, **browser}}


def chromium_policy(settings: dict[str, Any]) -> dict[str, Any]:
    """The sidecar Chromium's managed policy. A `javascript:` URL the agent
    navigates to runs its script in the current page (whose title, and so
    whatever the script puts there, the MCP returns): the same reach as
    `browser_evaluate`, so blocked unless that tool is allowed. The page's
    own handlers and links are unaffected."""
    return {} if "browser_evaluate" in settings["tools"] else {"URLBlocklist": ["javascript://*"]}


@hook
def materialize(ctx: HookContext) -> None:
    s = ctx.settings
    state = Path(ctx.state_dir)
    (state / "output").mkdir(mode=0o700, exist_ok=True)
    if s["mode"] == "host":
        ports = ctx.slot["browser"]["host_ports"]
        (state / PORTS_FILE).write_text(json.dumps(ports) + "\n")
        return
    (state / "mcp.json").write_text(json.dumps(mcp_config(s), indent=1) + "\n")
    (state / "chromium-policy.json").write_text(json.dumps(chromium_policy(s)) + "\n")
    if s["profile"] == "session":
        (state / "profile").mkdir(mode=0o700, exist_ok=True)
    # emptied by the sidecar as it starts (glove-pw-start), never here: a
    # sidecar from the last launch may still be running and using it
    (state / "downloading").mkdir(mode=0o700, exist_ok=True)


@hook
def launch_env(ctx: HookContext, resolve_secret) -> dict[str, Any]:
    s = ctx.settings
    out = {"env": state_env(s["storage_state"], resolve_secret)} if s.get("storage_state") else {}
    if s["mode"] == "host":  # after the secret: a bad reference starts nothing
        hs.start(host_services(ctx, ctx.slot["browser"]["host_ports"]), ctx.session["id"], ctx.state_dir)
    return out


@hook
def teardown(ctx: HookContext) -> None:
    # whatever the mode now: a session switched away from host mode may still run them;
    # none without the ports every host-mode launch records
    if not (ctx.state_dir / PORTS_FILE).exists():
        return
    hs.stop(SERVICES, ctx.session["id"], ctx.state_dir, keep=("chrome",) if ctx.settings["keep_browser"] else ())


@hook
def doctor(ctx: HookContext, probe) -> list[tuple[str, str, str]]:
    checks = []
    if ctx.settings.get("login"):
        path = chrome.chrome_executable()
        checks.append(("playwright login: browser", "ok" if path else "warn",
                       path or "no Chrome/Chromium found for `glove playwright login`"))
    try:
        rec = capture.spec(ctx.settings)
    except ValueError as e:
        checks.append(("playwright recording", "fail", str(e)))
        rec = None
    if rec is not None:
        d = capture.DIR
        where = f".glove/ext/playwright/{d}/" + (f" and browser-output/{d}/" if rec["to"] == "work" else "")
        checks.append(("playwright recording", "info",
                       f"`glove playwright record` records your pointer input (presses, drags, screenshots) as you "
                       f"use the browser, into {where}"))
    if ctx.settings["mode"] != "host":
        return checks
    for svc in host_services(ctx, ctx.slot["browser"]["host_ports"]):  # what `glove up` runs outside the sandbox
        checks.append((f"playwright host: {svc.name}", "info", svc.command))
    for tool in ("node", "npx"):
        p = shutil.which(tool)
        detail = p or f"absent — needed for {PLAYWRIGHT_MCP} mcp"
        checks.append((f"playwright host: {tool}", "ok" if p else "warn", detail))
    path, kind = chrome.discover_chrome()
    if kind == "system":
        checks.append(("playwright host: browser", "ok", f"system Chrome/Chromium ({path})"))
    elif kind == "cft":
        checks.append(("playwright host: browser", "ok", f"Chrome for Testing ({path})"))
    else:
        checks.append(("playwright host: browser", "warn",
                       "no Chrome/Chromium found — run `npx playwright install chromium`"))
    return checks
