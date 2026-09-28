"""Browser provider layer.

A ``BrowserProvider`` turns a compact ``browser:`` config block into the concrete
wiring the rest of glove already understands: host-side helpers (headed Chrome +
a Playwright MCP/server, run by ``hostsvc``), forwarder sidecars (the network
allow-list entry that bridges the harness to the host browser endpoint), the
harness env/MCP wiring, and an agent-facing context snippet.

The security rule that falls out of ring 1: the browser endpoint
hostname is in the *harness* policy allow-list but not the *tool* policy, so only
the harness's browser tool can drive it — a prompt-injected `curl` from a shell
command is ``--block-net`` and cannot reach it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from ...config import HostService, Service
from .chrome import DEFAULT_CHROME, chrome_executable

if TYPE_CHECKING:
    from ...config import Config
    from ...runtimes.base import Check


@dataclass
class BrowserWiring:
    """Everything a provider contributes to a session."""

    services: list[Service] = field(default_factory=list)  # forwarder sidecars
    host_services: list[HostService] = field(default_factory=list)  # host helpers
    env: dict[str, str] = field(default_factory=dict)  # harness env (endpoint URLs)
    context_note: str = ""  # agent-facing snippet for the context file


class BrowserProvider(Protocol):
    name: str

    def wiring(self, cfg: Config, session: str) -> BrowserWiring:
        ...

    def doctor(self, cfg: Config) -> list[Check]:
        ...


# Shared host helper: a headed Chrome on the host with remote debugging, so both
# host-mcp (CDP) and host-server (connectOverCDP) can attach to the same browser
# the operator watches. Its profile ({chrome_profile}) is per session, so
# sessions never share cookies or logins. It is stopped on `glove down` unless
# `browser.keep_browser: true`: a kept Chrome still owns :9222, and the next
# session's host-service start would reuse it — profile and all.
#
# The binary is discovered on the host at wiring time (system Google Chrome, then
# Playwright's Chrome for Testing) rather than hardcoded, so this works on Linux
# and on a macOS host with only Chrome for Testing — the very setup `glove doctor`
# recommends. Falls back to the macOS system path only so the command is still
# well-formed when nothing is found (doctor will have warned).
def keep_browser(cfg: Config) -> bool:
    return bool((cfg.browser or {}).get("keep_browser", False))


def headed_chrome_service(keep: bool = False) -> HostService:
    chrome = chrome_executable() or DEFAULT_CHROME
    return HostService(
        name="chrome",
        command=(
            f'"{chrome}" '
            "--remote-debugging-port=9222 --user-data-dir={chrome_profile} "
            "--no-first-run --no-default-browser-check"
        ),
        ready_port=9222,
        keep=keep,
    )
