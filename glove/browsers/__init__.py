"""Browser provider registry + wiring merge (PLAN §6).

``apply_browser(cfg, session)`` expands a ``browser:`` config block into the
session's ``services`` (forwarder allow-list), ``host_services`` (host helpers),
and harness env. Manually-configured services/host_services of the same name win
(backward compatible with v1 configs that wire the browser by hand).
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from .base import BrowserProvider, BrowserWiring
from .host_mcp import HostMcpProvider
from .host_server import HostServerProvider

if TYPE_CHECKING:
    from ..config import Config

_PROVIDERS: dict[str, type] = {
    "host-mcp": HostMcpProvider,
    "host-server": HostServerProvider,
}

# Registered-but-unimplemented (spec only, PLAN §6/§9).
_STUBS = {
    "sidecar-desktop": "docs/browsers/sidecar-desktop.md",
    "vm-desktop": "docs/browsers/vm-desktop.md",
}


def known_providers() -> list[str]:
    return [*_PROVIDERS, *_STUBS, "none"]


def get_provider(name: str) -> BrowserProvider:
    if name in _STUBS:
        raise ValueError(f"browser provider {name!r} is spec-only — see {_STUBS[name]}")
    try:
        return _PROVIDERS[name]()
    except KeyError:
        raise ValueError(
            f"unknown browser provider {name!r}; known: {', '.join(known_providers())}"
        ) from None


def provider_name(cfg: Config) -> str | None:
    """The configured browser provider, or None when the browser is unused."""
    name = (cfg.browser or {}).get("provider")
    return name if name and name != "none" else None


def apply_browser(cfg: Config, session: str) -> Config:
    """Merge the browser provider's wiring into ``cfg`` (in place) and return it."""
    name = provider_name(cfg)
    if name is None:
        return cfg
    # Persist a stable random ws-path for host-server so env + notes agree.
    if name == "host-server" and not (cfg.browser or {}).get("ws_path"):
        cfg.browser["ws_path"] = f"pw-{secrets.token_hex(16)}"

    wiring = get_provider(name).wiring(cfg, session)

    # The browser endpoint is reached through a forwarder sidecar, so the session
    # must render service sidecars (net profile "service"); enable it if the
    # operator left the harness otherwise-offline.
    if wiring.services and "service" not in cfg.net:
        cfg.net = [p for p in cfg.net if p != "none"] + ["service"]

    have_services = {s.name for s in cfg.services}
    for svc in wiring.services:
        if svc.name not in have_services:
            cfg.services.append(svc)
    have_hosts = {h.name for h in cfg.host_services}
    for hs in wiring.host_services:
        if hs.name not in have_hosts:
            cfg.host_services.append(hs)
    for k, v in wiring.env.items():
        cfg.env.setdefault(k, v)
    return cfg


__all__ = [
    "BrowserProvider",
    "BrowserWiring",
    "apply_browser",
    "get_provider",
    "known_providers",
    "provider_name",
]
