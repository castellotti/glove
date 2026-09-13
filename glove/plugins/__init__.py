"""Plugin registry — the opt-in capabilities glove can compose into a session.

Empty until capabilities are ported (media → search → browser). The default
session enables no plugins, so the base image stays minimal. Naming an unknown
plugin fails loudly rather than silently doing nothing.
"""

from __future__ import annotations

from .base import ALL_HARNESSES, ImageLayer, Plugin

_REGISTRY: dict[str, Plugin] = {}


def register(plugin: Plugin) -> None:
    """Add a plugin to the registry (raises on a duplicate name)."""
    if plugin.name in _REGISTRY:
        raise ValueError(f"plugin {plugin.name!r} is already registered")
    _REGISTRY[plugin.name] = plugin


def _register_builtins() -> None:
    """Register the plugins glove ships with. Imported here (not at module top)
    so the shipped plugin modules can import from this package without a cycle."""
    from .media import MEDIA
    from .search import SEARCH

    for plugin in (MEDIA, SEARCH):
        register(plugin)


def get_plugin(name: str) -> Plugin:
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(known_plugins()) or "(none)"
        raise ValueError(
            f"unknown plugin {name!r}; known: {known}"
        ) from None


def known_plugins() -> list[str]:
    return sorted(_REGISTRY)


def resolve_plugins(names: list[str]) -> list[Plugin]:
    """Validate + dedupe a name list into plugins, preserving first-seen order."""
    seen: set[str] = set()
    resolved: list[Plugin] = []
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        resolved.append(get_plugin(name))
    return resolved


__all__ = [
    "ALL_HARNESSES",
    "ImageLayer",
    "Plugin",
    "get_plugin",
    "known_plugins",
    "register",
    "resolve_plugins",
]

_register_builtins()
