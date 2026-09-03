"""Enforcer registry (PLAN §4). ``get_enforcer(name)`` returns the backend."""

from __future__ import annotations

from .base import ENFORCER_DIR, Enforcer
from .none import NoneEnforcer
from .nono import NonoEnforcer

_ENFORCERS: dict[str, type] = {
    "nono": NonoEnforcer,
    "none": NoneEnforcer,
    # "srt": SrtEnforcer — Phase 4
}


def known_enforcers() -> list[str]:
    return list(_ENFORCERS) + ["srt"]  # srt is a documented, not-yet-wired option


def get_enforcer(name: str):
    """Instantiate an enforcer backend by name (PLAN §7.2 `enforcer:`)."""
    if name == "srt":
        raise ValueError("enforcer 'srt' is not wired yet (Phase 4); use nono or none")
    try:
        return _ENFORCERS[name]()
    except KeyError:
        raise ValueError(
            f"unknown enforcer {name!r}; known: {', '.join(known_enforcers())}"
        ) from None


__all__ = ["ENFORCER_DIR", "Enforcer", "NonoEnforcer", "NoneEnforcer", "get_enforcer", "known_enforcers"]
