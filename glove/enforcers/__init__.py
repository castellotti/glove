"""Enforcer registry. ``get_enforcer(name)`` returns the backend."""

from __future__ import annotations

from .base import ENFORCER_DIR, Enforcer
from .none import NoneEnforcer
from .nono import NonoEnforcer
from .nono_srt import NonoSrtEnforcer
from .srt import SrtEnforcer

_ENFORCERS: dict[str, type] = {
    "nono": NonoEnforcer,
    "nono+srt": NonoSrtEnforcer,
    "srt": SrtEnforcer,
    "none": NoneEnforcer,
}


def known_enforcers() -> list[str]:
    return list(_ENFORCERS)


def get_enforcer(name: str):
    """Instantiate an enforcer backend by name."""
    try:
        return _ENFORCERS[name]()
    except KeyError:
        raise ValueError(
            f"unknown enforcer {name!r}; known: {', '.join(known_enforcers())}"
        ) from None


__all__ = [
    "ENFORCER_DIR",
    "Enforcer",
    "NoneEnforcer",
    "NonoEnforcer",
    "NonoSrtEnforcer",
    "SrtEnforcer",
    "get_enforcer",
    "known_enforcers",
]
