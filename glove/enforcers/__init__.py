"""Enforcer registry. ``get_enforcer(name)`` returns the backend."""

from __future__ import annotations

from typing import Any

from . import srt
from .base import ENFORCER_DIR, Enforcer
from .none import NoneEnforcer
from .nono import NonoEnforcer
from .nono import policies as nono_policies
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


# `enforcer_options` sections, one per sandbox rather than per enforcer, so a
# session file holds under each enforcer that runs it (nono+srt reads both).
OPTION_SECTIONS: dict[str, dict[str, dict]] = {"nono": nono_policies.OPTIONS, "srt": srt.OPTIONS}


def enforcer_options(raw: Any) -> dict[str, dict[str, Any]]:
    """`enforcer_options` checked like extension settings (an unknown section or
    key, or a value of the wrong type, is refused) and filled with defaults."""
    from ..config import ConfigError
    from ..extensions import _coerce_setting

    if not isinstance(raw, dict) or set(raw) - set(OPTION_SECTIONS):
        raise ConfigError(f"enforcer_options takes the sections {sorted(OPTION_SECTIONS)}, got {raw!r}")
    out: dict[str, dict[str, Any]] = {}
    for section, specs in OPTION_SECTIONS.items():
        given = raw.get(section) or {}
        if not isinstance(given, dict) or set(given) - set(specs):
            raise ConfigError(f"enforcer_options.{section} takes {sorted(specs)}, got {given!r}")
        out[section] = {k: _coerce_setting(f"enforcer_options.{section}", k, spec, given.get(k, spec["default"]))
                        for k, spec in specs.items()}
    return out


def tools_run_browsers(enforcer: str, options: dict[str, dict[str, Any]]) -> bool:
    """Whether Chromium can start inside a shell command's sandbox: nono's tool
    profile needs `nono.browsers` (/proc); srt's and none always can. The nono
    policy and the agent's brief both ask this, from the normalized options."""
    return get_enforcer(enforcer).tool_sandbox != "nono" or options["nono"]["browsers"]
