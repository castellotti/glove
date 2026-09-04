"""Runtime registry. ``get_runtime(name)`` returns the backend."""

from __future__ import annotations

from .base import Check, RenderedProject, RunningSession, Runtime, RuntimeCaps
from .docker import DockerRuntime
from .podman import PodmanRuntime
from .stubs import AppleContainerRuntime, GondolinRuntime, UTMRuntime

_RUNTIMES: dict[str, type] = {
    "docker": DockerRuntime,
    "podman": PodmanRuntime,
    "apple-container": AppleContainerRuntime,
    "gondolin": GondolinRuntime,
    "utm": UTMRuntime,
}


def known_runtimes() -> list[str]:
    return list(_RUNTIMES)


def get_runtime(name: str):
    """Instantiate a runtime backend by name."""
    try:
        return _RUNTIMES[name]()
    except KeyError:
        raise ValueError(
            f"unknown runtime {name!r}; known: {', '.join(_RUNTIMES)}"
        ) from None


__all__ = [
    "Check",
    "RenderedProject",
    "RunningSession",
    "Runtime",
    "RuntimeCaps",
    "DockerRuntime",
    "PodmanRuntime",
    "get_runtime",
    "known_runtimes",
]
