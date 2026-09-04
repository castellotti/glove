"""Registered-but-unimplemented runtimes.

These exist so ``--runtime`` validation and ``glove ls`` are complete from day
one. Each declares its ``RuntimeCaps`` and raises ``NotImplementedError`` with a
short description of the backend it will map to.
"""

from __future__ import annotations

from pathlib import Path

from .base import Check, RenderedProject, RunningSession, RuntimeCaps

if False:  # typing only
    from ..plan import SessionPlan


class _StubRuntime:
    name = "stub"
    caps = RuntimeCaps(implemented=False, tested=False)
    _desc = "registered but not implemented"

    def render(self, plan: "SessionPlan", project_dir: Path) -> RenderedProject:  # noqa: F821
        raise NotImplementedError(
            f"runtime {self.name!r} is not implemented yet ({self._desc})"
        )

    def ps(self) -> list[RunningSession]:
        return []

    def doctor(self) -> list[Check]:
        return [Check(f"runtime {self.name}", "info", f"stub — not implemented ({self._desc})")]


class AppleContainerRuntime(_StubRuntime):
    name = "apple-container"
    caps = RuntimeCaps(
        supports_internal_networks=True,
        supports_sidecars=False,  # no compose; glove would orchestrate itself
        supports_kvm=True,
        host_gateway_name=None,
        implemented=False,
        tested=False,
    )
    _desc = "one lightweight VM per container; macOS 26, Apple silicon"


class GondolinRuntime(_StubRuntime):
    name = "gondolin"
    caps = RuntimeCaps(
        supports_internal_networks=False,
        supports_sidecars=False,
        supports_kvm=True,
        implemented=False,
        tested=False,
    )
    _desc = "microVM peer of Docker; mapped-TCP egress, no UDP"


class UTMRuntime(_StubRuntime):
    name = "utm"
    caps = RuntimeCaps(
        supports_internal_networks=True,
        supports_sidecars=True,
        supports_kvm=True,
        implemented=False,
        tested=False,
    )
    _desc = "Linux VM running the same image under podman, over SSH/utmctl"
