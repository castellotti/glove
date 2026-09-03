"""Ring-0 runtime interface (PLAN §3.1).

A ``Runtime`` owns the container/VM boundary: image build, the mount
allow-list, network topology, resource limits, and the hardening set. It turns
a runtime-agnostic ``SessionPlan`` into a concrete ``RenderedProject`` and runs
it. ``docker`` is the full implementation in v2; ``podman`` subclasses it;
``apple-container``/``gondolin``/``utm`` are registered stubs so ``--runtime``
validation, ``glove ls`` and the docs are complete from day one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from ..plan import SessionPlan


@dataclass(frozen=True)
class RuntimeCaps:
    """Static capability flags used for validation, doctor, and docs."""

    supports_internal_networks: bool = False
    supports_sidecars: bool = False
    supports_seccomp_profile: bool = False
    supports_userns: bool = False
    supports_kvm: bool = False
    host_gateway_name: str | None = None
    compose_cmd: tuple[str, ...] = ()
    implemented: bool = False
    tested: bool = True  # False marks a backend we ship but cannot verify here


@dataclass
class Check:
    """One line in a ``glove doctor`` report."""

    name: str
    status: str  # "ok" | "warn" | "fail" | "skip" | "info"
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass(frozen=True)
class RenderedProject:
    """The concrete artifacts a runtime produces from a ``SessionPlan``."""

    session: str
    project: str
    compose_yaml: str
    project_dir: Path
    plan: SessionPlan

    @property
    def compose_file(self) -> Path:
        return self.project_dir / "docker-compose.yml"


@dataclass(frozen=True)
class RunningSession:
    project: str
    session: str
    services: list[str] = field(default_factory=list)
    status: str = ""


class Runtime(Protocol):
    name: str
    caps: RuntimeCaps

    def doctor(self) -> list[Check]: ...
    def render(self, plan: SessionPlan, project_dir: Path) -> RenderedProject: ...
    def ps(self) -> list[RunningSession]: ...
