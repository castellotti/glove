"""Suite-wide fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_runtime_networks(monkeypatch):
    """Subnet allocation asks the container runtime which subnets are taken;
    unit tests must not depend on (or shell out to) the host's Docker."""
    from glove.runtimes.docker import DockerRuntime

    monkeypatch.setattr(DockerRuntime, "network_subnets", lambda self: {})
