"""Suite-wide fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_runtime_networks(monkeypatch):
    """Subnet allocation asks the container runtime which subnets are taken;
    unit tests must not depend on (or shell out to) the host's Docker."""
    from glove.runtimes.docker import DockerRuntime

    monkeypatch.setattr(DockerRuntime, "network_subnets", lambda self: {})


@pytest.fixture(autouse=True)
def _throwaway_glove_home(tmp_path_factory, monkeypatch):
    """Unit tests never touch the real ~/.glove: plans compute export-root paths
    under it, and materialising writes there. A test that needs a specific
    home sets GLOVE_HOME itself (this default is replaced)."""
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path_factory.mktemp("glove-home")))
