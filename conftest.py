"""Suite-wide fixtures."""

from __future__ import annotations

import os

import pytest

# CLI output is matched as text: a shell's FORCE_COLOR would make rich colour it
# (splitting the words a test looks for). Before glove creates its consoles.
os.environ.pop("FORCE_COLOR", None)


@pytest.fixture(autouse=True)
def _umask_022():
    """Out-of-tree extension dirs another user could write are skipped: tests
    create theirs as a 022 umask does, whatever the host's (002 on Ubuntu)."""
    old = os.umask(0o022)
    yield
    os.umask(old)


@pytest.fixture(autouse=True)
def _no_runtime_networks(monkeypatch):
    """Subnet allocation asks the container runtime which subnets are taken;
    unit tests must not depend on (or shell out to) the host's Docker."""
    from glove.runtimes.docker import DockerRuntime

    monkeypatch.setattr(DockerRuntime, "network_subnets", lambda self: {})


@pytest.fixture(autouse=True)
def _no_landlock_probe(monkeypatch):
    """`glove up`/`plan` ask the runtime which bind mode Landlock needs (a
    container probe); unit tests get `native` without shelling out."""
    from glove.runtimes import landlock_mounts as lm
    from glove.runtimes.docker import DockerRuntime

    monkeypatch.setattr(DockerRuntime, "landlock_mounts",
                        lambda self, *, refresh=False: lm.MountMode("native", "stubbed in tests"))


@pytest.fixture(autouse=True)
def _no_podman_info(request, monkeypatch):
    """A Podman render asks `podman info` (rootless, SELinux, kernel) once per
    process: unit tests get no answer, as on a host without podman, whatever this
    host runs (test_host_info_* cover the probe)."""
    if not request.node.name.startswith("test_host_info_"):
        from glove.runtimes import podman

        monkeypatch.setattr(podman, "_probe_host_info", lambda cli: {})


@pytest.fixture(autouse=True)
def _throwaway_glove_home(tmp_path_factory, monkeypatch):
    """Unit tests never touch the real ~/.glove: plans compute export-root paths
    under it, and materialising writes there. A test that needs a specific
    home sets GLOVE_HOME itself (this default is replaced)."""
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path_factory.mktemp("glove-home")))


@pytest.fixture(autouse=True)
def _wide_console(monkeypatch):
    """No wrapping of long paths in CLI output assertions."""
    from glove import sessionops

    for c in (sessionops.console, sessionops.err):
        monkeypatch.setattr(c, "width", 400)


@pytest.fixture(autouse=True)
def _fresh_discovery():
    """`discover()` reads the extension dirs once per process: tests write theirs."""
    from glove.extensions import _discover

    _discover.cache_clear()


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A fresh GLOVE_HOME the test can inspect."""
    ghome = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(ghome))
    return ghome
