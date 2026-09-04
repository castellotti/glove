"""Network-plan tests: net profiles + declared services → sidecars."""

from __future__ import annotations

import pytest

from glove.config import Config, ConfigError, Service
from glove.network import build_network_plan


def _cfg(**kw) -> Config:
    return Config(harness="pi", name="s", **kw)


def test_declared_service_without_service_profile_errors():
    # Security default is no network: a declared service without the `service`
    # net profile is a contradiction. It used to be silently dropped (while the
    # harness config still pointed at the dead endpoint); now it fails loudly
    # rather than silently dropping OR auto-granting network.
    cfg = _cfg()  # net defaults to ["none"]
    cfg.services = [Service(name="llm", to="host.docker.internal:8899", port=8080)]
    with pytest.raises(ConfigError, match=r"net.*does not permit"):
        build_network_plan(cfg, "s")


def test_declared_service_renders_with_service_profile():
    cfg = _cfg(net=["service"])
    cfg.services = [Service(name="llm", to="host.docker.internal:8899", port=8080)]
    plan = build_network_plan(cfg, "s")
    assert [s.role for s in plan.sidecars] == ["llm"]
    assert plan.sidecars[0].listen_port == 8080


def test_service_join_network_becomes_external():
    cfg = _cfg(net=["service"])
    cfg.services = [Service(name="search", to="searxng:8080", join_network="my-net")]
    plan = build_network_plan(cfg, "s")
    assert "my-net" in plan.external_networks


def test_no_services_no_sidecars():
    plan = build_network_plan(_cfg(), "s")
    assert plan.sidecars == []
