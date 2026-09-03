"""Compose-render tests (DESIGN.md A.7 + Verification: --dry-run parses)."""

from __future__ import annotations

import shutil
import subprocess

import pytest
import yaml

from glove.compose import render_compose
from glove.config import AddDir, Config, Service


def _session_cfg(tmp_path):
    work = tmp_path / "vibe-local"
    work.mkdir()
    deliverable = tmp_path / "leeroy"
    deliverable.mkdir()
    cfg = Config(
        harness="vibe",
        workdir=str(work),
        name="vibe-local",
        net=["service"],
        add_dirs=[AddDir(str(deliverable), "rw")],
    )
    cfg.services = [
        Service(name="llm", to="host.docker.internal:8899", port=8080),
        Service(name="search", to="searxng:8080", join_network="local-llm_ai-net"),
        Service(name="browser", to="host.docker.internal:8931"),
    ]
    return cfg, work


def test_render_is_valid_yaml(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    result = render_compose(cfg, home_dir=str(tmp_path / "home"), cwd=str(work), uid=501, gid=20)
    doc = yaml.safe_load(result.compose_yaml)
    assert doc["name"] == "glove-vibe-local"
    services = doc["services"]
    assert "glove-vibe-local-harness" in services
    assert "glove-vibe-local-llm" in services
    assert "glove-vibe-local-search" in services
    assert "glove-vibe-local-browser" in services


def test_harness_hardening_present(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    result = render_compose(cfg, home_dir=str(tmp_path / "home"), cwd=str(work), uid=501, gid=20)
    doc = yaml.safe_load(result.compose_yaml)
    h = doc["services"]["glove-vibe-local-harness"]
    assert h["user"] == "501:20"
    assert h["cap_drop"] == ["ALL"]
    assert h["read_only"] is True
    assert "no-new-privileges:true" in h["security_opt"]
    # harness is on the internal net only
    assert h["networks"] == ["glove-vibe-local-net"]


def test_internal_network_and_external_ref(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    result = render_compose(cfg, home_dir=str(tmp_path / "home"), cwd=str(work), uid=501, gid=20)
    doc = yaml.safe_load(result.compose_yaml)
    nets = doc["networks"]
    assert nets["glove-vibe-local-net"]["internal"] is True
    assert nets["local-llm_ai-net"]["external"] is True
    # the search sidecar joins the external net; host-gateway sidecars don't
    search = doc["services"]["glove-vibe-local-search"]
    assert "local-llm_ai-net" in search["networks"]
    llm = doc["services"]["glove-vibe-local-llm"]
    assert llm["extra_hosts"] == ["host.docker.internal:host-gateway"]


def test_allow_root_relaxes_hardening(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    cfg.allow_root = True
    result = render_compose(cfg, home_dir=str(tmp_path / "home"), cwd=str(work), uid=501, gid=20)
    doc = yaml.safe_load(result.compose_yaml)
    h = doc["services"]["glove-vibe-local-harness"]
    assert "user" not in h
    assert "cap_drop" not in h


def test_mounts_rendered_with_readonly(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    result = render_compose(cfg, home_dir=str(tmp_path / "home"), cwd=str(work), uid=501, gid=20)
    doc = yaml.safe_load(result.compose_yaml)
    vols = doc["services"]["glove-vibe-local-harness"]["volumes"]
    binds = {v["target"]: v for v in vols if v["type"] == "bind"}
    assert binds["/work"].get("read_only") in (None, False)
    assert binds["/mnt/leeroy"].get("read_only") in (None, False)  # added rw


@pytest.mark.skipif(not shutil.which("docker"), reason="docker not installed")
def test_docker_compose_config_parses(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    result = render_compose(cfg, home_dir=str(tmp_path / "home"), cwd=str(work), uid=501, gid=20)
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(result.compose_yaml)
    proc = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "config"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
