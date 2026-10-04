"""Compose-render tests."""

from __future__ import annotations

import shutil
import subprocess

import pytest
import yaml
from helpers import make_cfg, render

from glove.config import AddDir


def _session_cfg(tmp_path):
    work = tmp_path / "vibe-local"
    work.mkdir()
    deliverable = tmp_path / "shared_lib"
    deliverable.mkdir()
    cfg = make_cfg(
        harness="vibe",
        workdir=str(work),
        name="vibe-local",
        add_dirs=[AddDir(str(deliverable), "rw")],
        extensions={"direct": {}, "search": {}},
    )
    return cfg, work


def test_render_is_valid_yaml(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    _, text = render(cfg, tmp_path, cwd=str(work))
    doc = yaml.safe_load(text)
    assert doc["name"] == "glove-vibe-local"
    services = doc["services"]
    assert "glove-vibe-local-harness" in services
    assert "glove-vibe-local-llm" in services
    assert "glove-vibe-local-search-mcp" in services


def test_harness_hardening_present(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    _, text = render(cfg, tmp_path, cwd=str(work))
    doc = yaml.safe_load(text)
    h = doc["services"]["glove-vibe-local-harness"]
    assert h["user"] == "501:20"
    assert h["cap_drop"] == ["ALL"]
    assert h["read_only"] is True
    assert "no-new-privileges:true" in h["security_opt"]
    # harness is on the internal net only
    assert h["networks"] == ["glove-vibe-local-net"]


def test_every_forwarder_is_hardened(tmp_path):
    # Plain socat forwarders get the same sidecar hardening set as the gates.
    cfg, work = _session_cfg(tmp_path)
    _, text = render(cfg, tmp_path, cwd=str(work))
    doc = yaml.safe_load(text)
    forwarders = {k: v for k, v in doc["services"].items() if v["image"].startswith("glove/forwarder:")}
    assert set(forwarders) == {f"glove-vibe-local-{r}" for r in ("llm", "search-mcp")}
    for name, svc in forwarders.items():
        assert svc["user"] == "501:20", name
        assert svc["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in svc["security_opt"], name
        assert svc["read_only"] is True, name
        assert svc["pids_limit"] and svc["mem_limit"], name
        assert "cap_add" not in svc and "privileged" not in svc, name


def test_protected_binds_render_read_only_after_work(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    (work / ".git" / "hooks").mkdir(parents=True)
    (work / ".git" / "config").write_text("")
    cfg.protect_ide_files = True
    from glove.plan import build_session_plan
    from glove.runtimes import get_runtime

    plan = build_session_plan(cfg, home_dir=str(tmp_path / "home"), cwd=str(work), uid=501, gid=20,
                              state_dir=str(tmp_path / "ext"))
    plan.placeholder_host_dir = str(tmp_path / "ph")
    doc = yaml.safe_load(get_runtime("docker").render(plan, tmp_path).compose_yaml)
    vols = doc["services"]["glove-vibe-local-harness"]["volumes"]
    targets = [v.get("target") for v in vols]
    for t in ("/work/.git/hooks", "/work/.git/config", "/work/.vscode", "/work/.envrc", "/work/.mcp.json"):
        v = vols[targets.index(t)]
        assert v["read_only"] is True, t
        assert targets.index(t) > targets.index("/work"), t  # nested bind overlays /work
    git = vols[targets.index("/work/.git")]
    assert not git.get("read_only") and targets.index("/work/.git") < targets.index("/work/.git/hooks")
    assert vols[targets.index("/work/.envrc")]["source"] == str(tmp_path / "ph" / ".envrc")


def test_internal_networks_and_forwarder_joins(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    _, text = render(cfg, tmp_path, cwd=str(work))
    doc = yaml.safe_load(text)
    nets = doc["networks"]
    assert nets["glove-vibe-local-net"]["internal"] is True
    assert not any(n.get("external") for n in nets.values())  # every network is the session's own
    # the search forwarder joins its target's private net; host-gateway ones the hostgw bridge
    search = doc["services"]["glove-vibe-local-search-mcp"]
    assert set(search["networks"]) == {"glove-vibe-local-net", "glove-vibe-local-searchnet"}
    llm = doc["services"]["glove-vibe-local-llm"]
    assert llm["extra_hosts"] == ["host.docker.internal:host-gateway"]
    assert set(llm["networks"]) == {"glove-vibe-local-net", "glove-vibe-local-hostgw"}


def test_allow_root_drops_only_the_user(tmp_path):
    # `allow_root` is an opt-out that runs as root but *keeps
    # everything else* — cap_drop, read-only rootfs, seccomp, limits all remain.
    cfg, work = _session_cfg(tmp_path)
    cfg.allow_root = True
    _, text = render(cfg, tmp_path, cwd=str(work))
    doc = yaml.safe_load(text)
    h = doc["services"]["glove-vibe-local-harness"]
    assert "user" not in h  # runs as root
    assert h["cap_drop"] == ["ALL"]  # but hardening is retained
    assert h["read_only"] is True
    assert any(s.startswith("seccomp=") for s in h["security_opt"])


def test_mounts_rendered_with_readonly(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    _, text = render(cfg, tmp_path, cwd=str(work))
    doc = yaml.safe_load(text)
    vols = doc["services"]["glove-vibe-local-harness"]["volumes"]
    binds = {v["target"]: v for v in vols if v["type"] == "bind"}
    assert binds["/work"].get("read_only") in (None, False)
    assert binds["/mnt/shared_lib"].get("read_only") in (None, False)  # added rw


@pytest.mark.skipif(not shutil.which("docker"), reason="docker not installed")
def test_docker_compose_config_parses(tmp_path):
    cfg, work = _session_cfg(tmp_path)
    _, text = render(cfg, tmp_path, cwd=str(work))
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(text)
    proc = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "config"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr


def test_the_merged_project_rechecks_the_harness_caps_and_security_opt(tmp_path):
    from glove.compose import validate_project
    from glove.extensions import ExtensionError

    plan, text = render(make_cfg(harness="pi", name="s", workdir=str(tmp_path)), tmp_path)
    validate_project(yaml.safe_load(text), plan, plan.composition)
    for key, value in (("cap_add", ["SYS_ADMIN"]), ("security_opt", ["no-new-privileges:true", "apparmor=unconfined"]),
                       ("security_opt", [f"seccomp={plan.hardening.seccomp_profile}"])):
        doc = yaml.safe_load(text)
        doc["services"][plan.harness_service][key] = value
        with pytest.raises(ExtensionError, match="hardening plan"):
            validate_project(doc, plan, plan.composition)


def test_a_harness_env_key_that_is_not_a_plain_name_refuses_to_render(tmp_path):
    import dataclasses

    from glove.hardening import HardeningError
    from glove.runtimes.docker import DockerRuntime

    plan, _ = render(make_cfg(harness="pi", name="s", workdir=str(tmp_path)), tmp_path)
    plan = dataclasses.replace(plan, environment={**plan.environment, "A: x\n      privileged": "true"})
    with pytest.raises(HardeningError, match="not a plain variable name"):
        DockerRuntime().render(plan, tmp_path)
