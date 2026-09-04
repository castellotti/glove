"""Runtime layer tests (PLAN §3.1): registry, render, ps parsing, stubs."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from glove.config import Config
from glove.doctor import run_doctor
from glove.plan import build_session_plan
from glove.runtimes import get_runtime, known_runtimes
from glove.runtimes.docker import DockerRuntime
from glove.runtimes.stubs import AppleContainerRuntime


def _plan(tmp_path, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    cfg = Config(harness="pi", workdir=str(work), name="s", **kw)
    return build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "h"), uid=501, gid=20)


def test_registry_lists_all_backends():
    assert set(known_runtimes()) == {"docker", "podman", "apple-container", "gondolin", "utm"}
    assert get_runtime("docker").name == "docker"
    assert get_runtime("podman").caps.tested is False


def test_unknown_runtime_raises():
    with pytest.raises(ValueError):
        get_runtime("nope")


def test_docker_render_produces_hardened_compose(tmp_path):
    rendered = DockerRuntime().render(_plan(tmp_path), tmp_path)
    doc = yaml.safe_load(rendered.compose_yaml)
    h = doc["services"]["glove-s-harness"]
    assert h["cap_drop"] == ["ALL"]
    assert h["read_only"] is True
    assert h["ipc"] == "private"
    assert h["pids_limit"] == 512
    assert any(s.startswith("seccomp=") for s in h["security_opt"])
    assert "no-new-privileges:true" in h["security_opt"]


def test_docker_render_refuses_bad_hardening(tmp_path):
    import dataclasses

    from glove.hardening import HardeningError

    plan = _plan(tmp_path)
    broken = dataclasses.replace(plan, hardening=dataclasses.replace(plan.hardening, read_only=False))
    with pytest.raises(HardeningError):
        DockerRuntime().render(broken, tmp_path)


def _run_ps(stdout: str):
    import types

    rt = DockerRuntime()
    fake = types.SimpleNamespace(returncode=0, stdout=stdout)

    import glove.runtimes.docker as mod

    orig_run = mod.subprocess.run
    orig_which = mod.shutil.which
    mod.subprocess.run = lambda *a, **k: fake
    mod.shutil.which = lambda _c: "/usr/bin/docker"
    try:
        return rt.ps()
    finally:
        mod.subprocess.run = orig_run
        mod.shutil.which = orig_which


def test_ps_groups_by_compose_project_label():
    # format is Names\tproject-label\tStatus; a dashed session name must survive.
    stdout = (
        "glove-ticket-1234-harness\tglove-ticket-1234\tUp 2 minutes\n"
        "glove-ticket-1234-llm\tglove-ticket-1234\tUp 2 minutes"
    )
    sessions = _run_ps(stdout)
    assert len(sessions) == 1
    assert sessions[0].session == "ticket-1234"
    assert sessions[0].project == "glove-ticket-1234"
    assert len(sessions[0].services) == 2


def test_ps_handles_compose_run_and_dashed_service():
    # `compose run` appends -run-<hash>; a service role (my-llm) contains a dash.
    # Both would break name-surgery but the project label keeps them grouped.
    stdout = (
        "glove-ticket-1234-harness-run-abcdef01\tglove-ticket-1234\tUp\n"
        "glove-ticket-1234-my-llm\tglove-ticket-1234\tUp"
    )
    sessions = _run_ps(stdout)
    assert len(sessions) == 1
    assert sessions[0].session == "ticket-1234"
    assert len(sessions[0].services) == 2


def test_ps_falls_back_to_name_without_label():
    # No project label (a non-compose container): derive project from the name.
    stdout = "glove-ticket-1234-harness\t\tUp"
    sessions = _run_ps(stdout)
    assert len(sessions) == 1
    assert sessions[0].session == "ticket-1234"


def test_stub_render_raises(tmp_path):
    with pytest.raises(NotImplementedError):
        AppleContainerRuntime().render(_plan(tmp_path), tmp_path)


def test_render_wraps_command_and_mounts_policies(tmp_path):
    plan = _plan(tmp_path, enforcer="nono")
    plan.policies_host_dir = str(tmp_path / "enforcer")
    doc = yaml.safe_load(DockerRuntime().render(plan, tmp_path).compose_yaml)
    h = doc["services"]["glove-s-harness"]
    # harness command is nono-wrapped
    assert h["command"][:2] == ["nono", "run"]
    # policies bind-mounted read-only at /etc/glove/enforcer
    binds = {v["target"]: v for v in h["volumes"] if v["type"] == "bind"}
    assert "/etc/glove/enforcer" in binds
    assert binds["/etc/glove/enforcer"]["read_only"] is True
    # enforcer env present
    assert h["environment"]["NONO_NO_PROXY"] == "localhost,127.0.0.1"


def test_render_none_enforcer_no_policies_mount(tmp_path):
    plan = _plan(tmp_path, enforcer="none")
    doc = yaml.safe_load(DockerRuntime().render(plan, tmp_path).compose_yaml)
    h = doc["services"]["glove-s-harness"]
    assert h["command"][0] == "pi"  # bare entry, not wrapped
    binds = {v["target"] for v in h["volumes"] if v["type"] == "bind"}
    assert "/etc/glove/enforcer" not in binds


def test_runtime_docs_exist_for_non_docker():
    docs = Path(__file__).parent.parent / "docs" / "runtimes"
    for name in ("podman", "apple-container", "gondolin", "utm"):
        assert (docs / f"{name}.md").is_file(), f"missing docs/runtimes/{name}.md"


def test_doctor_surfaces_untested_podman():
    from glove.doctor import run_doctor

    checks = run_doctor(runtime="podman", enforcer="nono", include_container_probes=False)
    assert any(c.status == "warn" and "UNTESTED" in c.detail for c in checks)


def test_doctor_surfaces_stub_runtime():
    from glove.doctor import run_doctor

    checks = run_doctor(runtime="gondolin", enforcer="none", include_container_probes=False)
    assert any("not implemented" in c.detail for c in checks)


def test_doctor_host_only_json_shape():
    checks = run_doctor(runtime="docker", enforcer="nono", include_container_probes=False)
    assert all({"name", "status", "detail"} <= set(c.to_dict()) for c in checks)
    # enforcer + file-sharing + host tools all present without touching docker
    names = {c.name for c in checks}
    assert "enforcer: nono" in names
    assert any(n.startswith("host tool") for n in names)
