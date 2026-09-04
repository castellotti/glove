"""Hardening-set tests: one row per assertion + the refusal path."""

from __future__ import annotations

import dataclasses

import pytest

from glove.config import AddDir, Config
from glove.hardening import HardeningError, find_violations, validate_hardening
from glove.plan import build_session_plan


def _plan(tmp_path, **cfg_kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    cfg = Config(harness="pi", workdir=str(work), name="s", **cfg_kw)
    return build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "home"), uid=1000, gid=1000)


def _reharden(plan, **changes):
    return dataclasses.replace(plan, hardening=dataclasses.replace(plan.hardening, **changes))


def test_compliant_plan_has_no_violations(tmp_path):
    plan = _plan(tmp_path)
    assert find_violations(plan) == []
    validate_hardening(plan)  # does not raise


def test_row_user_must_be_nonroot(tmp_path):
    plan = _reharden(_plan(tmp_path), user="0:0", allow_root=False)
    keys = {v.key for v in find_violations(plan)}
    assert "user" in keys


def test_row_cap_drop_all(tmp_path):
    plan = _reharden(_plan(tmp_path), cap_drop=())
    assert "cap-drop" in {v.key for v in find_violations(plan)}


def test_row_cap_add_limited_to_ptrace(tmp_path):
    assert find_violations(_reharden(_plan(tmp_path), cap_add=("SYS_PTRACE",))) == []
    assert "cap-add" in {v.key for v in find_violations(_reharden(_plan(tmp_path), cap_add=("SYS_ADMIN",)))}


def test_row_no_new_privileges(tmp_path):
    assert "no-new-privileges" in {v.key for v in find_violations(_reharden(_plan(tmp_path), no_new_privileges=False))}


def test_row_read_only(tmp_path):
    assert "read-only" in {v.key for v in find_violations(_reharden(_plan(tmp_path), read_only=False))}


def test_row_seccomp_required(tmp_path):
    assert "seccomp" in {v.key for v in find_violations(_reharden(_plan(tmp_path), seccomp_profile=None))}


def test_row_ipc_private(tmp_path):
    assert "ipc" in {v.key for v in find_violations(_reharden(_plan(tmp_path), ipc="shareable"))}


def test_row_pids_limit(tmp_path):
    from glove.hardening import Limits

    plan = _reharden(_plan(tmp_path), limits=Limits(pids=0))
    assert "pids" in {v.key for v in find_violations(plan)}


def test_row_no_host_gateway_on_harness(tmp_path):
    plan = _plan(tmp_path, net=["lan"])  # lan sets harness host-gateway
    assert "host-gateway" in {v.key for v in find_violations(plan)}


def test_row_no_docker_sock_mount(tmp_path):
    sock = tmp_path / "docker.sock"
    sock.write_text("")
    plan = _plan(tmp_path, add_dirs=[AddDir(str(sock), "rw")])
    assert "docker-sock" in {v.key for v in find_violations(plan)}


def test_allow_root_keeps_everything_else(tmp_path):
    plan = _plan(tmp_path, allow_root=True)
    # root is permitted, but cap_drop/read_only/seccomp remain → compliant
    assert plan.hardening.user is None
    assert find_violations(plan) == []


def test_refusal_and_override(tmp_path):
    plan = _reharden(_plan(tmp_path), read_only=False)
    with pytest.raises(HardeningError):
        validate_hardening(plan)
    # naming the row waives it
    validate_hardening(plan, overrides=frozenset({"read-only"}))
