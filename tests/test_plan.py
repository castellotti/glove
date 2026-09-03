"""SessionPlan tests (PLAN §3.1): resolution of Config → runtime-agnostic plan."""

from __future__ import annotations

import pytest

from glove.config import AddDir, Config
from glove.hardening import Limits
from glove.plan import build_session_plan
from glove.runtimes.seccomp import DEFAULT_PROFILE, NESTED_USERNS_PROFILE


def _cfg(tmp_path, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return Config(harness="pi", workdir=str(work), name="s", **kw)


def test_plan_basic_shape(tmp_path):
    plan = build_session_plan(_cfg(tmp_path), env_id="s", home_dir=str(tmp_path / "h"), uid=501, gid=20)
    assert plan.project == "glove-s"
    assert plan.harness_service == "glove-s-harness"
    assert plan.hardening.user == "501:20"
    assert plan.hardening.cap_drop == ("ALL",)
    assert plan.working_dir == "/work"


def test_nono_uses_default_seccomp(tmp_path):
    plan = build_session_plan(_cfg(tmp_path, enforcer="nono"), env_id="s", home_dir=str(tmp_path / "h"))
    assert plan.hardening.seccomp_profile == str(DEFAULT_PROFILE)
    assert plan.hardening.systempaths_unconfined is False


def test_srt_uses_nested_seccomp(tmp_path):
    # The srt *enforcer* is wired in Phase 4, but seccomp *selection* is ready:
    # test _seccomp_for directly so this doesn't depend on the enforcer backend.
    from glove.plan import _seccomp_for

    cfg = _cfg(tmp_path, enforcer="srt", enforcer_options={"srt": {"nested": "strong"}})
    profile, systempaths = _seccomp_for(cfg)
    assert profile == str(NESTED_USERNS_PROFILE)
    assert systempaths is True  # strong mode


def test_nono_wraps_harness_command(tmp_path):
    plan = build_session_plan(_cfg(tmp_path, enforcer="nono"), env_id="s", home_dir=str(tmp_path / "h"))
    assert plan.harness_command[:4] == ["nono", "run", "-s", "--allow-cwd"]
    assert plan.harness_command[-1] == "/opt/glove/pi-extensions/browser"  # original entry preserved
    assert set(plan.policies) == {"harness.json", "tool.json", "tool-wrapper.json"}


def test_none_enforcer_leaves_command_bare(tmp_path):
    plan = build_session_plan(_cfg(tmp_path, enforcer="none"), env_id="s", home_dir=str(tmp_path / "h"))
    assert plan.harness_command == list(plan.profile.entry)
    assert plan.policies == {}


def test_limits_flow_through(tmp_path):
    cfg = _cfg(tmp_path)
    cfg.limits = Limits(pids=100, memory="2g", cpus=1)
    plan = build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "h"))
    assert plan.hardening.limits.pids == 100
    assert plan.hardening.limits.memory == "2g"


def test_add_dir_modes(tmp_path):
    ro = tmp_path / "lib"
    ro.mkdir()
    plan = build_session_plan(
        _cfg(tmp_path, add_dirs=[AddDir(str(ro), "ro")]),
        env_id="s", home_dir=str(tmp_path / "h"),
    )
    ro_mounts = [m for m in plan.mounts if m.container_path.startswith("/mnt/")]
    assert ro_mounts and all(m.read_only for m in ro_mounts)
