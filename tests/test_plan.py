"""SessionPlan tests: resolution of Config → runtime-agnostic plan."""

from __future__ import annotations

import pytest
from helpers import make_cfg

from glove import plan as plan_mod
from glove.config import AddDir, ConfigError
from glove.hardening import Limits
from glove.plan import build_session_plan, write_in_place
from glove.runtimes.seccomp import DEFAULT_PROFILE, NESTED_USERNS_PROFILE


def _cfg(tmp_path, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return make_cfg(harness="pi", workdir=str(work), name="s", **kw)


def test_plan_basic_shape(tmp_path):
    plan = build_session_plan(_cfg(tmp_path), home_dir=str(tmp_path / "h"), uid=501, gid=20)
    assert plan.project == "glove-s"
    assert plan.harness_service == "glove-s-harness"
    assert plan.hardening.user == "501:20"
    assert plan.hardening.cap_drop == ("ALL",)
    assert plan.working_dir == "/work"


def test_nono_uses_default_seccomp(tmp_path):
    plan = build_session_plan(_cfg(tmp_path, enforcer="nono"), home_dir=str(tmp_path / "h"))
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
    plan = build_session_plan(_cfg(tmp_path, enforcer="nono"), home_dir=str(tmp_path / "h"))
    assert plan.harness_command[:4] == ["nono", "run", "-s", "--allow-cwd"]
    assert plan.harness_command[-1] == "/opt/glove/pi-extensions/enforcer"  # original entry preserved
    assert set(plan.policies) == {"harness.json", "tool.json", "tool-wrapper.json", "tool-wrapper.argv"}


def test_none_enforcer_leaves_command_bare(tmp_path):
    plan = build_session_plan(_cfg(tmp_path, enforcer="none"), home_dir=str(tmp_path / "h"))
    assert plan.harness_command == list(plan.profile.entry)
    assert plan.policies == {}


def test_limits_flow_through(tmp_path):
    cfg = _cfg(tmp_path)
    cfg.limits = Limits(pids=100, memory="2g", cpus=1)
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"))
    assert plan.hardening.limits.pids == 100
    assert plan.hardening.limits.memory == "2g"


def test_browser_endpoint_reaches_environment(tmp_path):
    cfg = _cfg(tmp_path, extensions={"playwright": {"mode": "host", "port": 8931}})
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"))
    assert plan.environment["BROWSER_MCP_URL"] == "http://glove-s-browser:8931/mcp"


def test_add_dir_modes(tmp_path):
    ro = tmp_path / "lib"
    ro.mkdir()
    plan = build_session_plan(
        _cfg(tmp_path, add_dirs=[AddDir(str(ro), "ro")]),
        home_dir=str(tmp_path / "h"),
    )
    ro_mounts = [m for m in plan.mounts if m.container_path.startswith("/mnt/")]
    assert ro_mounts and all(m.read_only for m in ro_mounts)


def test_git_trusts_the_session_mount_roots(tmp_path):
    # Docker Desktop shows a fresh .git as another uid: the session's own mount
    # roots (not extension mounts) are safe.directory, exact paths only
    lib = tmp_path / "lib"
    lib.mkdir()
    plan = build_session_plan(_cfg(tmp_path, add_dirs=[AddDir(str(lib), "ro")]), home_dir=str(tmp_path / "h"))
    assert plan.environment["GIT_CONFIG_PARAMETERS"] == "'safe.directory'='/work' 'safe.directory'='/mnt/lib'"


def test_an_explicit_git_config_replaces_the_default(tmp_path):
    cfg = _cfg(tmp_path, env={"GIT_CONFIG_PARAMETERS": "'safe.directory'='*'"})
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"))
    assert plan.environment["GIT_CONFIG_PARAMETERS"] == "'safe.directory'='*'"


def test_write_in_place_keeps_unchanged_files_and_drops_stale_ones(tmp_path):
    d = tmp_path / "enforcer"
    write_in_place(d, {"a.json": "1", "b.json": "2", "old.json": "x"})
    a, b = (d / "a.json").stat().st_ino, (d / "b.json").stat().st_ino
    write_in_place(d, {"a.json": "1", "b.json": "3"})
    assert (d / "a.json").stat().st_ino == a  # unchanged: not rewritten
    assert (d / "b.json").stat().st_ino != b and (d / "b.json").read_text() == "3"
    assert sorted(p.name for p in d.iterdir()) == ["a.json", "b.json"]
    assert not list(tmp_path.glob(".tmp-*"))
    assert oct((d / "b.json").stat().st_mode & 0o777) == "0o644"


def test_a_bad_system_files_target_fails_at_plan_time(tmp_path, monkeypatch):
    real = plan_mod.adapter_call

    def adapter_call(profile, name, *a, **kw):
        return {"/work/x": {"f": "x"}} if name == "system_files" else real(profile, name, *a, **kw)
    monkeypatch.setattr(plan_mod, "adapter_call", adapter_call)
    with pytest.raises(ConfigError, match="under /etc"):
        build_session_plan(_cfg(tmp_path), home_dir=str(tmp_path / "h"))
