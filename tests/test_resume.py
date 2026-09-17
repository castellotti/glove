"""Resume/session: HarnessProfile mapping, plan threading, discovery helpers."""

from __future__ import annotations

import pytest

from glove.config import AddDir, Config, ConfigError
from glove.harness import get_profile
from glove.plan import build_session_plan
from glove.sessions import (
    find_session,
    list_sessions,
    sessions_dir,
    widening_warnings,
)


def _cfg(tmp_path, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return Config(harness="pi", workdir=str(work), name="s", **kw)


# --- HarnessProfile.resume_args -------------------------------------------------

def test_resume_args_pi():
    pi = get_profile("pi")
    assert pi.resume_args(None) == ["--continue"]
    assert pi.resume_args("abc") == ["--session", "abc"]


def test_resume_args_vibe():
    vibe = get_profile("vibe")
    # continue-last is vibe's --continue (non-interactive); bare --resume is an
    # interactive picker, so it must not back glove's deterministic --resume.
    assert vibe.resume_args(None) == ["--continue"]
    assert vibe.resume_args("abc") == ["--resume", "abc"]


def test_resume_args_claude_code():
    cc = get_profile("claude-code")
    assert cc.resume_args(None) == ["--continue"]
    assert cc.resume_args("abc") == ["--resume", "abc"]


def test_resume_args_unsupported_raises():
    from glove.harness import HarnessProfile

    bare = HarnessProfile(
        name="bare", image="x:0", entry=["x"],
        config_home_env="X", config_home_path="/home/agent/.x", context_file="/x",
    )
    with pytest.raises(ConfigError):
        bare.resume_args(None)
    with pytest.raises(ConfigError):
        bare.resume_args("abc")


# --- plan threading (flag lands after the `--` sentinel) ------------------------

def _after_sentinel(command: list[str]) -> list[str]:
    return command[command.index("--") + 1:]


def test_plan_resume_continue_after_sentinel(tmp_path):
    plan = build_session_plan(
        _cfg(tmp_path), env_id="s", home_dir=str(tmp_path / "h"), resume=True
    )
    tail = _after_sentinel(plan.command)
    assert "--continue" in tail
    assert plan.command[:4] == ["nono", "run", "-s", "--allow-cwd"]  # wrapper intact


def test_plan_resume_session_after_sentinel(tmp_path):
    plan = build_session_plan(
        _cfg(tmp_path), env_id="s", home_dir=str(tmp_path / "h"), session_id="abc"
    )
    tail = _after_sentinel(plan.command)
    assert tail[-2:] == ["--session", "abc"]


def test_plan_no_resume_unchanged(tmp_path):
    base = build_session_plan(_cfg(tmp_path), env_id="s", home_dir=str(tmp_path / "h"))
    assert "--continue" not in base.command
    assert "--session" not in base.command


# --- discovery ------------------------------------------------------------------

def test_sessions_dir_derives_from_config_home(tmp_path):
    pi = get_profile("pi")
    assert sessions_dir(pi, tmp_path) == tmp_path / ".pi" / "agent" / "sessions"


def test_sessions_dir_claude_code_uses_projects(tmp_path):
    # CC writes transcripts under ~/.claude/projects/<slug>/, not sessions/.
    cc = get_profile("claude-code")
    assert sessions_dir(cc, tmp_path) == tmp_path / ".claude" / "projects"


def _seed(dir_, name):
    dir_.mkdir(parents=True, exist_ok=True)
    f = dir_ / name
    f.write_text("{}\n")
    return f


def test_list_and_find_sessions(tmp_path):
    sdir = tmp_path / ".pi" / "agent" / "sessions" / "--work--"
    old = _seed(sdir, "20240101_aaaa1111.jsonl")
    new = _seed(sdir, "20240102_bbbb2222.jsonl")
    import os

    os.utime(old, (1, 1))
    os.utime(new, (2, 2))
    root = tmp_path / ".pi" / "agent" / "sessions"
    refs = list_sessions(root)
    assert [r.id for r in refs] == ["bbbb2222", "aaaa1111"]  # newest first
    assert find_session(root, "aaaa").id == "aaaa1111"  # partial match
    assert find_session(root, "nope") is None
    # A full transcript path resolves (documented --session form); its length
    # exceeds any filename so it can only match via the path/basename branch.
    assert find_session(root, str(old)).id == "aaaa1111"
    assert find_session(root, old.name).id == "aaaa1111"  # basename


def test_list_sessions_missing_dir(tmp_path):
    assert list_sessions(tmp_path / "nope") == []


# --- post-exit hint attributes only THIS run's transcript -----------------------

def test_resume_hint_ignores_stale_pool_leftover(tmp_path, capsys):
    # A fresh session quit before any message persists nothing, so the newest
    # file in the pool is an unrelated earlier session. The hint must not report
    # it (that id would resume the wrong conversation).
    import os

    from glove.cli import _print_resume_hint

    pi = get_profile("pi")
    home = tmp_path / "home"
    wk = home / ".pi" / "agent" / "sessions" / "--work--"
    stale = _seed(wk, "20240101_01a09d62.jsonl")
    os.utime(stale, (1000, 1000))  # long before "now"

    _print_resume_hint(pi, home, "pi", since=time_now())
    assert "session saved" not in capsys.readouterr().out


def test_resume_hint_reports_this_runs_transcript(tmp_path, capsys):
    import os

    from glove.cli import _print_resume_hint

    pi = get_profile("pi")
    home = tmp_path / "home"
    wk = home / ".pi" / "agent" / "sessions" / "--work--"
    start = time_now()
    fresh = _seed(wk, "20240102_deadbeef.jsonl")
    os.utime(fresh, (start + 5, start + 5))  # written during this run

    _print_resume_hint(pi, home, "pi", since=start)
    out = capsys.readouterr().out
    assert "session saved" in out
    assert "deadbeef" in out


def time_now() -> float:
    import time

    return time.time()


# --- grant-widening -------------------------------------------------------------

def test_widening_detects_broader_grants():
    prev = Config(net=["none"], plugins=[], allow_root=False)
    cur = Config(
        net=["service"],
        plugins=["search"],
        allow_root=True,
        add_dirs=[AddDir("/data", "rw")],
    )
    warns = widening_warnings(prev, cur)
    joined = "\n".join(warns)
    assert "net" in joined
    assert "search" in joined
    assert "allow_root" in joined
    assert "/data" in joined


def test_widening_ro_to_rw_upgrade():
    prev = Config(add_dirs=[AddDir("/data", "ro")])
    cur = Config(add_dirs=[AddDir("/data", "rw")])
    warns = widening_warnings(prev, cur)
    assert any("ro → rw" in w for w in warns)


def test_widening_no_change_silent():
    cfg = Config(net=["service"], plugins=["search"])
    assert widening_warnings(cfg, cfg) == []


def test_widening_narrowing_silent():
    prev = Config(net=["service"], allow_root=True)
    cur = Config(net=["none"], allow_root=False)
    assert widening_warnings(prev, cur) == []
