"""srt enforcer tests — settings renderer, wrapping, image suffix.

Golden settings verified against sandbox-runtime 0.0.77 (see
tests/integration/test_pi_srt.sh, which reproduces the nested-sandbox matrix).
"""

from __future__ import annotations

import json
from pathlib import Path

from helpers import make_cfg

from glove.config import AddDir
from glove.enforcers import get_enforcer
from glove.enforcers.base import ENFORCER_DIR, SRT, srt_suffix
from glove.enforcers.srt import render_settings
from glove.plan import build_session_plan

GOLDEN = Path(__file__).parent / "golden" / "srt"


def _plan(tmp_path, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    cfg = make_cfg(harness="pi", workdir=str(work), name="s", enforcer="srt", **kw)
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=1000, gid=1000)


def test_get_enforcer_srt():
    assert get_enforcer("srt").name == "srt"


def test_weak_mode_default(tmp_path):
    settings = render_settings(_plan(tmp_path))
    assert settings["enableWeakerNestedSandbox"] is True
    fs = settings["filesystem"]
    assert fs["allowWrite"] == ["/work", "/tmp"]
    # the whole home MOUNT POINT is denied (denying a subdir of a bind mount is
    # a no-op under srt) — both read and write.
    assert fs["denyRead"] == ["/home/agent"]
    assert fs["denyWrite"] == ["/home/agent"]
    assert "deniedDomains" in settings["network"]  # required key
    assert settings["network"]["allowedDomains"] == []  # tools get no network


def test_llm_key_denied_to_tool_commands(tmp_path):
    # srt has no glob form: every harness secret is unset by exact name, and
    # the LLM key is always on the list even when no key is configured.
    assert render_settings(_plan(tmp_path))["credentials"]["envVars"] == [
        {"name": "GLOVE_LLM_API_KEY", "mode": "deny"},
    ]
    from helpers import STUB_LLM

    plan = _plan(tmp_path, extensions={"llm": {**STUB_LLM, "api_key": "env:SOME_VAR"}})
    plan.passthrough_env = [*plan.passthrough_env, "OTHER_SECRET"]
    names = [v["name"] for v in render_settings(plan)["credentials"]["envVars"]]
    assert names == ["GLOVE_LLM_API_KEY", "OTHER_SECRET"]
    assert {v["mode"] for v in render_settings(plan)["credentials"]["envVars"]} == {"deny"}


def test_no_top_level_allow_unix_sockets(tmp_path):
    # srt's root schema is not strict, so a misplaced key is silently dropped;
    # allowUnixSockets is a macOS-only network key and must not be rendered.
    settings = render_settings(_plan(tmp_path))
    assert "allowUnixSockets" not in settings
    assert "allowUnixSockets" not in settings["network"]


def test_strong_mode_from_options(tmp_path):
    plan = _plan(tmp_path, enforcer_options={"srt": {"nested": "strong"}})
    settings = render_settings(plan)
    assert settings["enableWeakerNestedSandbox"] is False
    assert plan.hardening.systempaths_unconfined is True


def test_rw_add_dir_in_allow_write(tmp_path):
    rw = tmp_path / "out"
    rw.mkdir()
    settings = render_settings(_plan(tmp_path, add_dirs=[AddDir(str(rw), "rw")]))
    assert "/mnt/out" in settings["filesystem"]["allowWrite"]


def test_srt_does_not_wrap_harness(tmp_path):
    plan = _plan(tmp_path)
    assert plan.harness_command == list(plan.profile.entry)  # TUI unwrapped
    assert plan.image.endswith(srt_suffix())  # distinct image variant
    wrapper = json.loads(plan.policies["tool-wrapper.json"])["argv"]
    assert wrapper[0] == SRT
    assert f"{ENFORCER_DIR}/srt-settings.json" in wrapper


def test_srt_uses_relaxed_seccomp(tmp_path):
    from glove.runtimes.seccomp import NESTED_USERNS_PROFILE

    plan = _plan(tmp_path)
    assert plan.hardening.seccomp_profile == str(NESTED_USERNS_PROFILE)


def test_golden_settings(tmp_path):
    for scenario, kw in (("weak", {}), ("strong", {"enforcer_options": {"srt": {"nested": "strong"}}})):
        settings = render_settings(_plan(tmp_path, **kw))
        golden = json.loads((GOLDEN / f"{scenario}.json").read_text())
        assert settings == golden


def test_gaps_documented(tmp_path):
    gaps = get_enforcer("srt").gaps(_plan(tmp_path))
    assert any("unwrapped" in g for g in gaps)
    assert not any("stays in the harness env" in g for g in gaps)  # no secret in the harness env
    plan = _plan(tmp_path)
    plan.passthrough_env = ["CLAUDE_CODE_OAUTH_TOKEN"]
    assert any("stays in the harness env" in g for g in get_enforcer("srt").gaps(plan))
