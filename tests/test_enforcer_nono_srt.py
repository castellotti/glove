"""nono+srt enforcer: srt wraps the harness, nono wraps every tool command.

The live checks (tightened seccomp, TUI relay, proxy-only harness network,
deny-inside-allow) are in tests/integration/test_nono_srt.sh.
"""

from __future__ import annotations

import json

import pytest
import yaml
from helpers import make_cfg, render

from glove.config import ConfigError
from glove.enforcers import get_enforcer
from glove.enforcers.base import ENFORCER_DIR, GLOVE_PTY, srt_suffix
from glove.enforcers.nono_srt import render_harness_settings
from glove.enforcers.srt import APPLY_SECCOMP, GLOVE_SRT, NODE
from glove.plan import build_session_plan
from glove.runtimes.podman import PodmanRuntime
from glove.runtimes.seccomp import NESTED_USERNS_PROFILE


def _plan(tmp_path, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    cfg = make_cfg(harness=kw.pop("harness", "pi"), workdir=str(work), name="s", enforcer="nono+srt", **kw)
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=1000, gid=1000,
                              state_dir=str(tmp_path / "ext"))


def test_harness_runs_under_srt_on_a_relayed_terminal(tmp_path):
    plan = _plan(tmp_path)
    cmd = plan.harness_command
    assert cmd[:3] == [GLOVE_PTY, "relay", "--"]
    assert cmd[3:7] == [NODE, GLOVE_SRT, f"{ENFORCER_DIR}/srt-harness.json", "--"]
    assert cmd[7:10] == [GLOVE_PTY, "ctty", "--"]
    assert cmd[10:] == list(plan.profile.entry) + cmd[10 + len(plan.profile.entry):]
    assert plan.image.endswith(srt_suffix())
    assert plan.hardening.seccomp_profile == str(NESTED_USERNS_PROFILE)
    assert not plan.hardening.systempaths_unconfined


def test_tool_commands_drop_the_terminal_then_run_under_nono(tmp_path):
    plan = _plan(tmp_path)
    argv = json.loads(plan.policies["tool-wrapper.json"])["argv"]
    assert argv[:3] == [GLOVE_PTY, "notty", "--"]
    assert argv[3:5] == ["nono", "wrap"] and f"{ENFORCER_DIR}/tool.json" in argv
    assert "tool.json" in plan.policies and "harness.json" not in plan.policies
    tool = json.loads(plan.policies["tool.json"])
    assert tool["network"]["block"] is True and "GLOVE_LLM_API_KEY" in tool["environment"]["deny_vars"]


def test_harness_settings(tmp_path):
    s = render_harness_settings(_plan(tmp_path))
    assert s["seccomp"] == {"applyPath": APPLY_SECCOMP}
    assert s["enableWeakerNestedSandbox"] is True
    fs = s["filesystem"]
    assert fs["allowWrite"] == ["/work", "/home/agent", "/tmp"]
    assert fs["denyWrite"] == []  # nothing exists yet: no placeholder is ever created on the host
    assert fs["denyRead"] == ["/work/**/.env", "/work/**/.env.*"]
    assert "credentials" not in s  # the harness keeps its env; nono strips tools'


def test_only_protected_paths_present_at_launch_are_denied(tmp_path):
    work = tmp_path / "work"
    (work / ".git" / "hooks").mkdir(parents=True)
    (work / ".git" / "config").write_text("")
    (work / ".vscode").mkdir()
    (work / ".envrc").write_text("")
    deny = render_harness_settings(_plan(tmp_path))["filesystem"]["denyWrite"]
    assert deny == ["/work/.git/hooks", "/work/.git/config", "/work/.vscode", "/work/.envrc"]


def test_env_hiding_can_be_turned_off(tmp_path):
    s = render_harness_settings(_plan(tmp_path, enforcer_options={"srt": {"hide_env": False}}))
    assert s["filesystem"]["denyRead"] == []


def test_strong_mode(tmp_path):
    plan = _plan(tmp_path, enforcer_options={"srt": {"nested": "strong"}})
    assert plan.hardening.systempaths_unconfined
    assert render_harness_settings(plan)["enableWeakerNestedSandbox"] is False


def test_the_harness_keeps_the_container_network(tmp_path):
    # no `network` block: srt makes no netns or proxy; ring 0 confines the
    # harness to the session's forwarders, which render exactly as with nono
    plan = _plan(tmp_path)
    assert "network" not in render_harness_settings(plan)
    assert plan.enforcer_env == {}
    assert plan.model.base_url.startswith("http://glove-s-llm:")


def test_rendered_compose(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    cfg = make_cfg(harness="pi", workdir=str(work), name="s", enforcer="nono+srt")
    plan, text = render(cfg, tmp_path)
    harness = yaml.safe_load(text)["services"][plan.harness_service]
    assert any("nested-userns" in o for o in harness["security_opt"])
    assert harness["command"][:2] == [GLOVE_PTY, "relay"]


def test_vibe_gets_the_same_shape(tmp_path):
    plan = _plan(tmp_path, harness="vibe")
    assert plan.harness_command[4] == GLOVE_SRT and plan.image.endswith(srt_suffix())


def test_podman_refuses_it():
    assert "not supported on the podman runtime" in PodmanRuntime().unsupported_enforcer_reason("nono+srt")


def test_gaps_documented(tmp_path):
    gaps = get_enforcer("nono+srt").gaps(_plan(tmp_path))
    assert any("nested-userns" in g for g in gaps) and any(".env" in g for g in gaps)


@pytest.mark.parametrize("enforcer", ["nono", "nono+srt"])
def test_browsers_option_grants_proc_to_commands_only(tmp_path, enforcer):
    """`enforcer_options: {nono: {browsers: true}}`: Chromium needs /proc in the tool
    profile (read-only); off by default, and the harness side is unchanged."""
    def policies(**kw):
        work = tmp_path / "work"
        work.mkdir(exist_ok=True)
        cfg = make_cfg(harness="pi", workdir=str(work), name="s", enforcer=enforcer, **kw)
        return build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=1000, gid=1000,
                                  state_dir=str(tmp_path / "ext")).policies

    off, on = policies(), policies(enforcer_options={"nono": {"browsers": True}})
    assert "/proc" not in json.loads(off["tool.json"])["filesystem"]["read"]
    tool = json.loads(on["tool.json"])["filesystem"]
    assert "/proc" in tool["read"] and "/proc" not in tool["allow"]
    assert {k: v for k, v in on.items() if k != "tool.json"} == {k: v for k, v in off.items() if k != "tool.json"}
    with pytest.raises(ConfigError, match="browsers"):
        policies(enforcer_options={"nono": {"browsers": "yes"}})
