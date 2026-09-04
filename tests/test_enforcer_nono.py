"""nono policy renderer tests with golden files.

The golden files under tests/golden/nono/ were verified with real nono
(`nono profile validate`) against the 0.75.0 image; see
tests/integration/test_pi_nono.sh for the enforcement checks.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from glove.config import AddDir, Config
from glove.enforcers import get_enforcer
from glove.enforcers.base import ENFORCER_DIR
from glove.plan import build_session_plan

GOLDEN = Path(__file__).parent / "golden" / "nono"


def _plan(tmp_path, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    cfg = Config(harness="pi", workdir=str(work), name="s", **kw)
    return build_session_plan(cfg, env_id="s", home_dir=str(tmp_path / "h"), uid=1000, gid=1000)


def _assert_matches_golden(plan, scenario):
    for fname, content in plan.policies.items():
        golden = (GOLDEN / scenario / fname).read_text()
        assert content == golden, f"{scenario}/{fname} drifted from golden"


def test_golden_single_workdir(tmp_path):
    _assert_matches_golden(_plan(tmp_path), "single")


def test_golden_ro_and_rw_add_dirs(tmp_path):
    ro = tmp_path / "lib"
    rw = tmp_path / "out"
    ro.mkdir()
    rw.mkdir()
    plan = _plan(tmp_path, add_dirs=[AddDir(str(ro), "ro"), AddDir(str(rw), "rw")])
    _assert_matches_golden(plan, "ro_rw")


def test_golden_command_overrides(tmp_path):
    plan = _plan(tmp_path, tools={"allow_commands": ["cp", "mv", "rm", "chmod"], "deny_commands": ["git"]})
    _assert_matches_golden(plan, "allow_cmds")


def test_tool_policy_denies_home_and_blocks_net(tmp_path):
    tool = json.loads(_plan(tmp_path).policies["tool.json"])
    # harness home must NOT be grantable to shell commands
    fs = tool["filesystem"]
    assert "/home/agent/.pi/agent" not in fs["allow"]
    assert "/home/agent/.pi/agent" not in fs.get("read", [])
    assert tool["network"]["block"] is True
    assert "GLOVE_LLM_API_KEY" in tool["environment"]["deny_vars"]


def test_harness_policy_grants_home_and_allows_net(tmp_path):
    harness = json.loads(_plan(tmp_path).policies["harness.json"])
    assert "/home/agent/.pi/agent" in harness["filesystem"]["allow"]
    assert harness["network"]["block"] is False


def test_wrap_and_wrapper_argv(tmp_path):
    plan = _plan(tmp_path)
    enf = get_enforcer("nono")
    wrapped = enf.wrap_harness(plan, ["pi", "-e", "x"])
    assert wrapped[:2] == ["nono", "run"]
    assert wrapped[-3:] == ["pi", "-e", "x"]
    assert f"{ENFORCER_DIR}/harness.json" in wrapped

    wrapper = json.loads(plan.policies["tool-wrapper.json"])["argv"]
    assert wrapper[:2] == ["nono", "wrap"]
    assert wrapper[-1] == "--"
    assert f"{ENFORCER_DIR}/tool.json" in wrapper


def test_nono_pin_matches_dockerfile():
    # The Pi image's `COPY --from` tag must match the pinned nono version, so a
    # bump in one place cannot silently diverge.
    from glove.enforcers.nono.version import nono_image_ref

    dockerfile = (Path(__file__).parent.parent / "glove/harnesses/pi/Dockerfile").read_text()
    assert f"COPY --from={nono_image_ref()} " in dockerfile


def test_rw_add_dir_writable_in_tool_but_ro_not(tmp_path):
    ro = tmp_path / "lib"
    rw = tmp_path / "out"
    ro.mkdir()
    rw.mkdir()
    tool = json.loads(_plan(tmp_path, add_dirs=[AddDir(str(ro), "ro"), AddDir(str(rw), "rw")]).policies["tool.json"])
    assert "/mnt/out" in tool["filesystem"]["allow"]
    assert "/mnt/lib" in tool["filesystem"]["read"]
    assert "/mnt/lib" not in tool["filesystem"]["allow"]
