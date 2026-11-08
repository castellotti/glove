"""`harness-config`: free-form settings, passed through as the harness's native config."""

from __future__ import annotations

import json

from helpers import STUB_LLM, make_cfg

from glove.harnessconfig import render_home
from glove.plan import build_session_plan


def _home(tmp_path, harness, extensions):
    work = tmp_path / "work"
    work.mkdir()
    cfg = make_cfg(harness=harness, name="s", workdir=str(work), extensions=extensions)
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))
    render_home(cfg, plan, tmp_path / "h")
    return plan, tmp_path / "h"


def test_any_key_passes_through_and_merges_with_llms(tmp_path):
    plan, home = _home(tmp_path, "pi", {
        "llm": {**STUB_LLM, "harness": {"defaultThinkingLevel": "xhigh", "compaction": {"reserveTokens": 49152}}},
        "harness-config": {"theme": "light", "compaction": {"keepRecentTokens": 32000}},
    })
    settings = json.loads((home / ".pi" / "agent" / "settings.json").read_text())
    assert settings["defaultThinkingLevel"] == "xhigh" and settings["theme"] == "light"
    assert settings["compaction"] == {"reserveTokens": 49152, "keepRecentTokens": 32000}
    # no sidecar, no endpoint: a config-only extension
    assert [e.name for e in plan.composition.endpoints] == ["llm"] and not plan.composition.fragments


def test_nothing_set_renders_glove_defaults(tmp_path):
    _, home = _home(tmp_path, "pi", {"harness-config": {}})
    assert json.loads((home / ".pi" / "agent" / "settings.json").read_text())["defaultThinkingLevel"] == "low"
