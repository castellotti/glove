"""The harness tool inventory (`harness.yml` `tools:`) rendered as tools.json:
the harness's classes, the tools the session's extensions add, and the session's
own `harness_config.tools.allow` (passthrough only)."""

from __future__ import annotations

import json
import tomllib

import pytest

from glove.config import ConfigError
from glove.harnessconfig import render_home
from glove.plan import build_session_plan
from tests.helpers import make_cfg

ANTHROPIC = {"provider": "anthropic", "model": "claude-x", "api_key": "keychain:test-cc"}


def _plan(tmp_path, harness="pi", **kw):
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)
    cfg = make_cfg(harness=harness, name="s", workdir=str(work), **kw)
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=501, gid=20, state_dir=str(tmp_path / "ext"))
    render_home(cfg, plan, tmp_path / "h")
    return plan


def _tools(plan) -> dict:
    return json.loads(plan.policies["tools.json"])


def test_the_harness_classes_render(tmp_path):
    t = _tools(_plan(tmp_path))
    assert set(t) == {"shell", "file_write", "allow", "ask", "deny"}  # the hooks refuse all but the first three
    assert (t["shell"], t["file_write"]) == (["bash"], ["write", "edit"])
    assert "read" in t["allow"] and "web_search" not in t["allow"]


def test_extensions_add_their_tools(tmp_path):
    exts = {"direct": {}, "search": {}, "webfetch": {}, "playwright": {"tools": ["browser_navigate"]}}
    pi = _tools(_plan(tmp_path / "pi", extensions=exts))["allow"]
    assert {"web_search", "web_fetch", "browser_status", "browser_navigate"} <= set(pi)
    assert "browser_click" not in pi  # not in the session's allowlist
    vibe = _tools(_plan(tmp_path / "vibe", harness="vibe", extensions=exts))["allow"]
    # Vibe 2.26 calls MCP tools from run_typescript, as mcp_<server>.<tool>
    assert {"mcp_searxng.web_search", "mcp_webfetch.fetch_url", "mcp_playwright.browser_navigate"} <= set(vibe)
    assert "mcp_playwright.browser_click" not in vibe and "web_search" not in vibe


def test_a_session_adds_passthrough_tools(tmp_path):
    plan = _plan(tmp_path, harness="vibe", harness_config={"tools": {"allow": ["mcp_mine.lookup"]}})
    assert "mcp_mine.lookup" in _tools(plan)["allow"]
    # `allow` is glove's key, never rendered into config.toml
    assert "tools" not in tomllib.loads((tmp_path / "h" / ".vibe" / "config.toml").read_text())


def test_vibe_keeps_its_own_tool_settings(tmp_path):
    hc = {"tools": {"allow": ["mcp_mine.lookup"], "bash": {"default_timeout": 60}}}
    plan = _plan(tmp_path, harness="vibe", harness_config=hc)
    assert "mcp_mine.lookup" in _tools(plan)["allow"]
    doc = tomllib.loads((tmp_path / "h" / ".vibe" / "config.toml").read_text())
    assert doc["tools"] == {"bash": {"default_timeout": 60}}


@pytest.mark.parametrize("harness,hc", [
    ("pi", {"tools": {"allow": ["bash"]}}),               # a shell tool keeps its wrapper
    ("pi", {"tools": {"allow": ["write"]}}),              # a file-write tool keeps its write roots
    ("vibe", {"tools": {"allow": ["web_fetch"]}}),        # a denied tool stays denied
    ("claude-code", {"tools": {"allow": ["EnterWorktree"]}}),
    ("claude-code", {"tools": {"allow": ["WebFetch"]}}),  # denied unless webfetch gives it the proxy
    ("pi", {"tools": {"allow": ["a b"]}}),                # not a tool name
    ("pi", {"tools": {"allow": "x"}}),                    # not a list
    ("claude-code", {"tools": {"shell": ["x"]}}),         # a session adds passthrough only
    ("claude-code", {"tools": ["x"]}),
])
def test_a_session_cannot_widen_a_classed_tool(tmp_path, harness, hc):
    with pytest.raises(ConfigError):
        _plan(tmp_path, harness=harness, harness_config=hc)


def test_claude_code_rules_follow_the_inventory(tmp_path):
    from glove.harness import get_profile

    plan = _plan(tmp_path, harness="claude-code", extensions={"llm": ANTHROPIC},
                 harness_config={"tools": {"allow": ["Skill"]}})
    m = json.loads(plan.system_files["/etc/claude-code"]["managed-settings.json"])
    tools = get_profile("claude-code").tools
    allow, deny = set(m["permissions"]["allow"]), set(m["permissions"]["deny"])
    assert {*tools["shell"], *tools["file_write"], *tools["allow"], "Skill"} <= allow  # an `ask` tool, opted in
    assert set(tools["deny"]) <= deny and not (set(tools["ask"]) - {"Skill"}) & allow
