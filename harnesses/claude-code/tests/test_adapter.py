"""Claude Code adapter: managed settings (glove's guard rails, read-only), the
home it seeds, and which env var the key travels in."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from helpers import make_cfg

from glove.config import ConfigError
from glove.harnessconfig import render_home
from glove.plan import build_session_plan, write_system_files

ANTHROPIC = {"provider": "anthropic", "model": "claude-x", "api_key": "keychain:test-cc"}
LOCAL = {"provider": "anthropic-compatible", "location": "host", "endpoint": "127.0.0.1:8080", "model": "m"}


def _plan(tmp_path: Path, llm: dict | None = None, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    cfg = make_cfg(harness="claude-code", name="s", workdir=str(work),
                   extensions={"llm": llm or ANTHROPIC, **kw.pop("extensions", {})}, **kw)
    return cfg, build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=501, gid=20)


def _managed(plan) -> dict:
    return json.loads(plan.system_files["/etc/claude-code"]["managed-settings.json"])


@pytest.mark.parametrize("auth,env", [("api-key", "ANTHROPIC_API_KEY"), ("oauth", "CLAUDE_CODE_OAUTH_TOKEN")])
def test_the_key_travels_in_the_env_claude_code_reads(tmp_path, auth, env):
    _, plan = _plan(tmp_path, {**ANTHROPIC, "auth": auth})
    assert plan.passthrough_env == [env]
    assert plan.model.api_key_env == env


def test_no_key_no_passthrough(tmp_path):
    _, plan = _plan(tmp_path, LOCAL)
    assert plan.passthrough_env == []


def test_only_the_anthropic_messages_api(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    cfg = make_cfg(harness="claude-code", name="s", workdir=str(work))  # the llama.cpp stub: OpenAI API
    with pytest.raises(ConfigError, match="only the Anthropic Messages API"):
        build_session_plan(cfg, home_dir=str(tmp_path / "h"))


@pytest.mark.parametrize("enforcer", ["nono", "nono+srt", "srt"])
def test_the_shell_prefix_is_managed_and_reads_the_rendered_argv(tmp_path, enforcer):
    _, plan = _plan(tmp_path, enforcer=enforcer)
    m = _managed(plan)
    assert m["env"]["CLAUDE_CODE_SHELL_PREFIX"] == "/opt/glove/bin/glove-cc-prefix"
    argv = json.loads(plan.policies["tool-wrapper.json"])["argv"]
    assert plan.policies["tool-wrapper.argv"] == "".join(f"{a}\n" for a in argv)
    assert "CLAUDE_CODE_SHELL_PREFIX" not in plan.environment  # never the process env (the agent's settings win)


def test_no_enforcer_no_prefix(tmp_path):
    # enforcer none: no tool wrapper to run commands under, so no prefix that would fail every command
    _, plan = _plan(tmp_path, enforcer="none")
    assert "CLAUDE_CODE_SHELL_PREFIX" not in _managed(plan)["env"]


def test_managed_settings_lock_hooks_rules_mcp_and_the_config_home(tmp_path):
    m = _managed(_plan(tmp_path)[1])
    assert m["allowManagedHooksOnly"] and m["allowManagedPermissionRulesOnly"] and m["allowManagedMcpServersOnly"]
    assert m["allowedMcpServers"] == []
    # `//` is an absolute path; Edit rules cover every file-writing tool
    deny = set(m["permissions"]["deny"])
    assert {"Read(//home/agent/.claude/**)", "Edit(//home/agent/.claude/**)", "WebFetch"} <= deny
    assert m["permissions"]["defaultMode"] == "default"
    assert m["sandbox"] == {"enabled": False} and m["enableArtifact"] is False


def test_base_url_only_off_the_default_host(tmp_path):
    assert "ANTHROPIC_BASE_URL" not in _managed(_plan(tmp_path)[1])["env"]
    (tmp_path / "b").mkdir()
    assert _managed(_plan(tmp_path / "b", LOCAL)[1])["env"]["ANTHROPIC_BASE_URL"] == "http://glove-s-llm:8080"


def test_harness_config_permissions(tmp_path):
    hc = {"permissions": {"defaultMode": "acceptEdits", "allow": ["Bash(git:*)"], "deny": ["Bash(rm:*)"]}}
    m = _managed(_plan(tmp_path, harness_config=hc)[1])
    assert m["permissions"]["defaultMode"] == "acceptEdits"
    assert "Bash(git:*)" in m["permissions"]["allow"] and "Bash(rm:*)" in m["permissions"]["deny"]


@pytest.mark.parametrize("hc", [{"mcp_servers": []}, {"permissions": {"mode": "x"}},
                                {"permissions": {"defaultMode": "bypassPermissions"}},
                                {"permissions": {"allow": "Bash(git:*)"}}, {"permissions": {"deny": [1]}},
                                {"settings": ["theme"]}])
def test_bad_harness_config_is_refused(tmp_path, hc):
    with pytest.raises(ConfigError, match="claude-code"):
        _plan(tmp_path, harness_config=hc)


def test_mcp_contributions_become_managed_servers_and_rules(tmp_path):
    _, plan = _plan(tmp_path, extensions={"direct": {}, "playwright": {}})
    files = plan.system_files["/etc/claude-code"]
    servers = json.loads(files["managed-mcp.json"])["mcpServers"]
    assert servers["playwright"] == {"type": "http", "url": "http://glove-s-browser:8931/mcp"}
    m = json.loads(files["managed-settings.json"])
    assert m["allowedMcpServers"] == [{"serverName": "playwright"}]
    assert "mcp__playwright__browser_navigate" in m["permissions"]["allow"]
    assert not any(r == "mcp__playwright" for r in m["permissions"]["allow"])  # an allowlist, not the server


def test_system_files_are_written_under_state_and_bound_read_only(tmp_path):
    from glove.runtimes.docker import DockerRuntime

    _, plan = _plan(tmp_path)
    write_system_files(plan, tmp_path / "state" / "harness")
    assert plan.system_mounts == [(str(tmp_path / "state/harness/claude-code"), "/etc/claude-code")]
    assert (tmp_path / "state/harness/claude-code/managed-settings.json").is_file()
    compose = DockerRuntime().render(plan, tmp_path / "state").compose_yaml
    assert f'source: "{tmp_path}/state/harness/claude-code"\n        target: /etc/claude-code\n' \
           "        read_only: true" in compose


@pytest.mark.parametrize("target", ["/etc", "/etc/glove/enforcer", "/home/agent/.claude", "/work/x", "/etc/../tmp"])
def test_system_files_only_in_a_dir_of_their_own_under_etc(tmp_path, target):
    _, plan = _plan(tmp_path)
    plan.system_files = {target: {"f": "x"}}
    with pytest.raises(ConfigError, match="under /etc"):
        write_system_files(plan, tmp_path / "harness")


def test_home_seeds_onboarding_and_trust_and_keeps_claude_codes_state(tmp_path):
    cfg, plan = _plan(tmp_path, harness_config={"settings": {"theme": "dark"}})
    home = tmp_path / "h"
    state = home / ".claude" / ".claude.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"numStartups": 7, "projects": {"/work": {"allowedTools": ["x"]}}}))
    render_home(cfg, plan.profile, home, plan.model, comp=plan.composition)
    doc = json.loads(state.read_text())
    assert doc["numStartups"] == 7 and doc["hasCompletedOnboarding"] is True
    assert doc["projects"]["/work"] == {"allowedTools": ["x"], "hasTrustDialogAccepted": True}
    settings = json.loads((home / ".claude" / "settings.json").read_text())
    assert settings["model"] == "claude-x" and settings["theme"] == "dark"
    assert settings["includeCoAuthoredBy"] is False
    assert (home / ".claude" / "projects").is_dir()  # observe binds over it before the first turn
    assert "How your environment works" in (home / ".claude" / "CLAUDE.md").read_text()


def test_skills_are_baked_outside_the_config_home(tmp_path):
    # the config home is denied to Read and to tool commands, so a skill's files
    # must be reachable by the path Claude Code shows: <add-dir>/.claude/skills/<name>
    from glove.harness import adapter_call

    cfg, plan = _plan(tmp_path, extensions={"media": {}, "ocr": {}, "rag": {"models_dir": str(tmp_path)}})
    assert plan.command[-2:] == ["--add-dir", "/opt/glove/cc"]
    lines, _ = adapter_call(plan.profile, "image_lines", plan.composition)
    assert lines[-1] == ("RUN mkdir -p /opt/glove/cc/.claude/skills"
                         " && ln -s /opt/glove/skills/rag/rag-parse /opt/glove/cc/.claude/skills/rag-parse"
                         " && ln -s /opt/glove/skills/rag/rag-query /opt/glove/cc/.claude/skills/rag-query")
    render_home(cfg, plan.profile, tmp_path / "h", plan.model, comp=plan.composition)
    assert not (tmp_path / "h" / ".claude" / "skills").exists()


def test_no_skills_no_add_dir(tmp_path):
    _, plan = _plan(tmp_path)
    assert "--add-dir" not in plan.command


def _searxng(tmp_path, enforcer):
    _, plan = _plan(tmp_path, enforcer=enforcer, extensions={"direct": {}, "search": {}})
    files = plan.system_files["/etc/claude-code"]
    return files, json.loads(files["managed-mcp.json"])["mcpServers"]["searxng"]


def test_stdio_mcp_runs_through_the_prefix_from_a_read_only_argv(tmp_path):
    # not the tool wrapper: its profile has no network, and the server talks to a sidecar
    files, server = _searxng(tmp_path, "nono")
    assert server["command"] == "/opt/glove/bin/glove-cc-prefix" and server["args"] == ["--mcp", "searxng"]
    assert server["env"] == {"SEARXNG_URL": "http://glove-s-search:8080"}
    assert files["mcp-searxng.argv"] == "python3\n/opt/glove/ext/search/searxng_mcp.py\n"


def test_stdio_mcp_without_an_enforcer_runs_directly(tmp_path):
    files, server = _searxng(tmp_path, "none")
    assert server["command"] == "python3" and not any(f.endswith(".argv") for f in files)


def test_the_trusted_project_settings_are_protected(tmp_path):
    _, plan = _plan(tmp_path)
    got = {p.container_path: (p.kind, p.read_only) for p in plan.protect}
    assert got == {"/work/.claude": ("dir", False), "/work/.claude/settings.json": ("file", True),
                   "/work/.claude/settings.local.json": ("file", True)}


def test_system_files_are_rewritten_in_place(tmp_path):
    # a live session binds the dir: a re-plan must keep it (same inode), not swap it
    _, plan = _plan(tmp_path)
    root = tmp_path / "state" / "harness"
    write_system_files(plan, root)
    d = root / "claude-code"
    inode = d.stat().st_ino
    (d / "managed-settings.json").write_text("stale")
    (d / "gone.json").write_text("{}")
    (root / "old-dir").mkdir()
    write_system_files(plan, root)
    assert d.stat().st_ino == inode
    assert json.loads((d / "managed-settings.json").read_text())["allowManagedHooksOnly"] is True
    assert sorted(p.name for p in root.iterdir()) == ["claude-code"]
    assert sorted(p.name for p in d.iterdir()) == ["managed-settings.json"]
