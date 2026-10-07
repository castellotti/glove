"""Claude Code adapter: managed settings (glove's guard rails, read-only), the
home it seeds, and which env var the key travels in."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from helpers import make_cfg

from glove.config import ConfigError
from glove.harnessconfig import render_home
from glove.plan import build_session_plan, write_system_files

ANTHROPIC = {"provider": "anthropic", "model": "claude-x", "api_key": "keychain:test-cc"}
OAUTH = {**ANTHROPIC, "auth": "oauth"}
LOCAL = {"provider": "anthropic-compatible", "location": "host", "endpoint": "127.0.0.1:8080", "model": "m"}


def _plan(tmp_path: Path, llm: dict | None = None, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    cfg = make_cfg(harness="claude-code", name="s", workdir=str(work),
                   extensions={"llm": llm or ANTHROPIC, **kw.pop("extensions", {})}, **kw)
    return cfg, build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=501, gid=20)


def _managed(plan) -> dict:
    return json.loads(plan.system_files["/etc/claude-code"]["managed-settings.json"])


def test_an_api_key_is_injected_and_claude_code_reads_a_placeholder(tmp_path):
    _, plan = _plan(tmp_path)
    assert plan.passthrough_env == [] and plan.model.api_key_env == "ANTHROPIC_API_KEY"
    assert plan.environment["ANTHROPIC_API_KEY"] == "glove-injected"


def test_the_placeholder_is_pre_approved_and_earlier_answers_kept(tmp_path):
    cfg, plan = _plan(tmp_path)
    state = tmp_path / "h" / ".claude" / ".claude.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"customApiKeyResponses": {"approved": ["abc"], "rejected": ["def"]}}))
    render_home(cfg, plan, tmp_path / "h")
    render_home(cfg, plan, tmp_path / "h")  # once only
    assert json.loads(state.read_text())["customApiKeyResponses"] == {"approved": ["abc", "glove-injected"],
                                                                      "rejected": ["def"]}
    (tmp_path / "o").mkdir()
    cfg, plan = _plan(tmp_path / "o", OAUTH)
    render_home(cfg, plan, tmp_path / "o" / "h")
    assert "customApiKeyResponses" not in json.loads((tmp_path / "o" / "h" / ".claude" / ".claude.json").read_text())


def test_a_subscription_token_is_injected_and_claude_code_reads_a_placeholder(tmp_path):
    # llm-auth serves api.anthropic.com itself, so the account API works too
    _, plan = _plan(tmp_path, OAUTH)
    assert plan.passthrough_env == [] and plan.model.api_key_env == "CLAUDE_CODE_OAUTH_TOKEN"
    assert plan.environment["CLAUDE_CODE_OAUTH_TOKEN"] == "glove-injected"
    assert "ANTHROPIC_BASE_URL" not in _managed(plan)["env"]  # the default host, by its name


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
    assert "ANTHROPIC_BASE_URL" not in _managed(_plan(tmp_path, OAUTH)[1])["env"]
    for sub, llm in (("b", LOCAL), ("c", ANTHROPIC)):  # a gateway, and llm-auth for an API key
        (tmp_path / sub).mkdir()
        assert _managed(_plan(tmp_path / sub, llm)[1])["env"]["ANTHROPIC_BASE_URL"] == "http://glove-s-llm:8080"


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
    # every other tool the pinned MCP has is denied by name: no prompt can approve it
    deny = m["permissions"]["deny"]
    assert {"mcp__playwright__browser_run_code_unsafe", "mcp__playwright__browser_evaluate"} <= set(deny)
    assert "mcp__playwright__browser_navigate" not in deny


def test_an_allowlisted_tool_is_not_denied(tmp_path):
    _, plan = _plan(tmp_path, extensions={"direct": {}, "playwright": {"tools": ["browser_navigate",
                                                                                 "browser_evaluate"]}})
    m = _managed(plan)
    assert "mcp__playwright__browser_evaluate" in m["permissions"]["allow"]
    assert "mcp__playwright__browser_evaluate" not in m["permissions"]["deny"]
    assert "mcp__playwright__browser_click" in m["permissions"]["deny"]


def test_host_mode_playwright_needs_the_rce_acknowledgement(tmp_path):
    from glove.extensions import ExtensionError

    with pytest.raises(ExtensionError, match="browser_run_code_unsafe"):
        _plan(tmp_path, extensions={"playwright": {"mode": "host"}})


def test_search_is_an_http_mcp_server_and_webfetch_is_claude_codes_own_through_the_proxy(tmp_path):
    _, plan = _plan(tmp_path, extensions={"direct": {}, "search": {}, "webfetch": {}})
    files = plan.system_files["/etc/claude-code"]
    servers = json.loads(files["managed-mcp.json"])["mcpServers"]
    assert servers == {"searxng": {"type": "http", "url": "http://glove-s-search-mcp:8000/mcp"}}
    m = json.loads(files["managed-settings.json"])
    assert {"mcp__searxng", "WebFetch"} <= set(m["permissions"]["allow"])
    assert "WebFetch" not in m["permissions"]["deny"]
    env = m["env"]
    assert env["HTTPS_PROXY"] == env["HTTP_PROXY"] == "http://glove-s-proxy:8888"
    no_proxy = env["NO_PROXY"].split(",")
    # inference and the MCP servers never go through the egress proxy
    assert {"localhost", "127.0.0.1", "glove-s-llm", "glove-s-search-mcp"} <= set(no_proxy)
    assert not any(k.startswith("HTTP") for k in plan.environment)  # managed env only
    assert not any(k.startswith("GLOVE_FETCH") for k in plan.environment)
    assert not any(s.role in ("webfetch-mcp", "fetcher") for s in plan.network.sidecars)


def test_the_cloud_alias_stays_off_the_proxy(tmp_path):
    _, plan = _plan(tmp_path, OAUTH, extensions={"direct": {}, "webfetch": {}})
    assert "api.anthropic.com" in _managed(plan)["env"]["NO_PROXY"].split(",")
    (tmp_path / "k").mkdir()
    _, plan = _plan(tmp_path / "k", extensions={"direct": {}, "webfetch": {}})
    assert "glove-s-llm" in _managed(plan)["env"]["NO_PROXY"].split(",")


def test_without_webfetch_webfetch_is_denied_and_no_proxy_is_set(tmp_path):
    m = _managed(_plan(tmp_path)[1])
    assert "WebFetch" in m["permissions"]["deny"] and "HTTPS_PROXY" not in m["env"]


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
    render_home(cfg, plan, home)
    doc = json.loads(state.read_text())
    assert doc["numStartups"] == 7 and doc["hasCompletedOnboarding"] is True
    assert doc["projects"]["/work"] == {"allowedTools": ["x"], "hasTrustDialogAccepted": True}
    settings = json.loads((home / ".claude" / "settings.json").read_text())
    assert settings["model"] == "claude-x" and settings["theme"] == "dark"
    assert settings["includeCoAuthoredBy"] is False
    assert (home / ".claude" / "projects").is_dir()  # observe binds over it before the first turn
    assert "How your environment works" in (home / ".claude" / "CLAUDE.md").read_text()


def test_trust_follows_the_plans_working_dir_from_a_subdirectory(tmp_path):
    # glove run from <work>/sub starts Claude Code in /work/sub: the trust entry
    # must name that directory, not the mount root
    cfg, _ = _plan(tmp_path)
    (tmp_path / "work" / "sub").mkdir()
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), cwd=str(tmp_path / "work" / "sub"), uid=501, gid=20)
    assert plan.mount_plan.working_dir == "/work/sub"
    home = tmp_path / "h"
    render_home(cfg, plan, home)
    doc = json.loads((home / ".claude" / ".claude.json").read_text())
    assert list(doc["projects"]) == ["/work/sub"]


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
    render_home(cfg, plan, tmp_path / "h")
    assert not (tmp_path / "h" / ".claude" / "skills").exists()


def test_no_skills_no_add_dir(tmp_path):
    _, plan = _plan(tmp_path)
    assert "--add-dir" not in plan.command


def _stdio_probe(tmp_path, enforcer):
    # the in-tree extensions serve MCP over HTTP: test_cc_nono.sh's stdio probe
    probes = Path(__file__).parents[3] / "tests" / "integration" / "extensions"
    (Path(os.environ["GLOVE_HOME"]) / "config.yml").write_text(f"extension_paths: [{probes}]\n")
    _, plan = _plan(tmp_path, enforcer=enforcer, extensions={"cc-mcp-probe": {}})
    files = plan.system_files["/etc/claude-code"]
    return files, json.loads(files["managed-mcp.json"])["mcpServers"]["probe"]


def test_stdio_mcp_runs_through_the_prefix_from_a_read_only_argv(tmp_path):
    # not the tool wrapper: its profile has no network, and a server may talk to a sidecar
    files, server = _stdio_probe(tmp_path, "nono")
    assert server["command"] == "/opt/glove/bin/glove-cc-prefix" and server["args"] == ["--mcp", "probe"]
    assert files["mcp-probe.argv"].startswith("bash\n-c\n{ test -r /home/agent/.claude/settings.json")


def test_stdio_mcp_without_an_enforcer_runs_directly(tmp_path):
    files, server = _stdio_probe(tmp_path, "none")
    assert server["command"] == "bash" and not any(f.endswith(".argv") for f in files)


def test_the_trusted_project_settings_and_the_home_loaders_are_protected(tmp_path):
    _, plan = _plan(tmp_path)
    got = {p.container_path: (p.kind, p.read_only) for p in plan.protect}
    home = "/home/agent/.claude"
    assert got == {"/work/.claude": ("dir", False), "/work/.claude/settings.json": ("file", True),
                   "/work/.claude/settings.local.json": ("file", True), home: ("dir", False),
                   **{f"{home}/{f}": ("file", True) for f in ("settings.json", "CLAUDE.md")},
                   **{f"{home}/{d}": ("dir", True)
                      for d in ("agents", "commands", "skills", "plugins", "output-styles", "rules")}}


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
