"""Harness-config generation tests (Pi models.json / Vibe config.toml / context)."""

from __future__ import annotations

import json
import re
import tomllib

import pytest
from helpers import STUB_LLM, make_cfg

from glove.config import AddDir, ConfigError
from glove.harnessconfig import INJECTED_KEY, LLM_API_KEY_ENV, ModelDescriptor, build_environment_context, render_home
from glove.plan import build_session_plan

EXTS = {"direct": {}, "search": {}, "playwright": {}}


def _home(harness: str, tmp_path, *, llm=None, extensions=EXTS, **kw):
    work = tmp_path / "wd"
    work.mkdir(parents=True, exist_ok=True)
    exts = dict(extensions)
    if llm is not None:
        exts["llm"] = llm
    cfg = make_cfg(harness=harness, workdir=str(work), name=f"{harness}-sess",
                   brief="Write output to /mnt/x.", extensions=exts, **kw)
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "home"), uid=1000, gid=1000,
                              state_dir=str(tmp_path / "ext"))
    home = tmp_path / "home"
    render_home(cfg, plan, home)
    return cfg, plan, home


def test_vibe_config_toml(tmp_path):
    _, _, home = _home("vibe", tmp_path)
    doc = tomllib.loads((home / ".vibe" / "config.toml").read_text())
    # Must be a unique alias, NOT Vibe's built-in "local" (Devstral) alias.
    assert doc["active_model"] == "glove"
    assert doc["models"][0]["alias"] == "glove"
    prov = doc["providers"][0]
    assert prov["api_base"] == "http://glove-vibe-sess-llm:8080/v1"
    assert prov["api_key_env_var"] == ""  # no key configured
    assert doc["models"][0]["name"] == "test-model"
    names = {s["name"] for s in doc["mcp_servers"]}
    assert names == {"playwright", "searxng"}
    pw = next(s for s in doc["mcp_servers"] if s["name"] == "playwright")
    # every HTTP server goes through the image's stdio bridge (one MCP session for Vibe's)
    assert pw == {"name": "playwright", "transport": "stdio", "command": "/opt/glove/bin/glove-mcp-bridge",
                  "args": ["http://glove-vibe-sess-browser:8931/mcp"]}
    # the playwright allowlist, as a Vibe denylist scoped to that server's tools
    deny, search = doc["disabled_tools"]
    assert search == "re:searxng_(?!(?:web_search)$).*"  # search's own allowlist
    assert deny.startswith("re:playwright_(?!(?:browser_navigate|")
    hidden = re.compile(deny.removeprefix("re:"))
    assert hidden.fullmatch("playwright_browser_run_code_unsafe") and hidden.fullmatch("playwright_browser_evaluate")
    assert not hidden.fullmatch("playwright_browser_navigate") and not hidden.fullmatch("bash")
    assert not hidden.fullmatch("searxng_search")
    sx = next(s for s in doc["mcp_servers"] if s["name"] == "searxng")
    assert sx == {"name": "searxng", "transport": "stdio", "command": "/opt/glove/bin/glove-mcp-bridge",
                  "args": ["http://glove-vibe-sess-search-mcp:8000/mcp"]}


def test_vibe_operator_mcp_servers_render_as_written(tmp_path):
    own = [{"name": "extra", "transport": "http", "url": "http://x:1/mcp"},
           {"name": "local", "transport": "stdio", "command": "/usr/bin/true"}]
    _, _, home = _home("vibe", tmp_path, harness_config={"mcp_servers": own})
    doc = tomllib.loads((home / ".vibe" / "config.toml").read_text())
    assert doc["mcp_servers"][-2:] == own  # no bridge: an operator who wants one writes the stdio form


def test_vibe_context_file_has_sudo_relay_brief_and_extension_briefs(tmp_path):
    _, _, home = _home("vibe", tmp_path)
    text = (home / ".vibe" / "AGENTS.md").read_text()
    assert "RUN ON HOST" in text
    assert "Write output to /mnt/x." in text
    assert "## Capabilities" in text
    assert "`web_search`" in text  # search brief
    assert "drive a Chromium in an isolated sidecar" in text  # playwright headless brief
    assert "Model: `test-model`" in text  # llm brief


def test_context_file_environment_block(tmp_path):
    _, _, home = _home("pi", tmp_path)
    text = (home / ".pi" / "agent" / "AGENTS.override.md").read_text()
    assert "How your environment works" in text
    assert "/work" in text
    assert "Shell commands have no network" in text
    assert "cannot read the LLM API key" in text
    assert "nono" in text  # names the enforcer


def test_context_uses_resolved_mounts_on_basename_collision(tmp_path):
    (tmp_path / "a" / "foo").mkdir(parents=True)
    (tmp_path / "b" / "foo").mkdir(parents=True)
    work = tmp_path / "wd"
    work.mkdir()
    cfg = make_cfg(harness="pi", workdir=str(work), name="pi-sess",
                   add_dirs=[AddDir(path=str(tmp_path / "a" / "foo"), mode="ro"),
                             AddDir(path=str(tmp_path / "b" / "foo"), mode="rw")])
    text = build_environment_context(build_session_plan(cfg, home_dir=str(tmp_path / "home")))
    assert "/mnt/foo`" in text
    assert "/mnt/foo-2`" in text
    assert "(ro)" in text and "(rw)" in text


def test_context_reflects_absorbed_workdir(tmp_path):
    parent = tmp_path / "proj"
    (parent / "sub").mkdir(parents=True)
    cfg = make_cfg(harness="pi", workdir=str(parent / "sub"), name="pi-sess", add_dirs=[AddDir(str(parent), "ro")])
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "home"), cwd=str(parent / "sub"))
    text = build_environment_context(plan)
    assert plan.working_dir == "/mnt/proj/sub"
    assert "You start in `/mnt/proj/sub`" in text
    assert "/mnt/proj` (rw)" in text


def test_vibe_seeds_hooks_for_nono(tmp_path):
    _, _, home = _home("vibe", tmp_path, enforcer="nono")
    text = (home / ".vibe" / "hooks.toml").read_text()
    assert 'type = "pre_tool"' in text
    assert "/opt/glove/vibe-hook" in text
    assert "strict = true" in text
    assert tomllib.loads((home / ".vibe" / "config.toml").read_text())["experimental_bash_tool"] is False


def test_vibe_no_hooks_for_none_enforcer(tmp_path):
    _, _, home = _home("vibe", tmp_path, enforcer="none")
    assert not (home / ".vibe" / "hooks.toml").exists()


def test_pi_config(tmp_path):
    _, plan, home = _home("pi", tmp_path)
    agent = home / ".pi" / "agent"
    prov = json.loads((agent / "models.json").read_text())["providers"]["glove"]
    assert prov["baseUrl"] == "http://glove-pi-sess-llm:8080/v1"
    assert prov["api"] == "openai-completions"
    assert prov["models"][0]["id"] == "test-model"
    assert prov["apiKey"] == "glove-no-key"  # Pi refuses a keyless provider; a fixed non-secret
    settings = json.loads((agent / "settings.json").read_text())
    assert settings["defaultModel"] == "test-model"
    assert "SEARXNG_URL" not in settings.get("env", {})  # container env, not settings
    # the project's .pi/ never loads: no prompt, and no saved decision to override it
    assert settings["defaultProjectTrust"] == "never"
    assert json.loads((agent / "trust.json").read_text()) == {}
    assert settings["extensions"] == []  # Pi's MCP is on: search and playwright render servers
    servers = json.loads((agent / "mcp.json").read_text())["mcpServers"]
    assert servers["searxng"] == {"url": "http://glove-pi-sess-search-mcp:8000/mcp", "exposure": "hidden",
                                  "toolExposure": {"web_search": "direct"}}
    assert servers["playwright"]["exposure"] == "hidden"
    tools = json.loads(plan.policies["tools.json"])["allow"]
    assert "mcp__searxng__web_search" in tools and "mcp__playwright__browser_navigate" in tools


def test_pi_mcp_is_off_without_a_server(tmp_path):
    _, _, home = _home("pi", tmp_path, extensions={"direct": {}})
    agent = home / ".pi" / "agent"
    # Pi's MCP would start what a planted mcp.json says (it is read-only, rendered empty)
    assert json.loads((agent / "settings.json").read_text())["extensions"] == ["-builtin:mcp"]
    assert (agent / "mcp.json").read_text() == ""


def test_pi_renders_stdio_mcp_as_given_and_refuses_what_pi_would_interpret(tmp_path):
    from types import SimpleNamespace

    from glove.harness import adapter_call, get_profile
    from glove.manifest import ExtensionError

    def call(name):
        return adapter_call(get_profile("pi"), name, actx)

    stdio = {"name": "s-1", "transport": "stdio", "command": "/c", "args": ["a"], "env": {"K": "v"}, "tools": ["t-x"]}
    actx = SimpleNamespace(mcp=[("x", stdio)], sections=[])
    assert call("_mcp_servers") == {"s-1": {"command": "/c", "args": ["a"], "env": {"K": "v"}, "exposure": "hidden",
                                            "toolExposure": {"t-x": "direct"}}}
    assert call("tool_names") == ["mcp__s_1__t_x"]  # Pi's name for it
    for value in ("!gh auth token", " !id", "Bearer ${TOKEN}", "$HOME"):
        actx.mcp = [("x", {**stdio, "env": {"K": value}})]
        with pytest.raises(ExtensionError, match="Pi would run"):
            call("_mcp_servers")
    http = {"name": "h", "transport": "http", "url": "http://o/mcp"}
    for items, why in [([http], "needs its `tools`"),
                       ([stdio, {**http, "name": "s_1", "tools": ["t"]}], "same name in Pi"),
                       ([{**http, "tools": ["a-b", "a_b"]}], "two tools have the same name")]:
        actx.mcp = [("x", i) for i in items]
        with pytest.raises(ExtensionError, match=why):
            call("_mcp_servers")


def test_pi_empties_the_loaders_left_in_its_home(tmp_path):
    agent = tmp_path / "home" / ".pi" / "agent"
    agent.mkdir(parents=True)
    names = ("SYSTEM.md", "APPEND_SYSTEM.md", "keybindings.json")
    for name in (*names, "mcp.json", "AGENTS.md"):
        (agent / name).write_text("planted")
    _home("pi", tmp_path)
    # rendered empty, not removed: each is a read-only bind source, which must stay a file
    assert all((agent / n).is_file() and (agent / n).read_text() == "" for n in names)
    assert "mcpServers" in json.loads((agent / "mcp.json").read_text())  # glove's servers, not the planted file
    assert not (agent / "AGENTS.md").exists()
    assert "planted" not in (agent / "AGENTS.override.md").read_text()  # glove's brief, rendered


@pytest.mark.parametrize("vision,expected", [(True, ["text", "image"]), (False, ["text"])])
def test_pi_models_follow_descriptor_capabilities(tmp_path, vision, expected):
    llm = {**STUB_LLM, "capabilities": {"vision": vision, "context_window": 65536, "max_tokens": 4096,
                                        "reasoning": True}}
    _, _, home = _home("pi", tmp_path, llm=llm, extensions={})
    m = json.loads((home / ".pi" / "agent" / "models.json").read_text())["providers"]["glove"]["models"][0]
    assert m["input"] == expected
    assert m["contextWindow"] == 65536
    assert m["maxTokens"] == 4096
    assert m["reasoning"] is True and "thinkingLevelMap" in m


def test_vibe_supports_images_follows_vision(tmp_path):
    llm = {**STUB_LLM, "capabilities": {"vision": False}}
    _, _, home = _home("vibe", tmp_path, llm=llm, extensions={})
    assert tomllib.loads((home / ".vibe" / "config.toml").read_text())["models"][0]["supports_images"] is False


def test_key_reference_renders_env_var_name_never_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_LLM_KEY", "sk-NEVER-ON-DISK")
    llm = {**STUB_LLM, "api_key": "env:MY_LLM_KEY"}
    _, plan, home = _home("pi", tmp_path, llm=llm, extensions={})
    prov = json.loads((home / ".pi" / "agent" / "models.json").read_text())["providers"]["glove"]
    assert prov["apiKey"] == f"${LLM_API_KEY_ENV}"
    # injected: the harness's variable holds a placeholder, never the key
    assert plan.environment[LLM_API_KEY_ENV] == INJECTED_KEY
    for f in home.rglob("*"):
        if f.is_file():
            assert "sk-NEVER-ON-DISK" not in f.read_text()
    _, plan, home = _home("vibe", tmp_path / "v", llm=llm, extensions={})
    assert tomllib.loads((home / ".vibe" / "config.toml").read_text())["providers"][0]["api_key_env_var"] == \
        LLM_API_KEY_ENV


def test_extra_models_rendered(tmp_path):
    llm = {**STUB_LLM, "extra_models": [{"id": "vision-model", "vision": True}]}
    _, _, home = _home("pi", tmp_path, llm=llm, extensions={})
    models = json.loads((home / ".pi" / "agent" / "models.json").read_text())["providers"]["glove"]["models"]
    assert [m["id"] for m in models] == ["test-model", "vision-model"]
    assert models[1]["input"] == ["text", "image"]


def test_descriptor_refuses_unknown_api():
    with pytest.raises(ValueError, match="not one of"):
        ModelDescriptor.from_exports({"base_url": "http://x", "api": "grpc", "model": "m"})


def test_pi_harness_config_overrides(tmp_path):
    cfg, plan, home = _home("pi", tmp_path)
    cfg.harness_config = {
        "settings": {"defaultThinkingLevel": "xhigh", "env": {"FOO": "bar"},
                     "extensions": ["npm:x", "+builtin:mcp", "builtin:mcp"]},
        "model": {"contextWindow": 131072, "maxTokens": 100000},
    }
    render_home(cfg, plan, home)
    agent = home / ".pi" / "agent"
    settings = json.loads((agent / "settings.json").read_text())
    assert settings["defaultThinkingLevel"] == "xhigh"
    assert settings["env"]["FOO"] == "bar"
    # a session's own extensions are added; none names Pi's MCP (on here: glove renders servers)
    assert settings["extensions"] == ["npm:x"]
    model = json.loads((agent / "models.json").read_text())["providers"]["glove"]["models"][0]
    assert model["contextWindow"] == 131072
    assert model["maxTokens"] == 100000


@pytest.mark.parametrize("opt", [None, False, True])
def test_vibe_project_skills_opt_in(tmp_path, opt):
    # The repo's .vibe/ and .agents/ stay masked; project_skills shows only
    # their skills/ through, read-only, and never reaches Vibe's config.toml.
    kw = {} if opt is None else {"harness_config": {"project_skills": opt}}
    _, plan, home = _home("vibe", tmp_path, **kw)
    got = {p.container_path: p for p in plan.protect if p.container_path.startswith("/work/")}
    assert got["/work/.vibe"].host_path is None and got["/work/.agents"].host_path is None
    skills = {"/work/.vibe/skills", "/work/.agents/skills"}
    assert (skills <= set(got)) is bool(opt) and all(got[s].read_only for s in skills & set(got))
    assert "project_skills" not in tomllib.loads((home / ".vibe" / "config.toml").read_text())


def test_pi_never_sees_the_projects_settings(tmp_path):
    # Pi 1.x loads the project's .pi/settings.json as trusted on some paths
    # (a `sessionDir`, packages, ...): the harness gets an empty one (read as {}),
    # the repo's own is never bound, and .pi/ is pinned so it cannot be swapped.
    (tmp_path / "wd" / ".pi").mkdir(parents=True)
    (tmp_path / "wd" / ".pi" / "settings.json").write_text('{"sessionDir": "/work/x"}')
    _, plan, _ = _home("pi", tmp_path)
    got = {p.container_path: p for p in plan.protect if p.container_path.startswith("/work/")}
    assert got["/work/.pi/settings.json"].host_path is None and got["/work/.pi/settings.json"].read_only
    assert got["/work/.pi"].host_path.endswith("/wd/.pi") and not got["/work/.pi"].read_only


def test_vibe_project_skills_must_be_a_bool(tmp_path):
    with pytest.raises(ConfigError, match="project_skills must be true or false"):
        _home("vibe", tmp_path, harness_config={"project_skills": "yes"})


def test_pi_pins_its_session_dir_and_renders_no_credentials(tmp_path):
    _, plan, home = _home("pi", tmp_path)
    assert plan.environment["PI_CODING_AGENT_SESSION_DIR"] == "/home/agent/.pi/agent/sessions/--work--"
    assert json.loads((home / ".pi" / "agent" / "auth.json").read_text()) == {}
    auth = next(p for p in plan.protect if p.container_path == "/home/agent/.pi/agent/auth.json")
    assert auth.read_only and auth.host_path == str(home / ".pi" / "agent" / "auth.json")


def test_vibe_bridges_a_checked_http_mcp_server():
    from types import SimpleNamespace

    from glove.extensions import mcp_server
    from glove.harness import adapter_call, get_profile

    def servers(item):
        return adapter_call(get_profile("vibe"), "_mcp_servers", SimpleNamespace(harness_config={}, mcp=[("x", item)]))

    item = mcp_server("x", {"name": "s", "transport": "streamable-http", "url": "http://s/mcp", "tools": "a, b"})
    assert servers(item) == ([{"name": "s", "transport": "stdio", "command": "/opt/glove/bin/glove-mcp-bridge",
                               "args": ["http://s/mcp"]}], ["re:s_(?!(?:a|b)$).*"])
    with pytest.raises(ValueError, match=r"\[a-z0-9_\]"):  # Vibe's own rule, for its `<server>_<tool>` names
        servers({**item, "name": "S-1"})
