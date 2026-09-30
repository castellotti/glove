"""Harness-config generation tests (Pi models.json / Vibe config.toml / context)."""

from __future__ import annotations

import json
import re
import tomllib

import pytest
from helpers import STUB_LLM, make_cfg

from glove.config import AddDir, Config
from glove.harness import get_profile
from glove.harnessconfig import LLM_API_KEY_ENV, ModelDescriptor, build_environment_context, render_home
from glove.mounts import compute_mounts
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
    render_home(cfg, plan.profile, home, plan.model, mount_plan=plan.mount_plan, comp=plan.composition)
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
    assert pw["url"] == "http://glove-vibe-sess-browser:8931/mcp" and "enabled_tools" not in pw
    # the playwright allowlist, as a Vibe denylist scoped to that server's tools
    (deny,) = doc["disabled_tools"]
    assert deny.startswith("re:playwright_(?!(?:browser_navigate|")
    hidden = re.compile(deny.removeprefix("re:"))
    assert hidden.fullmatch("playwright_browser_run_code_unsafe") and hidden.fullmatch("playwright_browser_evaluate")
    assert not hidden.fullmatch("playwright_browser_navigate") and not hidden.fullmatch("bash")
    assert not hidden.fullmatch("searxng_search")
    sx = next(s for s in doc["mcp_servers"] if s["name"] == "searxng")
    assert sx["env"]["SEARXNG_URL"] == "http://glove-vibe-sess-search:8080"


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
    text = (home / ".pi" / "agent" / "AGENTS.md").read_text()
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
    cfg = Config(harness="pi", workdir=str(work), name="pi-sess")
    cfg.add_dirs = [AddDir(path=str(tmp_path / "a" / "foo"), mode="ro"),
                    AddDir(path=str(tmp_path / "b" / "foo"), mode="rw")]
    plan = compute_mounts(cfg.workdir, [(a.path, a.mode) for a in cfg.add_dirs])
    text = build_environment_context(cfg, plan)
    assert "/mnt/foo`" in text
    assert "/mnt/foo-2`" in text
    assert "(ro)" in text and "(rw)" in text


def test_context_reflects_absorbed_workdir(tmp_path):
    parent = tmp_path / "proj"
    (parent / "sub").mkdir(parents=True)
    cfg = Config(harness="pi", workdir=str(parent / "sub"), name="pi-sess")
    cfg.add_dirs = [AddDir(path=str(parent), mode="ro")]
    plan = compute_mounts(cfg.workdir, [(a.path, a.mode) for a in cfg.add_dirs])
    text = build_environment_context(cfg, plan)
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
    _, _, home = _home("pi", tmp_path)
    agent = home / ".pi" / "agent"
    prov = json.loads((agent / "models.json").read_text())["providers"]["glove"]
    assert prov["baseUrl"] == "http://glove-pi-sess-llm:8080/v1"
    assert prov["api"] == "openai-completions"
    assert prov["models"][0]["id"] == "test-model"
    assert prov["apiKey"] == "glove-no-key"  # Pi refuses a keyless provider; a fixed non-secret
    settings = json.loads((agent / "settings.json").read_text())
    assert settings["defaultModel"] == "test-model"
    assert "SEARXNG_URL" not in settings.get("env", {})  # container env, not settings
    assert (agent / "extensions").is_dir()


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
    assert plan.passthrough_env == [LLM_API_KEY_ENV]
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
        "settings": {"defaultThinkingLevel": "xhigh", "env": {"FOO": "bar"}},
        "model": {"contextWindow": 131072, "maxTokens": 100000},
    }
    render_home(cfg, get_profile("pi"), home, plan.model, comp=plan.composition)
    agent = home / ".pi" / "agent"
    settings = json.loads((agent / "settings.json").read_text())
    assert settings["defaultThinkingLevel"] == "xhigh"
    assert settings["env"]["FOO"] == "bar"
    model = json.loads((agent / "models.json").read_text())["providers"]["glove"]["models"][0]
    assert model["contextWindow"] == 131072
    assert model["maxTokens"] == 100000
