"""Harness-config generation tests (DESIGN.md B.3 + A.6)."""

from __future__ import annotations

import json
import tomllib

from glove.config import AddDir, Config, Service
from glove.harness import get_profile
from glove.harnessconfig import container_llm_base, render_home


def _cfg(harness: str, tmp_path):
    work = tmp_path / "wd"
    work.mkdir()
    cfg = Config(
        harness=harness,
        workdir=str(work),
        name=f"{harness}-sess",
        net=["service"],
        model="qwen3.8-27b-5090",
        brief="Write output to /mnt/x.",
    )
    cfg.services = [
        Service(name="llm", to="host.docker.internal:8899", port=8080),
        Service(name="search", to="searxng:8080", join_network="local-llm_ai-net"),
        Service(name="browser", to="host.docker.internal:8931"),
    ]
    return cfg


def test_llm_base_from_service(tmp_path):
    cfg = _cfg("vibe", tmp_path)
    assert container_llm_base(cfg, "vibe-sess") == "http://glove-vibe-sess-llm:8080/v1"


def test_vibe_config_toml(tmp_path):
    cfg = _cfg("vibe", tmp_path)
    home = tmp_path / "home"
    render_home(cfg, get_profile("vibe"), "vibe-sess", home)
    doc = tomllib.loads((home / ".vibe" / "config.toml").read_text())
    # Must be a unique alias, NOT Vibe's built-in "local" (Devstral) alias.
    assert doc["active_model"] == "faustulus"
    assert doc["models"][0]["alias"] == "faustulus"
    prov = doc["providers"][0]
    assert prov["name"] == "faustulus"
    assert prov["api_base"] == "http://glove-vibe-sess-llm:8080/v1"
    assert prov["api_key_env_var"] == ""  # no MISTRAL_API_KEY needed
    model = doc["models"][0]
    assert model["name"] == "qwen3.8-27b-5090"
    assert model["provider"] == "faustulus"
    # MCP auto-derived from services
    names = {s["name"] for s in doc["mcp_servers"]}
    assert names == {"playwright", "searxng"}
    pw = next(s for s in doc["mcp_servers"] if s["name"] == "playwright")
    assert pw["url"] == "http://glove-vibe-sess-browser:8931/mcp"
    sx = next(s for s in doc["mcp_servers"] if s["name"] == "searxng")
    assert sx["env"]["SEARXNG_URL"] == "http://glove-vibe-sess-search:8080"


def test_vibe_context_file_has_sudo_relay_and_brief(tmp_path):
    cfg = _cfg("vibe", tmp_path)
    home = tmp_path / "home"
    render_home(cfg, get_profile("vibe"), "vibe-sess", home)
    text = (home / ".vibe" / "AGENTS.md").read_text()
    assert "RUN ON HOST" in text
    assert "Write output to /mnt/x." in text


def test_context_file_environment_block(tmp_path):
    # PLAN §5.1: generated "How your environment works" block.
    cfg = _cfg("pi", tmp_path)
    home = tmp_path / "home"
    render_home(cfg, get_profile("pi"), "pi-sess", home)
    text = (home / ".pi" / "agent" / "AGENTS.md").read_text()
    assert "How your environment works" in text
    assert "/work" in text
    assert "browser tool is the only way to reach the web" in text
    assert "Shell commands have no network" in text
    assert "cannot read the LLM API key" in text
    assert "nono" in text  # names the enforcer


def test_pi_config_and_extension(tmp_path):
    cfg = _cfg("pi", tmp_path)
    home = tmp_path / "home"
    render_home(cfg, get_profile("pi"), "pi-sess", home)
    agent = home / ".pi" / "agent"
    models = json.loads((agent / "models.json").read_text())
    prov = models["providers"]["faustulus"]
    assert prov["baseUrl"] == "http://glove-pi-sess-llm:8080/v1"
    assert prov["models"][0]["id"] == "qwen3.8-27b-5090"
    settings = json.loads((agent / "settings.json").read_text())
    assert settings["defaultModel"] == "qwen3.8-27b-5090"
    assert settings["env"]["SEARXNG_URL"] == "http://glove-pi-sess-search:8080"
    # glove's extensions are baked into the image (loaded via `pi -e`), not
    # seeded here; only a user extensions/ dir is ensured.
    assert (agent / "extensions").is_dir()
