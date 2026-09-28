"""Config resolution tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from glove.config import (
    AddDir,
    Config,
    Service,
    parse_add_dir_flag,
    resolve,
)


def test_defaults():
    cfg = Config()
    assert cfg.harness == "vibe"
    assert cfg.net == ["none"]
    assert cfg.allow_root is False


def test_env_file_over_defaults(tmp_path):
    env_cfg = tmp_path / "glove.yaml"
    env_cfg.write_text(
        "harness: pi\nnet: [service]\nadd_dirs:\n  - path: /data\n    mode: rw\n"
    )
    cfg = resolve(env_config_path=env_cfg, overrides={})
    assert cfg.harness == "pi"
    assert cfg.net == ["service"]
    assert cfg.add_dirs == [AddDir("/data", "rw")]


def test_flag_over_env_file(tmp_path):
    env_cfg = tmp_path / "glove.yaml"
    env_cfg.write_text("harness: pi\n")
    cfg = resolve(env_config_path=env_cfg, overrides={"harness": "vibe"})
    assert cfg.harness == "vibe"


def test_config_overlay_over_env_file(tmp_path):
    env_cfg = tmp_path / "glove.yaml"
    env_cfg.write_text("harness: pi\nenforcer: nono\n")
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text("enforcer: srt\n")
    cfg = resolve(env_config_path=env_cfg, config_path=overlay, overrides={})
    assert cfg.harness == "pi"  # kept from env file
    assert cfg.enforcer == "srt"  # overridden by --config overlay


def test_none_overrides_ignored(tmp_path):
    env_cfg = tmp_path / "glove.yaml"
    env_cfg.write_text("harness: pi\n")
    cfg = resolve(env_config_path=env_cfg, overrides={"harness": None, "name": "x"})
    assert cfg.harness == "pi"
    assert cfg.name == "x"


def test_add_dirs_from_flags_append(tmp_path):
    env_cfg = tmp_path / "glove.yaml"
    env_cfg.write_text("add_dirs:\n  - path: /a\n    mode: ro\n")
    cfg = resolve(env_config_path=env_cfg, overrides={"add_dirs": [AddDir("/b", "rw")]})
    assert cfg.add_dirs == [AddDir("/a", "ro"), AddDir("/b", "rw")]


def test_missing_env_file_yields_defaults(tmp_path):
    cfg = resolve(env_config_path=tmp_path / "nope.yaml", overrides={})
    assert cfg.harness == "vibe"


def test_service_infers_port():
    s = Service(name="llm", to="host.docker.internal:8899")
    assert s.port == 8899
    assert s.host_gateway is True


def test_service_join_network_no_host_gateway():
    s = Service(name="search", to="searxng:8080", join_network="my-llm-net")
    assert s.host_gateway is False
    assert s.port == 8080


def test_parse_add_dir_flag():
    assert parse_add_dir_flag("/x:rw") == AddDir("/x", "rw")
    assert parse_add_dir_flag("/x") == AddDir("/x", "ro")
    # a colon that isn't a mode is kept as part of the path
    assert parse_add_dir_flag("/x:y") == AddDir("/x:y", "ro")


def test_effective_config_round_trips():
    cfg = Config(harness="vibe", net=["service"], name="s")
    cfg.services = [Service(name="llm", to="host.docker.internal:8899")]
    dumped = cfg.to_yaml()
    data = yaml.safe_load(dumped)
    assert data["harness"] == "vibe"
    assert data["services"][0]["name"] == "llm"
    assert data["services"][0]["port"] == 8899


# --- secret references (keychain:/env:), resolved in memory at launch ----------

def _fake_security(monkeypatch, *, secret="sk-from-keychain", rc=0):
    import subprocess

    from glove import config as config_mod

    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, rc, stdout=secret + "\n", stderr="")

    monkeypatch.setattr(config_mod.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(config_mod.subprocess, "run", run)
    return calls


def test_resolve_secret_literal_is_unchanged():
    from glove.config import resolve_secret

    assert resolve_secret("sk-literal") == "sk-literal"


def test_resolve_secret_reads_the_environment(monkeypatch):
    import pytest

    from glove.config import ConfigError, resolve_secret

    monkeypatch.setenv("MY_LLM_KEY", "sk-env")
    assert resolve_secret("env:MY_LLM_KEY") == "sk-env"
    monkeypatch.delenv("MY_LLM_KEY")
    with pytest.raises(ConfigError, match="MY_LLM_KEY"):
        resolve_secret("env:MY_LLM_KEY")


def test_resolve_secret_reads_the_keychain_by_service(monkeypatch):
    from glove.config import resolve_secret

    calls = _fake_security(monkeypatch)
    assert resolve_secret("keychain:my-llm") == "sk-from-keychain"
    # the service name is the only argument; the secret comes back on stdout
    assert calls == [["security", "find-generic-password", "-s", "my-llm", "-w"]]


def test_resolve_secret_missing_keychain_entry_is_a_config_error(monkeypatch):
    import pytest

    from glove.config import ConfigError, resolve_secret

    _fake_security(monkeypatch, secret="", rc=44)
    with pytest.raises(ConfigError, match="my-llm"):
        resolve_secret("keychain:my-llm")


def test_retired_v2_keys_are_refused(tmp_path):
    import pytest

    from glove.config import ConfigError

    for key in ("model: m", "llm_api_key: keychain:x", "llm_service: llm", "plugins: [search]", "browser: {}"):
        (tmp_path / "glove.yaml").write_text(f"harness: pi\n{key}\n")
        with pytest.raises(ConfigError, match="unknown config keys"):
            resolve(env_config_path=tmp_path / "glove.yaml", overrides={})


@pytest.mark.parametrize("example", sorted((Path(__file__).parent.parent / "docs/examples").glob("*.yaml")),
                         ids=lambda p: p.name)
def test_examples_plan(example, tmp_path):
    from glove.config import load_config
    from glove.plan import build_session_plan

    cfg = load_config(example)
    cfg.workdir = str(tmp_path)
    plan = build_session_plan(cfg, env_id="ex", home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))
    assert plan.model is not None
