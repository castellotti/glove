"""Config resolution tests."""

from __future__ import annotations

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
    env_cfg.write_text("harness: pi\nmodel: a\n")
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text("model: b\n")
    cfg = resolve(env_config_path=env_cfg, config_path=overlay, overrides={})
    assert cfg.harness == "pi"  # kept from env file
    assert cfg.model == "b"  # overridden by --config overlay


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
    s = Service(name="search", to="searxng:8080", join_network="local-llm_ai-net")
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
