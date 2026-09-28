"""Config and secret-reference tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from glove.config import Config, Service


def test_defaults():
    cfg = Config()
    assert cfg.harness == "vibe"
    assert cfg.net == ["none"]
    assert cfg.allow_root is False


def test_service_infers_port():
    s = Service(name="llm", to="host.docker.internal:8899")
    assert s.port == 8899
    assert s.host_gateway is True


def test_service_join_network_no_host_gateway():
    s = Service(name="search", to="searxng:8080", join_network="my-llm-net")
    assert s.host_gateway is False
    assert s.port == 8080


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


@pytest.mark.parametrize("example", sorted((Path(__file__).parent.parent / "docs/examples").glob("*.yml")),
                         ids=lambda p: p.name)
def test_examples_plan(example, tmp_path):
    from glove import sessiondir
    from glove.plan import build_session_plan

    sd, sid = sessiondir.materialize(str(example), tmp_path / "s")
    cfg = sessiondir.to_config(sd, sessiondir.load_file(sd), sid)
    plan = build_session_plan(cfg, env_id="ex", home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))
    assert plan.model is not None


def test_secret_exists_never_reads_the_secret(monkeypatch):
    from glove.config import secret_exists

    calls = _fake_security(monkeypatch)
    assert secret_exists("keychain:my-llm")[0] is True
    assert calls == [["security", "find-generic-password", "-s", "my-llm"]]  # no -w: attributes only
    _fake_security(monkeypatch, rc=44)
    ok, detail = secret_exists("keychain:my-llm")
    assert not ok and "glove keychain set my-llm" in detail
    monkeypatch.setenv("K", "v")
    assert secret_exists("env:K")[0] and not secret_exists("env:NOPE_UNSET")[0]
    assert not secret_exists("sk-literal")[0]


def test_keychain_set_prompts_so_the_secret_is_never_in_argv(monkeypatch):
    from glove.config import ConfigError, keychain_set

    calls = _fake_security(monkeypatch)
    monkeypatch.setenv("USER", "me")
    assert keychain_set("my-llm") == 0
    assert calls == [["security", "add-generic-password", "-U", "-a", "me", "-s", "my-llm", "-w"]]  # -w last
    with pytest.raises(ConfigError):
        keychain_set("-s")
