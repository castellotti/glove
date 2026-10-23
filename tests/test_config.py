"""Config and secret-reference tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from glove.config import Config, ConfigError, _coerce


def test_defaults():
    cfg = Config()
    assert cfg.harness == ""  # no default: a session file names its harness
    assert cfg.allow_root is False
    assert not hasattr(cfg, "services") and not hasattr(cfg, "net")  # forwarders come from extensions


def test_effective_config_round_trips():
    cfg = Config(harness="vibe", name="s", extensions={"llm": {"provider": "llama.cpp"}})
    data = yaml.safe_load(cfg.to_yaml())
    assert data["harness"] == "vibe"
    assert data["extensions"] == {"llm": {"provider": "llama.cpp"}}


def test_keys_config_has_dropped_in_an_old_effective_file_are_ignored(tmp_path):
    """An older glove's effective.yml/baseline.yml still reads (v2's forwarder
    keys, round 16's toolchains/host_services): a None here would silently
    drop the resume widening warning."""
    from glove.sessiondir import read_effective

    f = tmp_path / "baseline.yml"
    f.write_text(yaml.safe_dump({"config": {
        "harness": "pi", "net": ["service"], "services": [{"name": "x", "to": "a:1"}],
        "observe": {"enabled": True}, "toolchains": [], "host_services": [], "allow_root": True}}))
    cfg, _ = read_effective(f)
    assert cfg is not None and cfg.harness == "pi" and cfg.allow_root is True
    with pytest.raises(ConfigError, match="unknown config keys"):  # a session file's typo still fails
        _coerce({"harness": "pi", "toolchains": []})


# --- secret references (keychain:/env:), resolved in memory at launch ----------

def _fake_security(monkeypatch, *, secret="sk-from-keychain", rc=0):
    import subprocess

    from glove import config as config_mod

    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, rc, stdout=secret + "\n", stderr="")

    monkeypatch.setattr(config_mod.sys, "platform", "darwin")
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
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))
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


def _fake_secret_tool(monkeypatch, *, which=("secret-tool",), rc=0, stderr=""):
    import subprocess

    from glove import config as config_mod

    calls = []
    monkeypatch.setattr(config_mod.sys, "platform", "linux")
    monkeypatch.setattr(config_mod.shutil, "which", lambda name: "/usr/bin/" + name if name in which else None)
    monkeypatch.setattr(config_mod.subprocess, "run", lambda cmd, **kw: calls.append(cmd)
                        or subprocess.CompletedProcess(cmd, rc, stdout="" if rc else "sk-from-secret-service",
                                                       stderr=stderr))
    return calls


def test_on_linux_keychain_reads_the_secret_service(monkeypatch):
    from glove.config import resolve_secret, secret_exists

    calls = _fake_secret_tool(monkeypatch)
    assert resolve_secret("keychain:my-llm") == "sk-from-secret-service"
    assert secret_exists("keychain:my-llm") == (True, "Secret Service item exists")
    assert calls == [["secret-tool", "lookup", "application", "glove", "service", "my-llm"]] * 2
    _fake_secret_tool(monkeypatch, rc=1)  # a missing item: secret-tool fails silently
    with pytest.raises(ConfigError, match="keychain:my-llm: no Secret Service item for service 'my-llm'"):
        resolve_secret("keychain:my-llm")
    assert secret_exists("keychain:my-llm") == (False, "no Secret Service item; create it with "
                                                       "`glove keychain set my-llm`")


@pytest.mark.parametrize(("which", "stderr", "match"), [
    ((), "", "libsecret-tools"),
    # no Secret Service on the bus (a server, SSH): secret-tool's own reason, never "no item"
    (("secret-tool",), "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY", "secret-tool: Cannot autolaunch"),
])
def test_on_linux_without_a_secret_service_keychain_says_why_and_points_at_env(monkeypatch, which, stderr, match):
    from glove.config import resolve_secret, secret_exists

    _fake_secret_tool(monkeypatch, which=which, rc=1, stderr=stderr)
    with pytest.raises(ConfigError, match=match) as e:
        resolve_secret("keychain:my-llm")
    assert str(e.value).startswith("keychain:my-llm: ") and "env:<VAR>" in str(e.value)
    ok, detail = secret_exists("keychain:my-llm")
    assert not ok and match in detail and "env:<VAR>" in detail  # nothing falls back to a file


@pytest.mark.parametrize(("tools", "match"), [
    ({"net": "block"}, r"unknown tools keys: \['net'\]"),
    ({"allow_comands": ["cp"]}, "unknown tools keys"),
    ({"allow_commands": "cp"}, "must be a list of command names"),
    ({"deny_commands": [""]}, "must be a list of command names"),
    (["cp"], "must be a mapping"),
])
def test_tools_keys_and_values_are_checked(tools, match):
    with pytest.raises(ConfigError, match=match):
        _coerce({"harness": "pi", "tools": tools})


def test_tools_command_lists_load():
    assert _coerce({"harness": "pi", "tools": {"allow_commands": ["cp"], "deny_commands": []}}).tools \
        == {"allow_commands": ["cp"], "deny_commands": []}


def test_a_blank_tools_key_or_value_is_unset():
    assert _coerce({"harness": "pi", "tools": None}).tools == {}
    assert _coerce({"harness": "pi", "tools": {"allow_commands": None, "deny_commands": ["git"]}}).tools \
        == {"deny_commands": ["git"]}


def test_tools_need_an_enforcer_that_runs_nono(tmp_path):
    from helpers import make_cfg

    from glove.plan import build_session_plan

    cfg = make_cfg(harness="pi", name="s", workdir=str(tmp_path), enforcer="srt",
                   tools={"allow_commands": ["cp"]})
    with pytest.raises(ConfigError, match="would be ignored"):
        build_session_plan(cfg, home_dir=str(tmp_path / "h"), uid=501, gid=20)


def test_host_services_are_no_longer_a_session_key(tmp_path):
    from helpers import make_session

    from glove import sessiondir as sdm

    d = make_session(tmp_path / "a", "host_services:\n  - {name: t, command: sleep 1}\n")
    with pytest.raises(sdm.SessionError, match=r"host_services: a session starts no host processes; `playwright: "):
        sdm.load_file(sdm.SessionDir(d))
    # an effective.yml written before they were removed still reads
    eff = tmp_path / "effective.yml"
    eff.write_text("config: {harness: pi, toolchains: [], host_services: [{name: t, command: sleep 1}]}\n"
                   "resolved: {}\n")
    assert sdm.read_effective(eff)[0].harness == "pi"


def test_load_yaml_errors_are_yaml_errors():
    import yaml

    from glove.config import load_yaml

    assert load_yaml("a: [1, 2]\n") == {"a": [1, 2]}
    for bad in ("a: [1\n", "a: \ud800\n"):  # a lone surrogate: libyaml's is a UnicodeError
        with pytest.raises(yaml.YAMLError):
            load_yaml(bad)
