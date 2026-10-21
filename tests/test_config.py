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


def test_legacy_v2_keys_in_an_old_effective_file_are_ignored():
    from glove.config import _coerce

    cfg = _coerce({"harness": "pi", "net": ["service"], "services": [{"name": "x", "to": "a:1"}],
                   "observe": {"enabled": True}})
    assert cfg.harness == "pi"


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


def test_keychain_set_prompts_so_the_secret_is_never_in_argv(monkeypatch):
    from glove.config import ConfigError, keychain_set

    calls = _fake_security(monkeypatch)
    monkeypatch.setenv("USER", "me")
    assert keychain_set("my-llm") == 0
    assert calls == [["security", "add-generic-password", "-U", "-a", "me", "-s", "my-llm", "-w"]]  # -w last
    with pytest.raises(ConfigError):
        keychain_set("-s")


def test_keychain_set_with_a_secret_feeds_it_to_security_on_stdin_quoted(monkeypatch):
    import subprocess

    from glove import config as config_mod
    from glove.config import ConfigError, keychain_set

    calls = []
    monkeypatch.setattr(config_mod.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(config_mod.subprocess, "run", lambda cmd, **kw: calls.append((cmd, kw.get("input")))
                        or subprocess.CompletedProcess(cmd, 44 if "delete-generic-password" in cmd else 0))
    monkeypatch.setenv("USER", "me")
    assert keychain_set("corp pat", 'a b"c\\d') == 0
    # never in argv: one `security -i` line, every word quoted (checked against
    # the real tool by hand: it stores a b"c\d); then no stale parts (below)
    assert calls == [(["security", "-i"],
                      '"add-generic-password" "-U" "-a" "me" "-s" "corp pat" "-w" "a b\\"c\\\\d"\n'),
                     (["security", "delete-generic-password", "-s", "corp pat.part1"], None)]
    for bad in ("", "two\nlines", "nul\0"):
        with pytest.raises(ConfigError, match="one non-empty line"):
            keychain_set("svc", bad)
    with pytest.raises(ConfigError, match="one non-empty line"):
        keychain_set("svc\n-x", "s")


class _FakeKeychain:
    """`security` over a dict: `-i` add lines, find -w, delete."""

    def __init__(self, monkeypatch):
        import shlex
        import subprocess

        from glove import config as config_mod

        self.items: dict[str, str] = {}
        self.lines: list[str] = []

        def run(cmd, **kw):
            rc, out = 0, ""
            if cmd[1] == "-i":
                self.lines.append(kw["input"])
                words = shlex.split(kw["input"])
                assert len(kw["input"]) < 4096  # what security -i reads of a line
                self.items[words[words.index("-s") + 1]] = words[-1]
            elif cmd[1] == "find-generic-password":
                rc, out = (0, self.items[cmd[3]] + "\n") if cmd[3] in self.items else (44, "")
            elif cmd[1] == "delete-generic-password":
                rc = 0 if self.items.pop(cmd[3], None) is not None else 44
            return subprocess.CompletedProcess(cmd, rc, out, "")

        monkeypatch.setattr(config_mod.shutil, "which", lambda name: "/usr/bin/" + name)
        monkeypatch.setattr(config_mod.subprocess, "run", run)


def test_a_long_secret_is_stored_in_parts_and_read_back_whole(monkeypatch):
    import json

    from glove.config import ConfigError, keychain_set, resolve_secret

    kc = _FakeKeychain(monkeypatch)
    value = json.dumps({"cookies": [{"name": f"c{i}", "value": 'v"\\' * 40} for i in range(200)]})
    assert keychain_set("state", value) == 0
    assert kc.items["state"].startswith("glove-parts:") and "state.part2" in kc.items
    assert all(value not in line for line in kc.lines)  # never one over-long line
    assert resolve_secret("keychain:state") == value
    # a torn store (a part replaced) is refused, not handed over spliced
    kc.items["state.part1"] = "x"
    with pytest.raises(ConfigError, match="parts"):
        resolve_secret("keychain:state")
    # a short value again: the old parts go
    assert keychain_set("state", "short") == 0
    assert kc.items == {"state": "short"}
    assert resolve_secret("keychain:state") == "short"


def test_keychain_set_refuses_what_security_would_read_back_differently(monkeypatch):
    from glove.config import ConfigError, keychain_set

    _FakeKeychain(monkeypatch)
    with pytest.raises(ConfigError, match="ASCII"):  # `security -w` prints it hex-encoded
        keychain_set("svc", "héllo")
    with pytest.raises(ConfigError, match="glove-parts:"):
        keychain_set("svc", "glove-parts:2:abc")


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
