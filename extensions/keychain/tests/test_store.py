"""The `keychain` library's writers (`store.keychain_set`): the secret is never in argv or a file."""

import json
import shlex
import shutil
import subprocess
import sys

import pytest

from extensions.keychain.store import keychain_set
from glove.api import ConfigError, resolve_secret


def _fake_run(monkeypatch, run, *, platform="darwin"):
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setenv("USER", "me")


def _recorder(monkeypatch, *, platform="darwin", rc=0, stderr=""):
    calls = []
    _fake_run(monkeypatch, lambda cmd, **kw: calls.append((cmd, kw.get("input"))) or subprocess.CompletedProcess(
        cmd, 44 if {"delete-generic-password", "clear"} & {*cmd} else rc, "", stderr), platform=platform)
    return calls


def test_keychain_set_prompts_so_the_secret_is_never_in_argv(monkeypatch):
    calls = _recorder(monkeypatch)
    assert keychain_set("my-llm") == 0
    assert calls == [(["security", "add-generic-password", "-U", "-a", "me", "-s", "my-llm", "-w"], None),  # -w last
                     (["security", "delete-generic-password", "-s", "my-llm.part1"], None)]
    with pytest.raises(ConfigError):
        keychain_set("-s")


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_no_prompt_without_a_terminal(monkeypatch, platform):
    # secret-tool would store what is piped, cut at 8 KB, and exit 0
    calls = _recorder(monkeypatch, platform=platform)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(ConfigError, match="--stdin"):
        keychain_set("svc")
    assert calls == []


def test_a_value_typed_at_the_prompt_clears_the_old_parts(monkeypatch):
    kc = _FakeKeychain(monkeypatch, "linux")
    assert keychain_set("state", "v" * 20_000) == 0 and "state.part3" in kc.items
    assert keychain_set("state") == 0  # the fake stores nothing for a prompt
    assert not [k for k in kc.items if ".part" in k]


def test_keychain_set_with_a_secret_feeds_it_to_security_on_stdin_quoted(monkeypatch):
    calls = _recorder(monkeypatch)
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
    """`security` (`-i` add lines, find -w, delete) or `secret-tool` (store from
    stdin, lookup, clear) over a dict; each write within what the tool takes."""

    def __init__(self, monkeypatch, platform="darwin"):
        self.items: dict[str, str] = {}
        self.lines: list[str] = []

        def run(cmd, **kw):
            rc, out = 0, ""
            if cmd[1] == "-i":
                self.lines.append(kw["input"])
                words = shlex.split(kw["input"])
                assert len(kw["input"]) < 4096  # what security -i reads of a line
                self.items[words[words.index("-s") + 1]] = words[-1]
            elif cmd[1] == "store":
                if kw.get("input") is None:  # prompted
                    return subprocess.CompletedProcess(cmd, 0, "", "")
                self.lines.append(kw["input"])
                assert len(kw["input"].encode()) < 8192  # what secret-tool keeps of stdin
                self.items[cmd[-1]] = kw["input"]
            elif cmd[1] in ("find-generic-password", "lookup"):
                svc = cmd[-1] if cmd[1] == "lookup" else cmd[3]  # security's `-w` comes last
                rc, out = (0, self.items[svc] + "\n") if svc in self.items else (44, "")
            elif cmd[1] in ("delete-generic-password", "clear"):
                rc = 0 if self.items.pop(cmd[-1], None) is not None else 44
            return subprocess.CompletedProcess(cmd, rc, out, "")

        _fake_run(monkeypatch, run, platform=platform)


@pytest.mark.parametrize(("platform", "unit"), [("darwin", 'v"\\'), ("linux", 'v"\\✓')])
def test_a_long_secret_is_stored_in_parts_and_read_back_whole(monkeypatch, platform, unit):
    kc = _FakeKeychain(monkeypatch, platform)
    value = json.dumps({"cookies": [{"name": f"c{i}", "value": unit * 40} for i in range(200)]}, ensure_ascii=False)
    assert keychain_set("state", value) == 0
    assert kc.items["state"].startswith("glove-parts:") and "state.part2" in kc.items
    assert all(value not in line for line in kc.lines)  # never one over-long line
    assert resolve_secret("keychain:state") == value  # core's reader joins them
    # a torn store (a part replaced) is refused, not handed over spliced
    kc.items["state.part1"] = "x"
    with pytest.raises(ConfigError, match="parts"):
        resolve_secret("keychain:state")
    # a short value again: the old parts go
    assert keychain_set("state", "short") == 0
    assert kc.items == {"state": "short"}
    assert resolve_secret("keychain:state") == "short"


def test_keychain_set_refuses_what_security_would_read_back_differently(monkeypatch):
    _FakeKeychain(monkeypatch)
    with pytest.raises(ConfigError, match="ASCII"):  # `security -w` prints it hex-encoded
        keychain_set("svc", "héllo")
    with pytest.raises(ConfigError, match="glove-parts:"):
        keychain_set("svc", "glove-parts:2:abc")


def test_on_linux_secret_tool_stores_from_stdin(monkeypatch):
    calls = _recorder(monkeypatch, platform="linux")
    store = ["secret-tool", "store", "--label", "glove: corp pat", "application", "glove", "service", "corp pat"]
    assert keychain_set("corp pat") == 0  # prompted: secret-tool asks, with no echo
    assert keychain_set("corp pat", "héllo") == 0  # not ASCII-only
    clear = (["secret-tool", "clear", "application", "glove", "service", "corp pat.part1"], None)
    assert calls == [(store, None), clear, (store, "héllo"), clear]
    with pytest.raises(ConfigError, match="one non-empty line"):
        keychain_set("svc", "two\nlines")


def test_on_linux_a_failed_store_says_why(monkeypatch):
    # a server or an SSH login: no Secret Service on the bus (or a locked collection)
    _recorder(monkeypatch, platform="linux", rc=1, stderr="secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY")
    with pytest.raises(ConfigError, match=r"^secret-tool: Cannot autolaunch .*; without a .*env:<VAR>$"):
        keychain_set("svc", "s3cret")
