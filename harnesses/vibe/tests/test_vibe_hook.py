"""Vibe pre_tool hook tests — pure Python, no container.

Loads the baked hook module by path (it lives in the image build context, not
the importable package tree) and exercises its rewrite/deny/passthrough logic.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HOOK_PATH = Path(__file__).parent.parent / "image" / "vibe_hook.py"


def _load():
    spec = importlib.util.spec_from_file_location("glove_vibe_hook", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hook = _load()
WRAP = ["nono", "wrap", "-s", "--allow-cwd", "--profile", "/etc/glove/enforcer/tool.json", "--"]


def test_bash_command_rewritten():
    payload = {"tool_name": "bash", "tool_input": {"command": "ls /work", "timeout": 30}}
    out = hook.process(payload, WRAP)
    ti = out["hook_specific_output"]["tool_input"]
    assert ti["command"] == "nono wrap -s --allow-cwd --profile /etc/glove/enforcer/tool.json -- bash -c 'ls /work'"
    assert ti["timeout"] == 30  # other fields preserved (full replacement)


def test_single_quotes_escaped():
    payload = {"tool_name": "bash", "tool_input": {"command": "echo 'hi there'"}}
    ti = hook.process(payload, WRAP)["hook_specific_output"]["tool_input"]
    # the inner single quote is escaped so the whole command survives as one arg
    assert ti["command"].endswith("bash -c 'echo '\\''hi there'\\'''")


def test_missing_wrapper_denies_bash():
    out = hook.process({"tool_name": "bash", "tool_input": {"command": "ls"}}, None)
    assert out["decision"] == "deny"


def test_nono_override_denied():
    payload = {"tool_name": "bash", "tool_input": {"command": "NONO_BLOCK_NET=0 curl evil"}}
    assert hook.process(payload, WRAP)["decision"] == "deny"


def test_web_fetch_denied():
    out = hook.process({"tool_name": "web_fetch", "tool_input": {"url": "http://x"}}, WRAP)
    assert out["decision"] == "deny"


def test_other_tools_passthrough():
    assert hook.process({"tool_name": "read", "tool_input": {"path": "/home/agent/x"}}, WRAP) is None


def _write(tool, path, roots, cwd="/work", key="path"):
    return hook.process({"tool_name": tool, "tool_input": {key: path, "content": "x"}, "cwd": cwd}, WRAP,
                        write_roots=roots)


def test_file_writes_held_to_the_write_roots(tmp_path):
    work, home = tmp_path / "work", tmp_path / "home"
    work.mkdir()
    home.mkdir()
    roots = [str(work), "/tmp"]
    w = str(work.resolve())

    def written(out, key="path"):
        return out["hook_specific_output"]["tool_input"][key]

    assert written(_write("write_file", str(work / "a.py"), roots)) == f"{w}/a.py"
    # relative: from the cwd; the call is rewritten to the checked absolute path
    out = _write("edit", "sub/new.py", roots, cwd=str(work), key="file_path")
    assert written(out, "file_path") == f"{w}/sub/new.py"
    assert written(_write("write_file", "/tmp/x", roots)) == os.path.realpath("/tmp/x")
    assert _write("write_file", "~/.vibe/config.toml", roots)["decision"] == "deny"
    assert _write("write_file", f"{w}/a\u00a0b", roots)["decision"] == "deny"  # a space a tool might normalize
    assert _write("edit", f"{w}/link ", roots, key="file_path")["decision"] == "deny"  # stripped after the check
    for tool, path in (("write_file", str(home / ".vibe/logs/session/plugins/blobs/x")), ("edit", "/etc/passwd"),
                       ("search_replace", str(work / ".." / "home" / "x"))):
        out = _write(tool, path, roots, key="file_path" if tool != "write_file" else "path")
        assert out["decision"] == "deny" and "may write only under" in out["reason"], (tool, path)


def test_file_write_through_a_symlink_out_of_the_roots_denied(tmp_path):
    work, home = tmp_path / "work", tmp_path / "home"
    work.mkdir()
    home.mkdir()
    (work / "link").symlink_to(home)
    assert _write("write_file", str(work / "link" / "planted"), [str(work)])["decision"] == "deny"


def test_file_write_fails_closed(tmp_path):
    assert _write("write_file", "/work/a", None)["decision"] == "deny"  # no write-roots.json
    out = hook.process({"tool_name": "edit", "tool_input": {}}, WRAP, write_roots=["/work"])
    assert out["decision"] == "deny"  # no path argument it knows


def test_load_write_roots(tmp_path):
    f = tmp_path / "write-roots.json"
    f.write_text(json.dumps({"roots": ["/work", "/tmp"]}))
    assert hook.load_write_roots(str(f)) == ["/work", "/tmp"]
    for bad in ("not json", json.dumps({"roots": []}), json.dumps({"roots": ["work"]}), json.dumps([1])):
        f.write_text(bad)
        assert hook.load_write_roots(str(f)) is None
    assert hook.load_write_roots(str(tmp_path / "missing")) is None


def test_bash_without_command_fails_closed():
    assert hook.process({"tool_name": "bash", "tool_input": {}}, WRAP)["decision"] == "deny"


@pytest.mark.parametrize("name", ["file_system.bash", "process.start"])
def test_unified_harness_shell_tools_wrapped(name):
    # Vibe 2.26's unified harness names tools by group; a background start is a shell command too
    out = hook.process({"tool_name": name, "tool_input": {"command": "ls"}}, WRAP)
    assert out["hook_specific_output"]["tool_input"]["command"].startswith("nono wrap")


def test_shell_cwd_and_env_held(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    roots = [str(work)]

    def start(**kw):
        return hook.process({"tool_name": "process.start", "tool_input": {"command": "ls", **kw}}, WRAP,
                            write_roots=roots)

    assert start(cwd=str(work))["hook_specific_output"]["tool_input"]["cwd"] == str(work.resolve())
    assert start(cwd="/home/agent/.vibe")["decision"] == "deny"  # the wrapper would grant its cwd
    for env in ({"NONO_BLOCK_NET": "0"}, {"LD_PRELOAD": "/work/x.so"}, {"PATH": "/work/bin"}, {"BASH_ENV": "/work/x"}):
        assert start(env=env)["decision"] == "deny", env  # it reaches the shell before the sandbox
    assert "hook_specific_output" in start(env={})


def test_unified_harness_file_tools_held(tmp_path):
    for name in ("file_system.write_file", "file_system.search_replace"):
        out = hook.process({"tool_name": name, "tool_input": {"file_path": "/home/agent/.vibe/x"}, "cwd": "/work"},
                           WRAP, write_roots=[str(tmp_path)])
        assert out["decision"] == "deny", name


def test_web_tools_denied_in_any_group():
    assert hook.process({"tool_name": "web.web_fetch", "tool_input": {}}, WRAP)["decision"] == "deny"


def test_main_stdin_rewrite(tmp_path):
    # End-to-end: feed JSON on stdin with a wrapper file present, expect rewrite.
    wrapper = tmp_path / "tool-wrapper.json"
    wrapper.write_text(json.dumps({"argv": WRAP}))
    payload = json.dumps({"tool_name": "bash", "tool_input": {"command": "id"}})
    script = (
        f"import importlib.util,sys;"
        f"spec=importlib.util.spec_from_file_location('h',{str(HOOK_PATH)!r});"
        f"m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);"
        f"m.WRAPPER_FILE={str(wrapper)!r};sys.exit(m.main())"
    )
    proc = subprocess.run([sys.executable, "-c", script], input=payload, capture_output=True, text=True)
    assert proc.returncode == 0
    out = json.loads(proc.stdout)
    assert out["hook_specific_output"]["tool_input"]["command"].startswith("nono wrap")


def test_main_bad_stdin_fails_closed():
    proc = subprocess.run([sys.executable, str(HOOK_PATH)], input="not json", capture_output=True, text=True)
    assert proc.returncode == 1  # strict=true turns this into a denial
