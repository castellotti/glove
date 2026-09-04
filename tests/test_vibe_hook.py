"""Vibe pre_tool hook tests — pure Python, no container.

Loads the baked hook module by path (it lives in the image build context, not
the importable package tree) and exercises its rewrite/deny/passthrough logic.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

HOOK_PATH = Path(__file__).parent.parent / "glove/harnesses/vibe/vibe_hook.py"


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
    assert ti["command"] == "nono wrap -s --allow-cwd --profile /etc/glove/enforcer/tool.json -- bash -lc 'ls /work'"
    assert ti["timeout"] == 30  # other fields preserved (full replacement)


def test_single_quotes_escaped():
    payload = {"tool_name": "bash", "tool_input": {"command": "echo 'hi there'"}}
    ti = hook.process(payload, WRAP)["hook_specific_output"]["tool_input"]
    # the inner single quote is escaped so the whole command survives as one arg
    assert ti["command"].endswith("bash -lc 'echo '\\''hi there'\\'''")


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
    assert hook.process({"tool_name": "read", "tool_input": {"path": "/work/x"}}, WRAP) is None
    assert hook.process({"tool_name": "edit", "tool_input": {}}, WRAP) is None


def test_bash_without_command_passthrough():
    assert hook.process({"tool_name": "bash", "tool_input": {}}, WRAP) is None


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
