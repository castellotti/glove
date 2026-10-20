"""The shared harness entrypoint fails closed, and nothing in the environment
(the session's `env:` reaches it) turns that off."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ENTRYPOINT = Path(__file__).resolve().parent.parent / "glove" / "enforcers" / "entrypoint" / "entrypoint.sh"


def _run(tmp_path: Path, files: dict[str, str], env: dict[str, str]) -> subprocess.CompletedProcess:
    enf = tmp_path / "enforcer"
    enf.mkdir()
    for name, body in files.items():
        (enf / name).write_text(body)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nono = bin_dir / "nono"  # every policy fails validation
    nono.write_text("#!/bin/sh\n[ \"$1\" = profile ] && exit 1\nexit 0\n")
    nono.chmod(0o755)
    script = tmp_path / "entrypoint.sh"
    script.write_text(ENTRYPOINT.read_text().replace("ENF_DIR=/etc/glove/enforcer", f"ENF_DIR={enf}"))
    return subprocess.run(["bash", str(script), "echo", "started"], capture_output=True, text=True,
                          env={"PATH": f"{bin_dir}:/usr/bin:/bin", **env})


@pytest.mark.parametrize("env", [{}, {"GLOVE_ENFORCER_FAIL_OPEN": "1"}])
def test_invalid_policy_refuses_to_start(tmp_path, env):
    out = _run(tmp_path, {"harness.json": "{}"}, env)
    assert out.returncode == 90
    assert "started" not in out.stdout
    assert "refusing to start" in out.stderr


@pytest.mark.parametrize("env", [{}, {"GLOVE_ENFORCER_FAIL_OPEN": "1"}])
def test_incomplete_srt_layer_refuses_to_start(tmp_path, env):
    out = _run(tmp_path, {"srt-settings.json": "{}"}, env)
    assert out.returncode == 90
    assert "srt layer is incomplete" in out.stderr


def test_no_policies_starts(tmp_path):
    out = _run(tmp_path, {}, {})
    assert out.returncode == 0
    assert out.stdout.strip() == "started"


def test_a_wrapped_session_without_glove_tool_refuses_to_start(tmp_path):
    out = _run(tmp_path, {"tool-wrapper.argv": "/opt/glove/bin/glove-pty\n"}, {})
    assert out.returncode == 90 and "/opt/glove/bin/glove-tool is missing" in out.stderr


GLOVE_TOOL = ENTRYPOINT.parent / "glove-tool"


def _tool(tmp_path: Path, wrapper: str | None, *args: str, **env: str) -> subprocess.CompletedProcess:
    w = tmp_path / "tool-wrapper.argv"
    if wrapper is not None:
        w.write_text(wrapper)
    script = tmp_path / "glove-tool"
    script.write_text(GLOVE_TOOL.read_text().replace("/etc/glove/enforcer/tool-wrapper.argv", str(w)))
    return subprocess.run(["bash", str(script), *args], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", **env})


@pytest.mark.parametrize(("wrapper", "args"), [
    (None, ("-c", "echo RAN")),  # no wrapper (or enforcer none)
    ("", ("-c", "echo RAN")),
    ("\nprintf\n", ("-c", "echo RAN")),  # an empty first line
    ("/usr/bin/env\n", ("echo RAN",)),  # not `-c <command>`
    ("/usr/bin/env\n", ("-c", "echo RAN", "x")),
    ("/usr/bin/env\n", ("-x", "echo RAN")),
    ("/usr/bin/env\n", ("--",)),  # no command
    (None, ("--", "echo", "RAN")),
])
def test_glove_tool_fails_closed(tmp_path, wrapper, args):
    out = _tool(tmp_path, wrapper, *args)
    assert out.returncode == 126 and "RAN" not in out.stdout and "fail closed" in out.stderr


def test_glove_tool_runs_the_command_as_one_argument_after_the_wrapper(tmp_path):
    cmd = """echo 'it'"'"'s' "$HOME" *KEY* $(id); x"""
    out = _tool(tmp_path, "printf\n%s|\nw 1\n", "-c", cmd)  # the wrapper's argv, one per line
    assert out.stdout == f"w 1|/bin/bash|--norc|-c|{cmd}|"


def test_glove_tool_runs_an_argv_after_the_wrapper(tmp_path):
    # a plugin's stdio MCP server (skills); a last line without a newline still counts
    out = _tool(tmp_path, "printf\n%s|\nw 1", "--", "srv", 'a "b', "")
    assert out.stdout == 'w 1|srv|a "b||'


def test_glove_tool_drops_what_is_aimed_at_the_enforcers(tmp_path):
    out = _tool(tmp_path, "/usr/bin/env\n", "-c", 'echo "${NONO_X-gone} ${SRT_Y-gone} $KEEP"',
                NONO_X="1", SRT_Y="1", KEEP="kept")
    assert out.returncode == 0 and out.stdout == "gone gone kept\n"
