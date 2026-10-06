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
