"""Layering: core (``glove``) must never import ``extensions`` (v3 D1)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LINT_IMPORTS = Path(sys.executable).parent / "lint-imports"

CONTRACT = """\
[importlinter]
root_packages =
    glove
    extensions

[importlinter:contract:core]
name = Core does not import extensions
type = forbidden
source_modules = glove
forbidden_modules = extensions
"""


def _run(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(cwd)}
    return subprocess.run(
        [str(LINT_IMPORTS), "--no-cache", *args], cwd=cwd, env=env, capture_output=True, text=True, check=False
    )


def test_core_does_not_import_extensions():
    r = _run(REPO)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Core does not import extensions KEPT" in r.stdout


def test_contract_catches_a_core_to_extension_import(tmp_path):
    # The same contract over a toy tree with the forbidden edge: must break.
    (tmp_path / "glove").mkdir()
    (tmp_path / "glove" / "__init__.py").write_text("import extensions.vpn\n")
    (tmp_path / "extensions" / "vpn").mkdir(parents=True)
    (tmp_path / "extensions" / "__init__.py").write_text("")
    (tmp_path / "extensions" / "vpn" / "__init__.py").write_text("")
    (tmp_path / ".importlinter").write_text(CONTRACT)
    r = _run(tmp_path, "--config", ".importlinter")
    assert r.returncode != 0
    assert "BROKEN" in r.stdout
