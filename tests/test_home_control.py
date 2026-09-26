"""glove owns its home: ``control/`` exists whenever glove creates the home
(docs/planning/layman-independence.md item 1)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from glove import registry
from glove.cli import app

runner = CliRunner()


@pytest.fixture
def ghome(tmp_path, monkeypatch):
    g = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(g))
    return g


# --- item 1: control/ exists whenever the home does ------------------------------------


def test_ensure_home_creates_home_and_control_idempotently(ghome):
    assert not ghome.exists()
    assert registry.ensure_home() == []
    assert (ghome / "control").is_dir()
    umask = os.umask(0)
    os.umask(umask)
    assert (ghome / "control").stat().st_mode & 0o777 == 0o777 & ~umask
    assert (ghome / "control").stat().st_uid == os.getuid()
    assert registry.ensure_home() == []


def test_any_registry_write_creates_control(ghome, tmp_path):
    registry.create_env(str(tmp_path), "pi")
    assert (ghome / "control").is_dir() and (ghome / "registry.json").is_file()


def test_cli_init_creates_control(ghome, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    assert (ghome / "control").is_dir()


def test_glove_init_adds_control_to_an_older_home(ghome, tmp_path, monkeypatch):
    ghome.mkdir()
    (ghome / "registry.json").write_text("[]\n")
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    assert (ghome / "control").is_dir()


def test_commands_do_not_create_a_missing_home(ghome):
    assert runner.invoke(app, ["ls"]).exit_code == 0
    assert not ghome.exists()


def test_read_only_commands_never_touch_the_home(ghome, tmp_path):
    ghome.mkdir()
    assert runner.invoke(app, ["version"]).exit_code == 0
    assert runner.invoke(app, ["ls"]).exit_code == 0
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"v": 1, "env": "e", "session": "e", "rules": []}))
    assert runner.invoke(app, ["net", "validate", str(rules)]).exit_code == 0
    assert list(ghome.iterdir()) == []


def test_a_control_dir_owned_by_someone_else_is_named_with_the_fix(ghome, monkeypatch):
    registry.ensure_home()
    real = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real + 1)
    [w] = registry.ensure_home()
    assert f"owned by uid {real}" in w and f"sudo chown {real + 1}:" in w


def test_a_rules_dir_whose_parent_is_foreign_names_the_parent(tmp_path, monkeypatch):
    from glove.hardening import HardeningError
    from glove.observe import ensure_net_dir

    (tmp_path / "control").mkdir()

    def eacces(self, *a, **k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "mkdir", eacces)
    with pytest.raises(HardeningError, match=rf"{tmp_path / 'control'} is owned by .* sudo chown"):
        ensure_net_dir(tmp_path / "control" / "e" / "s")


def test_an_unsearchable_foreign_parent_still_gets_the_fix(tmp_path, monkeypatch):
    """A root-run Layman's 0700 ``control/<env>/``: on Python 3.11/3.12
    ``Path.exists`` raises EACCES for the rules directory beneath it, which must
    not replace the HardeningError with a bare Permission denied."""
    from glove.hardening import HardeningError
    from glove.observe import ensure_net_dir

    (tmp_path / "control" / "e").mkdir(parents=True)

    def eacces(self, *a, **k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "mkdir", eacces)
    monkeypatch.setattr(Path, "exists", eacces)  # the 3.11/3.12 behaviour
    with pytest.raises(HardeningError, match=rf"{tmp_path / 'control' / 'e'} is owned by .* sudo chown"):
        ensure_net_dir(tmp_path / "control" / "e" / "s")
