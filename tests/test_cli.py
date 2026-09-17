"""CLI-level tests for the env workflow."""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from glove.cli import app

runner = CliRunner()


@pytest.fixture
def home(tmp_path, monkeypatch):
    ghome = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(ghome))
    return ghome


def _chdir(monkeypatch, d):
    d.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(d)
    return d


def test_init_writes_only_under_glove_home(home, tmp_path, monkeypatch):
    wd = _chdir(monkeypatch, tmp_path / "pi-local")
    result = runner.invoke(app, ["init", "pi"])
    assert result.exit_code == 0, result.output
    # cwd untouched
    assert list(wd.iterdir()) == []
    # env config written under GLOVE_HOME/envs/<id>/
    assert (home / "envs" / "pi-local" / "glove.yaml").is_file()
    assert (home / "registry.json").is_file()


def test_two_harnesses_one_dir_distinct_envs(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    assert runner.invoke(app, ["init", "vibe"]).exit_code == 0
    ids = {d.name for d in (home / "envs").iterdir()}
    assert ids == {"pi-local", "pi-local-vibe"}


def test_run_without_env_errors_with_hint(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "wd")
    result = runner.invoke(app, ["run", "pi"])
    assert result.exit_code == 1
    assert "glove init pi" in result.output


def test_run_dry_run_renders_under_env(home, tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    _chdir(monkeypatch, tmp_path / "vibe-local")
    assert runner.invoke(app, ["init", "vibe"]).exit_code == 0
    result = runner.invoke(
        app, ["run", "vibe", "--workdir", str(work), "--dry-run"]
    )
    assert result.exit_code == 0, result.output
    assert "name: glove-vibe-local" in result.output
    # compose renders under sessions/<session>/ (default session == env-id)
    compose = home / "envs" / "vibe-local" / "sessions" / "vibe-local" / "docker-compose.yml"
    assert compose.is_file()
    # harness home seeded under the env's own home/ (shared across sessions)
    assert (home / "envs" / "vibe-local" / "home" / ".vibe" / "config.toml").is_file()


def test_run_records_resolved_home_in_registry(home, tmp_path, monkeypatch):
    from glove import registry

    work = tmp_path / "work"
    work.mkdir()
    _chdir(monkeypatch, tmp_path / "vibe-local")
    assert runner.invoke(app, ["init", "vibe"]).exit_code == 0
    # Fresh registration has no home yet.
    assert registry.load_registry()[0].home is None
    result = runner.invoke(
        app, ["run", "vibe", "--workdir", str(work), "--dry-run"]
    )
    assert result.exit_code == 0, result.output
    # run records the resolved (default-layout) home as an abs realpath.
    (entry,) = registry.load_registry()
    expected = os.path.realpath(str(home / "envs" / "vibe-local" / "home"))
    assert entry.home == expected


def test_down_tears_down_named_sessions_too(home, tmp_path, monkeypatch):
    # Regression: `glove down <env>` must tear down every session, including
    # --name'd ones whose compose project is glove-<env>-<name>, not just the
    # default unnamed session.
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0

    sessions = home / "envs" / "pi-local" / "sessions"
    for sname, token in (("pi-local", "pi-local"), ("feat", "pi-local-feat")):
        sdir = sessions / sname
        sdir.mkdir(parents=True)
        (sdir / "glove.effective.yaml").write_text(f"harness: pi\nname: {token}\n")

    torn: list[str] = []
    import glove.session as session_mod

    monkeypatch.setattr(session_mod, "teardown", lambda s, **kw: torn.append(s))

    result = runner.invoke(app, ["down", "pi-local"])
    assert result.exit_code == 0, result.output
    assert set(torn) == {"pi-local", "pi-local-feat"}


def test_down_name_narrows_to_one_session(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "pi-local")
    assert runner.invoke(app, ["init", "pi"]).exit_code == 0
    sdir = home / "envs" / "pi-local" / "sessions" / "feat"
    sdir.mkdir(parents=True)
    (sdir / "glove.effective.yaml").write_text("harness: pi\nname: pi-local-feat\n")

    torn: list[str] = []
    import glove.session as session_mod

    monkeypatch.setattr(session_mod, "teardown", lambda s, **kw: torn.append(s))

    result = runner.invoke(app, ["down", "pi-local", "--name", "feat"])
    assert result.exit_code == 0, result.output
    assert torn == ["pi-local-feat"]


def test_ls_lists_registered_envs(home, tmp_path, monkeypatch):
    _chdir(monkeypatch, tmp_path / "wd")
    runner.invoke(app, ["init", "pi"])
    result = runner.invoke(app, ["ls"])
    assert result.exit_code == 0
    assert "wd" in result.output
    assert "pi" in result.output
