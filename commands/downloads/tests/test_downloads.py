"""`glove downloads mark` (down's quarantine is tested with `glove down`)."""

from helpers import command_module, make_session
from typer.testing import CliRunner

from glove.cli import app

runner = CliRunner()


def test_downloads_mark_is_macos_only(monkeypatch, tmp_path):
    monkeypatch.setattr(command_module("downloads"), "quarantine_supported", lambda: False)
    result = runner.invoke(app, ["downloads", "mark", str(make_session(tmp_path / "s"))])
    assert result.exit_code == 0 and "macOS-only" in result.output


def test_downloads_mark_needs_a_planned_session(home, monkeypatch, tmp_path):
    monkeypatch.setattr(command_module("downloads"), "quarantine_supported", lambda: True)
    result = runner.invoke(app, ["downloads", "mark", str(make_session(tmp_path / "s"))])
    assert result.exit_code == 1 and "has never been planned" in result.output
