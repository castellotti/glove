"""`glove keychain set`."""

from helpers import command_module
from typer.testing import CliRunner

from glove.cli import app

runner = CliRunner()


def test_keychain_set_runs_security_interactively(monkeypatch):
    calls = []
    monkeypatch.setattr(command_module("keychain"), "keychain_set",
                        lambda svc, secret=None: calls.append((svc, secret)) or 0)
    result = runner.invoke(app, ["keychain", "set", "my-llm"])
    assert result.exit_code == 0 and calls == [("my-llm", None)] and "keychain:my-llm" in result.output


def test_keychain_set_stdin_takes_one_piped_line(monkeypatch):
    calls = []
    monkeypatch.setattr(command_module("keychain"), "keychain_set",
                        lambda svc, secret=None: calls.append((svc, secret)) or 0)
    result = runner.invoke(app, ["keychain", "set", "--stdin", "corp-pat"], input="s3cret\n")
    assert result.exit_code == 0 and calls == [("corp-pat", "s3cret")]
    assert "s3cret" not in result.output
