"""`glove keychain set` (an extension CLI: its module is loaded per run, so the
store it imports is what is patched)."""

import pytest
from typer.testing import CliRunner

from glove.cli import app
from glove.extensions import IN_TREE_DIR, load_module

runner = CliRunner()


@pytest.fixture
def calls(monkeypatch):
    out = []
    store = load_module(IN_TREE_DIR / "keychain" / "store.py", "keychain")
    monkeypatch.setattr(store, "keychain_set", lambda svc, secret=None: out.append((svc, secret)) or 0)
    return out


def test_keychain_set_prompts_through_the_store(calls):
    result = runner.invoke(app, ["keychain", "set", "my-llm"])
    assert result.exit_code == 0 and calls == [("my-llm", None)] and "keychain:my-llm" in result.output


def test_keychain_set_stdin_takes_one_piped_line(calls):
    result = runner.invoke(app, ["keychain", "set", "--stdin", "corp-pat"], input="s3cret\n")
    assert result.exit_code == 0 and calls == [("corp-pat", "s3cret")]
    assert "s3cret" not in result.output
