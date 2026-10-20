"""`glove policy`."""

from helpers import make_session
from typer.testing import CliRunner

from glove.cli import app

runner = CliRunner()


def test_policy_shows_both_rings_and_writes_nothing(home, tmp_path):
    d = make_session(tmp_path / "s")
    result = runner.invoke(app, ["policy", str(d)])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "ring 0 — hardening" in out and "cap_drop=['ALL']" in out and "no_new_privileges=True" in out
    assert "ring 1 — srt-harness.json" in out and "llm" in out  # the default enforcer on docker; its extensions
    assert not (d / ".glove").exists() and not home.exists()  # read-only: no state, no registry row


def test_policy_reports_a_bad_session_file(home, tmp_path):
    result = runner.invoke(app, ["policy", str(make_session(tmp_path / "s", "frobnicate: 1\n"))])
    assert result.exit_code == 1 and "unknown key" in result.output
