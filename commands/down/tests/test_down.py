"""`glove down` (and `glove downloads mark` after it)."""

from helpers import darwin, make_session, quarantine_attr, session_id
from typer.testing import CliRunner

from glove.cli import app

runner = CliRunner()


def test_down_tears_down_the_sessions_project(home, tmp_path, monkeypatch):
    d = make_session(tmp_path / "s")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    calls = []
    monkeypatch.setattr("glove.session.teardown", lambda sid, **k: calls.append((sid, k)))
    assert runner.invoke(app, ["down", str(d), "--provider", "docker"]).exit_code == 0
    assert calls == [(session_id(d), {"provider": "docker", "wipe": False})]



def test_down_and_rm_use_the_sessions_runtime_not_path(home, tmp_path, monkeypatch):
    d = make_session(tmp_path / "s", "runtime: podman\n")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    monkeypatch.setattr("shutil.which", lambda c: f"/usr/bin/{c}")  # docker on PATH too
    calls = []
    monkeypatch.setattr("glove.session.teardown", lambda sid, **k: calls.append(k["provider"]))
    assert runner.invoke(app, ["down", str(d)]).exit_code == 0
    (d / ".glove" / "effective.yml").unlink()  # never planned since: the session file says
    assert runner.invoke(app, ["down", str(d)]).exit_code == 0
    assert runner.invoke(app, ["rm", str(d), "-y"]).exit_code == 0
    assert calls == ["podman", "podman", "podman"]



@darwin
def test_down_and_downloads_mark_quarantine_the_outputs_not_the_inputs(home, tmp_path, monkeypatch):
    d = make_session(tmp_path / "s", "  direct: {}\n  playwright: {downloads: work, uploads: work}\n")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    monkeypatch.setattr("glove.session.teardown", lambda sid, **k: None)
    monkeypatch.setattr("glove.sessionops.build_session_plan", None)  # down never re-plans: plan time recorded them
    (d / "browser-output" / "x.dmg").write_bytes(b"x")
    (d / "browser-uploads" / "mine.pdf").write_bytes(b"y")

    result = runner.invoke(app, ["down", str(d)])
    assert result.exit_code == 0 and "quarantined 1 downloaded file" in result.output, result.output
    assert quarantine_attr(d / "browser-output" / "x.dmg") and not quarantine_attr(d / "browser-uploads" / "mine.pdf")
    result = runner.invoke(app, ["downloads", "mark", str(d)])
    assert result.exit_code == 0 and "nothing new to quarantine (1 already marked)" in result.output
