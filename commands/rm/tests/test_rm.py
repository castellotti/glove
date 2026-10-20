"""`glove rm`."""

from helpers import make_session, session_id
from typer.testing import CliRunner

from glove import registry as reg
from glove.cli import app

runner = CliRunner()


def test_rm_keeps_work_unless_all(home, tmp_path, monkeypatch):
    monkeypatch.setattr("glove.session.teardown", lambda *a, **k: None)
    d = make_session(tmp_path / "s", "  observe: {}\n  filter: {}\n")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    sid = session_id(d)
    assert (home / "observe" / sid / "net" / "session.json").is_file() and (home / "control" / sid).is_dir()
    (d / "work" / "keep.txt").write_text("x")
    assert runner.invoke(app, ["rm", str(d), "--yes", "--provider", "docker"]).exit_code == 0
    assert not (d / ".glove").exists() and (d / "work" / "keep.txt").is_file()
    assert (d / "glove-session.yml").exists()
    assert not (home / "observe" / sid).exists() and not (home / "control" / sid).exists()
    assert reg.find(sid) is None
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0  # a fresh identity
    assert runner.invoke(app, ["rm", str(d), "--yes", "--all", "--provider", "docker"]).exit_code == 0
    assert not d.exists()
