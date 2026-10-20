"""`glove ls`."""

import shutil

from helpers import make_session, session_id
from typer.testing import CliRunner

from glove.cli import app

runner = CliRunner()


def test_ls_shows_rows_and_their_state(home, tmp_path):
    a, b = make_session(tmp_path / "a"), make_session(tmp_path / "b")
    for d in (a, b):
        assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    shutil.rmtree(b)
    out = runner.invoke(app, ["ls"]).output
    assert session_id(a) in out and "ok" in out and "missing" in out and "glove gc" in out
