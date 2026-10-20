"""`glove gc`."""

import shutil

from helpers import make_session, session_id
from typer.testing import CliRunner

from glove import registry as reg
from glove.cli import app

runner = CliRunner()


def test_deleting_the_dir_leaves_only_the_row_and_exports_which_gc_removes(home, tmp_path):
    d = make_session(tmp_path / "s", "  observe: {transcripts: false}\n")
    keep = make_session(tmp_path / "keep", "  observe: {transcripts: false}\n")
    for x in (d, keep):
        assert runner.invoke(app, ["plan", str(x)]).exit_code == 0
    sid, kept = session_id(d), session_id(keep)
    assert reg.find(sid).grants["observe"] == {"net": True, "transcripts": False}
    shutil.rmtree(d)
    foreign = home / "observe" / "pi-search"  # not a v3 id: never glove v3's to remove
    foreign.mkdir(parents=True)
    result = runner.invoke(app, ["gc", "--yes"])
    assert result.exit_code == 0, result.output
    assert reg.find(sid) is None and reg.find(kept) is not None
    assert not (home / "observe" / sid).exists() and not (home / "control" / sid).exists()
    assert (home / "observe" / kept).is_dir() and foreign.is_dir()
    assert "nothing to collect" in runner.invoke(app, ["gc", "--yes"]).output


def test_gc_refuses_a_v2_registry(home):
    home.mkdir()
    (home / "registry.json").write_text("[]")
    result = runner.invoke(app, ["gc", "--yes"])
    assert result.exit_code == 1 and "v2 registry" in result.output
