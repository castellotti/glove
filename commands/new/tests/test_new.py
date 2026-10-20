"""`glove new`."""

import json
import stat

from helpers import make_session, session_id
from typer.testing import CliRunner

from glove.cli import app

runner = CliRunner()


def test_new_minimal_materializes_the_layout(home, tmp_path):
    d = tmp_path / "My Research.1"
    result = runner.invoke(app, ["new", "minimal", str(d)])
    assert result.exit_code == 0, result.output
    assert (d / "glove-session.yml").is_file() and (d / "work").is_dir()
    assert stat.S_IMODE((d / ".glove").stat().st_mode) == 0o700
    sid = session_id(d)
    assert sid.startswith("my-research-1-") and len(sid.rsplit("-", 1)[1]) == 6
    assert "extensions.llm.provider" in result.output  # the <set-me>s to fill in
    doc = json.loads((home / "registry.json").read_text())
    assert doc["v"] == 2
    row = doc["sessions"][0]
    assert row["id"] == sid and row["dir"] == str(d.resolve()) and row["template"] == "minimal"
    assert row["harness"] == "pi" and row["grants"] == {"observe": None, "filter": None}
    assert row["subnet"] == "172.31.0.0/24"
    assert (home / "control").is_dir()  # Layman's overlay condition (handoff §2)


def test_new_refuses_an_existing_session_and_unknown_templates(home, tmp_path):
    d = tmp_path / "s"
    assert runner.invoke(app, ["new", "minimal", str(d)]).exit_code == 0
    again = runner.invoke(app, ["new", "minimal", str(d)])
    assert again.exit_code == 1 and "already" in again.output
    bad = runner.invoke(app, ["new", "no-such-template", str(tmp_path / "t")])
    assert bad.exit_code == 1 and "minimal" in bad.output  # lists the bundled ones


def test_new_from_a_path_and_diff(home, tmp_path):
    tpl = make_session(tmp_path / "tpl")
    d = tmp_path / "s"
    assert runner.invoke(app, ["new", str(tpl), str(d)]).exit_code == 0
    assert "unchanged" in runner.invoke(app, ["new", "--diff", "x", str(d)]).output
    (tpl / "glove-session.yml").write_text((tpl / "glove-session.yml").read_text() + "brief: new\n")
    assert "+brief: new" in runner.invoke(app, ["new", "--diff", "x", str(d)]).output


def test_new_refuses_to_overwrite_a_v2_registry(home, tmp_path):
    home.mkdir()
    (home / "registry.json").write_text('[{"dir": "/x", "harness": "pi", "env_id": "x"}]')
    result = runner.invoke(app, ["new", "minimal", str(tmp_path / "s")])
    assert result.exit_code == 1 and "glove v2 registry" in result.output
    assert not (tmp_path / "s").exists()
    assert json.loads((home / "registry.json").read_text())[0]["env_id"] == "x"  # untouched
