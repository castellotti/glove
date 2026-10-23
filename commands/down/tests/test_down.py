"""`glove down` (and `glove downloads mark` after it)."""

import os

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


def _created(d):
    import yaml

    resolved = yaml.safe_load((d / ".glove" / "effective.yml").read_text())["resolved"]
    return sorted(os.path.relpath(p, d / "work") for p in resolved.get("created", []))


def _up(d):
    """`glove up`'s materialise (its `launch` then makes the binds' mount points)."""
    from glove.sessionops import materialize_plan, open_session

    sd, _, sid, cfg = open_session(d)
    materialize_plan(sd, sid, cfg, home=False, launch=True)


def test_down_removes_the_empty_mount_points_glove_created_never_one_with_content(home, tmp_path, monkeypatch):
    d = make_session(tmp_path / "s", "protect_ide_files: true\n")
    w = d / "work"
    (w / ".envrc").write_text("")  # the user's own, empty: present before, so not glove's
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    assert _created(d) == []  # plan makes no mount point
    (w / ".mcp.json").touch()  # the user's, after plan: never glove's
    _up(d)
    assert _created(d) == [".idea", ".pi", ".vscode"]
    # as `launch` makes them; the agent wrote into .vscode (the user's now)
    for name in (".idea", ".pi", ".vscode"):
        (w / name).mkdir()
    (w / ".vscode" / "settings.json").write_text("{}")
    monkeypatch.setattr("glove.session.teardown", lambda sid, **k: None)
    result = runner.invoke(app, ["down", str(d)])
    assert result.exit_code == 0 and "removed 2 empty mount point(s)" in result.output, result.output
    assert sorted(p.name for p in w.iterdir()) == [".envrc", ".mcp.json", ".vscode"]
    assert _created(d) == []


def test_a_record_left_by_a_run_that_never_came_down_is_kept_at_the_next_up(home, tmp_path):
    d = make_session(tmp_path / "s", "protect_ide_files: true\n")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    _up(d)
    for name in (".idea", ".vscode"):
        (d / "work" / name).mkdir()
    (d / "work" / ".mcp.json").touch()  # now present: this run alone would not record them
    _up(d)
    assert _created(d) == [".envrc", ".idea", ".mcp.json", ".pi", ".vscode"]


def test_down_removes_the_record_of_a_config_this_glove_no_longer_reads(home, tmp_path, monkeypatch):
    import yaml

    d = make_session(tmp_path / "s", "protect_ide_files: true\n")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    eff = d / ".glove" / "effective.yml"
    doc = yaml.safe_load(eff.read_text())
    doc["config"]["unknown_key"] = 1
    eff.write_text(yaml.safe_dump(doc))
    monkeypatch.setattr("glove.session.teardown", lambda sid, **k: None)
    assert runner.invoke(app, ["down", str(d), "--provider", "docker"]).exit_code == 0
    assert not (d / "work" / ".pi").exists() and "created" not in yaml.safe_load(eff.read_text())["resolved"]


def test_a_failed_render_leaves_no_pinned_dir_behind(home, tmp_path, monkeypatch):
    from glove.runtimes.docker import DockerRuntime

    d = make_session(tmp_path / "s")

    def broken(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(DockerRuntime, "render", broken)
    assert runner.invoke(app, ["plan", str(d)]).exit_code != 0
    assert not (d / "work" / ".pi").exists()


def test_down_loads_only_the_extensions_whose_teardown_the_launch_recorded(home, tmp_path, monkeypatch):
    import yaml

    d = make_session(tmp_path / "s", "  direct: {}\n  playwright: {}\n")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    eff = d / ".glove" / "effective.yml"
    assert yaml.safe_load(eff.read_text())["resolved"]["teardown"] == ["playwright"]
    seen = []
    monkeypatch.setattr("glove.sessionops.run_teardown",
                        lambda sd, sid, rt, given, only: seen.append((sorted(given), only)) or [])
    monkeypatch.setattr("glove.session.teardown", lambda sid, **k: None)
    assert runner.invoke(app, ["down", str(d)]).exit_code == 0
    doc = yaml.safe_load(eff.read_text())
    del doc["resolved"]["teardown"]  # an older glove's record: every extension's hooks, as before
    eff.write_text(yaml.safe_dump(doc))
    assert runner.invoke(app, ["down", str(d)]).exit_code == 0
    given = ["direct", "llm", "playwright"]
    assert seen == [(given, ["playwright"]), (given, None)]


def test_a_malformed_teardown_record_loads_every_extensions_hooks(home, tmp_path, monkeypatch):
    import yaml

    d = make_session(tmp_path / "s")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    eff = d / ".glove" / "effective.yml"
    seen = []
    monkeypatch.setattr("glove.sessionops.run_teardown", lambda sd, sid, rt, given, only: seen.append(only) or [])
    monkeypatch.setattr("glove.session.teardown", lambda sid, **k: seen.append("down"))
    for bad in (5, "playwright"):
        doc = yaml.safe_load(eff.read_text())
        doc["resolved"]["teardown"] = bad
        eff.write_text(yaml.safe_dump(doc))
        assert runner.invoke(app, ["down", str(d)]).exit_code == 0
    assert seen == [None, "down", None, "down"]
