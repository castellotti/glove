"""`glove plan` (and, through it, what every session's render guarantees)."""

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml
from helpers import lan_llm, make_session, session_id
from typer.testing import CliRunner

from glove import registry as reg
from glove.cli import app

runner = CliRunner()


def _seed_transcript(d: Path, uuid="01a09d62"):
    tdir = d / ".glove" / "home" / ".pi" / "agent" / "sessions" / "--work--"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / f"20240101_{uuid}.jsonl").write_text("{}\n")
    return uuid



def test_plan_renders_under_dot_glove(home, tmp_path, monkeypatch):
    d = make_session(tmp_path / "s")
    monkeypatch.chdir(d / "work")  # found from a subdirectory
    result = runner.invoke(app, ["plan", "--compose"])
    assert result.exit_code == 0, result.output
    sid = session_id(d)
    compose = yaml.safe_load((d / ".glove" / "compose.yml").read_text())
    harness = compose["services"][f"glove-{sid}-harness"]
    sources = set()
    for v in harness["volumes"]:
        sources.add(v.split(":")[0] if isinstance(v, str) else v.get("source"))
    assert str((d / "work").resolve()) in sources and str((d / ".glove" / "home").resolve()) in sources
    # nothing else of the session dir is mounted: not the dir, not .glove/ itself
    assert not sources & {str(d.resolve()), str((d / ".glove").resolve())}
    # the default enforcer on docker: srt around the harness, nono per command
    assert {p.name for p in (d / ".glove" / "enforcer").iterdir()} >= {"srt-harness.json", "tool.json"}
    assert (d / ".glove" / "effective.yml").is_file() and (d / ".glove" / "baseline.yml").is_file()
    nets = compose["networks"]
    assert nets[f"glove-{sid}-net"]["ipam"]["config"][0]["subnet"] == "172.31.0.0/27"
    assert nets[f"glove-{sid}-hostgw"]["ipam"]["config"][0]["subnet"] == "172.31.0.32/27"
    base = json.loads((d / ".glove/home/.pi/agent/models.json").read_text())["providers"]["glove"]["baseUrl"]
    assert base == f"http://glove-{sid}-llm:8080/v1"



@pytest.mark.parametrize(("body", "shown"), [
    ("", "enforcer: nono+srt  subnet"),
    ("enforcer_options: {nono: {browsers: true}}\n", "enforcer: nono+srt (nono.browsers: true)  subnet"),
    # a section the enforcer never applies is not in effect, so not shown
    ("enforcer: srt\nenforcer_options: {nono: {browsers: true}}\n", "enforcer: srt  subnet"),
])
def test_plan_shows_the_enforcer_options_off_their_defaults(home, tmp_path, body, shown):
    result = runner.invoke(app, ["plan", str(make_session(tmp_path / "s", body))], env={"COLUMNS": "300"})
    assert result.exit_code == 0, result.output
    assert shown in result.output



def test_two_sessions_get_distinct_ids_projects_and_subnets(home, tmp_path):
    a, b = make_session(tmp_path / "a" / "proj"), make_session(tmp_path / "b" / "proj")
    for d in (a, b):
        assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    assert session_id(a) != session_id(b) and session_id(a).startswith("proj-") and session_id(b).startswith("proj-")
    assert {e.subnet for e in reg.load_registry()} == {"172.31.0.0/24", "172.31.1.0/24"}



@pytest.mark.parametrize(("extra", "msg"), [("toolchains: []\n", "an extension now"),
                                            ("runtime: utm\n", "`runtime` must be one of"),
                                            ("add_dirs: [/x]\n", "unknown key"), ("frobnicate: 1\n", "unknown key")])
def test_moved_and_unknown_keys_are_refused(home, tmp_path, extra, msg):
    d = make_session(tmp_path / "s", extra)
    result = runner.invoke(app, ["plan", str(d)])
    assert result.exit_code == 1 and msg in result.output



@pytest.mark.parametrize("mount", [".", ".glove", ".glove/home", "local", "glove-session.yml", ".."])
def test_mounts_never_expose_the_session_state(home, tmp_path, mount):
    d = make_session(tmp_path / "p" / "s", f"mounts: [{{path: \"{mount}\", mode: ro}}]\n")
    (d / "local").mkdir()
    result = runner.invoke(app, ["plan", str(d)])
    assert result.exit_code == 1 and "would expose" in result.output



def test_a_relative_mount_resolves_against_the_session_dir(home, tmp_path):
    d = make_session(tmp_path / "s", "mounts: [{path: data, mode: ro}]\n")
    (d / "data").mkdir()
    result = runner.invoke(app, ["plan", str(d)])
    assert result.exit_code == 0, result.output
    assert str((d / "data").resolve()) in result.output



def test_a_moved_session_keeps_its_id_and_updates_the_registry(home, tmp_path):
    d = make_session(tmp_path / "s")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    sid = session_id(d)
    moved = tmp_path / "elsewhere"
    d.rename(moved)
    result = runner.invoke(app, ["plan", str(moved)])
    assert result.exit_code == 0 and "moved" in result.output
    assert session_id(moved) == sid and reg.find(sid).dir == str(moved.resolve())



def test_a_copied_session_is_refused_until_it_gets_its_own_id(home, tmp_path):
    d = make_session(tmp_path / "s")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    copy = tmp_path / "copy"
    shutil.copytree(d, copy)
    result = runner.invoke(app, ["plan", str(copy)])
    assert result.exit_code == 1 and "same session id" in result.output
    (copy / ".glove" / "id").unlink()
    assert runner.invoke(app, ["plan", str(copy)]).exit_code == 0
    assert session_id(copy) != session_id(d)



def test_resume_no_prior_conversation_errors(home, tmp_path):
    d = make_session(tmp_path / "s")
    result = runner.invoke(app, ["plan", str(d), "--resume"])
    assert result.exit_code == 1 and "no previous conversation" in result.output



def test_resume_renders_continue_inside_the_wrapper(home, tmp_path):
    d = make_session(tmp_path / "s")
    _seed_transcript(d)
    assert runner.invoke(app, ["plan", str(d), "--resume"]).exit_code == 0
    compose = (d / ".glove" / "compose.yml").read_text()
    assert "--continue" in compose and compose.index("--continue") > compose.index("--")



def test_session_renders_id_and_lists_available_when_missing(home, tmp_path):
    d = make_session(tmp_path / "s")
    uuid = _seed_transcript(d)
    assert runner.invoke(app, ["plan", str(d), "--session", uuid]).exit_code == 0
    compose = (d / ".glove" / "compose.yml").read_text()
    assert "--session" in compose and uuid in compose
    missing = runner.invoke(app, ["plan", str(d), "--session", "nope"])
    assert missing.exit_code == 1 and "no conversation matching" in missing.output and uuid in missing.output



def test_resume_grant_widening_warns_against_the_baseline(home, tmp_path):
    d = make_session(tmp_path / "s")
    uuid = _seed_transcript(d)
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0  # baseline: llm only
    f = d / "glove-session.yml"
    f.write_text(f.read_text() + "allow_sensitive: true\n")
    result = runner.invoke(app, ["plan", str(d), "--session", uuid])
    assert result.exit_code == 0, result.output
    assert "broader access" in result.output and "allow_sensitive" in result.output
    # the baseline is the original, not the last run: a second widened run warns again
    assert "broader access" in runner.invoke(app, ["plan", str(d), "--session", uuid]).output



@pytest.mark.parametrize("harness", ["pi", "vibe"])
def test_the_llm_key_is_written_nowhere(home, tmp_path, monkeypatch, harness):
    secret = "sk-test-0123456789abcdef"
    monkeypatch.setenv("MY_LLM_KEY", secret)
    d = make_session(tmp_path / "s", harness=harness, llm=lan_llm(", api_key: env:MY_LLM_KEY"))
    result = runner.invoke(app, ["plan", str(d), "--compose"])
    assert result.exit_code == 0, result.output
    assert secret not in result.output
    for root in (home, d):
        assert [p for p in root.rglob("*") if p.is_file() and secret.encode() in p.read_bytes()] == []
    compose = (d / ".glove" / "compose.yml").read_text()
    # the harness holds a placeholder; the key reaches only llm-auth, at `compose up`
    assert 'GLOVE_LLM_API_KEY: "glove-injected"' in compose and "LLM_AUTH_KEY: null" in compose
    assert "api_key: env:MY_LLM_KEY" in (d / ".glove" / "effective.yml").read_text()
    if harness == "pi":
        models = json.loads((d / ".glove/home/.pi/agent/models.json").read_text())
        assert models["providers"]["glove"]["apiKey"] == "$GLOVE_LLM_API_KEY"



def test_a_literal_key_is_refused(home, tmp_path):
    d = make_session(tmp_path / "s", llm=lan_llm(", api_key: sk-literal-key"))
    result = runner.invoke(app, ["plan", str(d)])
    assert result.exit_code == 1 and "llm.api_key is a secret: use a reference" in result.output
    assert "sk-literal-key" not in result.output



def test_plan_never_resolves_a_keychain_reference(home, tmp_path, monkeypatch):
    from glove import config as config_mod

    def boom(*a, **k):
        raise AssertionError("planning must not resolve the key")

    monkeypatch.setattr(config_mod, "resolve_secret", boom)
    d = make_session(tmp_path / "s", llm=lan_llm(", api_key: keychain:my-llm"))
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0



def test_effective_records_launch_time_resolution(home, tmp_path):
    from glove import sessiondir

    d = make_session(tmp_path / "s")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    sd = sessiondir.SessionDir(d.resolve())
    cfg, _ = sessiondir.read_effective(sd.effective)
    sessiondir.write_effective(sd.effective, cfg, {"at": "2026-09-28T00:00:00Z",
                                                  "model": {"model": "qwen", "vision": True, "context_window": 131072}})
    out = runner.invoke(app, ["plan", str(d)]).output
    assert "resolved at last launch" in out and "qwen" in out and "131072" in out
    assert sessiondir.read_effective(sd.effective)[1]["model"]["model"] == "qwen"  # a re-plan keeps it
    assert os.stat(sd.state).st_mode & 0o777 == 0o700



def test_mounts_never_expose_the_glove_home_or_another_session(home, tmp_path):
    other = make_session(tmp_path / "other")
    assert runner.invoke(app, ["plan", str(other)]).exit_code == 0
    for mount in (str(home / "control"), str(home), str(other), str(other / ".glove" / "home")):
        d = make_session(tmp_path / "s", f"mounts: [{{path: \"{mount}\", mode: rw}}]\n")
        result = runner.invoke(app, ["plan", str(d)])
        assert result.exit_code == 1 and "would expose" in result.output, mount



def test_an_unsupported_runtime_enforcer_pair_is_a_clean_error(home, tmp_path):
    d = make_session(tmp_path / "s", "runtime: podman\nenforcer: srt\n")
    result = runner.invoke(app, ["plan", str(d)])
    assert result.exit_code == 1 and "not supported on the podman runtime" in result.output
    assert "Traceback" not in result.output



def test_files_left_in_an_old_work_subdir_are_pointed_out(home, tmp_path):
    # downloads: work used to land in work/browser-output/; the output beside
    # work/ is now mounted over that path, hiding what is left there
    d = make_session(tmp_path / "s", "  direct: {}\n  playwright: {downloads: work}\n")
    (d / "work" / "browser-output").mkdir()
    (d / "work" / "browser-output" / "old.zip").write_text("x")
    result = runner.invoke(app, ["plan", str(d)])
    assert result.exit_code == 0, result.output
    assert "work/browser-output/ has files" in result.output and "move them there" in result.output
    (d / "work" / "browser-output" / "old.zip").unlink()
    assert "has files" not in runner.invoke(app, ["plan", str(d)]).output
