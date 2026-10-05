"""CLI-level tests for the session-directory workflow (v3 §4)."""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

import pytest
import yaml
from helpers import make_session
from typer.testing import CliRunner

from glove import registry as reg
from glove.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _wide_console(monkeypatch):
    from glove import cli

    for c in (cli.console, cli.err):
        monkeypatch.setattr(c, "width", 400)  # no wrapping of long paths in assertions


@pytest.fixture
def home(tmp_path, monkeypatch):
    ghome = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(ghome))
    return ghome


def _sid(d: Path) -> str:
    return (d / ".glove" / "id").read_text().strip()


def _lan(extra: str = "") -> str:
    return "{provider: llama.cpp, location: lan, endpoint: \"example.test:8080\", model: m" + extra + "}"


# --- glove new ------------------------------------------------------------------------


def test_new_minimal_materializes_the_layout(home, tmp_path):
    d = tmp_path / "My Research.1"
    result = runner.invoke(app, ["new", "minimal", str(d)])
    assert result.exit_code == 0, result.output
    assert (d / "glove-session.yml").is_file() and (d / "work").is_dir()
    assert stat.S_IMODE((d / ".glove").stat().st_mode) == 0o700
    sid = _sid(d)
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


# --- plan / up ----------------------------------------------------------------------


def test_plan_renders_under_dot_glove(home, tmp_path, monkeypatch):
    d = make_session(tmp_path / "s")
    monkeypatch.chdir(d / "work")  # found from a subdirectory
    result = runner.invoke(app, ["plan", "--compose"])
    assert result.exit_code == 0, result.output
    sid = _sid(d)
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


def test_two_sessions_get_distinct_ids_projects_and_subnets(home, tmp_path):
    a, b = make_session(tmp_path / "a" / "proj"), make_session(tmp_path / "b" / "proj")
    for d in (a, b):
        assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    assert _sid(a) != _sid(b) and _sid(a).startswith("proj-") and _sid(b).startswith("proj-")
    assert {e.subnet for e in reg.load_registry()} == {"172.31.0.0/24", "172.31.1.0/24"}


def test_up_refuses_placeholders(home, tmp_path):
    d = tmp_path / "s"
    assert runner.invoke(app, ["new", "minimal", str(d)]).exit_code == 0
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 1 and "<set-me>" in result.output


def test_not_a_session_errors_with_a_hint(home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["up"])
    assert result.exit_code == 1 and "glove new" in result.output


@pytest.mark.parametrize(("extra", "msg"), [("workdir: .\n", "work/ directory"),
                                            ("net: [service]\n", "only from extensions"),
                                            ("add_dirs: [/x]\n", "mounts"), ("frobnicate: 1\n", "unknown key")])
def test_v2_keys_and_unknown_keys_are_refused(home, tmp_path, extra, msg):
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
    sid = _sid(d)
    moved = tmp_path / "elsewhere"
    d.rename(moved)
    result = runner.invoke(app, ["plan", str(moved)])
    assert result.exit_code == 0 and "moved" in result.output
    assert _sid(moved) == sid and reg.find(sid).dir == str(moved.resolve())


def test_a_copied_session_is_refused_until_it_gets_its_own_id(home, tmp_path):
    d = make_session(tmp_path / "s")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    copy = tmp_path / "copy"
    shutil.copytree(d, copy)
    result = runner.invoke(app, ["plan", str(copy)])
    assert result.exit_code == 1 and "same session id" in result.output
    (copy / ".glove" / "id").unlink()
    assert runner.invoke(app, ["plan", str(copy)]).exit_code == 0
    assert _sid(copy) != _sid(d)


# --- resume ---------------------------------------------------------------------------


def _seed_transcript(d: Path, uuid="01a09d62"):
    tdir = d / ".glove" / "home" / ".pi" / "agent" / "sessions" / "--work--"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / f"20240101_{uuid}.jsonl").write_text("{}\n")
    return uuid


def test_resume_and_session_mutually_exclusive(home, tmp_path):
    d = make_session(tmp_path / "s")
    for cmd in ("up", "plan"):
        result = runner.invoke(app, [cmd, str(d), "--resume", "--session", "x"])
        assert result.exit_code == 1 and "not both" in result.output


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


# --- secrets ------------------------------------------------------------------------------


@pytest.mark.parametrize("harness", ["pi", "vibe"])
def test_the_llm_key_is_written_nowhere(home, tmp_path, monkeypatch, harness):
    secret = "sk-test-0123456789abcdef"
    monkeypatch.setenv("MY_LLM_KEY", secret)
    d = make_session(tmp_path / "s", harness=harness, llm=_lan(", api_key: env:MY_LLM_KEY"))
    result = runner.invoke(app, ["plan", str(d), "--compose"])
    assert result.exit_code == 0, result.output
    assert secret not in result.output
    for root in (home, d):
        assert [p for p in root.rglob("*") if p.is_file() and secret.encode() in p.read_bytes()] == []
    assert "GLOVE_LLM_API_KEY: null" in (d / ".glove" / "compose.yml").read_text()
    assert "api_key: env:MY_LLM_KEY" in (d / ".glove" / "effective.yml").read_text()
    if harness == "pi":
        models = json.loads((d / ".glove/home/.pi/agent/models.json").read_text())
        assert models["providers"]["glove"]["apiKey"] == "$GLOVE_LLM_API_KEY"


def test_a_literal_key_is_refused(home, tmp_path):
    d = make_session(tmp_path / "s", llm=_lan(", api_key: sk-literal-key"))
    result = runner.invoke(app, ["plan", str(d)])
    assert result.exit_code == 1 and "llm.api_key is a secret: use a reference" in result.output
    assert "sk-literal-key" not in result.output


def test_plan_never_resolves_a_keychain_reference(home, tmp_path, monkeypatch):
    from glove import config as config_mod

    def boom(*a, **k):
        raise AssertionError("planning must not resolve the key")

    monkeypatch.setattr(config_mod, "resolve_secret", boom)
    d = make_session(tmp_path / "s", llm=_lan(", api_key: keychain:my-llm"))
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0


def _launch_plan(tmp_path, api_key):
    from helpers import STUB_LLM, make_cfg

    from glove.plan import build_session_plan
    from glove.runtimes.docker import DockerRuntime

    work = tmp_path / "work"
    work.mkdir()
    cfg = make_cfg(harness="pi", name="s", workdir=str(work), extensions={"llm": {**STUB_LLM, "api_key": api_key}})
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "ext"))
    (tmp_path / "compose.yml").write_text(DockerRuntime().render(plan, tmp_path).compose_yaml)
    return cfg, plan


def test_launch_passes_the_llm_key_to_compose_through_the_environment(tmp_path, monkeypatch):
    from glove import session as session_mod
    from glove.plan import secret_env

    calls = []
    monkeypatch.setattr(session_mod, "ensure_images", lambda *a, **k: None)
    monkeypatch.setattr(session_mod.subprocess, "run", lambda cmd, **k: calls.append((cmd, k)))
    monkeypatch.setenv("MY_LLM_KEY", "sk-x")
    cfg, plan = _launch_plan(tmp_path, "env:MY_LLM_KEY")
    session_mod.launch(cfg, plan, tmp_path / "compose.yml", provider="docker", rebuild=False,
                       secrets=secret_env(plan))
    assert calls and all(k["env"]["GLOVE_LLM_API_KEY"] == "sk-x" for _, k in calls)
    assert all("sk-x" not in " ".join(cmd) for cmd, _ in calls)
    assert "sk-x" not in (tmp_path / "compose.yml").read_text()


def test_secret_env_resolves_an_env_reference_in_memory(tmp_path, monkeypatch):
    from glove.plan import secret_env

    monkeypatch.setenv("MY_LLM_KEY", "sk-env")
    _, plan = _launch_plan(tmp_path, "env:MY_LLM_KEY")
    assert secret_env(plan) == {"GLOVE_LLM_API_KEY": "sk-env"}


def test_check_reports_secrets_without_reading_them(home, tmp_path, monkeypatch):
    from glove import config as config_mod

    def boom(*a, **k):
        raise AssertionError("check must not resolve the key")

    monkeypatch.setattr(config_mod, "resolve_secret", boom)
    monkeypatch.delenv("NOT_SET_KEY", raising=False)
    d = make_session(tmp_path / "s", llm=_lan(", api_key: env:NOT_SET_KEY"))
    result = runner.invoke(app, ["check", str(d), "--no-container"])
    assert result.exit_code == 1 and "NOT_SET_KEY is not set" in result.output
    assert not (d / ".glove").exists() and not (home / "registry.json").exists()  # check writes nothing
    monkeypatch.setenv("NOT_SET_KEY", "x")
    result = runner.invoke(app, ["check", str(d), "--no-container"])
    assert "secret llm.api_key" in result.output and "is not set" not in result.output


# --- ls / down / rm / gc ----------------------------------------------------------------------


def test_ls_shows_rows_and_their_state(home, tmp_path):
    a, b = make_session(tmp_path / "a"), make_session(tmp_path / "b")
    for d in (a, b):
        assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    shutil.rmtree(b)
    out = runner.invoke(app, ["ls"]).output
    assert _sid(a) in out and "ok" in out and "missing" in out and "glove gc" in out


def test_down_tears_down_the_sessions_project(home, tmp_path, monkeypatch):
    d = make_session(tmp_path / "s")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    calls = []
    monkeypatch.setattr("glove.session.teardown", lambda sid, **k: calls.append((sid, k)))
    assert runner.invoke(app, ["down", str(d), "--provider", "docker"]).exit_code == 0
    assert calls == [(_sid(d), {"provider": "docker", "wipe": False})]


@pytest.mark.parametrize(("wipe", "tail"), [(False, []), (True, ["--volumes"])])
def test_teardown_removes_a_killed_harness_run(monkeypatch, wipe, tail):
    # a `compose run` whose client was killed leaves its container (and so the
    # networks) unless down also removes orphans
    from glove import session

    calls = []
    monkeypatch.setattr(session.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    session.teardown("s-0a0b0c", provider="docker", wipe=wipe)
    assert calls == [["docker", "compose", "-p", session.project_name("s-0a0b0c"), "down", "--remove-orphans",
                      *tail]]


def test_rm_keeps_work_unless_all(home, tmp_path, monkeypatch):
    monkeypatch.setattr("glove.session.teardown", lambda *a, **k: None)
    d = make_session(tmp_path / "s", "  observe: {}\n  filter: {}\n")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    sid = _sid(d)
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


def test_deleting_the_dir_leaves_only_the_row_and_exports_which_gc_removes(home, tmp_path):
    d = make_session(tmp_path / "s", "  observe: {transcripts: false}\n")
    keep = make_session(tmp_path / "keep", "  observe: {transcripts: false}\n")
    for x in (d, keep):
        assert runner.invoke(app, ["plan", str(x)]).exit_code == 0
    sid, kept = _sid(d), _sid(keep)
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


def test_keychain_set_runs_security_interactively(monkeypatch):
    calls = []
    monkeypatch.setattr("glove.config.keychain_set", lambda svc: calls.append(svc) or 0)
    result = runner.invoke(app, ["keychain", "set", "my-llm"])
    assert result.exit_code == 0 and calls == ["my-llm"] and "keychain:my-llm" in result.output


def test_the_v2_commands_are_gone():
    for cmd in (["init", "pi"], ["run", "pi"], ["config"], ["pi"]):
        assert runner.invoke(app, cmd).exit_code != 0, cmd


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


def test_subnets_avoid_the_runtimes_networks_and_move_off_a_taken_one(home, tmp_path, monkeypatch):
    from glove.runtimes.docker import DockerRuntime

    taken = {"other_default": ["172.31.0.0/24"]}
    monkeypatch.setattr(DockerRuntime, "network_subnets", lambda self: taken)
    d = tmp_path / "s"
    assert runner.invoke(app, ["new", "minimal", str(d)]).exit_code == 0
    sid = _sid(d)
    assert reg.find(sid).subnet == "172.31.1.0/24"  # allocation skipped the runtime's network
    taken[f"glove-{sid}-net"] = ["172.31.1.0/27"]  # its own networks are not a conflict
    make_session(d)  # fill in the model so `up` gets as far as planning
    monkeypatch.setattr("glove.session.launch", lambda *a, **k: None)
    assert runner.invoke(app, ["up", str(d)]).exit_code == 0
    assert reg.find(sid).subnet == "172.31.1.0/24"
    taken["later_default"] = ["172.31.1.128/25"]  # a foreign network took part of it since
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 0 and "re-allocating" in result.output
    assert reg.find(sid).subnet == "172.31.2.0/24"
    assert "172.31.2.0/27" in (d / ".glove" / "compose.yml").read_text()


def test_an_unsupported_runtime_enforcer_pair_is_a_clean_error(home, tmp_path):
    d = make_session(tmp_path / "s", "runtime: podman\nenforcer: srt\n")
    result = runner.invoke(app, ["plan", str(d)])
    assert result.exit_code == 1 and "not supported on the podman runtime" in result.output
    assert "Traceback" not in result.output


def test_down_and_rm_use_the_sessions_runtime_not_path(home, tmp_path, monkeypatch):
    d = make_session(tmp_path / "s", "runtime: podman\n")
    assert runner.invoke(app, ["plan", str(d)]).exit_code == 0
    monkeypatch.setattr("glove.cli.shutil.which", lambda c: f"/usr/bin/{c}")  # docker on PATH too
    calls = []
    monkeypatch.setattr("glove.session.teardown", lambda sid, **k: calls.append(k["provider"]))
    assert runner.invoke(app, ["down", str(d)]).exit_code == 0
    (d / ".glove" / "effective.yml").unlink()  # never planned since: the session file says
    assert runner.invoke(app, ["down", str(d)]).exit_code == 0
    assert runner.invoke(app, ["rm", str(d), "-y"]).exit_code == 0
    assert calls == ["podman", "podman", "podman"]


def test_up_keeps_what_extensions_resolved_at_plan_time(home, tmp_path, monkeypatch):
    from glove import sessiondir as sdm

    d = make_session(tmp_path / "s")
    eff = d / ".glove" / "effective.yml"

    def launch(cfg, plan, *a, prepare, **k):
        _, resolved = sdm.read_effective(eff)  # as a `resolved` export would have recorded it
        sdm.write_effective(eff, cfg, {**resolved, "extensions": {"corp": {"routes": ["10.0.0.0/8"]}}})
        prepare()

    monkeypatch.setattr("glove.session.launch", launch)
    monkeypatch.setattr("glove.cli._resolve_extensions", lambda *a, **k: None)
    monkeypatch.setattr("glove.cli.start_host_services", lambda *a, **k: None)
    assert runner.invoke(app, ["up", str(d)]).exit_code == 0
    resolved = yaml.safe_load(eff.read_text())["resolved"]
    assert resolved["extensions"] == {"corp": {"routes": ["10.0.0.0/8"]}} and resolved["model"]


def test_a_broken_config_or_extension_cli_does_not_break_glove(home, tmp_path, monkeypatch):
    from glove import cli
    from glove.extensions import discover

    home.mkdir()
    (home / "config.yml").write_text("no_such_key: 1\n")
    cli._mount_extension_clis()  # the commands that read config.yml report it
    (home / "config.yml").unlink()
    ext = tmp_path / "exts" / "bad"
    ext.mkdir(parents=True)
    (ext / "extension.yml").write_text("api: 1\nname: bad\nsummary: x\ncli: cli.py\n")
    (ext / "cli.py").write_text("raise RuntimeError('boom')\n")
    monkeypatch.setattr("glove.extensions.discover", lambda: discover(tmp_path / "exts"))
    cli._mount_extension_clis()
    assert "bad" not in {g.name for g in app.registered_groups}
