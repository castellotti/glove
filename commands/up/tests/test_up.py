"""`glove up`."""

import os
import subprocess
import time

import pytest
import yaml
from helpers import command_module, make_session, session_id
from typer.testing import CliRunner

from glove import registry as reg
from glove.cli import app
from glove.config import ConfigError
from glove.harness import get_profile

runner = CliRunner()
up = command_module("up")


@pytest.fixture(autouse=True)
def _no_preflight(request, monkeypatch):
    # `up`'s doctor probes the real runtime; test_up_preflight_refuses_a_failing_extension_check covers it
    if "preflight" not in request.node.name:
        monkeypatch.setattr(up, "preflight", lambda *a: None)


def test_up_refuses_placeholders(home, tmp_path):
    d = tmp_path / "s"
    assert runner.invoke(app, ["new", "minimal", str(d)]).exit_code == 0
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 1 and "<set-me>" in result.output



def test_not_a_session_errors_with_a_hint(home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["up"])
    assert result.exit_code == 1 and "glove new" in result.output



def test_resume_and_session_mutually_exclusive(home, tmp_path):
    d = make_session(tmp_path / "s")
    for cmd in ("up", "plan"):
        result = runner.invoke(app, [cmd, str(d), "--resume", "--session", "x"])
        assert result.exit_code == 1 and "not both" in result.output



def test_subnets_avoid_the_runtimes_networks_and_move_off_a_taken_one(home, tmp_path, monkeypatch):
    from glove.runtimes.docker import DockerRuntime

    taken = {"other_default": ["172.31.0.0/24"]}
    monkeypatch.setattr(DockerRuntime, "network_subnets", lambda self: taken)
    d = tmp_path / "s"
    assert runner.invoke(app, ["new", "minimal", str(d)]).exit_code == 0
    sid = session_id(d)
    assert reg.find(sid).subnet == "172.31.1.0/24"  # allocation skipped the runtime's network
    taken[f"glove-{sid}-net"] = ["172.31.1.0/27"]  # its own networks are not a conflict
    make_session(d)  # fill in the model so `up` gets as far as planning
    monkeypatch.setattr(up, "launch", lambda *a, **k: None)
    assert runner.invoke(app, ["up", str(d)]).exit_code == 0
    assert reg.find(sid).subnet == "172.31.1.0/24"
    taken["later_default"] = ["172.31.1.128/25"]  # a foreign network took part of it since
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 0 and "re-allocating" in result.output
    assert reg.find(sid).subnet == "172.31.2.0/24"
    assert "172.31.2.0/27" in (d / ".glove" / "compose.yml").read_text()



def test_up_retries_on_a_subnet_another_session_took_meanwhile(home, tmp_path, monkeypatch):
    from glove.runtimes.docker import DockerRuntime
    from glove.session import SubnetTaken

    taken: dict[str, list[str]] = {}
    monkeypatch.setattr(DockerRuntime, "network_subnets", lambda self: taken)
    d = make_session(tmp_path / "s")
    subnets = []

    def launch(cfg, plan, *a, **k):  # the other session's networks appear during compose up
        subnets.append(cfg.subnet)
        if len(subnets) == 1:
            taken["glove-other-net"] = [cfg.subnet]
            raise SubnetTaken(f"another network took this session's subnet meanwhile: {cfg.subnet}")

    monkeypatch.setattr(up, "launch", launch)
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 0 and "re-allocating and retrying" in result.output
    assert subnets[0] != subnets[1] == reg.find(session_id(d)).subnet



def test_up_gives_up_after_three_taken_subnets(home, tmp_path, monkeypatch):
    from glove.session import SubnetTaken

    d = make_session(tmp_path / "s")
    rebuilds = []

    def always(cfg, plan, *a, rebuild, **k):
        rebuilds.append(rebuild)
        raise SubnetTaken("taken")

    monkeypatch.setattr(up, "launch", always)
    result = runner.invoke(app, ["up", str(d), "--rebuild"])
    assert result.exit_code == 1 and "gave up after 3 attempts" in result.output
    assert rebuilds == [True, False, False]  # the images are built once



def test_up_keeps_what_extensions_resolved_at_plan_time(home, tmp_path, monkeypatch):
    from glove import sessiondir as sdm

    d = make_session(tmp_path / "s")
    eff = d / ".glove" / "effective.yml"

    def launch(cfg, plan, *a, prepare, **k):
        _, resolved = sdm.read_effective(eff)  # as a `resolved` export would have recorded it
        sdm.write_effective(eff, cfg, {**resolved, "extensions": {"corp": {"routes": ["10.0.0.0/8"]}}})
        prepare()

    monkeypatch.setattr(up, "launch", launch)
    monkeypatch.setattr(up, "_resolve_extensions", lambda *a, **k: None)
    assert runner.invoke(app, ["up", str(d)]).exit_code == 0
    resolved = yaml.safe_load(eff.read_text())["resolved"]
    assert resolved["extensions"] == {"corp": {"routes": ["10.0.0.0/8"]}} and resolved["model"]



def test_up_preflight_refuses_a_failing_extension_check(home, tmp_path, monkeypatch):
    from glove.runtimes.base import Check

    d = make_session(tmp_path / "s")
    started, inspected = [], []
    monkeypatch.setattr(up, "launch", lambda *a, **k: started.append(1))
    monkeypatch.setattr(up, "clear_stale_harness", lambda *a: inspected.append(a))
    monkeypatch.setattr(up, "extension_checks", lambda *a, **k: [Check("chrome", "fail", "absent")])
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 1 and "chrome: absent" in result.output and not started
    monkeypatch.setattr(up, "extension_checks", lambda *a, **k: [Check("x", "warn", "meh")])
    assert runner.invoke(app, ["up", str(d)]).exit_code == 0 and started and inspected



@pytest.mark.parametrize(("error", "said"), [
    (lambda: ConfigError("keychain: no such item"), "no such item"),
    (lambda: NotImplementedError("not on this host"), "not on this host"),
    (lambda: subprocess.CalledProcessError(1, ["tmux", "new-session"]), "returned non-zero exit status 1"),
])
def test_up_stops_what_a_launch_hook_started_when_a_secret_is_missing(home, tmp_path, monkeypatch, error, said):
    d = make_session(tmp_path / "s")
    events = []

    def missing(plan):
        raise error()

    monkeypatch.setattr(up, "launch", lambda *a, **k: events.append("launched"))
    monkeypatch.setattr(up, "clear_stale_harness", lambda *a: None)
    monkeypatch.setattr(up, "extension_checks", lambda *a, **k: [])
    monkeypatch.setattr(up, "secret_env", missing)
    monkeypatch.setattr(up, "run_teardown", lambda sd, sid, rt, given: events.append(set(given)) or ["w"])
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 1 and said in result.output and "warn: w" in result.output
    assert "Traceback" not in result.output
    assert events == [{"llm"}]  # torn down, never launched


def _seed(dir_, name):
    dir_.mkdir(parents=True, exist_ok=True)
    f = dir_ / name
    f.write_text("{}\n")
    return f



def test_resume_hint_ignores_stale_pool_leftover(tmp_path, capsys):
    # A fresh session quit before any message persists nothing, so the newest
    # file in the pool is an unrelated earlier session. The hint must not report
    # it (that id would resume the wrong conversation).
    pi = get_profile("pi")
    home = tmp_path / "home"
    wk = home / ".pi" / "agent" / "sessions" / "--work--"
    stale = _seed(wk, "20240101_01a09d62.jsonl")
    os.utime(stale, (1000, 1000))  # long before "now"

    up._print_resume_hint(pi, home, "s-000000", since=time_now())
    assert "conversation saved" not in capsys.readouterr().out



def test_resume_hint_reports_this_runs_transcript(tmp_path, capsys):
    pi = get_profile("pi")
    home = tmp_path / "home"
    wk = home / ".pi" / "agent" / "sessions" / "--work--"
    start = time_now()
    fresh = _seed(wk, "20240102_deadbeef.jsonl")
    os.utime(fresh, (start + 5, start + 5))  # written during this run

    up._print_resume_hint(pi, home, "s-000000", since=start)
    out = capsys.readouterr().out
    assert "conversation saved" in out and "glove up --session deadbeef" in out
    assert "deadbeef" in out



def test_resume_hint_is_best_effort(tmp_path, capsys, monkeypatch):
    # an editable install updated mid-session: the old cli.py lazily imports new modules
    def broken(*a):
        raise AttributeError("'str' object has no attribute 'config_home_path'")

    monkeypatch.setattr(up, "conversations", broken)
    up._print_resume_hint(get_profile("pi"), tmp_path, "s-000000", since=time_now())
    out = capsys.readouterr().out
    assert "couldn't list the saved conversation" in out and "glove up --resume` still works" in out
    assert "Traceback" not in out


def test_up_notes_glove_updated_while_it_ran(home, tmp_path, monkeypatch):
    d = make_session(tmp_path / "s")
    stamps = iter([1.0, 2.0])
    monkeypatch.setattr(up, "_source_stamp", lambda: next(stamps))
    monkeypatch.setattr(up, "_started", lambda *a: {})
    monkeypatch.setattr(up, "launch", lambda *a, **k: None)
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 0 and "glove was updated while this session ran" in result.output


A, B = "2026-10-20T01:00:00.1Z", "2026-10-20T01:00:00.2Z"


@pytest.mark.parametrize(("after", "restarted"), [
    ({"c1": "2026-10-20T04:17:41.1Z", "c2": "2026-10-20T04:17:42.9Z"}, True),  # every sidecar started again
    ({"c1": A, "c3": "2026-10-20T04:17:41.1Z"}, False),  # one recreated (e.g. playwright reload)
    ({"c1": A, "c2": B}, False),  # nothing happened
    ({}, False), (None, False),  # nothing running again / the runtime doesn't answer
])
def test_a_runtime_restart_is_every_sidecar_started_again(after, restarted):
    assert up._runtime_restarted({"c1": A, "c2": B}, after) is restarted


def test_one_sidecar_restarting_is_not_a_runtime_restart():
    assert not up._runtime_restarted({"c1": A}, {"c1": B})


def test_started_reads_the_runtime_and_gives_up_quietly(monkeypatch):
    def run(argv, **k):
        assert k["timeout"] == 5
        out = "c1\nc2\n" if argv[1] == "ps" else f"c1 {A}\nc2 {B}\n"
        return subprocess.CompletedProcess(argv, 0, out, "")

    monkeypatch.setattr(up.subprocess, "run", run)
    assert up._started("docker", "glove-s-000000") == {"c1": A, "c2": B}

    def wedged(argv, **k):
        raise subprocess.TimeoutExpired(argv, k["timeout"])

    monkeypatch.setattr(up.subprocess, "run", wedged)
    assert up._started("docker", "glove-s-000000") is None


def test_after_harness_never_raises(monkeypatch, capsys):
    def boom(*a):
        raise ValueError("[/bad] markup")

    monkeypatch.setattr(up, "_started", boom)
    up._after_harness("docker", "glove-s-000000", {"c1": A, "c2": B}, None)
    assert "after the harness: [/bad] markup" in capsys.readouterr().err


def time_now() -> float:
    return time.time()
