"""CLI-level tests for the session-directory workflow (v3 §4)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml
from helpers import make_session
from typer.testing import CliRunner

from glove import registry as reg
from glove.cli import app
from glove.config import ConfigError

runner = CliRunner()


@pytest.fixture(autouse=True)
def _wide_console(monkeypatch):
    from glove import cli

    for c in (cli.console, cli.err):
        monkeypatch.setattr(c, "width", 400)  # no wrapping of long paths in assertions


@pytest.fixture(autouse=True)
def _no_preflight(request, monkeypatch):
    # `up`'s doctor probes the real runtime; test_up_refuses_a_failing_check covers it
    if "preflight" not in request.node.name:
        monkeypatch.setattr("glove.cli.preflight", lambda *a: None)


@pytest.fixture
def home(tmp_path, monkeypatch):
    ghome = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(ghome))
    return ghome


def _sid(d: Path) -> str:
    return (d / ".glove" / "id").read_text().strip()


# --- plan / up ----------------------------------------------------------------------


def test_up_refuses_placeholders(home, tmp_path):
    d = tmp_path / "s"
    assert runner.invoke(app, ["new", "minimal", str(d)]).exit_code == 0
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 1 and "<set-me>" in result.output


def test_not_a_session_errors_with_a_hint(home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["up"])
    assert result.exit_code == 1 and "glove new" in result.output


# --- resume ---------------------------------------------------------------------------


def test_resume_and_session_mutually_exclusive(home, tmp_path):
    d = make_session(tmp_path / "s")
    for cmd in ("up", "plan"):
        result = runner.invoke(app, [cmd, str(d), "--resume", "--session", "x"])
        assert result.exit_code == 1 and "not both" in result.output


# --- secrets ------------------------------------------------------------------------------


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
    monkeypatch.setattr(session_mod.subprocess, "run",
                        lambda cmd, **k: calls.append((cmd, k)) or subprocess.CompletedProcess(cmd, 0, "healthy\n", ""))
    monkeypatch.setenv("MY_LLM_KEY", "sk-x")
    cfg, plan = _launch_plan(tmp_path, "env:MY_LLM_KEY")
    session_mod.launch(cfg, plan, tmp_path / "compose.yml", provider="docker", rebuild=False,
                       secrets=secret_env(plan))
    # for llm-auth's `environment:`; the harness's variable is a placeholder in the compose file
    composes = [k["env"] for _, k in calls if "env" in k]  # the verify's inspects run without one
    assert composes and all(e["LLM_AUTH_KEY"] == "sk-x" and "GLOVE_LLM_API_KEY" not in e for e in composes)
    assert all("sk-x" not in " ".join(cmd) for cmd, _ in calls)
    assert "sk-x" not in (tmp_path / "compose.yml").read_text()
    assert calls[-1][0][-4:] == ["-it", "--name", plan.harness_service, plan.harness_service]


@pytest.mark.parametrize(("inspect", "removed"), [((1, ""), False), ((0, "false\n"), True), ((0, "true\n"), None)])
def test_a_stale_harness_is_removed_and_a_running_one_refused(monkeypatch, inspect, removed):
    from glove import session as session_mod
    from glove.config import ConfigError

    calls = []

    def run(cmd, **k):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, inspect[0], stdout=inspect[1])

    monkeypatch.setattr(session_mod.subprocess, "run", run)
    if removed is None:
        with pytest.raises(ConfigError, match="already running"):
            session_mod.clear_stale_harness("docker", "glove-s-harness")
    else:
        session_mod.clear_stale_harness("docker", "glove-s-harness")
    assert calls[0] == ["docker", "container", "inspect", "-f", "{{.State.Running}}", "glove-s-harness"]
    assert calls[1:] == ([["docker", "rm", "-f", "glove-s-harness"]] if removed else [])


def test_secret_env_resolves_an_env_reference_in_memory(tmp_path, monkeypatch):
    from glove.plan import secret_env

    monkeypatch.setenv("MY_LLM_KEY", "sk-env")
    _, plan = _launch_plan(tmp_path, "env:MY_LLM_KEY")
    assert secret_env(plan) == {"LLM_AUTH_KEY": "sk-env"}


# --- ls / down / rm / gc ----------------------------------------------------------------------


@pytest.mark.parametrize(("wipe", "tail"), [(False, []), (True, ["--volumes"])])
@pytest.mark.parametrize("runs", ["", "abc123\ndef456\n"])
def test_teardown_removes_a_killed_harness_run(monkeypatch, wipe, tail, runs):
    # one-off (`compose run`) containers are removed before `down`
    from glove import session

    calls = []

    def run(cmd, **k):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=runs if cmd[1] == "ps" else "")

    monkeypatch.setattr(session.subprocess, "run", run)
    session.teardown("s-0a0b0c", provider="podman", wipe=wipe)
    project = session.project_name("s-0a0b0c")
    assert calls[0] == ["podman", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}",
                        "--filter", "label=com.docker.compose.oneoff=True"]
    assert calls[1:] == ([["podman", "rm", "-f", "abc123", "def456"]] if runs else []) + [
        ["podman", "compose", "-p", project, "down", "--remove-orphans", *tail]]


@pytest.mark.parametrize(("provider", "banner_off"), [("docker", False), ("podman", True)])
def test_compose_runs_without_podmans_banner(monkeypatch, provider, banner_off):
    from glove import session

    envs = []
    monkeypatch.setattr(session.subprocess, "run",
                        lambda cmd, **k: envs.append(k.get("env")) or subprocess.CompletedProcess(cmd, 0, stdout=""))
    session.teardown("s-0a0b0c", provider=provider, wipe=False)
    assert ("PODMAN_COMPOSE_WARNING_LOGS" in envs[-1]) is banner_off


def test_the_v2_commands_are_gone():
    for cmd in (["init", "pi"], ["run", "pi"], ["config"], ["pi"]):
        assert runner.invoke(app, cmd).exit_code != 0, cmd


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

    monkeypatch.setattr("glove.session.launch", launch)
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 0 and "re-allocating and retrying" in result.output
    assert subnets[0] != subnets[1] == reg.find(_sid(d)).subnet


def test_up_gives_up_after_three_taken_subnets(home, tmp_path, monkeypatch):
    from glove.session import SubnetTaken

    d = make_session(tmp_path / "s")
    rebuilds = []

    def always(cfg, plan, *a, rebuild, **k):
        rebuilds.append(rebuild)
        raise SubnetTaken("taken")

    monkeypatch.setattr("glove.session.launch", always)
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

    monkeypatch.setattr("glove.session.launch", launch)
    monkeypatch.setattr("glove.cli._resolve_extensions", lambda *a, **k: None)
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
    (ext / "extension.yml").write_text("api: 2\nname: bad\nsummary: x\ncli: cli.py\n")
    (ext / "cli.py").write_text("raise RuntimeError('boom')\n")
    monkeypatch.setattr("glove.extensions.discover", lambda: discover(tmp_path / "exts"))
    cli._mount_extension_clis()
    assert "bad" not in {g.name for g in app.registered_groups}


def test_up_preflight_refuses_a_failing_extension_check(home, tmp_path, monkeypatch):
    from glove.runtimes.base import Check

    d = make_session(tmp_path / "s")
    started, inspected = [], []
    monkeypatch.setattr("glove.session.launch", lambda *a, **k: started.append(1))
    monkeypatch.setattr("glove.session.clear_stale_harness", lambda *a: inspected.append(a))
    monkeypatch.setattr("glove.doctor.extension_checks", lambda *a, **k: [Check("chrome", "fail", "absent")])
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 1 and "chrome: absent" in result.output and not started
    monkeypatch.setattr("glove.doctor.extension_checks", lambda *a, **k: [Check("x", "warn", "meh")])
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

    monkeypatch.setattr("glove.session.launch", lambda *a, **k: events.append("launched"))
    monkeypatch.setattr("glove.session.clear_stale_harness", lambda *a: None)
    monkeypatch.setattr("glove.doctor.extension_checks", lambda *a, **k: [])
    monkeypatch.setattr("glove.plan.secret_env", missing)
    monkeypatch.setattr("glove.extsession.run_teardown", lambda sd, sid, rt, given: events.append(set(given)) or ["w"])
    result = runner.invoke(app, ["up", str(d)])
    assert result.exit_code == 1 and said in result.output and "warn: w" in result.output
    assert "Traceback" not in result.output
    assert events == [{"llm"}]  # torn down, never launched


