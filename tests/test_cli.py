"""glove's CLI (`glove/cli.py`: the commands and extension CLIs it mounts) and the launch and
teardown machinery the commands drive. Each command's own tests are in `commands/<name>/tests/`."""

from __future__ import annotations

import subprocess

import pytest
from typer.testing import CliRunner

from glove.cli import app
from glove.config import ConfigError

runner = CliRunner()


@pytest.fixture(autouse=True)
def _wide_console(monkeypatch):
    from glove import sessionops

    for c in (sessionops.console, sessionops.err):
        monkeypatch.setattr(c, "width", 400)  # no wrapping of long paths in assertions


@pytest.fixture
def home(tmp_path, monkeypatch):
    ghome = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(ghome))
    return ghome


def test_help_lists_every_command():
    from glove.cli import COMMANDS_DIR

    out = runner.invoke(app, ["--help"], env={"COLUMNS": "200"}).output
    names = sorted(p.name for p in COMMANDS_DIR.iterdir() if (p / "cli.py").is_file())
    assert len(names) == 17
    for name in names:
        assert f" {name} " in out, name


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


# --- teardown ----------------------------------------------------------------------------


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




def test_a_broken_or_missing_command_does_not_break_glove(tmp_path, monkeypatch, capsys):
    import typer

    from glove import cli

    for name, text in {"good": "def command():\n    print('ran')\n", "broken": "raise RuntimeError('boom')\n",
                       "neither": "x = 1\n"}.items():
        (tmp_path / "commands" / name).mkdir(parents=True)
        (tmp_path / "commands" / name / "cli.py").write_text(text)
    fresh = typer.Typer()
    fresh.command("noop")(lambda: None)  # a group needs two commands to keep their names
    monkeypatch.setattr(cli, "app", fresh)
    monkeypatch.setattr(cli, "COMMANDS_DIR", tmp_path / "commands")
    cli._mount_commands()
    out = capsys.readouterr().err
    assert "command 'broken' failed to load: boom" in out and "'neither'" in out
    assert "neither `command` nor `app`" in out
    assert runner.invoke(fresh, ["good"]).output == "ran\n"
    monkeypatch.setattr(cli, "COMMANDS_DIR", tmp_path / "absent")  # e.g. a wheel install without commands/
    cli._mount_commands()
