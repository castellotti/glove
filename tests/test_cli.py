"""glove's CLI (`glove/cli.py`: the commands and extension CLIs it mounts) and the launch and
teardown machinery the commands drive. Each command's own tests are in `commands/<name>/tests/`."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from glove.cli import app
from glove.config import ConfigError

runner = CliRunner()


def test_help_lists_every_command():
    from glove.cli import COMMANDS_DIR

    out = runner.invoke(app, ["--help"], env={"COLUMNS": "200"}).output
    names = sorted(p.name for p in COMMANDS_DIR.iterdir() if (p / "cli.py").is_file())
    assert len(names) == 17
    for name in names:
        assert f" {name} " in out, name
    # workflow order (each command's RANK); Typer lists the groups after the commands
    shown = [line.split()[1] for line in out.splitlines() if line.startswith("│ ") and line[2:3].isalpha()]
    assert shown[:17] == ["new", "plan", "up", "check", "down", "rm", "ls", "ps", "gc", "clean", "build", "doctor",
                          "policy", "ext", "version", "downloads", "keychain"]


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


def test_launch_makes_the_binds_missing_mount_points_just_before_the_harness(tmp_path, monkeypatch):
    # Docker Desktop's native layer cannot make one nested in another bind ("outside of rootfs"), and a
    # refused or failed launch leaves none in the user's tree: after the sidecars and prepare()
    from glove import session as session_mod

    seen: list = []
    monkeypatch.setattr(session_mod, "ensure_images", lambda *a, **k: None)
    monkeypatch.setattr(session_mod, "start_sidecars", lambda *a, **k: None)
    monkeypatch.setattr(session_mod.subprocess, "run",
                        lambda cmd, **k: seen.append((tmp_path / "work" / ".pi" / "settings.json").is_file()))
    cfg, plan = _launch_plan(tmp_path, "env:MY_LLM_KEY")
    session_mod.launch(cfg, plan, tmp_path / "compose.yml", provider="docker", rebuild=False, secrets={},
                       prepare=lambda: seen.append((tmp_path / "work" / ".pi").exists()))
    assert seen == [False, True]  # none at prepare(); the harness's `compose run` finds it


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
    assert calls[1:] == ([["docker", "rm", "-fv", "glove-s-harness"]] if removed else [])


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
    assert calls[1:] == ([["podman", "rm", "-fv", "abc123", "def456"]] if runs else []) + [
        ["podman", "compose", "-p", project, "rm", "-fsv"],  # anonymous volumes go, named ones stay
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


# --- extension CLIs: listed from the manifest, loaded only when invoked (round 18 A) ----------------

_PROBE = """
import json, sys
from typer.testing import CliRunner
from glove.cli import app
r = CliRunner().invoke(app, sys.argv[1:], env={"COLUMNS": "200"})
print(r.output)
print(json.dumps([r.exit_code, sorted(k for k in sys.modules if k.startswith(("glove_ext.", "extensions.")))]))
"""


def _glove(home, *args):
    """`glove *args` in a fresh interpreter: its exit code, output and the extension modules it imported."""
    r = subprocess.run([sys.executable, "-c", _PROBE, *args], env={**os.environ, "GLOVE_HOME": str(home)},
                       cwd=Path(__file__).parents[1], capture_output=True, text=True, check=True)
    out, _, last = r.stdout.rstrip().rpartition("\n")
    code, modules = json.loads(last)
    return code, out + r.stderr, modules


def _planting_ext(root, marker, name="planted"):
    """An out-of-tree extension whose cli.py and hooks.py write `marker` when imported."""
    d = root / name
    d.mkdir(parents=True)
    (d / "extension.yml").write_text(f"api: 2\nname: {name}\nsummary: plants a marker\ncli: cli.py\n"
                                     "hooks: hooks.py\n")
    plant = f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n"
    (d / "cli.py").write_text(plant + "import typer\napp = typer.Typer()\n\n@app.command()\ndef hi():\n"
                              "    print('hi')\n\n@app.command()\ndef ho():\n    pass\n")
    (d / "hooks.py").write_text(plant)
    return d


def _config(home, oot, trusted=()):
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yml").write_text(f"extension_paths: [{oot}]\ntrusted_extensions: {list(trusted)}\n")


@pytest.mark.parametrize("args", [["--help"], ["ls"], ["version"], ["ext"]])
def test_glove_imports_no_extension_module_unless_its_cli_runs(tmp_path, args):
    marker = tmp_path / "marker"
    _planting_ext(tmp_path / "oot", marker)
    _config(tmp_path / "gh", tmp_path / "oot", trusted=["planted"])
    code, out, modules = _glove(tmp_path / "gh", *args)
    assert code == 0, out
    assert modules == [] and not marker.exists()
    if args == ["--help"]:  # listed from the manifest alone
        assert "planted" in out and "plants a marker" in out and "filter" in out


def test_glove_name_help_loads_exactly_that_cli(tmp_path):
    code, out, modules = _glove(tmp_path / "gh", "filter", "--help")
    assert code == 0 and "block" in out
    # filter's CLI imports observe's and the gate library's (in-tree)
    assert {m.split(".")[1] for m in modules} == {"filter", "observe", "gate"}
    code, out, modules = _glove(tmp_path / "gh", "playwright", "--help")
    assert code == 0 and {m.split(".")[1] for m in modules} == {"playwright"}


def test_an_untrusted_out_of_tree_cli_never_runs(tmp_path):
    marker = tmp_path / "marker"
    _planting_ext(tmp_path / "oot", marker)
    _config(tmp_path / "gh", tmp_path / "oot")
    for args in (["--help"], ["ls"], ["ext"], ["planted", "hi"], ["planted", "--help"]):
        code, out, modules = _glove(tmp_path / "gh", *args)
        assert not marker.exists() and modules == [], args
        refused = args[0] == "planted"
        assert code == refused and ("out-of-tree and not trusted" in out) is refused, args
        assert "trusted_extensions" in out if refused else True
    assert "planted" not in _glove(tmp_path / "gh", "--help")[1]  # no CLI to list
    assert "cli: glove planted … (untrusted: refused)" in _glove(tmp_path / "gh", "ext")[1]
    _config(tmp_path / "gh", tmp_path / "oot", trusted=["planted"])
    code, out, _ = _glove(tmp_path / "gh", "planted", "hi")
    assert code == 0 and "hi" in out and marker.exists()


def test_a_broken_config_or_extension_cli_does_not_break_glove(home, tmp_path):
    home.mkdir()
    (home / "config.yml").write_text("no_such_key: 1\n")
    r = runner.invoke(app, ["--help"])  # the commands that read config.yml report it
    assert r.exit_code == 0 and " up " in r.output
    ext = tmp_path / "exts" / "bad"
    ext.mkdir(parents=True)
    (ext / "extension.yml").write_text("api: 2\nname: bad\nsummary: x\ncli: cli.py\n")
    (ext / "cli.py").write_text("raise RuntimeError('boom')\n")
    (home / "config.yml").write_text(f"extension_paths: [{ext}]\ntrusted_extensions: [bad]\n")
    assert runner.invoke(app, ["version"]).exit_code == 0
    r = runner.invoke(app, ["bad", "--help"])
    assert r.exit_code == 1 and "failed to load: boom" in r.output
    (ext / "cli.py").write_text("app = 1\n")
    assert "has no `app`" in runner.invoke(app, ["bad", "x"]).output
    r = runner.invoke(app, ["bda"], env={"COLUMNS": "300"})  # extension CLIs are suggested too
    assert r.exit_code == 2 and "Did you mean 'bad'?" in r.output


def test_a_discovery_error_is_named_when_an_extension_cli_is_missing(home, tmp_path):
    shadow = tmp_path / "exts" / "observe"  # an out-of-tree extension reusing an in-tree name
    shadow.mkdir(parents=True)
    (shadow / "extension.yml").write_text("api: 2\nname: observe\nsummary: x\n")
    home.mkdir()
    (home / "config.yml").write_text(f"extension_paths: [{shadow}]\n")
    assert runner.invoke(app, ["version"]).exit_code == 0
    r = runner.invoke(app, ["filter", "--help"], env={"COLUMNS": "400"})
    assert r.exit_code == 2 and "extension CLIs are unavailable" in r.output and "shadows" in r.output


def test_a_core_command_wins_over_an_extension_of_its_name(tmp_path):
    marker = tmp_path / "marker"
    _planting_ext(tmp_path / "oot", marker, name="ls")
    _config(tmp_path / "gh", tmp_path / "oot", trusted=["ls"])
    code, _, modules = _glove(tmp_path / "gh", "ls")
    assert code == 0 and modules == [] and not marker.exists()


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
