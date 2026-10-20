"""`glove clean`: glove's stacks on a runtime, found by compose's project label."""

import subprocess

import pytest
import typer
from typer.testing import CliRunner

from glove import registry as reg
from glove.cli import COMMANDS_DIR
from glove.extensions import load_module

cli = load_module(COMMANDS_DIR / "clean" / "cli.py", "clean", ns="glove_cmd")
app = typer.Typer()
app.command()(cli.command)
runner = CliRunner()
LABEL = cli.PROJECT_LABEL


def _fake_runtime(monkeypatch, listing: dict[str, list[str]], *, fail: str = ""):
    """`_out` answering `<kind> inspect` from `listing` (kind → inspect lines)."""
    calls = []

    def out(rt, *args, partial=False):
        calls.append(args)
        if fail and fail in args:
            return None
        if "inspect" in args:
            return listing[args[0]]
        kind = "container" if args[0] == "ps" else args[0]
        return [f"{kind}-id"] if listing[kind] else []

    monkeypatch.setattr(cli, "_out", out)
    return calls


def test_stacks_groups_glove_v3_projects_and_skips_the_rest(monkeypatch):
    calls = _fake_runtime(monkeypatch, {
        "container": ["glove-a-0a0b0c c1 created", "glove-a-0a0b0c c2 exited", "open-webui c3 running",
                      "glove-pi-search x running"],  # not a v3 id: never glove v3's
        "network": ["glove-a-0a0b0c glove-a-0a0b0c-net"],
        "volume": ["glove-b-0d0e0f glove-b-0d0e0f-data", "open-webui_data x"]})
    a, b = cli.stacks("podman")
    assert (a.sid, a.containers, a.networks, a.active) == ("a-0a0b0c", {"c1": "created", "c2": "exited"},
                                                           ["glove-a-0a0b0c-net"], True)
    assert (b.sid, b.volumes, b.active, b.describe()) == ("b-0d0e0f", ["glove-b-0d0e0f-data"], False, "1 volume(s)")
    assert ("ps", "-aq", "--filter", f"label={LABEL}") in calls
    assert ("container", "inspect", "-f", f'{{{{index .Config.Labels "{LABEL}"}}}} {{{{.Id}}}} {{{{.State.Status}}}}',
            "container-id") in calls


def test_stacks_is_none_when_the_runtime_does_not_answer(monkeypatch):
    _fake_runtime(monkeypatch, {"container": [], "network": [], "volume": []}, fail="volume")
    assert cli.stacks("docker") is None


def test_stacks_keeps_what_an_inspect_printed_when_one_id_went_meanwhile(monkeypatch):
    monkeypatch.setattr(cli.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(
        cmd, 1, stdout="glove-a-0a0b0c n1\n", stderr="No such network: n-gone") if "inspect" in cmd
        else subprocess.CompletedProcess(cmd, 0 if "ls" in cmd else 1, stdout="n1\nn-gone\n"))
    assert cli._labelled("docker", "network", ".Labels", ".Name") == [["glove-a-0a0b0c", "n1"]]
    assert cli._out("docker", "network", "rm", "n1") is None  # a plain failure is still one


def test_stacks_with_nothing_labelled_inspects_nothing(monkeypatch):
    calls = _fake_runtime(monkeypatch, {"container": [], "network": [], "volume": []})
    assert cli.stacks("docker") == []
    assert not [c for c in calls if "inspect" in c]


@pytest.mark.parametrize("volumes", [True, False])
def test_remove_takes_containers_then_networks_and_volumes_only_when_asked(monkeypatch, volumes):
    cmds = []
    def run(cmd, **k):
        cmds.append(cmd)
        assert k["timeout"] == cli.TIMEOUT
        if cmd[-1] == "v1":
            raise subprocess.TimeoutExpired(cmd, k["timeout"])
        return subprocess.CompletedProcess(cmd, 1 if cmd[-1] == "n2" else 0)

    monkeypatch.setattr(cli.subprocess, "run", run)
    s = cli.Stack("docker", "a-0a0b0c", {"c1": "exited"}, ["n1", "n2"], ["v1"])
    assert cli.remove(s, volumes=volumes) == ["docker network n2", *(["docker volume v1"] if volumes else [])]
    assert cmds == [["docker", "rm", "-f", "c1"], ["docker", "network", "rm", "n1"], ["docker", "network", "rm", "n2"],
                    *([["docker", "volume", "rm", "v1"]] if volumes else [])]


def test_runtimes_are_the_named_one_or_those_on_path(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda c: c == "podman")
    assert cli.runtimes() == ["podman"]
    assert cli.runtimes("docker") == ["docker"]


def _session(tmp_path, name: str, sid: str, *, holds: str | None = None) -> None:
    """A registry row for `sid`; its directory holds `holds` (None: no directory)."""
    d = tmp_path / name
    if holds:
        (d / ".glove").mkdir(parents=True)
        (d / ".glove" / "id").write_text(holds)
    reg.upsert(reg.SessionEntry(id=sid, dir=str(d), harness="pi"))


@pytest.mark.parametrize("flag", [False, True])
def test_clean_removes_volumes_only_of_provably_gone_sessions(home, tmp_path, monkeypatch, flag):
    _session(tmp_path, "live", "live-0a0a0a", holds="live-0a0a0a")
    _session(tmp_path, "moved", "moved-0b0b0b")  # its directory is missing: maybe moved
    _session(tmp_path, "reused", "reused-0c0c0c", holds="reused-0d0d0d")  # re-launched under a new id
    found = [cli.Stack("docker", "live-0a0a0a", {"c1": "exited"}, ["n1"], ["v1"]),
             cli.Stack("docker", "moved-0b0b0b", {"c2": "exited"}, ["n2"], ["v2"]),
             cli.Stack("docker", "reused-0c0c0c", volumes=["v3"]),
             cli.Stack("docker", "other-home-0e0e0e", volumes=["v4"]),
             cli.Stack("docker", "starting-0f0f0f", {"c5": "created"}, volumes=["v5"])]
    removed = []
    monkeypatch.setattr(cli, "runtimes", lambda only=None: ["docker"])
    monkeypatch.setattr(cli, "stacks", lambda rt: found)
    monkeypatch.setattr(cli, "remove", lambda s, volumes: removed.append((s.sid, volumes)) or [])
    args = ["--volumes"] if flag else []
    result = runner.invoke(app, ["--dry-run", *args])
    assert result.exit_code == 0 and not removed
    out = result.output
    assert "glove-starting-0f0f0f is active: left alone" in out and "glove-live-0a0a0a" not in out
    if flag:
        assert "docker stack glove-moved-0b0b0b: 1 container(s), 1 network(s), 1 volume(s)" in out
        assert "keeping" not in out
    else:
        assert "docker stack glove-moved-0b0b0b: 1 container(s), 1 network(s)\n" in out
        assert "keeping docker glove-moved-0b0b0b's 1 volume(s): its directory is missing (moved?)" in out
        assert "keeping docker glove-other-home-0e0e0e's 1 volume(s): not in this registry" in out
    result = runner.invoke(app, ["-y", *args])
    assert result.exit_code == 0, result.output
    assert removed == [("moved-0b0b0b", flag), ("reused-0c0c0c", True),
                       *([("other-home-0e0e0e", True)] if flag else [])]


def test_clean_asks_first(home, monkeypatch):
    monkeypatch.setattr(cli, "runtimes", lambda only=None: ["docker"])
    monkeypatch.setattr(cli, "stacks", lambda rt: [cli.Stack("docker", "gone-0b0b0b", {"c": "exited"})])
    monkeypatch.setattr(cli, "remove", lambda s, volumes: pytest.fail("removed without asking"))
    assert runner.invoke(app, [], input="n\n").exit_code == 1


def test_clean_warns_when_a_runtime_does_not_answer_and_refuses_unknown_ones(home, monkeypatch):
    monkeypatch.setattr(cli, "stacks", lambda rt: None)
    result = runner.invoke(app, ["--runtime", "podman"])
    assert result.exit_code == 0 and "podman did not answer" in result.output and "nothing to clean" in result.output
    assert runner.invoke(app, ["--runtime", "lxc"]).exit_code == 1


def test_clean_refuses_an_unreadable_registry(home, tmp_path):
    (tmp_path / "ghome").mkdir()
    (tmp_path / "ghome" / "registry.json").write_text("[]")  # a glove v2 registry
    result = runner.invoke(app, ["--runtime", "docker"])
    assert result.exit_code == 1 and "v2 registry" in result.output


def test_glove_mounts_it():
    from glove.cli import app as glove

    assert "--dry-run" in runner.invoke(glove, ["clean", "--help"]).output
