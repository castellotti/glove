"""`glove ps`."""

from helpers import command_module
from typer.testing import CliRunner

from glove import registry as reg
from glove.cli import app
from glove.runtimes.base import RunningSession

runner = CliRunner()


def test_ps_lists_running_sessions_and_their_directories(home, monkeypatch, tmp_path):
    asked = []

    class Fake:
        def ps(self):
            return [RunningSession("glove-b-0d0e0f", "b-0d0e0f", ["harness"]),
                    RunningSession("glove-a-0a0b0c", "a-0a0b0c", ["llm", "harness"])]

    monkeypatch.setattr(command_module("ps"), "get_runtime", lambda name: asked.append(name) or Fake())
    reg.upsert(reg.SessionEntry(id="a-0a0b0c", dir=str(tmp_path / "a"), harness="pi"))
    out = runner.invoke(app, ["ps", "--runtime", "podman"]).output
    assert asked == ["podman"]
    a, b = out.splitlines()
    assert a.startswith("a-0a0b0c") and str(tmp_path / "a") in a and "2 containers: harness, llm" in a
    assert b.startswith("b-0d0e0f") and "(not registered)" in b


def test_ps_says_when_nothing_runs(monkeypatch):
    monkeypatch.setattr(command_module("ps"), "get_runtime", lambda name: type("R", (), {"ps": lambda self: []})())
    assert "no running glove sessions" in runner.invoke(app, ["ps"]).output
