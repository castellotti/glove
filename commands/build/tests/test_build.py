"""`glove build`."""

from helpers import command_module
from typer.testing import CliRunner

from glove.cli import app

runner = CliRunner()


def _record(monkeypatch):
    cli, calls = command_module("build"), []
    monkeypatch.setattr(cli, "build_forwarder", lambda prov, **k: calls.append(("forwarder", prov, k)))
    monkeypatch.setattr(cli, "build_harness", lambda prov, profile, **k: calls.append((profile.name, prov, k)))
    return calls


def test_build_without_a_harness_builds_the_forwarder_only(monkeypatch):
    calls = _record(monkeypatch)
    assert runner.invoke(app, ["build", "--provider", "podman"]).exit_code == 0
    assert calls == [("forwarder", "podman", {"force": False})]


def test_build_a_harness_with_its_enforcer_variant(monkeypatch):
    calls = _record(monkeypatch)
    assert runner.invoke(app, ["build", "pi", "--provider", "docker", "--enforcer", "srt", "--rebuild"]).exit_code == 0
    assert calls == [("forwarder", "docker", {"force": True}), ("pi", "docker", {"enforcer": "srt", "force": True})]
    calls.clear()
    assert runner.invoke(app, ["build", "pi", "--provider", "docker"]).exit_code == 0
    assert calls[1] == ("pi", "docker", {"enforcer": "nono", "force": False})  # the default variant
