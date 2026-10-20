"""`glove doctor`."""

import json

import pytest
from helpers import command_module
from typer.testing import CliRunner

from glove.cli import app
from glove.runtimes.base import Check

runner = CliRunner()


@pytest.fixture
def probed(monkeypatch):
    asked = []
    checks = [Check("os", "info", "x"), Check("runtime: podman", "ok", "y")]
    monkeypatch.setattr(command_module("doctor"), "run_doctor", lambda **k: asked.append(k) or checks)
    return asked, checks


def test_doctor_probes_the_runtimes_default_enforcer(probed):
    asked, _ = probed
    result = runner.invoke(app, ["doctor", "--runtime", "podman", "--no-container"])
    assert result.exit_code == 0, result.output
    assert asked == [{"runtime": "podman", "enforcer": "nono", "include_container_probes": False}]
    assert "glove doctor" in result.output and "runtime: podman" in result.output


def test_doctor_json_and_a_failing_check(probed):
    _, checks = probed
    checks.append(Check("enforcer", "fail", "absent"))
    result = runner.invoke(app, ["doctor", "--json", "--enforcer", "srt"])
    assert result.exit_code == 1
    doc = json.loads(result.output)
    assert (doc["runtime"], doc["enforcer"]) == ("docker", "srt") and doc["checks"][-1]["status"] == "fail"
