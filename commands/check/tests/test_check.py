"""`glove check`."""

from helpers import command_module, make_session
from typer.testing import CliRunner

from glove.cli import app

runner = CliRunner()


def _lan(extra: str = "") -> str:
    return "{provider: llama.cpp, location: lan, endpoint: \"example.test:8080\", model: m" + extra + "}"


def test_check_reports_secrets_without_reading_them(home, tmp_path, monkeypatch):
    from glove import config as config_mod

    def boom(*a, **k):
        raise AssertionError("check must not resolve the key")

    monkeypatch.setattr(config_mod, "resolve_secret", boom)
    monkeypatch.delenv("NOT_SET_KEY", raising=False)
    d = make_session(tmp_path / "s", llm=_lan(", api_key: env:NOT_SET_KEY"))
    result = runner.invoke(app, ["check", str(d), "--no-container", "--offline"])
    assert result.exit_code == 1 and "NOT_SET_KEY is not set" in result.output
    assert not (d / ".glove").exists() and not (home / "registry.json").exists()  # check writes nothing
    monkeypatch.setenv("NOT_SET_KEY", "x")
    result = runner.invoke(app, ["check", str(d), "--no-container", "--offline"])
    assert "secret llm.api_key" in result.output and "is not set" not in result.output


def test_check_asks_the_llm_server_only_from_a_container(home, tmp_path, monkeypatch):
    cli = command_module("check")
    asked = []
    monkeypatch.setattr(cli, "probe_direct", lambda provider, url, **kw:
                        asked.append((provider, url, kw)) or (200, '{"data": [{"id": "m"}]}'))
    monkeypatch.setattr(cli, "run_doctor", lambda **k: [])  # no runtime probes here
    d = make_session(tmp_path / "s", llm=_lan())
    result = runner.invoke(app, ["check", str(d)])
    assert result.exit_code == 0, result.output
    assert "llm server" in result.output and "serves m" in result.output
    assert asked == [("docker", "http://example.test:8080/v1/models", {"method": "GET", "body": None, "headers": {}})]
    for flag in ("--offline", "--no-container"):  # neither runs a container: nothing is asked
        result = runner.invoke(app, ["check", str(d), flag])
        assert result.exit_code == 0 and "llm server" not in result.output, result.output
    assert len(asked) == 1
