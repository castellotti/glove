"""`glove filter …` (the filter extension's CLI): rules.json editing, the same
file and writer contract as Layman, validated with the gate's own validator."""

from __future__ import annotations

import json
import socket

import pytest
from helpers import make_session
from typer.testing import CliRunner

from extensions.gate.netgate.policy import validate
from extensions.gate.tests.test_netgate_policy import CLI_ID, ENV, SESSION, doc, needs_non_root, rule
from glove.cli import app


@pytest.fixture
def ghome(tmp_path, monkeypatch):
    """A launched session with the filter grant: glove created control/<id>/."""
    g = tmp_path / "ghome"
    monkeypatch.setenv("GLOVE_HOME", str(g))
    wd = make_session(tmp_path / "wd")  # a launched session: .glove/id holds its id
    (wd / ".glove").mkdir()
    (wd / ".glove" / "id").write_text(CLI_ID + "\n")
    (g / "control" / CLI_ID).mkdir(parents=True, mode=0o700)
    monkeypatch.chdir(wd)
    return g


def test_cli_never_creates_the_control_dir(ghome):
    """Without the filter grant there is no control/<id>/, and the CLI will not
    make one (only `glove up` with `filter` active does)."""
    (ghome / "control" / CLI_ID).rmdir()
    for argv in (["filter", "block", "x.example"], ["filter", "rules"]):
        out = CliRunner().invoke(app, argv)
        assert out.exit_code == 1 and "no filter grant" in out.output, argv
    assert not (ghome / "control" / CLI_ID).exists()


def test_cli_block_unblock_rules(ghome):
    r = CliRunner()
    path = ghome / "control" / CLI_ID / "rules.json"
    out = r.invoke(app, ["filter", "block", "*.DoubleClick.net", "--terminate", "--note", "ads"])
    assert out.exit_code == 0, out.output
    assert r.invoke(app, ["filter", "block", "203.0.113.0/24", "--port", "443"]).exit_code == 0
    assert r.invoke(app, ["filter", "block", "api.example.com", "--allow"]).exit_code == 0
    data = json.loads(path.read_text())
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    rs = validate(data, env=CLI_ID, session=CLI_ID)  # the gate would accept it
    assert [(x.action, x.host, str(x.net) if x.net else None) for x in rs.rules] == [
        ("block", "*.doubleclick.net", None), ("block", None, "203.0.113.0/24"), ("allow", "api.example.com", None)]
    assert data["rules"][0]["terminate"] is True and data["updated_by"] == "glove-cli"

    shown = r.invoke(app, ["filter", "rules"])
    assert "*.doubleclick.net" in shown.output and "built-in SSRF guard" in shown.output

    assert r.invoke(app, ["filter", "unblock", "*.doubleclick.net"]).exit_code == 0
    assert r.invoke(app, ["filter", "unblock", data["rules"][1]["id"]]).exit_code == 0
    assert [x["match"] for x in json.loads(path.read_text())["rules"]] == [{"host": "api.example.com"}]
    assert r.invoke(app, ["filter", "unblock", "nope.example"]).exit_code == 1


def test_cli_refuses_to_overwrite_an_invalid_file(ghome):
    path = ghome / "control" / CLI_ID / "rules.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"v": 1, "env": CLI_ID, "session": CLI_ID, "rules": [], "exec": "x"}))
    out = CliRunner().invoke(app, ["filter", "block", "x.example"])
    assert out.exit_code == 1 and "unknown top-level" in out.output
    assert "exec" in path.read_text()  # untouched
    assert "invalid" in CliRunner().invoke(app, ["filter", "rules"]).output



def test_cli_rules_shows_a_file_without_default_or_rules(ghome):
    path = ghome / "control" / CLI_ID / "rules.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"v": 1, "env": CLI_ID, "session": CLI_ID}))  # valid: both optional
    out = CliRunner().invoke(app, ["filter", "rules"])
    assert out.exit_code == 0, out.output
    assert "default: allow" in out.output and "(no rules)" in out.output

def test_cli_block_never_resolves(ghome, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("DNS lookup")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom)
    assert CliRunner().invoke(app, ["filter", "block", "some.tracker.example"]).exit_code == 0


@needs_non_root
def test_cli_reports_an_unreadable_file_instead_of_crashing_or_replacing_it(ghome):
    path = ghome / "control" / CLI_ID / "rules.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc(rule(host="kept.example"))))
    path.chmod(0o000)
    try:
        for argv in (["filter", "rules"], ["filter", "block", "x.example"], ["filter", "unblock", "r_1"]):
            out = CliRunner().invoke(app, argv)
            assert out.exit_code == 1 and "cannot read rules.json: permission denied" in out.output, argv
            assert out.exception is None or isinstance(out.exception, SystemExit), argv
    finally:
        path.chmod(0o600)
    assert "kept.example" in path.read_text()


def test_cli_rules_says_whether_the_file_on_disk_is_enforced(ghome):
    from extensions.gate.netgate.policy import sha256_hex

    r = CliRunner()
    assert r.invoke(app, ["filter", "block", "a.example"]).exit_code == 0
    path = ghome / "control" / CLI_ID / "rules.json"
    net = ghome / "observe" / CLI_ID / "net"
    net.mkdir(parents=True, exist_ok=True)

    def status(**rules):
        (net / "status.json").write_text(json.dumps({"rules": {"ok": True, "active_count": 1, **rules}}))
        return r.invoke(app, ["filter", "rules"]).output

    digest = sha256_hex(path.read_bytes())
    assert "enforced" in status(sha256=digest)
    assert "pending" in status(sha256="0" * 64, last_rejected=None)
    assert "rejected" in status(sha256="0" * 64, last_rejected={"sha256": digest})
    assert "predates" in status()


def test_validate_cli_is_the_gates_validator_and_pure(tmp_path, monkeypatch):
    from extensions.gate.netgate.policy import sha256_hex

    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "nonexistent"))  # never consulted
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(AssertionError("DNS")))
    good = tmp_path / "rules.json"
    good.write_text(json.dumps(doc(rule(host="a.example"))))
    r = CliRunner()
    out = r.invoke(app, ["filter", "validate", str(good), "--env", ENV, "--session", SESSION, "--json"])
    assert out.exit_code == 0, out.output
    assert json.loads(out.stdout) == {"ok": True, "error": None, "sha256": sha256_hex(good.read_bytes()),
                                      "default": "allow", "active_count": 1}
    out = r.invoke(app, ["filter", "validate", str(good), "--env", ENV, "--session", "pi-search-other", "--json"])
    res = json.loads(out.stdout)
    assert out.exit_code == 1 and res["ok"] is False and "file is for 'pi-search'" in res["error"]
    assert res["sha256"] == sha256_hex(good.read_bytes())
    assert r.invoke(app, ["filter", "validate", str(good)]).exit_code == 0  # env/session optional

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc(rule(host="a.example"), exec="x")))
    out = r.invoke(app, ["filter", "validate", str(bad)])
    assert out.exit_code == 1 and "unknown top-level keys ['exec']" in out.output  # markup escaped
    out = r.invoke(app, ["filter", "validate", "-", "--json"], input=good.read_bytes())
    assert out.exit_code == 0 and json.loads(out.stdout)["ok"]
    out = r.invoke(app, ["filter", "validate", str(tmp_path / "missing.json"), "--json"])
    assert out.exit_code == 1 and json.loads(out.stdout) == {
        "ok": False, "error": "cannot read missing.json: no such file or directory", "sha256": None,
        "default": None, "active_count": None}
