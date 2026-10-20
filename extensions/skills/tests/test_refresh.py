"""`glove skills refresh`: what is stored is shown, Enter keeps it, one secret
can be named alone, and a captured one goes to `glove playwright login`."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
import yaml

from glove.api import ExtSession
from glove.extensions import load_module

HERE = Path(__file__).resolve().parent.parent
cli = load_module(HERE / "cli.py", "skills")
SCRIPT = "#!/usr/bin/env python3\nprint('x')\n"
RELAY = {"commands": {
    "scripts/wiki.py": {"allow": ["*"], "env": {"WIKI_PAT": "keychain:t-wiki"}},
    "scripts/chat.py": {"allow": ["*"], "files": {"~/.config/chat.json": {
        "template": "local/chat.json.j2", "secrets": {"xoxc": "keychain:t-xoxc", "xoxd": "keychain:t-xoxd"}}}},
    "scripts/api.py": {"allow": ["*"], "env": {"API_TOKEN": {"secret": "keychain:t-api", "refresh": "local/mint.sh"}}},
}}
LOGIN = {"start_url": "https://chat.example/", "domains": ["chat.example"],
         "capture": {"t-xoxd": {"cookie": {"domain": "chat.example", "name": "d"}}}}


@pytest.fixture
def session(tmp_path, monkeypatch):
    root = tmp_path / "skills" / "demo"
    for name in ("wiki", "chat", "api"):
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "scripts" / f"{name}.py").write_text(SCRIPT)
    (root / ".claude-plugin").mkdir()
    (root / ".claude-plugin" / "plugin.json").write_text('{"name": "demo"}')
    (tmp_path / "work").mkdir()
    (tmp_path / "local").mkdir()
    (tmp_path / "local" / "chat.json.j2").write_text("{}\n")
    (tmp_path / "local" / "mint.sh").write_text("#!/bin/sh\necho minted-$1\n")
    (tmp_path / "local" / "mint.sh").chmod(0o755)
    (tmp_path / ".glove").mkdir(mode=0o700)
    (tmp_path / ".glove" / "id").write_text("s-0a0b0c\n")
    (tmp_path / "glove-session.yml").write_text(yaml.safe_dump({"glove": 3, "harness": "pi", "extensions": {
        "direct": {}, "skills": {"plugins": {"demo": {"path": "skills/demo", "relay": RELAY}}},
        "playwright": {"login": LOGIN}}}))
    stored = {"t-wiki": "old", "t-xoxc": "old"}   # t-api and t-xoxd are missing
    monkeypatch.setattr(cli, "secret_exists", lambda ref: (ref.removeprefix("keychain:") in stored, ""))
    monkeypatch.setattr(cli, "keychain_set", lambda svc, v=None: stored.update({svc: v}) or 0)
    monkeypatch.setattr(ExtSession, "running", lambda self, service: False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    return tmp_path, stored


def _run(d, *names, no_reload=False, secret=()):
    cli.refresh(plugin="demo", names=list(names), secret=list(secret), no_reload=no_reload, directory=d)


def _answers(monkeypatch, typed=(), confirms=()):
    typed, confirms = iter(typed), iter(confirms)  # then StopIteration: an unexpected prompt fails, never hangs
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(typed))
    monkeypatch.setattr(cli.typer, "confirm", lambda text, default=False: next(confirms))


def test_enter_keeps_or_skips_and_shows_what_is_stored(session, monkeypatch, capsys):
    d, stored = session
    _answers(monkeypatch, typed=["", ""], confirms=[False, False])  # wiki, xoxc kept; no mint.sh, no sign-in
    _run(d)
    out = " ".join(capsys.readouterr().out.split())
    assert stored == {"t-wiki": "old", "t-xoxc": "old"}
    assert "t-wiki stored hook" not in out and "t-wiki stored typed; WIKI_PAT (scripts/wiki.py)" in out
    assert "t-api missing hook local/mint.sh; API_TOKEN (scripts/api.py)" in out
    assert "t-xoxd missing `glove playwright login`; xoxd in ~/.config/chat.json (scripts/chat.py)" in out
    assert "t-wiki: kept" in out and "nothing changed" in out


def test_a_typed_value_is_stored(session, monkeypatch):
    d, stored = session
    _answers(monkeypatch, typed=["new-wiki", ""], confirms=[True, False])
    _run(d)
    assert stored == {"t-wiki": "new-wiki", "t-xoxc": "old", "t-api": "minted-t-api"}


@pytest.mark.parametrize("name", ["t-wiki", "WIKI_PAT"])
def test_one_secret_alone_asks_nothing_else(session, monkeypatch, name):
    d, stored = session
    _answers(monkeypatch, typed=["new-wiki"])
    _run(d, name)
    assert stored == {"t-wiki": "new-wiki", "t-xoxc": "old"}


def test_a_named_hook_runs_without_asking(session, monkeypatch):
    d, stored = session
    _answers(monkeypatch)
    _run(d, secret=["t-api"])
    assert stored["t-api"] == "minted-t-api"


def test_an_unknown_name_lists_the_secrets(session, monkeypatch, capsys):
    d, _ = session
    with pytest.raises(typer.Exit):
        _run(d, "nope")
    assert "t-api, t-wiki, t-xoxc, t-xoxd" in " ".join(capsys.readouterr().err.split())


@pytest.mark.parametrize("no_reload", [False, True])
def test_a_captured_secret_runs_playwright_login(session, monkeypatch, no_reload):
    d, _ = session
    ran = []
    monkeypatch.setattr(cli.subprocess, "run", lambda argv, check: ran.append(argv) or
                        type("R", (), {"returncode": 0})())
    _answers(monkeypatch)
    _run(d, "xoxd", no_reload=no_reload)
    assert ran == [[cli.sys.executable, "-m", "glove.cli", "playwright", "login", "--dir", str(d),
                    *(["--no-reload"] if no_reload else [])]]


def test_a_failure_names_what_was_already_stored(session, monkeypatch, capsys):
    d, stored = session
    monkeypatch.setattr(cli, "keychain_set", lambda svc, v=None: 1 if svc == "t-wiki" else stored.update({svc: v}) or 0)
    _answers(monkeypatch, typed=["new-wiki"])
    with pytest.raises(typer.Exit):
        _run(d, "t-api", "t-wiki")   # the hook's value is stored, then the typed one fails
    err = " ".join(capsys.readouterr().err.split())
    assert stored["t-api"] == "minted-t-api" and "storing t-wiki failed (exit 1)" in err
    assert "stored before stopping: t-api; `glove skills reload demo` applies them" in err


def test_without_a_terminal_typed_secrets_are_skipped(session, monkeypatch, capsys):
    d, stored = session
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    _answers(monkeypatch)
    _run(d)
    out = " ".join(capsys.readouterr().out.split())
    assert stored["t-api"] == "minted-t-api" and stored["t-wiki"] == "old"
    assert "t-wiki: skipped (no refresh hook, and no terminal" in out
    assert "t-xoxd: skipped (`glove playwright login` needs a terminal)" in out
    for name in ("t-wiki", "t-xoxd"):  # named: an error, not a skip
        with pytest.raises(typer.Exit):
            _run(d, name)
