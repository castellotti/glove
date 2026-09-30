"""`glove playwright view`: the tunnel's request filter, the URL, and refusals."""

from __future__ import annotations

import pytest
import typer

from glove.extensions import IN_TREE_DIR, load_module

cli = load_module(IN_TREE_DIR / "playwright" / "cli.py", "playwright")


def _head(host="127.0.0.1:4242", origin=None):
    lines = ["GET /websockify HTTP/1.1", f"Host: {host}", "Upgrade: websocket"]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


@pytest.mark.parametrize(("head", "ok"), [
    (_head(), True),                                          # a plain GET (vnc.html)
    (_head(origin="http://127.0.0.1:4242"), True),            # noVNC's own WebSocket
    (_head(origin="https://evil.example"), False),            # another page in your browser
    (_head(origin="http://127.0.0.1:9999"), False),           # another local listener
    (_head(host="evil.example:4242"), False),                 # DNS rebinding
    (_head(host="evil.example:4242", origin="http://evil.example:4242"), False),
    (_head(host="localhost:4242"), False),
    (b"GET / HTTP/1.1\r\n\r\n", False),                       # no Host at all
])
def test_only_this_listener_may_use_the_tunnel(head, ok):
    assert cli.allowed(head, 4242) is ok


def test_the_password_is_only_in_the_fragment():
    url = cli.view_url(4242, "s3cret", control=False)
    base, _, frag = url.partition("#")
    assert "s3cret" not in base and "password=s3cret" in frag and "view_only=1" in frag
    assert "view_only=0" in cli.view_url(4242, "x", control=True)


def _session(tmp_path, pw: str):
    (tmp_path / "work").mkdir()
    (tmp_path / ".glove").mkdir(mode=0o700)
    (tmp_path / ".glove" / "id").write_text("s-abc123\n")
    (tmp_path / "glove-session.yml").write_text(f"glove: 3\nharness: pi\nextensions:\n  playwright: {pw}\n")
    return tmp_path


@pytest.mark.parametrize(("pw", "args", "match"), [
    ("{mode: headless}", [], "needs `playwright: {mode: novnc}`"),
    ("{mode: novnc}", ["--control"], "needs `allow_control: true`"),
])
def test_view_refusals(tmp_path, capsys, pw, args, match):
    d = _session(tmp_path, pw)
    with pytest.raises(typer.Exit):
        cli.view(directory=d, control="--control" in args, no_open=True)
    assert match in capsys.readouterr().err.replace("\n", " ")


def test_a_stopped_sidecar_is_reported(tmp_path, capsys, monkeypatch):
    d = _session(tmp_path, "{mode: novnc}")
    monkeypatch.setattr(cli, "_running", lambda *a: False)
    with pytest.raises(typer.Exit):
        cli.view(directory=d, control=False, no_open=True)
    assert "glove-s-abc123-pw is not running" in capsys.readouterr().err.replace("\n", " ")


