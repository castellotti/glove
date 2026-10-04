"""`relay`: the library behind relayed commands — relayd's egress fence, the
client, the image pins (the FIFO transport itself is Linux-only: it runs live
in tests/integration/test_github.sh)."""

from __future__ import annotations

import importlib.util
import re
import socket
import subprocess
import threading
from pathlib import Path

import pytest
from helpers import make_cfg

from glove.extensions import ExtensionError
from glove.plan import build_session_plan

HERE = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("relayd", HERE / "image" / "relayd.py")
relayd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(relayd)


@pytest.mark.parametrize("host,ok", [
    ("github.com", True), ("GitHub.com.", True), ("objects.githubusercontent.com", True),
    ("githubusercontent.com", False), ("evilgithub.com", False), ("github.com.evil.example", False),
    ("api.github.com", True), ("gist.github.com", False),
])
def test_host_allowed(host, ok):
    hosts = ("github.com", "api.github.com", ".githubusercontent.com")
    assert relayd.host_allowed(host, hosts) is ok


def _upstream():
    """A CONNECT proxy stand-in: answers 200 and echoes the tunnel."""
    srv = socket.create_server(("127.0.0.1", 0))
    seen: list[bytes] = []

    def serve():
        while True:
            c, _ = srv.accept()
            head = b""
            while b"\r\n\r\n" not in head:
                head += c.recv(4096)
            seen.append(head.split(b"\r\n")[0])
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            data = c.recv(4096)
            c.sendall(b"echo:" + data)
            c.close()

    threading.Thread(target=serve, daemon=True).start()
    return f"http://127.0.0.1:{srv.getsockname()[1]}", seen


def _ask(url: str, first: str, payload: bytes = b"") -> bytes:
    port = int(url.rsplit(":", 1)[1])
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(f"{first}\r\nHost: x\r\n\r\n".encode())
        out = s.recv(4096)
        if payload and b" 200 " in out:
            s.sendall(payload)
            out += s.recv(4096)
        return out


def test_the_fence_tunnels_to_the_policys_hosts_only():
    up, seen = _upstream()
    fence = relayd.Fence(up, ("github.com", ".githubusercontent.com"))
    out = _ask(fence.url, "CONNECT github.com:443 HTTP/1.1", b"hello")
    assert b" 200 " in out and out.endswith(b"echo:hello")
    assert seen == [b"CONNECT github.com:443 HTTP/1.1"]
    for first in ("CONNECT example.com:443 HTTP/1.1", "CONNECT github.com:22 HTTP/1.1",
                  "GET http://github.com/ HTTP/1.1", "CONNECT [::1]:443 HTTP/1.1"):
        out = _ask(fence.url, first)
        assert out.startswith(b"HTTP/1.1 403") and b"glove relay refused" in out, first
    assert len(seen) == 1  # nothing refused ever reached the upstream


def test_the_client_is_valid_bash_and_executable():
    assert (HERE / "glove-relay").stat().st_mode & 0o111
    subprocess.run(["bash", "-n", str(HERE / "glove-relay")], check=True)


def test_the_image_pins_its_base_and_gh():
    df = (HERE / "image" / "Dockerfile").read_text()
    search = (HERE.parent / "search" / "image" / "Dockerfile").read_text()
    base = re.search(r"^FROM (\S+)", df, re.M).group(1)
    assert "@sha256:" in base and base in search
    assert re.search(r"GH_SHA256_AMD64=[0-9a-f]{64}", df) and re.search(r"GH_SHA256_ARM64=[0-9a-f]{64}", df)
    assert "sha256sum -c" in df


def test_relay_is_a_library(tmp_path):
    cfg = make_cfg(harness="pi", name="s", workdir=str(tmp_path), extensions={"direct": {}, "relay": {}})
    with pytest.raises(ExtensionError, match="library extension"):
        build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))
