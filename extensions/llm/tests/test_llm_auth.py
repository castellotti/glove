"""llm-auth (image/llm_auth.py), in-process against a local upstream: the key
swap, the allowlist, one check per request, streaming, TLS to the provider's
name, and logs without values."""

from __future__ import annotations

import contextlib
import http.client
import importlib.util
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

spec = importlib.util.spec_from_file_location("llm_auth", Path(__file__).parents[1] / "image" / "llm_auth.py")
llm_auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(llm_auth)

KEY = "sk-real-0123456789"
ALLOW = [["POST", "/v1/chat/completions"], ["GET", "/v1/models"], ["GET", "/api/v0/models/{model}"]]


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: ClassVar[list[tuple[str, str, dict[str, str]]]] = []
    release = threading.Event()

    def log_message(self, *a):
        pass

    def _handle(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        Upstream.seen.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
        if self.path == "/v1/chat/completions" and b"stream" in body:
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("connection", "close")
            self.end_headers()
            self.wfile.write(b"data: first\n\n")
            self.wfile.flush()
            Upstream.release.wait(5)  # the client must see `first` before this returns
            self.wfile.write(b"data: [DONE]\n\n")
            self.close_connection = True
            return
        out = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_HEAD = _handle


def _serve(server):
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return server


@pytest.fixture
def proxy():
    Upstream.seen = []
    Upstream.release = threading.Event()
    up = _serve(ThreadingHTTPServer(("127.0.0.1", 0), Upstream))
    servers = [up]

    def make(**over):
        env = {"LLM_AUTH_KEY": KEY, "LLM_AUTH_UPSTREAM": f"127.0.0.1:{up.server_address[1]}",
               "LLM_AUTH_HOST": "api.example.com", "LLM_AUTH_HEADER": "Authorization", "LLM_AUTH_SCHEME": "Bearer",
               "LLM_AUTH_ALLOW": json.dumps(ALLOW), "LLM_AUTH_PORT": "0", **over}
        cfg = llm_auth.Config(env)
        srv = _serve(llm_auth.serve(cfg, host="127.0.0.1"))
        servers.append(srv)
        return srv.server_address[1], cfg

    yield make
    Upstream.release.set()
    for s in servers:
        s.shutdown()


def _request(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    return r.status, r.read()


def test_the_key_replaces_the_clients_and_host_is_the_upstreams(proxy):
    port, _ = proxy()
    status, _ = _request(port, "POST", "/v1/chat/completions", b"{}",
                         {"Authorization": "Bearer glove-injected", "x-api-key": "glove-injected", "api-key": "x",
                          "Proxy-Authorization": "y", "Connection": "x-drop", "x-drop": "1", "anthropic-beta": "b"})
    assert status == 200
    method, path, h = Upstream.seen[-1]
    assert (method, path, h["authorization"], h["host"]) == ("POST", "/v1/chat/completions", f"Bearer {KEY}",
                                                            "api.example.com")
    assert not {"x-api-key", "api-key", "proxy-authorization", "x-drop"} & set(h)
    assert h["anthropic-beta"] == "b"  # every other header passes


def test_a_scheme_less_header(proxy):
    port, _ = proxy(LLM_AUTH_HEADER="x-api-key", LLM_AUTH_SCHEME="")
    _request(port, "GET", "/v1/models")
    assert Upstream.seen[-1][2]["x-api-key"] == KEY and "authorization" not in Upstream.seen[-1][2]


@pytest.mark.parametrize(("method", "path"), [
    ("GET", "/v1/files"), ("POST", "/v1/models"), ("GET", "/v1/models/../files"), ("GET", "/v1/%6Dodels"),
    ("DELETE", "/v1/models"), ("GET", "/api/v0/models"), ("GET", "http://evil.example/v1/models"),
])
def test_anything_off_the_allowlist_is_refused_before_the_upstream(proxy, method, path):
    port, _ = proxy()
    status, body = _request(port, method, path)
    assert status == 403 and b"not an inference path" in body and Upstream.seen == []


def test_a_query_and_a_model_segment_pass(proxy):
    port, _ = proxy()
    assert _request(port, "GET", "/v1/models?limit=1000")[0] == 200
    assert _request(port, "GET", "/api/v0/models/qwen/qwen3-8b")[0] == 200  # LM Studio: publisher/model
    assert [p for _, p, _ in Upstream.seen] == ["/v1/models?limit=1000", "/api/v0/models/qwen/qwen3-8b"]


def test_every_request_on_a_kept_alive_connection_is_checked(proxy):
    port, _ = proxy()
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"GET /v1/models HTTP/1.1\r\nHost: x\r\n\r\n"
              b"GET /v1/files HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer glove-injected\r\n\r\n")
    got = b""
    deadline = time.time() + 10
    while got.count(b"HTTP/1.1 ") < 2 and time.time() < deadline:
        got += s.recv(65536)
    s.close()
    assert b"HTTP/1.1 200" in got and b"HTTP/1.1 403" in got
    assert [p for _, p, _ in Upstream.seen] == ["/v1/models"]


def test_a_refused_request_closes_its_connection(proxy):
    port, _ = proxy()
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    # its body is never read, so it must not be taken for the next request
    s.sendall(b"POST /v1/files HTTP/1.1\r\nHost: x\r\nContent-Length: 30\r\n\r\nGET /v1/models HTTP/1.1\r\n\r\n...")
    got = b""
    while chunk := s.recv(65536):
        got += chunk
    s.close()
    assert got.startswith(b"HTTP/1.1 403") and got.count(b"HTTP/1.1 ") == 1 and Upstream.seen == []


def test_a_chunked_request_body_is_refused(proxy):
    port, _ = proxy()
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
              b"2\r\n{}\r\n0\r\n\r\n")
    assert s.recv(65536).startswith(b"HTTP/1.1 411")
    s.close()
    assert Upstream.seen == []


def test_an_answer_streams_unbuffered(proxy):
    port, _ = proxy()
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", "/v1/chat/completions", body=b'{"stream": true}')
    r = c.getresponse()
    assert r.status == 200 and r.read1(100) == b"data: first\n\n"  # before the upstream has finished
    Upstream.release.set()
    assert r.read() == b"data: [DONE]\n\n"


def test_an_unreachable_upstream_is_a_502(proxy):
    with socket.socket() as s:  # a port nothing listens on
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
    port, _ = proxy(LLM_AUTH_UPSTREAM=f"127.0.0.1:{dead}")
    assert _request(port, "GET", "/v1/models")[0] == 502


def _logged(capsys, *want: str) -> str:
    """The captured output once every `want` line is in it (llm-auth logs a
    request from its server thread after the client has the answer); fails
    after 5 s."""
    out, deadline = capsys.readouterr().out, time.time() + 5
    while not all(w in out for w in want) and time.time() < deadline:
        time.sleep(0.02)
        out += capsys.readouterr().out
    assert all(w in out for w in want), out
    return out


def test_logs_name_the_path_never_a_value(proxy, capsys):
    port, _ = proxy()
    _request(port, "GET", "/v1/models?limit=1000", headers={"Authorization": "Bearer glove-injected"})
    _request(port, "GET", "/v1/files")
    out = _logged(capsys, "llm-auth: GET /v1/models 200", "llm-auth: GET /v1/files 403")
    assert KEY not in out and "glove-injected" not in out and "limit" not in out


def test_an_empty_key_refuses_to_start():
    with pytest.raises(SystemExit, match="LLM_AUTH_KEY"):
        llm_auth.Config({"LLM_AUTH_KEY": "", "LLM_AUTH_UPSTREAM": "x:1", "LLM_AUTH_HOST": "x",
                         "LLM_AUTH_HEADER": "a", "LLM_AUTH_ALLOW": "[]"})


def _need_openssl():
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")


@pytest.fixture
def tls_upstream(tmp_path):
    """An HTTPS upstream for `api.example.com`, its certificate from llm-auth's
    own session CA recipe; returns (port, CA path)."""
    _need_openssl()
    d = tmp_path / "upstream-ca"
    d.mkdir()
    ctx = llm_auth.server_tls("api.example.com", str(d))
    Upstream.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    _serve(srv)
    yield srv.server_address[1], d / "ca.pem"
    srv.shutdown()


@pytest.mark.parametrize(("name", "status"), [("api.example.com", 200), ("other.example.com", 502)])
def test_tls_checks_the_providers_name(proxy, tls_upstream, name, status):
    up, ca = tls_upstream
    port, cfg = proxy(LLM_AUTH_UPSTREAM=f"127.0.0.1:{up}", LLM_AUTH_TLS_NAME=name)
    cfg.tls.load_verify_locations(ca)  # the image trusts its CA store; this test, its own CA
    assert _request(port, "GET", "/v1/models")[0] == status
    assert len(Upstream.seen) == (1 if status == 200 else 0)
    if status == 200:  # the next request resumes the session
        first = cfg.tls_session
        assert first is not None and _request(port, "GET", "/v1/models")[0] == 200
        assert cfg.tls_session.id == first.id


@pytest.fixture
def tls_proxy(proxy, tls_upstream, tmp_path, monkeypatch):
    """llm-auth serving TLS as api.example.com (and dialing it over TLS, as in
    a session); returns (port, CA dir, key dir)."""
    up, up_ca = tls_upstream
    keys, ca_dir = tmp_path / "tmpfs", tmp_path / "chan"
    keys.mkdir()
    ca_dir.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(keys))  # where its keys live while it starts
    port, cfg = proxy(LLM_AUTH_UPSTREAM=f"127.0.0.1:{up}", LLM_AUTH_SERVE_TLS="1",
                      LLM_AUTH_TLS_NAME="api.example.com", LLM_AUTH_CA_DIR=str(ca_dir))
    cfg.tls.load_verify_locations(up_ca)
    return port, ca_dir, keys


def _tls_get(port, ca, name="api.example.com"):
    ctx = ssl.create_default_context(cafile=str(ca))  # that CA only
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10), server_hostname=name)
    c.request("GET", "/v1/models", headers={"Authorization": "Bearer glove-injected"})
    r = c.getresponse()
    return r.status, r.read()


def test_it_serves_tls_as_the_providers_name_with_a_session_ca(tls_proxy):
    port, ca_dir, keys = tls_proxy
    assert sorted(p.name for p in ca_dir.iterdir()) == ["ca.pem"]
    assert oct((ca_dir / "ca.pem").stat().st_mode & 0o777) == "0o644"
    assert _tls_get(port, ca_dir / "ca.pem")[0] == 200
    assert Upstream.seen[-1][2]["authorization"] == f"Bearer {KEY}"
    assert list(keys.iterdir()) == []  # the CA key and the leaf key are gone


def test_the_session_ca_signs_only_that_name(tls_proxy):
    port, ca_dir, _ = tls_proxy
    text = subprocess.run(["openssl", "x509", "-noout", "-text", "-in", str(ca_dir / "ca.pem")],
                          capture_output=True, text=True, check=True).stdout
    assert "Name Constraints" in text and "DNS:api.example.com" in text and "pathlen:0" in text
    with pytest.raises(ssl.SSLCertVerificationError):
        _tls_get(port, ca_dir / "ca.pem", name="other.example.com")


def test_a_failed_handshake_is_logged_and_dropped(tls_proxy, capsys):
    port, _, _ = tls_proxy
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(b"GET /v1/models HTTP/1.1\r\nHost: x\r\n\r\n")  # plain HTTP to the TLS port
        with contextlib.suppress(ConnectionResetError):
            assert s.recv(65536) == b""  # closed, or reset: never an answer
    _logged(capsys, "tls handshake failed")
    assert Upstream.seen == []


def test_serving_tls_needs_a_name_and_a_ca_dir():
    with pytest.raises(SystemExit, match="LLM_AUTH_TLS_NAME and LLM_AUTH_CA_DIR"):
        llm_auth.Config({"LLM_AUTH_KEY": "k", "LLM_AUTH_UPSTREAM": "x:1", "LLM_AUTH_HOST": "x",
                         "LLM_AUTH_HEADER": "a", "LLM_AUTH_ALLOW": "[]", "LLM_AUTH_SERVE_TLS": "1"})
