"""`webfetch`: the fetch_url MCP sidecar (Pi, Vibe) and Claude Code's own WebFetch, through the egress provider."""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
import yaml
from helpers import PEM, make_cfg, render

from glove.extensions import ExtensionError, load_module
from glove.plan import build_session_plan


def _plan(tmp_path, exts, harness="pi", session_dir=None):
    cfg = make_cfg(harness=harness, name="s", workdir=str(tmp_path), extensions=exts)
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"),
                              session_dir=session_dir)


def test_requires_egress(tmp_path):
    with pytest.raises(ExtensionError, match="requires the 'egress' slot"):
        _plan(tmp_path, {"webfetch": {}})


LOCAL_LLM = {"provider": "anthropic-compatible", "location": "host", "endpoint": "127.0.0.1:8080", "model": "m"}


@pytest.mark.parametrize("harness", ["pi", "vibe"])
@pytest.mark.parametrize("observe", [False, True])
def test_pi_and_vibe_get_fetch_url_from_a_sidecar(tmp_path, harness, observe):
    exts = {"direct": {}, "webfetch": {}, **({"observe": {}} if observe else {})}
    cfg = make_cfg(harness=harness, name="s", workdir=str(tmp_path), extensions=exts)
    plan, text = render(cfg, tmp_path)
    assert [s for _, s in plan.composition.mcp] == [
        {"name": "webfetch", "transport": "http", "url": "http://glove-s-webfetch-mcp:8000/mcp",
         "tools": ["fetch_url"]}]
    # the harness reaches the fetcher, never the egress proxy
    roles = {s.role for s in plan.network.sidecars if s.harness}
    assert "webfetch-mcp" in roles and "proxy" not in roles
    assert not any(k.startswith("GLOVE_FETCH") for k in plan.environment)
    svc = yaml.safe_load(text)["services"]["glove-s-fetcher"]
    assert svc["read_only"] is True and svc["cap_drop"] == ["ALL"]
    assert svc["environment"]["MCP_ALLOWED_HOST"] == "glove-s-webfetch-mcp:8000"
    if observe:  # only through the gate, labelled for Layman
        assert set(svc["networks"]) == {"glove-s-fetchnet"}
        assert svc["environment"]["GLOVE_FETCH_PROXY"] == "http://glove-s-webfetch-egress:8888"
        hop = next(s for s in plan.network.sidecars if s.role == "webfetch-egress")
        assert not hop.harness and hop.facts.get("client") == "webfetch"
    else:
        assert set(svc["networks"]) == {"glove-s-egress", "glove-s-fetchnet"}
        assert svc["environment"]["GLOVE_FETCH_PROXY"] == "http://glove-s-direct-proxy:8888"
    assert "webfetch" not in (plan.derived_dockerfile or "")


def test_claude_code_uses_its_own_webfetch_through_the_proxy_endpoint(tmp_path):
    cfg = make_cfg(harness="claude-code", name="s", workdir=str(tmp_path),
                   extensions={"direct": {}, "webfetch": {}, "llm": LOCAL_LLM})
    plan, text = render(cfg, tmp_path)
    assert plan.composition.mcp == [] and "glove-s-fetcher" not in yaml.safe_load(text)["services"]
    fwd = next(s for s in plan.network.sidecars if s.role == "proxy")
    assert fwd.harness and fwd.target == "glove-s-direct-proxy:8888" and fwd.networks == ("glove-s-egress",)
    assert "WebFetch" in dict(plan.composition.rendered_briefs())["webfetch"]


@pytest.mark.parametrize("harness", ["pi", "vibe", "claude-code"])
def test_downloads_put_the_fetcher_on_every_harness(tmp_path, harness):
    from glove.extensions import materialize

    (tmp_path / "work").mkdir()
    exts = {"direct": {}, "webfetch": {"downloads": "work"}, **({"llm": LOCAL_LLM} if harness == "claude-code" else {})}
    plan = _plan(tmp_path / "work", exts, harness, session_dir=str(tmp_path))
    comp = plan.composition
    assert {"webdownload-mcp", "webdownload-egress"} <= {e.name for e in comp.endpoints}
    assert comp.mcp[-1][1]["name"] == "webdownload"
    assert comp.mcp[-1][1]["tools"] == ["web_download", "web_download_status"]
    # written by the sidecar beside work/, read by the harness at /work/downloads
    mount = next(m for m in plan.mounts if m.container_path == "/work/downloads")
    assert (mount.host_path, mount.mode) == (str(tmp_path / "downloads"), "ro")
    materialize(comp)
    assert (tmp_path / "downloads").is_dir()


def test_downloads_need_a_session_dir_and_refuse_planted_links(tmp_path):
    from glove.extensions import ExtensionError, materialize
    from glove.mounts import MountError

    exts = {"direct": {}, "webfetch": {"downloads": "work"}}
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ExtensionError, match="needs a session directory"):
        _plan(work, exts)
    (work / "downloads").symlink_to(tmp_path)  # the mount point, where the agent writes
    with pytest.raises(MountError, match="not a symlink"):
        _plan(work, exts, session_dir=str(tmp_path))
    (work / "downloads").unlink()
    (tmp_path / "downloads").symlink_to(work)
    plan = _plan(work, exts, session_dir=str(tmp_path))
    with pytest.raises(MountError, match="not a symlink"):
        materialize(plan.composition)


def test_core_binds_the_downloads_output_into_the_fetcher_only(tmp_path):
    (tmp_path / "work").mkdir()
    cfg = make_cfg(name="s", workdir=str(tmp_path / "work"),
                   extensions={"direct": {}, "webfetch": {"downloads": "work"}})
    from glove.plan import build_session_plan
    from glove.runtimes.docker import DockerRuntime

    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"),
                              session_dir=str(tmp_path))
    doc = yaml.safe_load(DockerRuntime().render(plan, tmp_path / "st").compose_yaml)
    fetcher = doc["services"]["glove-s-fetcher"]
    assert fetcher["volumes"] == [{"type": "bind", "source": str(tmp_path / "downloads"),
                                   "target": "/run/glove-output/downloads"}]
    assert fetcher["environment"]["GLOVE_DOWNLOADS"] == "/run/glove-output/downloads"
    assert fetcher["environment"]["GLOVE_DOWNLOADS_SHOWN_AS"] == "/work/downloads"
    binding = {n for n, svc in doc["services"].items() if str(tmp_path / "downloads") in str(svc.get("volumes"))}
    assert binding == {"glove-s-fetcher", "glove-s-harness"}  # and the harness read-only


def test_the_fetcher_trusts_the_sessions_corporate_ca_read_only(tmp_path):
    from glove.cafile import CORPORATE_CA_PATH
    from glove.runtimes.docker import DockerRuntime

    (tmp_path / "work").mkdir()
    ca = tmp_path / "ca.pem"
    ca.write_text(PEM)
    cfg = make_cfg(name="s", workdir=str(tmp_path / "work"), corporate_ca=str(ca),
                   extensions={"direct": {}, "webfetch": {"downloads": "work"}})
    plan = build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"),
                              session_dir=str(tmp_path))
    fetcher = yaml.safe_load(DockerRuntime().render(plan, tmp_path / "st").compose_yaml)["services"]["glove-s-fetcher"]
    assert fetcher["environment"]["GLOVE_CORPORATE_CA"] == CORPORATE_CA_PATH
    assert sorted(v["target"] for v in fetcher["volumes"]) == [CORPORATE_CA_PATH, "/run/glove-output/downloads"]
    assert {"type": "bind", "source": str(ca.resolve()), "target": CORPORATE_CA_PATH,
            "read_only": True} in fetcher["volumes"]


def test_trust_corporate_ca_points_ssl_at_roots_then_the_ca(tmp_path, monkeypatch):
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    (tmp_path / "roots.pem").write_bytes(b"ROOTS\n")
    (tmp_path / "corp.pem").write_bytes(b"CORP")
    _server().trust_corporate_ca(str(tmp_path / "corp.pem"), dest=str(tmp_path / "b.pem"),
                                 roots=str(tmp_path / "roots.pem"))
    assert (tmp_path / "b.pem").read_bytes() == b"ROOTS\nCORP\n"
    import os

    assert os.environ["SSL_CERT_FILE"] == str(tmp_path / "b.pem")
    # the relay image's copy of the same step (two images, no shared code)
    relayd = load_module(Path(__file__).parents[2] / "relay" / "image" / "relayd.py", "relay")
    relayd.ca_bundle_env(str(tmp_path / "corp.pem"), dest=str(tmp_path / "r.pem"), roots=str(tmp_path / "roots.pem"))
    assert (tmp_path / "r.pem").read_bytes() == (tmp_path / "b.pem").read_bytes()
    assert _server().SYSTEM_ROOTS == relayd.SYSTEM_ROOTS


def test_downloads_off_render_no_downloader(tmp_path):
    names = {e.name for e in _plan(tmp_path, {"direct": {}, "webfetch": {}}).composition.endpoints}
    assert "webfetch-mcp" in names and not {"webdownload-mcp", "webdownload-egress"} & names


def test_the_sidecar_image_is_hash_pinned():
    d = Path(__file__).resolve().parent.parent / "image"
    df = (d / "Dockerfile").read_text()
    assert "@sha256:" in df and "--require-hashes" in df
    assert (d / "requirements.txt").read_text() == (d.parents[1] / "search" / "image" / "requirements.txt").read_text()


# --- the fetch_url server (webfetch_mcp.py), without the MCP layer ------------------


def _server():
    return load_module(Path(__file__).parents[1] / "image" / "webfetch_mcp.py", "webfetch")


# the guard's table (README "Destinations")
@pytest.mark.parametrize("url,ok", [
    ("https://example.com/x", True), ("http://93.184.215.14/", True), ("http://[2606:4700::1111]/", True),
    ("ftp://example.com/", False), ("https://u:p@example.com/", False),
    ("http://127.0.0.1/", False), ("http://10.1.2.3/", False), ("http://172.20.0.1/", False),
    ("http://192.168.1.1/", False), ("http://169.254.169.254/latest/meta-data/", False),
    ("http://100.64.0.1/", False), ("http://224.0.0.1/", False), ("http://198.18.0.1/", False),
    ("http://[::1]/", False), ("http://[fd00::1]/", False), ("http://[fe80::1]/", False),
    ("http://[::ffff:10.0.0.1]/", False), ("http://localhost:8080/", False), ("http://intranet/", False),
    ("http://host.docker.internal:8080/", False), ("http://printer.local/", False),
    ("http://nas.home.arpa/", False), ("http://example.com./", True),
    # IPv4 spelled other than as a dotted quad: Node's URL normalises it, urlsplit
    # does not, and the resolver behind the proxy (inet_aton) reads it as an address
    ("http://0xa.0.0.1/", False), ("http://012.0.0.1/", False), ("http://010.0.0.1/", False),
    ("http://127.1/", False), ("http://10.1/", False), ("http://2130706433/", False), ("http://0x8.8.8.8/", False),
    # IPv6 is judged compressed, IPv4-mapped as IPv4
    ("http://[0:0:0:0:0:0:0:1]/", False), ("http://[::ffff:a00:1]/", False), ("http://[FD00::1]/", False),
    ("http://[::ffff:8.8.8.8]/", True), ("http://[::ffff:808:808]/", True),
])
def test_guard(url, ok):
    assert (_server().refusal(url, []) is None) is ok


def test_guard_corporate_allowlist():
    m = _server()
    allow = ["*.corp.example", "10.20.0.0/16"]
    assert m.refusal("https://git.corp.example/", allow) is None
    assert m.refusal("http://10.20.3.4/", allow) is None
    assert m.refusal("http://10.21.3.4/", allow) == "10.21.3.4 is not a public address"
    assert m.refusal("http://0xa.20.3.4/", allow) == "0xa.20.3.4 is an IP address in a non-standard form"
    # this machine and metadata stay refused whatever the list says
    assert "this machine" in m.refusal("http://localhost/", ["localhost"])
    assert "not a reachable address" in m.refusal("http://169.254.169.254/", ["169.254.0.0/16"])


def test_html_to_text():
    html = ("<html><head><title>t</title><style>x{}</style></head><body><nav>menu</nav><h1>Title</h1>"
            "<p>One &amp; two</p><script>evil()</script><ul><li>a</li><li>b</li></ul></body></html>")
    assert _server().html_to_text(html) == "Title\n\nOne & two\n\na\n\nb"


PDF = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"1 0 obj << >> endobj\n" * 400
ZIP = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + bytes(range(256)) * 40


class _Proxy(BaseHTTPRequestHandler):
    """A forward proxy stand-in: answers absolute-URI GETs itself."""

    seen: ClassVar[list[str]] = []  # request lines, in order

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.seen.append(self.requestline)
        routes = {
            "http://example.com/page": (200, "text/html", "<p>Example Domain</p>", {}),
            "http://example.com/hop": (302, "text/plain", "", {"Location": "/page"}),
            "http://example.com/evil": (302, "text/plain", "", {"Location": "http://169.254.169.254/"}),
            "http://example.com/loop": (302, "text/plain", "", {"Location": "/loop"}),
            "http://example.com/blocked": (403, "text/plain", "glove netgate refused: rule example", {}),
            "http://example.com/slow": (429, "text/plain", "", {}),
            "http://example.com/slower": (429, "text/plain", "", {"Retry-After": "120"}),
            "http://example.com/paper.pdf": (200, "application/pdf", PDF, {}),
            "http://example.com/a.zip": (200, "application/zip", ZIP, {}),
            "http://example.com/blob": (200, "application/octet-stream", ZIP, {}),
            "http://example.com/mislabelled": (200, "application/octet-stream", "<p>Plain page</p>", {}),
            "http://example.com/data.json": (200, "application/json", '{"a": 1}', {}),
            "http://example.com/nul.txt": (200, "text/plain", "a\0b", {}),
            "http://example.com/bogus-charset": (200, "text/html; charset=no-such-codec", "<p>café</p>", {}),
        }
        status, ctype, body, headers = routes.get(self.path, (404, "text/plain", "", {}))
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_CONNECT(self):
        self.seen.append(self.requestline)
        # The gate refuses a tunnel with 403 and a reason; anything else is a network failure.
        refused = self.path.startswith("blocked.example:")
        data = b"glove netgate refused: rule tunnel" if refused else b""
        self.send_response(403 if refused else 502)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def server(monkeypatch):
    _Proxy.seen.clear()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Proxy)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    m = _server()
    monkeypatch.setattr(m, "PROXY", f"http://127.0.0.1:{httpd.server_address[1]}")
    yield m
    httpd.shutdown()


def test_fetch_through_the_proxy_follows_redirects_through_the_guard(server):
    out = server.fetch("http://example.com/hop")
    assert out.startswith("Example Domain") and "[fetched: http://example.com/page | text/html | via egress]" in out
    assert server.fetch("http://example.com/evil") == \
        "Refused a redirect to http://169.254.169.254/: 169.254.169.254 is not a public address."
    assert server.fetch("http://example.com/loop") == "Too many redirects from http://example.com/loop"


def test_fetch_reports_policy_refusals_and_rate_limits(server):
    assert server.fetch("http://example.com/blocked").startswith(
        "Refused by this session's network policy for http://example.com/blocked: glove netgate refused")
    assert server.fetch("http://example.com/slow").startswith("Rate-limited (HTTP 429)")
    assert server.fetch("http://example.com/missing") == "HTTP 404 for http://example.com/missing"
    assert server.fetch("http://example.com/page", max_chars=5).startswith("Examp\n\n[truncated to 5 chars]")


def test_fetch_sends_plain_http_unwrapped(server):
    # an http:// URL goes to the proxy as an absolute-form request, never a CONNECT
    # tunnel to port 80, and a refusal of it is the gate's own 403 answer
    assert server.fetch("http://example.com/blocked").startswith("Refused by this session's network policy")
    assert _Proxy.seen == ["GET http://example.com/blocked HTTP/1.1"]


def test_fetch_tells_the_server_s_retry_after(server):
    assert server.fetch("http://example.com/slower") == \
        "Rate-limited (HTTP 429). Back off; the server asks to wait 120 s before retrying."
    assert server.rate_limited("Wed, 21 Oct 2015 07:28:00 GMT", now=1445412420) == \
        "Rate-limited (HTTP 429). Back off; the server asks to wait 60 s before retrying."
    assert server.rate_limited("soon").endswith("do not retry immediately.")


def test_fetch_returns_no_binary_body(server, monkeypatch):
    out = server.fetch("http://example.com/paper.pdf", raw=True)
    assert out == (f"[binary: application/pdf, {len(PDF)} bytes] http://example.com/paper.pdf\n"
                   "fetch_url returns text only. This session has no web_download: ask the operator to provide "
                   "this file.")
    assert server.fetch("http://example.com/a.zip").startswith(f"[binary: application/zip, {len(ZIP)} bytes]")
    # unlabelled: decided by a NUL in the first bytes, either way
    assert server.fetch("http://example.com/blob").startswith("[binary: application/octet-stream,")
    assert server.fetch("http://example.com/mislabelled").startswith(
        "[content-type: application/octet-stream]\n\n<p>Plain page</p>")
    assert server.fetch("http://example.com/nul.txt").startswith("[binary: text/plain, 3 bytes]")
    assert server.fetch("http://example.com/data.json").startswith('[content-type: application/json]\n\n{"a": 1}')
    monkeypatch.setattr(server, "DOWNLOADS", "/run/glove-output/downloads")
    assert server.fetch("http://example.com/a.zip").endswith(
        "fetch_url returns text only. Use web_download to save the file, then open it with a shell tool the "
        "session has (e.g. pdftotext, 7z).")


BODY_CASES = [
    ("text/html; charset=utf-8", b"<p>x</p>"), ("application/json", b"{}"), ("application/ld+json", b"{}"),
    ("image/svg+xml", b"<svg/>"), ("text/xml", b"<a/>"), ("application/javascript", b"x"),
    ("application/pdf", b"%PDF"), ("application/zip", b"PK"), ("image/png", b""), ("", b"plain"),
    ("", b"a\0b"), ("application/octet-stream", b"<html>"), ("APPLICATION/OCTET-STREAM", PDF[:10] + b"\0"),
    ("text/plain", b"x" * 4096 + b"\0"), ("text/plain", b"x" * 4095 + b"\0"), ("video/mp4", b"x"),
    ("application/yaml", b"a: 1"), ("application/x-ndjson", b"{}"), ("application/vnd.oai.openapi+yaml", b"a"),
    ("application/x-sh", b"echo"), ("application/x-tar", b"x"),
]
RETRY_CASES = [None, "", "0", "120", "-5", "1.5", "soon", "2015", "Wed, 21 Oct 2015 07:28:00 GMT",
               "Wed, 21 Oct 2015 07:26:00 GMT", "Wed, 32 Oct 2015 07:28:00 GMT", "21 Oct 2015 07:28:00 GMT",
               "Sat, 31 Feb 2015 07:28:00 GMT", "Thu, 21 Oct 2015 07:28:00 GMT"]


def test_body_rules():
    m = _server()
    assert [m.is_binary(c, h) for c, h in BODY_CASES] == [
        False, False, False, False, False, False, True, True, True, False,
        True, False, True, False, True, True, False, False, False, False, True]
    assert m.binary_notice("t", "u", "image/png", None, 0, False).startswith("[binary: image/png, size unknown] u")

    def wait(n):
        return "do not retry immediately." if n is None else f"the server asks to wait {n} s before retrying."

    assert [m.rate_limited(r, now=1445412420).split("; ")[1] for r in RETRY_CASES] == \
        [wait(n) for n in (None, None, 0, 120, None, None, None, 2015, 60, 0, None, None, None, None)]


def test_fetch_asks_the_proxy_why_only_when_a_tunnel_is_refused(server, monkeypatch):
    assert server.fetch("https://blocked.example/").startswith(
        "Refused by this session's network policy for https://blocked.example/: glove netgate refused: rule tunnel")
    monkeypatch.setattr(server, "tunnel_refusal", lambda url, proxy: pytest.fail(f"probed {url}"))
    assert server.fetch("https://down.example/").startswith("Fetch failed for this URL (Tunnel connection failed: 502")


def test_fetch_falls_back_to_utf8_for_an_unknown_charset(server):
    assert server.fetch("http://example.com/bogus-charset").startswith("café")


def test_fetch_refuses_without_a_proxy_or_to_a_private_host(server, monkeypatch):
    assert server.fetch("http://10.0.0.1/").startswith("Refused: 10.0.0.1 is not a public address")
    monkeypatch.setattr(server, "PROXY", "")
    assert "not configured" in server.fetch("http://example.com/page")


# --- web_download (the sidecar's job manager) --------------------------------------

BLOB = bytes(range(256)) * 4096  # 1 MiB


class _Files(BaseHTTPRequestHandler):
    """A forward proxy serving files: `?cut=N` sends only N bytes of the first
    response for a URL (then closes), `?noranges` turns byte ranges off,
    `?shrunk` answers a range with 416, `?cd=<name>` sets Content-Disposition,
    `/hold` waits for `release`."""

    seen: ClassVar[list] = []
    cut: ClassVar[set] = set()  # URLs already cut once
    release = threading.Event()

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        rng, if_range = self.headers.get("Range"), self.headers.get("If-Range")
        type(self).seen.append((u.path, rng, if_range))
        if u.path in ("/hop", "/evil"):
            self.send_response(302)
            self.send_header("Location", "/file.bin" if u.path == "/hop" else "http://169.254.169.254/x")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if u.path == "/hold":
            type(self).release.wait(10)
        if rng and "shrunk" in q:
            self.send_response(416)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        ranges = "noranges" not in q
        start = int(rng.split("=")[1].rstrip("-")) if rng and ranges and if_range == '"v1"' else 0
        body = BLOB[start:]
        self.send_response(206 if start else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        if start:
            self.send_header("Content-Range", f"bytes {start}-{len(BLOB) - 1}/{len(BLOB)}")
        if ranges:
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", '"v1"')
        if "cd" in q:
            self.send_header("Content-Disposition", f'attachment; filename="{q["cd"][0]}"')
        self.end_headers()
        cut = int(q["cut"][0]) if "cut" in q and self.path not in type(self).cut else 0
        type(self).cut.add(self.path)
        self.wfile.write(body[:cut] if cut else body)


@pytest.fixture
def dl(tmp_path, monkeypatch):
    _Files.seen, _Files.cut = [], set()
    _Files.release = threading.Event()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Files)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    m = _server()
    (tmp_path / "dl").mkdir()
    monkeypatch.setattr(m, "DOWNLOADS", str(tmp_path / "dl"))
    monkeypatch.setattr(m, "DOWNLOAD_PROXY", f"http://127.0.0.1:{httpd.server_address[1]}")
    monkeypatch.setattr(m, "MIN_FREE", 0)
    yield m
    _Files.release.set()
    httpd.shutdown()


def _field(out: str, key: str) -> str:
    return re.search(rf"^{key}: (.*)$", out, re.M).group(1)


def test_safe_name():
    m = _server()
    assert m.safe_name("../../etc/passwd") == "passwd"
    assert m.safe_name("..\\x\\.bashrc") == "bashrc"
    assert m.safe_name("My File (1).pdf") == "My_File__1_.pdf"
    assert m.safe_name("...") == m.safe_name("") == "download"
    long = m.safe_name("a" * 300 + ".tar.gz")
    assert len(long) == 200 and long.endswith("a.gz")
    assert m.parse_size("2g") == 2 << 30 and m.parse_size("512M") == 512 << 20 and m.parse_size("10") == 10


def test_download_saves_follows_redirects_and_never_overwrites(dl, tmp_path):
    out = dl.download("http://example.com/hop")
    assert _field(out, "saved") == "/work/downloads/file.bin"
    assert _field(out, "sha256") == hashlib.sha256(BLOB).hexdigest()
    assert _field(out, "final_url") == "http://example.com/file.bin" and _field(out, "bytes") == str(len(BLOB))
    assert (tmp_path / "dl" / "file.bin").read_bytes() == BLOB
    # a second copy gets a new name; the server's name is sanitised; `name` wins
    assert _field(dl.download("http://example.com/file.bin"), "saved") == "/work/downloads/file-1.bin"
    out = dl.download("http://example.com/x?cd=../.bashrc")
    assert _field(out, "saved") == "/work/downloads/bashrc"
    assert _field(dl.download("http://example.com/x", name="a/b.iso"), "saved") == "/work/downloads/b.iso"
    assert sorted(os.listdir(tmp_path / "dl")) == ["b.iso", "bashrc", "file-1.bin", "file.bin"]


def test_download_guard_on_every_hop(dl):
    assert dl.download("http://10.0.0.1/x").startswith("Refused: 10.0.0.1 is not a public address")
    out = dl.download("http://example.com/evil")
    assert "failed: Refused a redirect to http://169.254.169.254/x" in out
    assert [p for p, _, _ in _Files.seen] == ["/evil"]


def test_download_never_writes_through_a_planted_link(dl, tmp_path):
    target = tmp_path / "home-file"
    target.write_text("keep")
    (tmp_path / "dl" / "file.bin.part").symlink_to(target)
    (tmp_path / "dl" / "file-1.bin").symlink_to(target)
    out = dl.download("http://example.com/file.bin")
    assert _field(out, "saved") == "/work/downloads/file-2.bin"
    assert target.read_text() == "keep" and (tmp_path / "dl" / "file-2.bin").read_bytes() == BLOB


def test_a_failed_download_drops_its_part_unless_it_can_resume(dl, tmp_path):
    out = dl.download("http://example.com/file.bin?noranges&cut=1000")
    assert "failed: the connection closed after 1000 B of 1.0 MiB" in out and "resume" not in out
    assert os.listdir(tmp_path / "dl") == []
    # with ranges the .part stays, and the same URL resumes it from where it stopped
    url = "http://example.com/file.bin?cut=300000"
    out = dl.download(url)
    assert "kept in /work/downloads/file.bin.part" in out
    assert (tmp_path / "dl" / "file.bin.part").stat().st_size == 300000
    out = dl.download(url)
    assert _field(out, "sha256") == hashlib.sha256(BLOB).hexdigest()
    assert _Files.seen[-1] == ("/file.bin", "bytes=300000-", '"v1"')
    assert os.listdir(tmp_path / "dl") == ["file.bin"]


def test_a_resume_starts_over_when_the_part_was_replaced(dl, tmp_path):
    url = "http://example.com/file.bin?cut=300000"
    dl.download(url)
    part = tmp_path / "dl" / "file.bin.part"
    part.unlink()
    part.write_bytes(b"planted")
    out = dl.download(url)  # a fresh download, under a new name
    assert _field(out, "saved") == "/work/downloads/file-1.bin"
    assert _Files.seen[-1][1] is None and part.read_bytes() == b"planted"


def test_a_resume_refused_with_416_starts_over(dl, tmp_path):
    url = "http://example.com/file.bin?cut=300000&shrunk"
    assert "call web_download with the same URL to resume" in dl.download(url)
    out = dl.download(url)
    assert _field(out, "sha256") == hashlib.sha256(BLOB).hexdigest()
    assert [r for _, r, _ in _Files.seen] == [None, "bytes=300000-", None]


def test_download_keeps_the_free_space_reserve(dl, tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "MIN_FREE", 1 << 60)
    out = dl.download("http://example.com/file.bin")
    assert "would leave less than the 2g free-space reserve" in out
    assert os.listdir(tmp_path / "dl") == []


def test_downloads_run_in_the_background_three_at_a_time(dl, tmp_path):
    outs = [dl.download(f"http://example.com/hold?{i}", name=f"h{i}", wait_s=0) for i in range(3)]
    assert all(o.startswith(f"started: d{i + 1} ") for i, o in enumerate(outs))
    assert dl.download("http://example.com/file.bin").startswith("3 downloads are already running")
    _Files.release.set()
    for _ in range(100):
        if all(j.state == "done" for j in dl._jobs):
            break
        time.sleep(0.05)
    status = dl.status()
    assert status.count("saved: /work/downloads/h") == 3
    assert dl.status("d2").startswith("saved: /work/downloads/h1") and dl.status("d9") == "No download d9."


def test_download_is_off_without_its_settings(dl, monkeypatch):
    monkeypatch.setattr(dl, "DOWNLOADS", "")
    assert "not configured" in dl.download("http://example.com/file.bin")
