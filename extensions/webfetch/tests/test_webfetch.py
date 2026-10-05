"""`webfetch`: Pi's web_fetch, and the fetch_url MCP sidecar (Vibe, Claude Code), through the egress provider."""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from helpers import make_cfg, render

from glove.extensions import ExtensionError, load_module
from glove.plan import build_session_plan


def _plan(tmp_path, exts, harness="pi"):
    cfg = make_cfg(harness=harness, name="s", workdir=str(tmp_path), extensions=exts)
    return build_session_plan(cfg, home_dir=str(tmp_path / "h"), state_dir=str(tmp_path / "x"))


def test_proxy_endpoint_targets_the_egress_proxy(tmp_path):
    plan = _plan(tmp_path, {"tor": {}, "webfetch": {}})
    assert plan.environment["GLOVE_FETCH_PROXY"] == "http://glove-s-proxy:8888"
    fwd = next(s for s in plan.network.sidecars if s.role == "proxy")
    assert fwd.target == "glove-s-privoxy:8118" and fwd.harness and fwd.networks == ("glove-s-egress",)
    assert "/opt/glove/ext/webfetch/pi-extension" in plan.command


def test_requires_egress(tmp_path):
    with pytest.raises(ExtensionError, match="requires the 'egress' slot"):
        _plan(tmp_path, {"webfetch": {}})


LOCAL_LLM = {"provider": "anthropic-compatible", "location": "host", "endpoint": "127.0.0.1:8080", "model": "m"}


@pytest.mark.parametrize("observe", [False, True])
def test_vibe_gets_fetch_url_from_a_sidecar(tmp_path, observe):
    exts = {"direct": {}, "webfetch": {}, **({"observe": {}} if observe else {})}
    cfg = make_cfg(harness="vibe", name="s", workdir=str(tmp_path), extensions=exts)
    plan, text = render(cfg, tmp_path)
    assert [s for _, s in plan.composition.mcp] == [
        {"name": "webfetch", "transport": "http", "url": "http://glove-s-webfetch-mcp:8000/mcp"}]
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
    assert fwd.harness and fwd.target == "glove-s-direct-proxy:8888"
    assert "WebFetch" in dict(plan.composition.rendered_briefs())["webfetch"]


def test_the_sidecar_image_is_hash_pinned():
    d = Path(__file__).resolve().parent.parent / "image"
    df = (d / "Dockerfile").read_text()
    assert "@sha256:" in df and "--require-hashes" in df
    assert (d / "requirements.txt").read_text() == (d.parents[1] / "search" / "image" / "requirements.txt").read_text()


def test_npm_dependencies_are_pinned_exactly():
    pkg = json.loads((Path(__file__).parents[1] / "pi-extension" / "package.json").read_text())
    for name, version in pkg["dependencies"].items():
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), (name, version)


# --- the fetch_url server (webfetch_mcp.py), without the MCP layer ------------------


def _server():
    return load_module(Path(__file__).parents[1] / "image" / "webfetch_mcp.py", "webfetch")


# the same table as guard.ts's behaviour (README "Destinations")
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


class _Proxy(BaseHTTPRequestHandler):
    """A forward proxy stand-in: answers absolute-URI GETs itself."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        routes = {
            "http://example.com/page": (200, "text/html", "<p>Example Domain</p>", {}),
            "http://example.com/hop": (302, "text/plain", "", {"Location": "/page"}),
            "http://example.com/evil": (302, "text/plain", "", {"Location": "http://169.254.169.254/"}),
            "http://example.com/loop": (302, "text/plain", "", {"Location": "/loop"}),
            "http://example.com/blocked": (403, "text/plain", "glove netgate refused: rule example", {}),
            "http://example.com/slow": (429, "text/plain", "", {}),
            "http://example.com/bogus-charset": (200, "text/html; charset=no-such-codec", "<p>café</p>", {}),
        }
        status, ctype, body, headers = routes.get(self.path, (404, "text/plain", "", {}))
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_CONNECT(self):
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


def test_fetch_asks_the_proxy_why_only_when_a_tunnel_is_refused(server, monkeypatch):
    assert server.fetch("https://blocked.example/").startswith(
        "Refused by this session's network policy for https://blocked.example/: glove netgate refused: rule tunnel")
    monkeypatch.setattr(server, "tunnel_refusal", lambda url: pytest.fail(f"probed {url}"))
    assert server.fetch("https://down.example/").startswith("Fetch failed for this URL (Tunnel connection failed: 502")


def test_fetch_falls_back_to_utf8_for_an_unknown_charset(server):
    assert server.fetch("http://example.com/bogus-charset").startswith("café")


def test_fetch_refuses_without_a_proxy_or_to_a_private_host(server, monkeypatch):
    assert server.fetch("http://10.0.0.1/").startswith("Refused: 10.0.0.1 is not a public address")
    monkeypatch.setattr(server, "PROXY", "")
    assert "not configured" in server.fetch("http://example.com/page")
