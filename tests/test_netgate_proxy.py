"""netgate M2: http-proxy mode, chain: upstream, SNI peek, SSRF guard.

In-process with real sockets. A stub upstream HTTP proxy stands in for
gluetun/privoxy. It records every request line it receives and maps
destination names to a local origin itself, so it performs no DNS either. Every
test runs with the host resolver booby-trapped: the gate must never resolve the
agent's destination (invariant 4) — it only ever passes it upstream as text.
"""

from __future__ import annotations

import asyncio
import os
import socket
import ssl

import pytest

from glove.netgate import guard, httpproxy, sni
from glove.netgate.forward import EventSink, Forwarder, ForwardSpec


def run(coro, timeout: float = 20.0):
    return asyncio.run(asyncio.wait_for(coro, timeout))


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    def boom(*a, **k):
        raise AssertionError(f"DNS lookup attempted: {a!r}")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo", "getfqdn"):
        monkeypatch.setattr(socket, name, boom)


def client_hello(server_name: str) -> bytes:
    """A real ClientHello from the ssl module, generated in memory."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    out = ssl.MemoryBIO()
    obj = ctx.wrap_bio(ssl.MemoryBIO(), out, server_hostname=server_name)
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    return out.read()


# --- SNI ---------------------------------------------------------------------


def test_sni_from_a_real_client_hello():
    hello = client_hello("En.Wikipedia.org")
    assert sni.is_tls_handshake(hello)
    assert sni.record_length(hello) == len(hello)
    assert sni.parse_sni(hello) == "en.wikipedia.org"


def test_sni_absent_for_ip_and_garbage():
    assert sni.parse_sni(client_hello("192.0.2.1")) is None  # no SNI for IP literals
    assert sni.parse_sni(b"GET / HTTP/1.1\r\n\r\n") is None
    hello = client_hello("example.com")
    for cut in (3, 10, 60, len(hello) - 3):
        assert sni.parse_sni(hello[:cut]) in (None, "example.com")  # truncated never raises
    assert sni.parse_sni(os.urandom(4096)) is None


# --- guard -------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254", "127.0.0.1", "10.1.2.3", "192.168.0.1", "172.31.0.5", "100.64.0.1",
        "0.0.0.0", "::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1",
        "2130706433", "0x7f.1", "0177.0.0.1", "127.1",
        "localhost", "gluetun", "egress-proxy", "glove-pi-search-llm", "searxng",
        "host.docker.internal", "metadata.google.internal", "printer.local", "x.localhost", "nas.home.arpa",
    ],
)
def test_guard_refuses_non_public_destinations(host):
    norm = guard.normalize_host(host)
    assert norm is not None
    reason, is_local = guard.check(norm)
    assert reason is not None and is_local


@pytest.mark.parametrize(
    "host", ["en.wikipedia.org", "EXAMPLE.com.", "1.1.1.1", "2606:4700:4700::1111", "xn--bcher-kva.example"]
)
def test_guard_allows_public_destinations(host):
    assert guard.check(guard.normalize_host(host)) == (None, False)


@pytest.mark.parametrize("host", ["", "a b.com", "evil.com\r\nX: y", "a..b", "-bad.com", "x" * 300, "ex@mple.com"])
def test_normalize_rejects_ambiguous_hosts(host):
    assert guard.normalize_host(host) is None


# --- request parsing ---------------------------------------------------------


def test_parse_connect():
    r = httpproxy.parse_request_head(b"CONNECT En.Wikipedia.org:443 HTTP/1.1\r\nHost: x\r\n\r\n")
    assert (r.host, r.port, r.proto) == ("en.wikipedia.org", 443, "http-connect")
    assert r.upstream_head == b"CONNECT en.wikipedia.org:443 HTTP/1.1\r\nHost: en.wikipedia.org:443\r\n\r\n"


def test_parse_connect_ipv6_and_mapped():
    r = httpproxy.parse_request_head(b"CONNECT [::ffff:127.0.0.1]:80 HTTP/1.1\r\n\r\n")
    assert r.host == "127.0.0.1"  # normalised, so the guard sees the real address


def test_absolute_form_is_reserialised_with_connection_close():
    head = (b"GET http://Example.COM/a/b?q=1 HTTP/1.1\r\nHost: evil.internal\r\n"
            b"Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n")
    r = httpproxy.parse_request_head(head)
    assert (r.host, r.port, r.proto) == ("example.com", 80, "http")
    assert r.upstream_head == (b"GET http://example.com:80/a/b?q=1 HTTP/1.1\r\nHost: example.com:80\r\n"
                               b"Accept: */*\r\nConnection: close\r\n\r\n")


@pytest.mark.parametrize(
    "head",
    [
        b"GET /origin-form HTTP/1.1\r\n\r\n",
        b"GET http://user@evil.com/ HTTP/1.1\r\n\r\n",
        b"GET http://a.com\\@127.0.0.1/ HTTP/1.1\r\n\r\n",
        b"CONNECT example.com HTTP/1.1\r\n\r\n",
        b"CONNECT example.com:99999 HTTP/1.1\r\n\r\n",
        b"BREW http://example.com/ HTTP/1.1\r\n\r\n",
        b"GET ftp://example.com/ HTTP/1.1\r\n\r\n",
        b"GET http://example.com/ HTTP/2\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\n folded: header\r\n\r\n",
        "GET http://exämple.com/ HTTP/1.1\r\n\r\n".encode(),
    ],
)
def test_parse_rejects(head):
    with pytest.raises(httpproxy.BadRequest):
        httpproxy.parse_request_head(head)


# --- end to end ----------------------------------------------------------------


class StubUpstreamProxy:
    """A minimal HTTP proxy standing in for gluetun: CONNECT + absolute-form.
    Resolves destination names from a fixed table (no DNS), logs request heads."""

    def __init__(self, table: dict[str, int], *, connect_status: int = 200):
        self.table = table
        self.connect_status = connect_status
        self.heads: list[bytes] = []

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        self.heads.append(head)
        line = head.split(b"\r\n", 1)[0].decode()
        method, target, _ = line.split(" ")
        if method == "CONNECT":
            host = target.rsplit(":", 1)[0]
            if self.connect_status != 200 or host not in self.table:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            o_r, o_w = await asyncio.open_connection("127.0.0.1", self.table[host])
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
        else:
            host = target.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[0]
            o_r, o_w = await asyncio.open_connection("127.0.0.1", self.table[host])
            path = "/" + target.split("://", 1)[1].split("/", 1)[1]
            o_w.write(head.replace(target.encode(), path.encode(), 1))

        async def pipe(a, b):
            try:
                while data := await a.read(65536):
                    b.write(data)
                    await b.drain()
            finally:
                if b.can_write_eof():
                    b.write_eof()

        await asyncio.gather(pipe(reader, o_w), pipe(o_r, writer), return_exceptions=True)
        writer.close()
        o_w.close()


async def _origin(body: bytes):
    """Origin: answers any HTTP request with `body`; echoes raw bytes otherwise."""

    async def handle(reader, writer):
        first = await reader.read(65536)
        if first.startswith((b"GET ", b"POST ")):
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        else:
            writer.write(first + body)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def _proxy_spec(upstream_port: int, route: str = "vpn") -> ForwardSpec:
    return ForwardSpec(service="proxy", listen_port=0, upstream_host="127.0.0.1", upstream_port=upstream_port,
                       env="pi-search", session="pi-search", tool="web_fetch", listen_host="127.0.0.1",
                       mode="http-proxy", route_kind=route)


class Captured(EventSink):
    """Records the gate would send; gate lifecycle records go to ``gates``."""

    def __init__(self):
        super().__init__(None)
        self.records: list[dict] = []
        self.gates: list[dict] = []

    def send(self, record):
        (self.gates if record.get("type") == "gate" else self.records).append(record)
        return True


async def _exchange(port: int, data: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(data)
    await w.drain()
    out = await r.read()
    w.close()
    return out


def _proxy_run(scenario, *, route="vpn", connect_status=200, table_names=("www.origin.test",), body=b"B" * 70_000):
    async def main():
        origin, oport = await _origin(body)
        up = StubUpstreamProxy(dict.fromkeys(table_names, oport), connect_status=connect_status)
        await up.start()
        sink = Captured()
        fwd = Forwarder(_proxy_spec(up.port, route), sink)
        await fwd.start()
        result = await scenario(fwd.port)
        await asyncio.sleep(0.05)
        await fwd.stop()
        origin.close()
        up.server.close()
        return result, sink.records, up.heads

    return run(main())


def test_connect_tunnel_records_hostname_tool_scope_and_exact_bytes():
    hello = client_hello("www.origin.test")
    req = b"CONNECT www.origin.test:443 HTTP/1.1\r\nHost: www.origin.test:443\r\n\r\n"
    out, recs, heads = _proxy_run(lambda p: _exchange(p, req + hello))
    assert out.startswith(b"HTTP/1.1 200 Connection established\r\n\r\n" + hello)  # tunnel is byte-transparent
    assert heads == [b"CONNECT www.origin.test:443 HTTP/1.1\r\nHost: www.origin.test:443\r\n\r\n"]
    close = recs[-1]
    assert (recs[0]["phase"], close["phase"]) == ("open", "close")
    assert close["proto"] == "http-connect" and close["tool"] == "web_fetch"
    assert close["dest"] == {"host": "www.origin.test", "port": 443, "ip": None, "resolution": "unavailable"}
    assert close["scope"] == "tunnelled"
    assert close["route"]["kind"] == "vpn" and close["route"]["upstream"].startswith("http://127.0.0.1:")
    assert close["verdict"] == "allow" and close["close_reason"] == "eof"
    assert close["bytes"] == {"up": len(req) + len(hello), "down": len(out)}
    assert recs[0]["dest"]["host"] == "www.origin.test"  # known from the open onward


def test_absolute_form_get_is_canonicalised_upstream():
    req = (b"GET http://WWW.origin.test:80/page?x=1 HTTP/1.1\r\nHost: www.origin.test\r\n"
           b"Proxy-Connection: keep-alive\r\nUser-Agent: t\r\n\r\n")
    out, recs, heads = _proxy_run(lambda p: _exchange(p, req), body=b"hello")
    assert out.endswith(b"\r\n\r\nhello")
    assert heads == [b"GET http://www.origin.test:80/page?x=1 HTTP/1.1\r\nHost: www.origin.test:80\r\n"
                     b"User-Agent: t\r\nConnection: close\r\n\r\n"]
    assert recs[-1]["proto"] == "http" and recs[-1]["dest"]["port"] == 80
    assert recs[-1]["bytes"] == {"up": len(req), "down": len(out)}


@pytest.mark.parametrize(
    "target",
    ["169.254.169.254:80", "127.0.0.1:8000", "2130706433:80", "[::1]:80", "localhost:80",
     "gluetun:8000", "egress-proxy:8888", "host.docker.internal:8080"],
)
def test_ssrf_guard_blocks_before_anything_goes_upstream(target):
    req = f"CONNECT {target} HTTP/1.1\r\n\r\n".encode()
    out, recs, heads = _proxy_run(lambda p: _exchange(p, req))
    assert out.startswith(b"HTTP/1.1 403 Forbidden")
    assert heads == []  # the upstream never heard of it
    assert [r["phase"] for r in recs] == ["open", "close"]
    for r in recs:
        assert r["verdict"] == "block" and r["rule"] == "builtin:ssrf-guard" and r["scope"] == "local"
    assert recs[-1]["close_reason"] == "blocked"
    assert recs[-1]["bytes"] == {"up": len(req), "down": len(out)}


def test_truncated_request_is_malformed():
    async def main():
        up = StubUpstreamProxy({})
        await up.start()
        sink = Captured()
        fwd = Forwarder(_proxy_spec(up.port), sink)
        await fwd.start()
        r, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        w.write(b"CONNECT half")
        w.write_eof()  # a partial head, then EOF
        out = await r.read()
        w.close()
        await fwd.stop()
        return out, sink.records

    out, recs = run(main())
    assert out.startswith(b"HTTP/1.1 400") and recs[-1]["rule"] == "builtin:malformed-request"


def test_malformed_request_is_blocked_and_recorded():
    out, recs, heads = _proxy_run(lambda p: _exchange(p, b"GET /not-a-proxy-request HTTP/1.1\r\n\r\n"))
    assert out.startswith(b"HTTP/1.1 400 Bad Request") and heads == []
    assert recs[-1]["verdict"] == "block" and recs[-1]["rule"] == "builtin:malformed-request"
    assert recs[-1]["dest"]["host"] is None and recs[-1]["close_reason"] == "blocked"
    assert {r["scope"] for r in recs} == {"local"}  # nothing left the gate: never "tunnelled"


def test_upstream_refusal_is_upstream_unreachable_not_blocked():
    req = b"CONNECT www.origin.test:443 HTTP/1.1\r\n\r\n"
    out, recs, _ = _proxy_run(lambda p: _exchange(p, req), connect_status=502)
    assert out.startswith(b"HTTP/1.1 502")  # the upstream's answer is passed through
    assert recs[-1]["verdict"] == "allow" and recs[-1]["close_reason"] == "upstream_unreachable"


def test_dead_upstream_proxy_returns_502():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()

    async def main():
        sink = Captured()
        fwd = Forwarder(_proxy_spec(dead), sink)
        await fwd.start()
        out = await _exchange(fwd.port, b"CONNECT www.origin.test:443 HTTP/1.1\r\n\r\n")
        await fwd.stop()
        return out, sink.records

    out, recs = run(main())
    assert out.startswith(b"HTTP/1.1 502")
    assert recs[-1]["close_reason"] == "upstream_unreachable" and recs[-1]["dest"]["host"] == "www.origin.test"


def test_direct_route_marks_flows_direct():
    req = b"CONNECT www.origin.test:443 HTTP/1.1\r\n\r\n"
    _, recs, _ = _proxy_run(lambda p: _exchange(p, req + b"x"), route="direct")
    assert {r["scope"] for r in recs} == {"direct"}
    assert recs[-1]["route"]["kind"] == "direct"


def test_empty_connection_is_eof_not_a_block():
    async def main():
        up = StubUpstreamProxy({})
        await up.start()
        sink = Captured()
        fwd = Forwarder(_proxy_spec(up.port), sink)
        await fwd.start()
        _, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        w.close()  # connect, send nothing, leave
        await asyncio.sleep(0.1)
        await fwd.stop()
        return sink.records

    recs = run(main())
    assert recs[-1]["close_reason"] == "eof" and recs[-1]["verdict"] == "allow" and recs[-1]["rule"] is None
    assert recs[-1]["dest"]["host"] is None and recs[-1]["scope"] == "local"


def test_slowloris_head_times_out():
    async def main():
        up = StubUpstreamProxy({})
        await up.start()
        sink = Captured()
        fwd = Forwarder(_proxy_spec(up.port), sink, head_timeout=0.2)
        await fwd.start()
        r, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        w.write(b"CONNECT www.origin")
        out = await r.read()
        w.close()
        await fwd.stop()
        return out, sink.records, up.heads

    out, recs, heads = run(main())
    assert out == b"" and heads == []  # closed without an answer; nothing reached the upstream
    assert recs[-1]["close_reason"] == "timeout" and recs[-1]["verdict"] == "allow"


# --- tcp mode SNI peek ---------------------------------------------------------


def _tcp_run(payload: bytes, **spec_kw):
    async def main():
        async def echo(reader, writer):
            data = await reader.readexactly(len(payload))
            writer.write(data)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        sink = Captured()
        spec = ForwardSpec(service="llm", listen_port=0, upstream_host="127.0.0.1",
                           upstream_port=server.sockets[0].getsockname()[1], env="e", session="e",
                           listen_host="127.0.0.1", **spec_kw)
        fwd = Forwarder(spec, sink)
        await fwd.start()
        out = await _exchange(fwd.port, payload)
        await asyncio.sleep(0.05)
        await fwd.stop()
        server.close()
        return out, sink.records

    return run(main())


def test_tcp_mode_takes_dest_host_from_sni_and_forwards_unmodified():
    hello = client_hello("api.llm-provider.example")
    out, recs = _tcp_run(hello)
    assert out == hello
    assert recs[0]["phase"] == "open" and recs[0]["dest"]["host"] == "api.llm-provider.example"
    assert recs[-1]["dest"]["port"] == recs[0]["dest"]["port"]
    assert recs[-1]["bytes"] == {"up": len(hello), "down": len(hello)}


def test_tcp_mode_reassembles_a_split_client_hello():
    hello = client_hello("split.example")

    async def main():
        async def echo(reader, writer):
            data = await reader.readexactly(len(hello))
            writer.write(data)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        sink = Captured()
        fwd = Forwarder(ForwardSpec(service="llm", listen_port=0, upstream_host="127.0.0.1",
                                    upstream_port=server.sockets[0].getsockname()[1], env="e", session="e",
                                    listen_host="127.0.0.1"), sink)
        await fwd.start()
        r, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        w.write(hello[:7])  # the record header + a sliver, then the rest later
        await w.drain()
        await asyncio.sleep(0.05)
        w.write(hello[7:])
        out = await r.read()
        w.close()
        await asyncio.sleep(0.05)
        await fwd.stop()
        server.close()
        return out, sink.records

    out, recs = run(main())
    assert out == hello
    assert recs[0]["dest"]["host"] == "split.example"


def test_tcp_mode_plaintext_keeps_the_configured_target():
    _, recs = _tcp_run(b"GET /v1/models HTTP/1.1\r\n\r\n")
    assert recs[0]["dest"]["host"] == "127.0.0.1" and recs[0]["dest"]["resolution"] == "literal"


def test_no_sni_flag_disables_the_peek():
    hello = client_hello("api.llm-provider.example")
    _, recs = _tcp_run(hello, sni=False)
    assert recs[0]["dest"]["host"] == "127.0.0.1"
