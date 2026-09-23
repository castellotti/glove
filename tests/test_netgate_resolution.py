"""netgate M4: in-tunnel resolution (DNS / Tor RESOLVE), rebinding refusal,
fail-closed behaviour, and exit-identity polling — in-process, no host DNS."""

from __future__ import annotations

import asyncio
import json
import socket
import struct

import pytest
from test_netgate_proxy import Captured, StubUpstreamProxy, _exchange, _origin, run

from glove.netgate import resolver as res
from glove.netgate.collector import Collector
from glove.netgate.exitid import ExitPoller, parse_echo
from glove.netgate.forward import Forwarder, ForwardSpec


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    """The host resolver is booby-trapped for every test here. Only IP literals
    (the stubs' 127.0.0.1) may be used — exactly as in the gate, where the only
    names handed to a system resolver are the configured resolver's own."""
    real = socket.getaddrinfo

    def guarded(host, *a, **k):
        if host not in ("127.0.0.1", None):
            raise AssertionError(f"DNS lookup attempted for {host!r}")
        return real(host, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", guarded)
    for name in ("gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo", "getfqdn"):
        monkeypatch.setattr(socket, name, lambda *a, **k: (_ for _ in ()).throw(AssertionError(a)))


def dns_answer(query: bytes, ips: list[str], *, ttl=60, tc=False, rcode=0) -> bytes:
    qid = query[:2]
    flags = 0x8180 | (0x0200 if tc else 0) | rcode
    head = qid + struct.pack(">HHHHH", flags, 1, len(ips), 0, 0)
    q = query[12:]
    ans = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip) for ip in ips)
    return head + q + ans


class StubDns(asyncio.DatagramProtocol):
    """UDP (and TCP, for truncation) DNS server answering from a table."""

    def __init__(self, table: dict[str, list[str]], *, truncate: bool = False):
        self.table, self.truncate, self.names = table, truncate, []

    def _name(self, q: bytes) -> str:
        i, labels = 12, []
        while q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode())
            i += 1 + q[i]
        return ".".join(labels)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        name = self._name(data)
        self.names.append(name)
        ips = self.table.get(name, [])
        self.transport.sendto(dns_answer(data, [] if self.truncate else ips, tc=self.truncate,
                                         rcode=0 if name in self.table else 3), addr)

    async def tcp(self, r, w):
        n = struct.unpack(">H", await r.readexactly(2))[0]
        q = await r.readexactly(n)
        reply = dns_answer(q, self.table.get(self._name(q), []))
        w.write(struct.pack(">H", len(reply)) + reply)
        await w.drain()
        w.close()


async def start_dns(table, **kw):
    loop = asyncio.get_running_loop()
    proto = StubDns(table, **kw)
    transport, _ = await loop.create_datagram_endpoint(lambda: proto, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    tcp = await asyncio.start_server(proto.tcp, "127.0.0.1", port)
    return proto, port, (transport, tcp)


def test_dns_resolver_udp_and_tcp_fallback():
    async def main():
        out = []
        for truncate in (False, True):
            _, port, (t, tcp) = await start_dns({"en.wikipedia.org": ["185.15.59.224"]}, truncate=truncate)
            r = res.DnsResolver("127.0.0.1", port)
            out.append(await r.lookup("en.wikipedia.org"))
            out.append(await r.lookup("nx.example"))
            t.close()
            tcp.close()
        return out

    assert [ip for ip, _ in run(main())] == ["185.15.59.224", None, "185.15.59.224", None]


def test_tor_socks_resolve():
    async def socks(r, w):
        assert await r.readexactly(3) == b"\x05\x01\x00"
        w.write(b"\x05\x00")
        head = await r.readexactly(5)
        assert head[:4] == b"\x05\xf0\x00\x03"
        name = (await r.readexactly(head[4])).decode()
        await r.readexactly(2)
        if name == "duckduckgo.com":
            w.write(b"\x05\x00\x00\x01" + socket.inet_aton("52.142.124.215") + b"\x00\x00")
        else:
            w.write(b"\x05\x04\x00\x01" + b"\x00" * 6)
        await w.drain()
        w.close()

    async def main():
        server = await asyncio.start_server(socks, "127.0.0.1", 0)
        r = res.TorSocksResolver("127.0.0.1", server.sockets[0].getsockname()[1])
        got = [await r.lookup("duckduckgo.com"), await r.lookup("nx.onion")]
        server.close()
        return got

    assert [ip for ip, _ in run(main())] == ["52.142.124.215", None]


def test_in_tunnel_caches_and_backs_off():
    class Flaky:
        source = "stub"
        calls = 0
        fail = False

        async def lookup(self, name):
            Flaky.calls += 1
            if Flaky.fail:
                raise OSError("down")
            return "93.184.216.34", 60

    now = [1000.0]
    t = res.InTunnel(Flaky(), clock=lambda: now[0])

    async def main():
        a = await t.resolve("example.com")
        b = await t.resolve("example.com")  # cached
        Flaky.fail = True
        now[0] += 120
        c = await t.resolve("example.com")  # expired, resolver down
        d = await t.resolve("other.example")  # backing off: no attempt at all
        now[0] += res.BACKOFF + 1
        Flaky.fail = False
        e = await t.resolve("other.example")
        return a, b, c, d, e

    a, b, c, d, e = run(main())
    assert (a, b, c, d, e) == ("93.184.216.34", "93.184.216.34", None, None, "93.184.216.34")
    assert Flaky.calls == 3 and t.healthy is True and t.failures == 1


@pytest.mark.parametrize(
    "url", ["https://x", "dns://gluetun", "dns://:53", "doh://x:1", "tor-socks://tor:x"]
)
def test_resolver_url_validation(url):
    with pytest.raises(ValueError):
        res.from_url(url)


# --- the gate with a resolver ------------------------------------------------------


def _gate(dns_port: int | None, upstream_port: int, sink, *, exit_url=None, policy=None) -> Forwarder:
    spec = ForwardSpec(service="proxy", listen_port=0, upstream_host="127.0.0.1", upstream_port=upstream_port,
                       env="pi-search", session="pi-search", tool="web_fetch", listen_host="127.0.0.1",
                       mode="http-proxy", route_kind="vpn",
                       resolver_url=f"dns://127.0.0.1:{dns_port}" if dns_port else None, exit_url=exit_url)
    return Forwarder(spec, sink, policy=policy)


def _session(table, scenario, *, resolver_alive=True, policy=None):
    async def main():
        proto, dns_port, (t, tcp) = await start_dns(table)
        if not resolver_alive:
            t.close()
            tcp.close()
        origin, oport = await _origin(b"B" * 100)
        up = StubUpstreamProxy({"good.example": oport, "rebind.example": oport, "nx.example": oport})
        await up.start()
        sink = Captured()
        fwd = _gate(dns_port, up.port, sink, policy=policy)
        await fwd.start()
        result = await scenario(fwd)
        await asyncio.sleep(0.05)
        await fwd.stop()
        for s in (origin, up.server):
            s.close()
        if resolver_alive:
            t.close()
            tcp.close()
        return result, sink.records, up.heads, proto.names

    return run(main())


def test_destination_gets_an_in_tunnel_ip():
    async def scenario(fwd):
        return await _exchange(fwd.port, b"CONNECT good.example:443 HTTP/1.1\r\n\r\nx")

    out, recs, heads, asked = _session({"good.example": ["93.184.216.34"]}, scenario)
    assert out.startswith(b"HTTP/1.1 200")
    assert asked == ["good.example"]  # asked the in-tunnel resolver, nobody else
    assert heads == [b"CONNECT good.example:443 HTTP/1.1\r\nHost: good.example:443\r\n\r\n"]  # still by name
    for r in (r for r in recs if r["type"] == "flow"):
        assert r["dest"] == {"host": "good.example", "port": 443, "ip": "93.184.216.34", "resolution": "in-tunnel"}
    health = [r for r in recs if r["type"] == "health"]
    assert health == [{"v": 1, "type": "health", "service": "proxy",
                       "resolver": {"source": f"dns://127.0.0.1:{health[0]['resolver']['source'].rsplit(':', 1)[1]}",
                                    "healthy": True}}]


def test_rebinding_to_a_private_address_is_refused():
    async def scenario(fwd):
        return await _exchange(fwd.port, b"CONNECT rebind.example:443 HTTP/1.1\r\n\r\n")

    out, recs, heads, _ = _session({"rebind.example": ["127.0.0.1"]}, scenario)
    assert out.startswith(b"HTTP/1.1 403") and b"resolves in-tunnel" in out
    assert heads == []  # refused before the upstream heard of it
    close = [r for r in recs if r.get("phase") == "close"][-1]
    assert close["rule"] == "builtin:ssrf-guard" and close["scope"] == "local"
    assert close["dest"]["ip"] == "127.0.0.1" and close["dest"]["resolution"] == "in-tunnel"


def test_resolver_down_fails_closed_to_unavailable_and_traffic_flows():
    async def scenario(fwd):
        return await _exchange(fwd.port, b"CONNECT good.example:443 HTTP/1.1\r\n\r\nx")

    out, recs, heads, _ = _session({}, scenario, resolver_alive=False)
    assert out.startswith(b"HTTP/1.1 200") and heads  # traffic unaffected
    flows = [r for r in recs if r["type"] == "flow"]
    assert all(r["dest"]["ip"] is None and r["dest"]["resolution"] == "unavailable" for r in flows)
    assert [r["resolver"]["healthy"] for r in recs if r["type"] == "health"] == [False]


def test_nxdomain_is_unavailable_not_an_error():
    async def scenario(fwd):
        return await _exchange(fwd.port, b"CONNECT nx.example:443 HTTP/1.1\r\n\r\nx")

    _, recs, _, _ = _session({}, scenario)
    flows = [r for r in recs if r["type"] == "flow"]
    assert flows[-1]["dest"]["resolution"] == "unavailable"


# --- exit identity --------------------------------------------------------------------


def test_parse_echo_shapes():
    assert parse_echo(b'{"ip":"195.177.93.1","country":"Switzerland","city":null,"latitude":47.36,"longitude":8.54}') \
        == {"ip": "195.177.93.1", "country": "Switzerland", "city": None, "lat": 47.36, "lon": 8.54}
    assert parse_echo(b'{"ip":"1.2.3.4","country":"NL","city":"Amsterdam","loc":"52.37,4.90"}')["lon"] == 4.9
    with pytest.raises(ValueError):
        parse_echo(b'{"country":"x"}')


def test_exit_poller_fetches_through_the_chain_and_emits_on_change():
    bodies = [b'{"ip":"195.177.93.1","country":"Switzerland","latitude":47.36,"longitude":8.54}',
              b'{"ip":"195.177.93.1","country":"Switzerland","latitude":47.36,"longitude":8.54}',
              b'{"ip":"198.51.100.7","country":"Netherlands","city":"Amsterdam","latitude":52.37,"longitude":4.9}']

    async def echo(r, w):
        await r.readuntil(b"\r\n\r\n")
        body = bodies.pop(0) if bodies else b"{}"
        w.write(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + body)
        await w.drain()
        w.close()

    async def main():
        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        up = StubUpstreamProxy({"am.i.mullvad.net": server.sockets[0].getsockname()[1]})
        await up.start()
        records = []
        poller = ExitPoller(url="https://am.i.mullvad.net/json", kind="vpn",
                            dial=lambda: asyncio.open_connection("127.0.0.1", up.port),
                            emit=records.append, env="pi-search", session="pi-search", tls=False)
        oks = [await poller.poll_once() for _ in range(4)]
        server.close()
        up.server.close()
        return oks, records, up.heads

    oks, records, heads = run(main())
    assert oks == [True, True, True, False]
    assert heads[0] == b"CONNECT am.i.mullvad.net:443 HTTP/1.1\r\nHost: am.i.mullvad.net:443\r\n\r\n"
    assert [(r["ip"], r["healthy"]) for r in records] == [
        ("195.177.93.1", True), ("198.51.100.7", True), (None, False)]  # unchanged poll: no record
    assert records[0]["source"] == "via-proxy:am.i.mullvad.net" and records[0]["kind"] == "vpn"


def test_collector_writes_exit_ndjson_and_resolver_health(tmp_path):
    (tmp_path / "session.json").write_text(json.dumps({"env": "pi-search", "session": "pi-search"}))
    c = Collector(tmp_path, "/tmp/unused.sock")
    c.ingest(json.dumps({"v": 1, "type": "exit", "ip": "198.51.100.7", "healthy": True}).encode())
    c.ingest(json.dumps({"v": 1, "type": "health", "service": "proxy",
                         "resolver": {"source": "dns://gluetun:53", "healthy": False}}).encode())
    assert json.loads((tmp_path / "exit.ndjson").read_text())["ip"] == "198.51.100.7"
    assert not (tmp_path / "flows.ndjson").exists()  # neither leaks into the flow stream
    assert c.status("running")["resolver"]["healthy"] is False and c.invalid == 0


def test_ip_rule_blocks_a_hostname_by_its_in_tunnel_address(tmp_path):
    from glove.netgate.policy import PolicyWatcher

    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"v": 1, "env": "pi-search", "session": "pi-search", "default": "allow",
                                "rules": [{"id": "r_net", "action": "block", "match": {"ip": "93.184.216.0/24"}}]}))

    async def scenario(fwd):
        return await _exchange(fwd.port, b"CONNECT good.example:443 HTTP/1.1\r\n\r\n")

    out, recs, heads, _ = _session({"good.example": ["93.184.216.34"]}, scenario,
                                   policy=PolicyWatcher(path, env="pi-search", session="pi-search"))
    assert out.startswith(b"HTTP/1.1 403") and heads == []
    close = [r for r in recs if r.get("phase") == "close"][-1]
    assert close["rule"] == "r_net" and close["dest"]["ip"] == "93.184.216.34"
