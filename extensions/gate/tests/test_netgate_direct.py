"""The corporate egress gate (`--upstream direct`) and guard exceptions.

In-process with real sockets. Destination names resolve through a fake table
(never the host resolver), and the direct dial is redirected to a local origin
while recording the address the gate chose — so each test sees exactly which
checked address would have been dialled."""

from __future__ import annotations

import asyncio
import ipaddress

import pytest

from extensions.gate.netgate import __main__ as entry
from extensions.gate.netgate import forward, guard
from extensions.gate.netgate.forward import Forwarder, ForwardSpec
from extensions.gate.netgate.policy import StaticPolicy, baseline, parse_bytes
from extensions.gate.tests.test_netgate_proxy import Captured, StubUpstreamProxy, _exchange, _origin, run

ALLOW = guard.parse_exceptions(["*.corp.example", "git.example.internal"], ["10.20.0.0/16"], ["172.31.3.0/24"])
TABLE = {
    "wiki.corp.example": "10.20.1.5",
    "git.example.internal": "10.20.1.6",
    "rebind.corp.example": "169.254.169.254",  # allowlisted name, metadata address
    "own.corp.example": "172.31.3.7",  # the session's own network (denied)
    "gw.corp.example": "10.20.9.9",  # the runtime's host gateway, inside the allowed CIDR
    "example.com": "93.184.215.14",  # public, not allowlisted
    "cidr-only.example": "10.20.2.2",  # not allowlisted by name, but inside the CIDR
}


class FakeResolver:
    async def resolve(self, name):
        return TABLE.get(name)


def _direct(monkeypatch, scenario, *, exceptions=ALLOW, body=b"corp page", origin_factory=None):
    dialled: list[tuple[str, int]] = []

    async def main():
        origin, oport = await (origin_factory or _origin)(body)

        async def dial(self, ip, port):
            dialled.append((ip, port))
            return await asyncio.open_connection("127.0.0.1", oport)

        async def gateways():
            return (ipaddress.ip_network("10.20.9.9/32"),)

        monkeypatch.setattr(Forwarder, "_dial_direct", dial)
        monkeypatch.setattr(forward, "_runtime_gateways", gateways)
        spec = ForwardSpec(service="corporate-proxy", listen_port=0, upstream_host="", upstream_port=0, env="c",
                           session="c", listen_host="127.0.0.1", mode="http-proxy", route_kind="corporate",
                           exceptions=exceptions, direct=True)
        sink = Captured()
        fwd = Forwarder(spec, sink, policy=StaticPolicy(baseline(exceptions)))
        fwd.resolver = FakeResolver()
        await fwd.start()
        out = await scenario(fwd.port)
        await asyncio.sleep(0.05)
        await fwd.stop()
        origin.close()
        return out, sink.records

    out, records = run(main())
    return out, records, dialled


def _connect(host: str, port: int = 443):
    async def scenario(p):
        return await _exchange(p, f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\nhello".encode())
    return scenario


@pytest.mark.parametrize(("host", "ip"), [("wiki.corp.example", "10.20.1.5"), ("git.example.internal", "10.20.1.6"),
                                          ("cidr-only.example", "10.20.2.2"), ("10.20.3.3", "10.20.3.3")])
def test_allowlisted_destinations_are_dialled_by_their_checked_address(monkeypatch, host, ip):
    out, records, dialled = _direct(monkeypatch, _connect(host))
    assert out.startswith(b"HTTP/1.1 200 Connection established\r\n\r\n")
    assert out.endswith(b"hellocorp page")  # the tunnel is spliced to the origin
    assert dialled == [(ip, 443)]
    close = records[-1]
    assert close["verdict"] == "allow" and close["dest"]["ip"] == ip
    assert close["route"]["kind"] == "corporate" and close["route"]["upstream"] == "direct"


@pytest.mark.parametrize(("host", "why"), [
    ("example.com", b"blocked by the default policy"),  # the general internet: default block
    ("rebind.corp.example", b"link-local/metadata"),  # an allowlisted name resolving to metadata
    ("own.corp.example", b"this session's own network"),
    ("gw.corp.example", b"the host gateway"),  # inside 10.20/16, still refused
    ("10.21.0.1", b"non-public address 10.21.0.1"),  # private, outside the allowlist
    ("127.0.0.1", b"this machine"),
    ("host.docker.internal", b"local-only name"),
    ("other.internal", b"local-only name"),  # the shape guard still applies to the rest
])
def test_everything_else_is_refused_and_never_dialled(monkeypatch, host, why):
    out, records, dialled = _direct(monkeypatch, _connect(host))
    assert out.startswith(b"HTTP/1.1 403 Forbidden") and why in out, out
    assert dialled == []
    assert records[-1]["verdict"] == "block"


def test_unresolvable_name_is_a_502_not_a_block(monkeypatch):
    out, records, dialled = _direct(monkeypatch, _connect("missing.corp.example"))
    assert out.startswith(b"HTTP/1.1 502") and b"cannot resolve" in out and dialled == []
    assert records[-1]["close_reason"] == "upstream_unreachable"


def test_absolute_form_goes_to_the_origin_in_origin_form(monkeypatch):
    seen: list[bytes] = []

    async def recording_origin(_body):
        async def handle(reader, writer):
            seen.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    async def get(p):
        return await _exchange(p, b"GET http://wiki.corp.example/a?b HTTP/1.1\r\nHost: x\r\n\r\n")

    out, _, dialled = _direct(monkeypatch, get, origin_factory=recording_origin)
    assert out.endswith(b"ok") and dialled == [("10.20.1.5", 80)]
    assert seen == [b"GET /a?b HTTP/1.1\r\nHost: wiki.corp.example:80\r\nConnection: close\r\n\r\n"]


def test_direct_gate_refuses_a_rules_file():
    with pytest.raises(SystemExit, match="never reads --rules"):
        run(entry._run_forward(entry._parser().parse_args([
            "forward", "--service", "c", "--listen", "0", "--mode", "http-proxy", "--upstream", "direct",
            "--env", "c", "--session", "c", "--rules", "/etc/glove/netgate-control/rules.json"])))


def test_exceptions_parse_strictly():
    with pytest.raises(ValueError):
        guard.parse_exceptions(["bad host!"], [], [])
    with pytest.raises(ValueError):
        guard.parse_exceptions([], ["10.0.0.0/33"], [])


# --- chained gates under the corporate route -------------------------------------------


def _chain(hosts, *, exceptions, rules=None):
    async def main():
        origin, oport = await _origin(b"x")
        up = StubUpstreamProxy(dict.fromkeys(hosts, oport))
        await up.start()
        spec = ForwardSpec(service="proxy", listen_port=0, upstream_host="127.0.0.1", upstream_port=up.port,
                           env="c", session="c", listen_host="127.0.0.1", mode="http-proxy", route_kind="corporate",
                           resolve="none", exceptions=exceptions)
        sink = Captured()
        policy = StaticPolicy(rules) if rules is not None else None
        fwd = Forwarder(spec, sink, policy=policy)
        await fwd.start()
        outs = [await _exchange(fwd.port, f"CONNECT {h}:443 HTTP/1.1\r\n\r\nhi".encode()) for h in hosts]
        await asyncio.sleep(0.05)
        await fwd.stop()
        origin.close()
        up.server.close()
        return outs, up.heads

    return run(main())


def test_chained_gate_passes_the_allowlist_upstream_by_name():
    outs, heads = _chain(["git.example.internal", "10.20.3.3"], exceptions=ALLOW)
    assert all(o.startswith(b"HTTP/1.1 200") for o in outs)
    assert [h.split(b" ")[1] for h in heads] == [b"git.example.internal:443", b"10.20.3.3:443"]


def test_a_rules_json_allow_never_widens_the_guard():
    """Only the operator's exceptions widen the guard. A rules.json `allow` for
    a private range (the only way rules.json could try) changes nothing."""
    rules = parse_bytes(b'{"v": 1, "env": "c", "session": "c", "default": "allow", "rules": ['
                        b'{"id": "r_1", "action": "allow", "match": {"ip": "10.0.0.0/8"}},'
                        b'{"id": "r_2", "action": "allow", "match": {"host": "*.internal"}}]}', env="c", session="c")
    outs, heads = _chain(["10.20.3.3", "git.example.internal"], exceptions=guard.Exceptions(), rules=rules)
    assert all(o.startswith(b"HTTP/1.1 403") for o in outs) and heads == []


def test_a_chained_refusal_reaches_the_client_with_its_reason(monkeypatch):
    """observe's gate in front of the corporate gate relays the refusal body."""

    async def main():
        async def corp(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            body = b"glove netgate refused this request: blocked by the default policy\n"
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n"
                         b"Connection: close\r\n\r\n" % len(body) + body)
            await writer.drain()
            writer.close()

        up = await asyncio.start_server(corp, "127.0.0.1", 0)
        spec = ForwardSpec(service="proxy", listen_port=0, upstream_host="127.0.0.1",
                           upstream_port=up.sockets[0].getsockname()[1], env="c", session="c",
                           listen_host="127.0.0.1", mode="http-proxy", route_kind="corporate", resolve="none")
        fwd = Forwarder(spec, Captured())
        await fwd.start()
        out = await _exchange(fwd.port, b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        await fwd.stop()
        up.close()
        return out

    out = run(main())
    assert out.startswith(b"HTTP/1.1 403") and out.endswith(b"blocked by the default policy\n")
