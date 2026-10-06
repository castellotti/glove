"""The non-negotiable invariants of network observability, each as a test.

docs/planning/network-observability.md §2.6 / §7:

1. the gate exposes no telemetry or control API on the internal network;
2. it never gains NET_ADMIN, never joins the harness's network or PID namespace,
   and never mounts the harness home;
3. net/ (the observe export) has no harness mount;
4. no host DNS resolution of a destination hostname, ever, on any code path;
5. telemetry failure degrades to dropping records, never to dropping traffic
   (the behavioural tests live in tests/test_netgate.py; the structural half —
   the send path cannot block — is here).

Also: the emitted records match the normative handoff schema (its tracked copy,
tests/fixtures/netobs-contract.json; see contract.py).

The render-level halves of 1-3 (and 4 for `glove plan`) are in
extensions/observe/tests/test_observe.py and test_observe_filter_split.py.
"""

from __future__ import annotations

import ast
import asyncio
import os
import socket
from pathlib import Path

import pytest

from extensions.gate.netgate.collector import Collector
from extensions.gate.netgate.forward import EventSink, Forwarder, ForwardSpec
from extensions.gate.netgate.records import flow_record
from extensions.gate.tests.contract import CONTRACT, HANDOFF, ROOT, SECTIONS, from_handoff

NETGATE = ROOT / "extensions" / "gate" / "netgate"


# --- 1. no API on the internal network --------------------------------------


def test_forwarder_binds_exactly_one_socket():
    async def main():
        fwd = Forwarder(
            ForwardSpec(service="s", listen_port=0, upstream_host="127.0.0.1", upstream_port=9,
                        env="e", session="e", listen_host="127.0.0.1"),
            EventSink(None),
        )
        await fwd.start()
        sockets = list(fwd._server.sockets)
        await fwd.stop()
        return sockets

    socks = asyncio.run(main())
    assert len(socks) == 1 and socks[0].family == socket.AF_INET


def test_collector_listens_only_on_a_unix_socket(tmp_path):
    import tempfile

    d = tempfile.mkdtemp(dir="/tmp")
    c = Collector(tmp_path, f"{d}/ev.sock")
    c._bind()
    try:
        assert c._sock.family == socket.AF_UNIX and c._sock.type == socket.SOCK_DGRAM
        assert os.stat(f"{d}/ev.sock").st_mode & 0o077 == 0  # owner-only
    finally:
        c._sock.close()


# --- 4. no host DNS resolution of a destination hostname ---------------------

RESOLVERS = {"getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo",
             "getfqdn", "open_connection", "create_connection"}
# The only name lookups the gate may perform (see netgate/forward.py):
ALLOWED = {
    ("forward.py", "_dial_upstream"): {"open_connection"},  # the operator-configured target
    # a `via: lan` configured target, resolved to check it is private before the dial
    ("forward.py", "lan_address"): {"getaddrinfo"},
    ("forward.py", "_ingress_addresses"): {"getaddrinfo"},  # glove's own ingress alias
    # M4: the configured in-tunnel resolver's OWN name/address (e.g. gluetun:53,
    # tor:9150) — the destination only ever travels inside the DNS / SOCKS query.
    ("resolver.py", "_resolver_address"): {"getaddrinfo"},
    ("resolver.py", "_resolver_tcp"): {"open_connection"},
    ("resolver.py", "_open_socks"): {"open_connection"},
    # v3 M5: the corporate egress gate (`--upstream direct`) alone resolves and
    # dials destinations — by the checked address — and learns the runtime's
    # host-gateway addresses (fixed names) to keep them refused.
    ("resolver.py", "_resolve_destination"): {"getaddrinfo"},  # SystemResolver
    ("forward.py", "_dial_direct"): {"open_connection"},
    ("forward.py", "_runtime_gateways"): {"getaddrinfo"},
}


def _resolver_calls(path: Path):
    tree = ast.parse(path.read_text())
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                if name in RESOLVERS:
                    yield fn.name, name


def test_gate_resolves_names_only_in_allowlisted_functions():
    seen = set()
    for path in sorted(NETGATE.glob("*.py")):
        for fn, call in _resolver_calls(path):
            allowed = ALLOWED.get((path.name, fn), set())
            assert call in allowed, f"{path.name}:{fn} calls {call} — a new name-resolution path " \
                                    "must be reviewed against invariant 4 and added to ALLOWED"
            seen.add((path.name, fn))
    assert seen == set(ALLOWED)


@pytest.mark.parametrize("module", ["gate/gatelib.py", "observe/netview.py", "observe/hooks.py", "observe/cli.py",
                                    "filter/netrules.py", "filter/cli.py", "corporate/hooks.py"])
def test_host_side_modules_never_touch_sockets(module):
    tree = ast.parse((ROOT / "extensions" / module).read_text())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not {"socket", "urllib", "urllib.request", "http.client", "ssl"} & imported


@pytest.fixture
def no_dns(monkeypatch):
    """Any name resolution on the host process becomes a test failure."""

    def boom(*a, **k):
        raise AssertionError(f"host DNS lookup attempted: {a!r}")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo",
                 "getfqdn", "create_connection"):
        monkeypatch.setattr(socket, name, boom)


def test_gate_never_resolves_for_an_ip_literal_upstream(no_dns, tmp_path):
    """With an IP-literal target (and no ingress alias) the forwarder performs
    zero lookups — the dest IP is the literal, `resolution: literal`."""

    async def main():
        async def echo(r, w):
            w.write(await r.read(5))
            await w.drain()
            w.close()

        server = await asyncio.start_server(echo, "127.0.0.1", 0, family=socket.AF_INET)
        port = server.sockets[0].getsockname()[1]
        records: list[dict] = []
        sink = EventSink(None)
        sink.send = lambda rec: records.append(rec) or True
        fwd = Forwarder(ForwardSpec(service="s", listen_port=0, upstream_host="127.0.0.1", upstream_port=port,
                                    env="e", session="e", listen_host="127.0.0.1"), sink)
        await fwd.start()
        r, w = await asyncio.open_connection("127.0.0.1", fwd.port, family=socket.AF_INET)
        w.write(b"hello")
        got = await r.read()
        w.close()
        await asyncio.sleep(0.05)
        await fwd.stop()
        server.close()
        return got, records

    got, records = asyncio.run(asyncio.wait_for(main(), 10))
    assert got == b"hello"
    records = [r for r in records if r["type"] == "flow"]
    assert records[-1]["dest"]["ip"] == "127.0.0.1" and records[-1]["dest"]["resolution"] == "literal"


def test_hostname_target_is_recorded_unresolved():
    # tcp mode forwards to a configured endpoint: never resolved, by design
    spec = ForwardSpec(service="s", listen_port=1, upstream_host="searxng", upstream_port=8080,
                       env="e", session="e")
    assert spec.display_ip(spec.upstream_host) == (None, "disabled")
    # proxy mode: unavailable until the in-tunnel resolver answers; disabled under resolve: none
    proxy = ForwardSpec(service="p", listen_port=1, upstream_host="egress-proxy", upstream_port=8888,
                        env="e", session="e", mode="http-proxy", route_kind="vpn")
    assert proxy.display_ip("en.wikipedia.org") == (None, "unavailable")
    proxy_none = ForwardSpec(service="p", listen_port=1, upstream_host="egress-proxy", upstream_port=8888,
                             env="e", session="e", mode="http-proxy", route_kind="vpn", resolve="none")
    assert proxy_none.display_ip("en.wikipedia.org") == (None, "disabled")


# --- 5. telemetry cannot block traffic (structural half) ---------------------


def test_event_sink_is_non_blocking_and_never_raises(tmp_path):
    sink = EventSink(str(tmp_path / "missing.sock"))
    assert sink._sock.getblocking() is False
    assert sink.send({"x": object()}) is False  # unserialisable
    assert sink.send({"ok": 1}) is False  # no listener
    assert sink.dropped == 2


# --- schema conformance with the normative handoff brief ---------------------


def _shape(obj):
    if isinstance(obj, dict):
        return {k: _shape(v) for k, v in obj.items()}
    return None


def test_flow_record_matches_handoff_schema_exactly():
    spec_flow = CONTRACT["flow"]
    ours = flow_record(phase="open", flow_id="f_x", env="e", session="e", t=0, t_open=0, t_close=None,
                       service="llm", tool="llm", client="harness", proto="tcp", dest_host="h", dest_port=1,
                       dest_ip=None, resolution="unavailable", scope="local", route_kind="tcp",
                       route_upstream="tcp:h:1", up=0, down=0)
    assert _shape(ours) == _shape(spec_flow)
    assert list(ours) == list(spec_flow)  # same key order as the brief
    assert list(ours["dest"]) == list(spec_flow["dest"])


# Additive flow keys (handoff §2, "Additive fields"), after the frozen v1 keys.
ADDITIVE_FLOW_KEYS = ["run"]


def test_forwarder_records_are_v1_plus_only_documented_additive_keys():
    spec_flow = CONTRACT["flow"]

    async def main():
        async def up(r, w):
            await r.read()
            w.close()

        server = await asyncio.start_server(up, "127.0.0.1", 0)
        records: list[dict] = []
        sink = EventSink(None)
        sink.send = lambda rec: records.append(rec) or True
        fwd = Forwarder(ForwardSpec(service="s", listen_port=0, upstream_host="127.0.0.1",
                                    upstream_port=server.sockets[0].getsockname()[1], env="e", session="e",
                                    listen_host="127.0.0.1"), sink)
        await fwd.start()
        _, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        w.write(b"x")
        await w.drain()
        await asyncio.sleep(0.05)
        await fwd.stop()
        w.close()
        server.close()
        return records

    flows = [r for r in asyncio.run(asyncio.wait_for(main(), 10)) if r["type"] == "flow"]
    assert flows
    for rec in flows:
        assert list(rec) == [*spec_flow, *ADDITIVE_FLOW_KEYS]
        assert {k: _shape(v) for k, v in rec.items() if k in spec_flow} == _shape(spec_flow)


def test_status_json_carries_every_handoff_field(tmp_path):
    spec_status = CONTRACT["status"]
    # with the filter grant (a rules path) every handoff field is there...
    ours = Collector(tmp_path, "/tmp/unused.sock", rules_path=tmp_path / "rules.json").status("running")
    for key, sub in _shape(spec_status).items():
        assert key in ours, key
        if isinstance(sub, dict):
            assert set(sub) <= set(ours[key]), key
    assert ours["v"] == 1 and ours["record"] == "metadata"
    # ...and without it `rules` is absent: no gate reads a rules file (v3 §5.2)
    assert "rules" not in Collector(tmp_path, "/tmp/unused.sock").status("running")


@pytest.mark.skipif(not HANDOFF.exists(), reason="the handoff brief is a private planning doc")
def test_the_contract_fixture_is_what_the_handoff_says():
    text = HANDOFF.read_text()
    # on a change: uv run python -m extensions.gate.tests.contract
    assert from_handoff(text) == CONTRACT
    flow_section = text[text.index(SECTIONS["flow"]):text.index(SECTIONS["rules"])]
    for key in ADDITIVE_FLOW_KEYS:
        assert f"`{key}`" in flow_section, key
