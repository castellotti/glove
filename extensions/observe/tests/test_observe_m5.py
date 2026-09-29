"""The gate's client labels, record: full, retention (v2's netgate M5), and
`glove down --wipe`."""

from __future__ import annotations

import json
import os

from helpers import make_session
from typer.testing import CliRunner

from extensions.gate.netgate.httpproxy import parse_request_head, request_summary
from extensions.gate.netgate.writer import NdjsonWriter
from extensions.gate.tests.test_netgate_proxy import Captured, StubUpstreamProxy, _exchange, _origin, run
from glove.cli import app


def test_connections_off_the_ingress_carry_the_client_label():
    from extensions.gate.netgate.forward import Forwarder, ForwardSpec

    async def main():
        origin, oport = await _origin(b"x")
        up = StubUpstreamProxy({"duckduckgo.com": oport})
        await up.start()
        sink = Captured()
        spec = ForwardSpec(service="fanout", listen_port=0, upstream_host="127.0.0.1", upstream_port=up.port,
                           env="e", session="e", tool="search-engine-fanout", listen_host="127.0.0.1",
                           mode="http-proxy", route_kind="vpn", client="searxng")
        fwd = Forwarder(spec, sink)
        await fwd.start()
        await _exchange(fwd.port, b"CONNECT duckduckgo.com:443 HTTP/1.1\r\n\r\nx")
        await fwd.stop()
        origin.close()
        up.server.close()
        return sink.records

    recs = run(main())
    assert {r["client"] for r in recs} == {"searxng"} and recs[-1]["tool"] == "search-engine-fanout"


# --- record: full ------------------------------------------------------------------


def test_request_summary_cleartext_url_and_redacted_headers():
    head = (b"GET http://Example.com/search?q=secret HTTP/1.1\r\nHost: example.com\r\n"
            b"Cookie: session=abc\r\nAuthorization: Bearer x\r\nAccept: */*\r\n\r\n")
    req = parse_request_head(head)
    assert request_summary(head, req, headers=False) == {"method": "GET",
                                                        "url": "http://example.com:80/search?q=secret"}
    hs = request_summary(head, req, headers=True)["headers"]
    assert hs["Cookie"] == "[redacted]" and hs["Authorization"] == "[redacted]" and hs["Accept"] == "*/*"


def test_request_summary_connect_has_no_url():
    head = b"CONNECT en.wikipedia.org:443 HTTP/1.1\r\n\r\n"
    assert request_summary(head, parse_request_head(head), headers=False) == {"method": "CONNECT", "url": None}


def test_full_mode_records_request_and_metadata_mode_never_does():
    from extensions.gate.netgate.forward import Forwarder, ForwardSpec

    def session(record):
        async def main():
            origin, oport = await _origin(b"hello")
            up = StubUpstreamProxy({"example.org": oport})
            await up.start()
            sink = Captured()
            spec = ForwardSpec(service="proxy", listen_port=0, upstream_host="127.0.0.1", upstream_port=up.port,
                               env="e", session="e", tool="web_fetch", listen_host="127.0.0.1",
                               mode="http-proxy", route_kind="vpn", record=record)
            fwd = Forwarder(spec, sink)
            await fwd.start()
            await _exchange(fwd.port, b"GET http://example.org/robots.txt HTTP/1.1\r\nHost: example.org\r\n\r\n")
            await fwd.stop()
            origin.close()
            up.server.close()
            return sink.records

        return run(main())

    assert {json.dumps(r["request"]) for r in session("metadata")} == {"null"}
    full = session("full")
    assert full[-1]["request"] == {"method": "GET", "url": "http://example.org:80/robots.txt"}


# --- retention ----------------------------------------------------------------------


def test_retention_rotates_and_expires_by_age(tmp_path):
    now = [1_700_000_000.0]
    w = NdjsonWriter(tmp_path, max_bytes=10**9, clock=lambda: now[0])
    w.write({"type": "flow", "id": "old"})
    now[0] += 3600 / 4  # a quarter of a 1h retention
    assert w.expire(3600) == 0
    assert len(w.rotated_files()) == 1 and w.path.stat().st_size == 0  # rotated, fresh live file
    old = w.rotated_files()[0]
    os.utime(old, (now[0] - 7200, now[0] - 7200))
    w.write({"type": "flow", "id": "new"})
    assert w.expire(3600) == 1 and not old.exists()
    assert [json.loads(line)["id"] for line in w.path.read_text().splitlines()] == ["new"]


def test_existing_live_file_is_aged_by_its_mtime(tmp_path):
    (tmp_path / "flows.ndjson").write_text('{"type":"flow","id":"stale"}\n')
    os.utime(tmp_path / "flows.ndjson", (1000, 1000))
    w = NdjsonWriter(tmp_path, max_bytes=10**9, clock=lambda: 1_000_000.0)
    w.write({"type": "flow", "id": "x"})
    w.expire(3600)
    assert w.rotated_files()  # rotated on the first check, not after another retain/4


def test_down_wipe_clears_the_flow_record(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "gh"))
    d = make_session(tmp_path / "s")
    (d / ".glove").mkdir()
    (d / ".glove" / "id").write_text("s-0a0b0c\n")
    net = tmp_path / "gh/observe/s-0a0b0c/net"
    net.mkdir(parents=True)
    for f in ("flows.ndjson", "flows-20260923T000000000Z.ndjson", "exit.ndjson", "status.json", "session.json"):
        (net / f).write_text("{}")
    monkeypatch.setattr("glove.session.teardown", lambda *a, **k: None)
    out = CliRunner().invoke(app, ["down", str(d), "--wipe", "--provider", "docker"])
    assert out.exit_code == 0, out.output
    assert sorted(p.name for p in net.iterdir()) == ["session.json"]


def test_retention_keeps_the_current_exit_record(tmp_path):
    from extensions.gate.netgate.collector import Collector

    (tmp_path / "session.json").write_text(json.dumps({"rotate": {"retain_s": 3600}}))
    c = Collector(tmp_path, "/tmp/unused.sock")
    now = [1_700_000_000.0]
    c.writer._clock = c.exits._clock = lambda: now[0]
    c.ingest(json.dumps({"v": 1, "type": "exit", "ip": "198.51.100.7", "healthy": True}).encode())
    now[0] += 3600  # the exit file is now old enough to rotate, then expire
    c.write_status("running")
    for old in c.exits.rotated_files():
        os.utime(old, (now[0] - 7200, now[0] - 7200))
    c.write_status("running")
    assert not c.exits.rotated_files()  # history expired...
    assert json.loads((tmp_path / "exit.ndjson").read_text())["ip"] == "198.51.100.7"  # ...the present did not


def test_size_rotation_of_exit_ndjson_carries_the_current_exit_forward(tmp_path):
    """Followup item 8: not only retention — a size rotation too."""
    from extensions.gate.netgate.collector import Collector

    c = Collector(tmp_path, "/tmp/unused.sock")
    c.exits.max_bytes = 200  # a couple of records per file
    for i in range(7):
        c.ingest(json.dumps({"v": 1, "type": "exit", "ip": f"198.51.100.{i}", "healthy": True}).encode())
        live = (tmp_path / "exit.ndjson").read_text().splitlines()
        assert live and json.loads(live[-1])["ip"] == f"198.51.100.{i}", i  # never an empty live file
    assert c.exits.rotations >= 2
