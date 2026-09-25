"""netgate M5: egress-side listeners (harness: false), client labels,
record: full, retention, and `glove down --wipe`."""

from __future__ import annotations

import json
import os

import pytest
from test_netgate_proxy import Captured, StubUpstreamProxy, _exchange, _origin, run
from test_observe import pi_search_services, render
from typer.testing import CliRunner

from glove.cli import app
from glove.config import ConfigError, Service
from glove.harnessconfig import service_base
from glove.netgate.httpproxy import parse_request_head, request_summary
from glove.netgate.writer import NdjsonWriter
from glove.observe import session_facts

FANOUT = Service(name="fanout", to="egress-proxy:8888", port=8899, join_network="pi-search-egress", harness=False,
                 observe={"mode": "http-proxy", "route": "vpn", "tool": "search-engine-fanout", "client": "searxng"})


def test_harness_false_needs_a_network():
    with pytest.raises(ConfigError, match="needs join_network"):
        Service(name="x", to="egress-proxy:8888", harness=False)


def test_fanout_listener_is_never_on_the_harness_network(tmp_path):
    plan, doc, _ = render(tmp_path, services=[*pi_search_services(), FANOUT])
    fan = doc["services"]["glove-ps-fanout"]
    assert set(fan["networks"]) == {"pi-search-egress"}  # not glove-ps-net
    cmd = fan["command"]
    assert "--ingress-alias" not in cmd
    assert cmd[cmd.index("--client") + 1] == "searxng"
    assert cmd[cmd.index("--tool") + 1] == "search-engine-fanout"
    # the harness is never offered it
    assert service_base(_cfg(), "ps", "fanout") is None
    facts = {s["service"]: s for s in session_facts(plan)["services"]}
    assert facts["fanout"]["harness"] is False and facts["fanout"]["client"] == "searxng"
    assert facts["proxy"]["harness"] is True


def _cfg():
    from glove.config import Config

    c = Config(harness="pi", name="ps", net=["service"])
    c.services = [*pi_search_services(), FANOUT]
    return c


def test_harness_false_plain_socat_also_stays_off_the_internal_net(tmp_path):
    plain = Service(name="fanout", to="egress-proxy:8888", port=8899, join_network="n", harness=False)
    _, doc, _ = render(tmp_path, services=[plain], observe={})
    assert doc["services"]["glove-ps-fanout"]["networks"] == ["n"]


def test_harness_false_search_listener_does_not_imply_the_search_plugin():
    from glove.config import Config
    from glove.plan import _legacy_bridges

    c = Config(harness="pi", name="ps", net=["service"])
    c.services = [Service(name="search", to="egress-proxy:8888", join_network="n", harness=False)]
    assert _legacy_bridges(c) == []


def test_client_label_validation():
    from glove.network import build_network_plan

    c = _cfg()
    c.observe = {"enabled": True}
    c.services[-1] = Service(name="fanout", to="egress-proxy:8888", join_network="n", harness=False,
                             observe={"mode": "http-proxy", "route": "vpn", "client": "harness"})
    with pytest.raises(ConfigError, match="NOT the harness"):
        build_network_plan(c, "ps")


def test_connections_off_the_ingress_carry_the_client_label():
    from glove.netgate.forward import Forwarder, ForwardSpec

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
    from glove.netgate.forward import Forwarder, ForwardSpec

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


def test_cli_warns_loudly_under_full_record_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("GLOVE_HOME", str(tmp_path / "gh"))
    (tmp_path / "w").mkdir()
    (tmp_path / "work").mkdir()
    monkeypatch.chdir(tmp_path / "w")
    r = CliRunner()
    assert r.invoke(app, ["init", "pi"]).exit_code == 0
    over = tmp_path / "o.yaml"
    over.write_text("net: [service]\nmodel: m\nobserve: {enabled: true, record: full, record_headers: true}\n"
                    "services:\n  - { name: llm, to: host.docker.internal:8080 }\n")
    out = r.invoke(app, ["run", "pi", "--config", str(over), "--workdir", str(tmp_path / "work"), "--dry-run"])
    assert out.exit_code == 0, out.output
    assert "record: full" in out.output and "browsing log" in out.output
    facts = json.loads((tmp_path / "gh/envs/w/sessions/w/net/session.json").read_text())
    assert facts["record"] == "full" and facts["record_headers"] is True


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
    net = tmp_path / "gh/envs/e/sessions/e/net"
    net.mkdir(parents=True)
    for f in ("flows.ndjson", "flows-20260923T000000000Z.ndjson", "exit.ndjson", "status.json", "session.json"):
        (net / f).write_text("{}")
    monkeypatch.setattr("glove.session.teardown", lambda *a, **k: None)
    out = CliRunner().invoke(app, ["down", "e", "--wipe", "--provider", "docker"])
    assert out.exit_code == 0, out.output
    assert sorted(p.name for p in net.iterdir()) == ["session.json"]


def test_retention_keeps_the_current_exit_record(tmp_path):
    from glove.netgate.collector import Collector

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
