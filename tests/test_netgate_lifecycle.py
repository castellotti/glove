"""Followup item 6: a reader can tell a flow cut by a gate that went away from a
pooled one — `run` on every flow record, `gate` start/stop records in
flows.ndjson, and the reference reader's rule (glove.netview.ended_runs)."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest
from test_netgate_proxy import Captured, run

from glove.netgate import forward
from glove.netgate.collector import Collector
from glove.netgate.forward import EventSink, Forwarder, ForwardSpec
from glove.netview import ended_runs, summarize

ENV = SESSION = "e"


def _spec(port: int) -> ForwardSpec:
    return ForwardSpec(service="llm", listen_port=0, upstream_host="127.0.0.1", upstream_port=port,
                       env=ENV, session=SESSION, listen_host="127.0.0.1")


async def _silent_upstream():
    async def h(r, w):
        await r.read()
        w.close()

    s = await asyncio.start_server(h, "127.0.0.1", 0)
    return s, s.sockets[0].getsockname()[1]


def test_every_flow_record_carries_its_forwarders_run_and_stop_follows_the_closes():
    async def main():
        server, port = await _silent_upstream()
        sink = Captured()
        fwd = Forwarder(_spec(port), sink, update_interval=0.05)
        await fwd.start()
        _, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        w.write(b"x")
        await w.drain()
        await asyncio.sleep(0.2)
        order = []
        sink.send = lambda rec: order.append(rec) or True  # the order the collector would see
        await fwd.stop()
        w.close()
        server.close()
        return fwd, sink, order

    fwd, sink, order = run(main())
    assert fwd.run_id.startswith("g_") and len(fwd.run_id) == 28
    assert sink.records and {r["run"] for r in sink.records} == {fwd.run_id}
    start = sink.gates[0]
    assert start == {"v": 1, "type": "gate", "event": "start", "role": "forward", "run": fwd.run_id,
                     "service": "llm", "env": ENV, "session": SESSION, "t": start["t"]}
    assert [(r["type"], r.get("phase") or r.get("event")) for r in order] == [("flow", "close"), ("gate", "stop")]
    assert order[0]["close_reason"] == "gate_shutdown"


def test_start_is_re_announced_so_one_lost_at_startup_is_recovered(monkeypatch):
    monkeypatch.setattr(forward, "ANNOUNCE_EVERY", 0.1)  # the name forward.py reads

    async def main():
        server, port = await _silent_upstream()
        sink = Captured()
        fwd = Forwarder(_spec(port), sink, update_interval=0.05)
        await fwd.start()
        await asyncio.sleep(0.35)
        await fwd.stop()
        server.close()
        return sink.gates

    gates = run(main())
    starts = [g for g in gates if g["event"] == "start"]
    assert len(starts) >= 3 and len({(g["run"], g["t"]) for g in starts}) == 1  # same run, same start time


def test_collector_writes_each_run_start_once_and_its_own_lifecycle(tmp_path):
    c = Collector(tmp_path, "/tmp/unused.sock")
    start = {"v": 1, "type": "gate", "event": "start", "role": "forward", "run": "g_A", "service": "llm"}
    for _ in range(3):
        c.ingest(json.dumps(start).encode())
    c.ingest(json.dumps({**start, "event": "stop"}).encode())
    c.ingest(json.dumps({**start, "event": "restart"}).encode())  # not a gate event
    c.ingest(json.dumps({**start, "role": "collect"}).encode())  # forwarders cannot speak for the collector
    lines = [json.loads(x) for x in (tmp_path / "flows.ndjson").read_text().splitlines()]
    assert [(r["event"], r["run"]) for r in lines] == [("start", "g_A"), ("stop", "g_A")]
    assert c.invalid == 2


def test_live_shutdown_order_in_flows_ndjson():
    """Real sockets: collector up, forwarder up, a flow open, forwarder stopped
    (as compose stops dependants first), then the collector."""

    async def main(d: Path):
        sock = str(d / "events.sock")
        col = Collector(d, sock, status_interval=0.1)
        stop_col = asyncio.Event()
        col_task = asyncio.create_task(col.run(stop_col))
        await asyncio.sleep(0.1)
        server, port = await _silent_upstream()
        fwd = Forwarder(_spec(port), EventSink(sock), update_interval=0.05)
        await fwd.start()
        _, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        w.write(b"x")
        await w.drain()
        await asyncio.sleep(0.2)
        await fwd.stop()
        stop_col.set()
        await col_task
        w.close()
        server.close()
        return col, fwd

    with tempfile.TemporaryDirectory(dir="/tmp") as d:  # short path: AF_UNIX limit
        col, fwd = run(main(Path(d)))
        recs = [json.loads(x) for x in (Path(d) / "flows.ndjson").read_text().splitlines()]
        status = json.loads((Path(d) / "status.json").read_text())
    kinds = [(r["type"], r.get("event") or r.get("phase"), r.get("role")) for r in recs]
    assert kinds[0] == ("gate", "start", "collect") and kinds[1] == ("gate", "start", "forward")
    assert kinds[-3:] == [("flow", "close", None), ("gate", "stop", "forward"), ("gate", "stop", "collect")]
    assert recs[-3]["close_reason"] == "gate_shutdown" and recs[-3]["run"] == fwd.run_id
    assert recs[0]["run"] == col.run_id != fwd.run_id and status["state"] == "stopped"


def _flow(fid, run, phase="open", service="proxy"):
    return {"v": 1, "type": "flow", "phase": phase, "id": fid, "service": service, "run": run}


def _gate(event, run, service="proxy", role="forward"):
    return {"v": 1, "type": "gate", "event": event, "role": role, "run": run, "service": service}


@pytest.mark.parametrize(
    ("records", "ended"),
    [
        ([_gate("start", "g_1"), _flow("f_a", "g_1")], set()),  # pooled/open: not ended
        ([_flow("f_a", "g_1"), _gate("stop", "g_1")], {"g_1"}),  # clean stop, close lost
        ([_flow("f_a", "g_1"), _gate("start", "g_2")], {"g_1"}),  # crash + restart (e.g. docker kill)
        ([_flow("f_a", "g_1"), _flow("f_b", "g_2")], {"g_1"}),  # restart seen via a flow; start lost
        ([_flow("f_a", "g_1"), _flow("f_b", "g_2", service="llm")], set()),  # other service: independent
        ([_flow("f_a", "g_1"), _gate("start", "g_c", service=None, role="collect")], set()),  # collector restart
        ([_flow("f_a", None)], set()),  # a pre-`run` gate: nothing inferred
        ([_flow("f_a", "g_1"), {**_gate("stop", "g_1"), "inferred": True}], {"g_1"}),  # killed, no restart
        ([_flow("f_a", "g_1"), _gate("stop", "g_1"), _gate("start", "g_1")], set()),  # paused, then resumed
    ],
)
def test_ended_runs(records, ended):
    assert ended_runs(records) == ended


def test_status_counts_unclosed_flows_of_ended_runs_as_cut_not_active(tmp_path):
    recs = [_gate("start", "g_1"), _flow("f_a", "g_1"), _flow("f_b", "g_1"), _flow("f_b", "g_1", "close"),
            _gate("start", "g_2"), _flow("f_c", "g_2")]
    (tmp_path / "flows.ndjson").write_text("".join(json.dumps(r) + "\n" for r in recs))
    (tmp_path / "session.json").write_text("{}")
    (tmp_path / "status.json").write_text(json.dumps({"state": "running", "t": "2099-01-01T00:00:00.000Z"}))
    flows = summarize(tmp_path)["flows"]
    assert (flows["total"], flows["active"], flows["cut_inferred"]) == (3, 1, 1)


def test_gate_records_are_not_flows_to_the_reference_tailer(tmp_path):
    from glove.netview import read_records

    (tmp_path / "flows.ndjson").write_text(json.dumps(_gate("start", "g_1")) + "\n"
                                           + json.dumps(_flow("f_a", "g_1")) + "\n")
    assert [r["id"] for r in read_records(tmp_path)] == ["f_a"]



def test_collector_infers_the_stop_of_a_forwarder_that_went_silent(tmp_path):
    now = [100.0]
    c = Collector(tmp_path, "/tmp/unused.sock")
    c._clock = lambda: now[0]
    start = {"v": 1, "type": "gate", "event": "start", "role": "forward", "run": "g_A", "service": "llm"}
    c.ingest(json.dumps(start).encode())
    c.ingest(json.dumps({**start, "run": "g_B", "service": "proxy"}).encode())
    now[0] += 25
    c.ingest(json.dumps({**start, "run": "g_B", "service": "proxy"}).encode())  # g_B's heartbeat
    c.write_status("running")
    now[0] += 10  # g_A silent 35 s > RUN_LOST_AFTER; g_B 10 s
    c.write_status("running")
    c.write_status("running")  # reaped once
    lines = [json.loads(x) for x in (tmp_path / "flows.ndjson").read_text().splitlines()]
    stops = [r for r in lines if r["event"] == "stop"]
    assert [(r["run"], r["service"], r.get("inferred")) for r in stops] == [("g_A", "llm", True)]
    assert ended_runs(lines) == {"g_A"}


def test_a_flow_record_keeps_its_run_alive(tmp_path):
    now = [0.0]
    c = Collector(tmp_path, "/tmp/unused.sock")
    c._clock = lambda: now[0]
    c.ingest(json.dumps({"v": 1, "type": "gate", "event": "start", "role": "forward", "run": "g_A",
                         "service": "llm"}).encode())
    now[0] += 29
    c.ingest(json.dumps({"v": 1, "type": "flow", "phase": "update", "id": "f_1", "service": "llm",
                         "run": "g_A"}).encode())
    now[0] += 29
    c.write_status("running")
    assert "stop" not in (tmp_path / "flows.ndjson").read_text()
