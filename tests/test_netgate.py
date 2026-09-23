"""netgate (in-container half) — exercised in-process with real sockets.

A forwarder, a collector and a stub upstream run on loopback; the tests assert
byte-exact forwarding, flow records with correct cumulative byte counts, the
rotation contract, and that every telemetry failure drops records, never traffic.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import shutil
import socket
import tempfile
from pathlib import Path

import pytest

from glove.netgate.collector import Collector
from glove.netgate.forward import EventSink, Forwarder, ForwardSpec
from glove.netgate.records import iso_utc, ulid
from glove.netgate.writer import NdjsonWriter
from glove.netview import follow_records, read_records


def run(coro, timeout: float = 20.0):
    """asyncio.run with a hard ceiling, so a regression fails instead of hanging."""
    return asyncio.run(asyncio.wait_for(coro, timeout))


@pytest.fixture
def sockdir():
    # AF_UNIX paths are capped at ~104 bytes on macOS; pytest's tmp_path is longer.
    d = tempfile.mkdtemp(prefix="ng-", dir="/tmp")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


async def _upstream(response: bytes, *, read_request: int):
    """Stub upstream: read `read_request` bytes, send `response`, close."""

    async def handle(reader, writer):
        got = await reader.readexactly(read_request)
        writer.write(response)
        await writer.drain()
        writer.close()
        handle.seen.append(got)

    handle.seen = []
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], handle.seen


def _spec(port: int, **kw) -> ForwardSpec:
    base = {
        "service": "llm",
        "listen_port": 0,
        "upstream_host": "127.0.0.1",
        "upstream_port": port,
        "env": "pi-search",
        "session": "pi-search",
        "tool": "llm",
        "scope": "local",
        "listen_host": "127.0.0.1",
    }
    base.update(kw)
    return ForwardSpec(**base)


async def _client(port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    data = await reader.read()  # until upstream closes
    writer.close()
    return data


async def _settle(collector: Collector | None = None, *, rounds: int = 20):
    for _ in range(rounds):
        await asyncio.sleep(0.01)
        if collector is not None:
            collector._on_readable()


class _Running:
    """A collector bound on a socket, driven manually (no status loop)."""

    def __init__(self, net_dir: Path, sock: Path):
        self.c = Collector(net_dir, str(sock))
        self.c._bind()

    def drain(self):
        self.c._on_readable()

    def close(self):
        self.c._sock.close()


def test_forward_is_byte_exact_and_records_counts(tmp_path, sockdir):
    request = os.urandom(12_345)
    response = os.urandom(250_000)

    async def main():
        server, uport, seen = await _upstream(response, read_request=len(request))
        col = _Running(tmp_path, sockdir / "ev.sock")
        fwd = Forwarder(_spec(uport), EventSink(str(sockdir / "ev.sock")), update_interval=0.05)
        await fwd.start()
        got = await _client(fwd.port, request)
        await _settle(col.c)
        await fwd.stop()
        server.close()
        col.drain()
        col.close()
        return got, seen

    got, seen = run(main())
    assert hashlib.sha256(got).digest() == hashlib.sha256(response).digest()
    assert seen == [request]

    recs = read_records(tmp_path)
    phases = [r["phase"] for r in recs]
    assert phases[0] == "open" and phases[-1] == "close"
    assert len({r["id"] for r in recs}) == 1
    close = recs[-1]
    assert close["bytes"] == {"up": len(request), "down": len(response)}
    assert close["close_reason"] == "eof"
    assert close["t_close"] is not None and close["t_open"] == recs[0]["t_open"]
    assert close["dest"] == {"host": "127.0.0.1", "port": close["dest"]["port"], "ip": "127.0.0.1",
                             "resolution": "literal"}
    assert close["route"] == {"kind": "tcp", "upstream": f"tcp:127.0.0.1:{close['dest']['port']}"}
    assert close["verdict"] == "allow" and close["rule"] is None and close["request"] is None
    # cumulative, monotonic byte counts across phases
    ups = [r["bytes"]["up"] for r in recs]
    downs = [r["bytes"]["down"] for r in recs]
    assert ups == sorted(ups) and downs == sorted(downs)
    assert os.stat(tmp_path / "flows.ndjson").st_mode & 0o777 == 0o600


def test_periodic_updates_for_a_long_flow(tmp_path, sockdir):
    async def main():
        async def slow(reader, writer):
            for _ in range(5):
                writer.write(b"x" * 1000)
                await writer.drain()
                await asyncio.sleep(0.06)
            writer.close()

        server = await asyncio.start_server(slow, "127.0.0.1", 0)
        col = _Running(tmp_path, sockdir / "ev.sock")
        fwd = Forwarder(_spec(server.sockets[0].getsockname()[1]), EventSink(str(sockdir / "ev.sock")),
                        update_interval=0.05)
        await fwd.start()
        got = await _client(fwd.port, b"")
        await _settle(col.c)
        await fwd.stop()
        server.close()
        col.drain()
        col.close()
        return got

    assert len(run(main())) == 5000
    recs = read_records(tmp_path)
    assert sum(r["phase"] == "update" for r in recs) >= 2
    assert recs[-1]["bytes"]["down"] == 5000


def test_upstream_unreachable_is_recorded_not_blocked(tmp_path, sockdir):
    # A closed port: the flow opens and closes with upstream_unreachable, which
    # Layman must render differently from a policy block (handoff §8).
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()

    async def main():
        col = _Running(tmp_path, sockdir / "ev.sock")
        fwd = Forwarder(_spec(dead), EventSink(str(sockdir / "ev.sock")))
        await fwd.start()
        got = await _client(fwd.port, b"hello")
        await _settle(col.c)
        await fwd.stop()
        col.drain()
        col.close()
        return got, col.c.status("running")

    got, status = run(main())
    assert got == b""
    recs = read_records(tmp_path)
    assert [r["phase"] for r in recs] == ["open", "close"]
    assert recs[-1]["close_reason"] == "upstream_unreachable"
    assert recs[-1]["verdict"] == "allow"
    assert status["upstream"]["healthy"] is False


def test_shutdown_closes_active_flows_with_gate_shutdown(tmp_path, sockdir):
    async def main():
        hold = asyncio.Event()

        async def idle(reader, writer):
            await hold.wait()

        server = await asyncio.start_server(idle, "127.0.0.1", 0)
        col = _Running(tmp_path, sockdir / "ev.sock")
        fwd = Forwarder(_spec(server.sockets[0].getsockname()[1]), EventSink(str(sockdir / "ev.sock")))
        await fwd.start()
        _, w = await asyncio.open_connection("127.0.0.1", fwd.port)
        await _settle(col.c)
        assert fwd.active == 1
        await fwd.stop()
        hold.set()
        server.close()
        w.close()
        col.drain()
        col.close()

    run(main())
    assert read_records(tmp_path)[-1]["close_reason"] == "gate_shutdown"


# --- telemetry fails open ---------------------------------------------------


def test_no_collector_drops_records_not_traffic(sockdir):
    response = os.urandom(50_000)

    async def main():
        server, uport, _ = await _upstream(response, read_request=3)
        sink = EventSink(str(sockdir / "nobody-listening.sock"))
        fwd = Forwarder(_spec(uport), sink)
        await fwd.start()
        got = await _client(fwd.port, b"abc")
        await fwd.stop()
        server.close()
        return got, sink

    got, sink = run(main())
    assert got == response
    assert sink.sent == 0 and sink.dropped >= 2


def test_unwritable_net_dir_drops_records_not_traffic(tmp_path, sockdir):
    ro = tmp_path / "ro"
    ro.mkdir()
    response = os.urandom(40_000)

    async def main():
        server, uport, _ = await _upstream(response, read_request=4)
        col = _Running(ro, sockdir / "ev.sock")
        os.chmod(ro, 0o500)  # collector can no longer create flows.ndjson
        fwd = Forwarder(_spec(uport), EventSink(str(sockdir / "ev.sock")))
        await fwd.start()
        got = await _client(fwd.port, b"ping")
        await _settle(col.c)
        await fwd.stop()
        server.close()
        col.drain()
        col.close()
        return got, col.c

    try:
        got, c = run(main())
    finally:
        os.chmod(ro, 0o700)
    if os.geteuid() == 0:  # pragma: no cover - root ignores the mode bits
        pytest.skip("running as root")
    assert got == response
    assert c.writer.written == 0 and c.writer.dropped >= 2
    assert c.status("running")["telemetry"]["dropped"] >= 2


def test_full_disk_write_error_is_swallowed(tmp_path, monkeypatch):
    w = NdjsonWriter(tmp_path)
    assert w.write({"type": "flow", "id": "a"})

    def enospc(fd, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "write", enospc)
    assert w.write({"type": "flow", "id": "b"}) is False
    monkeypatch.undo()
    assert w.write({"type": "flow", "id": "c"})  # recovers on the next record
    assert [r["id"] for r in read_records(tmp_path)] == ["a", "c"]
    assert w.dropped == 1


def test_collector_ignores_garbage(tmp_path, sockdir):
    c = Collector(tmp_path, str(sockdir / "x.sock"))
    c.ingest(b"not json")
    c.ingest(b'["list"]')
    c.ingest(b'{"type":"other"}')
    c.ingest(json.dumps({"type": "flow", "id": "f_1", "phase": "open"}).encode())
    assert c.invalid == 3 and c.writer.written == 1


# --- rotation (writer honours the reader contract) --------------------------


def _flow(i: int, phase: str = "open") -> dict:
    return {"v": 1, "type": "flow", "id": f"f_{i:04d}", "phase": phase, "pad": "x" * 200}


def test_rotation_renames_and_keeps_newest(tmp_path):
    clock = iter(range(1_700_000_000, 1_800_000_000))
    w = NdjsonWriter(tmp_path, max_bytes=2_000, keep=2, clock=lambda: next(clock))
    for i in range(40):
        assert w.write(_flow(i))
    rotated = w.rotated_files()
    assert w.rotations >= 3
    assert len(rotated) == 2  # older ones pruned
    assert all(p.name.startswith("flows-") and p.name.endswith("Z.ndjson") for p in rotated)
    assert [p.name for p in rotated] == sorted(p.name for p in rotated)
    assert all(os.stat(p).st_mode & 0o777 == 0o600 for p in rotated)
    ids = [r["id"] for r in read_records(tmp_path)]
    assert ids == sorted(ids) and ids[-1] == "f_0039"


def test_open_and_close_straddling_rotation_join_on_id(tmp_path):
    w = NdjsonWriter(tmp_path, max_bytes=10**9)
    w.write(_flow(1, "open"))
    w.rotate()
    w.write(_flow(1, "close"))
    recs = read_records(tmp_path)
    assert [(r["id"], r["phase"]) for r in recs] == [("f_0001", "open"), ("f_0001", "close")]


def test_rotation_opens_the_fresh_file_immediately(tmp_path):
    w = NdjsonWriter(tmp_path, max_bytes=10**9)
    w.write(_flow(1))
    ino = os.stat(tmp_path / "flows.ndjson").st_ino
    w.rotate()
    fresh = tmp_path / "flows.ndjson"
    assert fresh.is_file() and fresh.stat().st_size == 0 and fresh.stat().st_ino != ino
    assert len(list(tmp_path.glob("flows-*.ndjson"))) == 1


def test_follow_survives_rotation(tmp_path):
    w = NdjsonWriter(tmp_path, max_bytes=10**9)
    w.write(_flow(0))
    got: list[str] = []
    it = follow_records(tmp_path, from_end=False, poll=0.001, stop=lambda: len(got) >= 3)
    got.append(next(it)["id"])
    w.write(_flow(1))
    w.rotate()  # new inode for flows.ndjson
    w.write(_flow(2))
    got.append(next(it)["id"])
    got.append(next(it)["id"])
    with contextlib.suppress(StopIteration):
        next(it)
    assert got == ["f_0000", "f_0001", "f_0002"]


def test_torn_trailing_line_is_not_consumed(tmp_path):
    (tmp_path / "flows.ndjson").write_bytes(
        json.dumps(_flow(1)).encode() + b"\n" + b'{"v":1,"type":"flow","id":"f_0002"'
    )
    assert [r["id"] for r in read_records(tmp_path)] == ["f_0001"]


# --- ids and timestamps -----------------------------------------------------


def test_ulid_shape_and_order():
    a, b = ulid(1_000.0), ulid(2_000.0)
    assert len(a) == 26 and set(a) <= set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    assert a < b


def test_iso_utc_format():
    assert iso_utc(0) == "1970-01-01T00:00:00.000Z"
