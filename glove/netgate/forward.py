"""The ``forward`` role: a TCP forwarder that records flows.

A drop-in for ``socat TCP4-LISTEN:<port>,fork,reuseaddr TCP4:<host>:<port>``:
same listen port, same target, same IPv4 pinning. It reads nothing it does not
forward and forwards every byte unmodified; the only additions are counters and
datagrams to the collector.

Name resolution happens in exactly two places, both enforced by
``tests/test_netgate_invariants.py``:

- ``_dial_upstream`` — the *configured* target (``tcp:<host>:<port>``), resolved
  by the container's resolver exactly as socat resolved it. A destination the
  agent chose is never resolved here: in ``tcp`` mode the destination *is* the
  operator's configured target.
- ``_ingress_addresses`` — glove's own per-network ingress alias for this
  container, used only to label the ``client`` of a flow.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import socket
import time
from dataclasses import dataclass

from .records import flow_record, ulid

READ_CHUNK = 64 * 1024


@dataclass(frozen=True)
class ForwardSpec:
    service: str
    listen_port: int
    upstream_host: str
    upstream_port: int
    env: str
    session: str
    tool: str | None = None
    scope: str = "local"
    resolve: str = "in-tunnel"  # "in-tunnel" | "none"
    listen_host: str = "0.0.0.0"
    ingress_alias: str | None = None

    @property
    def upstream(self) -> str:
        return f"tcp:{self.upstream_host}:{self.upstream_port}"

    def dest_ip_and_resolution(self) -> tuple[str | None, str]:
        """The display IP for the configured target, without ever resolving it.

        An IP-literal target is its own address (``literal``). Otherwise M1 has no
        in-tunnel resolver, so the IP is ``unavailable`` — or ``disabled`` under
        ``resolve: none``. There is deliberately no host-resolver fallback.
        """
        try:
            return str(ipaddress.ip_address(self.upstream_host)), "literal"
        except ValueError:
            return None, ("disabled" if self.resolve == "none" else "unavailable")


class EventSink:
    """Fire-and-forget datagrams to the collector's Unix socket.

    Non-blocking by construction: a missing socket, a dead collector or a full
    receive buffer all make ``send`` return False and bump ``dropped``. Nothing
    here can raise into, or stall, the forwarding path.
    """

    def __init__(self, path: str | None):
        self.path = path
        self.sent = 0
        self.dropped = 0
        self._sock: socket.socket | None = None
        if path:
            try:
                self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                self._sock.setblocking(False)
            except OSError:
                self._sock = None

    def send(self, record: dict) -> bool:
        if self._sock is None or not self.path:
            self.dropped += 1
            return False
        try:
            data = json.dumps(record, separators=(",", ":")).encode()
            self._sock.sendto(data, self.path)
        except (OSError, ValueError, TypeError):
            self.dropped += 1
            return False
        self.sent += 1
        return True

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None


class _Flow:
    __slots__ = ("client", "close_reason", "down", "id", "last_emitted", "t_open", "up")

    def __init__(self, client: str):
        self.t_open = time.time()
        self.id = f"f_{ulid(self.t_open)}"
        self.client = client
        self.up = 0
        self.down = 0
        self.last_emitted = (0, 0)
        self.close_reason: str | None = None


def _set_nodelay(writer: asyncio.StreamWriter) -> None:
    sock = writer.get_extra_info("socket")
    if sock is not None:
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


class Forwarder:
    def __init__(
        self,
        spec: ForwardSpec,
        sink: EventSink,
        *,
        update_interval: float = 1.0,
        connect_timeout: float = 10.0,
        half_close_timeout: float = 60.0,
    ):
        self.spec = spec
        self.sink = sink
        self.update_interval = update_interval
        self.connect_timeout = connect_timeout
        self.half_close_timeout = half_close_timeout
        self._server: asyncio.Server | None = None
        self._ticker: asyncio.Task | None = None
        self._flows: dict[_Flow, asyncio.Task] = {}
        self._ingress: frozenset[str] = frozenset()
        self._dest_ip, self._resolution = spec.dest_ip_and_resolution()

    # --- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        self._ingress = await _ingress_addresses(self.spec.ingress_alias)
        self._server = await asyncio.start_server(
            self._handle,
            host=self.spec.listen_host,
            port=self.spec.listen_port,
            family=socket.AF_INET,
            reuse_address=True,
        )
        self._ticker = asyncio.create_task(self._tick())

    @property
    def port(self) -> int:
        """The bound port (useful when started on port 0 in tests)."""
        assert self._server is not None
        return self._server.sockets[0].getsockname()[1]

    @property
    def active(self) -> int:
        return len(self._flows)

    async def stop(self) -> None:
        # Stop accepting, then cut live flows (each records `gate_shutdown`), and
        # only then wait: since 3.12 `wait_closed` waits for open connections.
        if self._server is not None:
            self._server.close()
        if self._ticker is not None:
            self._ticker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._ticker
        tasks = list(self._flows.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self._server is not None:
            await self._server.wait_closed()

    # --- records -----------------------------------------------------------

    def _record(self, flow: _Flow, phase: str, now: float) -> dict:
        s = self.spec
        return flow_record(
            phase=phase,
            flow_id=flow.id,
            env=s.env,
            session=s.session,
            t=now,
            t_open=flow.t_open,
            t_close=now if phase == "close" else None,
            service=s.service,
            tool=s.tool,
            client=flow.client,
            proto="tcp",
            dest_host=s.upstream_host,
            dest_port=s.upstream_port,
            dest_ip=self._dest_ip,
            resolution=self._resolution,
            scope=s.scope,
            route_kind="tcp",
            route_upstream=s.upstream,
            up=flow.up,
            down=flow.down,
            close_reason=flow.close_reason if phase == "close" else None,
        )

    def _emit(self, flow: _Flow, phase: str) -> None:
        flow.last_emitted = (flow.up, flow.down)
        self.sink.send(self._record(flow, phase, time.time()))

    async def _tick(self) -> None:
        while True:
            await asyncio.sleep(self.update_interval)
            for flow in list(self._flows):
                if (flow.up, flow.down) != flow.last_emitted:
                    self._emit(flow, "update")

    # --- connections -------------------------------------------------------

    def _client_label(self, writer: asyncio.StreamWriter) -> str:
        """``harness`` when the connection arrived on the internal network.

        The internal network is identified by the local address the connection
        landed on: the one glove's ingress alias resolves to. Anything else (a
        peer on a joined network) is honestly ``unknown``.
        """
        sockname = writer.get_extra_info("sockname")
        local = sockname[0] if sockname else None
        return "harness" if local in self._ingress else "unknown"

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        flow = _Flow(self._client_label(writer))
        task = asyncio.current_task()
        assert task is not None
        self._flows[flow] = task
        self._emit(flow, "open")
        up_w: asyncio.StreamWriter | None = None
        try:
            try:
                up_r, up_w = await asyncio.wait_for(self._dial_upstream(), self.connect_timeout)
            except TimeoutError:
                flow.close_reason = "timeout"
                return
            except OSError:
                flow.close_reason = "upstream_unreachable"
                return
            _set_nodelay(writer)
            _set_nodelay(up_w)
            flow.close_reason = await self._relay(flow, reader, writer, up_r, up_w)
        except asyncio.CancelledError:
            flow.close_reason = "gate_shutdown"
        finally:
            for w in (writer, up_w):
                if w is not None:
                    w.close()
            self._flows.pop(flow, None)
            self._emit(flow, "close")

    async def _dial_upstream(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        # IPv4 only, like socat's TCP4: host.docker.internal carries an AAAA
        # record with no route on the Docker Desktop VM.
        return await asyncio.open_connection(
            self.spec.upstream_host, self.spec.upstream_port, family=socket.AF_INET
        )

    async def _relay(self, flow, reader, writer, up_r, up_w) -> str:
        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, upstream: bool) -> None:
            while True:
                data = await src.read(READ_CHUNK)
                if not data:
                    if dst.can_write_eof():
                        with contextlib.suppress(OSError):
                            dst.write_eof()
                    return
                dst.write(data)
                await dst.drain()
                if upstream:
                    flow.up += len(data)
                else:
                    flow.down += len(data)

        tasks = {
            asyncio.create_task(pump(reader, up_w, True)),
            asyncio.create_task(pump(up_r, writer, False)),
        }
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            reason = _reason(done)
            if pending and reason == "eof":
                # One direction finished cleanly (a half-close); let the other
                # drain, bounded so a silent peer can't pin the flow forever.
                done2, pending = await asyncio.wait(pending, timeout=self.half_close_timeout)
                reason = _reason(done2) if done2 else "timeout"
            return reason
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


def _reason(done: set[asyncio.Task]) -> str:
    for t in done:
        if t.cancelled():
            continue
        if t.exception() is not None:
            return "reset"
    return "eof"


async def _ingress_addresses(alias: str | None) -> frozenset[str]:
    """Local addresses of glove's internal-network ingress alias (never a
    destination). Failure degrades the ``client`` label to ``unknown``."""
    if not alias:
        return frozenset()
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(alias, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        return frozenset()
    return frozenset(info[4][0] for info in infos)
