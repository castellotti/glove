"""The ``forward`` role: an instrumented forwarder, one per observed service.

Two listener modes (plan §2.1):

- ``tcp`` — a drop-in for ``socat TCP4-LISTEN:<port>,fork,reuseaddr
  TCP4:<host>:<port>``: same port, same target, same IPv4 pinning, every byte
  forwarded unmodified. The first client bytes are *peeked* (not terminated)
  for a TLS ClientHello's SNI, which becomes ``dest.host`` when present.
- ``http-proxy`` — speaks HTTP ``CONNECT`` and absolute-form requests, learns the
  destination from the request line, applies the SSRF guard, and chains to an
  upstream HTTP proxy **by hostname** (``chain:http://<host>:<port>``), so the
  upstream — inside the tunnel — resolves it. The gate never does.

Name resolution happens in exactly two places, both enforced by
``tests/test_netgate_invariants.py``:

- ``_dial_upstream`` — the *configured* upstream (the tcp target, or the chained
  proxy), resolved by the container's resolver exactly as socat resolved it. A
  destination the agent chose is never resolved: in ``http-proxy`` mode it only
  ever travels upstream as text.
- ``_ingress_addresses`` — glove's own per-network ingress alias for this
  container, used only to label the ``client`` of a flow.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import time
from dataclasses import dataclass

from . import guard, httpproxy, sni
from .exitid import ExitPoller
from .policy import PolicyWatcher
from .records import flow_record, ulid
from .resolver import InTunnel
from .resolver import from_url as resolver_from_url

READ_CHUNK = 64 * 1024
SNI_WAIT = 0.25  # tcp mode: emit `open` without SNI if the client is silent this long
HEAD_TIMEOUT = 30.0  # client request head / upstream CONNECT response (Tor can be slow)
POLICY_POLL = 1.0  # seconds between rules.json checks


class _Blocked(Exception):
    """Raised inside the relay when a rule blocks a flow mid-inspection (SNI)."""


@dataclass(frozen=True)
class ForwardSpec:
    service: str
    listen_port: int
    upstream_host: str  # tcp: the target; http-proxy: the chained proxy
    upstream_port: int
    env: str
    session: str
    tool: str | None = None
    scope: str = "local"  # tcp mode only; http-proxy classifies per flow
    resolve: str = "in-tunnel"  # "in-tunnel" | "none"
    listen_host: str = "0.0.0.0"
    ingress_alias: str | None = None
    mode: str = "tcp"  # "tcp" | "http-proxy"
    route_kind: str = "tcp"  # "tcp" | "vpn" | "tor" | "direct"
    sni: bool = True
    resolver_url: str | None = None  # http-proxy mode: dns://h:p | tor-socks://h:p (in-tunnel)
    exit_url: str | None = None  # http-proxy mode: poll the apparent origin through the chain

    @property
    def upstream(self) -> str:
        if self.mode == "http-proxy":
            return f"http://{self.upstream_host}:{self.upstream_port}"
        return f"tcp:{self.upstream_host}:{self.upstream_port}"

    def display_ip(self, host: str | None) -> tuple[str | None, str]:
        """(dest.ip, dest.resolution) for ``host`` before any in-tunnel lookup.

        An IP literal is its own address (``literal``). A ``tcp``-mode flow goes
        to a configured endpoint and is never resolved by design (``disabled``),
        as is everything under ``resolve: none``. A proxy destination starts
        ``unavailable`` and becomes ``in-tunnel`` if the in-tunnel resolver
        answers. There is deliberately no host-resolver fallback."""
        ip = guard.ip_literal(host) if host else None
        if ip is not None:
            return str(ip), "literal"
        if self.mode == "tcp" or self.resolve == "none":
            return None, "disabled"
        return None, "unavailable"

    def dest_ip_and_resolution(self) -> tuple[str | None, str]:
        return self.display_ip(self.upstream_host)

    def flow_scope(self, is_local: bool) -> str:
        """§2.5 scope of a proxied destination: local stays local; anything else
        is tunnelled only when the operator declared the chain a vpn/tor route."""
        if is_local:
            return "local"
        return "tunnelled" if self.route_kind in ("vpn", "tor") else "direct"


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
    """Per-connection state. The destination fields start as the configured
    target (tcp mode) and are refined by SNI or the proxy request line."""

    __slots__ = (
        "client", "close_reason", "down", "host", "id", "ip", "last_emitted", "opened",
        "port", "proto", "resolution", "rule", "scope", "t_open", "up", "verdict",
    )

    def __init__(self, client: str, spec: ForwardSpec):
        self.t_open = time.time()
        self.id = f"f_{ulid(self.t_open)}"
        self.client = client
        self.up = 0
        self.down = 0
        self.last_emitted = (0, 0)
        self.close_reason: str | None = None
        self.opened = False
        self.verdict = "allow"
        self.rule: str | None = None
        if spec.mode == "tcp":
            self.proto = "tcp"
            self.host: str | None = spec.upstream_host
            self.port: int | None = spec.upstream_port
            self.scope = spec.scope
        else:
            self.proto = "http"
            self.host = None
            self.port = None
            # Until a destination passes the guard nothing has left the gate: never
            # claim a tunnel for a refused or unparseable request.
            self.scope = "local"
        self.ip, self.resolution = spec.display_ip(self.host)


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
        policy: PolicyWatcher | None = None,
        policy_poll: float = POLICY_POLL,
        update_interval: float = 1.0,
        connect_timeout: float = 10.0,
        half_close_timeout: float = 60.0,
        head_timeout: float = HEAD_TIMEOUT,
    ):
        self.spec = spec
        self.sink = sink
        self.policy = policy
        self.policy_poll = policy_poll
        self._policy_task: asyncio.Task | None = None
        self.update_interval = update_interval
        self.connect_timeout = connect_timeout
        self.half_close_timeout = half_close_timeout
        self.head_timeout = head_timeout
        self._server: asyncio.Server | None = None
        self._ticker: asyncio.Task | None = None
        self._flows: dict[_Flow, asyncio.Task] = {}
        self._ingress: frozenset[str] = frozenset()
        proxy = spec.mode == "http-proxy"
        resolver = resolver_from_url(spec.resolver_url) if proxy and spec.resolve != "none" else None
        self.resolver = InTunnel(resolver) if resolver is not None else None
        self._resolver_reported: bool | None = None
        self.exit = (
            ExitPoller(url=spec.exit_url, kind=spec.route_kind, dial=self._dial_upstream, emit=sink.send,
                       env=spec.env, session=spec.session)
            if proxy and spec.exit_url else None
        )
        self._exit_task: asyncio.Task | None = None

    # --- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        self._ingress = await _ingress_addresses(self.spec.ingress_alias)
        self._server = await asyncio.start_server(
            self._handle,
            host=self.spec.listen_host,
            port=self.spec.listen_port,
            family=socket.AF_INET,
            reuse_address=True,
            limit=httpproxy.MAX_HEAD,
        )
        self._ticker = asyncio.create_task(self._tick())
        if self.policy is not None:
            self.policy.poll()
            self._policy_task = asyncio.create_task(self._watch_policy())
        if self.exit is not None:
            self._exit_task = asyncio.create_task(self.exit.run())

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
        for t in (self._ticker, self._policy_task, self._exit_task):
            if t is not None:
                t.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await t
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
            proto=flow.proto,
            dest_host=flow.host,
            dest_port=flow.port,
            dest_ip=flow.ip,
            resolution=flow.resolution,
            scope=flow.scope,
            route_kind=s.route_kind,
            route_upstream=s.upstream,
            up=flow.up,
            down=flow.down,
            verdict=flow.verdict,
            rule=flow.rule,
            close_reason=flow.close_reason if phase == "close" else None,
        )

    def _emit(self, flow: _Flow, phase: str) -> None:
        flow.last_emitted = (flow.up, flow.down)
        self.sink.send(self._record(flow, phase, time.time()))

    def _open(self, flow: _Flow) -> None:
        if not flow.opened:
            flow.opened = True
            self._emit(flow, "open")

    async def _tick(self) -> None:
        while True:
            await asyncio.sleep(self.update_interval)
            for flow in list(self._flows):
                if flow.opened and (flow.up, flow.down) != flow.last_emitted:
                    self._emit(flow, "update")

    # --- in-tunnel resolution ------------------------------------------------

    def _report_resolver(self) -> None:
        """Tell the collector when the resolver's health changes (for status.json)."""
        assert self.resolver is not None
        if self.resolver.healthy is not None and self.resolver.healthy != self._resolver_reported:
            self._resolver_reported = self.resolver.healthy
            self.sink.send({"v": 1, "type": "health", "service": self.spec.service,
                            "resolver": {"source": self.resolver.source, "healthy": self.resolver.healthy}})

    async def _resolve(self, flow: _Flow) -> str | None:
        """Resolve a proxy destination in-tunnel; a refusal reason if it resolves
        to a non-public address (DNS rebinding past the shape-only guard)."""
        if self.resolver is None or flow.host is None or guard.ip_literal(flow.host) is not None:
            return None
        ip = await self.resolver.resolve(flow.host)
        self._report_resolver()
        if ip is None:
            return None
        flow.ip, flow.resolution = ip, "in-tunnel"
        why, is_local = guard.check(ip)
        if why is not None:
            flow.scope = self.spec.flow_scope(is_local)
            return f"{flow.host} resolves in-tunnel to a {why}"
        return None

    # --- policy ------------------------------------------------------------

    @staticmethod
    def _facts(flow: _Flow, spec: ForwardSpec) -> dict:
        return {"host": flow.host, "ip": flow.ip, "port": flow.port, "service": spec.service,
                "tool": spec.tool, "scope": flow.scope}

    def _decide(self, flow: _Flow) -> bool:
        """Apply the operator's rules (after the built-in guard). False ⇒ blocked,
        with the verdict and rule id recorded on the flow."""
        if self.policy is None:
            return True
        verdict, rule, _ = self.policy.rules.evaluate(self._facts(flow, self.spec))
        if verdict == "block":
            flow.verdict, flow.rule = "block", rule
            return False
        return True

    async def _watch_policy(self) -> None:
        """Reload on change; a rule with `terminate: true` also cuts established
        flows it now blocks. Others only affect new connections."""
        assert self.policy is not None
        while True:
            await asyncio.sleep(self.policy_poll)
            if not self.policy.poll():
                continue
            for flow, task in list(self._flows.items()):
                if flow.verdict != "allow" or not flow.opened:
                    continue
                verdict, rule, terminate = self.policy.rules.evaluate(self._facts(flow, self.spec))
                if verdict == "block" and terminate:
                    flow.verdict, flow.rule = "block", rule
                    task.cancel()

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
        flow = _Flow(self._client_label(writer), self.spec)
        task = asyncio.current_task()
        assert task is not None
        self._flows[flow] = task
        up_w: asyncio.StreamWriter | None = None
        try:
            if self.spec.mode == "http-proxy":
                up_w = await self._handle_proxy(flow, reader, writer)
            else:
                up_w = await self._handle_tcp(flow, reader, writer)
        except asyncio.CancelledError:
            # cut by a `terminate: true` rule, or the gate stopping
            flow.close_reason = "blocked" if flow.verdict == "block" else "gate_shutdown"
        except (ConnectionError, OSError):
            flow.close_reason = "reset"
        finally:
            for w in (writer, up_w):
                if w is not None:
                    w.close()
            self._flows.pop(flow, None)
            self._open(flow)
            self._emit(flow, "close")

    async def _connect(self, flow: _Flow):
        """Dial the configured upstream; None (with close_reason set) on failure."""
        try:
            return await asyncio.wait_for(self._dial_upstream(), self.connect_timeout)
        except TimeoutError:
            flow.close_reason = "timeout"
        except OSError:
            flow.close_reason = "upstream_unreachable"
        return None

    async def _dial_upstream(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        # IPv4 only, like socat's TCP4: host.docker.internal carries an AAAA
        # record with no route on the Docker Desktop VM.
        return await asyncio.open_connection(
            self.spec.upstream_host, self.spec.upstream_port, family=socket.AF_INET
        )

    # --- tcp mode ----------------------------------------------------------

    async def _handle_tcp(self, flow, reader, writer):
        if not self._decide(flow):
            flow.close_reason = "blocked"
            return None
        conn = await self._connect(flow)
        if conn is None:
            return None
        up_r, up_w = conn
        _set_nodelay(writer)
        _set_nodelay(up_w)
        # Server-first protocols must not wait on the SNI peek: both directions
        # relay at once, and `open` goes out on the first client bytes (with the
        # SNI host, if any) or after SNI_WAIT, whichever comes first.
        timer = asyncio.get_running_loop().call_later(SNI_WAIT, self._open, flow)
        try:
            flow.close_reason = await self._relay(
                flow, reader, writer, up_r, up_w, first=self._sni_first if self.spec.sni else None
            )
        finally:
            timer.cancel()
        if flow.verdict == "block":
            flow.close_reason = "blocked"
        return up_w

    async def _sni_first(self, flow: _Flow, reader: asyncio.StreamReader, data: bytes) -> bytes:
        """Inspect the client's first chunk before it is forwarded. A TLS record
        split across segments is read to completion (bounded) so a large
        post-quantum ClientHello still yields its SNI. The bytes are returned for
        forwarding unmodified — a peek, never a termination."""
        need = sni.record_length(data)
        while need is not None and len(data) < min(need, sni.MAX_HELLO):
            try:
                more = await asyncio.wait_for(reader.read(need - len(data)), SNI_WAIT * 4)
            except TimeoutError:
                break
            if not more:
                break
            data += more
        name = sni.parse_sni(data)
        if name:
            flow.host = name
            flow.ip, flow.resolution = self.spec.display_ip(name)
            if not self._decide(flow):  # a host rule can only match once the SNI is known
                self._open(flow)
                raise _Blocked(flow.rule)
        self._open(flow)
        return data

    # --- http-proxy mode ---------------------------------------------------

    async def _refuse(self, flow, writer, status: int, reason: str, rule: str | None, why: str) -> None:
        flow.verdict = "block"
        flow.rule = rule
        flow.close_reason = "blocked"
        self._open(flow)
        body = httpproxy.response(status, reason, f"glove netgate refused this request: {why}\n")
        with contextlib.suppress(OSError):
            writer.write(body)
            await writer.drain()
            flow.down += len(body)

    async def _handle_proxy(self, flow, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.head_timeout)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError) as e:
            partial = getattr(e, "partial", b"") or b""
            flow.up += len(partial)
            await self._refuse(flow, writer, 400, "Bad Request", guard.MALFORMED_RULE, "incomplete request head")
            return None
        flow.up += len(head)
        try:
            req = httpproxy.parse_request_head(head)
        except httpproxy.BadRequest as e:
            await self._refuse(flow, writer, 400, "Bad Request", guard.MALFORMED_RULE, str(e))
            return None

        flow.proto = req.proto
        flow.host, flow.port = req.host, req.port
        flow.ip, flow.resolution = self.spec.display_ip(req.host)
        why, is_local = guard.check(req.host)
        flow.scope = self.spec.flow_scope(is_local)
        if why is not None:
            await self._refuse(flow, writer, 403, "Forbidden", guard.GUARD_RULE, why)
            return None
        why = await self._resolve(flow)
        if why is not None:
            await self._refuse(flow, writer, 403, "Forbidden", guard.GUARD_RULE, why)
            return None
        if not self._decide(flow):
            # rule is None when `default: block` (no rule matched) decided it
            await self._refuse(flow, writer, 403, "Forbidden", flow.rule,
                               f"blocked by rule {flow.rule}" if flow.rule else "blocked by the default policy")
            return None

        self._open(flow)
        conn = await self._connect(flow)
        if conn is None:
            with contextlib.suppress(OSError):
                body = httpproxy.response(502, "Bad Gateway", "glove netgate: upstream proxy unreachable\n")
                writer.write(body)
                await writer.drain()
                flow.down += len(body)
            return None
        up_r, up_w = conn
        _set_nodelay(writer)
        _set_nodelay(up_w)
        up_w.write(req.upstream_head)
        await up_w.drain()

        if req.proto == "http-connect":
            try:
                resp = await asyncio.wait_for(up_r.readuntil(b"\r\n\r\n"), self.head_timeout)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
                flow.close_reason = "upstream_unreachable"
                return up_w
            writer.write(resp)
            await writer.drain()
            flow.down += len(resp)
            code = httpproxy.status_code(resp)
            if code is None or not 200 <= code < 300:
                # The upstream could not reach the destination (e.g. tunnel down,
                # 502/503): distinct from a policy block.
                flow.close_reason = "upstream_unreachable"
                return up_w

        flow.close_reason = await self._relay(flow, reader, writer, up_r, up_w)
        return up_w

    # --- relay -------------------------------------------------------------

    async def _relay(self, flow, reader, writer, up_r, up_w, *, first=None) -> str:
        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, upstream: bool) -> None:
            inspect = first if upstream else None
            while True:
                data = await src.read(READ_CHUNK)
                if inspect is not None and data:
                    data = await inspect(flow, src, data)
                    inspect = None
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
