"""In-tunnel resolution of destination hostnames (plan §3.1, M4).

The gate learns a destination's IP by asking a resolver **inside the tunnel**,
never the host's:

- ``dns://<host>:<port>`` — a plain DNS server on the egress network whose own
  upstream is in the tunnel. gluetun serves exactly this on ``gluetun:53`` (DoT
  upstream through ``wg0``, rebinding protection, caching), so the gate's query
  is a cached repeat of the one gluetun makes for the CONNECT itself.
- ``tor-socks://<host>:<port>`` — Tor's SOCKS5 ``RESOLVE`` extension (command
  0xF0), resolved by the exit relay.

**Fail closed.** Any failure yields ``None`` — the flow is recorded
``resolution: "unavailable"`` and traffic is unaffected. There is no fallback
path: nothing in this module can reach the host resolver, and the only names
it hands to a system resolver are the *configured resolver's own* (enforced by
``tests/test_netgate_invariants.py``). After a failure the resolver backs off
briefly so a dead resolver cannot add latency to every connection.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
import time

TIMEOUT = 2.0
TOR_TIMEOUT = 8.0  # the exit relay resolves; allow for circuit latency
BACKOFF = 15.0
CACHE_MAX = 4096
MIN_TTL, MAX_TTL = 5, 300


class ResolveError(Exception):
    pass


# --- DNS wire format (A records only; the egress stacks are IPv4) -------------


def build_query(qid: int, name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    if any(not 0 < len(label) < 64 for label in labels):
        raise ResolveError(f"bad name {name!r}")
    q = b"".join(bytes([len(lb)]) + lb.encode("ascii") for lb in labels) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)


def _skip_name(d: bytes, i: int) -> int:
    while True:
        n = d[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:  # compression pointer
            return i + 2
        i += 1 + n


def parse_response(d: bytes, qid: int) -> tuple[list[str], int, bool]:
    """(IPv4 answers, min TTL, truncated). Raises ResolveError on a bad reply."""
    try:
        rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", d[:12])
        if rid != qid or not flags & 0x8000:
            raise ResolveError("mismatched reply")
        truncated = bool(flags & 0x0200)
        rcode = flags & 0x000F
        if rcode not in (0, 3):  # NOERROR, NXDOMAIN
            raise ResolveError(f"rcode {rcode}")
        i = 12
        for _ in range(qd):
            i = _skip_name(d, i) + 4
        ips, ttl = [], MAX_TTL
        for _ in range(an):
            i = _skip_name(d, i)
            rtype, _, rttl, rdlen = struct.unpack(">HHIH", d[i:i + 10])
            i += 10
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(d[i:i + 4]))
                ttl = min(ttl, rttl)
            i += rdlen
        return ips, ttl, truncated
    except (struct.error, IndexError) as e:
        raise ResolveError(f"malformed reply: {e}") from e


class _UdpOnce(asyncio.DatagramProtocol):
    def __init__(self):
        self.reply: asyncio.Future = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        if not self.reply.done():
            self.reply.set_result(data)

    def error_received(self, exc):
        if not self.reply.done():
            self.reply.set_exception(exc)


# --- resolvers -----------------------------------------------------------------


class DnsResolver:
    """Plain DNS to a configured in-tunnel server (UDP, TCP on truncation)."""

    def __init__(self, host: str, port: int = 53):
        self.host, self.port = host, port
        self.source = f"dns://{host}:{port}"
        self._addr: str | None = None

    async def _resolver_address(self) -> str:
        """The configured resolver's own address (a glove-configured endpoint,
        like the upstream proxy — never a destination)."""
        if self._addr is None:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(self.host, self.port, family=socket.AF_INET, type=socket.SOCK_DGRAM)
            self._addr = infos[0][4][0]
        return self._addr

    async def _resolver_tcp(self, addr: str):
        # TCP fallback to the configured resolver's own (already known) address
        return await asyncio.open_connection(addr, self.port, family=socket.AF_INET)

    async def lookup(self, name: str) -> tuple[str | None, int]:
        addr = await self._resolver_address()
        qid = int.from_bytes(os.urandom(2), "big")
        query = build_query(qid, name)
        loop = asyncio.get_running_loop()
        transport, proto = await loop.create_datagram_endpoint(_UdpOnce, remote_addr=(addr, self.port))
        try:
            transport.sendto(query)
            data = await asyncio.wait_for(proto.reply, TIMEOUT)
        finally:
            transport.close()
        ips, ttl, truncated = parse_response(data, qid)
        if truncated:
            r, w = await asyncio.wait_for(self._resolver_tcp(addr), TIMEOUT)
            try:
                w.write(struct.pack(">H", len(query)) + query)
                await w.drain()
                n = struct.unpack(">H", await asyncio.wait_for(r.readexactly(2), TIMEOUT))[0]
                ips, ttl, _ = parse_response(await asyncio.wait_for(r.readexactly(n), TIMEOUT), qid)
            finally:
                w.close()
        return (ips[0] if ips else None), ttl


class TorSocksResolver:
    """Tor's SOCKS5 RESOLVE (0xF0): the exit relay resolves the name."""

    def __init__(self, host: str, port: int = 9150):
        self.host, self.port = host, port
        self.source = f"tor-socks://{host}:{port}"

    async def _open_socks(self):
        # the configured Tor SOCKS endpoint's own name — never a destination
        return await asyncio.open_connection(self.host, self.port, family=socket.AF_INET)

    async def lookup(self, name: str) -> tuple[str | None, int]:
        r, w = await asyncio.wait_for(self._open_socks(), TIMEOUT)
        try:
            w.write(b"\x05\x01\x00")
            if await asyncio.wait_for(r.readexactly(2), TOR_TIMEOUT) != b"\x05\x00":
                raise ResolveError("SOCKS5 greeting refused")
            host = name.encode("ascii")
            w.write(b"\x05\xf0\x00\x03" + bytes([len(host)]) + host + b"\x00\x00")
            head = await asyncio.wait_for(r.readexactly(4), TOR_TIMEOUT)
            if head[1] != 0:
                return None, MIN_TTL  # e.g. 0x04 host unreachable: resolved to nothing
            if head[3] != 1:
                raise ResolveError(f"unexpected address type {head[3]}")
            ip = socket.inet_ntoa(await asyncio.wait_for(r.readexactly(4), TOR_TIMEOUT))
            await r.readexactly(2)
            return ip, 60
        finally:
            w.close()


def from_url(url: str | None):
    """A resolver for ``dns://h:p`` / ``tor-socks://h:p``; None for none/empty."""
    if not url or url == "none":
        return None
    scheme, sep, rest = url.partition("://")
    host, _, port = rest.rstrip("/").rpartition(":")
    if not sep or not host or not port.isdigit():
        raise ValueError(f"resolver must be dns://<host>:<port> or tor-socks://<host>:<port>, got {url!r}")
    if scheme == "dns":
        return DnsResolver(host, int(port))
    if scheme == "tor-socks":
        return TorSocksResolver(host, int(port))
    raise ValueError(f"unknown resolver scheme {scheme!r}")


class InTunnel:
    """Cache + backoff around a resolver. ``resolve`` never raises."""

    def __init__(self, resolver, *, clock=time.monotonic):
        self.resolver = resolver
        self.source = getattr(resolver, "source", "?")
        self._clock = clock
        self._cache: dict[str, tuple[str | None, float]] = {}
        self._down_until = 0.0
        self.healthy: bool | None = None  # None until the first attempt
        self.failures = 0

    async def resolve(self, name: str) -> str | None:
        now = self._clock()
        hit = self._cache.get(name)
        if hit and hit[1] > now:
            return hit[0]
        if now < self._down_until:
            return None
        try:
            ip, ttl = await asyncio.wait_for(self.resolver.lookup(name), TOR_TIMEOUT + TIMEOUT)
        # IncompleteReadError is an EOFError, not an OSError: a SOCKS/DNS peer
        # that accepts and then hangs up (Tor still bootstrapping) lands here.
        except (OSError, EOFError, ResolveError, TimeoutError, UnicodeError, ValueError, IndexError):
            self.failures += 1
            self.healthy = False
            self._down_until = now + BACKOFF
            return None
        self.healthy = True
        try:
            ip = str(ipaddress.IPv4Address(ip)) if ip is not None else None
        except ValueError:
            ip = None
        if len(self._cache) >= CACHE_MAX:
            self._cache.clear()
        self._cache[name] = (ip, now + max(MIN_TTL, min(MAX_TTL, ttl)))
        return ip
