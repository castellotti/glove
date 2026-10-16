"""Apparent-origin polling (plan §3.2, M4) → ``exit`` records.

The session's apparent origin is the egress's exit, not the operator. The gate
asks the egress's own software, never a lookup service glove picks
(``observe.exit_identity: auto`` follows the egress slot's ``exit_identity``):

- **a file** (``--exit-file``) the egress provider shares read-only with this
  gate: one bare IP, empty or absent while unknown. vpn writes the VPN server's
  endpoint there at ``glove up`` (``vpn-endpoint``), or gluetun its own lookup
  through the tunnel, which it empties when the tunnel drops
  (``gluetun:publicip``). No network, no geo.
- **a URL** fetched **through the chained upstream** (``CONNECT host:443`` to
  the egress proxy, then TLS), so the service sees only the exit — the same
  path as the agent's own traffic: tor's Tor Project check (``IsTor`` must be
  true; Tor picks this gate its own circuit, so its exit need not be the
  agent's), or a URL the operator names.

Records are emitted on the first result and on change (address, location or
health). The URL fetch is glove's own traffic, not the agent's, so it is not a
flow record; it is documented instead.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import ssl
from pathlib import Path
from urllib.parse import urlsplit

from . import SCHEMA_VERSION
from .httpproxy import status_code
from .records import iso_utc

POLL_INTERVAL = 300.0
FILE_INTERVAL = 30.0  # a local read: a dropped tunnel shows within half a minute
RETRY_INTERVAL = 30.0
FETCH_TIMEOUT = 30.0
MAX_BODY = 64 * 1024


def _float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _ip(v) -> str:
    """``v`` as a canonical IP address; anything else (a page, an empty body) is
    not an exit."""
    if not isinstance(v, str):
        raise ValueError("no ip in the answer")
    return str(ipaddress.ip_address(v.strip()))


def parse_echo(body: bytes) -> dict:
    """Normalise an IP-echo JSON body: ipinfo/echoip-style keys (``ip``, geo),
    or the Tor Project's check (``IP``, ``IsTor``, which must be true)."""
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("the answer is not a JSON object")
    if "IsTor" in data and data["IsTor"] is not True:
        raise ValueError("the exit is not a Tor exit")
    lat = data.get("latitude", data.get("lat"))
    lon = data.get("longitude", data.get("lon"))
    if isinstance(data.get("loc"), str) and "," in data["loc"]:  # ipinfo "lat,lon"
        lat, lon = data["loc"].split(",", 1)
    return {"ip": _ip(data.get("ip", data.get("IP"))), "country": data.get("country"), "city": data.get("city"),
            "lat": _float(lat), "lon": _float(lon)}


def parse_ip_file(text: str) -> dict:
    """A bare IP (vpn's endpoint, gluetun's ``PUBLICIP_FILE``); empty = unknown."""
    if not text.strip():
        raise ValueError("no exit known (the tunnel is down, or not checked yet)")
    return {"ip": _ip(text), "country": None, "city": None, "lat": None, "lon": None}


class NotYet(ValueError):
    """The egress has published no exit yet (its file is absent): no record
    until it has, so a session does not open with a false "unhealthy"."""


def _status_line(head: bytes) -> bytes:
    return head.split(b"\r\n", 1)[0]


def check_url(url: str) -> tuple[str, int, str]:
    """An exit-identity URL as (host, port, path): https with a host, or ValueError
    (observe checks it at render time, so the gate never crash-loops on it)."""
    parts = urlsplit(str(url))
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"exit identity URL must be https://<host>/…, got {url!r}")
    return parts.hostname, parts.port or 443, (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


class ExitPoller:
    """Polls one exit source (``fetch``); emits a record on the first result
    and on change."""

    timeout: float | None = FETCH_TIMEOUT

    def __init__(self, *, source: str, kind: str, emit, env: str, session: str, interval: float,
                 retry: float = RETRY_INTERVAL):
        self.source, self.kind, self.emit = source, kind, emit
        self.env, self.session = env, session
        self.interval, self.retry = interval, retry
        self.last: tuple | None = None

    async def fetch(self) -> dict:
        raise NotImplementedError

    def _record(self, info: dict | None, healthy: bool) -> dict:
        info = info or {}
        return {"v": SCHEMA_VERSION, "type": "exit", "t": iso_utc(), "env": self.env, "session": self.session,
                "kind": self.kind, "ip": info.get("ip"), "country": info.get("country"),
                "city": info.get("city"), "lat": info.get("lat"), "lon": info.get("lon"),
                "source": self.source, "healthy": healthy}

    async def poll_once(self) -> bool:
        try:
            info = await (asyncio.wait_for(self.fetch(), self.timeout) if self.timeout else self.fetch())
            healthy = True
        except NotYet:
            if self.last is None:
                return False
            info, healthy = None, False  # removed again: the egress restarted
        except (OSError, ValueError, TimeoutError, ssl.SSLError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError):
            info, healthy = None, False
        key = (healthy, *(info or {}).values()) if healthy else (False,)
        if key != self.last:
            self.last = key
            self.emit(self._record(info, healthy))
        return healthy

    async def run(self) -> None:
        while True:
            ok = await self.poll_once()
            await asyncio.sleep(self.interval if ok else self.retry)


class FileExit(ExitPoller):
    """The egress provider's read-only file, labelled ``source`` (a local read)."""

    timeout = None

    def __init__(self, path: str, *, source: str, interval: float = FILE_INTERVAL, retry: float = FILE_INTERVAL,
                 **kw):
        super().__init__(source=source, interval=interval, retry=retry, **kw)
        self.path = Path(path)

    async def fetch(self) -> dict:
        try:
            with self.path.open(errors="replace") as f:
                return parse_ip_file(f.read(MAX_BODY))
        except FileNotFoundError:
            raise NotYet(f"{self.path} is absent") from None


class UrlExit(ExitPoller):
    """An https URL fetched through ``dial`` (the chained upstream)."""

    def __init__(self, url: str, *, dial, tls: bool = True, interval: float = POLL_INTERVAL, **kw):
        self.host, self.port, self.path = check_url(url)
        super().__init__(source=f"via-proxy:{self.host}", interval=interval, **kw)
        self.dial = dial
        # built once: loading the CA bundle blocks the event loop
        self.tls = ssl.create_default_context() if tls else None

    async def fetch(self) -> dict:
        r, w = await self.dial()  # the configured upstream proxy (never a destination lookup)
        try:
            w.write(f"CONNECT {self.host}:{self.port} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode())
            await w.drain()
            resp = await r.readuntil(b"\r\n\r\n")
            if status_code(resp) != 200:
                raise OSError(f"upstream refused CONNECT: {_status_line(resp)!r}")
            if self.tls is not None:
                await w.start_tls(self.tls, server_hostname=self.host)
            w.write(f"GET {self.path} HTTP/1.0\r\nHost: {self.host}\r\nAccept: application/json\r\n"
                    "User-Agent: glove-netgate\r\n\r\n".encode())
            await w.drain()
            raw = b""
            while len(raw) < MAX_BODY and (chunk := await r.read(MAX_BODY - len(raw))):
                raw += chunk  # HTTP/1.0: the server closes after the body
        finally:
            w.close()
        head, _, body = raw.partition(b"\r\n\r\n")
        if status_code(head) != 200:
            raise OSError(f"echo endpoint answered {_status_line(head)!r}")
        return parse_echo(body)
