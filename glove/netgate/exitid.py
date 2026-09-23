"""Apparent-origin polling (plan §3.2, M4) → ``exit`` records.

The session's apparent origin is the tunnel's exit, not the operator. The gate
learns it by fetching an IP-echo endpoint **through the chained upstream**
(``CONNECT host:443`` to the egress proxy, then TLS), so the echo service sees
only the exit — the same path and identity as the agent's own traffic. The
default endpoint (am.i.mullvad.net/json) is the one glove-pi-search already uses
for its leak check. It is still a third party, so exit identity is opt-in.

gluetun's own control server (``/v1/publicip/ip``) would avoid the third party,
but it answers 401 without a configured credential, and handing the gate one is
an operator decision — not wired yet.

Records are emitted on the first result and on change (address, location or
health). The echo fetch is glove's own traffic, not the agent's, so it is not a
flow record; it is documented instead.
"""

from __future__ import annotations

import asyncio
import json
import ssl
from urllib.parse import urlsplit

from .records import iso_utc

POLL_INTERVAL = 300.0
RETRY_INTERVAL = 30.0
FETCH_TIMEOUT = 30.0
MAX_BODY = 64 * 1024


def _float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_echo(body: bytes) -> dict:
    """Normalise an IP-echo JSON body (mullvad / ipinfo-style keys)."""
    data = json.loads(body)
    if not isinstance(data, dict) or not isinstance(data.get("ip"), str):
        raise ValueError("no ip in echo response")
    lat = data.get("latitude", data.get("lat"))
    lon = data.get("longitude", data.get("lon"))
    if isinstance(data.get("loc"), str) and "," in data["loc"]:  # ipinfo "lat,lon"
        lat, lon = data["loc"].split(",", 1)
    return {"ip": data["ip"], "country": data.get("country"), "city": data.get("city"),
            "lat": _float(lat), "lon": _float(lon)}


class ExitPoller:
    def __init__(self, *, url: str, kind: str, dial, emit, env: str, session: str,
                 interval: float = POLL_INTERVAL, retry: float = RETRY_INTERVAL, tls: bool = True):
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError(f"exit identity URL must be https://…, got {url!r}")
        self.host = parts.hostname
        self.port = parts.port or 443
        self.path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        self.kind, self.dial, self.emit = kind, dial, emit
        self.env, self.session = env, session
        self.interval, self.retry, self.tls = interval, retry, tls
        self.source = f"via-proxy:{self.host}"
        self.last: tuple | None = None

    async def fetch(self) -> dict:
        r, w = await self.dial()  # the configured upstream proxy (never a destination lookup)
        try:
            w.write(f"CONNECT {self.host}:{self.port} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n".encode())
            await w.drain()
            status = (await r.readuntil(b"\r\n\r\n")).split(b"\r\n", 1)[0]
            if b" 200 " not in status + b" ":
                raise OSError(f"upstream refused CONNECT: {status!r}")
            if self.tls:
                await w.start_tls(ssl.create_default_context(), server_hostname=self.host)
            w.write(f"GET {self.path} HTTP/1.0\r\nHost: {self.host}\r\nAccept: application/json\r\n"
                    "User-Agent: glove-netgate\r\n\r\n".encode())
            await w.drain()
            raw = b""
            while len(raw) < MAX_BODY and (chunk := await r.read(MAX_BODY - len(raw))):
                raw += chunk  # HTTP/1.0: the server closes after the body
        finally:
            w.close()
        head, _, body = raw.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0]
        if b" 200 " not in status + b" ":
            raise OSError(f"echo endpoint answered {status!r}")
        return parse_echo(body)

    def _record(self, info: dict | None, healthy: bool) -> dict:
        info = info or {}
        return {"v": 1, "type": "exit", "t": iso_utc(), "env": self.env, "session": self.session,
                "kind": self.kind, "ip": info.get("ip"), "country": info.get("country"),
                "city": info.get("city"), "lat": info.get("lat"), "lon": info.get("lon"),
                "source": self.source, "healthy": healthy}

    async def poll_once(self) -> bool:
        try:
            info = await asyncio.wait_for(self.fetch(), FETCH_TIMEOUT)
            healthy = True
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

