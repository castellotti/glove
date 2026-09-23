"""Flow-record construction: ids, timestamps, and the normative wire shape.

The record layout is normative — it is the cross-repo contract in
``docs/planning/network-observability-layman-handoff.md`` §2. Key order follows
that document so a fixture diff reads naturally.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime

from . import SCHEMA_VERSION

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def iso_utc(ts: float | None = None) -> str:
    """RFC 3339 UTC with millisecond precision: ``2026-09-23T04:12:33.412Z``."""
    dt = datetime.fromtimestamp(time.time() if ts is None else ts, tz=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def ulid(ts: float | None = None) -> str:
    """A 26-char ULID: 48-bit ms timestamp + 80 random bits, Crockford base32."""
    ms = int((time.time() if ts is None else ts) * 1000) & ((1 << 48) - 1)
    value = (ms << 80) | int.from_bytes(os.urandom(10), "big")
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(out))


def flow_record(
    *,
    phase: str,
    flow_id: str,
    env: str,
    session: str,
    t: float,
    t_open: float,
    t_close: float | None,
    service: str,
    tool: str | None,
    client: str,
    proto: str,
    dest_host: str | None,
    dest_port: int | None,
    dest_ip: str | None,
    resolution: str,
    scope: str,
    route_kind: str,
    route_upstream: str,
    up: int,
    down: int,
    verdict: str = "allow",
    rule: str | None = None,
    close_reason: str | None = None,
) -> dict:
    return {
        "v": SCHEMA_VERSION,
        "type": "flow",
        "phase": phase,
        "id": flow_id,
        "env": env,
        "session": session,
        "t": iso_utc(t),
        "t_open": iso_utc(t_open),
        "t_close": iso_utc(t_close) if t_close is not None else None,
        "service": service,
        "tool": tool,
        "client": client,
        "proto": proto,
        "dest": {"host": dest_host, "port": dest_port, "ip": dest_ip, "resolution": resolution},
        "scope": scope,
        "route": {"kind": route_kind, "upstream": route_upstream},
        "bytes": {"up": up, "down": down},
        "verdict": verdict,
        "rule": rule,
        "close_reason": close_reason,
        # Only populated under `record: full` (M5); metadata mode never records it.
        "request": None,
    }
