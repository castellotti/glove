"""TLS ClientHello SNI peek — a read of plaintext bytes, never a termination.

The bytes inspected here are forwarded unmodified; the gate never completes, or
takes part in, a handshake. Every length is bounds-checked: malformed or
truncated input yields None, never an exception.
"""

from __future__ import annotations

import re

MAX_HELLO = 16 * 1024 + 5  # one TLS record
_HOST_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$")


def is_tls_handshake(data: bytes) -> bool:
    return len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03


def record_length(data: bytes) -> int | None:
    """Total bytes of the first TLS record (header + body), if the header is in."""
    if len(data) < 5 or not is_tls_handshake(data):
        return None
    return 5 + int.from_bytes(data[3:5], "big")


def parse_sni(data: bytes) -> str | None:
    """The ``server_name`` from a ClientHello in ``data``, lowercased, or None."""
    try:
        return _parse(data)
    except (IndexError, ValueError):
        return None


def _parse(d: bytes) -> str | None:
    if not is_tls_handshake(d) or len(d) < 9 or d[5] != 0x01:  # handshake: client_hello
        return None
    end = min(len(d), 5 + int.from_bytes(d[3:5], "big"))
    p = 9 + 2 + 32  # record(5) + hs type/len(4) + legacy_version(2) + random(32)
    p += 1 + d[p]  # session_id
    p += 2 + int.from_bytes(d[p : p + 2], "big")  # cipher_suites
    p += 1 + d[p]  # compression_methods
    ext_end = min(end, p + 2 + int.from_bytes(d[p : p + 2], "big"))
    p += 2
    while p + 4 <= ext_end:
        etype = int.from_bytes(d[p : p + 2], "big")
        elen = int.from_bytes(d[p + 2 : p + 4], "big")
        p += 4
        if p + elen > ext_end:
            return None
        if etype == 0:  # server_name
            q = p + 2
            list_end = min(p + elen, q + int.from_bytes(d[p : p + 2], "big"))
            while q + 3 <= list_end:
                ntype, nlen = d[q], int.from_bytes(d[q + 1 : q + 3], "big")
                q += 3
                if ntype == 0 and q + nlen <= list_end:
                    name = d[q : q + nlen].decode("ascii").lower().rstrip(".")
                    return name if len(name) <= 253 and _HOST_RE.match(name) else None
                q += nlen
            return None
        p += elen
    return None
