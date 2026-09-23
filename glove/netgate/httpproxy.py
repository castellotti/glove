"""HTTP proxy request parsing for the ``http-proxy`` listener mode.

The gate reads the client's request head, learns the destination from it
(``CONNECT host:port`` or an absolute-form ``GET http://host/…``), and forwards a
*canonical re-serialisation* to the chained upstream — never the client's bytes
verbatim — so the host the SSRF guard checked is exactly the host the upstream
acts on (no parser-differential tricks like ``http://a\\@b/``).

Absolute-form requests are rewritten to ``Connection: close``: one request per
connection, so a kept-alive client cannot slip a second, unchecked destination
through an already-open upstream connection. CONNECT tunnels carry one
destination by construction and are spliced unmodified after the handshake.
"""

from __future__ import annotations

from dataclasses import dataclass

from .guard import normalize_host

MAX_HEAD = 32 * 1024
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"})
HOP_BY_HOP = frozenset({
    "connection", "proxy-connection", "keep-alive", "te", "trailer", "upgrade",
    "proxy-authorization", "proxy-authenticate", "host",
})


class BadRequest(ValueError):
    pass


@dataclass(frozen=True)
class ProxyRequest:
    method: str
    host: str  # normalized: lowercase DNS name or canonical IP literal
    port: int
    proto: str  # "http-connect" | "http"
    upstream_head: bytes  # what the gate sends to the chained upstream

    @property
    def authority(self) -> str:
        return f"{_bracket(self.host)}:{self.port}"


def _bracket(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _split_authority(auth: str) -> tuple[str, int | None]:
    if auth.startswith("["):
        host, sep, rest = auth[1:].partition("]")
        if not sep:
            raise BadRequest("unterminated IPv6 literal")
        port = rest[1:] if rest.startswith(":") else None
        if rest and not rest.startswith(":"):
            raise BadRequest("garbage after IPv6 literal")
    else:
        host, sep, port = auth.rpartition(":")
        if not sep:
            host, port = auth, None
    if port is not None and not (port.isdigit() and 0 < int(port) < 65536):
        raise BadRequest(f"bad port {port!r}")
    return host, int(port) if port is not None else None


def _host(raw: str) -> str:
    host = normalize_host(raw)
    if host is None:
        raise BadRequest(f"invalid host {raw!r}")
    return host


def parse_request_head(head: bytes) -> ProxyRequest:
    """Parse a proxy request head (through the blank line). Raises BadRequest."""
    try:
        text = head.decode("ascii")
    except UnicodeDecodeError as e:
        raise BadRequest("non-ASCII request head") from e
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise BadRequest("malformed request line")
    method, target, _ = parts
    headers = [ln for ln in lines[1:] if ln]
    for ln in headers:
        if ":" not in ln or ln[0] in " \t":
            raise BadRequest("malformed header line")

    if method == "CONNECT":
        host, port = _split_authority(target)
        if port is None:
            raise BadRequest("CONNECT needs host:port")
        host = _host(host)
        auth = f"{_bracket(host)}:{port}"
        up = f"CONNECT {auth} HTTP/1.1\r\nHost: {auth}\r\n\r\n".encode()
        return ProxyRequest(method, host, port, "http-connect", up)

    if method not in METHODS:
        raise BadRequest(f"unsupported method {method!r}")
    scheme, sep, rest = target.partition("://")
    if not sep or scheme.lower() not in ("http", "https"):
        raise BadRequest("proxy requests must use absolute-form http:// URLs")
    auth, slash, path = rest.partition("/")
    if "@" in auth:
        raise BadRequest("userinfo in proxy URL")
    host, port = _split_authority(auth)
    host = _host(host)
    port = port or (443 if scheme.lower() == "https" else 80)
    path = "/" + path if slash else "/"
    if any(c in path for c in " \r\n"):
        raise BadRequest("invalid path")
    authority = f"{_bracket(host)}:{port}"
    kept = [ln for ln in headers if ln.split(":", 1)[0].strip().lower() not in HOP_BY_HOP]
    up_lines = [
        f"{method} {scheme.lower()}://{authority}{path} HTTP/1.1",
        f"Host: {authority}",
        *kept,
        "Connection: close",
        "",
        "",
    ]
    return ProxyRequest(method, host, port, "http", "\r\n".join(up_lines).encode())


def response(status: int, reason: str, body: str) -> bytes:
    data = body.encode()
    return (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n"
    ).encode() + data


def status_code(head: bytes) -> int | None:
    try:
        parts = head.split(b"\r\n", 1)[0].split(b" ")
        return int(parts[1]) if parts[0].startswith(b"HTTP/1.") else None
    except (IndexError, ValueError):
        return None
