"""The SSRF guard for proxy-mode listeners (plan §2.6 invariant 3).

``socat`` was point-to-point; an HTTP proxy lets the agent name any destination.
Before anything is sent upstream, the gate refuses — regardless of rules — any
destination that is not plainly public:

- IP literals that are not globally routable: loopback, RFC 1918, CGNAT,
  link-local (``169.254.0.0/16``, cloud metadata), multicast, reserved,
  unspecified — including IPv4-mapped IPv6 and the legacy numeric forms a
  resolver would happily accept (``2130706433``, ``0x7f.1``, ``0177.0.0.1``);
- single-label names — container/service names on the egress network, which
  is where the gate's own upstream and its control plane live (``gluetun``,
  ``egress-proxy``, ``glove-<session>-*``);
- local-only suffixes (``localhost``, ``.local``, ``.internal`` …).

It classifies by *shape*. It never resolves a name — that is invariant 4 — so it
cannot see what a public-looking name resolves to (DNS rebinding, e.g.
``127.0.0.1.nip.io``). That gap is documented in docs/SECURITY.md and is the
upstream's own resolver to police until the in-tunnel resolver (M4).
"""

from __future__ import annotations

import ipaddress
import re
import socket

GUARD_RULE = "builtin:ssrf-guard"
MALFORMED_RULE = "builtin:malformed-request"

LOCAL_SUFFIXES = (
    ".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa",
    ".localdomain", ".intranet", ".corp", ".private",
)
_LABEL = r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?"
_HOST_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")
_NUMERICISH = re.compile(r"^[0-9a-fx.]+$")


def ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """``host`` as an IP address if it is written as one (in any form a resolver
    would accept), else None. Pure parsing — no lookup."""
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
        if _NUMERICISH.match(h.lower()):
            try:
                # inet_aton is a parser, not a resolver: it accepts exactly the
                # shorthand/octal/hex IPv4 forms getaddrinfo would.
                ip = ipaddress.IPv4Address(socket.inet_aton(h))
            except OSError:
                return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def normalize_host(host: str) -> str | None:
    """Lowercased, trailing-dot-free host, or None if it is not a valid DNS name
    or IP literal (so nothing ambiguous is ever passed upstream)."""
    ip = ip_literal(host)
    if ip is not None:
        return str(ip)
    name = host.strip().lower().rstrip(".")
    if not name or len(name) > 253 or not _HOST_RE.match(name):
        return None
    return name


def check(host: str) -> tuple[str | None, bool]:
    """(refusal reason or None, is_local) for a normalized destination host."""
    ip = ip_literal(host)
    if ip is not None:
        if not ip.is_global or ip.is_multicast:
            return f"non-public address {ip}", True
        return None, False
    if "." not in host:
        return f"single-label name {host!r} (an internal service)", True
    if host == "localhost" or host.endswith(LOCAL_SUFFIXES):
        return f"local-only name {host!r}", True
    return None, False
