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

import fnmatch
import ipaddress
import re
import socket
from dataclasses import dataclass

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


# --- operator-configured exceptions (the `corporate` egress, plan §5.1) --------
#
# Corporate resources are private, so the shape guard above would refuse them.
# The operator's allowlist from `glove-session.yml` (never rules.json, which has
# no key for it) is passed on the gate's command line as exceptions. Some
# destinations stay refused even inside an allowed range: this machine, the
# container runtime's host gateway, cloud metadata, and the session's own subnet.

# Names that always mean this machine or the runtime, whatever the allowlist says.
HARD_DENY_NAMES = frozenset({
    "localhost", "host.docker.internal", "gateway.docker.internal", "host.containers.internal",
    "host.lima.internal", "metadata.google.internal", "metadata",
})
# Metadata endpoints outside link-local (Alibaba) — link-local itself is always denied.
_METADATA = (ipaddress.ip_network("100.100.100.200/32"), ipaddress.ip_network("fd00:ec2::254/128"))


@dataclass(frozen=True)
class Exceptions:
    """Guard exceptions: host globs and CIDRs the operator allowed, plus ranges
    that are denied even when an allowed CIDR covers them."""

    hosts: tuple[str, ...] = ()
    cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    deny: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.hosts or self.cidrs)

    def host_allowed(self, host: str) -> bool:
        return any(fnmatch.fnmatchcase(host, g) for g in self.hosts)

    def ip_allowed(self, ip) -> bool:
        return any(ip.version == n.version and ip in n for n in self.cidrs)


def hard_denied(ip, exc: Exceptions) -> str | None:
    """Why ``ip`` is refused whatever the allowlist says, or None."""
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return f"address {ip} (this machine, link-local/metadata or reserved)"
    if any(ip.version == n.version and ip in n for n in (*_METADATA, *exc.deny)):
        return f"address {ip} (metadata, the host gateway or this session's own network)"
    return None


def check_ip(ip, exc: Exceptions) -> tuple[str | None, bool]:
    """(refusal reason or None, is_local) for a destination address — a literal or
    one the gate resolved — honouring the operator's CIDR exceptions."""
    why = hard_denied(ip, exc)
    if why is not None:
        return f"non-public {why}", True
    if not ip.is_global:
        if exc.ip_allowed(ip):
            return None, False
        return f"non-public address {ip}", True
    return None, False


def check_with(host: str, exc: Exceptions) -> tuple[str | None, bool]:
    """``check`` with operator exceptions: an allowlisted name skips the shape
    rules (corporate names are often single-label or `.internal`), an IP literal
    inside an allowed CIDR passes; hard-denied names and ranges never do."""
    if not exc:
        return check(host)
    if host in HARD_DENY_NAMES or host.endswith(".localhost"):
        return f"local-only name {host!r}", True
    ip = ip_literal(host)
    if ip is not None:
        return check_ip(ip, exc)
    if exc.host_allowed(host):
        return None, False
    return check(host)


def parse_exceptions(hosts=(), cidrs=(), deny=()) -> Exceptions:
    """From the gate's command line; raises ValueError on a malformed entry."""
    norm = []
    for h in hosts:
        g = h.strip().lower().rstrip(".")
        if not g or not re.fullmatch(r"[a-z0-9*?._-]{1,253}", g):
            raise ValueError(f"bad allowed host {h!r}")
        norm.append(g)
    return Exceptions(
        hosts=tuple(norm),
        cidrs=tuple(ipaddress.ip_network(c, strict=False) for c in cidrs),
        deny=tuple(ipaddress.ip_network(c, strict=False) for c in deny),
    )
