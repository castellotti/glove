"""corporate hooks: validate the allowlist, add the host's routes via the
corporate VPN interface, and declare the raw TCP endpoints.

Everything that widens the gate's SSRF guard comes from here — the operator's
``glove-session.yml`` — and reaches the gate only on its command line
(``--guard-allow-host``/``--guard-allow-cidr``). ``rules.json`` has no key that
could; the corporate gate does not even read it.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from typing import Any

_GLOB = re.compile(r"[a-z0-9*?._-]{1,253}")
_NAME = re.compile(r"[a-z][a-z0-9-]{0,30}")
# never allowed by CIDR (the gate refuses them anyway; say so at plan time)
_NEVER = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "0.0.0.0/8")]


def parse_netstat(text: str, iface: str) -> list[str]:
    """IPv4 destinations routed via ``iface`` in macOS ``netstat -rn -f inet``
    output, as CIDRs. macOS abbreviates: ``10.20/16`` = 10.20.0.0/16, ``10.20.30``
    = 10.20.30.0/24; a host route (flag H) is a /32. The default route is left
    out (a full-tunnel VPN would otherwise allow everything)."""
    out: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[3] != iface or parts[0] in ("default", "Destination"):
            continue
        dest, flags = parts[0], parts[2]
        addr, _, mask = dest.partition("/")
        octets = addr.split(".")
        if not all(o.isdigit() for o in octets) or len(octets) > 4:
            continue
        prefix = int(mask) if mask.isdigit() else (32 if "H" in flags else 8 * len(octets))
        try:
            net = ipaddress.ip_network(f"{'.'.join([*octets, *['0'] * (4 - len(octets))])}/{prefix}", strict=False)
        except ValueError:
            continue
        if any(net.subnet_of(n) for n in _NEVER) or net.prefixlen == 0:
            continue
        if str(net) not in out:
            out.append(str(net))
    return out


def interface_routes(iface: str) -> list[str]:
    if not shutil.which("netstat"):
        raise ValueError("from_interface needs `netstat` (macOS) to read the host's routes")
    r = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise ValueError(f"netstat -rn failed: {r.stderr.strip()}")
    routes = parse_netstat(r.stdout, iface)
    if not routes:
        raise ValueError(f"no IPv4 routes via {iface!r} — is the corporate VPN connected (check `netstat -rn`)?")
    return routes


def _cidrs(values: list) -> list[str]:
    out = []
    for c in values:
        try:
            net = ipaddress.ip_network(str(c), strict=False)
        except ValueError as e:
            raise ValueError(f"corporate.allow_cidrs: {c!r} is not a CIDR") from e
        if net.version != 4:
            raise ValueError(f"corporate.allow_cidrs: {c!r} — the egress stacks are IPv4")
        if net.prefixlen == 0 or any(net.overlaps(n) for n in _NEVER):
            raise ValueError(f"corporate.allow_cidrs: {c!r} covers loopback, link-local/metadata or multicast")
        out.append(str(net))
    return out


def _tcp(items: list) -> list[dict[str, Any]]:
    out = []
    for t in items:
        if not isinstance(t, dict) or set(t) != {"name", "to"}:
            raise ValueError(f"corporate.tcp entries are {{name, to: host:port}}, got {t!r}")
        name, to = str(t["name"]), str(t["to"])
        host, _, port = to.rpartition(":")
        if not _NAME.fullmatch(name) or not host or not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError(f"corporate.tcp: bad entry {t!r} (name: [a-z][a-z0-9-]*, to: host:port)")
        out.append({"name": name, "to": to, "host": host.lower(), "port": int(port)})
    return out


def contribute(ctx: dict[str, Any]) -> dict[str, Any]:
    s = ctx["settings"]
    hosts = []
    for h in s["allow_domains"]:
        g = str(h).strip().lower().rstrip(".")
        if not _GLOB.fullmatch(g) or g in ("*", "*.*"):
            raise ValueError(f"corporate.allow_domains: {h!r} is not a host glob (e.g. '*.corp.example')")
        hosts.append(g)
    cidrs = _cidrs(s["allow_cidrs"])
    resolved = {}
    if s.get("from_interface"):
        routes = interface_routes(s["from_interface"])
        resolved[f"routes via {s['from_interface']}"] = routes
        cidrs += [r for r in _cidrs(routes) if r not in cidrs]
    if not hosts and not cidrs:
        raise ValueError("corporate needs an allowlist: allow_domains, allow_cidrs or from_interface")
    if s["dns"] != "host":
        try:
            ipaddress.IPv4Address(s["dns"])
        except ValueError as e:
            raise ValueError(f"corporate.dns must be `host` or an IPv4 address, got {s['dns']!r}") from e
    tcp = _tcp(s["tcp"])
    probe = s.get("probe_url")
    if probe and not re.match(r"https?://", probe):
        raise ValueError("corporate.probe_url must be an http(s):// URL")
    return {
        "exports": {"guard_hosts": hosts, "guard_cidrs": cidrs, "tcp": tcp,
                    **({"resolved": resolved} if resolved else {})},
        # raw TCP (ssh, a database): a forwarder that dials the host itself over
        # wan, reachable from the harness as glove-<id>-<name>:<port>. (Not under
        # the corporate name: an alias on the harness network would also answer
        # the forwarder's own lookup of that name, and it would dial itself.)
        "endpoints": {t["name"]: {"port": t["port"], "target": {"address": t["to"], "via": "wan"},
                                  "observe": {"scope": "direct"}} for t in tcp},
        "verify": [{"name": "probe", "kind": "http-ok", "url": probe, "network": "egress", "retries": 5,
                    "interval": 3, "proxy": f"http://glove-{ctx['session']['id']}-corporate-proxy:8888",
                    "service": "corporate-proxy"}] if probe else [],
    }
