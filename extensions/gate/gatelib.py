"""Host side of the `gate` library: how an endpoint becomes a netgate forwarder.

Used by the `observe` extension's `forwarder` hook (one gate per endpoint) and
by `corporate` (its egress proxy is a gate with ``--upstream direct``). The
in-container half is ``netgate/``. Wire contract: the Layman handoff
(``docs/planning/network-observability-layman-handoff.md``), frozen at v1.

Nothing here resolves a hostname. Classification is by the *shape* of the
configured target (IP literal, single-label container name, the host gateway),
never by a lookup — ``tests/test_netgate_invariants.py`` keeps it that way.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .netgate import CONTROL_DIR, EVENTS_DIR, EVENTS_SOCKET, MODES, NET_DIR, ROUTES, RULES_FILE, SCOPES, client_problem

# §2.4 tool labels by conventional endpoint name. An explicit `observe.tool`
# (e.g. the llm extension's annotation) always wins.
DEFAULT_TOOLS = {"proxy": "web_fetch", "search": "web_search", "browser": "browser", "llm": "llm"}
HOST_GATEWAY_NAMES = frozenset({"host.docker.internal", "host.containers.internal"})
ANNOTATION_KEYS = frozenset({"mode", "tool", "scope", "upstream", "route", "client"})


@dataclass(frozen=True)
class GateSpec:
    """How one endpoint's forwarder is instrumented.

    ``tcp`` forwards to the endpoint's target; ``http-proxy`` speaks HTTP proxy
    to its clients and chains to ``upstream_host:upstream_port`` by hostname."""

    service: str
    upstream_host: str
    upstream_port: int
    scope: str | None  # tcp: fixed; http-proxy: None (classified per flow)
    tool: str | None = None
    mode: str = "tcp"
    route_kind: str = "tcp"
    client: str = "unknown"  # label for connections that did not come from the harness
    resolver: str | None = None  # http-proxy: the egress provider's in-tunnel resolver
    # http-proxy: the egress provider's guard exceptions (corporate's allowlist)
    guard_hosts: tuple[str, ...] = ()
    guard_cidrs: tuple[str, ...] = ()

    @property
    def upstream(self) -> str:
        """The upstream as written in config (``tcp:h:p`` / ``chain:http://h:p``)."""
        if self.mode == "http-proxy":
            return f"chain:http://{self.upstream_host}:{self.upstream_port}"
        return f"tcp:{self.upstream_host}:{self.upstream_port}"

    @property
    def route_upstream(self) -> str:
        """The upstream as flow records carry it in ``route.upstream``."""
        return self.upstream.removeprefix("chain:")


@dataclass(frozen=True)
class Recording:
    """The observe settings a gate's command line carries."""

    record: str = "metadata"
    record_headers: bool = False
    resolve: str = "in-tunnel"
    resolver: str | None = None  # overrides the egress provider's
    exit_url: str | None = None  # set on the one gate that polls exit identity
    rules: bool = False  # the filter grant: read rules.json


def classify_scope(host: str, host_gateway: bool) -> str:
    """§2.5 scope for a configured tcp target, from its shape alone (no lookup)."""
    if host_gateway or host in HOST_GATEWAY_NAMES or host == "localhost":
        return "local"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # A single-label name is a container/service on a docker network; a
        # dotted name is taken to be the internet with no tunnel — the loud case.
        return "local" if "." not in host else "direct"
    return "local" if (ip.is_private or ip.is_loopback or ip.is_link_local) else "direct"


def _split(to: str, name: str) -> tuple[str, int]:
    host, _, port = to.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"endpoint {name!r}: target {to!r} is not host:port")
    return host.strip("[]"), int(port)


def gate_spec(ep: dict[str, Any], egress: dict[str, Any]) -> GateSpec:
    """The gate for one endpoint (``glove.network.endpoint_info``), from its
    target and its manifest's ``observe:`` annotation. A slot target (the
    egress proxy) is gated in ``http-proxy`` mode with the egress provider's
    route, resolver and guard exceptions; anything else in ``tcp`` mode."""
    name = ep["name"]
    raw = ep.get("observe") or {}
    if not isinstance(raw, dict):
        raise ValueError(f"endpoint {name!r}: observe annotation must be a mapping, got {raw!r}")
    unknown = set(raw) - ANNOTATION_KEYS
    if unknown:
        raise ValueError(f"endpoint {name!r}: unknown observe keys {sorted(unknown)}")
    slot = ep.get("target_kind") == "slot"
    mode = raw.get("mode", "http-proxy" if slot else "tcp")
    if mode not in MODES:
        raise ValueError(f"endpoint {name!r}: unknown observe.mode {mode!r} (supported: {', '.join(MODES)})")
    tool = raw.get("tool") or DEFAULT_TOOLS.get(name)
    # off a harness hop, the peer is the declaring extension's own sidecar; on
    # one, a peer that did not come through the harness ingress is unknown
    own = "unknown" if ep.get("harness", True) or ep["extension"] == "harness" else ep["extension"]
    client = raw.get("client", own)
    problem = client_problem(client) if isinstance(client, str) else f"got {client!r}"
    if problem:
        raise ValueError(f"endpoint {name!r}: observe.client labels peers that are NOT the harness — {problem}")
    host, port = _split(ep["target"], name)
    if mode == "http-proxy":
        if "scope" in raw:
            raise ValueError(f"endpoint {name!r}: observe.scope is classified per destination in http-proxy mode")
        route = raw.get("route") or (egress.get("route") if slot else None)
        if route not in ROUTES:
            raise ValueError(
                f"endpoint {name!r}: http-proxy mode needs a route — what the chained upstream really is: one "
                f"of {ROUTES}. glove cannot verify a tunnel exists, so it will not assume one."
            )
        resolver = egress.get("resolver") if slot else None
        return GateSpec(
            service=name, upstream_host=host, upstream_port=port, scope=None, tool=tool, mode=mode,
            route_kind=route, client=client, resolver=None if resolver in (None, "", "none") else str(resolver),
            guard_hosts=tuple(egress.get("guard_hosts") or ()) if slot else (),
            guard_cidrs=tuple(egress.get("guard_cidrs") or ()) if slot else (),
        )
    if "route" in raw or "upstream" in raw:
        raise ValueError(f"endpoint {name!r}: observe.route/upstream apply to http-proxy mode only")
    scope = raw.get("scope") or classify_scope(host, bool(ep.get("host_gateway")))
    if scope not in SCOPES:
        raise ValueError(f"endpoint {name!r}: observe.scope must be one of {SCOPES}, got {scope!r}")
    return GateSpec(service=name, upstream_host=host, upstream_port=port, scope=scope, tool=tool, client=client)


def ingress_alias(container: str) -> str:
    """Per-network alias a gate carries on the harness network only.

    The gate resolves it to learn which local address is its harness-network
    one, so a connection landing there is labelled ``client: harness``."""
    return f"{container}-ingress"


def forward_command(gate: GateSpec, rec: Recording, *, session: str, listen: int,
                    ingress: str | None) -> list[str]:
    cmd = [
        "forward",
        "--service", gate.service,
        "--mode", gate.mode,
        "--listen", str(listen),
        "--upstream", gate.upstream,
        "--route", gate.route_kind,
        "--env", session,
        "--session", session,
        "--resolve", rec.resolve,
        "--events", EVENTS_SOCKET,
        "--client", gate.client,
        "--record", rec.record,
    ]
    if rec.rules:  # the filter grant; observe-only gates never read a rules file
        cmd += ["--rules", RULES_FILE]
    if rec.record_headers:
        cmd.append("--record-headers")
    if ingress:
        cmd += ["--ingress-alias", ingress]
    if gate.mode == "http-proxy":
        resolver = rec.resolver or gate.resolver
        if rec.resolve == "in-tunnel" and resolver:
            cmd += ["--resolver", resolver]
        if rec.exit_url:
            cmd += ["--exit-url", rec.exit_url]
        for h in gate.guard_hosts:
            cmd += ["--guard-allow-host", h]
        for c in gate.guard_cidrs:
            cmd += ["--guard-allow-cidr", c]
    if gate.scope:
        cmd += ["--scope", gate.scope]
    if gate.tool:
        cmd += ["--tool", gate.tool]
    return cmd


def collect_command(*, rules: bool) -> list[str]:
    return ["collect", "--net-dir", NET_DIR, "--events", EVENTS_SOCKET, *(["--rules", RULES_FILE] if rules else [])]


def facts(gate: GateSpec, *, harness: bool) -> dict[str, Any]:
    """The ``session.json`` entry fields for a gated endpoint (handoff §8)."""
    return {
        "mode": gate.mode,
        "tool": gate.tool,
        "scope": gate.scope,  # null in http-proxy mode: classified per flow
        "upstream": gate.upstream,
        "route": {"kind": gate.route_kind, "upstream": gate.route_upstream},
        "client": "harness" if harness else gate.client,
        "summary": f"netgate {gate.mode}, tool={gate.tool}, scope={gate.scope or 'per-destination'}",
    }


def rules_file_problem(control: Path) -> str | None:
    """Why the gate would reject ``control/rules.json`` as unreadable, or None.
    Checked at launch because the gate runs as this same user."""
    from .netgate.policy import PolicyError, read_file

    try:
        read_file(Path(control) / "rules.json")
    except PolicyError as e:
        return str(e)
    return None


__all__ = [
    "CONTROL_DIR", "EVENTS_DIR", "NET_DIR", "GateSpec", "Recording", "classify_scope", "collect_command",
    "facts", "forward_command", "gate_spec", "ingress_alias", "rules_file_problem",
]
