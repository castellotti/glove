"""Forwarder sidecars and session networks.

The harness container is attached only to an `internal: true` bridge, so it has
no route off the host and cannot see host localhost or the LAN. Everything it
may reach is bridged in by single-purpose forwarders, one per extension
endpoint, making the "network permissions" an explicit allow-list.

A forwarder is `socat` by default. When an extension fills the `forwarder`
slot (observe's netgate), its `forwarder` hook renders the forwarder instead —
same name, networks and port, a drop-in — and core hardens what it returns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .config import ConfigError

if TYPE_CHECKING:
    from .config import Config
    from .extensions import Composition, Endpoint


@dataclass(frozen=True)
class Sidecar:
    role: str  # short role name, e.g. "llm"; service = glove-<session>-<role>
    listen_port: int  # port exposed on its listen network(s)
    target: str  # host:port the sidecar forwards to
    host_gateway: bool = False  # needs extra_hosts host.docker.internal:host-gateway
    # False: a listener for egress-stack components only (never the harness net)
    harness: bool = True
    # Session-scoped networks it also joins (the network its target is on, extra
    # listen networks) — full names.
    networks: tuple[str, ...] = ()
    # Extra names on the harness network (e.g. a cloud API hostname).
    aliases: tuple[str, ...] = ()
    # Set when the `forwarder` provider implements it: the service fragment its
    # hook returned (hardened by core), what it reports about the forwarder
    # (session.json), and extra harness-network aliases it asked for.
    impl: dict[str, Any] | None = None
    facts: dict[str, Any] = field(default_factory=dict)
    impl_aliases: tuple[str, ...] = ()

    @property
    def command(self) -> str:
        # Force IPv4 on both ends. host-gateway targets (host.docker.internal)
        # get BOTH an A and AAAA record in /etc/hosts; socat's generic `TCP:`
        # prefers the IPv6 address, which has no route on the Docker Desktop VM
        # ("Network unreachable"). TCP4 pins the reachable IPv4 path.
        return f"TCP4-LISTEN:{self.listen_port},fork,reuseaddr TCP4:{self.target}"


@dataclass(frozen=True)
class NetworkPlan:
    internal_network: str  # name of the harness-only internal bridge
    sidecars: list[Sidecar] = field(default_factory=list)
    # A normal (non-internal) bridge that host-gateway sidecars join so they have
    # a route to host.docker.internal. The internal net alone has no such route,
    # so socat would fail with "Network unreachable". The harness never joins it.
    hostgw_network: str | None = None
    # Session-owned networks from extensions: full name → internal?
    session_networks: dict[str, bool] = field(default_factory=dict)
    # Session-owned network name → its /27 of the session subnet (empty: the
    # runtime's default pools).
    subnets: dict[str, str] = field(default_factory=dict)

    @property
    def socat(self) -> list[Sidecar]:
        return [s for s in self.sidecars if s.impl is None]

    @property
    def implemented(self) -> list[Sidecar]:
        return [s for s in self.sidecars if s.impl is not None]


SLICE_PREFIX = 27  # 8 networks per /24 session subnet, 29 usable addresses each


def slice_subnet(subnet: str, networks: list[str]) -> dict[str, str]:
    """Deterministic /27 slices of a session's subnet, one per owned network
    (in the given order), so a session's addresses never depend on what else
    the runtime has allocated."""
    import ipaddress

    slices = list(ipaddress.ip_network(subnet).subnets(new_prefix=SLICE_PREFIX))
    if len(networks) > len(slices):
        raise ConfigError(f"session subnet {subnet} has room for {len(slices)} networks; "
                          f"this session needs {len(networks)}")
    return {n: str(s) for n, s in zip(networks, slices, strict=False)}


def endpoint_info(ep: Endpoint, session: str, networks: tuple[str, ...]) -> dict[str, Any]:
    """What a `forwarder` hook is told about one endpoint (plain data)."""
    return {
        "name": ep.name, "extension": ep.extension, "port": ep.port,
        "target": f"{ep.target.host}:{ep.target.port}", "target_kind": ep.target.kind,
        "harness": ep.harness, "host_gateway": ep.target.kind == "host", "networks": list(networks),
        "aliases": list(ep.aliases), "observe": ep.observe, "interpose": ep.interpose,
        "container": ep.host(session),
    }


def build_network_plan(cfg: Config, session: str, comp: Composition | None = None) -> NetworkPlan:
    """Extension endpoints → forwarder sidecars (socat, or the forwarder slot's
    implementation), plus the session's networks."""
    from .extensions import forwarder_service, network_name

    internal_net = f"glove-{session}-net"
    sidecars: list[Sidecar] = []
    session_networks: dict[str, bool] = {}
    for ep in comp.endpoints if comp else []:
        if ep.interpose and not ep.interposed:
            continue
        nets = []
        for logical in (ep.target.network, *ep.listen_networks):
            if logical and logical not in ("net", "hostgw") and network_name(session, logical) not in nets:
                nets.append(network_name(session, logical))
        impl = forwarder_service(comp, endpoint_info(ep, session, tuple(nets)))
        sidecars.append(Sidecar(
            role=ep.name, listen_port=ep.port, target=f"{ep.target.host}:{ep.target.port}",
            host_gateway=ep.target.kind == "host", harness=ep.harness, networks=tuple(nets),
            aliases=ep.aliases, impl=impl[0] if impl else None, facts=impl[1] if impl else {},
            impl_aliases=tuple(impl[2]) if impl else (),
        ))
    for logical, spec in (comp.networks if comp else {}).items():
        if logical not in ("net", "hostgw"):
            session_networks[network_name(session, logical)] = bool(spec.get("internal", True))

    # Any sidecar that reaches host.docker.internal needs a routable bridge.
    hostgw_network = f"glove-{session}-hostgw" if any(s.host_gateway for s in sidecars) else None
    owned = [internal_net, *([hostgw_network] if hostgw_network else []), *sorted(session_networks)]
    plan = NetworkPlan(
        subnets=slice_subnet(cfg.subnet, owned) if cfg.subnet else {},
        internal_network=internal_net,
        sidecars=sidecars,
        hostgw_network=hostgw_network,
        session_networks=session_networks,
    )
    if comp is not None:
        comp.forwarders = [
            {"service": s.role, "listen": f"glove-{session}-{s.role}:{s.listen_port}", "harness": s.harness,
             "target": s.target, "observed": s.impl is not None, **s.facts}
            for s in sidecars
        ]
    return plan
