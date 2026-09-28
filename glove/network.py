"""Network profiles + forwarder sidecar synthesis.

The harness container is attached only to an `internal: true` bridge, so it has
no route off the host and cannot see host localhost or the LAN. Everything it
may reach is bridged in by single-purpose `socat` forwarder sidecars, making the
"network permissions" an explicit allow-list.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .config import Config, ConfigError, Service
from .observe import GateSpec, ObserveSettings, gate_spec_for, parse_observe

if TYPE_CHECKING:
    from .extensions import Composition, Endpoint


@dataclass(frozen=True)
class Sidecar:
    role: str  # short role name, e.g. "llm"; service = glove-<session>-<role>
    listen_port: int  # port exposed on the internal net
    target: str  # host:port the sidecar forwards to
    join_network: str | None = None  # external docker network to also join
    host_gateway: bool = False  # needs extra_hosts host.docker.internal:host-gateway
    # Set when the service is observed: the sidecar runs the netgate `forward`
    # role instead of socat (same name, networks and port — a drop-in).
    gate: GateSpec | None = None
    # False: joined only to join_network (never the harness's internal net)
    harness: bool = True
    # Session-scoped networks it also joins (extension endpoints: the network
    # its target is on, extra listen networks) — full names.
    networks: tuple[str, ...] = ()
    # Extra names on the harness network (e.g. a cloud API hostname).
    aliases: tuple[str, ...] = ()

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
    external_networks: list[str] = field(default_factory=list)  # pre-existing nets to reference
    harness_extra_networks: list[str] = field(default_factory=list)  # nets the harness also joins
    harness_host_gateway: bool = False  # escape hatch: harness reaches host directly
    # A normal (non-internal) bridge that host-gateway sidecars join so they have
    # a route to host.docker.internal. The internal net alone has no such route,
    # so socat would fail with "Network unreachable". The harness never joins it.
    hostgw_network: str | None = None
    # Session-owned networks from extensions: full name → internal?
    session_networks: dict[str, bool] = field(default_factory=dict)
    observe: ObserveSettings | None = None  # set iff observation is enabled
    # Session-owned network name → its /27 of the session subnet (empty: the
    # runtime's default pools).
    subnets: dict[str, str] = field(default_factory=dict)

    @property
    def gated(self) -> list[Sidecar]:
        """Sidecars running the netgate forwarder (only ever when observing)."""
        return [s for s in self.sidecars if s.gate is not None]

    @property
    def exit_gate(self) -> Sidecar | None:
        """The one proxy gate that polls exit identity (so records aren't duplicated)."""
        return next((s for s in self.gated if s.gate.mode == "http-proxy"), None)


def _sidecar_for(svc: Service, gate: GateSpec | None = None) -> Sidecar:
    return Sidecar(
        role=svc.name,
        listen_port=svc.port,
        target=svc.to,
        join_network=svc.join_network,
        host_gateway=svc.host_gateway,
        gate=gate,
        harness=svc.harness,
    )


def endpoint_service(ep: Endpoint) -> Service:
    """An extension endpoint as the forwarder spec the render path consumes."""
    return Service(
        name=ep.name, to=f"{ep.target.host}:{ep.target.port}", port=ep.port,
        host_gateway=ep.target.kind == "host", observe=ep.observe,
    )


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


def build_network_plan(cfg: Config, session: str, comp: Composition | None = None) -> NetworkPlan:
    """Translate net profiles, services and extension endpoints into concrete
    sidecars and networks."""
    from .extensions import network_name

    internal_net = f"glove-{session}-net"
    profiles = cfg.net or ["none"]

    sidecars: list[Sidecar] = []
    external: list[str] = []
    harness_extra: list[str] = []
    harness_host_gateway = False

    wants_services = "service" in profiles or any(
        p.startswith("service:") for p in profiles
    )
    # Security default is no network: a forwarder sidecar (which grants the
    # harness a route to an endpoint) renders ONLY when the operator has
    # explicitly opted in with the `service` net profile. Declaring `services:`
    # without it is a contradiction — the old behaviour silently dropped the
    # service AND still pointed the harness config at the (now dead) endpoint,
    # so the first turn failed with an opaque connection-refused. Fail loudly and
    # early instead of either dropping silently or auto-granting network.
    if cfg.services and not wants_services:
        names = ", ".join(s.name for s in cfg.services)
        raise ConfigError(
            f"services are declared ({names}) but net={profiles} does not permit "
            "them — add 'service' to `net` (e.g. net: [service]) to render their "
            "forwarder sidecars, or remove the services. glove grants no network "
            "unless explicitly requested."
        )
    settings: ObserveSettings | None = parse_observe(cfg)
    if wants_services:
        for svc in cfg.services:
            sidecars.append(_sidecar_for(svc, gate_spec_for(svc, cfg, settings)))
            if svc.join_network and svc.join_network not in external:
                external.append(svc.join_network)
    session_networks: dict[str, bool] = {}
    for ep in comp.endpoints if comp else []:
        if any(s.role == ep.name for s in sidecars):
            raise ConfigError(f"endpoint {ep.name!r} (extension {ep.extension!r}) clashes with a declared service")
        nets = []
        for logical in (ep.target.network, *ep.listen_networks):
            if logical and logical not in ("net", "hostgw") and network_name(session, logical) not in nets:
                nets.append(network_name(session, logical))
        svc = endpoint_service(ep)
        sidecars.append(Sidecar(
            role=ep.name, listen_port=ep.port, target=svc.to, host_gateway=svc.host_gateway,
            gate=gate_spec_for(svc, cfg, settings), harness=ep.harness, networks=tuple(nets),
            aliases=ep.aliases,
        ))
    for logical, spec in (comp.networks if comp else {}).items():
        if logical not in ("net", "hostgw"):
            session_networks[network_name(session, logical)] = bool(spec.get("internal", True))

    for p in profiles:
        if p.startswith("docker:"):
            netname = p.split(":", 1)[1]
            if netname not in external:
                external.append(netname)
            if netname not in harness_extra:
                harness_extra.append(netname)
        elif p == "lan":
            harness_host_gateway = True
        elif p == "internet":
            # Egress-proxy sidecar (Tor/gluetun-style) is future work; flag the
            # harness to route via a bridge with egress rather than internal-only.
            harness_host_gateway = True

    if settings is not None and settings.exit_identity == "via-proxy" and not any(
        s.gate and s.gate.mode == "http-proxy" for s in sidecars
    ):
        raise ConfigError(
            "observe.exit_identity: via-proxy needs a service in http-proxy mode — the exit is "
            "fetched through that service's chained upstream"
        )

    # Any sidecar that reaches host.docker.internal needs a routable bridge.
    hostgw_network = (
        f"glove-{session}-hostgw" if any(s.host_gateway for s in sidecars) else None
    )

    owned = [internal_net, *([hostgw_network] if hostgw_network else []), *sorted(session_networks)]
    return NetworkPlan(
        subnets=slice_subnet(cfg.subnet, owned) if cfg.subnet else {},
        internal_network=internal_net,
        sidecars=sidecars,
        external_networks=external,
        harness_extra_networks=harness_extra,
        harness_host_gateway=harness_host_gateway,
        hostgw_network=hostgw_network,
        session_networks=session_networks,
        observe=settings,
    )
