"""Network profiles + forwarder sidecar synthesis.

The harness container is attached only to an `internal: true` bridge, so it has
no route off the host and cannot see host localhost or the LAN. Everything it
may reach is bridged in by single-purpose `socat` forwarder sidecars, making the
"network permissions" an explicit allow-list.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Config, ConfigError, Service


@dataclass(frozen=True)
class Sidecar:
    role: str  # short role name, e.g. "llm"; service = glove-<session>-<role>
    listen_port: int  # port exposed on the internal net
    target: str  # host:port the sidecar forwards to
    join_network: str | None = None  # external docker network to also join
    host_gateway: bool = False  # needs extra_hosts host.docker.internal:host-gateway

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
    egress_network: str | None = None


def _sidecar_for(svc: Service) -> Sidecar:
    return Sidecar(
        role=svc.name,
        listen_port=svc.port,
        target=svc.to,
        join_network=svc.join_network,
        host_gateway=svc.host_gateway,
    )


def build_network_plan(cfg: Config, session: str) -> NetworkPlan:
    """Translate net profiles + services into concrete sidecars and networks."""
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
    if wants_services:
        for svc in cfg.services:
            sidecars.append(_sidecar_for(svc))
            if svc.join_network and svc.join_network not in external:
                external.append(svc.join_network)

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

    # Any sidecar that reaches host.docker.internal needs a routable bridge.
    egress_network = (
        f"glove-{session}-egress" if any(s.host_gateway for s in sidecars) else None
    )

    return NetworkPlan(
        internal_network=internal_net,
        sidecars=sidecars,
        external_networks=external,
        harness_extra_networks=harness_extra,
        harness_host_gateway=harness_host_gateway,
        egress_network=egress_network,
    )
