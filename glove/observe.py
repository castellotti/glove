"""Network observability — the host-side half (config, plan, render facts).

Turns ``observe:`` config into gate specs for the render path, lays out the
session's ``net/`` directory, writes ``net/session.json``, enforces that ``net/``
is invisible to the harness, and builds the netgate image. The in-container half
is ``glove.netgate``. Design: ``docs/planning/network-observability.md``; wire
contract: ``docs/planning/network-observability-layman-handoff.md``.

Nothing in this module resolves a hostname. Classification is by the *shape* of
the configured target (IP literal, single-label container name, the host
gateway), never by a lookup — ``tests/test_netgate_invariants.py`` keeps it that
way.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .config import Config, ConfigError, Service
from .hardening import HardeningError
from .netgate import EVENTS_DIR, EVENTS_SOCKET, GATE_VERSION, NET_DIR, SCHEMA_VERSION
from .netgate.records import iso_utc
from .netgate.writer import write_json_atomic

if TYPE_CHECKING:
    from .network import Sidecar
    from .plan import SessionPlan

NETGATE_SRC = Path(__file__).parent / "netgate"
NETGATE_DOCKERFILE = Path(__file__).parent / "templates" / "netgate.Dockerfile"

OBSERVE_KEYS = frozenset({"enabled", "record", "resolve", "rotate_mb", "keep"})
SERVICE_OBSERVE_KEYS = frozenset({"mode", "tool", "scope", "upstream"})
SCOPES = ("local", "tunnelled", "direct")
# Planned listener modes and the milestone that lands them; only `tcp` is live.
LATER_MODES = {"http-proxy": "M2", "socks5": "M2"}
# §2.4 tool labels by conventional service name (the llm service is added from
# `llm_service`). An explicit `observe.tool` always wins.
DEFAULT_TOOLS = {"proxy": "web_fetch", "search": "web_search", "browser": "browser"}
HOST_GATEWAY_NAMES = frozenset({"host.docker.internal", "host.containers.internal"})


@dataclass(frozen=True)
class ObserveSettings:
    record: str = "metadata"
    resolve: str = "in-tunnel"
    rotate_bytes: int = 64 * 1024 * 1024
    keep: int = 8


@dataclass(frozen=True)
class GateSpec:
    """How one service's forwarder is instrumented (M1: tcp mode only)."""

    service: str
    upstream_host: str
    upstream_port: int
    scope: str
    tool: str | None = None
    mode: str = "tcp"

    @property
    def upstream(self) -> str:
        return f"tcp:{self.upstream_host}:{self.upstream_port}"

    @property
    def route_kind(self) -> str:
        return "tcp"


# --- config ----------------------------------------------------------------


def parse_observe(cfg: Config) -> ObserveSettings | None:
    """Validated settings when observation is enabled, else None."""
    raw: Any = cfg.observe
    if raw in (None, False, {}):
        return None
    if raw is True:
        raw = {"enabled": True}
    if not isinstance(raw, dict):
        raise ConfigError(f"observe must be a mapping, got {raw!r}")
    unknown = set(raw) - OBSERVE_KEYS
    if unknown:
        raise ConfigError(f"unknown observe keys: {sorted(unknown)} (known: {sorted(OBSERVE_KEYS)})")
    if not raw.get("enabled", False):
        return None
    record = raw.get("record", "metadata")
    if record == "full":
        raise ConfigError("observe.record: full is not implemented yet (milestone M5); use metadata")
    if record != "metadata":
        raise ConfigError(f"observe.record must be metadata|full, got {record!r}")
    resolve = raw.get("resolve", "in-tunnel")
    if resolve not in ("in-tunnel", "none"):
        # There is deliberately no `host`: destinations are never resolved on
        # the host (§1.2 constraint 2).
        raise ConfigError(f"observe.resolve must be in-tunnel|none, got {resolve!r}")
    try:
        rotate_mb = float(raw.get("rotate_mb", 64))
        keep = int(raw.get("keep", 8))
    except (TypeError, ValueError) as e:
        raise ConfigError(f"observe.rotate_mb/keep must be numbers: {e}") from e
    if rotate_mb <= 0 or keep < 0:
        raise ConfigError("observe.rotate_mb must be > 0 and observe.keep >= 0")
    return ObserveSettings(
        record=record, resolve=resolve, rotate_bytes=int(rotate_mb * 1024 * 1024), keep=keep
    )


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


def _split_target(to: str, service: str) -> tuple[str, int]:
    host, _, port = to.rpartition(":")
    if not host or not port.isdigit():
        raise ConfigError(f"service {service!r}: target {to!r} is not host:port")
    return host.strip("[]"), int(port)


def gate_spec_for(svc: Service, cfg: Config, settings: ObserveSettings | None) -> GateSpec | None:
    """The gate spec for ``svc``, or None when it stays a plain socat forwarder.

    With observation enabled every service is gated in ``tcp`` mode unless it
    opts out with ``observe: false``; an ``observe:`` mapping annotates it.
    """
    raw: Any = svc.observe
    if settings is None:
        if raw not in (None, False):
            raise ConfigError(
                f"service {svc.name!r} has an observe block but observe.enabled is not "
                "true — enable it at the top level (observe: {enabled: true}) or remove it."
            )
        return None
    if raw is False:
        return None
    if raw in (None, True):
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"service {svc.name!r}: observe must be a mapping or false, got {raw!r}")
    unknown = set(raw) - SERVICE_OBSERVE_KEYS
    if unknown:
        raise ConfigError(f"service {svc.name!r}: unknown observe keys {sorted(unknown)}")

    mode = raw.get("mode", "tcp")
    if mode in LATER_MODES:
        raise ConfigError(
            f"service {svc.name!r}: observe.mode {mode!r} is not implemented yet "
            f"(milestone {LATER_MODES[mode]}); M1 supports tcp"
        )
    if mode != "tcp":
        raise ConfigError(f"service {svc.name!r}: unknown observe.mode {mode!r}")

    host, port = _split_target(svc.to, svc.name)
    upstream = raw.get("upstream")
    if upstream is not None and upstream != f"tcp:{svc.to}":
        raise ConfigError(
            f"service {svc.name!r}: observe.upstream {upstream!r} is not supported in M1 — "
            f"tcp mode forwards to the service target (tcp:{svc.to}); chain:/direct land in M2"
        )

    scope = raw.get("scope") or classify_scope(host, svc.host_gateway)
    if scope not in SCOPES:
        raise ConfigError(f"service {svc.name!r}: observe.scope must be one of {SCOPES}, got {scope!r}")

    tool = raw.get("tool")
    if tool is None:
        tool = "llm" if svc.name == cfg.llm_service else DEFAULT_TOOLS.get(svc.name)
    return GateSpec(service=svc.name, upstream_host=host, upstream_port=port, scope=scope, tool=tool)


# --- render ----------------------------------------------------------------


def ingress_alias(session: str, role: str) -> str:
    """Per-network alias a gated forwarder carries on the internal net only.

    The forwarder resolves it to learn which local address is its internal-network
    one, so a connection landing there is labelled ``client: harness``."""
    return f"glove-{session}-{role}-ingress"


def forward_command(plan: SessionPlan, sidecar: Sidecar) -> list[str]:
    gate = sidecar.gate
    assert gate is not None and plan.observe is not None
    cmd = [
        "forward",
        "--service", gate.service,
        "--listen", str(sidecar.listen_port),
        "--upstream", gate.upstream,
        "--env", plan.env_id,
        "--session", plan.session,
        "--scope", gate.scope,
        "--resolve", plan.observe.resolve,
        "--ingress-alias", ingress_alias(plan.session, sidecar.role),
        "--events", EVENTS_SOCKET,
    ]
    if gate.tool:
        cmd += ["--tool", gate.tool]
    return cmd


def collect_command() -> list[str]:
    return ["collect", "--net-dir", NET_DIR, "--events", EVENTS_SOCKET]


def render_context(plan: SessionPlan) -> dict:
    """Template variables for the gate services (empty-ish when not observing)."""
    gated = [s for s in plan.network.sidecars if s.gate is not None]
    return {
        "netgate": bool(gated) and plan.observe is not None,
        "netgate_image": plan.netgate_image,
        "net_host_dir": plan.net_host_dir,
        "net_container_dir": NET_DIR,
        "events_dir": EVENTS_DIR,
        "gate_commands": {s.role: forward_command(plan, s) for s in gated} if plan.observe else {},
        "gate_aliases": {s.role: ingress_alias(plan.session, s.role) for s in gated},
        "collect_command": collect_command(),
    }


# --- net/ layout -----------------------------------------------------------


def net_dir(session_dir: Path) -> Path:
    """``<session>/net`` — a sibling of ``home/``, never mounted into the harness."""
    return Path(session_dir) / "net"


def ensure_net_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _within(child: str, parent: str) -> bool:
    return child == parent or child.startswith(parent.rstrip(os.sep) + os.sep)


def validate_net_isolation(plan: SessionPlan) -> None:
    """Refuse to render if the agent could see or write its own flow record.

    ``net/`` must share no path with any harness bind: not the home (which a
    ``config_home_source`` may relocate anywhere), not /work, not an add-dir. A
    harness mount at or above ``net/`` would let the agent read its surveillance
    record; one inside it would let the agent forge it. Not waivable."""
    if plan.observe is None:
        return
    if not plan.net_host_dir:
        raise HardeningError("observe is enabled but the session net/ dir was not materialised")
    net = os.path.realpath(plan.net_host_dir)
    binds = [("home", plan.home_dir)]
    binds += [(m.container_path, m.host_path) for m in plan.mounts]
    if plan.policies_host_dir:
        binds.append(("enforcer", plan.policies_host_dir))
    for label, host_path in binds:
        rp = os.path.realpath(host_path)
        if _within(net, rp) or _within(rp, net):
            raise HardeningError(
                f"refusing to render: observe net/ dir {net} overlaps the harness mount "
                f"{rp} ({label}) — the agent could read or forge its own flow record. "
                "Move the mount (or config_home_source) outside the session's net/."
            )


def session_facts(plan: SessionPlan) -> dict:
    """Static ``net/session.json``: what Layman needs before any flow arrives —
    including services that have not been used yet (handoff §8)."""
    assert plan.observe is not None
    services = []
    for s in plan.network.sidecars:
        entry: dict[str, Any] = {
            "service": s.role,
            "listen": f"glove-{plan.session}-{s.role}:{s.listen_port}",
            "observed": s.gate is not None,
        }
        if s.gate is not None:
            entry.update(
                mode=s.gate.mode,
                tool=s.gate.tool,
                scope=s.gate.scope,
                upstream=s.gate.upstream,
                route={"kind": s.gate.route_kind, "upstream": s.gate.upstream},
            )
        services.append(entry)
    return {
        "v": SCHEMA_VERSION,
        "type": "session",
        "env": plan.env_id,
        "session": plan.session,
        "harness": plan.profile.name,
        "gate": GATE_VERSION,
        "image": plan.netgate_image,
        "record": plan.observe.record,
        "resolve": plan.observe.resolve,
        "upstream_kind": "tcp",
        "rotate": {"max_bytes": plan.observe.rotate_bytes, "keep": plan.observe.keep},
        "rendered_at": iso_utc(),
        "services": services,
    }


def write_session_facts(path: Path, facts: dict) -> None:
    if not write_json_atomic(Path(path) / "session.json", facts):
        raise OSError(f"could not write {path}/session.json")


# --- image -----------------------------------------------------------------


def _netgate_sources() -> list[Path]:
    return sorted(p for p in NETGATE_SRC.glob("*.py") if p.is_file())


def netgate_image() -> str:
    """``glove/netgate:<version>-<hash>`` — the hash covers the gate sources and
    Dockerfile, so any change to the gate yields a new tag (and a rebuild)."""
    h = hashlib.sha256()
    for p in [NETGATE_DOCKERFILE, *_netgate_sources()]:
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return f"glove/netgate:{GATE_VERSION}-{h.hexdigest()[:10]}"


def build_netgate(provider: str, *, force: bool = False, console=None) -> str:
    tag = netgate_image()
    exists = subprocess.run(
        [provider, "image", "inspect", tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0
    if exists and not force:
        return tag
    if console is not None:
        console.print(f"[bold]building netgate image[/bold] {tag}")
    with tempfile.TemporaryDirectory(prefix="glove-netgate-") as ctx:
        ctx_dir = Path(ctx)
        shutil.copy(NETGATE_DOCKERFILE, ctx_dir / "Dockerfile")
        pkg = ctx_dir / "netgate"
        pkg.mkdir()
        for src in _netgate_sources():
            shutil.copy(src, pkg / src.name)
        subprocess.run([provider, "build", "-t", tag, str(ctx_dir)], check=True)
    return tag
