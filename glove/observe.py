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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .config import Config, ConfigError, Service
from .hardening import HardeningError
from .netgate import (
    CLIENTS,
    CONTROL_DIR,
    EVENTS_DIR,
    EVENTS_SOCKET,
    GATE_VERSION,
    MODES,
    NET_DIR,
    RECORD_MODES,
    RESOLVE_MODES,
    ROTATE_BYTES,
    ROTATE_KEEP,
    ROUTES,
    RULES_FILE,
    SCHEMA_VERSION,
    SCOPES,
)
from .netgate.records import iso_utc
from .netgate.writer import write_json_atomic

if TYPE_CHECKING:
    from .network import Sidecar
    from .plan import SessionPlan

NETGATE_SRC = Path(__file__).parent / "netgate"
NETGATE_DOCKERFILE = Path(__file__).parent / "templates" / "netgate.Dockerfile"

OBSERVE_KEYS = frozenset({
    "enabled", "record", "record_headers", "resolve", "rotate_mb", "keep", "retain",
    "resolver", "exit_identity", "exit_identity_url",
})
DEFAULT_EXIT_URL = "https://am.i.mullvad.net/json"
SERVICE_OBSERVE_KEYS = frozenset({"mode", "tool", "scope", "upstream", "route", "client"})
# §2.4 tool labels by conventional service name (the llm service is added from
# `llm_service`). An explicit `observe.tool` always wins.
DEFAULT_TOOLS = {"proxy": "web_fetch", "search": "web_search", "browser": "browser"}
HOST_GATEWAY_NAMES = frozenset({"host.docker.internal", "host.containers.internal"})


@dataclass(frozen=True)
class ObserveSettings:
    record: str = "metadata"
    resolve: str = "in-tunnel"
    rotate_bytes: int = ROTATE_BYTES
    keep: int = ROTATE_KEEP
    record_headers: bool = False  # record: full only — request headers, secrets redacted
    retain_s: int | None = None  # expire flow/exit files older than this
    resolver: str | None = None  # dns://h:p | tor-socks://h:p — queried in-tunnel by proxy gates
    exit_identity: str = "none"  # "via-proxy" | "none"
    exit_url: str = DEFAULT_EXIT_URL


@dataclass(frozen=True)
class GateSpec:
    """How one service's forwarder is instrumented.

    ``tcp`` forwards to the service target; ``http-proxy`` speaks HTTP proxy to
    the harness and chains to ``upstream_host:upstream_port`` by hostname."""

    service: str
    upstream_host: str
    upstream_port: int
    scope: str | None  # tcp: fixed; http-proxy: None (classified per flow)
    tool: str | None = None
    mode: str = "tcp"
    route_kind: str = "tcp"
    client: str = "unknown"  # label for connections that did not come from the harness

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
    if record not in RECORD_MODES:
        raise ConfigError(f"observe.record must be metadata|full, got {record!r}")
    record_headers = raw.get("record_headers", False)
    if not isinstance(record_headers, bool):
        raise ConfigError("observe.record_headers must be true|false")
    if record_headers and record != "full":
        raise ConfigError("observe.record_headers needs observe.record: full")
    retain_s = _duration(raw["retain"]) if raw.get("retain") not in (None, "none") else None
    resolve = raw.get("resolve", "in-tunnel")
    if resolve not in RESOLVE_MODES:
        # There is deliberately no `host`: destinations are never resolved on
        # the host (§1.2 constraint 2).
        raise ConfigError(f"observe.resolve must be in-tunnel|none, got {resolve!r}")
    try:
        rotate_mb = float(raw.get("rotate_mb", ROTATE_BYTES // (1024 * 1024)))
        keep = int(raw.get("keep", ROTATE_KEEP))
    except (TypeError, ValueError) as e:
        raise ConfigError(f"observe.rotate_mb/keep must be numbers: {e}") from e
    if rotate_mb <= 0 or keep < 0:
        raise ConfigError("observe.rotate_mb must be > 0 and observe.keep >= 0")
    resolver = raw.get("resolver")
    if resolver in ("none", ""):
        resolver = None
    if resolver is not None:
        from .netgate.resolver import from_url

        try:
            from_url(str(resolver))  # parse only: nothing is resolved here
        except ValueError as e:
            raise ConfigError(f"observe.resolver: {e}") from e
        if resolve == "none":
            raise ConfigError("observe.resolver is set but observe.resolve is none — pick one")
    exit_identity = raw.get("exit_identity", "none")
    if exit_identity not in ("via-proxy", "none"):
        raise ConfigError(
            f"observe.exit_identity must be via-proxy|none, got {exit_identity!r} "
            "(gluetun:// needs a control-server credential and is not wired yet)"
        )
    exit_url = raw.get("exit_identity_url", DEFAULT_EXIT_URL)
    if not isinstance(exit_url, str) or not exit_url.startswith("https://"):
        raise ConfigError("observe.exit_identity_url must be an https:// URL")
    return ObserveSettings(
        record=record, resolve=resolve, rotate_bytes=int(rotate_mb * 1024 * 1024), keep=keep,
        resolver=resolver, exit_identity=exit_identity, exit_url=exit_url,
        record_headers=record_headers, retain_s=retain_s,
    )


def _duration(v) -> int:
    """``90s``, ``30m``, ``12h``, ``7d`` (or plain seconds) → seconds (>= 60)."""
    import re

    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", str(v))
    if not m:
        raise ConfigError(f"observe.retain must be a duration like 30m, 12h or 7d, got {v!r}")
    secs = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if secs < 60:
        raise ConfigError("observe.retain must be at least 60s")
    return secs


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
    opts out with ``observe: false``; an ``observe:`` mapping annotates it. With
    it disabled, every service is plain socat whatever its annotation says.
    """
    raw: Any = svc.observe
    if settings is None:
        # `observe.enabled` is the master switch: with it off, per-service
        # annotations are inert (still type-checked), so a config can carry them
        # and toggle observation with one key.
        if raw not in (None, False, True) and not isinstance(raw, dict):
            raise ConfigError(f"service {svc.name!r}: observe must be a mapping or false, got {raw!r}")
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
    if mode == "socks5":  # planned, not yet implemented
        raise ConfigError(
            f"service {svc.name!r}: observe.mode {mode!r} is not implemented yet "
            f"(a later milestone); supported: {', '.join(MODES)}"
        )
    if mode not in MODES:
        raise ConfigError(f"service {svc.name!r}: unknown observe.mode {mode!r} (supported: {', '.join(MODES)})")

    tool = raw.get("tool")
    if tool is None:
        tool = "llm" if svc.name == cfg.llm_service else DEFAULT_TOOLS.get(svc.name)
    client = raw.get("client", "unknown")
    if client not in CLIENTS:
        raise ConfigError(
            f"service {svc.name!r}: observe.client labels peers that are NOT the harness — one of "
            f"{CLIENTS}, got {client!r}"
        )

    if mode == "http-proxy":
        return replace(_proxy_gate(svc, raw, tool), client=client)

    host, port = _split_target(svc.to, svc.name)
    upstream = raw.get("upstream")
    if upstream is not None and upstream != f"tcp:{svc.to}":
        raise ConfigError(
            f"service {svc.name!r}: observe.upstream {upstream!r} is not valid in tcp mode — "
            f"tcp mode forwards to the service target (tcp:{svc.to}); use mode: http-proxy "
            "for a chain: upstream"
        )
    if "route" in raw:
        raise ConfigError(f"service {svc.name!r}: observe.route applies to http-proxy mode only")
    scope = raw.get("scope") or classify_scope(host, svc.host_gateway)
    if scope not in SCOPES:
        raise ConfigError(f"service {svc.name!r}: observe.scope must be one of {SCOPES}, got {scope!r}")
    return GateSpec(service=svc.name, upstream_host=host, upstream_port=port, scope=scope, tool=tool,
                    client=client)


def _proxy_gate(svc: Service, raw: dict, tool: str | None) -> GateSpec:
    """``http-proxy`` mode: the harness speaks HTTP proxy to the gate, which
    chains to the upstream proxy — by default the service's own target, so the
    socat-era ``to:`` keeps meaning "where this service goes"."""
    upstream = raw.get("upstream") or f"chain:http://{svc.to}"
    if upstream.startswith("chain:socks5://"):
        raise ConfigError(f"service {svc.name!r}: chain:socks5:// upstreams are not implemented yet")
    if upstream.startswith("direct"):
        raise ConfigError(
            f"service {svc.name!r}: a `direct` upstream (the gate resolving and dialling itself, "
            "plan §4.4) is not implemented — it would need host-side resolution of destinations"
        )
    if not upstream.startswith("chain:http://"):
        raise ConfigError(
            f"service {svc.name!r}: http-proxy mode needs upstream chain:http://<host>:<port>, got {upstream!r}"
        )
    host, port = _split_target(upstream.removeprefix("chain:http://").rstrip("/"), svc.name)
    if "scope" in raw:
        raise ConfigError(
            f"service {svc.name!r}: observe.scope is classified per destination in http-proxy mode; "
            "declare observe.route (vpn|tor|direct) instead"
        )
    route = raw.get("route")
    if route not in ROUTES:
        raise ConfigError(
            f"service {svc.name!r}: http-proxy mode needs observe.route — what the chained upstream "
            f"really is: one of {ROUTES}. glove cannot verify a tunnel exists, so it will not assume "
            "one; `direct` marks every flow as leaving untunnelled."
        )
    return GateSpec(
        service=svc.name, upstream_host=host, upstream_port=port, scope=None, tool=tool,
        mode="http-proxy", route_kind=route,
    )


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
        "--mode", gate.mode,
        "--listen", str(sidecar.listen_port),
        "--upstream", gate.upstream,
        "--route", gate.route_kind,
        "--env", plan.env_id,
        "--session", plan.session,
        "--resolve", plan.observe.resolve,
        "--events", EVENTS_SOCKET,
        "--rules", RULES_FILE,
        "--client", gate.client,
        "--record", plan.observe.record,
    ]
    if plan.observe.record_headers:
        cmd.append("--record-headers")
    if sidecar.harness:
        cmd += ["--ingress-alias", ingress_alias(plan.session, sidecar.role)]
    if gate.mode == "http-proxy":
        if plan.observe.resolve == "in-tunnel" and plan.observe.resolver:
            cmd += ["--resolver", plan.observe.resolver]
        if plan.observe.exit_identity == "via-proxy" and plan.network.exit_gate is sidecar:
            cmd += ["--exit-url", plan.observe.exit_url]
    if gate.scope:
        cmd += ["--scope", gate.scope]
    if gate.tool:
        cmd += ["--tool", gate.tool]
    return cmd


def collect_command() -> list[str]:
    return ["collect", "--net-dir", NET_DIR, "--events", EVENTS_SOCKET, "--rules", RULES_FILE]


def render_context(plan: SessionPlan) -> dict:
    """Template variables for the gate services (empty-ish when not observing)."""
    gated = plan.network.gated
    return {
        "netgate": bool(gated),
        "netgate_image": plan.netgate_image,
        "net_host_dir": plan.net_host_dir,
        "net_container_dir": NET_DIR,
        "control_host_dir": plan.control_host_dir,
        "control_container_dir": CONTROL_DIR,
        "events_dir": EVENTS_DIR,
        "gate_commands": {s.role: forward_command(plan, s) for s in gated},
        "gate_aliases": {s.role: ingress_alias(plan.session, s.role) for s in gated},
        "collect_command": collect_command(),
    }


# --- net/ layout -----------------------------------------------------------


def net_dir(session_dir: Path) -> Path:
    """``<session>/net`` — a sibling of ``home/``, never mounted into the harness."""
    return Path(session_dir) / "net"


def control_dir(env_id: str, session_name: str) -> Path:
    """``~/.glove/control/<env>/<session>/`` — where ``rules.json`` lives. Written
    by Layman or ``glove net block``; mounted read-only into the gate only."""
    from .registry import glove_home

    return glove_home() / "control" / env_id / session_name


def ensure_net_dir(path: Path) -> Path:
    """Create ``path`` as the invoking user, mode 0700. The gate runs as this
    same uid:gid, so this is what lets it write ``net/`` and read ``control/``.

    A directory someone else created (e.g. a root-run Layman on native Linux
    Docker, which the ownership contract forbids) cannot be chmod'ed back; say
    so rather than fail with a bare EPERM."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError as e:
        st = path.stat()
        raise HardeningError(
            f"{path} is owned by uid {st.st_uid}, not by you (uid {os.getuid()}): glove creates it, and "
            f"the netgate runs as your uid and needs it. Fix with: sudo chown {os.getuid()}:{os.getgid()} "
            f"{path} (handoff §3, 'Ownership')"
        ) from e
    return path


def rules_file_problem(control: Path) -> str | None:
    """Why the gate would reject ``control/rules.json`` as unreadable, or None.
    Checked at launch because the gate runs as this same user."""
    from .netgate.policy import PolicyError, read_file

    try:
        read_file(Path(control) / "rules.json")
    except PolicyError as e:
        return str(e)
    return None


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
    if not plan.net_host_dir or not plan.control_host_dir:
        raise HardeningError("observe is enabled but the session net/ or control/ dir was not materialised")
    binds = [("home", plan.home_dir)]
    binds += [(m.container_path, m.host_path) for m in plan.mounts]
    if plan.policies_host_dir:
        binds.append(("enforcer", plan.policies_host_dir))
    for what, guarded, harm in (
        ("observe net/", plan.net_host_dir, "read or forge its own flow record"),
        ("control/ (rules.json)", plan.control_host_dir, "read or rewrite its own network rules"),
    ):
        g = os.path.realpath(guarded)
        for label, host_path in binds:
            rp = os.path.realpath(host_path)
            if _within(g, rp) or _within(rp, g):
                raise HardeningError(
                    f"refusing to render: {what} dir {g} overlaps the harness mount "
                    f"{rp} ({label}) — the agent could {harm}. "
                    "Move the mount (or config_home_source) outside it."
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
            "harness": s.harness,  # false: a listener for egress-stack components only
        }
        if s.gate is not None:
            entry.update(
                mode=s.gate.mode,
                tool=s.gate.tool,
                scope=s.gate.scope,  # null in http-proxy mode: classified per flow
                upstream=s.gate.upstream,
                route={"kind": s.gate.route_kind, "upstream": s.gate.route_upstream},
                client=s.gate.client if not s.harness else "harness",
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
        "resolver": plan.observe.resolver if plan.observe.resolve == "in-tunnel" else None,
        "exit_identity": (f"via-proxy:{plan.observe.exit_url}"
                          if plan.observe.exit_identity == "via-proxy" else "none"),
        "upstream_kind": _upstream_kind(plan),
        "rotate": {"max_bytes": plan.observe.rotate_bytes, "keep": plan.observe.keep,
                   "retain_s": plan.observe.retain_s},
        "record_headers": plan.observe.record_headers,
        "rendered_at": iso_utc(),
        "services": services,
    }


def _upstream_kind(plan: SessionPlan) -> str:
    """Session-level upstream kind for ``status.json``: the chained route if any
    service proxies through one (``direct`` wins — it must never be masked),
    else ``tcp``."""
    kinds = {s.gate.route_kind for s in plan.network.gated if s.gate.mode == "http-proxy"}
    for k in ("direct", "vpn", "tor"):
        if k in kinds:
            return k
    return "tcp"


def wipe_flow_record(path: Path) -> int:
    """Delete the flow/exit record and status (not session.json, not rules)."""
    n = 0
    for f in [*Path(path).glob("flows*.ndjson"), *Path(path).glob("exit*.ndjson"), Path(path) / "status.json"]:
        if f.is_file():
            f.unlink()
            n += 1
    return n


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
    from .session import _image_exists

    tag = netgate_image()
    if _image_exists(provider, tag) and not force:
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
