"""Merge extension compose fragments into the session project, and validate it.

A fragment (``services:`` in a manifest) may contain only ``services`` and
``volumes``, and each service only the keys in ``ALLOWED_SERVICE_KEYS``. It never
sets a security key: core injects the sidecar hardening set (non-root,
``cap_drop: ALL``, ``no-new-privileges``, read-only rootfs, seccomp, ipc
private, pids/memory limits) and then applies exactly the ``privileges:``
exceptions the manifest declares, drawn from ``PRIVILEGE_ALLOWLIST``. Names are
session-scoped (``glove-<id>-<short>``), networks are logical (``egress``,
``wan``, an extension-private net), and host binds are limited to the
extension's own state dir, (read-only) its assets, and an export root it owns
(``Composition.export_access``). A `forwarder` provider's per-endpoint services
go through the same path, with networks set by core.

``validate_project`` then re-checks the §3.4 invariants on the *merged*
project, so a bug in the merge cannot ship a weaker project.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from .cafile import CA_DIR, TRUST_DIR, TRUST_ENV, trust_argv
from .extensions import (
    CORE_NETWORKS,
    SECRETS_DIR,
    Active,
    Composition,
    ExtensionError,
    require_trust,
    required_libs,
    secret_env_var,
)
from .extensions import active_items as _active_items
from .extensions import base_context as _ctx
from .extensions import image_tag as _image_tag
from .extensions import render_value as _render
from .hardening import SIDECAR_ONLY_SECCOMP
from .mounts import WORK_TARGET
from .naming import scoped
from .runtimes.landlock_mounts import host_under_virtiofs
from .runtimes.seccomp import SECCOMP_DIR

if TYPE_CHECKING:
    from .plan import SessionPlan

ALLOWED_SERVICE_KEYS = frozenset({
    "image", "command", "entrypoint", "environment", "volumes", "tmpfs", "networks", "depends_on",
    "healthcheck", "restart", "init", "shm_size", "working_dir", "labels", "secrets",
    "stop_grace_period", "stop_signal", "network_mode", "dns",
})
PRIVILEGE_ALLOWLIST = {
    "cap_add": frozenset({"NET_ADMIN", "NET_RAW", "CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE"}),
    "devices": frozenset({"/dev/net/tun"}),
}
PRIVILEGE_KEYS = frozenset({"cap_add", "devices", "user_root", "read_only", "seccomp", "low_ports", "work"})
# Not privileges: the text shown when a runtime cannot grant one (e.g. a way to
# run without it).
PRIVILEGE_META = frozenset({"hint"})
DEFAULT_LIMITS = {"pids": 256, "memory": "512m"}


def seccomp_profiles() -> set[str]:
    """Core-owned profiles a sidecar may request by name (an extension never
    ships its own JSON). `nested-userns` stays harness-only (srt); these never are."""
    return {p.stem for p in SECCOMP_DIR.glob("*.json")} & SIDECAR_ONLY_SECCOMP


def _privileges(comp: Composition, a: Active, short: str) -> dict[str, Any]:
    ctx = _ctx(comp, a)
    raw = a.spec("privileges", ctx).get(short)
    items = raw if isinstance(raw, list) else [raw] if raw else []
    merged: dict[str, Any] = {}
    for p in _active_items(items, ctx):
        unknown = set(p) - PRIVILEGE_KEYS - PRIVILEGE_META
        if unknown:
            raise ExtensionError(f"extension {a.name!r} service {short!r}: unknown privilege(s) {sorted(unknown)}")
        for key in ("cap_add", "devices"):
            bad = [x for x in p.get(key, []) if x not in PRIVILEGE_ALLOWLIST[key]]
            if bad:
                raise ExtensionError(
                    f"extension {a.name!r} service {short!r}: {key} {bad} not in the allowlist "
                    f"{sorted(PRIVILEGE_ALLOWLIST[key])}"
                )
            if p.get(key):
                merged.setdefault(key, []).extend(x for x in p[key] if x not in merged.get(key, []))
        if "seccomp" in p:
            if p["seccomp"] not in seccomp_profiles():
                raise ExtensionError(
                    f"extension {a.name!r} service {short!r}: seccomp {p['seccomp']!r} is not a core profile "
                    f"({sorted(seccomp_profiles())})"
                )
            merged["seccomp"] = p["seccomp"]
            if p.get("hint"):
                merged["seccomp_hint"] = str(p["hint"])
        if p.get("user_root") is True:
            merged["user_root"] = True
        if p.get("read_only") is False:
            merged["read_only"] = False
        if p.get("low_ports") is True:
            merged["low_ports"] = True
        if p.get("work") is True:  # binds the harness's whole /work, read-write, at /work
            merged["work"] = True
    if merged and not a.manifest.trusted:
        raise ExtensionError(
            f"extension {a.name!r} requests privileges {sorted(merged)} for {short!r}, but it is out-of-tree "
            "and not in `trusted_extensions` (~/.glove/config.yml)"
        )
    return merged


def _allowed_networks(comp: Composition, a: Active) -> set[str]:
    nets = {n for n, spec in comp.networks.items() if spec.get("owner") == a.name}
    provides_egress = "egress" in a.manifest.provides
    consumes_egress = comp.slots.get("egress") is not None and a is not comp.slots.get("egress")
    if provides_egress:
        nets |= {"egress", "wan"}
    elif consumes_egress:
        nets.add("egress")
    return nets


def _within(path: str, root: str) -> bool:
    p, r = os.path.realpath(path), os.path.realpath(root)
    return p == r or p.startswith(r.rstrip("/") + "/")


def _volume_name(comp: Composition, ext: str, vname: str) -> str:
    """An extension fragment's volume, as the project names it."""
    return scoped(comp.session, f"{ext}-{vname}")


def _volumes(comp: Composition, a: Active, short: str, vols: list, declared: set[str],
             extra: dict | None = None, *, work: bool = False, shared: Mapping[str, str] = MappingProxyType({})
             ) -> list[dict]:
    """`shared`: other extensions' volumes this service may mount read-only
    (`<ref>` → full name; a forwarder's `egress:<volume>`)."""
    out = []
    state = str(comp.state_dir(a.name))
    roots = {root: ro for root, ro in comp.export_access(a).items() if root in comp.export_dirs}
    label = (extra or {}).get("bind_selinux")
    for v in vols or []:
        where = f"extension {a.name!r} service {short!r} volume {v!r}"
        if not isinstance(v, dict):
            raise ExtensionError(f"{where}: use the long syntax ({{type, source, target}})")
        t = v.get("type")
        if t == "tmpfs":
            out.append(dict(v))
        elif t == "volume" and v.get("source") in shared:
            if v.get("read_only") is not True:
                raise ExtensionError(f"{where}: another extension's volume mounts read-only")
            out.append({**v, "source": shared[v["source"]]})
        elif t == "volume":
            if v.get("source") not in declared:
                raise ExtensionError(f"{where}: named volume must be declared in the fragment's `volumes:`")
            out.append({**v, "source": _volume_name(comp, a.name, v["source"])})
        elif t == "bind":
            src = str(v.get("source", ""))
            if "docker.sock" in src:
                raise ExtensionError(f"{where}: the docker socket is never mounted")
            root = next((r for r in roots if _within(src, str(comp.export_dirs[r]))), None)
            if _within(src, state):
                bind = dict(v)
            elif _within(src, str(a.manifest.path)):
                if not v.get("read_only"):
                    raise ExtensionError(f"{where}: extension assets bind read-only")
                bind = dict(v)
            elif root is not None:
                if roots[root] and not v.get("read_only"):
                    raise ExtensionError(f"{where}: the {root!r} export root binds read-only here")
                bind = dict(v)
            elif comp.work_dir is not None and _within(src, str(comp.work_dir)):
                # all of /work, read-write at /work, with the `work` privilege;
                # never a path in it: the agent can swap one for a link that the
                # bind follows when the sidecar restarts (`outputs:`/`inputs:`
                # are directories beside /work instead)
                if os.path.realpath(src) != os.path.realpath(comp.work_dir) or not work:
                    raise ExtensionError(f"{where}: a sidecar never binds a path in /work, only all of it with "
                                         "the `work` privilege (for files it writes or reads: `outputs:`/`inputs:`)")
                if v.get("target") != WORK_TARGET or v.get("read_only"):
                    raise ExtensionError(f"{where}: the `work` privilege binds /work read-write at {WORK_TARGET}")
                require_trust(a, f"{where}: binding /work")
                bind = dict(v)
            else:
                raise ExtensionError(
                    f"{where}: a sidecar may bind only its state dir ({{{{ state }}}}), read-only its "
                    "assets ({{ assets }}), an export root it owns ({{ exports.<root> }}), or all of /work "
                    "with the `work` privilege"
                )
            if label:
                # SELinux hosts deny containers an unlabelled bind; `z`: shared
                bind["bind"] = {"selinux": label}
            out.append(bind)
        else:
            raise ExtensionError(f"{where}: type must be tmpfs|volume|bind")
    return out


def _networks(comp: Composition, a: Active, short: str, svc: dict) -> dict | None:
    if svc.get("network_mode") is not None:
        if svc["network_mode"] != "none":
            raise ExtensionError(f"extension {a.name!r} service {short!r}: network_mode may only be `none`")
        if svc.get("networks"):
            raise ExtensionError(f"extension {a.name!r} service {short!r}: network_mode none has no networks")
        return None
    raw = svc.get("networks") or []
    items = raw if isinstance(raw, dict) else {n: {} for n in raw}
    allowed = _allowed_networks(comp, a)
    out: dict[str, Any] = {}
    for logical, spec in items.items():
        if logical == "net":
            raise ExtensionError(
                f"extension {a.name!r} service {short!r}: never joins the harness network — "
                "declare an endpoint instead"
            )
        if logical not in allowed:
            raise ExtensionError(
                f"extension {a.name!r} service {short!r}: may not join network {logical!r} (allowed: {sorted(allowed)})"
            )
        if logical in CORE_NETWORKS:
            comp.networks.setdefault(logical, {**CORE_NETWORKS[logical], "owner": "core"})
        out[scoped(comp.session, logical)] = dict(spec or {})
    if not out:
        raise ExtensionError(f"extension {a.name!r} service {short!r}: needs `networks` or `network_mode: none`")
    return out


def _declared_volumes(comp: Composition, a: Active, doc: dict, extra: dict,
                      volumes: dict[str, Any]) -> set[str]:
    declared = set((doc.get("volumes") or {}).keys())
    for vname, vspec in (doc.get("volumes") or {}).items():
        vspec = vspec or {}
        opts = dict(vspec.get("driver_opts") or {})
        if set(vspec) - {"driver_opts"} or (opts and (opts.get("type") != "tmpfs" or set(opts) - {"type"})):
            raise ExtensionError(
                f"extension {a.name!r}: volume {vname!r} may only be a plain or tmpfs volume "
                "(`driver_opts: {type: tmpfs}`; core sets its size, mode and owner)"
            )
        full = _volume_name(comp, a.name, vname)
        if opts:
            # owned by the session uid as the mount sees ids, mode 0700
            opts = {"type": "tmpfs", "device": "tmpfs", "o": f"size=1m,{extra.get('tmpfs_volume_opts', 'mode=0700')}"}
        volumes[full] = {"name": full, **({"driver": "local", "driver_opts": opts} if opts else {})}
    return declared


def _harden_service(comp: Composition, a: Active, short: str, svc: dict, plan: SessionPlan, extra: dict,
                    declared: set[str], *, networks: dict[str, Any] | None = None,
                    tmpfs_volumes: frozenset[str] = frozenset(),
                    shared: Mapping[str, str] = MappingProxyType({})) -> dict[str, Any]:
    """One validated, hardened service. `networks` (already full names) is core's
    choice for a forwarder; fragment services declare logical networks."""
    where = f"extension {a.name!r} service {short!r}"
    image = str(svc.get("image", ""))
    built = {_image_tag(x, k) for x in (a, *required_libs(comp, a)) for k in (x.manifest.raw.get("images") or {})}
    if "@sha256:" not in image and image not in built:
        raise ExtensionError(f"{where}: image must be pinned by digest (@sha256:…) or built by the extension")
    priv = _privileges(comp, a, short) if networks is None else {}
    lim = {**DEFAULT_LIMITS, **_render((a.manifest.raw.get("limits") or {}).get(short) or {}, _ctx(comp, a),
                                       f"{where} limits")}
    if svc.get("dns") and "wan" not in (svc.get("networks") or []):
        raise ExtensionError(f"{where}: `dns` is only meaningful on the egress provider's wan network")
    name = scoped(comp.session, short)
    out: dict[str, Any] = {"container_name": name, **{k: v for k, v in svc.items() if k not in (
        "volumes", "networks", "depends_on", "secrets", "network_mode")}}
    if networks is not None:
        out["networks"] = networks
    else:
        nets = _networks(comp, a, short, svc)
        if nets is None:
            out["network_mode"] = "none"
        else:
            out["networks"] = nets
    if svc.get("volumes"):
        out["volumes"] = _volumes(comp, a, short, svc["volumes"], declared, extra, work=bool(priv.get("work")),
                                  shared=shared)
    if priv.get("work") and not any(v.get("target") == WORK_TARGET for v in out.get("volumes") or []):
        raise ExtensionError(f"{where}: holds the `work` privilege but binds no /work")
    for c in comp.channels:
        if c.extension == a.name and short in c.services:
            out.setdefault("volumes", []).append({"type": "volume", "source": c.volume(comp.session),
                                                  "target": c.path})
    relabel = {"bind": {"selinux": extra["bind_selinux"]}} if extra.get("bind_selinux") else {}  # glove's own files
    for o in comp.outputs_of(a.name):
        if short in o.services:
            out.setdefault("volumes", []).append({"type": "bind", "source": str(o.host), "target": o.path,
                                                  **({"read_only": True} if o.input else {}), **relabel})
    cas = comp.trusted_cas(a.name) if short in a.spec("trust") else []
    if cas:
        # as in the harness: the copies read-only (glove's own, so relabelling
        # is safe), the bundle built on a tmpfs by core's entrypoint (it
        # replaces the image's), which then runs the whole `command`
        env = out.get("environment") or {}
        if not isinstance(env, dict) or not isinstance(out.get("command"), list) or "entrypoint" in out:
            raise ExtensionError(f"{where}: trusts the session's CAs, so it needs a `command` list (the whole "
                                 "argv), no `entrypoint`, and an `environment` mapping")
        out.setdefault("volumes", []).extend([
            {"type": "bind", "source": plan.trust_host_dir, "target": TRUST_DIR, "read_only": True, **relabel},
            {"type": "tmpfs", "target": CA_DIR, "tmpfs": {"mode": 0o1777}}])
        out["environment"] = {**env, **TRUST_ENV}
        out["entrypoint"] = trust_argv(cas, [])
    deps = svc.get("depends_on") or []
    if deps:
        items = deps.items() if isinstance(deps, dict) else ((d, None) for d in deps)
        out["depends_on"] = {scoped(comp.session, d): (c or {"condition": "service_started"})
                             for d, c in items}
    if svc.get("secrets"):
        own = {k.removeprefix(f"{a.name}-") for k, (ext, _) in comp.secrets.items() if ext == a.name}
        missing = [x for x in svc["secrets"] if x not in own]
        if missing:
            raise ExtensionError(f"{where}: secret(s) {missing} are not declared (or not active)")
        out["secrets"] = [{"source": scoped(comp.session, f"{a.name}-{x}"), "target": f"{SECRETS_DIR}/{x}"}
                          for x in svc["secrets"]]
    out.setdefault("restart", "unless-stopped")
    if not priv.get("user_root"):
        out["user"] = f"{plan.uid}:{plan.gid}"
        # Rootless podman's keep-id only where the sidecar must be the session
        # uid: it writes a host bind (it must own what it writes), reads an
        # input (the harness's files may be 0600), or shares a tmpfs volume,
        # which core creates owned by that uid (e.g. the netgate events
        # socket). Elsewhere its uid stays an unprivileged subuid.
        rw_bind = any(v.get("type") == "bind" and not v.get("read_only") for v in out.get("volumes") or [])
        on_tmpfs = any(v.get("type") == "volume" and v.get("source") in tmpfs_volumes for v in out.get("volumes") or [])
        reads_input = any(o.input and short in o.services for o in comp.outputs_of(a.name))
        if extra.get("userns_mode") and (rw_bind or on_tmpfs or reads_input):
            out["userns_mode"] = extra["userns_mode"]
    out["cap_drop"] = ["ALL"]
    if priv.get("cap_add"):
        out["cap_add"] = list(priv["cap_add"])
    if priv.get("devices"):
        out["devices"] = [f"{d}:{d}" for d in priv["devices"]]
    hint = priv.pop("seccomp_hint", None)
    if priv.get("seccomp") and not extra.get("emit_seccomp", True):
        # never drop a sidecar's profile silently: it is what the sidecar needs
        raise ExtensionError(
            f"{where} needs the {priv['seccomp']!r} seccomp profile, which this runtime cannot apply "
            "(podman compose inlines a custom profile and podman rejects it)" + (f" — {hint}" if hint else ""))
    sec = ["no-new-privileges:true"]
    if extra.get("emit_seccomp", True):
        sec.append(f"seccomp={SECCOMP_DIR / (priv.get('seccomp', 'default') + '.json')}")
    out["security_opt"] = sec
    out["read_only"] = priv.get("read_only", True)
    if priv.get("low_ports"):
        # listen below 1024 without NET_BIND_SERVICE, in its own network
        # namespace only: docker's default for every container, podman's not
        out["sysctls"] = {"net.ipv4.ip_unprivileged_port_start": 0}
    out["ipc"] = "private"
    out["pids_limit"] = int(lim["pids"])
    out["mem_limit"] = str(lim["memory"])
    if lim.get("cpus"):
        out["cpus"] = float(lim["cpus"])
    if priv:
        comp.privileges[f"{a.name}/{short}"] = [{k: v} for k, v in priv.items()]
    return out


def _tmpfs(volumes: dict[str, Any]) -> frozenset[str]:
    return frozenset(n for n, v in volumes.items() if (v.get("driver_opts") or {}).get("type") == "tmpfs")


def _forwarder_networks(plan: SessionPlan, s) -> dict[str, Any]:
    nets: dict[str, Any] = {}
    if s.harness:
        aliases = [*s.impl_aliases, *s.aliases]
        nets[plan.network.internal_network] = {"aliases": aliases} if aliases else {}
    for n in s.networks:
        nets[n] = {}
    if s.host_gateway and plan.network.hostgw_network:
        nets[plan.network.hostgw_network] = {}
    return nets


def harden_fragments(comp: Composition, plan: SessionPlan, extra: dict) -> dict[str, dict]:
    """Validated, namespaced, hardened `services`/`volumes`/`secrets` blocks —
    extension fragments plus the `forwarder` provider's per-endpoint services."""
    services: dict[str, Any] = {}
    volumes: dict[str, Any] = {}
    reserved = {scoped(comp.session, e.name) for e in comp.endpoints} | {plan.harness_service,
                                                                         scoped(comp.session, "mount-watch")}
    declared_by: dict[str, set[str]] = {}
    _channel_volumes(comp, extra, volumes)
    for a, doc in comp.fragments:
        bad_top = set(doc) - {"services", "volumes"}
        if bad_top:
            raise ExtensionError(
                f"extension {a.name!r}: a fragment may hold only services/volumes, got {sorted(bad_top)}"
            )
        declared = _declared_volumes(comp, a, doc, extra, volumes)
        declared_by[a.name] = declared
        for short, svc in (doc.get("services") or {}).items():
            where = f"extension {a.name!r} service {short!r}"
            svc = dict(svc or {})
            bad = set(svc) - ALLOWED_SERVICE_KEYS
            if bad:
                raise ExtensionError(f"{where}: key(s) {sorted(bad)} are not allowed (core sets security keys)")
            name = scoped(comp.session, short)
            if name in services or name in reserved:
                raise ExtensionError(f"{where}: name {name!r} is already used")
            services[name] = _harden_service(comp, a, short, svc, plan, extra, declared,
                                             tmpfs_volumes=_tmpfs(volumes))
    provider = comp.slots.get("forwarder")
    # a forwarder sits on the egress hop: it may read the volumes the egress
    # provider `shares` (e.g. vpn's exit IP for observe's gate), never write them
    egress = comp.slots.get("egress")
    shared: dict[str, str] = {}
    for vol in comp.slot_exports("egress").get("shares") or []:
        if vol not in declared_by.get(egress.name, ()):
            raise ExtensionError(f"extension {egress.name!r} shares {vol!r}, which its fragment does not declare")
        shared[f"egress:{vol}"] = _volume_name(comp, egress.name, vol)
    for s in plan.network.implemented:
        assert provider is not None
        name = scoped(comp.session, s.role)
        if name in services:
            raise ExtensionError(f"forwarder {name!r} clashes with an extension service")
        services[name] = _harden_service(comp, provider, s.role, dict(s.impl or {}), plan, extra,
                                         declared_by.get(provider.name, set()),
                                         networks=_forwarder_networks(plan, s), tmpfs_volumes=_tmpfs(volumes),
                                         shared=shared)
        if s.host_gateway:
            services[name]["extra_hosts"] = [f"{extra.get('host_gateway_name', 'host.docker.internal')}:host-gateway"]
        if s.listen_port < 1024:
            # a low port as non-root: podman does not default this (docker does)
            services[name]["sysctls"] = {"net.ipv4.ip_unprivileged_port_start": 0}
    secrets = {scoped(comp.session, c): {"environment": secret_env_var(c)} for c in comp.secrets}
    return {"services": services, "volumes": volumes, "secrets": secrets}


def _channel_volumes(comp: Composition, extra: dict, volumes: dict[str, Any]) -> None:
    """One session tmpfs volume per channel (owned by the session uid, 0700),
    and a check that each service a channel or an output names is one of its
    extension's."""
    shared = [*(("channel", c) for c in comp.channels),
              *(("input" if o.input else "output", o) for o in comp.outputs)]
    for kind, x in shared:
        owner = comp.by_name(x.extension)
        doc = next((d for e, d in comp.fragments if e is owner), {})
        missing = [svc for svc in x.services if svc not in (doc.get("services") or {})]
        if missing:
            raise ExtensionError(f"extension {x.extension!r} {kind} {x.name!r}: no service(s) {missing}")
    for c in comp.channels:
        opts = f"size=4m,{extra.get('tmpfs_volume_opts', 'mode=0700')}"
        name = c.volume(comp.session)
        volumes[name] = {"name": name, "driver": "local",
                         "driver_opts": {"type": "tmpfs", "device": "tmpfs", "o": opts}}


# --- final invariants on the merged project ----------------------------------------

FORBIDDEN_ANYWHERE = ("privileged", "ports")


def validate_project(doc: dict, plan: SessionPlan, comp: Composition) -> None:
    """§3.4, re-checked on the merged project (defence against merge bugs)."""
    services = doc.get("services") or {}
    session = plan.session
    harness_net = scoped(session, "net")
    for name, svc in services.items():
        for key in FORBIDDEN_ANYWHERE:
            if svc.get(key):
                raise ExtensionError(f"service {name!r}: `{key}` is never allowed")
        if svc.get("network_mode") not in (None, "none") or svc.get("pid") == "host" or svc.get("ipc") == "host":
            raise ExtensionError(f"service {name!r}: host namespaces are never allowed")
        for v in svc.get("volumes") or []:
            src = v.get("source", "") if isinstance(v, dict) else str(v).split(":")[0]
            if "docker.sock" in str(src):
                raise ExtensionError(f"service {name!r}: the docker socket is never mounted")
            if (host_under_virtiofs(str(src)) is not None
                    and not (name == plan.harness_service and plan.bind_layer == "virtiofs")):
                raise ExtensionError(f"service {name!r}: only a Landlock harness binds from Docker Desktop's "
                                     f"virtiofs layer ({src})")
        if name == scoped(session, "mount-watch"):  # never wider than the harness: its own binds, read-only
            harness = {host_under_virtiofs(str(v.get("source"))) for v in services[plan.harness_service]["volumes"]
                       if isinstance(v, dict)}
            if any(not (isinstance(v, dict) and v.get("read_only") and v.get("source") in harness)
                   for v in svc.get("volumes") or []):
                raise ExtensionError("mount-watch binds only the harness's own binds, read-only")
        if name == plan.harness_service:
            nets = svc.get("networks") or []
            nets = list(nets) if isinstance(nets, list) else list(nets.keys())
            extension_nets = {scoped(session, n) for n in comp.networks}
            if any(n in extension_nets for n in nets):
                raise ExtensionError("the harness joins no extension network — only its own internal network")
            channels = {c.volume(session) for c in comp.channels}
            for v in svc.get("volumes") or []:
                bind = isinstance(v, dict) and v.get("type") == "bind"
                src = str(v["source"]) if bind else ""
                if bind and plan.bind_layer == "virtiofs":
                    # each bind a translated host path, never a top-level directory (/Users: every share's tree)
                    host = host_under_virtiofs(src)
                    if host is None or host.count("/") < 2:
                        raise ExtensionError(f"the harness's bind {src} is not a host path on Docker Desktop's "
                                             "virtiofs layer")
                    src = host
                if bind and _within(src, str(comp.state_root)):
                    raise ExtensionError(f"the harness never mounts extension state ({v['source']})")
                if isinstance(v, dict) and v.get("type") == "volume" and v.get("source") not in channels:
                    raise ExtensionError(f"the harness mounts no volume but a channel ({v.get('source')})")
            h = plan.hardening
            if set(svc.get("cap_add") or []) != set(h.cap_add) or set(svc.get("cap_drop") or []) != set(h.cap_drop):
                raise ExtensionError("the harness's capabilities differ from its hardening plan")
            allowed_opts = {"no-new-privileges:true", f"seccomp={h.seccomp_profile}",
                            *(["systempaths=unconfined"] if h.systempaths_unconfined else [])}
            opts = set(svc.get("security_opt") or [])
            if not opts <= allowed_opts or "no-new-privileges:true" not in opts:
                raise ExtensionError("the harness's security_opt differs from its hardening plan")
            continue
        if svc.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in (svc.get("security_opt") or []):
            raise ExtensionError(f"sidecar {name!r} is missing the hardening set")
    wan, lan = scoped(session, "wan"), scoped(session, "lan")
    egress_provider = comp.slots.get("egress")
    for name, svc in services.items():
        nets = svc.get("networks") or {}
        nets = set(nets) if not isinstance(nets, dict) else set(nets.keys())
        short = name.removeprefix(scoped(session, ""))
        if wan in nets:
            owner = next((a for a, d in comp.fragments if short in (d.get("services") or {})), None)
            # ...or the forwarder of an endpoint the egress provider declared (a raw TCP hop)
            ep_owner = next((comp.by_name(e.extension) for e in comp.endpoints if e.name == short), None)
            if egress_provider is None or egress_provider not in (owner, ep_owner):
                raise ExtensionError(f"service {name!r} joins the wan network, which only the egress provider may")
        if lan in nets and not any(e.target.network == "lan" and short in (e.name, f"{e.name}-out")
                                   for e in comp.endpoints):
            raise ExtensionError(f"service {name!r} joins the lan network, which only `via: lan` forwarders may")
        if harness_net in nets and name != plan.harness_service and short not in {
            e.name for e in comp.endpoints if e.harness
        } | {s.role for s in plan.network.sidecars if s.harness}:
            raise ExtensionError(f"service {name!r} joins the harness network but is not a harness endpoint")
