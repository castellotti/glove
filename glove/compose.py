"""Merge extension compose fragments into the session project, and validate it.

A fragment (``services:`` in a manifest) may contain only ``services`` and
``volumes``, and each service only the keys in ``ALLOWED_SERVICE_KEYS``. It never
sets a security key: core injects the sidecar hardening set (non-root,
``cap_drop: ALL``, ``no-new-privileges``, read-only rootfs, seccomp, ipc
private, pids/memory limits) and then applies exactly the ``privileges:``
exceptions the manifest declares, drawn from ``PRIVILEGE_ALLOWLIST``. Names are
session-scoped (``glove-<id>-<short>``), networks are logical (``egress``,
``wan``, an extension-private net), and host binds are limited to the
extension's own state dir and (read-only) its assets.

``validate_project`` then re-checks the §3.4 invariants on the *merged*
project, so a bug in the merge cannot ship a weaker project.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from .extensions import CORE_NETWORKS, Active, Composition, ExtensionError, network_name, secret_env_var
from .extensions import active_items as _active_items
from .extensions import base_context as _ctx
from .extensions import image_tag as _image_tag
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
PRIVILEGE_KEYS = frozenset({"cap_add", "devices", "user_root", "read_only", "seccomp"})
DEFAULT_LIMITS = {"pids": 256, "memory": "512m"}


# Core-owned profiles a sidecar may request by name (an extension never ships
# its own JSON). `nested-userns` stays harness-only (srt).
SIDECAR_SECCOMP = frozenset({"chromium-userns"})


def seccomp_profiles() -> set[str]:
    return {p.stem for p in SECCOMP_DIR.glob("*.json")} & SIDECAR_SECCOMP


def _privileges(comp: Composition, a: Active, short: str) -> dict[str, Any]:
    raw = (a.manifest.raw.get("privileges") or {}).get(short)
    items = raw if isinstance(raw, list) else [raw] if raw else []
    merged: dict[str, Any] = {}
    for p in _active_items(items, _ctx(comp, a)):
        unknown = set(p) - PRIVILEGE_KEYS
        if unknown:
            raise ExtensionError(f"extension {a.name!r} service {short!r}: unknown privilege(s) {sorted(unknown)}")
        for key in ("cap_add", "devices"):
            bad = [x for x in p.get(key, []) if x not in PRIVILEGE_ALLOWLIST[key]]
            if bad:
                raise ExtensionError(
                    f"extension {a.name!r} service {short!r}: {key} {bad} not in the allowlist "
                    f"{sorted(PRIVILEGE_ALLOWLIST[key])}"
                )
            merged.setdefault(key, []).extend(x for x in p.get(key, []) if x not in merged.get(key, []))
        if "seccomp" in p:
            if p["seccomp"] not in seccomp_profiles():
                raise ExtensionError(
                    f"extension {a.name!r} service {short!r}: seccomp {p['seccomp']!r} is not a core profile "
                    f"({sorted(seccomp_profiles())})"
                )
            merged["seccomp"] = p["seccomp"]
        if p.get("user_root") is True:
            merged["user_root"] = True
        if p.get("read_only") is False:
            merged["read_only"] = False
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


def _volumes(comp: Composition, a: Active, short: str, vols: list, declared: set[str]) -> list[dict]:
    out = []
    state = str(comp.state_dir(a.name))
    for v in vols or []:
        where = f"extension {a.name!r} service {short!r} volume {v!r}"
        if not isinstance(v, dict):
            raise ExtensionError(f"{where}: use the long syntax ({{type, source, target}})")
        t = v.get("type")
        if t == "tmpfs":
            out.append(dict(v))
        elif t == "volume":
            if v.get("source") not in declared:
                raise ExtensionError(f"{where}: named volume must be declared in the fragment's `volumes:`")
            out.append({**v, "source": f"glove-{comp.session}-{a.name}-{v['source']}"})
        elif t == "bind":
            src = str(v.get("source", ""))
            if "docker.sock" in src:
                raise ExtensionError(f"{where}: the docker socket is never mounted")
            if _within(src, state):
                out.append(dict(v))
            elif _within(src, str(a.manifest.path)):
                if not v.get("read_only"):
                    raise ExtensionError(f"{where}: extension assets bind read-only")
                out.append(dict(v))
            else:
                raise ExtensionError(
                    f"{where}: a sidecar may bind only its state dir ({{{{ state }}}}) or, read-only, its "
                    "assets ({{ assets }})"
                )
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
        out[network_name(comp.session, logical)] = dict(spec or {})
    if not out:
        raise ExtensionError(f"extension {a.name!r} service {short!r}: needs `networks` or `network_mode: none`")
    return out


def harden_fragments(comp: Composition, plan: SessionPlan, extra: dict) -> dict[str, dict]:
    """Validated, namespaced, hardened `services`/`volumes`/`secrets` blocks."""
    services: dict[str, Any] = {}
    volumes: dict[str, Any] = {}
    reserved = {f"glove-{comp.session}-{e.name}" for e in comp.endpoints} | {plan.harness_service}
    for a, doc in comp.fragments:
        bad_top = set(doc) - {"services", "volumes"}
        if bad_top:
            raise ExtensionError(
                f"extension {a.name!r}: a fragment may hold only services/volumes, got {sorted(bad_top)}"
            )
        declared = set((doc.get("volumes") or {}).keys())
        for vname, vspec in (doc.get("volumes") or {}).items():
            vspec = vspec or {}
            opts = vspec.get("driver_opts") or {}
            if set(vspec) - {"driver_opts"} or (opts and opts.get("type") != "tmpfs"):
                raise ExtensionError(f"extension {a.name!r}: volume {vname!r} may only be a plain or tmpfs volume")
            full = f"glove-{comp.session}-{a.name}-{vname}"
            volumes[full] = {"name": full, **({"driver": "local", "driver_opts": opts} if opts else {})}
        limits = {**DEFAULT_LIMITS}
        for short, svc in (doc.get("services") or {}).items():
            where = f"extension {a.name!r} service {short!r}"
            svc = dict(svc or {})
            bad = set(svc) - ALLOWED_SERVICE_KEYS
            if bad:
                raise ExtensionError(f"{where}: key(s) {sorted(bad)} are not allowed (core sets security keys)")
            name = f"glove-{comp.session}-{short}"
            if name in services or name in reserved:
                raise ExtensionError(f"{where}: name {name!r} is already used")
            image = str(svc.get("image", ""))
            built = {_image_tag(a, k) for k in (a.manifest.raw.get("images") or {})}
            if "@sha256:" not in image and image not in built:
                raise ExtensionError(f"{where}: image must be pinned by digest (@sha256:…) or built by the extension")
            priv = _privileges(comp, a, short)
            lim = {**limits, **((a.manifest.raw.get("limits") or {}).get(short) or {})}
            if svc.get("dns") and "wan" not in (svc.get("networks") or []):
                raise ExtensionError(f"{where}: `dns` is only meaningful on the egress provider's wan network")
            out: dict[str, Any] = {"container_name": name, **{k: v for k, v in svc.items() if k not in (
                "volumes", "networks", "depends_on", "secrets", "network_mode")}}
            nets = _networks(comp, a, short, svc)
            if nets is None:
                out["network_mode"] = "none"
            else:
                out["networks"] = nets
            if svc.get("volumes"):
                out["volumes"] = _volumes(comp, a, short, svc["volumes"], declared)
            deps = svc.get("depends_on") or []
            if deps:
                items = deps.items() if isinstance(deps, dict) else ((d, None) for d in deps)
                out["depends_on"] = {f"glove-{comp.session}-{d}": (c or {"condition": "service_started"})
                                     for d, c in items}
            if svc.get("secrets"):
                own = {k.removeprefix(f"{a.name}-") for k, (ext, _) in comp.secrets.items() if ext == a.name}
                missing = [s for s in svc["secrets"] if s not in own]
                if missing:
                    raise ExtensionError(f"{where}: secret(s) {missing} are not declared (or not active)")
                out["secrets"] = [{"source": f"glove-{comp.session}-{a.name}-{s}", "target": s}
                                  for s in svc["secrets"]]
            out.setdefault("restart", "unless-stopped")
            if not priv.get("user_root"):
                out["user"] = f"{plan.uid}:{plan.gid}"
                if extra.get("userns_mode"):
                    out["userns_mode"] = extra["userns_mode"]
            out["cap_drop"] = ["ALL"]
            if priv.get("cap_add"):
                out["cap_add"] = list(priv["cap_add"])
            if priv.get("devices"):
                out["devices"] = [f"{d}:{d}" for d in priv["devices"]]
            sec = ["no-new-privileges:true"]
            if extra.get("emit_seccomp", True):
                sec.append(f"seccomp={SECCOMP_DIR / (priv.get('seccomp', 'default') + '.json')}")
            out["security_opt"] = sec
            out["read_only"] = priv.get("read_only", True)
            out["ipc"] = "private"
            out["pids_limit"] = int(lim["pids"])
            out["mem_limit"] = str(lim["memory"])
            if lim.get("cpus"):
                out["cpus"] = lim["cpus"]
            if priv:
                comp.privileges[f"{a.name}/{short}"] = [{k: v} for k, v in priv.items()]
            services[name] = out
    secrets = {f"glove-{comp.session}-{c}": {"environment": secret_env_var(c)} for c in comp.secrets}
    return {"services": services, "volumes": volumes, "secrets": secrets}


# --- final invariants on the merged project ----------------------------------------

FORBIDDEN_ANYWHERE = ("privileged", "ports")


def validate_project(doc: dict, plan: SessionPlan, comp: Composition | None) -> None:
    """§3.4, re-checked on the merged project (defence against merge bugs)."""
    services = doc.get("services") or {}
    session = plan.session
    harness_net = f"glove-{session}-net"
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
        if name == plan.harness_service:
            nets = svc.get("networks") or []
            nets = list(nets) if isinstance(nets, list) else list(nets.keys())
            extension_nets = {network_name(session, n) for n in (comp.networks if comp else {})}
            if any(n in extension_nets for n in nets):
                raise ExtensionError("the harness joins no extension network — only its own internal network")
            if comp is not None:
                for v in svc.get("volumes") or []:
                    bind = isinstance(v, dict) and v.get("type") == "bind"
                    if bind and _within(str(v["source"]), str(comp.state_root)):
                        raise ExtensionError(f"the harness never mounts extension state ({v['source']})")
            continue
        if svc.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in (svc.get("security_opt") or []):
            raise ExtensionError(f"sidecar {name!r} is missing the hardening set")
    if comp is None:
        return
    wan = network_name(session, "wan")
    egress_provider = comp.slots.get("egress")
    for name, svc in services.items():
        nets = svc.get("networks") or {}
        nets = set(nets) if not isinstance(nets, dict) else set(nets.keys())
        if wan in nets:
            owner = next((a for a, d in comp.fragments
                          if name.removeprefix(f"glove-{session}-") in (d.get("services") or {})), None)
            if egress_provider is None or owner is not egress_provider:
                raise ExtensionError(f"service {name!r} joins the wan network, which only the egress provider may")
        if harness_net in nets and name != plan.harness_service:
            role = name.removeprefix(f"glove-{session}-")
            if not any(e.name == role and e.harness for e in comp.endpoints) and role not in {
                s.role for s in plan.network.sidecars if s.harness
            }:
                raise ExtensionError(f"service {name!r} joins the harness network but is not a harness endpoint")
