"""observe hooks: settings, the netgate forwarder per endpoint, and session.json.

``forwarder`` makes every endpoint's forwarder a netgate ``forward`` (the
`forwarder` slot): same name, networks and port as the socat it replaces. The
gates read ``rules.json`` **only** while the `filter` extension is active —
observe alone never mounts ``~/.glove/control/<id>/`` and never passes
``--rules`` (``tests/test_observe_filter_split.py``).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from extensions.gate import gatelib
from extensions.gate.netgate import GATE_VERSION, SCHEMA_VERSION
from extensions.gate.netgate.exitid import check_url
from extensions.gate.netgate.records import iso_utc
from extensions.gate.netgate.resolver import from_url
from extensions.gate.netgate.writer import write_json_atomic
from glove.api import HookContext, hook

EVENTS_VOLUME = "events"  # the fragment's tmpfs volume


def _duration(v: Any) -> int | None:
    """``90s``, ``30m``, ``12h``, ``7d`` (or plain seconds) → seconds (>= 60); none → None."""
    if v in (None, "", "none"):
        return None
    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", str(v))
    if not m:
        raise ValueError(f"observe.retain must be a duration like 30m, 12h or 7d, got {v!r}")
    secs = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if secs < 60:
        raise ValueError("observe.retain must be at least 60s")
    return secs


def _check(s: dict[str, Any]) -> None:
    if s["record_headers"] and s["record"] != "full":
        raise ValueError("observe.record_headers needs observe.record: full")
    if s["rotate_mb"] <= 0 or s["keep"] < 0:
        raise ValueError("observe.rotate_mb must be > 0 and observe.keep >= 0")
    _duration(s["retain"])
    if s.get("resolver") not in (None, "", "none"):
        # There is deliberately no host resolver: destinations are only ever
        # resolved in-tunnel (§1.2 constraint 2). Parse only — nothing resolves here.
        from_url(str(s["resolver"]))
        if s["resolve"] == "none":
            raise ValueError("observe.resolver is set but observe.resolve is none — pick one")
    if s["exit_identity"] not in ("auto", "none"):
        try:
            check_url(s["exit_identity"])
        except ValueError:
            raise ValueError("observe.exit_identity must be auto, none or an https://<host>/… URL (got "
                             f"{s['exit_identity']!r}; `via-proxy` and exit_identity_url became a URL here)") from None


def exit_identity(ctx: HookContext) -> dict[str, str] | None:
    """Where the exit identity comes from: ``{url}`` (polled through the egress)
    or ``{source, volume, file}`` (the egress provider's shared file, e.g.
    vpn's `vpn-endpoint`) — the egress's `exit_identity` export under `auto`."""
    v = ctx.settings["exit_identity"]
    if v == "none":
        return None
    if v != "auto":
        return {"url": str(v)}
    ex = (ctx.slot.get("egress") or {}).get("exit_identity")
    if not ex:
        return None
    ok = isinstance(ex, dict) and (
        (set(ex) == {"url"} and _url_ok(ex["url"]))
        or (set(ex) == {"source", "volume", "file"}
            and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", str(ex[k])) for k in ex)))
    if not ok:
        raise ValueError("the egress's exit_identity export must be {url: https://…} or "
                         f"{{source, volume, file}}, got {ex!r}")
    return {k: str(x) for k, x in ex.items()}


def _url_ok(url: Any) -> bool:
    try:
        check_url(url)
    except ValueError:
        return False
    return True


def _polls_exit(harness: bool, mode: str | None, upstream: str | None) -> bool:
    """The gate that polls the exit: the harness's own proxy gate, chained to the
    egress (one, so the egress consumers' gates do not duplicate its records)."""
    return harness and mode == "http-proxy" and upstream != "direct"


def _polled(ctx: HookContext) -> bool:
    return any(f["observed"] and _polls_exit(f["harness"], f.get("mode"), f["route"].get("upstream"))
               for f in ctx.forwarders)


@hook
def contribute(ctx: HookContext) -> dict[str, Any]:
    s = ctx.settings
    _check(s)
    return {"exports": {"transcripts": bool(s["transcripts"])}}


def _rules(ctx: HookContext) -> bool:
    """The filter grant is on: core offers the control root to this extension."""
    return "control" in ctx.export_dirs


@hook
def forwarder(ctx: HookContext, ep: dict[str, Any]) -> dict[str, Any] | None:
    s = ctx.settings
    if ep["name"] in (s["skip"] or []):
        return None
    gate = gatelib.gate_spec(ep, ctx.slot.get("egress") or {})
    rules = _rules(ctx)
    volumes = [{"type": "volume", "source": EVENTS_VOLUME, "target": gatelib.EVENTS_DIR}]
    exit_url = exit_file = None
    exit_id = exit_identity(ctx) if _polls_exit(ep["harness"], gate.mode, gate.route_upstream) else None
    if exit_id and "url" in exit_id:
        exit_url = exit_id["url"]
    elif exit_id:
        # the egress provider's shared volume, read-only, in this gate only
        volumes.append({"type": "volume", "source": f"egress:{exit_id['volume']}", "target": gatelib.EXIT_DIR,
                        "read_only": True})
        exit_file = f"{exit_id['source']}={gatelib.EXIT_DIR}/{exit_id['file']}"
    rec = gatelib.Recording(
        record=s["record"], record_headers=s["record_headers"], resolve=s["resolve"],
        resolver=s.get("resolver") or None, rules=rules, exit_url=exit_url, exit_file=exit_file,
    )
    ingress = gatelib.ingress_alias(ep["container"]) if ep["harness"] else None
    if rules:
        # directory mount (atomic-rename writes stay visible), read-only
        volumes.append({"type": "bind", "source": str(ctx.export_dirs["control"]), "target": gatelib.CONTROL_DIR,
                        "read_only": True})
    return {
        "service": {
            "image": ctx.libs["gate"]["images"]["netgate"],
            "command": gatelib.forward_command(gate, rec, session=ctx.session["id"], listen=ep["port"],
                                               ingress=ingress),
            "volumes": volumes,
            "depends_on": ["netgate"],
        },
        "facts": gatelib.facts(gate, harness=ep["harness"]),
        "aliases": [ingress] if ingress else [],
    }


def session_facts(ctx: HookContext) -> dict[str, Any]:
    """Static ``net/session.json``: what Layman needs before any flow arrives —
    including services that have not been used yet (handoff §8)."""
    s = ctx.settings
    sid = ctx.session["id"]
    services = []
    for f in ctx.forwarders:
        entry = {k: f[k] for k in ("service", "listen", "observed", "harness", "next")}
        if f["observed"]:
            entry.update({k: f[k] for k in ("mode", "tool", "scope", "upstream", "route", "client")})
        services.append(entry)
    kinds = {f["route"]["kind"] for f in ctx.forwarders if f.get("observed") and f.get("mode") == "http-proxy"}
    egress = ctx.slot.get("egress") or {}
    resolver = s.get("resolver") or egress.get("resolver")
    return {
        "v": SCHEMA_VERSION,
        "type": "session",
        "env": sid,
        "session": sid,
        "harness": ctx.harness,
        "gate": GATE_VERSION,
        "image": ctx.libs["gate"]["images"]["netgate"],
        "record": s["record"],
        "resolve": s["resolve"],
        "resolver": resolver if s["resolve"] == "in-tunnel" and resolver not in (None, "", "none") else None,
        "exit_identity": _exit_fact(exit_identity(ctx) if _polled(ctx) else None),
        # session-level: the chained route if any gate proxies through one
        # (`direct` wins — it must never be masked), else tcp
        "upstream_kind": next((k for k in ("direct", "corporate", "vpn", "tor") if k in kinds), "tcp"),
        "rotate": {"max_bytes": int(s["rotate_mb"] * 1024 * 1024), "keep": s["keep"],
                   "retain_s": _duration(s["retain"])},
        "record_headers": s["record_headers"],
        "rendered_at": iso_utc(),
        "services": services,
        "grants": dict(ctx.grants),
    }


def _exit_fact(exit_id: dict[str, str] | None) -> str:
    if exit_id is None:
        return "none"
    return f"via-proxy:{exit_id['url']}" if "url" in exit_id else exit_id["source"]


@hook
def materialize(ctx: HookContext) -> None:
    """Lay out ``net/`` in the observe export (0700, the collector writes it as
    this user) and write ``session.json``. Core created the export root."""
    net = Path(ctx.export_dirs["observe"]) / "net"
    net.mkdir(mode=0o700, parents=True, exist_ok=True)
    net.chmod(0o700)
    if not write_json_atomic(net / "session.json", session_facts(ctx)):
        raise OSError(f"could not write {net}/session.json")
    s = ctx.settings
    if s["record"] == "full":
        print(
            "⚠ observe.record: full — this session writes a browsing log to "
            f"{net}: the method and URL of every cleartext HTTP request"
            + (" and request headers (credentials redacted)" if s["record_headers"] else "")
            + ". HTTPS paths stay invisible (no TLS interception). This trades the session's privacy for "
            "visibility; `glove observe status` and Layman badge it.", file=sys.stderr)
    if _rules(ctx):
        problem = gatelib.rules_file_problem(Path(ctx.export_dirs["control"]))
        if problem:
            print(f"⚠ rules.json: {problem} — the gates run as you, so they will reject this file "
                  "(status.json rules.ok: false) and enforce no rules until it is readable. A second writer "
                  "must leave it readable by you: mode 0644, or owned by you.", file=sys.stderr)
