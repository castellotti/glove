"""Reading a session's ``net/`` dir for ``glove net status|flows``.

Implements the reader side of the handoff contract (§2) — the same rules Layman
follows, so this doubles as the reference reader:

- only complete (``\\n``-terminated) lines are consumed; a line that does not
  parse is skipped, as is any record whose ``type`` is not ``flow``;
- rotated ``flows-<ts>.ndjson`` files are read before the live ``flows.ndjson``,
  and flow state keys on ``id`` across files (an ``open`` and its ``close`` may
  straddle a rotation);
- ``follow`` detects rotation by inode change and drains the renamed file
  through its still-open descriptor before switching.

Pure file reads — nothing here touches the network or resolves a name.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

from rich.markup import escape

STALE_AFTER_S = 20.0


def _parse_line(raw: bytes) -> dict | None:
    try:
        rec = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(rec, dict) or rec.get("type") != "flow":
        return None
    return rec


def flow_files(net_dir: Path) -> list[Path]:
    net_dir = Path(net_dir)
    files = sorted(net_dir.glob("flows-*.ndjson"))
    live = net_dir / "flows.ndjson"
    if live.is_file():
        files.append(live)
    return files


def read_records(net_dir: Path) -> list[dict]:
    out: list[dict] = []
    for path in flow_files(net_dir):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for raw in data.split(b"\n")[:-1]:  # the tail after the last \n is incomplete
            rec = _parse_line(raw)
            if rec is not None:
                out.append(rec)
    return out


def follow_records(
    net_dir: Path,
    *,
    from_end: bool = True,
    poll: float = 0.25,
    stop: Callable[[], bool] | None = None,
) -> Iterator[dict]:
    path = Path(net_dir) / "flows.ndjson"
    fh = None
    ino = None
    buf = b""
    first = True
    while stop is None or not stop():
        if fh is None:
            try:
                fh = open(path, "rb")  # noqa: SIM115 - held open across rotations
            except FileNotFoundError:
                time.sleep(poll)
                first = False
                continue
            if first and from_end:
                fh.seek(0, os.SEEK_END)
            first = False
            ino = os.fstat(fh.fileno()).st_ino
            buf = b""
        chunk = fh.read()
        if chunk:
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for raw in lines:
                rec = _parse_line(raw)
                if rec is not None:
                    yield rec
            continue
        try:
            current = os.stat(path).st_ino
        except FileNotFoundError:
            current = None
        if current != ino:
            # Rotated: the old inode is fully drained (read() hit EOF above);
            # the next file is new, so read it from its start.
            fh.close()
            fh = None
            continue
        time.sleep(poll)
    if fh is not None:
        fh.close()


def _load_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _parse_ts(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def summarize(net_dir: Path, *, now: float | None = None) -> dict:
    net_dir = Path(net_dir)
    now = time.time() if now is None else now
    facts = _load_json(net_dir / "session.json")
    status = _load_json(net_dir / "status.json")

    gate_state = "absent"
    age = None
    if status is not None:
        beat = _parse_ts(status.get("t"))
        age = None if beat is None else round(now - beat, 1)
        if status.get("state") != "running":
            gate_state = str(status.get("state"))
        elif age is not None and age > STALE_AFTER_S:
            gate_state = "stale"
        else:
            gate_state = "running"

    latest: dict[str, dict] = {}
    for rec in read_records(net_dir):
        fid = rec.get("id")
        if isinstance(fid, str):
            latest[fid] = rec
    by_service: dict[str, dict] = {}
    reasons: Counter = Counter()
    up = down = active = 0
    for rec in latest.values():
        b = rec.get("bytes") or {}
        u, d = int(b.get("up") or 0), int(b.get("down") or 0)
        up += u
        down += d
        svc = by_service.setdefault(str(rec.get("service")), {"flows": 0, "active": 0, "up": 0, "down": 0})
        svc["flows"] += 1
        svc["up"] += u
        svc["down"] += d
        if rec.get("phase") == "close":
            reasons[str(rec.get("close_reason"))] += 1
        else:
            active += 1
            svc["active"] += 1

    return {
        "net_dir": str(net_dir),
        "observed": facts is not None,
        "session": facts,
        "status": status,
        "gate_state": gate_state,
        "status_age_s": age,
        "flows": {
            "total": len(latest),
            "active": active,
            "bytes_up": up,
            "bytes_down": down,
            "by_service": by_service,
            "close_reasons": dict(reasons),
        },
        "files": [p.name for p in flow_files(net_dir)],
    }


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{n}B"  # pragma: no cover


def render_status(env_id: str, sname: str, net_dir: Path, s: dict) -> list[str]:
    lines = [f"[bold]{env_id}[/bold] / session [bold]{sname}[/bold]  [dim]{net_dir}[/dim]"]
    if not s["observed"]:
        lines.append(
            "  [yellow]not observed[/yellow] — no net/session.json. Enable with "
            "`observe: {enabled: true}` in the env's glove.yaml and re-run."
        )
        return lines
    facts = s["session"] or {}
    st = s["status"] or {}
    colour = {"running": "green", "stale": "yellow", "stopped": "dim", "absent": "red"}.get(s["gate_state"], "red")
    age = f" (heartbeat {s['status_age_s']}s ago)" if s["status_age_s"] is not None else ""
    lines.append(f"  gate      [{colour}]{s['gate_state']}[/{colour}]{age}  version {facts.get('gate')}")
    record = st.get("record") or facts.get("record")
    badge = "  [bold red]FULL — browsing log on disk[/bold red]" if record == "full" else ""
    lines.append(f"  record    {record}{badge}")
    upstream = st.get("upstream") or {"kind": facts.get("upstream_kind"), "healthy": None}
    lines.append(f"  upstream  {upstream.get('kind')}  healthy={upstream.get('healthy')}")
    resolver = st.get("resolver") or {"mode": facts.get("resolve"), "healthy": None}
    lines.append(f"  resolver  {resolver.get('mode')}  healthy={resolver.get('healthy')}")
    rules = st.get("rules") or {}
    lines.append(
        f"  rules     {rules.get('active_count', 0)} active  ok={rules.get('ok', True)}"
        + (f"  error={rules.get('error')}" if rules.get("error") else "")
        + "  [dim](default allow; rules land in M3)[/dim]"
    )
    tel = st.get("telemetry") or {}
    if tel:
        lines.append(
            f"  telemetry written={tel.get('written')} dropped={tel.get('dropped')} "
            f"invalid={tel.get('invalid')} rotations={tel.get('rotations')}"
        )
    lines.append("  services")
    flows = s["flows"]
    for svc in facts.get("services", []):
        name = svc.get("service")
        stats = flows["by_service"].get(name, {"flows": 0, "active": 0, "up": 0, "down": 0})
        if svc.get("observed"):
            desc = (f"{svc.get('mode')} → {svc.get('upstream')}  tool={svc.get('tool')} "
                    f"scope={svc.get('scope') or 'per-destination'}")
        else:
            desc = "[dim]not observed (plain socat)[/dim]"
        lines.append(
            f"    {name:<10} {desc}  flows={stats['flows']} active={stats['active']} "
            f"↑{human_bytes(stats['up'])} ↓{human_bytes(stats['down'])}"
        )
    lines.append(
        f"  totals    flows={flows['total']} active={flows['active']} "
        f"↑{human_bytes(flows['bytes_up'])} ↓{human_bytes(flows['bytes_down'])}"
        + (f"  closes={flows['close_reasons']}" if flows["close_reasons"] else "")
    )
    return lines


def format_record(rec: dict) -> str:
    t = str(rec.get("t", ""))[11:23]
    dest = rec.get("dest") or {}
    host = escape(str(dest.get("host") or dest.get("ip") or "?"))
    b = rec.get("bytes") or {}
    phase = rec.get("phase", "?")
    reason = f"  ({rec.get('close_reason')})" if phase == "close" else ""
    verdict = rec.get("verdict", "allow")
    vcol = "red" if verdict == "block" else "green"
    return (
        f"{t}  {phase:<6} {rec.get('service', '?'):<8} tool={rec.get('tool')!s:<10} "
        f"{rec.get('client', '?')} → {host}:{dest.get('port')} ({rec.get('scope')})  "
        f"↑{human_bytes(int(b.get('up') or 0))} ↓{human_bytes(int(b.get('down') or 0))}  "
        f"[{vcol}]{verdict}[/{vcol}]{reason}  [dim]{rec.get('id')}[/dim]"
    )
