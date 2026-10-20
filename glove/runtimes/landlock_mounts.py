"""The bind mode a Landlock-wrapped container needs.

Docker Desktop (4.96+) serves its shares through ``fakeowner`` over virtiofs, and
Landlock never matches a rule for a ``fakeowner`` file; the same file bound from
the virtiofs layer (``/run/host_virtiofs/<path>`` in the VM) works. The probe
(``landlock_probe.py``) tests a temp dir bound both ways. Modes: ``native`` (the
normal path works), ``virtiofs`` (only that layer does), ``broken`` (neither: a
nono session is refused), ``unknown`` (not probed, or a failure that isn't
Landlock's). Cached per engine (version, kernel, Docker Desktop settings) in
``~/.glove/runtime-cache.json``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..registry import glove_home, write_json_atomic

if TYPE_CHECKING:
    from .docker import DockerRuntime

VIRTIOFS_ROOT = "/run/host_virtiofs"
MIN_LANDLOCK_ABI = 4  # nono's floor (also doctor's "landlock (hardened container)")
PROBE_SCRIPT = Path(__file__).with_name("landlock_probe.py")
DESKTOP_SETTINGS = Path.home() / "Library/Group Containers/group.com.docker/settings-store.json"
_IN = "/glove-probe"  # where the probe's binds land in its container


@dataclass(frozen=True)
class MountMode:
    mode: str  # native | virtiofs | broken | unknown
    detail: str


def landlock_enforced(enforcer: str) -> bool:
    """Whether the enforcer runs nono (Landlock) around commands."""
    return "nono" in enforcer.split("+")


def _first_bad(steps: dict | None) -> str | None:
    bad = next(((k, v) for k, v in (steps or {"probe": "no result"}).items() if v != "ok"), None)
    return " ".join(bad) if bad else None


def classify(report: dict) -> MountMode:
    """The mode from the probe's JSON report."""
    abi = report.get("abi")
    if not isinstance(abi, int) or abi < MIN_LANDLOCK_ABI:
        return MountMode("broken", f"Landlock ABI {abi} in the engine (nono needs {MIN_LANDLOCK_ABI}+)")
    ok, parts = {}, []
    for name, label in (("native", "normal path"), ("virtiofs", "virtiofs layer")):
        m = report.get("mounts", {}).get(f"{_IN}/{name}")
        if m is None:
            continue
        control = _first_bad(m.get("control"))
        if control:  # denied without Landlock too: file modes, SELinux, uid mapping — not what this probes
            return MountMode("unknown", f"{label} {m.get('fstype', '?')} fails without Landlock: {control}")
        bad = _first_bad(m.get("steps"))
        # a source Docker made up would be the VM's own disk: only a real virtiofs mount counts
        ok[name] = bad is None and (name == "native" or m.get("fstype", "").startswith("virtiofs"))
        parts.append(f"{label} {m.get('fstype', '?')}: {bad or 'ok'}")
    mode = "native" if ok.get("native") else "virtiofs" if ok.get("virtiofs") else "broken"
    return MountMode(mode, "; ".join(parts))


def probe(rt: DockerRuntime, desktop: bool) -> MountMode:
    """A temp dir under ~/.glove bound from its normal path (and on Docker
    Desktop from the virtiofs layer), probed as the host user."""
    glove_home().mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="landlock-probe-", dir=glove_home())
    binds = [(tmp, f"{_IN}/native", True)]
    if desktop:  # --mount refuses a missing source: a moved layer fails, then only the normal path runs
        binds.append((f"{VIRTIOFS_ROOT}{os.path.realpath(tmp)}", f"{_IN}/virtiofs", True))
    try:
        for b in (binds, binds[:1]) if desktop else (binds,):
            proc = subprocess.run(rt.throwaway_argv(
                rt.probe_image, ["python3", f"{_IN}.py", *(t for _, t, _ in b)], as_host=True, binds=b,
                mounts=[(str(PROBE_SCRIPT), f"{_IN}.py")]), capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                return classify(json.loads(proc.stdout.strip().splitlines()[-1]))
        return MountMode("unknown", f"probe failed: {proc.stderr.strip()[-200:]}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, IndexError) as e:
        return MountMode("unknown", f"probe failed: {e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def mount_mode(rt: DockerRuntime, *, refresh: bool = False) -> MountMode:
    """The cached mode for this engine (probed on a miss, or with ``refresh``)."""
    try:
        ver = shutil.which(rt.cli) and subprocess.run([rt.cli, *rt.engine_key_argv], capture_output=True,
                                                      text=True, timeout=15)
    except subprocess.TimeoutExpired:
        ver = None
    if not ver or ver.returncode != 0:
        return MountMode("unknown", f"{rt.cli} engine not available")
    key, desktop = ver.stdout.strip(), "Docker Desktop" in ver.stdout
    if desktop and DESKTOP_SETTINGS.is_file():
        key += f" settings@{DESKTOP_SETTINGS.stat().st_mtime_ns}"
    path = glove_home() / "runtime-cache.json"
    try:
        cache = json.loads(path.read_text())
    except (OSError, ValueError):
        cache = {}
    cache = cache if isinstance(cache, dict) else {}  # damaged: a miss, rewritten below
    hit = cache.get(rt.name)
    if not refresh and isinstance(hit, dict) and hit.get("key") == key and hit.get("mode") in ("native", "virtiofs"):
        return MountMode(hit["mode"], str(hit.get("detail", "")))
    mm = probe(rt, desktop)
    if mm.mode in ("native", "virtiofs"):  # a failure is never cached: the next launch probes again
        write_json_atomic(path, {**cache, rt.name: {"key": key, **asdict(mm)}})
    return mm
