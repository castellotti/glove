"""``glove doctor``: probe the host, runtime, and enforcer.

Aggregates host-tool checks and Docker Desktop hints with the runtime's own
container probes (Landlock ABI, seccomp, kvm) and per-enforcer readiness. Every
check is a small, side-effect-light probe; the command has a ``--json`` mode so
tests can assert structure without scraping Rich output.
"""

from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from .runtimes import get_runtime
from .runtimes.base import Check
from .runtimes.landlock_mounts import landlock_enforced

if TYPE_CHECKING:
    from .extensions import Composition

# Docker Desktop's default File sharing list when no explicit key is set.
_DEFAULT_FILE_SHARING = ["/Users", "/Volumes", "/private", "/tmp", "/var/folders"]


def _file_sharing_check() -> Check:
    """Best-effort read of Docker Desktop's File sharing list (macOS)."""
    settings = (
        Path.home()
        / "Library/Group Containers/group.com.docker/settings-store.json"
    )
    if not settings.is_file():
        return Check(
            "docker desktop file sharing",
            "info",
            f"defaults assumed: {', '.join(_DEFAULT_FILE_SHARING)} — recommend narrowing to code roots",
        )
    try:
        data = json.loads(settings.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return Check("docker desktop file sharing", "warn", f"unreadable: {e}")
    shared = data.get("filesharingDirectories") or data.get("FilesharingDirectories")
    if not shared:
        return Check(
            "docker desktop file sharing",
            "info",
            f"key absent; defaults: {', '.join(_DEFAULT_FILE_SHARING)} — recommend narrowing",
        )
    return Check("docker desktop file sharing", "ok", ", ".join(shared))


def _enforcer_checks(enforcer: str, runtime) -> list[Check]:
    # Runtime/enforcer compatibility gate, surfaced BEFORE the enforcer's own
    # probes: a combo the runtime can't render (e.g. podman + srt) fails here up
    # front rather than aborting mid-render on `glove run`.
    reason = runtime.unsupported_enforcer_reason(enforcer)
    if reason:
        return [Check(f"enforcer: {enforcer} on {runtime.name}", "fail", reason)]
    try:
        from .enforcers import get_enforcer

        return get_enforcer(enforcer).doctor(runtime)
    except ValueError as e:
        return [Check(f"enforcer: {enforcer}", "warn", str(e))]


def extension_checks(requested: dict, *, harness: str, comp: Composition | None = None, probe=None,
                     **session) -> list[Check]:
    """Selection/settings validation plus each extension's own `doctor` hook.
    ``comp``: the session plan's composition, when it already built one; ``session``:
    its `session_dir` (relative path settings), `enforcer` and `enforcer_options` when it did not;
    ``probe``: ``probe(url, method=, body=, headers=)`` → (status, text), a
    request to what the session reaches from a throwaway container, never the
    host; a `doctor(ctx, probe)` hook calls ``probe(url, method=, body=)``, as at
    launch, with its own ``probe_headers`` export (None: a hook contacts nothing)."""
    from .extensions import call_hook, compose
    from .session import with_headers

    if comp is None:
        try:
            # Stand-in paths: nothing is created; export roots only need to render
            # (observe/filter fragments bind them).
            comp = compose(requested, harness=harness, session="doctor", state_root=Path("/nonexistent"), **session,
                           export_dirs={r: Path("/nonexistent") / r for r in ("observe", "control")})
        except ValueError as e:
            return [Check("extensions", "fail", str(e))]
    checks = [Check("extensions", "ok", ", ".join(f"{a.name} ({a.manifest.taint})" for a in comp.active))]
    for a in comp.active:
        if "doctor" in a.hooks:
            hook_probe = probe and with_headers(probe, a.exports)
            checks += [Check(n, st, d) for n, st, d in call_hook(comp, a, "doctor", hook_probe)]
        checks += egress_host_checks(comp, a)
    return checks


def egress_host_checks(comp: Composition, a) -> list[Check]:
    """An egress that admits only listed names (`guard_hosts`, e.g.
    `corporate.allow_domains`) must admit every name an extension's sidecars
    reach (its contributed `egress_hosts`: names, or `*.x` for x's
    subdomains). The gate also checks the address a name resolves to: a
    private one passes only inside an allowed CIDR (`guard_cidrs`)."""
    wanted = a.contributed.get("egress_hosts") or []
    egress = comp.slots.get("egress")
    guard = egress.exports.get("guard_hosts") if egress is not None else None
    if not wanted or not guard:  # nothing named, or an egress that does not filter by name
        return []
    missing = [h for h in wanted if not any(fnmatch.fnmatchcase(h.replace("*", "sub", 1), g) for g in guard)]
    if missing:
        return [Check(f"{a.name} egress", "warn", f"{egress.name} does not admit all it reaches: add "
                      f"{', '.join(repr(h) for h in missing)} to the hosts {egress.name} allows")]
    cidrs = "" if egress.exports.get("guard_cidrs") else (
        f"; a name that resolves to a private address needs {egress.name} to allow it by CIDR too")
    return [Check(f"{a.name} egress", "ok", f"{egress.name} admits {', '.join(wanted)}{cidrs}")]


def landlock_mounts_check(rt) -> Check:
    """Whether Landlock (nono) can open files on a bind mount, probed afresh."""
    mm = rt.landlock_mounts(refresh=True)
    note = {"virtiofs": "; the harness's binds need Docker Desktop's virtiofs layer (its fakeowner layer "
                        "breaks Landlock)",
            "broken": "; a session whose enforcer runs nono is refused (README: Docker Desktop shared folders)"}
    return Check("landlock on a bind mount", {"broken": "fail", "unknown": "warn"}.get(mm.mode, "ok"),
                 f"{mm.mode}: {mm.detail}{note.get(mm.mode, '')}")


def run_doctor(
    *,
    runtime: str = "docker",
    enforcer: str = "nono",
    include_container_probes: bool = True,
) -> list[Check]:
    """Full doctor report for the given runtime/enforcer selection."""
    checks: list[Check] = [Check("os", "info", f"{os.uname().sysname} {os.uname().release} {os.uname().machine}")]
    rt = get_runtime(runtime)
    if not rt.caps.tested:
        checks.append(Check(f"runtime: {runtime}", "warn",
                            "ships but UNTESTED on this host — validate before relying on it"))
    if not rt.caps.implemented:
        checks.append(Check(f"runtime: {runtime}", "warn", "not implemented (stub)"))
    if include_container_probes:
        checks.extend(rt.doctor())
    else:
        checks.append(Check(f"runtime: {runtime}", "info", "container probes skipped"))
    checks.extend(_enforcer_checks(enforcer, rt))
    if include_container_probes and landlock_enforced(enforcer) and rt.caps.implemented:
        checks.append(landlock_mounts_check(rt))
    # Docker Desktop's File sharing list is a docker-only concept; podman shares
    # the whole home via the machine mount, so the hint is misleading there.
    if runtime == "docker":
        checks.append(_file_sharing_check())
    return checks


def worst_status(checks: list[Check]) -> str:
    order = {"fail": 3, "warn": 2, "ok": 1, "skip": 0, "info": 0}
    return max(checks, key=lambda c: order.get(c.status, 0)).status if checks else "ok"
