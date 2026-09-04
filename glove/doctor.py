"""``glove doctor``: probe the host, runtime, and enforcer.

Aggregates host-tool checks and Docker Desktop hints with the runtime's own
container probes (Landlock ABI, seccomp, kvm) and per-enforcer readiness. Every
check is a small, side-effect-light probe; the command has a ``--json`` mode so
tests can assert structure without scraping Rich output.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from .runtimes import get_runtime
from .runtimes.base import Check

# Docker Desktop's default File sharing list when no explicit key is set.
_DEFAULT_FILE_SHARING = ["/Users", "/Volumes", "/private", "/tmp", "/var/folders"]


def _host_tool_checks() -> list[Check]:
    checks: list[Check] = []
    for tool, why in (
        ("ssh", "host_services: SSH model tunnel"),
        ("node", "host_services: Playwright MCP/server"),
        ("npx", "host_services: Playwright MCP/server"),
    ):
        path = shutil.which(tool)
        checks.append(
            Check(f"host tool: {tool}", "ok" if path else "warn", path or f"absent — needed for {why}")
        )
    return checks


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
    try:
        from .enforcers import get_enforcer

        return get_enforcer(enforcer).doctor(runtime)
    except ValueError as e:
        return [Check(f"enforcer: {enforcer}", "warn", str(e))]


def _browser_checks(browser: str | None) -> list[Check]:
    if not browser or browser == "none":
        return []
    try:
        from .browsers import get_provider
        from .config import Config

        return get_provider(browser).doctor(Config())
    except ValueError as e:
        return [Check(f"browser: {browser}", "warn", str(e))]


def run_doctor(
    *,
    runtime: str = "docker",
    enforcer: str = "nono",
    browser: str | None = None,
    include_container_probes: bool = True,
) -> list[Check]:
    """Full doctor report for the given runtime/enforcer/browser selection."""
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
    checks.extend(_browser_checks(browser))
    checks.append(_file_sharing_check())
    checks.extend(_host_tool_checks())
    return checks


def worst_status(checks: list[Check]) -> str:
    order = {"fail": 3, "warn": 2, "ok": 1, "skip": 0, "info": 0}
    return max(checks, key=lambda c: order.get(c.status, 0)).status if checks else "ok"
