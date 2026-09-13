"""The ``podman`` runtime — a docker subclass with rootless-podman handling.

Reuses the docker runtime's compose rendering and hardening; only the CLI
binary, the compose provider, and a handful of rootless/compat differences
diverge:

- **Rootless userns.** Rootless podman maps the invoking uid to container root
  by default, so a bind mount owned by the host user appears owned by root and
  the non-root ``user: <uid:gid>`` harness cannot write it. ``userns_mode:
  keep-id`` maps the host uid/gid straight through, restoring ownership.
- **Seccomp.** ``podman compose`` runs an external compose provider
  (docker-compose) that inlines a referenced seccomp profile's JSON; podman's
  compat API then treats that JSON blob as a *path* and fails. glove therefore
  omits the custom profile on podman and relies on podman's built-in default
  (the same moby-derived filter that already allows the ``landlock_*`` calls).
- **Host gateway / networking.** podman provides both ``host.docker.internal``
  and ``host.containers.internal`` (gvproxy); the harness never uses either,
  but egress forwarder sidecars route off-host through gvproxy. The template's
  ``extra_hosts: host.docker.internal:host-gateway`` on host-service forwarders
  is safe here: on rootless podman 6 ``host-gateway`` resolves to gvproxy's host
  address (192.168.127.254) — identical to podman's built-in
  ``host.containers.internal`` and distinct from the netavark bridge gateway
  (10.88.0.x) — so it reaches the host rather than shadowing it. Verified with
  ``podman run --add-host host.docker.internal:host-gateway`` on this machine.

Validated on rootless podman 6 (libkrun machine, Fedora VM, Landlock ABI 9).
``srt`` is not supported on podman yet: its relaxed nested-userns profile can't
be applied through the inlining compose provider.
"""

from __future__ import annotations

import functools
import shutil
import subprocess
from dataclasses import replace
from typing import TYPE_CHECKING

from .base import Check
from .docker import DockerRuntime

if TYPE_CHECKING:
    from ..plan import SessionPlan


@functools.cache
def _host_info(cli: str) -> dict[str, str]:
    """One `podman info` call for every Host field doctor + rootless detection
    need (kernel, rootless, seccomp), cached process-wide by cli name.

    Cached at module scope, not on the instance: ``get_runtime('podman')`` builds
    a fresh ``PodmanRuntime`` per call, so an instance-level cache would re-probe
    on every doctor/plan/run step. Returns ``{}`` when podman is absent or the
    probe fails (callers fall back to safe defaults). Empty on missing binary so
    ``--dry-run`` on a host without podman never shells out.
    """
    if not shutil.which(cli):
        return {}
    proc = subprocess.run(
        [cli, "info", "--format",
         "{{.Host.Kernel}}|{{.Host.Security.Rootless}}|{{.Host.Security.SECCOMPEnabled}}"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return {}
    parts = [*proc.stdout.strip().split("|"), "", "", ""]
    return {"kernel": parts[0], "rootless": parts[1], "seccomp": parts[2]}


class PodmanRuntime(DockerRuntime):
    name = "podman"
    cli = "podman"
    caps = replace(
        DockerRuntime.caps,
        compose_cmd=("podman", "compose"),
        tested=True,
        # podman's compose provider inlines a referenced seccomp file (rejected by
        # the compat API), so glove omits it and relies on podman's built-in
        # default — the same moby-derived filter that allows landlock_*. This flag
        # sanctions that omission for the render-layer seccomp invariant check.
        applies_builtin_seccomp=True,
    )

    _rootless: bool | None = None

    # --- rootless detection ------------------------------------------------

    def is_rootless(self) -> bool:
        """Whether podman runs rootless (cached). Defaults True when unknown.

        The macOS/podman-machine case is always rootless; a host without podman
        (e.g. ``--dry-run``) can't be probed, and rootless is the safe default
        there since ``keep-id`` is the setting most hosts need.
        """
        if self._rootless is not None:
            return self._rootless
        # `!= "false"` (not `== "true"`) keeps rootless the default when podman is
        # absent or the probe fails: _host_info returns {} → "" → rootless.
        self._rootless = _host_info(self.cli).get("rootless", "") != "false"
        return self._rootless

    # --- compatibility -----------------------------------------------------

    def unsupported_enforcer_reason(self, enforcer: str) -> str | None:
        if enforcer == "srt":
            return (
                "enforcer 'srt' is not supported on the podman runtime yet: its "
                "relaxed seccomp profile can't be applied through podman's "
                "inlining compose provider. Use --enforcer nono (or run srt on "
                "the docker runtime)."
            )
        return None

    # --- rendering ---------------------------------------------------------

    def compose_extra(self, plan: SessionPlan) -> dict:
        reason = self.unsupported_enforcer_reason(plan.enforcer)
        if reason:
            raise NotImplementedError(reason)
        return {
            # Map the host uid/gid through so bind mounts stay owned by the
            # non-root harness user (rootless only; rootful maps 1:1 already).
            "userns_mode": "keep-id" if self.is_rootless() else None,
            # Rely on podman's built-in default seccomp (see module docstring).
            "emit_seccomp": False,
            "host_gateway_name": self.caps.host_gateway_name or "host.docker.internal",
        }

    # --- doctor ------------------------------------------------------------

    def _engine_check(self) -> Check:
        # podman's `version --format` has no `.Server.Os`/`.Server.Arch`/
        # `.Server.KernelVersion`; use `.Server.OsArch` and read the kernel from
        # the shared (cached) `podman info` probe (`.Host.Kernel`).
        ver = subprocess.run(
            [self.cli, "version", "--format", "{{.Server.Version}} {{.Server.OsArch}}"],
            capture_output=True, text=True,
        )
        if ver.returncode != 0:
            return Check("podman engine", "fail", ver.stderr.strip() or "not responding")
        detail = ver.stdout.strip()
        kernel = _host_info(self.cli).get("kernel")
        if kernel:
            detail += f" kernel={kernel}"
        return Check("podman engine", "ok", detail)

    def _security_checks(self) -> list[Check]:
        info = _host_info(self.cli)
        sec = f"seccomp={info.get('seccomp', '')} rootless={info.get('rootless', '')}"
        checks = [Check("security options", "ok" if info.get("seccomp") == "true" else "warn", sec)]
        # A compose provider must exist or the compose-based launch path fails.
        prov = subprocess.run(
            [self.cli, "compose", "version"], capture_output=True, text=True,
        )
        if prov.returncode == 0:
            line = next((ln for ln in prov.stdout.splitlines() if ln.strip()), "").strip()
            checks.append(Check("compose provider", "ok", line or "available"))
        else:
            checks.append(Check(
                "compose provider", "fail",
                "no `podman compose` provider — install docker-compose "
                "(brew install docker-compose) or podman-compose",
            ))
        return checks

    def _probe_seccomp_args(self) -> list[str]:
        # podman applies its built-in default profile; passing glove's vendored
        # path would be inlined/rejected the same way the harness service is.
        return []
