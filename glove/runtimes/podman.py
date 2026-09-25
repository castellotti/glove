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

- **Netgate (observe).** The events tmpfs volume's ``uid=``/``gid=`` are
  interpreted in the rootless user namespace, so they are ``0`` (the host user)
  there; and the gate's ``net/``/``control/`` binds carry ``selinux: z``, since
  an SELinux-enforcing host denies containers an unlabelled bind. Verified in a
  podman machine VM (Fedora, SELinux enforcing) on its own filesystem.

Validated on rootless podman 6 (libkrun machine, Fedora VM, Landlock ABI 9).
``srt`` is not supported on podman yet: its relaxed nested-userns profile can't
be applied through the inlining compose provider.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import replace
from typing import TYPE_CHECKING

from .base import Check
from .docker import DockerRuntime

if TYPE_CHECKING:
    from ..plan import SessionPlan


# Successful `podman info` probes, keyed by cli name. Only *successful* results
# are memoized (see _host_info) so a transient early failure never sticks.
_HOST_INFO_CACHE: dict[str, dict[str, str]] = {}


def _probe_host_info(cli: str) -> dict[str, str]:
    """One `podman info` call for the Host fields doctor + rootless detection
    need (kernel, rootless, seccomp, selinux). ``{}`` when podman is absent or the probe
    fails, so callers fall back to safe defaults and ``--dry-run`` on a host
    without podman never shells out.

    Field order matters: the boolean security flags come first and the
    free-text kernel string last, split with ``maxsplit=3`` so a kernel
    description containing ``|`` lands wholly in the trailing field instead of
    shifting rootless/seccomp onto a kernel fragment.
    """
    if not shutil.which(cli):
        return {}
    proc = subprocess.run(
        [cli, "info", "--format",
         "{{.Host.Security.Rootless}}|{{.Host.Security.SECCOMPEnabled}}|{{.Host.Security.SELinuxEnabled}}"
         "|{{.Host.Kernel}}"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return {}
    parts = [*proc.stdout.strip().split("|", 3), "", "", "", ""]
    return {"rootless": parts[0], "seccomp": parts[1], "selinux": parts[2], "kernel": parts[3]}


def _host_info(cli: str) -> dict[str, str]:
    """`_probe_host_info` memoized process-wide by cli name.

    Cached at module scope, not on the instance: ``get_runtime('podman')`` builds
    a fresh ``PodmanRuntime`` per call, so an instance-level cache would re-probe
    on every doctor/plan/run step.

    Only a *successful* (non-empty) probe is cached. A transient failure — the
    podman machine not yet ready on the first probe of a process — must not
    permanently pin rootless/seccomp/kernel to their unknown-defaults for the
    whole run; leaving it uncached lets the next call re-probe once the machine
    is up.
    """
    cached = _HOST_INFO_CACHE.get(cli)
    if cached is not None:
        return cached
    info = _probe_host_info(cli)
    if info:
        _HOST_INFO_CACHE[cli] = info
    return info


# functools.cache-style hook so tests (and callers) can drop the memoized probe.
_host_info.cache_clear = _HOST_INFO_CACHE.clear  # type: ignore[attr-defined]


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

    def selinux_enabled(self) -> bool:
        """Whether the podman host enforces SELinux labels. False when unknown:
        a ``context=`` mount option on a kernel without SELinux fails the mount,
        while a missing label on an SELinux host fails visibly at gate start."""
        return _host_info(self.cli).get("selinux", "") == "true"

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
        rootless = self.is_rootless()
        return {
            # Map the host uid/gid through so bind mounts stay owned by the
            # non-root harness user (rootless only; rootful maps 1:1 already).
            "userns_mode": "keep-id" if rootless else None,
            # Rely on podman's built-in default seccomp (see module docstring).
            "emit_seccomp": False,
            "host_gateway_name": self.caps.host_gateway_name or "host.docker.internal",
            # Rootless podman mounts the events tmpfs inside its user namespace,
            # where the host user is uid 0: `uid=<host uid>` would name a subuid
            # (seen as 500:999 under keep-id) and the gate could not create its
            # socket. Namespace root is the host user, i.e. the gate's uid.
            "events_owner": (0, 0) if rootless else None,
            # ...and on SELinux the shared tmpfs needs a container label too, or
            # container_t may not create the socket in it (tmpfs_t). A bind can
            # say `selinux: z`; a tmpfs volume only takes a mount `context=`.
            "events_context": "system_u:object_r:container_file_t:s0" if self.selinux_enabled() else None,
            # SELinux-enforcing hosts (Fedora/RHEL) deny containers an unlabelled
            # bind; `z` (shared: the collector and every forwarder mount them)
            # relabels net/ and control/. A no-op where SELinux is off, and on a
            # podman machine's virtiofs share.
            "gate_bind_selinux": "z",
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
