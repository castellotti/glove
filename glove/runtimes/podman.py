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
  but egress forwarder sidecars route off-host through gvproxy.

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


class PodmanRuntime(DockerRuntime):
    name = "podman"
    cli = "podman"
    caps = replace(DockerRuntime.caps, compose_cmd=("podman", "compose"), tested=True)

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
        if not shutil.which(self.cli):
            self._rootless = True
            return self._rootless
        proc = subprocess.run(
            [self.cli, "info", "--format", "{{.Host.Security.Rootless}}"],
            capture_output=True, text=True,
        )
        self._rootless = proc.returncode != 0 or proc.stdout.strip() != "false"
        return self._rootless

    # --- rendering ---------------------------------------------------------

    def compose_extra(self, plan: SessionPlan) -> dict:
        if plan.enforcer == "srt":
            raise NotImplementedError(
                "enforcer 'srt' is not supported on the podman runtime yet: its "
                "relaxed seccomp profile can't be applied through podman's "
                "inlining compose provider. Use --enforcer nono (or run srt on "
                "the docker runtime)."
            )
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
        # `info` (`.Host.Kernel`).
        ver = subprocess.run(
            [self.cli, "version", "--format", "{{.Server.Version}} {{.Server.OsArch}}"],
            capture_output=True, text=True,
        )
        if ver.returncode != 0:
            return Check("podman engine", "fail", ver.stderr.strip() or "not responding")
        kern = subprocess.run(
            [self.cli, "info", "--format", "{{.Host.Kernel}}"],
            capture_output=True, text=True,
        )
        detail = ver.stdout.strip()
        if kern.returncode == 0 and kern.stdout.strip():
            detail += f" kernel={kern.stdout.strip()}"
        return Check("podman engine", "ok", detail)

    def _security_checks(self) -> list[Check]:
        info = subprocess.run(
            [self.cli, "info", "--format",
             "seccomp={{.Host.Security.SECCOMPEnabled}} rootless={{.Host.Security.Rootless}}"],
            capture_output=True, text=True,
        )
        sec = info.stdout.strip()
        checks = [Check("security options", "ok" if "seccomp=true" in sec else "warn", sec)]
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
