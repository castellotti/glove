"""The ``nono`` enforcer — default ring-1 Landlock sandbox."""

from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

from ...runtimes.base import Check
from . import policies
from .version import nono_image_ref

if TYPE_CHECKING:
    from ...plan import SessionPlan


class NonoEnforcer:
    name = "nono"

    def render_policies(self, plan: SessionPlan) -> dict[str, str]:
        return policies.render_all(plan)

    def wrap_harness(self, plan: SessionPlan, entry: list[str]) -> list[str]:
        return policies.harness_argv(entry)

    def tool_wrapper_argv(self, plan: SessionPlan) -> list[str]:
        return policies.tool_wrapper_argv()

    def compose_env(self, plan: SessionPlan) -> dict[str, str]:
        # nono's supervisor talks to its child over loopback; keep that direct.
        return {"NONO_NO_PROXY": "localhost,127.0.0.1"}

    def extra_tmpfs(self, plan: SessionPlan) -> list[str]:
        # The supervisor creates a PTY-proxy Unix socket under its state root
        # ($HOME/.local/state/nono) plus lock/state under $HOME/.nono. On Docker
        # Desktop (macOS/Windows) the /home/agent bind mount is a virtiofs/
        # gRPC-FUSE share that cannot host an AF_UNIX socket — bind() fails with
        # EINVAL ("os error 22") and the sandbox never starts. Back both state
        # roots with tmpfs: a native fs that supports sockets, and — since neither
        # path is in the harness/tool Landlock allow-lists — still off-limits to
        # the sandboxed agent. State is per-session and needs no persistence.
        #
        # Target nono's OWN state root, not the whole ~/.local/state: a broad
        # tmpfs there would shadow every sibling's persisted state (caches,
        # tokens, resume data) under the /home/agent bind mount each session.
        return ["/home/agent/.nono", "/home/agent/.local/state/nono"]

    def cap_add(self, plan: SessionPlan) -> list[str]:
        # Phase 2 runs no proxy, so no SYS_PTRACE is needed (verified). The
        # proxy/credential-injection path that needs it is a follow-up.
        return []

    def image_reference(self) -> str:
        return nono_image_ref()

    def doctor(self, runtime) -> list[Check]:
        checks = [Check("enforcer: nono", "ok", f"policy backend; binary from {nono_image_ref()}")]
        # If a nono binary is on PATH (rare on the host) we can validate; inside
        # the image the entrypoint runs `nono profile validate`.
        if shutil.which("nono"):
            proc = subprocess.run(["nono", "--version"], capture_output=True, text=True)
            checks.append(Check("nono binary", "ok" if proc.returncode == 0 else "warn", proc.stdout.strip()))
        else:
            checks.append(Check("nono binary", "info", "not on host PATH — baked into the harness image"))
        return checks
