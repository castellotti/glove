"""The ``nono`` enforcer (PLAN §4.2) — default ring-1 Landlock sandbox."""

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
