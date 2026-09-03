"""The ``srt`` enforcer (PLAN §4.3) — opt-in Anthropic sandbox-runtime backend.

For users who prefer Anthropic's runtime (parity with Claude Code's sandbox, or
Pi's own `sandbox` extension). Unlike nono, srt:

- **wraps tool commands only** (`srt -s srt-settings.json -- bash -lc <cmd>`);
  it has no "wrap the whole TUI and run proxies for children" mode, so the
  harness *process* is protected by ring 0 alone (documented in doctor / policy
  show).
- needs **unprivileged user namespaces**, so it runs only under the surgically
  relaxed seccomp profile (`nested-userns.json`, selected in `plan._seccomp_for`
  when `enforcer: srt`). `srt.nested: strong` additionally needs
  `systempaths=unconfined` (masked /proc exposed to the container).
- has **no credential injection** available (its TLS-terminate + filterRequest
  is experimental), so the LLM key stays in the harness env as in v1.

Verified against the sandbox-runtime 0.0.75 probe: weak mode enforces under the
surgical profile (allowWrite honored, everything else read-only, empty
allowedDomains = no network, denyRead hides the harness home); strong mode needs
`systempaths=unconfined` (reproduces research §5).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import TYPE_CHECKING

from ..runtimes.base import Check
from .base import ENFORCER_DIR

if TYPE_CHECKING:
    from ..plan import SessionPlan

SRT_VERSION = "0.0.75"
SRT_PACKAGE = f"@anthropic-ai/sandbox-runtime@{SRT_VERSION}"
SETTINGS_FILE = "srt-settings.json"

TMP = "/tmp"
# The harness home bind-mount point. srt's `--ro-bind /` does NOT downgrade a
# nested docker bind mount, and denying a *subdir* of a bind mount is a no-op —
# so glove denies the whole home MOUNT POINT (verified against 0.0.75). srt then
# binds an empty overlay over it, hiding the harness config/extensions/
# transcripts from tool commands entirely.
HARNESS_HOME_MOUNT = "/home/agent"


def _rw_paths(plan: SessionPlan) -> list[str]:
    work = next((m.container_path for m in plan.mounts if m.is_workdir), "/work")
    rw = [m.container_path for m in plan.mounts if not m.is_workdir and m.mode == "rw"]
    return [work, *rw, TMP]


def render_settings(plan: SessionPlan) -> dict:
    """Render the single srt tool-command settings file (PLAN §4.3).

    `deniedDomains` and `denyWrite` are required keys in 0.0.75 (validation
    error otherwise). `enableWeakerNestedSandbox` follows `srt.nested` — strong
    mode is signalled by `systempaths_unconfined` on the hardening set.
    """
    weak = not plan.hardening.systempaths_unconfined
    return {
        "filesystem": {
            # deny the whole harness home mount to tool commands (extensions,
            # skills, session transcripts, config) — both read and write, since
            # srt cannot restrict a nested bind mount via allowWrite alone.
            "denyRead": [HARNESS_HOME_MOUNT],
            "allowRead": [],
            "allowWrite": _rw_paths(plan),
            "denyWrite": [HARNESS_HOME_MOUNT],
        },
        # Tool commands get no network (§6: only the harness browser tool reaches
        # the web). srt network is allow-only, so empty allowedDomains = blocked.
        "network": {"allowedDomains": [], "deniedDomains": []},
        "allowUnixSockets": [],
        "enableWeakerNestedSandbox": weak,
    }


def tool_wrapper_argv() -> list[str]:
    return ["srt", "-s", f"{ENFORCER_DIR}/{SETTINGS_FILE}", "--"]


class SrtEnforcer:
    name = "srt"

    def render_policies(self, plan: SessionPlan) -> dict[str, str]:
        return {
            SETTINGS_FILE: json.dumps(render_settings(plan), indent=2) + "\n",
            "tool-wrapper.json": json.dumps({"argv": tool_wrapper_argv()}, indent=2) + "\n",
        }

    def wrap_harness(self, plan: SessionPlan, entry: list[str]) -> list[str]:
        # srt does not wrap the TUI; the harness process is ring-0 only (§4.3).
        return list(entry)

    def tool_wrapper_argv(self, plan: SessionPlan) -> list[str]:
        return tool_wrapper_argv()

    def compose_env(self, plan: SessionPlan) -> dict[str, str]:
        return {}

    def cap_add(self, plan: SessionPlan) -> list[str]:
        return []  # bwrap uses userns via the relaxed seccomp; no caps needed

    def gaps(self, plan: SessionPlan) -> list[str]:
        """Documented weaknesses vs nono (printed by `glove policy show`)."""
        g = [
            "harness PROCESS is unwrapped (ring-0 only) — srt wraps tool commands only",
            "LLM key stays in the harness env (no srt credential injection)",
            "runs under the relaxed nested-userns seccomp (unprivileged userns enabled)",
            "srt cannot restrict a nested docker bind mount via allowWrite; the "
            "harness home is denied by denying its mount point (verified)",
        ]
        if plan.hardening.systempaths_unconfined:
            g.append("srt.nested: strong → systempaths=unconfined exposes masked /proc,/sys to the container")
        return g

    def doctor(self, runtime) -> list[Check]:
        checks = [
            Check("enforcer: srt", "warn",
                  f"opt-in; wraps tool commands only, harness process is ring-0 only ({SRT_PACKAGE})"),
        ]
        # bwrap smoke test under the relaxed profile (reproduces research §3).
        checks.append(self._bwrap_smoke(runtime))
        return checks

    def _bwrap_smoke(self, runtime) -> Check:
        """Run bwrap as uid 1000 under the relaxed profile in a baked -srt image.

        Reproduces research §3 weak mode: unprivileged userns + bind /proc. Uses
        a locally-built `*-srt` harness image (which has bubblewrap baked) so the
        probe never needs network or root to install it; skips if none exists.
        """
        cli = getattr(runtime, "cli", "docker")
        if not shutil.which(cli):
            return Check("srt bwrap smoke", "skip", f"{cli} not available")
        images = subprocess.run(
            [cli, "images", "--filter", "reference=glove/*-srt", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True,
        )
        image = next((ln for ln in images.stdout.splitlines() if ln.strip()), None)
        if not image:
            return Check("srt bwrap smoke", "skip", "no local glove/*-srt image — run `glove build <harness> --enforcer srt`")
        from ..runtimes.seccomp import nested_userns_profile_path

        proc = subprocess.run(
            [
                cli, "run", "--rm",
                "--security-opt", f"seccomp={nested_userns_profile_path()}",
                "--security-opt", "no-new-privileges:true",
                "--cap-drop", "ALL", "--user", "1000:1000",
                image, "bwrap",
                "--unshare-user", "--unshare-net", "--ro-bind", "/", "/",
                "--bind", "/proc", "/proc", "--dev", "/dev", "echo", "OK",
            ],
            capture_output=True, text=True, timeout=120,
        )
        out = (proc.stdout + proc.stderr).strip()
        if proc.returncode == 0 and "OK" in out:
            return Check("srt bwrap smoke (relaxed seccomp, weak mode)", "ok",
                         f"unprivileged userns + bind /proc works [{image}]")
        return Check("srt bwrap smoke", "fail", out[-200:])
