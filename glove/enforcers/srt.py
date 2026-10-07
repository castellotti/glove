"""The ``srt`` enforcer — opt-in Anthropic sandbox-runtime backend.

For users who prefer Anthropic's runtime (parity with Claude Code's sandbox, or
Pi's own `sandbox` extension). Unlike nono, srt:

- **wraps tool commands only** (`srt -s srt-settings.json -- bash -c <cmd>`);
  it has no "wrap the whole TUI and run proxies for children" mode, so the
  harness *process* is protected by ring 0 alone (documented in doctor / policy
  show).
- needs **unprivileged user namespaces**, so it runs only under the surgically
  relaxed seccomp profile (`nested-userns.json`, selected in `plan._seccomp_for`
  when `enforcer: srt`). `srt.nested: strong` additionally needs
  `systempaths=unconfined` (masked /proc exposed to the container).
- strips secrets from tool commands only by **exact name**: every harness
  secret env var (`plan.passthrough_env`) and the LLM key's name is
  rendered as a `credentials.envVars` entry with `mode: deny`, which srt turns
  into bwrap `--unsetenv`. srt has no glob form, unlike nono's `deny_vars`.
  srt's credential *masking* (sentinel + proxy-side substitution) exists but
  requires TLS termination, so glove does not use it. An LLM API key or
  subscription token never reaches the harness (`llm`'s llm-auth injects it).

Verified against sandbox-runtime 0.0.77: weak mode enforces under the surgical
profile (allowWrite honored, everything else read-only, empty allowedDomains =
no network, denyRead hides the harness home, denied env vars absent); strong
mode needs `systempaths=unconfined`.

The `-srt` image is the overlay in ``srt_image/`` on the harness image. Its
``apply-seccomp`` is srt's own, compiled with glove's filter
(``srt_image/glove-tighten.c``): srt's stock filter leaves `unshare(CLONE_NEWUSER)`
open under the relaxed container profile, so a wrapped command could make a user
namespace and mount; glove's denies namespaces and mounts to everything below it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import TYPE_CHECKING

from ..harnessconfig import LLM_API_KEY_ENV
from ..mounts import CONTAINER_HOME
from ..runtimes.base import Check
from .base import ENFORCER_DIR, SRT, write_roots

if TYPE_CHECKING:
    from ..plan import SessionPlan

SRT_VERSION = "0.0.77"
SRT_PACKAGE = f"@anthropic-ai/sandbox-runtime@{SRT_VERSION}"
SETTINGS_FILE = "srt-settings.json"

# The srt layer (srt_image/Dockerfile) installs these; the entrypoint refuses to
# start an srt session without them (srt itself would silently fall back to its
# stock apply-seccomp, or run with no filter).
SRT_DIR = "/opt/glove/srt"
APPLY_SECCOMP = f"{SRT_DIR}/apply-seccomp"

# `enforcer_options.srt` (setting specs, as in an extension manifest).
# nested: srt's user namespace (strong needs systempaths=unconfined);
# hide_env: nono+srt hides /work's .env files from the harness.
OPTIONS = {
    "nested": {"type": "enum", "values": ["weak", "strong"], "default": "weak"},
    "hide_env": {"type": "bool", "default": True},
}
GLOVE_SRT = f"{SRT_DIR}/glove-srt.mjs"  # srt's library without a network namespace (nono+srt)
NODE = f"{SRT_DIR}/node"

def denied_env_vars(plan: SessionPlan) -> list[str]:
    """Exact env var names srt must unset for tool commands: the LLM key always
    (it may reach the harness env even when unset in config) plus every secret
    the harness receives by passthrough."""
    return list(dict.fromkeys([LLM_API_KEY_ENV, *plan.passthrough_env]))


def render_settings(plan: SessionPlan) -> dict:
    """Render the single srt tool-command settings file.

    `deniedDomains` and `denyWrite` are required keys (validation error
    otherwise). `enableWeakerNestedSandbox` follows `srt.nested` — strong mode
    is signalled by `systempaths_unconfined` on the hardening set. There is no
    `allowUnixSockets`: in srt it is a macOS-only `network` key, ignored on
    Linux, where srt's seccomp filter blocks new AF_UNIX sockets anyway.
    """
    weak = not plan.hardening.systempaths_unconfined
    return {
        "filesystem": {
            # deny the whole harness home MOUNT POINT to tool commands (extensions,
            # skills, session transcripts, config), read and write: srt's
            # `--ro-bind /` keeps a nested bind mount writable, and denying a
            # subdir of one is a no-op (verified against 0.0.75/0.0.77).
            "denyRead": [CONTAINER_HOME],
            "allowRead": [],
            "allowWrite": write_roots(plan),
            "denyWrite": [CONTAINER_HOME],
        },
        # Tool commands get no network (only the harness browser tool reaches
        # the web). srt network is allow-only, so empty allowedDomains = blocked.
        "network": {"allowedDomains": [], "deniedDomains": []},
        "credentials": {"envVars": [{"name": n, "mode": "deny"} for n in denied_env_vars(plan)]},
        "enableWeakerNestedSandbox": weak,
        "seccomp": {"applyPath": APPLY_SECCOMP},
    }


def tool_wrapper_argv() -> list[str]:
    return [SRT, "-s", f"{ENFORCER_DIR}/{SETTINGS_FILE}", "--"]


class SrtEnforcer:
    name = "srt"
    tool_sandbox = "srt"

    def render_policies(self, plan: SessionPlan) -> dict[str, str]:
        return {
            SETTINGS_FILE: json.dumps(render_settings(plan), indent=2) + "\n",
            "tool-wrapper.json": json.dumps({"argv": tool_wrapper_argv()}, indent=2) + "\n",
        }

    def wrap_harness(self, plan: SessionPlan, entry: list[str]) -> list[str]:
        # srt does not wrap the TUI; the harness process is ring-0 only.
        return list(entry)

    def tool_wrapper_argv(self, plan: SessionPlan) -> list[str]:
        return tool_wrapper_argv()

    def compose_env(self, plan: SessionPlan) -> dict[str, str]:
        return {}

    def extra_tmpfs(self, plan: SessionPlan) -> list[str]:
        return []

    def cap_add(self, plan: SessionPlan) -> list[str]:
        return []  # bwrap uses userns via the relaxed seccomp; no caps needed

    def gaps(self, plan: SessionPlan) -> list[str]:
        """Documented weaknesses vs nono (printed by `glove policy show`)."""
        g = [
            "harness PROCESS is unwrapped (ring-0 only) — srt wraps tool commands only",
            *(["a secret stays in the harness env (tool commands get it unset "
               "by exact name only)"] if plan.passthrough_env else []),
            "runs under the relaxed nested-userns seccomp (unprivileged userns enabled; "
            "re-tightened for everything srt wraps)",
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
        # bwrap smoke test under the relaxed profile.
        checks.append(self._bwrap_smoke(runtime))
        return checks

    def _bwrap_smoke(self, runtime) -> Check:
        """Run bwrap as uid 1000 under the relaxed profile in a baked -srt image.

        Reproduces weak mode: unprivileged userns + bind /proc. Uses
        a locally-built `*-srt-<hash>` harness image (which has bubblewrap baked) so the
        probe never needs network or root to install it; skips if none exists.
        """
        cli = getattr(runtime, "cli", "docker")
        if not shutil.which(cli):
            return Check("srt bwrap smoke", "skip", f"{cli} not available")
        from .base import srt_suffix

        images = subprocess.run(
            [cli, "images", "--filter", "reference=glove/*", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True,
        )
        suffix = srt_suffix()
        image = next((ln for ln in images.stdout.splitlines() if ln.strip().endswith(suffix)), None)
        if not image:
            return Check("srt bwrap smoke", "skip",
                         f"no local glove/*{suffix} image — run `glove build <harness> --enforcer srt`")
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
