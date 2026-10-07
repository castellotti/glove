"""The ``nono+srt`` enforcer — srt wraps the harness, nono wraps every tool command.

    glove-pty relay -- glove-srt srt-harness.json -- glove-pty ctty -- <harness>
        tool command: glove-pty notty -- nono wrap --profile tool.json -- bash -c <cmd>  (as with nono)

srt is outermost because bubblewrap needs mount/pivot_root, which Landlock
cannot grant; nono's Landlock stacks inside it (verified by the M8 spike).
What the layering adds over ``nono`` alone:

- deny-inside-allow writes: `/work/.git/hooks`, `.vscode`, `.envrc`, … stay
  read-only even though `/work` is writable (those present at launch; nothing
  is created on the host), and `.env` files are hidden;
- no new AF_UNIX sockets or io_uring, and — glove's apply-seccomp — no
  namespaces or mounts for anything below srt (the relaxed container profile
  that bwrap needs stays open only to srt itself);
- the TUI keeps a working terminal (glove-pty relay/ctty) without srt's
  `--new-session` being dropped;
- a PID namespace between srt and everything it wraps;
- two independent kernel mechanisms between a tool command and the host.

The harness keeps the container's network: srt's settings have no `network`
block, and `glove-srt` (srt's library; its CLI always confines the network)
makes no network namespace or proxy. Ring 0 already confines the
harness to the session's forwarders on an internal network (no route, no
external DNS), which is exactly what srt's allowlist would name; confining it
again broke every client that speaks its own proxy protocol (web_fetch) and
raw-TCP endpoints (M8 spike). Tool commands still have no network (nono).

Costs: the container runs under the relaxed ``nested-userns`` seccomp profile
(like ``srt``); the harness starts ~0.1 s slower. Podman is refused: its
compose provider cannot apply the profile.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from ..mounts import CONTAINER_HOME
from ..runtimes.base import Check
from .base import ENFORCER_DIR, GLOVE_PTY
from .nono import policies as nono_policies
from .srt import APPLY_SECCOMP, GLOVE_SRT, NODE, TMP, SrtEnforcer

if TYPE_CHECKING:
    from ..plan import SessionPlan

HARNESS_SETTINGS = "srt-harness.json"

# Trusted by the host (git, IDEs, direnv, agent CLIs) when the user opens /work:
# the harness and its tools may not write them. Only those present at launch:
# denying a missing path makes bwrap create an empty placeholder in the user's
# work/ on the host (so a fresh /work also keeps `git init` working). srt adds
# its own list (DANGEROUS_FILES/DIRECTORIES) where they exist in writable paths.
PROTECTED = (
    ".git/hooks", ".git/config", ".vscode", ".idea", ".envrc", ".mcp.json", ".gitmodules",
    ".claude/commands", ".claude/agents", ".claude/settings.json", ".claude/settings.local.json",
)
# Read-hidden from the harness and its tools (matches at launch).
HIDDEN = ("**/.env", "**/.env.*")


def _work(plan: SessionPlan) -> str:
    return next((m.container_path for m in plan.mounts if m.is_workdir), "/work")


def _work_host(plan: SessionPlan) -> str | None:
    return next((m.host_path for m in plan.mounts if m.is_workdir), None)


def protected_paths(plan: SessionPlan) -> list[str]:
    from pathlib import Path

    work, host = _work(plan), _work_host(plan)
    return [f"{work}/{p}" for p in PROTECTED if host and os.path.lexists(Path(host) / p)]


def render_harness_settings(plan: SessionPlan) -> dict:
    hide = [f"{_work(plan)}/{g}" for g in HIDDEN] if plan.enforcer_options["srt"]["hide_env"] else []
    rw = [m.container_path for m in plan.mounts if not m.is_workdir and m.mode == "rw"]
    return {
        "filesystem": {
            "denyRead": hide,
            "allowRead": [],
            "allowWrite": [_work(plan), *rw, CONTAINER_HOME, TMP, *plan.composition.channel_paths],
            "denyWrite": protected_paths(plan),
        },
        # No `network` block: srt then creates no network namespace or proxy
        # (the harness stays on ring 0's internal network). No `credentials`:
        # the harness keeps its env (an LLM key or token is injected by `llm`);
        # tool commands lose every secret-shaped name to nono's deny_vars.
        "enableWeakerNestedSandbox": not plan.hardening.systempaths_unconfined,
        "seccomp": {"applyPath": APPLY_SECCOMP},
    }


class NonoSrtEnforcer:
    name = "nono+srt"
    tool_sandbox = "nono"

    def render_policies(self, plan: SessionPlan) -> dict[str, str]:
        out = nono_policies.render_all(plan)
        out.pop("harness.json")  # srt wraps the harness, not `nono run`
        out[HARNESS_SETTINGS] = json.dumps(render_harness_settings(plan), indent=2) + "\n"
        return out

    def wrap_harness(self, plan: SessionPlan, entry: list[str]) -> list[str]:
        return [GLOVE_PTY, "relay", "--", NODE, GLOVE_SRT, f"{ENFORCER_DIR}/{HARNESS_SETTINGS}", "--",
                GLOVE_PTY, "ctty", "--", *entry]

    def tool_wrapper_argv(self, plan: SessionPlan) -> list[str]:
        return nono_policies.tool_wrapper_argv()

    def compose_env(self, plan: SessionPlan) -> dict[str, str]:
        return {}

    def extra_tmpfs(self, plan: SessionPlan) -> list[str]:
        return []

    def cap_add(self, plan: SessionPlan) -> list[str]:
        return []

    def gaps(self, plan: SessionPlan) -> list[str]:
        g = [
            "runs under the relaxed nested-userns seccomp; glove's apply-seccomp re-denies namespaces and "
            "mounts to the harness and every tool command, so only srt itself holds them",
            "protected /work paths and hidden .env files are those present at launch "
            "(a .vscode or .env created later is writable/readable)",
            "the harness process keeps the container network (ring 0: the session's forwarders only)",
        ]
        if plan.hardening.systempaths_unconfined:
            g.append("srt.nested: strong → systempaths=unconfined exposes masked /proc,/sys to the container")
        return g

    def doctor(self, runtime) -> list[Check]:
        smoke = SrtEnforcer()._bwrap_smoke(runtime)
        return [
            Check("enforcer: nono+srt", "ok",
                  "srt wraps the harness (deny-inside-allow, no namespaces/mounts below it), nono every command"),
            smoke,
        ]
