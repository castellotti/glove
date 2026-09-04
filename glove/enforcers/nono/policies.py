"""Render nono profiles from a ``SessionPlan``.

Two profiles per session, both extending nono's built-in ``default`` (which
brings system reads, deny_credentials/deny_shell_configs, and the
dangerous_commands deny groups):

- ``harness.json`` — the harness *process*: its config home + /work + rw mounts
  are writable, ro mounts readable, network open (ring 0 already restricts which
  hosts are routable to the sidecars).
- ``tool.json`` — every *shell command* the agent runs: /work + rw mounts + /tmp
  writable, **harness home denied** (omitted from the allow-list; Landlock is
  allow-list so anything ungranted is denied), network blocked, and secret-ish
  env vars stripped so a prompt-injected `env` cannot read the LLM key.

Both are validated empirically against the nono probe image (see
tests/integration/test_pi_nono.sh). A key subtlety: nono refuses to grant a
directory that contains its own protected state roots (`$HOME/.nono`,
`$HOME/.local/state/nono`), so the harness profile grants only the harness's
*config subdir* (e.g. `/home/agent/.pi/agent`) rather than all of `$HOME` — the
supervisor still writes nono state on the (ungranted) home bind mount, and the
sandboxed agent cannot touch it.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ...harnessconfig import LLM_API_KEY_ENV
from ..base import ENFORCER_DIR

if TYPE_CHECKING:
    from ...plan import SessionPlan

TMP = "/tmp"
GLOVE_READ = ["/etc/glove", "/opt/glove"]

# Env vars a shell command must never see (the LLM key and any secret-shaped
# name). nono's environment.deny_vars strips these from wrapped commands.
SECRET_DENY_VARS = [
    LLM_API_KEY_ENV,
    "*KEY*",
    "*TOKEN*",
    "*SECRET*",
    "*API_KEY*",
    "*CREDENTIAL*",
    "*PASSWORD*",
]

# Commands agents legitimately need that live in nono's default deny list; the
# tool profile re-allows them (startup-only gate — the strong guarantee is the
# filesystem/network policy, which confines these to /work anyway).
DEFAULT_ALLOW_COMMANDS = ["cp", "mv", "rm"]


def _rw_mounts(plan: SessionPlan) -> list[str]:
    return [m.container_path for m in plan.mounts if not m.is_workdir and m.mode == "rw"]


def _ro_mounts(plan: SessionPlan) -> list[str]:
    return [m.container_path for m in plan.mounts if m.mode == "ro"]


def _workdir(plan: SessionPlan) -> str:
    for m in plan.mounts:
        if m.is_workdir:
            return m.container_path
    return "/work"


def render_harness_profile(plan: SessionPlan) -> dict:
    work = _workdir(plan)
    config_home = plan.profile.config_home_path
    return {
        "meta": {"name": "glove-harness"},
        "extends": "default",
        "workdir": {"access": "readwrite"},
        "filesystem": {
            "allow": [work, *_rw_mounts(plan), config_home, TMP],
            "read": [*_ro_mounts(plan), *GLOVE_READ],
        },
        # Ring 0 already limits routable hosts to the sidecars; the harness needs
        # network to reach them. (Proxy-allowlist + credential injection is a
        # follow-up.)
        "network": {"block": False},
        "security": {"signal_mode": "allow_same_sandbox"},
    }


def render_tool_profile(plan: SessionPlan) -> dict:
    work = _workdir(plan)
    tools = plan.tools or {}
    allow_commands = list(tools.get("allow_commands", DEFAULT_ALLOW_COMMANDS))
    deny_commands = list(tools.get("deny_commands", []))
    profile = {
        "meta": {"name": "glove-tool"},
        "extends": "default",
        "workdir": {"access": "readwrite"},
        "filesystem": {
            # harness home intentionally absent → denied by omission (Landlock).
            "allow": [work, *_rw_mounts(plan), TMP],
            "read": [*_ro_mounts(plan), *GLOVE_READ],
        },
        "network": {"block": True},
        "environment": {"deny_vars": list(SECRET_DENY_VARS)},
        "security": {"signal_mode": "allow_same_sandbox"},
    }
    if allow_commands:
        profile["commands"] = {"allow": allow_commands}
    if deny_commands:
        profile.setdefault("commands", {})["deny"] = deny_commands
    return profile


def tool_wrapper_argv() -> list[str]:
    """The prefix the harness hooks prepend to every shell command."""
    return [
        "nono", "wrap", "-s", "--allow-cwd",
        "--profile", f"{ENFORCER_DIR}/tool.json", "--",
    ]


def harness_argv(entry: list[str]) -> list[str]:
    """Wrap the harness TUI under `nono run` (supervised: audit, no proxy)."""
    return [
        "nono", "run", "-s", "--allow-cwd",
        "--profile", f"{ENFORCER_DIR}/harness.json", "--",
        *entry,
    ]


def render_all(plan: SessionPlan) -> dict[str, str]:
    """All policy files for a session: filename → JSON/text contents."""
    return {
        "harness.json": json.dumps(render_harness_profile(plan), indent=2) + "\n",
        "tool.json": json.dumps(render_tool_profile(plan), indent=2) + "\n",
        "tool-wrapper.json": json.dumps({"argv": tool_wrapper_argv()}, indent=2) + "\n",
    }
