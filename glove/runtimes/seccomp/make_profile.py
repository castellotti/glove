#!/usr/bin/env python3
"""Generate ``nested-userns.json`` from the vendored moby ``default.json``.

This is the *surgical* relaxation described here (not a coarse profile). It takes the vendored Docker default
seccomp profile and makes exactly the namespace/mount syscalls that
bubblewrap needs available to an *unprivileged* process, and **nothing else**.

Concretely it:

1. Adds one unconditional ``SCMP_ACT_ALLOW`` group for exactly::

       unshare clone clone3 setns mount umount2 pivot_root mount_setattr
       open_tree move_mount fsopen fsconfig fsmount fspick

   In the default profile these live in a single group gated on
   ``CAP_SYS_ADMIN`` that *also* contains ``bpf``, ``perf_event_open``,
   ``fanotify_init``, ``syslog``, ``quotactl``, ``lsm_*``, ``setdomainname``
   and ``sethostname`` — none of which we relax. ``pivot_root`` is absent from
   the default allowlist entirely (bwrap fails without it), so it is added
   here too.

2. Drops the ``CLONE_NEW*`` argument mask on ``clone`` so an unprivileged
   process may create new namespaces.

No Linux capability is granted; the still-masked ``/proc`` paths that make
bwrap's *fresh* ``/proc`` mount fail are a Docker ``systempaths`` concern, not
a seccomp one.

Run ``python -m glove.runtimes.seccomp.make_profile`` to regenerate the
checked-in ``nested-userns.json``; ``glove build`` / CI assert it is current.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
DEFAULT = HERE / "default.json"
NESTED = HERE / "nested-userns.json"

# Exactly the namespace/mount syscalls bubblewrap needs — and nothing else.
NS_SYSCALLS: list[str] = [
    "clone",
    "clone3",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "mount",
    "mount_setattr",
    "move_mount",
    "open_tree",
    "pivot_root",
    "setns",
    "umount2",
    "unshare",
]

# Syscalls that share the default profile's CAP_SYS_ADMIN group but must stay
# gated — asserted by the tests so a future edit cannot widen the blast radius.
MUST_STAY_GATED: list[str] = [
    "bpf",
    "perf_event_open",
    "fanotify_init",
    "syslog",
    "quotactl",
    "quotactl_fd",
    "lsm_get_self_attr",
    "lsm_set_self_attr",
    "lsm_list_modules",
    "setdomainname",
    "sethostname",
    "lookup_dcookie",
    "umount",  # only umount2 is relaxed
]

# CLONE_NEW* mask the default profile applies to clone's flags argument.
_CLONE_NEW_MASK = 0x7E020000


def build_nested(default_profile: dict) -> dict:
    """Return the surgically relaxed profile derived from ``default_profile``."""
    profile = json.loads(json.dumps(default_profile))  # deep copy

    # 2. Drop the CLONE_NEW* argument mask on clone (all arches).
    for group in profile["syscalls"]:
        if group.get("names") == ["clone"] and group.get("args"):
            group["args"] = []

    # 1. Add one unconditional allow group for exactly the NS/mount syscalls.
    profile["syscalls"].append(
        {"names": list(NS_SYSCALLS), "action": "SCMP_ACT_ALLOW"}
    )
    return profile


def is_unconditionally_allowed(profile: dict, syscall: str) -> bool:
    """True if ``syscall`` is allowed with no cap/arch/arg condition."""
    for group in profile["syscalls"]:
        if (
            group.get("action") == "SCMP_ACT_ALLOW"
            and syscall in group.get("names", [])
            and not group.get("includes")
            and not group.get("excludes")
            and not group.get("args")
        ):
            return True
    return False


def main() -> None:
    default_profile = json.loads(DEFAULT.read_text())
    nested = build_nested(default_profile)
    NESTED.write_text(json.dumps(nested, indent=1) + "\n")
    print(f"wrote {NESTED}")


if __name__ == "__main__":
    main()
