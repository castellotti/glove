"""The non-negotiable hardening set and its validator.

Every harness container glove renders must satisfy the table below. A config
key may only *tighten* these; the one documented opt-out (`allow_root`) still
keeps everything except the non-root user. `validate_hardening` is the single
gate that enforces this — it refuses to let a project render unless every row
holds, or an explicit override key names the exception (surfaced on the CLI as
`--i-know-what-i-am-doing <key>`).

This module has no other glove imports so the rules stay independently
testable (one unit test per row, plus the refusal path).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid an import cycle: plan imports hardening
    from .plan import SessionPlan


class HardeningError(ValueError):
    """Raised when a rendered project would violate the hardening set."""


# Capabilities glove may ever add back. SYS_PTRACE is scoped to nono's proxy
# mode; nothing else is permitted.
ALLOWED_CAP_ADD: frozenset[str] = frozenset({"SYS_PTRACE"})


@dataclass(frozen=True)
class Limits:
    """Resource bounds. Defaults double as fork-bomb/DoS caps."""

    pids: int = 512
    memory: str = "4g"
    cpus: float = 2.0


@dataclass(frozen=True)
class Hardening:
    """The rendered hardening spec for one harness service."""

    user: str | None  # "uid:gid"; None only under allow_root (runs as root)
    cap_drop: tuple[str, ...] = ("ALL",)
    cap_add: tuple[str, ...] = ()
    no_new_privileges: bool = True
    read_only: bool = True
    seccomp_profile: str | None = None  # host path to the vendored profile
    systempaths_unconfined: bool = False  # only for srt strong mode
    ipc: str = "private"
    tmpfs: tuple[str, ...] = ("/tmp",)
    limits: Limits = field(default_factory=Limits)
    allow_root: bool = False


@dataclass(frozen=True)
class Violation:
    key: str  # override key (`--i-know-what-i-am-doing <key>`)
    message: str


def find_violations(plan: SessionPlan) -> list[Violation]:
    """Return every hardening row the plan breaks (empty == compliant).

    Kept side-effect-free and structural so each row is unit-testable.
    """
    h = plan.hardening
    v: list[Violation] = []

    # Row: non-root user (opt-out: allow_root runs as uid 0 but keeps the rest).
    if not h.allow_root and (h.user is None or h.user.split(":")[0] in ("0", "")):
        v.append(Violation("user", f"harness must not run as root (user={h.user!r})"))

    # Row: cap_drop ALL.
    if tuple(h.cap_drop) != ("ALL",):
        v.append(Violation("cap-drop", f"cap_drop must be [ALL], got {list(h.cap_drop)}"))

    # Row: cap_add limited to the SYS_PTRACE opt-in (nono proxy).
    stray = [c for c in h.cap_add if c not in ALLOWED_CAP_ADD]
    if stray:
        v.append(Violation("cap-add", f"cap_add may only include {sorted(ALLOWED_CAP_ADD)}, got {stray}"))

    # Row: no-new-privileges.
    if not h.no_new_privileges:
        v.append(Violation("no-new-privileges", "security_opt no-new-privileges:true is required"))

    # Row: read-only rootfs.
    if not h.read_only:
        v.append(Violation("read-only", "read_only rootfs is required"))

    # Row: a seccomp profile is applied (never unconfined).
    if not h.seccomp_profile:
        v.append(Violation("seccomp", "a seccomp profile must be applied"))

    # Row: private IPC namespace.
    if h.ipc != "private":
        v.append(Violation("ipc", f"ipc must be 'private', got {h.ipc!r}"))

    # Row: pids/memory bounds present.
    if h.limits.pids <= 0:
        v.append(Violation("pids", f"pids_limit must be > 0, got {h.limits.pids}"))
    if not h.limits.memory:
        v.append(Violation("memory", "a memory limit is required"))

    # Row: internal network only — no host-gateway / host.docker.internal on the
    # harness itself (`net: lan|internet` set this and are an explicit opt-out).
    if plan.network.harness_host_gateway:
        v.append(
            Violation(
                "host-gateway",
                "harness must not reach host.docker.internal (net: lan/internet)",
            )
        )

    # Row: never mount the docker socket.
    for m in plan.mounts:
        if m.host_path.rstrip("/").endswith("docker.sock"):
            v.append(Violation("docker-sock", f"refusing to mount the docker socket: {m.host_path}"))

    return v


def validate_hardening(plan: SessionPlan, *, overrides: frozenset[str] = frozenset()) -> None:
    """Raise ``HardeningError`` unless the plan is compliant (or overridden).

    ``overrides`` is the set of row keys the operator waived via
    ``--i-know-what-i-am-doing``. The error lists both the unwaived violations
    and, for context, which were waived.
    """
    violations = find_violations(plan)
    unwaived = [x for x in violations if x.key not in overrides]
    if unwaived:
        lines = "\n".join(f"  - [{x.key}] {x.message}" for x in unwaived)
        keys = ", ".join(sorted({x.key for x in unwaived}))
        raise HardeningError(
            "refusing to render: hardening set violated:\n"
            f"{lines}\n"
            f"override individually with --i-know-what-i-am-doing <key> ({keys})"
        )
