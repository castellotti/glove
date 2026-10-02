"""Ring-1 enforcer interface.

An ``Enforcer`` renders the kernel-policy files for a session, wraps the harness
process, and provides the per-command wrapper the harness hooks prepend to every
shell command. ``nono`` (Landlock) is the default; ``none`` is ring-0 only.

Policies render to ``<session-dir>/.glove/enforcer/`` on the host
and bind-mount read-only at ``/etc/glove/enforcer/`` — never inside ``/work``,
never writable by the agent.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..plan import SessionPlan
    from ..runtimes.base import Check

# Where policies are mounted (read-only) inside the container.
ENFORCER_DIR = "/etc/glove/enforcer"

# glove-pty (enforcers/pty/glove-pty.c), baked into every harness base image:
# `notty` before each tool command, `relay`/`ctty` around a harness under srt.
PTY_DIR = Path(__file__).parent / "pty"
GLOVE_PTY = "/opt/glove/bin/glove-pty"

# Enforcers that run srt (bubblewrap) in the harness container: the `-srt`
# image overlay and the relaxed nested-userns seccomp profile.
SRT_ENFORCERS = frozenset({"srt", "nono+srt"})


def uses_srt(enforcer: str) -> bool:
    return enforcer in SRT_ENFORCERS


def default_enforcer(runtime: str) -> str:
    """A session file's enforcer when it names none: `nono+srt` where the
    runtime can apply its seccomp profile (docker), `nono` elsewhere (podman's
    compose provider cannot)."""
    return "nono+srt" if runtime == "docker" else "nono"


SRT_IMAGE_DIR = Path(__file__).parent / "srt_image"


def srt_suffix() -> str:
    """The image-tag suffix of the srt overlay, content-addressed so an image
    built from an older overlay (e.g. without glove's apply-seccomp) is never
    reused."""
    h = hashlib.sha256()
    for f in sorted(SRT_IMAGE_DIR.iterdir()):
        if f.is_file():
            h.update(f.name.encode() + b"\0" + f.read_bytes())
    return f"-srt-{h.hexdigest()[:10]}"




@runtime_checkable
class Enforcer(Protocol):
    name: str
    # Whether a browser (Chromium) can start inside a per-command sandbox: told
    # to the agent when `toolchains` bakes browsers.
    tools_run_browsers: bool

    def render_policies(self, plan: SessionPlan) -> dict[str, str]:
        """Map of filename → file contents, written to the session enforcer dir."""
        ...

    def wrap_harness(self, plan: SessionPlan, entry: list[str]) -> list[str]:
        """Wrap the harness TUI entry command under the enforcer (ring 1)."""
        ...

    def tool_wrapper_argv(self, plan: SessionPlan) -> list[str]:
        """Prefix the harness hooks prepend to every shell command."""
        ...

    def compose_env(self, plan: SessionPlan) -> dict[str, str]:
        """Extra environment variables the enforcer needs on the harness service."""
        ...

    def extra_tmpfs(self, plan: SessionPlan) -> list[str]:
        """Extra tmpfs mount paths the enforcer needs on the harness service.

        Used for enforcer state that must live on a native filesystem (e.g. a
        Unix-domain control socket) rather than the /home/agent bind mount, which
        on Docker Desktop is a virtiofs/gRPC-FUSE share that cannot host sockets.
        """
        ...

    def cap_add(self, plan: SessionPlan) -> list[str]:
        """Linux capabilities the enforcer requires (scoped)."""
        ...

    def doctor(self, runtime) -> list[Check]:
        ...
