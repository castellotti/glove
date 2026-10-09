"""Ring-1 enforcer interface.

An ``Enforcer`` renders the kernel-policy files for a session, wraps the harness
process, and provides the per-command wrapper the harness hooks prepend to every
shell command. ``nono`` (Landlock) is the default; ``none`` is ring-0 only.

Policies render to ``<session-dir>/.glove/enforcer/`` on the host
and bind-mount read-only at ``/etc/glove/enforcer/`` — never inside ``/work``,
never writable by the agent.
"""

from __future__ import annotations

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
# The entrypoint every harness image bakes (the `gloveentry` build context): it
# validates the ring-1 policies, then execs the compose command.
ENTRYPOINT_DIR = Path(__file__).parent / "entrypoint"
GLOVE_PTY = "/opt/glove/bin/glove-pty"
# The sandboxes the tool wrapper runs, by absolute path: a harness may put a
# directory of its home first on a tool command's PATH (Pi's agent `bin/`).
NONO = "/usr/bin/nono"  # every harness base image
SRT = "/usr/local/bin/srt"  # the -srt overlay (srt_image)

TMP = "/tmp"
# The harness hooks hold the harness's own file tools (Pi's write/edit, Vibe's
# write_file/edit: they run in the harness process, outside ring 1) to these
# roots, as every enforcer holds a tool command (`write_roots`).
WRITE_ROOTS_FILE = "write-roots.json"
# The tool inventory the harness hooks classify each call by (harness.tool_inventory):
# a tool not in it is refused, and so is every tool when it is missing.
TOOLS_FILE = "tools.json"

# Enforcers that run srt (bubblewrap) in the harness container: the `-srt`
# image overlay and the relaxed nested-userns seccomp profile.
SRT_ENFORCERS = frozenset({"srt", "nono+srt"})


def workdir(plan: SessionPlan) -> str:
    """The working dir's container path."""
    return next((m.container_path for m in plan.mounts if m.is_workdir), "/work")


def write_roots(plan: SessionPlan) -> list[str]:
    """Where a tool command may write under every enforcer: the working dir,
    the rw mounts, /tmp and the writable channels. The harness also writes its
    home."""
    rw = [m.container_path for m in plan.mounts if not m.is_workdir and m.mode == "rw"]
    return [workdir(plan), *rw, TMP, *plan.composition.channel_paths]


def argv_lines(argv: list[str]) -> str:
    """An argv one argument per line (`*.argv`), for glue with no JSON parser
    (Claude Code's shell prefix is a bash script)."""
    return "".join(f"{a}\n" for a in argv)


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
    from ..image import content_hash

    return f"-srt-{content_hash('', [('srt', SRT_IMAGE_DIR)])}"




@runtime_checkable
class Enforcer(Protocol):
    name: str
    # The sandbox each shell command runs in ("nono", "srt", or None): what
    # `tools_run_browsers` asks.
    tool_sandbox: str | None

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
