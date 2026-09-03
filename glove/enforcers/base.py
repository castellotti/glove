"""Ring-1 enforcer interface (PLAN §4.1).

An ``Enforcer`` renders the kernel-policy files for a session, wraps the harness
process, and provides the per-command wrapper the harness hooks prepend to every
shell command. ``nono`` (Landlock) is the default; ``none`` is ring-0 only.

Policies render to ``~/.glove/envs/<env>/sessions/<name>/enforcer/`` on the host
and bind-mount read-only at ``/etc/glove/enforcer/`` — never inside ``/work``,
never writable by the agent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..plan import SessionPlan
    from ..runtimes.base import Check

# Where policies are mounted (read-only) inside the container.
ENFORCER_DIR = "/etc/glove/enforcer"


@runtime_checkable
class Enforcer(Protocol):
    name: str

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

    def cap_add(self, plan: SessionPlan) -> list[str]:
        """Linux capabilities the enforcer requires (scoped; see PLAN §3.2)."""
        ...

    def doctor(self, runtime) -> list[Check]:
        ...
