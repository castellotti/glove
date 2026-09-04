"""The ``none`` enforcer — ring 0 only, for debugging / VM runtimes.

`glove doctor` prints a red line when this is selected: there is no in-container
kernel policy, so a malicious extension is confined only by the container.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..runtimes.base import Check

if TYPE_CHECKING:
    from ..plan import SessionPlan


class NoneEnforcer:
    name = "none"

    def render_policies(self, plan: SessionPlan) -> dict[str, str]:
        return {}

    def wrap_harness(self, plan: SessionPlan, entry: list[str]) -> list[str]:
        return list(entry)

    def tool_wrapper_argv(self, plan: SessionPlan) -> list[str]:
        return []

    def compose_env(self, plan: SessionPlan) -> dict[str, str]:
        return {}

    def cap_add(self, plan: SessionPlan) -> list[str]:
        return []

    def doctor(self, runtime) -> list[Check]:
        return [Check("enforcer: none", "fail", "ring-0 only — NO in-container kernel policy")]
