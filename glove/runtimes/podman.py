"""The ``podman`` runtime — a docker subclass, marked *untested*.

Podman is not installed on the development host, so glove ships this backend
but ``glove doctor`` flags it untested until validated on a machine that has
it. Differences from docker (rootless userns, ``--userns=keep-id``, seccomp /
systempaths flag spelling, ``internal`` network validation) are documented
inline; validate before relying on it.
"""

from __future__ import annotations

from dataclasses import replace

from .base import Check
from .docker import DockerRuntime


class PodmanRuntime(DockerRuntime):
    name = "podman"
    cli = "podman"
    caps = replace(DockerRuntime.caps, compose_cmd=("podman", "compose"), tested=False)

    def doctor(self) -> list[Check]:
        checks = super().doctor()
        checks.insert(
            0,
            Check(
                "podman backend",
                "warn",
                "untested on this host — validate rootless userns/seccomp before relying on it",
            ),
        )
        return checks
