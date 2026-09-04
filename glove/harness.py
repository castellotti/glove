"""Harness profile registry.

Each profile keeps the glove core generic: it declares the base image build
context, the config-home env var + in-container path, the TUI entry command,
the context file that carries the host-sudo relay rule, and default env.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

HARNESSES_DIR = Path(__file__).parent / "harnesses"


@dataclass(frozen=True)
class HarnessProfile:
    name: str
    image: str  # image tag glove builds/uses
    entry: list[str]  # TUI entry command
    config_home_env: str  # env var pointing the harness at its config dir
    config_home_path: str  # in-container config dir (on a writable volume)
    context_file: str  # in-container path for the sudo-relay instruction
    default_env: dict[str, str] = field(default_factory=dict)

    @property
    def dockerfile(self) -> Path:
        return HARNESSES_DIR / self.name / "Dockerfile"


_REGISTRY: dict[str, HarnessProfile] = {
    "vibe": HarnessProfile(
        name="vibe",
        # 0.3.0: ring-1 enforcer — baked nono binary + pre_tool hook that routes
        # every bash tool call through the per-command sandbox policy.
        image="glove/vibe:0.3.0",
        entry=["vibe", "--trust", "--yolo", "--workdir", "/work"],
        config_home_env="VIBE_HOME",
        config_home_path="/home/agent/.vibe",
        context_file="/home/agent/.vibe/AGENTS.md",
        default_env={"VIBE_HOME": "/home/agent/.vibe"},
    ),
    "pi": HarnessProfile(
        name="pi",
        # 0.3.0: ring-1 enforcer — baked nono binary + enforcer extension that
        # routes every shell command through the per-command sandbox policy.
        image="glove/pi:0.3.0",
        # Load glove's baked extensions (deps installed in the image) from system
        # paths; the user's own extensions still load from the config home. The
        # `enforcer` extension must load so shell commands are sandboxed.
        entry=[
            "pi",
            "-e", "/opt/glove/pi-extensions/enforcer",
            "-e", "/opt/glove/pi-extensions/searxng",
            "-e", "/opt/glove/pi-extensions/browser",
        ],
        config_home_env="PI_CODING_AGENT_DIR",
        config_home_path="/home/agent/.pi/agent",
        context_file="/home/agent/.pi/agent/AGENTS.md",
        # PI_OFFLINE stops Pi's startup egress attempts (fd download, version
        # check, telemetry) that fail in the no-egress sandbox; fd is baked in.
        default_env={
            "PI_CODING_AGENT_DIR": "/home/agent/.pi/agent",
            "PI_OFFLINE": "1",
        },
    ),
    "claude-code": HarnessProfile(
        name="claude-code",
        image="glove/claude-code:0.1.0",
        entry=["claude"],
        config_home_env="CLAUDE_CONFIG_DIR",
        config_home_path="/home/agent/.claude",
        context_file="/home/agent/.claude/CLAUDE.md",
        default_env={"CLAUDE_CONFIG_DIR": "/home/agent/.claude"},
    ),
}


def effective_image(
    profile: HarnessProfile,
    apt_packages: list[str] | None = None,
    pip_packages: list[str] | None = None,
) -> str:
    """Image tag for a profile, suffixed with a hash when extra packages are
    requested so a distinct package set gets its own image (and rebuilds)."""
    apt_packages = apt_packages or []
    pip_packages = pip_packages or []
    if not apt_packages and not pip_packages:
        return profile.image
    payload = "apt:" + ",".join(sorted(apt_packages)) + "|pip:" + ",".join(
        sorted(pip_packages)
    )
    digest = hashlib.sha1(payload.encode()).hexdigest()[:10]
    base, sep, tag = profile.image.rpartition(":")
    return f"{base}:{tag}-{digest}" if sep else f"{profile.image}-{digest}"


def get_profile(name: str) -> HarnessProfile:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise ValueError(
            f"unknown harness {name!r}; known: {', '.join(sorted(_REGISTRY))}"
        ) from None


def known_harnesses() -> list[str]:
    return sorted(_REGISTRY)
